// ecwcode: run the user's own `claude` with every argument passed through,
// the terminal handed over as-is, and Enclawed's hooks added through
// `--settings`. Exit status and signals are propagated.
//
// Before claude starts, the launcher:
//   1. refuses what would switch Enclawed off or leave it blind: hook-disabling
//      flags, a too-old claude, a --settings value Claude Code would reject, a
//      project that contains Enclawed Code's own install or state, a project
//      settings file that adds its own PreToolUse hooks;
//   2. holds the hardware root for the session (and refuses to start while it
//      is halted, e.g. latched DIRTY);
//   3. verifies the person (auth.mjs) when activation auth is required;
//   4. writes the session file (session.mjs) and the settings file into a
//      private directory outside the project.
// While claude runs it waits for the session-start handshake (the hook's
// first record carrying this launch's nonce) and watches the hardware root:
// on a halt it stops claude and erases Claude Code's login (credentials.mjs).

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  extractMcpConfig,
  extractPassphraseFd,
  extractSettingsArgs,
  extractWorkflow,
  optionValues,
  withoutOption,
  HOOK_DISABLING_FLAGS,
  hasBackgroundFlag,
  isPrintMode,
  routeArgs,
} from "./args.mjs";
import { LockedAuditLog } from "./audit.mjs";
import { launchAuthContext, launchAuthMessage } from "./auth.mjs";
import { MIN_CLAUDE_VERSION, claudeVersion, locateClaude, versionAtLeast } from "./claude.mjs";
import { eraseClaudeCredentials } from "./credentials.mjs";
import { launchCommandSetPin } from "./command-set.mjs";
import { attest, sessionDevice, startAnchoring } from "./device.mjs";
import { loadFramework } from "./framework.mjs";
import { kit } from "./kit.mjs";
import { heldRelayHealth, holdSessionRoot, launcherHealth, startHardwareRelay, watchForHalt } from "./hardware.mjs";
import { managedHooksStatus, readManagedSettings } from "./managed.mjs";
import { APP_ROOT, auditLogPath, hardwareLatchPaths, realpathNearest, stateDir } from "./paths.mjs";
import { loadPolicy } from "./policy.mjs";
import { createSession, helperEnvPins, indexProtectedInodes, isSensitiveEnvName, lowerSettingsFiles, otherHooks, policyCandidates, repositoryCommandSettings, repositoryEnv, repositoryEnvMessage, sensitiveSettingsEnv, sessionRoot, updateSession } from "./session.mjs";
import { classifyEnv, recordableValue } from "./claude-env.mjs";
import { PRE_TOOL_APPROVAL_TIMEOUT_S, buildSettings, findDisableAllHooks, hookCommand, readSettingsValue, writeSessionSettings } from "./settings.mjs";
import { createApprover, pauser } from "./approval.mjs";
import { launchContext } from "./launch-context.mjs";
import { MANAGED_NO_BYPASS_TEXT, ROOT_NO_BYPASS_TEXT, effectivePermissionMode } from "./permission-mode.mjs";
import { DROP_HEADER, prevalidateSettings } from "./prevalidate.mjs";
import { OPT_OUT_FILENAME, RETIRED_ENV, SYSTEM_POLICY_DIR, grantWarnings, resolveGrants } from "./opt-outs.mjs";
import { authority } from "./authority.mjs";
import { frameworkEnv, replaceEnvInPlace, resolveHardwareRootMode, shellFlavor } from "./env-authority.mjs";
import { matchGrant, matchHookGrant } from "./project-grants.mjs";
import { userNamespaceDeviceRisk } from "./userns.mjs";
import { EXIT_ANCHOR_REFUSED, anchorRefusalMessage, launchAnchorGate } from "./anchor-gate.mjs";
import { startControl, verifyChainedRecord } from "./control.mjs";
import { claudeCredentialLocations } from "./credentials.mjs";
import { startFileIntegrity } from "./file-integrity.mjs";
import { CommitLedger, launchJob, approvalRefusalMessage, approvalsFile, approvingDevices, commitmentLaunchRecord, decisionAgainstCommitment, effectivePolicy, measureLaunch } from "./commitments.mjs";
// How sessions authenticate: Claude Code's own login (never read here), or a sealed API key through the relay (claude-login.mjs).
import { closeLoginForSession, discardSessionLogin, loginLaunchPrecheck, openLoginForSession } from "./claude-login.mjs";
import { HOOK_BIN } from "./paths.mjs";
// The reviewed Claude Code versions and the session's update switches (claude-terms.mjs).
import { SESSION_UPDATE_ENV, claudeVersionGate } from "./claude-terms.mjs";
import { openSessionState, sessionStatePrecheck } from "./session-state.mjs";
import { processTable, processTree } from "./peer.mjs";
import { ask } from "./cli-util.mjs";
import { activateLaunch } from "./device-activation.mjs";
import { killSession, procStartTime, sessionContainment, signalContainment } from "./containment.mjs";
import { say, setProgram } from "./program.mjs";
import { warningLines } from "./warning-signals.mjs";
import { noteOnce, welcomeOnce } from "./welcome.mjs";
import { applyToSettings, askOnTerminal, excludeHooks, exclusionLine, groupBySource, questionText } from "./hook-exclusion.mjs";
import { watchTranscripts } from "./transcript-watch.mjs";
import { VERSION } from "./version.mjs";
import { loadFormal } from "./formal.mjs";
import { admitServers, candidateServers, definitionIdentity, pinStore, sessionMcp, watchMcpEvents } from "./mcp.mjs";
import { approveRepoConfigWriteIn, watchRepoConfigRequests } from "./repo-config-relay.mjs";
import { admitSkills, enabledPluginRoots, watchSkills } from "./skills.mjs";
import { profileDigest, selectWorkflow } from "./workflow.mjs";
import { recordClaudeEnvironment, settingSourcesOf } from "./shell-env.mjs";

const FORWARDED_SIGNALS = ["SIGTERM", "SIGHUP", "SIGQUIT", "SIGUSR1", "SIGUSR2", "SIGWINCH"];
export const EXIT_NO_HANDSHAKE = 3;
export const EXIT_HARDWARE_HALT = 4;
export const EXIT_AUTH = 5;
// A skill changed or appeared, or an MCP server broke its admission, during the session.
export const EXIT_ADMISSION = 7;
export { EXIT_ANCHOR_REFUSED };
export const DEFAULT_HANDSHAKE_TIMEOUT_S = kit.HANDSHAKE_TIMEOUT_S;

/** The hook handshake timeout (N4): a fixed internal constant, not a setting (authority.mjs). */
export function handshakeTimeoutS() {
  return authority().handshakeTimeoutS;
}

// Framework variables whose being dropped is worth a warning (they move
// evidence or send it somewhere); the rest are dropped silently and recorded.
const NOTED_DROPS = /^(ENCLAWEDER_|ENCLAWED_(AUDIT_PATH|CLASSIFICATION_SCHEME|NIX_MODE)$)/;

/**
 * `env` without the loader-injection variables (claude-env.mjs
 * LOADER_INJECTION_ENV), except those the administrator granted.
 * @returns {{ env: object, removed: string[], granted: string[] }}
 */
export function scrubLoaderEnv(env, granted = []) {
  return kit.scrubLoaderEnv(env, granted);
}

/**
 * The launcher's authority for one start, from its own environment: the
 * administrator's grants (opt-outs.mjs), the hardware-root mode (strict, see
 * env-authority.mjs), and the environment every later decision and the
 * framework see (only allowlisted framework variables, resolved values).
 * @returns {{ ok: true, grants: object, hardwareRoot: string, shellFlavor: object, env: object, dropped: string[], warnings: string[] }
 *         | { ok: false, message: string, grants: object }}
 */
export function launchAuthority(env) {
  const grants = resolveGrants(env);
  const hw = resolveHardwareRootMode(env, { granted: grants.grants.hardwareRoot });
  if (!hw.ok) {
    return { ok: false, message: `${hw.reason}; not starting`, grants };
  }
  // The kit removes loader-injection variables unless the administrator granted them.
  const fe = frameworkEnv(env, { hardwareRoot: hw.mode, forensicWebhook: grants.grants.forensicWebhook, loaderGranted: grants.grants.loaderEnv });
  const warnings = grantWarnings(grants);
  const noted = fe.dropped.filter((n) => NOTED_DROPS.test(n) && n !== "ENCLAWEDER_ROOT");
  if (noted.length > 0) {
    warnings.push(`ignoring ${noted.join(", ")} from your shell: Enclawed Code passes only its own allowlisted variables to Enclawed (an administrator sets a forensic webhook in ${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME})`);
  }
  const sf = shellFlavor(env);
  if (sf.unknown) {
    warnings.push(`ENCLAWED_FLAVOR=${JSON.stringify(env.ENCLAWED_FLAVOR)} is not "open" or "enclaved"; using the strictest flavor, enclaved`);
  }
  // Loader injection (LD_PRELOAD, LD_AUDIT, DYLD_INSERT_LIBRARIES) would map
  // a library into claude itself and every process it starts, the hook's
  // own claude included: removed from everything Enclawed Code starts unless
  // the administrator grants it (opt-outs.mjs loaderEnv). Recorded either way.
  const loader = { env: fe.env, removed: [...(fe.loaderRemoved ?? [])].sort(), granted: grants.grants.loaderEnv.filter((n) => typeof env[n] === "string").sort() };
  if (loader.removed.length > 0) {
    warnings.push(
      `removing ${loader.removed.join(", ")} from claude's environment: a library preloaded into claude could change what it runs and what it reports to Enclawed. ` +
        `An administrator who needs it adds "loaderEnv": ${JSON.stringify(loader.removed)} to ${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME} (root-owned). This is recorded in the audit log`,
    );
  }
  return { ok: true, grants, hardwareRoot: hw.mode, shellFlavor: sf, env: loader.env, dropped: fe.dropped, loader: { removed: loader.removed, granted: loader.granted }, warnings };
}

// Flags after which Claude Code writes no transcript, so the launcher could
// not see a tool call that ran without Enclawed Code's hook (N1).
export const NO_TRANSCRIPT_FLAGS = Object.freeze(["--no-session-persistence"]);

/** Append the MCP proxies' containment events (<session>/containment-events.jsonl) to the audit log. */
function forwardContainmentEvents(dir, audit) {
  if (!dir) {
    return;
  }
  let text = "";
  try {
    text = fs.readFileSync(path.join(dir, "containment-events.jsonl"), "utf8");
  } catch {
    return;
  }
  for (const line of text.split("\n")) {
    try {
      const r = JSON.parse(line);
      if (r && typeof r.type === "string" && /^claude-code\.(mcp\.)?containment\./.test(r.type)) {
        void audit.append({ type: r.type, actor: "enclawed-code", level: null, payload: r.payload ?? {} }).catch(() => {});
      }
    } catch {
      /* a torn line */
    }
  }
}

/** `--plugin-dir X` / `--plugin-dir=X` values (their hooks are scanned, N3). */
function pluginDirs(args, cwd) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--") {
      break;
    }
    if (args[i] === "--plugin-dir" && i + 1 < args.length) {
      out.push(path.resolve(cwd, args[++i]));
    } else if (args[i].startsWith("--plugin-dir=")) {
      out.push(path.resolve(cwd, args[i].slice("--plugin-dir=".length)));
    }
  }
  return out;
}

/** True when the organization's managed settings really run ecwcode-hook (structural check, I10). */
export function managedHookInstalled(dir) {
  return managedHooksStatus(dir).installed;
}

/**
 * What to tell the user about a device anchor alarm (round 4, N15). BUSY:
 * another process holds the Enclaweder's one anchor session (or one that
 * crashed left it open); until the firmware has a session lease, only
 * re-enumerating the device ends it.
 */
export function anchorAlarmAdvice(e) {
  if (e?.code === "ANCHOR_SESSION_BUSY") {
    const wait = typeof e.waitMs === "number" && Number.isFinite(e.waitMs) ? Math.ceil(e.waitMs / 1000) : null;
    return (
      "The Enclaweder's anchor channel is held by another process (or by one that exited without closing it), so this session cannot anchor its log; claude is stopped. " +
      (wait !== null
        ? `The holder's lease ends in ${wait} s if it stops renewing: stop any other Enclawed Code session on this machine, wait ${wait} s and start Enclawed Code again. To recover at once, take the channel over with the operator quorum, each operator signing on their own device (never on this machine): ecwctl recover-anchor --operator-offline <N>. `
        : "This firmware has no session lease: stop any other Enclawed Code session on this machine, then unplug the Enclaweder and plug it back in (the device ends an anchor session only when it is re-enumerated), and start Enclawed Code again. ") +
      "If it happens again right away, something on this machine is opening the anchor channel: check it before you continue"
    );
  }
  return "Something other than this session held or opened the Enclaweder's anchor channel during the session; claude is stopped. Run: ecwctl audit verify";
}

/**
 * Did a call that ran (a successful tool_result) violate Enclawed's decision
 * (round 4, N13)? null: no; "wait": not yet decidable (an interactive ask
 * whose PostToolUse evidence may still arrive, or a decision not reported
 * yet); otherwise the decision it ran against. `final` turns "wait" into a verdict.
 */
export function decisionViolation(decision, { askNeedsPerson, posted = false, launcherPrompt = false, approved = false, final = false }) {
  if (decision === "allow") {
    return null;
  }
  if (decision === "deny") {
    return "deny";
  }
  if (decision === "ask") {
    if (launcherPrompt) {
      // Interactive (round 5, N13c): only Enclawed Code's own prompt approves.
      // A PostToolUse report proves nothing (any descendant can produce one).
      return approved ? null : final ? "ask" : "wait";
    }
    if (!askNeedsPerson) {
      return "ask (headless: nobody to ask)";
    }
    // -p with --permission-prompt-tool: the prompt tool answers; the genuine
    // hook's PostToolUse is the (weaker) evidence there.
    return posted ? null : final ? "ask" : "wait";
  }
  return final ? "nothing (no decision was reported)" : "wait";
}

/**
 * How long Enclawed Code's prompt waits for a person: the kit's internal
 * constant (a security parameter, never a setting; a timeout denies).
 * ECWCODE_APPROVAL_TIMEOUT_S is retired (opt-outs.mjs).
 */
export function approvalTimeoutMs() {
  return authority().approvalTimeoutMs;
}

/** How this session's processes are contained for a halt (containment.mjs), for the audit log. */
export function containmentMode(c) {
  if (!c) {
    return null;
  }
  return [c.reaper ? "subreaper" : null, c.unit ? "systemd-scope" : null, c.tracked ? "tracked" : null, "marker"].filter(Boolean).join("+");
}

function fail(stderr, message, code = 2) {
  say(stderr, `${message}`);
  return code;
}

/**
 * Check and prepare the claude invocation, without writing anything.
 * Separated from spawning so it is testable.
 *
 * @returns {{ ok: true, claude: string, args: string[], session: boolean, managed: boolean, userSettings: object[], pins: object, warnings: string[], background: boolean, print: boolean, passphraseFd: string|null }
 *         | { ok: false, code: number, message: string }}
 */
export function prepareLaunch(argv, { env = process.env, cwd = process.cwd(), managedDir, stdoutIsTTY = Boolean(process.stdout.isTTY), stdinIsTTY = Boolean(process.stdin.isTTY) } = {}) {
  const route = routeArgs(argv);
  // The administrator's grants come only from a root-owned file
  // (opt-outs.mjs), and only allowlisted framework variables pass on
  // (env-authority.mjs); every decision below sees that environment.
  const auth = launchAuthority(env);
  if (!auth.ok) {
    return { ok: false, code: 2, message: auth.message };
  }
  const shellEnv = env;
  env = auth.env;
  const grantFile = `${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME}`;
  const claude = locateClaude(env);
  if (!claude) {
    return {
      ok: false,
      code: 127,
      message: "cannot find your Claude Code installation (`claude` on PATH). Install Claude Code, or set ECWCODE_CLAUDE_PATH to its executable.",
    };
  }
  if (!route.session) {
    // No session in this process, so no tool calls to gate.
    return { ok: true, claude, args: route.args, session: false, managed: false, userSettings: [], pins: {}, warnings: [], background: false, print: false, passphraseFd: null };
  }
  let args;
  let passphraseFd;
  let workflow = null;
  try {
    ({ rest: args, fd: passphraseFd } = extractPassphraseFd(route.args));
    ({ rest: args, workflow } = extractWorkflow(args));
  } catch (err) {
    return { ok: false, code: 2, message: err.message };
  }
  // R1: a flag that turns the settings hooks off is refused (the kit's decision; the flag list is Claude Code's).
  const disabling = kit.decideHookFlags(args, HOOK_DISABLING_FLAGS, "claude");
  if (disabling) {
    return { ok: false, code: 2, message: disabling.message };
  }
  // R4: a flag that turns the transcript off is refused (the kit's decision; the flag list is Claude Code's).
  const noTranscript = kit.decideTranscriptFlags(args, NO_TRANSCRIPT_FLAGS, "claude");
  if (noTranscript) {
    return { ok: false, code: 2, message: noTranscript.message };
  }
  // Claude Code runs headless whenever stdout is not a terminal (CI, a pipe
  // into tee), with or without -p; treat that as print mode (N4).
  const print = isPrintMode(args) || !stdoutIsTTY;
  const version = claudeVersion(claude, env, { cached: false });
  // A compliance control: only a Claude Code version whose terms Enclawed Code reviewed (claude-terms.mjs).
  const terms = claudeVersionGate(version, claude);
  if (!terms.ok) {
    return { ok: false, code: 2, message: terms.message };
  }
  if (!version || !versionAtLeast(version, MIN_CLAUDE_VERSION)) {
    return {
      ok: false,
      code: 2,
      message:
        `Claude Code ${version ?? "(unknown version)"} at ${claude} is older than ${MIN_CLAUDE_VERSION}, ` +
        "the first version that blocks a tool call when its hook fails. Update Claude Code (`claude update`).",
    };
  }
  // Enclawed Code's own install and state must not be inside the workspace the
  // agent edits (red-team I3, I4). Writes there are denied anyway; refusing
  // up front keeps the overlap from going unnoticed.
  const project = realpathNearest(path.resolve(cwd));
  // The overlap decision is the kit's (launch-refusals.ts); the roots are Enclawed Code's.
  const overlap = kit.decideProjectOverlap({
    projectDir: project,
    roots: [
      { label: "Enclawed Code's installation", path: APP_ROOT },
      { label: "the Enclawed state directory", path: stateDir(env) },
    ],
  });
  if (overlap) {
    return { ok: false, code: 2, message: `${overlap.message}; run Enclawed Code in a project directory` };
  }
  const warnings = [...auth.warnings];
  // Variables of the pre-rename names are not read any more: say so, once per launch.
  const legacyVars = Object.keys(env).filter((n) => (n.startsWith("CODENCLAWED_") || n.startsWith("ENCLAWDE_")) && !Object.hasOwn(RETIRED_ENV, n)).sort();
  if (legacyVars.length > 0) {
    warnings.push(`ignoring ${legacyVars.join(", ")} from your shell: Enclawed Code reads ECWCODE_* (renamed from CODENCLAWED_* and ENCLAWDE_*)`);
  }
  // A repository's settings `env` must not change where the session's
  // traffic goes, what it trusts, whose account it uses, what it loads or
  // what it exports (CVE-2026-21852; claude-env.mjs). Checked before the
  // managed-hooks branch: the managed hooks do not stop this either.
  let flagSettings = [];
  try {
    flagSettings = extractSettingsArgs(args).values.map((v) => readSettingsValue(v, cwd));
  } catch {
    /* reported below, where the --settings values are read for the session */
  }
  let managedDocs = [];
  try {
    managedDocs = readManagedSettings(managedDir);
  } catch {
    /* no managed settings */
  }
  const repoEnv = repositoryEnv({ projectDir: project, env, extra: flagSettings, managedDocs });
  if (repoEnv.refusals.length > 0) {
    return { ok: false, code: 2, message: repositoryEnvMessage(repoEnv.refusals), repositoryEnv: repoEnv.refusals };
  }
  for (const name of auth.loader?.removed ?? []) {
    repoEnv.origins.push({ name, source: "shell", class: "load", outcome: "removed from claude's environment", ...recordableValue(name, shellEnv[name]) });
  }
  for (const o of repoEnv.origins) {
    if (o.source === "shell" && (auth.loader?.granted ?? []).includes(o.name)) {
      o.outcome = "kept: granted by loaderEnv";
    }
  }
  const managed = managedHooksStatus(managedDir);
  if (managed.installed) {
    // The organization already runs Enclawed for every session; adding it
    // again would check and record every call twice.
    return { ok: true, claude, args, session: true, managed: true, userSettings: [], pins: {}, warnings, background: hasBackgroundFlag(args), print, passphraseFd, projectHooks: [], workflow, mcpConfigValues: [], addDirs: [], pluginDirs: [], envOrigins: repoEnv.origins };
  }
  if (managed.files.length > 0) {
    warnings.push(`managed settings exist but ${managed.reason}; Enclawed Code adds its own hooks for this session`);
  }
  let extracted;
  let userSettings;
  let mcpArgs;
  try {
    extracted = extractSettingsArgs(args);
    userSettings = extracted.values.map((v) => readSettingsValue(v, cwd));
    // The user's --mcp-config servers are admission candidates (mcp.mjs);
    // Enclawed Code passes its own --mcp-config and --strict-mcp-config.
    mcpArgs = extractMcpConfig(extracted.rest);
  } catch (err) {
    return { ok: false, code: 2, message: err.message };
  }
  // Hooks from every other source (I9a; round 2, N3; round 3, N9). Any hook
  // the repository supplies runs code inside the session as a descendant of
  // claude: a PreToolUse hook could rewrite a call after Enclawed approved
  // it, and a SessionStart hook (N9) ran Enclawed Code's genuine hook command on
  // forged inputs. So a project hook of ANY event refuses the launch, in
  // every flavor, unless the administrator granted that hook (below)
  // in the launcher's own environment (`env` here is the shell that started
  // Enclawed Code; no settings file can set it, since they are read only by
  // claude, which starts later). Hooks from the user's own settings, plugins
  // and --settings get a warning.
  //
  // A repository hook starts only when the root-owned opt-out file grants
  // that exact hook for this exact repository (projectHooks, by digest:
  // project-grants.mjs); a changed hook, or the script it runs, needs a new
  // grant. Hooks in .claude/settings.local.json come from the repository
  // directory too and are treated the same way.
  const others = otherHooks({ projectDir: project, env, extra: userSettings, pluginDirs: pluginDirs(args, cwd) });
  const fromProject = others.filter((h) => h.scope === "project" || h.scope === "local");
  for (const h of fromProject) {
    const m = matchGrant({ kind: "hook", file: h.file, event: h.event, matcher: h.matcher, value: h.raw ?? h.command }, project, auth.grants.grants.projectHooks);
    h.grant = m.granted ? m.grant : null;
    if (!m.granted) {
      return {
        ok: false,
        code: 2,
        message:
          `${h.file} adds its own ${h.event} hook (${h.command.slice(0, 80)}); a repository's hook runs code inside the session, outside Enclawed's checks` +
          `${h.event === "PreToolUse" ? ", and could rewrite a tool call after Enclawed checked it" : ""}. ` +
          (m.error
            ? `It cannot be granted: ${m.error}`
            : `Review it; to start anyway an administrator adds this entry to "projectHooks" in ${grantFile} (root-owned): ${JSON.stringify(m.grant)} (a changed hook needs a new entry)`),
      };
    }
  }
  // Command-valued settings and enabled .mcp.json servers from the
  // repository run its code the way a hook does (round 4, F2: a project
  // apiKeyHelper ran 8 times inside a session, and a helper that runs the
  // genuine hook can forge decisions). Refused by default; the override, like
  // the hooks one, is read from the launcher's own environment only.
  const pre = args.slice(0, args.includes("--") ? args.indexOf("--") : args.length);
  // The person's own bypass choice. Enclawed Code's default bypass mode
  // (permission-mode.mjs) would auto-approve project .mcp.json servers too, but
  // every ecwcode session passes --strict-mcp-config while any MCP source other
  // than its admitted servers exists (admitLaunch), so none of them starts; an
  // interactive launch keeps working in a repository with a .mcp.json.
  const bypass = pre.includes("--dangerously-skip-permissions") || pre.some((a, i) => a === "--permission-mode=bypassPermissions" || (a === "--permission-mode" && pre[i + 1] === "bypassPermissions"));
  // A project .mcp.json server stays refused unless it is pinned or attested
  // with this exact definition (it then starts only through Enclawed Code's MCP
  // proxy; the signature is checked again at launch, mcp.mjs admitServers).
  // Only a record whose signature verifies counts (kit.signedMcpPinStore).
  let verifiedPins = null;
  const pinnedProjectServer = (key) => {
    if (!key.startsWith("mcpServers.")) {
      return false;
    }
    const name = key.slice("mcpServers.".length);
    try {
      verifiedPins ??= kit.signedMcpPinStore(pinStore(env)).load().records;
      const rec = verifiedPins.find((r) => r.name === name);
      const def = JSON.parse(fs.readFileSync(path.join(project, ".mcp.json"), "utf8"))?.mcpServers?.[name];
      return Boolean(def && rec && rec.identity?.definitionDigest === definitionIdentity(def, env).definitionDigest);
    } catch {
      return false;
    }
  };
  const repoCommands = repositoryCommandSettings({ projectDir: project, env, extra: userSettings, print, bypass }).filter((c) => !pinnedProjectServer(c.key));
  for (const [i, c] of repoCommands.entries()) {
    const m = matchGrant({ kind: "command", file: c.file, key: c.key, value: c.raw ?? c.command }, project, auth.grants.grants.projectCommands);
    c.grant = m.granted ? m.grant : null;
    if (!m.granted) {
      const what = c.key.startsWith("mcpServers.") ? `starts the MCP server ${JSON.stringify(c.key.slice("mcpServers.".length))} (${c.command.slice(0, 80)}), enabled by ${c.enabledBy}` : `sets ${c.key} (${c.command.slice(0, 80)}), which Claude Code runs as a command`;
      const more = repoCommands.length - i - 1;
      return {
        ok: false,
        code: 2,
        message:
          `${c.file} ${what}; a repository's command runs code inside the session, outside Enclawed's checks, like a hook` +
          `${more > 0 ? ` (and ${more} more after it: ${repoCommands.slice(i + 1, i + 4).map((x) => x.key).join(", ")})` : ""}. ` +
          "Enclawed Code refuses to start with it. " +
          (m.error
            ? `It cannot be granted: ${m.error}`
            : `Review it; to start anyway an administrator adds this entry to "projectCommands" in ${grantFile} (root-owned): ${JSON.stringify(m.grant)} (a changed command needs a new entry)`),
      };
    }
  }
  for (const c of repoCommands) {
    warnings.push(`${c.file} ${c.key.startsWith("mcpServers.") ? `starts MCP server ${c.key.slice(11)}` : `sets ${c.key}`}; granted for this repository by ${grantFile} (digest ${c.grant.digest.slice(0, 12)}), it runs code from the repository in this session, outside Enclawed's checks`);
  }
  // Hooks from the user's settings, plugins, the user's skills and
  // subagents, and --settings run code in every session too (closure plan
  // M7; ClawHavoc, Miasma): each needs an administrator's grant by digest
  // ("hooks" in the opt-out file), like a repository's. One without a grant
  // is asked about at an interactive launch (hook-exclusion.mjs: start this
  // session without its source, default No); with nobody to ask, refused.
  const unapproved = [];
  let refusal = null;
  for (const h of others.filter((x) => x.scope !== "project" && x.scope !== "local")) {
    const m = matchHookGrant(h, { home: env.HOME, projectDir: project, grants: auth.grants.grants.hooks });
    h.grant = m.granted ? m.grant : null;
    if (!m.granted) {
      h.wouldGrant = m.grant ?? null;
      unapproved.push(h);
      refusal ??=
        `${h.file} (${h.scope}) adds a ${h.event} hook (${h.command.slice(0, 80)}); a hook runs code inside the session, outside Enclawed's checks` +
        `${h.event === "PreToolUse" ? ", and could rewrite a tool call after Enclawed checked it" : ""}. ` +
        (m.error ? `It cannot be granted: ${m.error}` : `Review it; to start with it an administrator adds this entry to "hooks" in ${grantFile} (root-owned): ${JSON.stringify(m.grant)} (a changed hook, or a changed file it runs, needs a new entry)`);
    }
  }
  const askable = stdinIsTTY && stdoutIsTTY && !print && !hasBackgroundFlag(args);
  if (unapproved.length > 0 && !askable) {
    const more = unapproved.length > 1 ? ` (${unapproved.length - 1} more hook(s) have no grant either)` : "";
    return {
      ok: false,
      code: 2,
      message: `${refusal}${more}. Nobody can be asked here (-p, a background session, or no terminal): it needs that administrator's grant, or start ecwcode at a terminal to be asked whether to run this session without it`,
    };
  }
  const hookQuestion = unapproved.length > 0 ? { hooks: unapproved, refusal: `${refusal} You chose not to start without ${unapproved.length > 1 ? "them" : "it"}` } : null;
  const projectHooks = fromProject.filter((h) => h.event !== "PreToolUse");
  for (const h of others.filter((x) => !unapproved.includes(x))) {
    if (h.scope === "project" || h.scope === "local") {
      warnings.push(`${h.file} adds a ${h.event} hook (${h.command.slice(0, 60)}); granted for this repository by ${grantFile} (digest ${h.grant.digest.slice(0, 12)}), it runs code from the repository in this session, outside Enclawed's checks`);
    } else {
      warnings.push(`${h.file} (${h.scope}) adds a ${h.event} hook (${h.command.slice(0, 60)}); granted by ${grantFile} (digest ${h.grant.digest.slice(0, 12)}), it runs in this session outside Enclawed's checks${h.event === "PreToolUse" ? "; if it rewrites a call's input, Enclawed Code reports input-changed-after-decision" : ""}`);
    }
  }
  // Sensitive variables in lower settings `env`: pinned to the launcher's own
  // values; the helper variables (HELPER_ENV) always (round 4, F2).
  const pins = helperEnvPins(env);
  for (const x of sensitiveSettingsEnv({ projectDir: project, env })) {
    if (x.scope === "user" && ["destination", "trust", "credential"].includes(classifyEnv(x.name, "").class)) {
      // The user's own choice (e.g. NODE_EXTRA_CA_CERTS for a TLS-inspecting
      // proxy): kept, and recorded in the session.start record.
      continue;
    }
    pins[x.name] = env[x.name] ?? pins[x.name] ?? "";
    warnings.push(`${x.file} sets ${x.name} in its env; Enclawed Code pins it to your shell's value (or Enclawed's default) for this session`);
  }
  for (const s of userSettings) {
    for (const name of Object.keys(s.env ?? {})) {
      if (isSensitiveEnvName(name) && /^(ENCLAWED_|ENCLAWEDER_|ECWCODE_|CODENCLAWED_|ENCLAWDE_|NODE_OPTIONS$|NODE_PATH$|LD_|DYLD_)/.test(name)) {
        warnings.push(`--settings sets ${name}; Enclawed Code's hook ignores its environment, so this changes nothing for Enclawed`);
      }
    }
  }
  for (const f of findDisableAllHooks({ cwd, env })) {
    warnings.push(`${f} sets disableAllHooks; Enclawed Code's settings override it for this session`);
  }
  return {
    ok: true,
    claude,
    args: mcpArgs.rest,
    session: true,
    managed: false,
    workflow,
    mcpConfigValues: mcpArgs.values,
    addDirs: optionValues(mcpArgs.rest, "--add-dir").map((d) => realpathNearest(path.resolve(cwd, d))),
    pluginDirs: pluginDirs(mcpArgs.rest, cwd),
    userSettings,
    pins,
    envOrigins: repoEnv.origins,
    warnings,
    background: hasBackgroundFlag(args),
    print,
    passphraseFd,
    projectHooks,
    grantsUsed: {
      projectHooks: fromProject.map((h) => ({ file: h.file, event: h.event, ...h.grant })),
      projectCommands: repoCommands.map((c) => ({ file: c.file, key: c.key, ...c.grant })),
      hooks: others.filter((h) => h.scope !== "project" && h.scope !== "local" && h.grant).map((h) => ({ scope: h.scope, file: h.file, event: h.event, ...h.grant })),
    },
    hookQuestion,
  };
}

// The default mode goes before the person's arguments, or after `agents` (whose
// own --permission-mode sets the mode of the sessions it dispatches).
function withMode(args, add) {
  return add.length === 0 ? args : args[0] === "agents" ? [args[0], ...add, ...args.slice(1)] : [...add, ...args];
}

/**
 * Write the session file and the settings file for a prepared plan.
 * @returns the plan with `args` (the --settings argument injected), `sessionFile`, `settingsDir`, `nonce`
 */
export function materializeSession(plan, { env = process.env, cwd = process.cwd(), fw, hardware = null, approval = false, admission = null }) {
  let s = createSession({ env, cwd, fw, hardware });
  s = indexProtectedInodes(s);
  // What was admitted for this session (workflow profile, verified skills,
  // admitted MCP servers), read by the hook and the MCP proxy from the
  // digest-checked session file only.
  const mcp = admission?.mcp ? sessionMcp(admission.mcp, { sessionDir: s.dir }) : null;
  if (admission) {
    s = updateSession(s, {
      workflow: admission.workflow ?? null,
      skills: admission.skills?.session ?? null,
      mcp: mcp?.session ?? null,
    });
  }
  // Foreground sessions get the launcher's control socket (control.mjs); a
  // background session outlives the launcher, so it has none. Interactive
  // ones answer an "ask" at the launcher's own prompt (approval.mjs, N13c).
  const launcherApproval = approval && !plan.background && !plan.print;
  s = updateSession(s, {
    // The URLs the person's own command line names (the prompt of -p, or any argument they typed):
    // the kit treats a fetch of exactly one of them as the person's request. Never from files or tool output.
    personUrls: kit.personUrlsOf((plan.args ?? []).filter((a) => typeof a === "string").join("\n")),
    pinnedEnv: Object.keys(plan.pins),
    // What the user's shell, settings and the managed settings chose of the
    // variables a repository may not set (claude-env.mjs), and the loader
    // variables removed: recorded in the session.start record.
    envOrigins: plan.envOrigins ?? [],
    ...(plan.background ? {} : { control: { path: path.join(s.dir, "ctl.sock") } }),
    ...(launcherApproval ? { approval: "launcher", approvalTimeoutS: Math.round(approvalTimeoutMs() / 1000) } : {}),
  });
  if (hardware?.mode === "relay") {
    // The relay secret is not written into the session file (N5): the
    // verified hook gets it over the control socket.
    s = updateSession(s, { hardware: { ...hardware, relay: { path: hardware.relay.path } } });
  }
  const command = hookCommand({ origin: "launcher", session: s.file, digest: s.digest });
  // Claude Code reloads its settings files when they change. The project's
  // and the local settings are therefore never read live: Claude Code starts
  // with --setting-sources=user (its other sources, as the person asked),
  // and the admitted copy of the repository's settings, read now, is part of
  // this session's own settings file (below the person's --settings and
  // Enclawed Code's own keys). A later change of them takes effect only after
  // Enclawed Code admits it at the next launch.
  const asked = optionValues(plan.args ?? [], "--setting-sources");
  const sources = asked.length ? asked.join(",").split(",").map((x) => x.trim()).filter(Boolean) : ["user", "project", "local"];
  const repoDocs = lowerSettingsFiles({ projectDir: realpathNearest(path.resolve(cwd)), env })
    .filter((f) => f.scope !== "user" && sources.includes(f.scope))
    .flatMap((f) => {
      try {
        const doc = JSON.parse(fs.readFileSync(f.file, "utf8"));
        return doc && typeof doc === "object" && !Array.isArray(doc) ? [doc] : [];
      } catch {
        return [];
      }
    });
  // A hook in the user's settings file the person chose to start without:
  // the session reads a copy of that file without it, instead of the file.
  const userCopy = plan.hookExclusion?.userSettingsCopy ?? null;
  const userDocs = userCopy && sources.includes("user") ? [userCopy] : [];
  const built = buildSettings([...userDocs, ...repoDocs, ...plan.userSettings], command, {
    pins: plan.pins,
    ...(launcherApproval ? { preToolTimeoutS: kit.approvalHookTimeoutS(PRE_TOOL_APPROVAL_TIMEOUT_S) } : {}),
    ...(admission ? { skills: { overrides: admission.skills?.overrides ?? {}, bundled: admission.skillsBundled ?? "off" } } : {}),
    ...(admission?.mcp && !admission.mcp.connectors?.enabled ? { disableClaudeAiConnectors: true } : {}),
  });
  // The permission mode (permission-mode.mjs): the person's, else bypassPermissions, whose
  // one-time confirmation is pre-accepted in this session's own settings file only.
  const permissionMode = effectivePermissionMode(plan.args ?? [], { managedDocs: readManagedSettings(), env });
  const finalSettings = applyToSettings(built.settings, plan.hookExclusion);
  const { file } = writeSessionSettings(permissionMode.acceptBypass ? { ...finalSettings, skipDangerousModePermissionPrompt: true } : finalSettings, s.dir);
  // The only MCP servers Claude Code starts: the admitted ones, each behind
  // Enclawed Code's proxy, which reads this final session file (its digest is on
  // the proxy's command line, like the hook's).
  let mcpArgs = [];
  if (mcp) {
    for (const def of Object.values(mcp.config.mcpServers)) {
      def.args = [def.args[0], "--session", s.file, "--digest", s.digest, ...def.args.slice(5)];
    }
    const mcpFile = path.join(s.dir, "mcp.json");
    fs.writeFileSync(mcpFile, `${JSON.stringify(mcp.config, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    // `--mcp-config=FILE`: the variadic option then takes exactly this value
    // (checked on 2.1.326). --strict-mcp-config keeps every other MCP source
    // (user, local, project .mcp.json, plugins, claude.ai connectors) from
    // starting; it is left out only when the policy admits claude.ai
    // connectors and no other MCP source exists (admitLaunch).
    mcpArgs = [`--mcp-config=${mcpFile}`, ...(admission.mcp.strict === false ? [] : ["--strict-mcp-config"])];
  }
  return {
    ...plan,
    args: ["--settings", file, `--setting-sources=${sources.filter((x) => x === "user" && userDocs.length === 0).join(",")}`, ...mcpArgs, ...withMode(withoutOption(plan.args, "--setting-sources"), permissionMode.add)],
    permissionMode,
    // Claude Code reads ENABLE_CLAUDEAI_MCP_SERVERS from its own environment.
    // Claude Code's automatic updates are off in this session (claude-terms.mjs): it stays a reviewed version.
    childEnv: { ...(admission?.mcp && !admission.mcp.connectors?.enabled ? { ENABLE_CLAUDEAI_MCP_SERVERS: "false" } : {}), ...SESSION_UPDATE_ENV },
    warnings: [...plan.warnings, ...built.warnings],
    settingsDir: s.dir,
    sessionFile: s.file,
    sessionDigest: s.digest,
    hookArgv: [process.execPath, HOOK_BIN, "--origin", "launcher", "--session", s.file, "--digest", s.digest],
    nonce: s.session.nonce,
    session: s.session,
    keepSettings: plan.background,
  };
}

/**
 * A stderr reader that calls `onDrop(line)` when Claude Code reports that the
 * settings file in `settingsDir` did not load. Claude Code prints the header
 * once and then one line per dropped file ("  <path> (<key>): <problem>").
 */
export function settingsDropWatcher(settingsDir, onDrop) {
  // Which stderr line reports this session's settings as dropped is the kit's (settings-drop.ts).
  return kit.settingsDropWatcher({ settingsDir, header: DROP_HEADER, onDrop });
}

/** One hook's identity, to tell a hook asked about at launch from a new one. */
function hookKey(h) {
  return JSON.stringify([h.scope, h.file, h.event, h.raw ?? h.command]);
}

/** The --settings values plus the plugins the person switched off for this session (what Claude Code will see). */
function settingsWithExclusion(plan) {
  const off = plan.hookExclusion?.disabledPlugins ?? [];
  return [...(plan.userSettings ?? []), ...(off.length ? [{ enabledPlugins: Object.fromEntries(off.map((id) => [id, false])) }] : [])];
}

/** Run claude and resolve with its exit. `control.onChild(child)` gets the process. */
export function runClaude(plan, { env = process.env, stderr = process.stderr, extraEnv = {}, onExit = () => {}, onChild = () => {}, onStderr = null, detached = false, containment = null } = {}) {
  for (const w of plan.warnings) {
    say(stderr, `${w}`);
  }
  return new Promise((resolve) => {
    // The session marker, and claude inside its own systemd scope when one
    // is available, so a halt reaches what escaped the tree (containment.mjs).
    const baseEnv = { ...env, ...extraEnv, ...(plan.childEnv ?? {}), ...(containment?.env ?? {}), ECWCODE_SESSION: "1", ECWCODE_VERSION: VERSION };
    delete baseEnv.ECWCODE_HW_BROKER;
    // The subreaper wrapper's own variables (containment.mjs) never reach claude.
    for (const k of Object.keys(baseEnv)) {
      if (k.startsWith("ECWCODE_WRAP_")) {
        delete baseEnv[k];
      }
    }
    let pathMarker = null;
    if (plan.settingsDir && plan.nonce && process.platform === "linux") {
      // The hook tells this session's shell snapshot apart by an empty directory of the session as
      // the last PATH entry (nothing can be found there, so no command resolves differently), and
      // bash reads no startup file for a command only at a shell level of 2 or more (shell-env.mjs).
      pathMarker = path.join(plan.settingsDir, "no-programs");
      fs.mkdirSync(pathMarker, { mode: 0o500 });
      baseEnv.PATH = baseEnv.PATH ? `${baseEnv.PATH}${path.delimiter}${pathMarker}` : pathMarker;
      if (!/^[0-9]{1,3}$/.test(baseEnv.SHLVL ?? "") || Number(baseEnv.SHLVL) < 1 || Number(baseEnv.SHLVL) > 998) {
        baseEnv.SHLVL = "1";
      }
    }
    if (plan.settingsDir && plan.nonce) {
      // The environment claude starts with, for the hook's map of its shell's environment (shell-env.mjs).
      const at = plan.args.indexOf("--settings");
      recordClaudeEnvironment({
        sessionDir: plan.settingsDir,
        nonce: plan.nonce,
        env: baseEnv,
        settingsFile: at >= 0 ? plan.args[at + 1] : null,
        settingSources: settingSourcesOf(plan.args),
        pathMarker,
      });
    }
    // The subreaper wrapper's interpreter gets its own variables moved aside
    // (containment.mjs perlWrapperEnv); it puts them back for claude.
    const childEnv = containment?.wrapEnv ? containment.wrapEnv(baseEnv) : baseEnv;
    const [cmd, cmdArgs] = containment ? containment.command(plan.claude, plan.args) : [plan.claude, plan.args];
    const child = spawn(cmd, cmdArgs, {
      // Headless: claude's stderr is read (and passed on) to catch a dropped
      // settings file at once (round 4, F1). An interactive claude keeps the
      // terminal exactly as it is.
      stdio: onStderr ? ["inherit", "inherit", "pipe"] : "inherit",
      env: childEnv,
      // On Windows, claude may be a .cmd shim, which needs a shell.
      shell: process.platform === "win32" && /\.cmd$/i.test(plan.claude),
      // Headless runs get their own process group, so a halt can stop claude
      // and everything it started at once (N7). An interactive claude must
      // stay in the terminal's foreground group to own the terminal; there
      // the halt stops its process tree instead (stopClaude).
      detached: detached && process.platform !== "win32",
    });
    if (onStderr && child.stderr) {
      child.stderr.on("data", (d) => {
        stderr.write(d);
        onStderr(d.toString("utf8"));
      });
    }
    if (containment && child.pid !== undefined) {
      // The launcher's children from here on may be the session's (CLONE_PARENT, containment.mjs).
      containment.startedAfter = procStartTime(child.pid);
      // macOS: track claude's descendants while it runs (containment.mjs, nets 5-7).
      containment.tracker?.start(child.pid);
      child.once("exit", () => containment.tracker?.stop());
    }
    onChild(child);
    const handlers = new Map();
    // The terminal sends SIGINT to the whole foreground process group, so an
    // attached claude already receives it; Enclawed Code just must not die from
    // it. A detached claude is not in that group: forward it.
    const onInt = () => {
      if (detached) {
        try {
          child.kill("SIGINT");
        } catch {
          /* gone */
        }
      }
    };
    process.on("SIGINT", onInt);
    for (const sig of FORWARDED_SIGNALS) {
      const h = () => {
        try {
          child.kill(sig);
        } catch {
          /* child gone */
        }
      };
      try {
        process.on(sig, h);
        handlers.set(sig, h);
      } catch {
        /* signal not supported on this platform */
      }
    }
    const cleanup = () => {
      process.off("SIGINT", onInt);
      for (const [sig, h] of handlers) {
        process.off(sig, h);
      }
      onExit();
    };
    child.on("error", (err) => {
      cleanup();
      say(stderr, `could not start ${plan.claude}: ${err.message}`);
      resolve({ code: 127, signal: null });
    });
    child.on("exit", (code, signal) => {
      cleanup();
      resolve({ code: code ?? null, signal: signal ?? null });
    });
  });
}

/** Exit the way the child did: same code, or the same signal. */
export function exitLikeChild({ code, signal }) {
  if (signal) {
    try {
      process.kill(process.pid, signal);
    } catch {
      /* fall through */
    }
    // If the signal did not end us (it is ignored or handled), use the shell convention.
    const num = { SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGKILL: 9, SIGTERM: 15 }[signal] ?? 1;
    process.exit(128 + num);
  }
  process.exit(code ?? 1);
}

/** Watch the audit log for the session.start record that carries `nonce`. */
export function watchHandshake(auditFile, nonce, { intervalMs = 200 } = {}) {
  let offset = 0;
  try {
    offset = fs.statSync(auditFile).size;
  } catch {
    offset = 0;
  }
  let seen = false;
  let rest = "";
  const check = () => {
    if (seen) {
      return true;
    }
    let size;
    try {
      size = fs.statSync(auditFile).size;
    } catch {
      return false;
    }
    if (size < offset) {
      offset = 0; // rotated or replaced: read again from the start
      rest = "";
    }
    if (size === offset) {
      return false;
    }
    const fd = fs.openSync(auditFile, "r");
    try {
      const buf = Buffer.alloc(size - offset);
      fs.readSync(fd, buf, 0, buf.length, offset);
      offset = size;
      const text = rest + buf.toString("utf8");
      const lines = text.split("\n");
      rest = lines.pop() ?? "";
      for (const l of lines) {
        if (l.includes(nonce)) {
          try {
            const r = JSON.parse(l);
            // A raw line with the nonce is not enough (N2): the record must be
            // a genuine link of the hash chain.
            if (r.type === "claude-code.session.start" && r.payload?.launcherNonce === nonce && verifyChainedRecord(auditFile, r.recordHash).ok) {
              seen = true;
            }
          } catch {
            /* not a record */
          }
        }
      }
    } finally {
      fs.closeSync(fd);
    }
    return seen;
  };
  return { check, get seen() {
    return check();
  }, intervalMs };
}

/**
 * Stop claude and everything it started (N7): the process group when claude
 * has its own, plus its whole process tree and the groups its descendants
 * lead (hook and tool commands run in sessions of their own), first with
 * SIGTERM, then SIGKILL for whatever is left after `waitMs`. The tree is
 * captured before the first signal, because orphans are re-parented.
 */
export function stopClaude(child, { detached = false, waitMs = 3000, table = processTable, containment = null, env = process.env, launcherChildren = false } = {}) {
  if (((process.platform === "linux" && table === processTable) || containment?.tracker) && child?.pid !== undefined) {
    // N7b: kill everything the session started (claude kept alive as the
    // subreaper until its subtree is gone), then claude, then verify.
    // An exited claude's pid may already belong to another process: never signal it.
    const running = child.exitCode === null && child.signalCode === null;
    // macOS has no CLONE_PARENT: the launcher's own children are never the session's there.
    return killSession(running ? child.pid : null, containment, { graceMs: waitMs, launcherChildren: launcherChildren && !containment?.tracker, env });
  }
  return new Promise((resolve) => {
    if (!child || child.pid === undefined) {
      resolve({ verified: true, survivors: [], killed: 0 });
      return;
    }
    const pid = child.pid;
    const own = table().find((p) => p.pid === process.pid)?.pgid ?? null;
    const remembered = { pids: new Set([pid]), groups: new Set(detached ? [pid] : []) };
    const capture = () => {
      for (const p of processTree(pid, table())) {
        remembered.pids.add(p.pid);
        if (p.pgid > 1 && p.pgid !== own) {
          remembered.groups.add(p.pgid);
        }
      }
      remembered.pids.delete(process.pid);
    };
    const signalAll = (sig) => {
      // The scope's cgroup and the marked processes (N12): what left the tree.
      signalContainment(containment, sig, { env });
      for (const g of remembered.groups) {
        try {
          process.kill(-g, sig);
        } catch {
          /* gone */
        }
      }
      for (const p of remembered.pids) {
        try {
          process.kill(p, sig);
        } catch {
          /* gone */
        }
      }
    };
    capture();
    const alive = child.exitCode === null && child.signalCode === null;
    signalAll("SIGTERM");
    const finish = () => {
      // Whatever survived SIGTERM, or was started meanwhile. Not verified:
      // without /proc the subtree cannot be re-read reliably.
      signalAll("SIGKILL");
      setTimeout(() => resolve({ verified: null, survivors: [], killed: 0 }), 200);
    };
    if (!alive) {
      setTimeout(finish, Math.min(waitMs, 500));
      return;
    }
    const t = setTimeout(() => {
      capture();
      finish();
    }, waitMs);
    child.once("exit", () => {
      clearTimeout(t);
      setTimeout(finish, 300);
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Start the detached watcher (erase-watch.mjs, round 3 N7b) that keeps
 * re-checking the erased login for `seconds` with backoff, outliving the
 * launcher. Best effort: revocation at claude.ai is the real control.
 * @returns {{ pid: number, seconds: number, log: string } | null}
 */
export function startEraseWatcher({ env, seconds = 60, logDir }) {
  if (!(seconds > 0)) {
    return null;
  }
  try {
    fs.mkdirSync(logDir, { recursive: true, mode: 0o700 });
    const envFile = path.join(logDir, `erase-watch-env.${process.pid}.${Date.now()}.json`);
    // Only what locates Claude Code's login and the keyring tools.
    const keep = {};
    for (const k of ["HOME", "USER", "LOGNAME", "PATH", "CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]) {
      if (env[k] !== undefined) {
        keep[k] = env[k];
      }
    }
    fs.writeFileSync(envFile, JSON.stringify(keep), { mode: 0o600 });
    const log = path.join(logDir, "erase-watch.jsonl");
    const w = spawn(process.execPath, [path.join(APP_ROOT, "src", "erase-watch.mjs"), envFile, String(seconds), log], { detached: true, stdio: "ignore", env: { PATH: keep.PATH ?? "/usr/bin:/bin" } });
    w.unref();
    return { pid: w.pid, seconds, log };
  } catch {
    return null;
  }
}

/**
 * Erase Claude Code's login, then watch for a few seconds and erase again
 * if something writes it back (N7). Erasing is not revocation: a copy taken
 * earlier keeps working until it is revoked at claude.ai. The launcher then
 * hands the longer watch to startEraseWatcher.
 */
export async function eraseAndRecheck({ env, checks = 5, intervalMs = 1000, erase = eraseClaudeCredentials } = {}) {
  const first = erase({ env });
  const out = { erased: [...first.erased], remaining: [...first.remaining], notes: [...first.notes], reappeared: 0 };
  const file = claudeCredentialLocations(env).file;
  for (let i = 0; i < checks; i++) {
    await sleep(intervalMs);
    if (fs.existsSync(file)) {
      out.reappeared++;
      const again = erase({ env });
      out.remaining = again.remaining;
    }
  }
  if (out.reappeared > 0) {
    out.notes.push(`the login file was written back ${out.reappeared} time(s) after the erase and erased again; another Claude Code process may still hold the token`);
  }
  return out;
}

/**
 * The launch's admission decisions (workflow.mjs, skills.mjs, mcp.mjs), each
 * recorded in the audit log. Refused: { ok: false, message }.
 */
export async function admitLaunch(plan, { env, cwd, fw, loaded, audit, stderr, formalLoader = loadFormal }) {
  const projectDir = realpathNearest(path.resolve(cwd));
  const refuse = async (reason, message, payload = {}) => {
    await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason, detail: String(message).slice(0, 2000), ...payload } }).catch(() => {});
    return { ok: false, message };
  };
  // 1. The workflow profile: --workflow, or the policy's project binding.
  const sel = selectWorkflow({ requested: plan.workflow ?? null, options: loaded.options, projectDir });
  if (!sel.ok) {
    return refuse("workflow", `${sel.message}; not starting claude`);
  }
  if (plan.managed && plan.workflow) {
    return refuse("workflow", "--workflow needs Enclawed Code's per-session hooks, and this machine runs Enclawed's managed hooks; bind the workflow to the project in the managed policy (enclawedCode.projectWorkflows) instead");
  }
  const workflow = sel.profile ? { name: sel.profile.name, source: sel.source, digest: profileDigest(sel.profile), ...(sel.boundTo ? { boundTo: sel.boundTo } : {}), profile: sel.profile } : null;
  await recordWorkflow({ env, audit, projectDir, workflow });
  if (workflow) {
    say(stderr, `workflow "${workflow.name}" (${workflow.source === "flag" ? "--workflow" : `bound to ${workflow.boundTo}`}): anything outside it is denied`);
  }
  // 2. Skills: every skill Claude Code would load, verified by the biconditional criterion.
  let formal;
  try {
    formal = await formalLoader();
  } catch (err) {
    return refuse("skills", `cannot load the skill verifier (${err.message}); not starting claude`);
  }
  const ss = optionValues(plan.args ?? [], "--setting-sources");
  const settingSources = ss.length ? ss.join(",").split(",").map((x) => x.trim()).filter(Boolean) : null;
  const sk = admitSkills({ formal, projectDir, env, addDirs: plan.addDirs ?? [], pluginDirs: plan.pluginDirs ?? [], settingSources, extraSettings: settingsWithExclusion(plan), mode: loaded.options.skills?.unverified ?? "refuse" });
  // Kept small: one audit record must stay well under the log readers' tail window.
  const skillSummary = sk.results.slice(0, 12).map((r) => ({ name: r.name.slice(0, 80), scope: r.scope, status: r.status, ...(r.reasons.length ? { reason: r.reasons[0].slice(0, 120) } : {}) }));
  if (sk.results.length > 12) {
    skillSummary.push({ more: sk.results.length - 12, notAdmissible: sk.results.filter((r) => r.status !== "verified").length });
  }
  if (!sk.ok) {
    return refuse("skills-not-admissible", `${sk.message}; not starting claude`, { skills: skillSummary });
  }
  for (const w of sk.warnings) {
    say(stderr, `${w}`);
  }
  // 3. MCP servers: only pinned or attested ones start, behind the proxy.
  let mcp = null;
  if (!plan.managed) {
    let candidates;
    try {
      candidates = candidateServers({ projectDir, env, mcpConfigValues: plan.mcpConfigValues ?? [], cwd });
    } catch (err) {
      return refuse("mcp", `${err.message}; not starting claude`);
    }
    mcp = admitServers({ fw, env, candidates, cwd: projectDir });
    if (!mcp.ok) {
      return refuse("mcp-shadowing", `${mcp.message}`);
    }
    // claude.ai connectors: on only when the policy lists some of their
    // tools and, under a workflow, the profile's mcpTools lists one too.
    const allow = (loaded.options.claudeAiConnectors ?? []).filter((t) => !workflow || workflow.profile.mcpTools.some((p) => p === t || (p.endsWith("__*") && t.startsWith(p.slice(0, -1))) || (t.endsWith("__*") && p.startsWith(t.slice(0, -1)))));
    // --strict-mcp-config also stops claude.ai connectors (2.1.326), so
    // admitting them means leaving it out, which is safe only when no other
    // MCP source would start a server: none configured (user, local,
    // project), none from an enabled plugin.
    const others = candidates.filter((c) => c.scope !== "--mcp-config");
    const pluginMcp = enabledPluginRoots({ configDir: env.CLAUDE_CONFIG_DIR || path.join(env.HOME || "", ".claude"), projectDir, settingSources, extraSettings: settingsWithExclusion(plan) }).filter((d) => {
      if (fs.existsSync(path.join(d, ".mcp.json"))) {
        return true;
      }
      try {
        return JSON.parse(fs.readFileSync(path.join(d, ".claude-plugin", "plugin.json"), "utf8"))?.mcpServers !== undefined;
      } catch {
        return false;
      }
    });
    if (allow.length > 0 && (others.length > 0 || pluginMcp.length > 0)) {
      say(stderr, `claude.ai connectors stay off: admitting them means not passing --strict-mcp-config, and other MCP servers are configured here (${[...others.map((c) => `${c.name} (${c.scope})`), ...pluginMcp.map((d) => `plugin ${path.basename(d)}`)].slice(0, 4).join(", ")}) that would then start unchecked`);
      allow.length = 0;
    }
    mcp.connectors = { enabled: allow.length > 0, allow };
    mcp.strict = !mcp.connectors.enabled;
    // Off is the default and said once (the first launch's welcome) and by ecwctl doctor; on is said.
    if (allow.length) {
      say(stderr, `claude.ai connectors allowed for this session: only ${allow.join(", ")}`);
    }
    for (const x of mcp.skipped) {
      // Switched off for this session (security-relevant): what it is for and how to change it.
      say(stderr, `MCP server ${JSON.stringify(x.name)} (${x.scope}) is not started (${x.why}): only pinned servers run, so a server's code and tools are the ones checked; to admit it: ecwctl mcp pin ${x.name}`);
    }
  }
  await audit
    .append({
      type: "claude-code.launch.admission",
      actor: "enclawed-code",
      level: null,
      payload: {
        workflow: workflow ? { name: workflow.name, source: workflow.source, digest: workflow.digest } : null,
        skills: skillSummary,
        claudeAiConnectors: mcp?.connectors ?? null,
        mcp: mcp ? { admitted: mcp.admitted.slice(0, 20).map((a) => ({ name: a.name, scope: a.scope, signer: a.record.signerKeyId, tools: Object.keys(a.record.tools ?? {}).length })), skipped: mcp.skipped.slice(0, 20).map((x) => ({ name: String(x.name).slice(0, 80), scope: x.scope, why: x.why.slice(0, 120) })) } : null,
      },
    })
    .catch(() => {});
  return { ok: true, admission: { workflow, skills: sk, skillsBundled: loaded.options.skills?.bundled ?? "off", mcp } };
}

/**
 * Repository configuration changed mid-session (a contained git checked it
 * out): the same launch-time admission again, over the files as they are now
 * (prepareLaunch's repository rules: env, hooks, command settings, .mcp.json
 * servers; then admitLaunch: workflow, skills, MCP). For kit.handleRepoConfigEvent.
 * @returns {Promise<{ ok: true } | { ok: false, refusals: string[] }>}
 */
export async function readmitRepository({ launchArgv = [], env, cwd, fw, loaded, audit, stderr, excludedHooks = [] }) {
  const again = prepareLaunch(launchArgv, { env, cwd });
  if (!again.ok) {
    return { ok: false, refusals: [again.message] };
  }
  // Ungranted hooks were asked about once, at the launch: one that was not declined then is not admitted now.
  const declined = new Set(excludedHooks);
  const fresh = (again.hookQuestion?.hooks ?? []).filter((h) => !declined.has(hookKey(h)));
  if (fresh.length > 0) {
    return { ok: false, refusals: [again.hookQuestion.refusal.replace(/ You chose not to start without (it|them)$/, "")] };
  }
  const a = await admitLaunch(again, { env, cwd, fw, loaded, audit, stderr });
  return a.ok ? { ok: true } : { ok: false, refusals: [a.message] };
}

/** Audit a change of the workflow a project runs under (since its last launch). */
async function recordWorkflow({ env, audit, projectDir, workflow }) {
  const file = path.join(stateDir(env), "claude-code", "workflow-last.json");
  let last = {};
  try {
    last = JSON.parse(fs.readFileSync(file, "utf8")) ?? {};
  } catch {
    last = {};
  }
  const prev = last[projectDir] ?? null;
  const now = workflow ? { name: workflow.name, digest: workflow.digest, source: workflow.source } : null;
  if ((prev?.name ?? null) !== (now?.name ?? null) || (prev?.digest ?? null) !== (now?.digest ?? null)) {
    await audit.append({ type: "claude-code.workflow.change", actor: "enclawed-code", level: null, payload: { projectDir, from: prev, to: now } }).catch(() => {});
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      fs.writeFileSync(`${file}.tmp`, JSON.stringify({ ...last, [projectDir]: now }), { mode: 0o600 });
      fs.renameSync(`${file}.tmp`, file);
    } catch {
      /* the audit record is the evidence */
    }
  }
  await audit.append({ type: "claude-code.workflow.select", actor: "enclawed-code", level: null, payload: { projectDir, workflow: now } }).catch(() => {});
}

/** Is a hardware root in use on this machine (for the auth requirement)? */
function hardwareInUse(env, root) {
  // `env` is the launcher's resolved environment: ENCLAWEDER_ROOT there is
  // unset, "required" or (admin-granted) "optional" (env-authority.mjs).
  if (root?.mode === "held" || root?.mode === "halted" || env.ENCLAWEDER_ROOT === "required") {
    return true;
  }
  const latch = hardwareLatchPaths(env);
  try {
    return fs.existsSync(latch.file) || fs.readdirSync(latch.dir).some((f) => /^\.enclawed-hw-root\./.test(f));
  } catch {
    return false;
  }
}

export async function main(argv = process.argv.slice(2), env = { ...process.env }) {
  setProgram("ecwcode");
  let plan;
  try {
    plan = prepareLaunch(argv, { env });
  } catch (err) {
    process.exit(fail(process.stderr, err.message));
  }
  if (!plan.ok) {
    // A refused start still says which shell settings were ignored.
    const auth = launchAuthority(env);
    for (const w of auth.ok ? auth.warnings : []) {
      say(process.stderr, `${w}`);
    }
    process.exit(fail(process.stderr, plan.message, plan.code));
  }
  if (!plan.session) {
    exitLikeChild(await runClaude(plan, { env }));
    return;
  }
  if (plan.hookQuestion) {
    // Hooks with no administrator's grant: asked on the terminal, per launch (hook-exclusion.mjs).
    const configDir = env.CLAUDE_CONFIG_DIR || path.join(env.HOME || os.homedir(), ".claude");
    const groups = groupBySource(plan.hookQuestion.hooks, { configDir });
    const yes = await askOnTerminal(questionText(groups, `${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME}`), { ttyPath: authority().approvalTty });
    if (!yes) {
      process.exit(fail(process.stderr, plan.hookQuestion.refusal, 2));
    }
    const ex = excludeHooks(plan, plan.hookQuestion.hooks, { cwd: process.cwd(), configDir });
    if (!ex.ok) {
      process.exit(fail(process.stderr, ex.message, 2));
    }
    plan = { ...ex.plan, hookExclusionRecord: ex.record };
  }
  // Kept for re-admitting repository configuration a contained git checks out mid-session.
  plan.launchArgv = argv;
  const code = await launchSession(plan, { env, ownProcess: true });
  if (typeof code === "object") {
    exitLikeChild(code);
  }
  process.exit(code);
}

/**
 * Everything after prepareLaunch for a session: framework, hardware root,
 * auth, session file, claude, handshake, halt monitor.
 * @returns {Promise<number | { code: number|null, signal: string|null }>}
 */
export async function launchSession(plan, { env = process.env, cwd = process.cwd(), stderr = process.stderr, load = loadFramework, hold = holdSessionRoot, interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY), ownProcess = false, containmentFor = sessionContainment } = {}) {
  // Same authority as prepareLaunch (whose warnings already went out with
  // the plan); recorded in the audit log below on every start.
  const auth = launchAuthority(env);
  if (!auth.ok) {
    return fail(stderr, auth.message);
  }
  env = auth.env;
  if (ownProcess) {
    // The framework reads process.env directly (hardware root, forensics).
    replaceEnvInPlace(process.env, env);
  }
  let fw;
  try {
    ({ fw } = await load());
  } catch (err) {
    return fail(stderr, `cannot load the enclawed framework (${err.message}); not starting claude`);
  }
  const audit = new LockedAuditLog(fw, auditLogPath(env));
  let loaded;
  try {
    // The flavor: the managed policy's, raised (never lowered) by the shell
    // (policy.mjs loadPolicy); user policy files layer tighten-only over it.
    loaded = loadPolicy(fw, { candidates: policyCandidates(env, { fw }), flavor: auth.shellFlavor.flavor });
  } catch (err) {
    return fail(stderr, `${err.message}; not starting claude`);
  }
  const flavor = loaded.flavor;
  // The framework and the session file must see the same flavor.
  env = { ...env, ENCLAWED_FLAVOR: flavor };
  if (ownProcess) {
    process.env.ENCLAWED_FLAVOR = flavor;
  }
  if (loaded.note) {
    say(stderr, `${loaded.note}`);
  }
  for (const r of loaded.refused ?? []) {
    say(stderr, `ignoring ${r} from ${loaded.source}: a user policy file can only tighten the organization's policy (${loaded.baseSource})`);
  }
  const g = auth.grants;
  const used = plan.grantsUsed ?? { projectHooks: [], projectCommands: [] };
  const loader = auth.loader ?? { removed: [], granted: [] };
  if (g.retired.length > 0 || g.files.length > 0 || g.notes.length > 0 || auth.dropped.length > 0 || loader.removed.length > 0 || loader.granted.length > 0 || (loaded.refused ?? []).length > 0) {
    await audit
      .append({
        type: "claude-code.launch.opt-outs",
        actor: "enclawed-code",
        level: null,
        payload: {
          retiredFromShell: g.retired.map((r) => r.name),
          grantFiles: g.files,
          granted: {
            reducedContainment: g.grants.reducedContainment,
            hardwareRoot: g.grants.hardwareRoot,
            forensicWebhook: g.grants.forensicWebhook !== null,
            loaderEnv: loader.granted,
            projectHooks: used.projectHooks,
            projectCommands: used.projectCommands,
            hooks: used.hooks ?? [],
          },
          droppedFrameworkEnv: auth.dropped,
          removedLoaderEnv: loader.removed,
          policyRefused: loaded.refused ?? [],
          flavor,
          notes: g.notes,
        },
      })
      .catch(() => {});
  }

  // Hooks with no grant that the person chose, at main()'s question, to start without (hook-exclusion.mjs).
  if (plan.hookQuestion && !plan.hookExclusion) {
    return fail(stderr, plan.hookQuestion.refusal);
  }
  if (plan.hookExclusionRecord) {
    await audit.append({ type: "claude-code.launch.hooks-excluded", actor: "enclawed-code", level: null, payload: plan.hookExclusionRecord });
    say(stderr, `${exclusionLine(plan.hookExclusionRecord)}`);
  }

  // Admission, before anything is held or started: the workflow profile,
  // the skills Claude Code would load, and the MCP servers it may start.
  const admitted = await admitLaunch(plan, { env, cwd, fw, loaded, audit, stderr });
  if (!admitted.ok) {
    return fail(stderr, admitted.message, admitted.code ?? 2);
  }
  const admission = admitted.admission;

  // Repository hooks other than PreToolUse: refused in the enclaved flavor (N3).
  // prepareLaunch refuses every ungranted one; this re-checks the plan.
  const ungranted = (plan.projectHooks ?? []).find((h) => !h.grant);
  if (flavor === "enclaved" && ungranted) {
    return fail(stderr, `${ungranted.file} adds a ${ungranted.event} hook, which runs repository code in the session; the enclaved flavor does not start with repository hooks that ${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME} does not grant (projectHooks)`);
  }

  // Background sessions outlive this process: no held root, no halt
  // monitor, no credential erase (N6). Where a hardware root is in use that
  // guarantee matters, so they are refused.
  if (plan.background && (env.ENCLAWEDER_ROOT === "required" || hardwareInUse(env, null))) {
    return fail(
      stderr,
      "background sessions (--bg, agents) cannot hold the hardware root, so a halt would neither stop them nor erase the login; with a hardware root in use, run the session in the foreground",
    );
  }

  // N16: never boot the hardware root from a user namespace with a device visible.
  const nsRisk = userNamespaceDeviceRisk();
  if (nsRisk) {
    await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: "user-namespace-device", detail: nsRisk } }).catch(() => {});
    return fail(stderr, `not starting: ${nsRisk}`, EXIT_HARDWARE_HALT);
  }
  // The hardware root: held for a foreground session.
  const root = plan.background ? null : await hold(fw);
  if (root?.mode === "halted") {
    root.release();
    await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: "hardware-halted", detail: root.reason } }).catch(() => {});
    return fail(
      stderr,
      `the hardware root refused to start (${root.reason}). Nothing was started. If the Enclaweder latched DIRTY, recover it with the genuine device: ` +
        "ecwctl recover-root (then log in to Claude Code again if its login was erased)",
      EXIT_HARDWARE_HALT,
    );
  }

  // The command-set pin (the kit's commandSetPin): with the root required, a
  // launch starts only on the Enclaweder's own signed proof of command set 0.5
  // (an owner claiming older firmware would get the launch's unlock use
  // relayed in the clear). Asked before activation, so nothing is spent on a
  // device that fails it; without the root required, what an older device
  // leaves open goes into the launch record.
  const pin = await launchCommandSetPin({ fw, rootRequired: env.ENCLAWEDER_ROOT === "required", held: root?.mode === "held" });
  if (!pin.ok) {
    root?.release();
    await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: "command-set", code: pin.code, proof: pin.proof.status } }).catch(() => {});
    return fail(stderr, `not starting: ${pin.message}`, EXIT_HARDWARE_HALT);
  }
  const residuals = pin.residual ? [pin.residual] : [];

  // The session's devices and the device anchor, checked on the log as found
  // BEFORE claude starts (round 5, R5-A): a log, anchor file or anchor history
  // that does not match what the device anchored would otherwise be laundered
  // by this session. Both run before the activation below: neither spends
  // anything on the device (the gate is a fresh ANCHOR_READ over our own
  // nonce, ANCHOR_GET and the files), so a launch the gate refuses never
  // costs a device-unlock use.
  let device = null;
  if (root?.mode === "held") {
    try {
      device = await sessionDevice(fw);
    } catch {
      device = null;
    }
    if (!device) {
      // Held mode with no attestable device is a refusal, never "no attestation"
      // (red-team H15: a root with two members used to give null here, and every
      // hook call then ran on the owner's word alone).
      root.release();
      return fail(
        stderr,
        "the hardware root is held, but its devices could not be attested (every member's certificate and a fresh device signature are required). Nothing was started.",
        EXIT_HARDWARE_HALT,
      );
    }
    const gate = await launchAnchorGate(fw, device, auditLogPath(env), { rootRequired: env.ENCLAWEDER_ROOT === "required" }).catch((err) => ({ ok: false, status: "error", code: "check-failed", detail: `the device anchor could not be checked: ${err.message}`, counter: null }));
    if (!gate.ok) {
      await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: "anchor-not-matched", status: gate.status, code: gate.code, detail: String(gate.detail).slice(0, 1000), counter: gate.counter, ...(device.anchorRefused ? { anchorRefused: { code: device.anchorRefused.code, reason: String(device.anchorRefused.reason).slice(0, 500) } } : {}) } }).catch(() => {});
      root.release();
      return fail(stderr, anchorRefusalMessage(gate, auditLogPath(env)), EXIT_ANCHOR_REFUSED);
    }
    // Also before the activation: a launch the login step or the sealed session state would refuse
    // for a local reason (memory others can read, a sealed store that is not what the log recorded)
    // is refused here, so the refusal spends nothing.
    const pre = loginLaunchPrecheck({ deviceBound: true });
    const preState = pre.ok ? await sessionStatePrecheck({ env }).catch((e) => ({ ok: false, code: "error", message: e.message })) : pre;
    if (!preState.ok) {
      await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: pre.ok ? "session-state" : "login", code: preState.code, beforeActivation: true } }).catch(() => {});
      root.release();
      return fail(stderr, `${preState.message}; not starting claude (nothing was spent on the Enclaweder)`);
    }
  }

  // Activation: the kit's (kit.activateSession over the framework's
  // two-factor gate), one factor per verification. With an Enclaweder held, the
  // factor is one this host cannot forge (attack 7): a code the DEVICE verifies
  // at a terminal, or, for a headless start, one use of a device unlock it
  // counts; a held device that cannot be asked refuses the launch (never the
  // passkey instead). Without one: the passkey or security key, or its ticket.
  const activeTerminal = interactive && !plan.print;
  // The measured launch and the effective policy (commitments.mjs), measured
  // by the launcher before anything starts: approved below, committed per
  // call, and the job a device unlock is bound to.
  let measurement = null;
  let measurementError = null;
  const effective = effectivePolicy(loaded);
  if (root?.mode === "held") {
    try {
      measurement = measureLaunch();
    } catch (err) {
      measurementError = err.message;
    }
  }
  const jobOf = (name) =>
    measurement ? launchJob({ name, measurementDigest: measurement.digest, policyDigest: effective.digest, projectDir: cwd, kind: plan.print ? "headless:print" : "headless" }) : null;
  try {
    const ctx = await launchAuthContext({ env, interactive: activeTerminal, passphraseFd: plan.passphraseFd, audit: (r) => audit.append(r), readCode: (q) => ask(q) });
    // One factor (device-activation.mjs activateLaunch): with the Enclaweder held, only the code it
    // verifies (or its counted unlock, headless); without it, only the passkey or security key.
    await activateLaunch(ctx, { fw, env, held: root?.mode === "held", interactive: activeTerminal, job: jobOf });
  } catch (err) {
    root?.release();
    return fail(stderr, `not starting: ${launchAuthMessage(err, env)}`, EXIT_AUTH);
  }

  // The session file, the relay and the settings.
  let relay = null;
  // The session's commitment ledger (held root only) and what to do with each commitment.
  let ledger = null;
  let onCommitted = () => {};
  if (device) {
    try {
      // A short socket path, in a private directory outside the project.
      const dir = fs.mkdtempSync(path.join(sessionRoot(env, realpathNearest(path.resolve(cwd))), "h-"));
      fs.chmodSync(dir, 0o700);
      relay = await startHardwareRelay({
        socketPath: path.join(dir, "hw.sock"),
        health: heldRelayHealth(fw, device, (dev, nonce) => attest(dev, nonce, fw)),
        // Per-call commitments (commitments.mjs), once the session's ledger exists.
        commit: async (call, policyDigest) => {
          if (!ledger) {
            throw new Error("the session has not started; nothing is committed yet");
          }
          const ev = await ledger.commit(call, policyDigest);
          onCommitted(call?.callId, call?.decision);
          return ev;
        },
      });
      relay.dir = dir;
    } catch (err) {
      root.release();
      return fail(stderr, `cannot start the hardware relay (${err.message}); not starting claude`);
    }
  }
  // The measured launch and the approved policy (commitments.mjs): measured
  // HERE, by the launcher, before claude starts. With the hardware root
  // required, both must carry a device-signed approval, else nothing starts.
  if (device) {
    const refuse = async (reason, detail, message) => {
      await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason, detail: String(detail).slice(0, 1000) } }).catch(() => {});
      await relay?.close();
      if (relay?.dir) {
        fs.rmSync(relay.dir, { recursive: true, force: true });
      }
      root?.release();
      return fail(stderr, message, EXIT_AUTH);
    };
    if (!measurement) {
      return refuse("measurement-failed", measurementError ?? "not measured", `Enclawed Code could not measure its own code (${measurementError}); not starting claude`);
    }
    const gate = kit.decideApprovalGate({
      rootRequired: env.ENCLAWEDER_ROOT === "required",
      approvalsFile: approvalsFile(env),
      devices: approvingDevices(device),
      measurementDigest: measurement.digest,
      policyDigest: effective.digest,
      policyNeedsApproval: effective.needsApproval,
    });
    if (!gate.ok) {
      return refuse(gate.code, `${gate.digest}: ${gate.reason}`, `not starting: ${approvalRefusalMessage(gate)}`);
    }
  }
  let full = plan;
  if (!plan.managed) {
    try {
      full = materializeSession(plan, { env, cwd, fw, approval: interactive, admission, hardware: relay ? { mode: "relay", relay: { path: relay.path, secret: relay.secret }, device: device ? { pub: device.pub, uid: device.uid, serial: device.serial, ...(device.kind === "members" ? { pubs: device.members.map((m) => m.pub) } : {}) } : null } : null });
    } catch (err) {
      await relay?.close();
      root?.release();
      return fail(stderr, err.message);
    }
  }
  // Interactive: the real claude checks the same settings once, headless,
  // before the interactive launch (round 5, N13c; prevalidate.mjs), since an
  // interactive claude's own "did not load" message cannot be read.
  if (interactive && !plan.print && !plan.background && full.settingsDir && authority().prevalidate) {
    const settingsFile = full.args[full.args.indexOf("--settings") + 1];
    const t0 = Date.now();
    const pv = await prevalidateSettings({ claude: plan.claude, settingsFile, settingsDir: full.settingsDir, env, cwd, dropWatcher: settingsDropWatcher });
    await audit.append({ type: "claude-code.launch.prevalidated", actor: "enclawed-code", level: null, payload: { nonce: full.nonce ?? null, ok: pv.ok, ran: pv.ok ? pv.ran : true, ms: Date.now() - t0 } }).catch(() => {});
    if (!pv.ok) {
      await audit.append({ type: "claude-code.launch.settings-dropped", actor: "enclawed-code", level: null, payload: { nonce: full.nonce ?? null, detail: pv.line.slice(0, 500), prevalidated: true } }).catch(() => {});
      await relay?.close();
      if (relay?.dir) {
        fs.rmSync(relay.dir, { recursive: true, force: true });
      }
      root?.release();
      fs.rmSync(full.settingsDir, { recursive: true, force: true });
      return fail(stderr, `Claude Code reports that it would not load Enclawed Code's settings file (${pv.line.slice(0, 200)}); not starting claude: no tool call would be checked. Fix the --settings value it names, or the setting it complains about`);
    }
  }
  // With a device bound: Claude Code keeps the session's login in Enclawed Code's login directory (never read
  // here; erased on a halt), or a sealed API key reaches the model through the relay (claude-login.mjs).
  const login = await openLoginForSession({ env, sessionDir: full.settingsDir, device, rootRequired: env.ENCLAWEDER_ROOT === "required", audit: (r) => audit.append(r) }).catch((e) => ({ ok: false, code: "error", message: e.message }));
  if (!login.ok) {
    await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: "login", code: login.code } }).catch(() => {});
    await relay?.close();
    root?.release();
    fs.rmSync(full.settingsDir, { recursive: true, force: true });
    return fail(stderr, `${login.message}; not starting claude`);
  }
  // The root takeover (session-state.mjs): the person's Claude Code context and the credentials the
  // session's tools make are opened from their sealed stores into private directories, and sealed
  // again at the end; then the launch forgets every opening key (its boxes seal, open nothing).
  const state = login.ok && login.action !== "pass" && login.boxes ? await openSessionState({ env, cwd, boxes: login.boxes, audit: (r) => audit.append(r) }).catch((e) => ({ ok: false, code: "error", message: e.message })) : { ok: true, action: "pass" };
  kit.forgetLaunchCredentialKeys();
  if (!state.ok) {
    await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: "session-state", code: state.code } }).catch(() => {});
    await discardSessionLogin(login);
    await relay?.close();
    root?.release();
    fs.rmSync(full.settingsDir, { recursive: true, force: true });
    return fail(stderr, `${state.message}; not starting claude`);
  }
  if (state.plaintextOutside?.length) {
    say(stderr, `note: Claude Code's own directory holds plaintext session context made outside Enclawed Code (${state.plaintextOutside.join(", ")}); any process of this user can resume it. This session's context is sealed apart from it.`);
    await audit.append({ type: "claude-code.context.plaintext-outside", actor: "enclawed-code", level: null, payload: { names: state.plaintextOutside } }).catch(() => {});
  }
  if (login.notice) {
    say(stderr, `note: ${login.notice}`);
  }
  env = login.applyEnv ? login.applyEnv(env) : env;
  env = state.applyEnv ? state.applyEnv(env) : env;
  const nonce = full.nonce ?? null;
  const launchRecord = await audit
    .append({
      type: "claude-code.launch",
      actor: "enclawed-code",
      level: null,
      payload: {
        nonce,
        cwd: realpathNearest(cwd),
        managed: plan.managed,
        background: plan.background,
        print: plan.print,
        hardware: root?.mode ?? "per-call",
        // How the login's key was had (command set 0.5: KEY_DERIVE), and what an older device leaves open.
        ...(login.keyDerivation ? { keyDerivation: login.keyDerivation } : {}),
        // The session's context and tool credentials sealed at rest (session-state.mjs).
        ...(state.action === "sealed" ? { sessionState: "sealed" } : {}),
        // How the session authenticates: Claude Code's own login (never read by Enclawed Code), or a sealed API key through the relay.
        login: login.action,
        ...([...residuals, ...(login.residual ? [login.residual] : [])].length ? { residuals: [...new Set([...residuals, ...(login.residual ? [login.residual] : [])])] } : {}),
        policy: { source: loaded.source, kind: loaded.kind },
        version: VERSION,
        workflow: admission.workflow ? { name: admission.workflow.name, source: admission.workflow.source, digest: admission.workflow.digest } : null,
        // What every committed call is checked against (audit verify).
        ...(device && measurement && nonce ? { commitments: commitmentLaunchRecord({ nonce, required: true, policy: effective, measurement, device }) } : {}),
      },
    })
    .catch((err) => {
      say(stderr, `could not audit the launch: ${err.message}`);
      return null;
    });

  // Held root: every decision of this session is committed by the device, in order.
  if (device && measurement && nonce) {
    ledger = new CommitLedger({
      sessionNonce: nonce,
      policyDigest: effective.digest,
      measurementDigest: measurement.digest,
      stamps: measurement.stamps,
      attest: (commitment) => attest(device, commitment, fw),
    });
  }
  // Anchor the audit log's head in the device while the session runs.
  let anchorAlarm = null;
  // The launcher holds the anchor session (with firmware that has it, the
  // framework opens it lazily, and its key stays in this process); the hook
  // only asks over the control socket (N10, docs/anchor-auth-design.md).
  const anchoring = device
    ? startAnchoring(fw, device, auditLogPath(env), {
        onError: (e) => say(stderr, `device anchor: ${e.message}`),
        // An alarm, not a transient error: something else holds or held the
        // device's anchor channel (BUSY), or opened it while ours was down
        // (HIJACKED). Loud message, audit record, and the session is stopped.
        onAlarm: async (e) => {
          if (anchorAlarm) {
            return;
          }
          anchorAlarm = e;
          say(stderr, `ALARM ${e.code ?? "HeadAnchorAlarm"}: ${e.message}. ${anchorAlarmAdvice(e)}`);
          await audit.append({ type: "claude-code.launch.anchor-alarm", actor: "enclawed-code", level: null, payload: { nonce, code: e.code ?? null, message: e.message } }).catch(() => {});
          unchecked ??= `anchor alarm ${e.code ?? ""}`.trim();
          await stop();
        },
        // The log, the anchor file or the anchor history changed under the
        // session (round 4, N14): nothing more is anchored, claude is stopped.
        onTamper: async (e) => {
          if (anchorAlarm) {
            return;
          }
          anchorAlarm = e;
          say(stderr, `ALARM ANCHOR_TAMPER: ${e.message}. Something rewrote the audit log or its anchor files during this session; Enclawed Code anchors nothing more and is stopping claude. Keep the files as they are and run: ecwctl audit verify`);
          await audit.append({ type: "claude-code.launch.anchor-tamper", actor: "enclawed-code", level: null, payload: { nonce, reason: e.message } }).catch(() => {});
          unchecked ??= `anchor tamper: ${e.message}`;
          await stop();
        },
      })
    : null;
  let child = null;
  let halted = null;
  // Headless runs get their own process group (N7); see runClaude.
  const detached = !interactive;
  // claude's scope and session marker (containment.mjs, round 3 N12).
  const containment = plan.managed ? null : containmentFor(env);
  // `ownProcess`: this process is the launcher alone, so its own late children
  // are the session's too (a CLONE_PARENT sibling of claude, containment.mjs).
  const stop = (c = child) => stopClaude(c, { detached, containment, env, launcherChildren: ownProcess });
  let haltStop = null;
  const stopWatch = relay
    ? watchForHalt(
        (tool) => launcherHealth(fw, tool),
        async (h) => {
          halted = h;
          // Stop claude and everything the session started first, so nothing
          // of it can rewrite the login after the erase (N7b).
          haltStop ??= stop();
          await haltStop;
        },
      )
    : () => {};
  // Whether this session may start with the process nets it has is the kit's
  // decision (decideHaltNets): a halt kills every process of the session
  // before it erases the login (N7b), and without a scope, the subreaper or
  // process tracking one that left claude's tree and cleared its environment
  // is not found. Refused unless an administrator accepted that
  // (reducedContainment in the root-owned opt-out file).
  const nets = kit.decideHaltNets({
    hardwareRoot: Boolean(relay && containment),
    eraseOnHalt: loaded.options.onHardwareHalt.eraseClaudeCredentials,
    nets: { scope: Boolean(containment?.unit), subreaper: Boolean(containment?.reaper), tracked: Boolean(containment?.tracked) },
    reducedContainmentGranted: auth.grants.grants.reducedContainment === true,
  });
  // The nets Enclawed Code looked for, in its words.
  const netsHow = "(a systemd user scope: systemd-run and systemctl in /usr/bin or /bin; the subreaper wrapper: python3 or perl in /usr/bin or /bin, Linux only; process tracking on macOS)";
  if (nets.action === "refuse") {
    stopWatch();
    await anchoring?.close().catch(() => {});
    await relay?.close();
    if (relay?.dir) {
      fs.rmSync(relay.dir, { recursive: true, force: true });
    }
    root?.release();
    await discardSessionLogin(login);
    await state.close?.();
    if (full.settingsDir) {
      fs.rmSync(full.settingsDir, { recursive: true, force: true });
    }
    await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: nets.code } }).catch(() => {});
    return fail(stderr, `not starting: ${nets.message} ${netsHow}. An administrator who accepts this sets "reducedContainment": true in ${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME} (root-owned)`, EXIT_HARDWARE_HALT);
  }
  if (nets.action === "start-reduced") {
    say(stderr, `warning: ${nets.message} ${netsHow}; started anyway because ${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME} sets reducedContainment`);
  }

  // The control socket (control.mjs): the verified hook's handshake, and
  // the tool calls it decided.
  let control = null;
  // The mode claude really starts in (the person's arguments plus Enclawed Code's default).
  const launchCtx = launchContext({ args: full.args ?? plan.args, env, cwd, print: plan.print, userSettings: plan.userSettings ?? [] });
  if (full.permissionMode?.source === "managed") {
    noteOnce(env, "managed-no-bypass", () => say(stderr, MANAGED_NO_BYPASS_TEXT));
  } else if (full.permissionMode?.source === "root") {
    say(stderr, ROOT_NO_BYPASS_TEXT);
  }
  const approver = createApprover({ ...pauser(() => child?.pid ?? null), timeoutMs: approvalTimeoutMs(), ttyPath: authority().approvalTty });
  // Project scripts and package installs the agent runs are contained here
  // (kit.scriptContainer): the launcher outlives each hook process, so the
  // containment's relay serves the command while it runs. Every containment
  // event goes on the audit log (kit.containmentAuditOf).
  const holdFile = full.settingsDir ? path.join(full.settingsDir, "repo-config-hold.json") : null;
  // Repository configuration a contained git checked out: the session holds
  // (every hook decision denies) while Enclawed Code's launch admission runs
  // again over the files; inadmissible files are moved to the session's
  // quarantine, and the hold stays (kit.handleRepoConfigEvent).
  const readmitRepoConfig = () => readmitRepository({ launchArgv: plan.launchArgv ?? [], env, cwd, fw, loaded, audit, stderr, excludedHooks: (plan.hookQuestion?.hooks ?? []).map(hookKey) });
  const quarantineRepoConfig = (paths) => {
    const q = path.join(full.settingsDir, "quarantine");
    fs.mkdirSync(q, { recursive: true, mode: 0o700 });
    for (const p of paths) {
      try {
        fs.renameSync(p, path.join(q, `${Date.now()}-${path.basename(p)}`));
      } catch {
        /* gone already: nothing to keep from the next launch */
      }
    }
  };
  // `approveWrite`: lets the containment that reported a conflict write it
  // once (this launcher's script containments, or an MCP proxy's through the
  // relay); `forwarded`: the event came from a proxy, whose own events file
  // already carries its audit record.
  const containmentEvent = (e, { approveWrite = (x) => scripts?.approveRepoConfigWrite(x) ?? false, forwarded = false } = {}) => {
    if (!forwarded) {
      const r = kit.containmentAuditOf(e);
      void audit.append({ type: `claude-code.${r.type}`, actor: "enclawed-code", level: null, payload: r.payload }).catch(() => {});
    }
    if (holdFile && (e?.code === "containment-repo-config-changed" || e?.code === "containment-repo-config-refused")) {
      void kit
        .handleRepoConfigEvent(e, { hold: kit.fileHoldStore(holdFile), admit: readmitRepoConfig, onInadmissible: quarantineRepoConfig })
        .then(async (o) => {
          // A conflict is resolved only by a person, through Enclawed Code's own
          // prompt, a single-use grant bound to the path and content
          // (kit.approveConflictResolution), then the containment lets one write through.
          if (o.action === "held" && o.code === "repo-config-conflicted" && full.session?.approval === "launcher") {
            const ledger = new fw.ApprovalGrantLedger();
            for (const p of (e.paths ?? []).filter((x) => x?.state === "conflicted").map((x) => x.path)) {
              const r = await kit.approveConflictResolution({
                path: p,
                ledger,
                ask: async (question) => (await approver.ask({ id: `repo-config:${p}`, tool: "repo-config-write", reason: `Enclawed: ${question}` })).approved === true,
                approveWrite,
              });
              void audit.append({ type: "claude-code.repo-config.conflict-resolution", actor: "enclawed-code", level: null, payload: { path: p, ...r } }).catch(() => {});
            }
          }
          if (o.action !== "none") {
            say(stderr, `repository configuration ${o.action === "resumed" ? "admitted; the session goes on" : `not admitted (${o.code}); tool calls are held: ${(o.refusals ?? []).join("; ")}`}`);
            void audit.append({ type: "claude-code.repo-config.readmission", actor: "enclawed-code", level: null, payload: o }).catch(() => {});
          }
        })
        .catch(() => {});
    }
  };
  const scripts = full.settingsDir && !plan.managed ? kit.scriptContainer({ stateDir: path.join(full.settingsDir, "containment"), onEvent: (e) => containmentEvent(e) }) : null;
  // Events from the MCP proxies' containments (repo-config-relay.mjs): the
  // same re-admission, and a resolved conflict's write goes back to that proxy.
  const relayed =
    full.settingsDir && !plan.background && full.session?.mcp
      ? watchRepoConfigRequests(full.settingsDir, (origin, e) => containmentEvent(e, { forwarded: true, approveWrite: (x) => approveRepoConfigWriteIn(full.settingsDir, origin, x) }))
      : null;
  if (!plan.managed && !plan.background && full.session?.control?.path) {
    try {
      control = await startControl({
        socketPath: full.session.control.path,
        expectedArgv: () => full.hookArgv,
        claudePid: () => child?.pid ?? null,
        nonce,
        auditFile: auditLogPath(env),
        launchHash: () => launchRecord?.recordHash ?? null,
        relaySecret: relay?.secret ?? null,
        // Decisions are bound to the transcript's calls (round 3, N9).
        pollTranscripts: () => transcripts?.poll(),
        onAnchorRequest: () => anchoring?.request(),
        onMismatch: (m) => onMismatch(m),
        // Held root: a reported decision must be the one the device signed (commitments.mjs).
        ...(ledger
          ? {
              onDecision: (d) => {
                const why = decisionAgainstCommitment(ledger, d.id, d.decision);
                if (why) {
                  void onMismatch({ id: d.id, code: "decision-not-committed", reason: why });
                }
              },
            }
          : {}),
        // Claude Code runs in a stricter mode than launched (auto unavailable
        // for the model, say): the session continues, and the downgrade is on record.
        onModeDowngrade: (d) => {
          say(stderr, `Claude Code runs in ${d.reported}, stricter than the ${d.launched} it was launched in (it fell back by itself); continuing in ${d.reported}`);
          audit.append({ type: "claude-code.launch.host-mode-downgraded", actor: "enclawed-code", level: null, payload: { nonce, toolUseId: d.id, launched: d.launched, reported: d.reported } }).catch(() => {});
        },
        // The context each decision was made in (round 5).
        context: () => launchCtx,
        // Interactive Claude Code writes a call's transcript line only after
        // its PreToolUse hook answered: bind those decisions when it appears.
        deferBinding: () => interactive && !plan.print,
        // Interactive "ask": the launcher's own prompt (round 5, N13c).
        ...(full.session?.approval === "launcher" ? { onApprove: (q) => approver.ask({ ...q, warnings: warningLines(q.signals ?? [], { home: env.HOME ?? null, cwd }) }) } : {}),
        // The kit marked the call (Decision.contain): contain it in this session's project.
        ...(scripts ? { onContain: (req) => scripts.contain({ ...req, projectDir: full.session?.projectDir ?? req.projectDir }) } : {}),
        cwd: realpathNearest(cwd),
        home: env.HOME ?? null,
      });
    } catch (err) {
      await anchoring?.close().catch(() => {});
      await relay?.close();
      root?.release();
      await discardSessionLogin(login);
      await state.close?.();
      return fail(stderr, `cannot start Enclawed Code's control socket (${err.message}); not starting claude`);
    }
  }
  // Background sessions: no control socket; the chained session.start record is the only signal.
  const hs = nonce && plan.background ? watchHandshake(auditLogPath(env), nonce) : null;
  const handshakeDone = () => (control ? control.state.handshake : hs ? hs.check() : true);
  const timeoutS = handshakeTimeoutS();
  let handshakeTimer = null;
  let handshakeFailed = false;
  let unchecked = null;
  // A decision reported for a call whose name or input is not the
  // transcript's (call-binding.mjs): flagged, audited, and claude stopped.
  let mismatch = null;
  const onMismatch = async (m) => {
    if (mismatch || halted) {
      return;
    }
    mismatch = m;
    unchecked ??= `a hook decision did not match tool call ${m.id}: ${m.reason}`;
    say(stderr, `${m.reason} (tool call ${m.id}); stopping claude: a decision was reported for a different call than the one that runs`);
    await audit.append({ type: "claude-code.launch.decision-mismatch", actor: "enclawed-code", level: null, payload: { nonce, toolUseId: m.id, code: m.code, reason: m.reason } }).catch(() => {});
    await stop();
  };
  // A call that ran (a successful tool_result) although Enclawed decided
  // deny, or ask with no sign that a person answered (round 4, N13). In -p
  // there is no one to ask, so an ask is a deny there (unless claude was
  // given a --permission-prompt-tool, where the genuine hook's PostToolUse
  // is the evidence). Interactively the only evidence is a yes at the
  // launcher's own prompt (round 5, N13c, approval.mjs): any descendant can
  // run the genuine hook on a PostToolUse (or any other event's) input, so no
  // hook event proves that a person approved. A short grace absorbs socket
  // and poll timing.
  // A commitment whose decision is not the one the hook reported for that call.
  onCommitted = (id, decision) => {
    const reported = typeof id === "string" ? control?.decisions.get(id) : undefined;
    if (reported && reported !== "pending" && reported !== decision) {
      void onMismatch({ id, code: "decision-not-committed", reason: `the hook reported ${reported} for ${id}, and the device signed ${decision}` });
    }
  };
  const promptTool = plan.args.some((a) => a === "--permission-prompt-tool" || a.startsWith("--permission-prompt-tool="));
  const askNeedsPerson = !plan.print || promptTool;
  let violated = null;
  const onViolation = async (id, decision) => {
    if (violated || halted) {
      return;
    }
    violated = { id, decision };
    unchecked ??= `tool call ${id} ran although Enclawed decided ${decision}`;
    say(stderr, `tool call ${id} ran although Enclawed decided "${decision}"${decision === "ask" ? " and no person approved it" : ""}; stopping claude: Enclawed's decisions are not being enforced`);
    await audit.append({ type: "claude-code.launch.decision-violated", actor: "enclawed-code", level: null, payload: { nonce, toolUseId: id, decision } }).catch(() => {});
    await stop();
  };
  const launcherPrompt = full.session?.approval === "launcher";
  const verdict = (id, final) => decisionViolation(control.decisions.get(id) ?? "pending", { askNeedsPerson, posted: control.posts.has(id), launcherPrompt, approved: control.approved.has(id), final });
  const checkDecision = (id, graceMs = 2000) => {
    const v = verdict(id, false);
    if (v === "wait") {
      // An interactive ask, or a decision not reported yet: wait for the evidence.
      let done;
      pendingChecks.add(new Promise((r) => (done = r)));
      const t = setTimeout(() => {
        done();
        const w = verdict(id, true);
        if (w) {
          onViolation(id, w);
        }
      }, graceMs);
      t.unref?.();
    } else if (v) {
      onViolation(id, v);
    }
  };
  const pendingChecks = new Set();
  // A tool call claude ran without Enclawed Code's hook (transcript-watch.mjs).
  const onUnchecked = async (why) => {
    if (unchecked || halted) {
      return;
    }
    unchecked = why;
    say(stderr, `${why}; stopping claude: tool calls are NOT being checked`);
    await stop();
  };
  const transcripts = control
    ? watchTranscripts({
        env,
        cwd,
        onUse: (u) => {
          control.noteUse(u);
          if (!control.state.handshake && !control.decided.has(u.id)) {
            onUnchecked(`a ${u.name ?? "tool"} call (${u.id}) started before Enclawed's hooks reported in`);
          }
        },
        onResult: (r) => {
          if (r.isError) {
            return;
          }
          if (!control.decided.has(r.id)) {
            onUnchecked(`a tool call (${r.id}) ran without a decision from Enclawed's hook`);
            return;
          }
          checkDecision(r.id);
        },
      })
    : null;
  // Defense in depth for a dropped settings file (round 4, F1): Claude Code
  // says so on stderr ("These settings files did not load, so nothing in
  // them is in effect, including hooks ..."). When the file it names is
  // Enclawed Code's generated one, claude is stopped at once.
  let dropped = null;
  const droppedWatch = full.settingsDir && !interactive ? settingsDropWatcher(full.settingsDir, async (line) => {
    if (dropped || halted) {
      return;
    }
    dropped = line;
    unchecked ??= "Claude Code did not load Enclawed Code's settings file, hooks included";
    say(stderr, `Claude Code reports that it did not load Enclawed Code's settings file (${line.slice(0, 200)}); stopping claude: no tool call would be checked`);
    await audit.append({ type: "claude-code.launch.settings-dropped", actor: "enclawed-code", level: null, payload: { nonce, detail: line.slice(0, 500) } }).catch(() => {});
    await stop();
  }) : null;
  // Mid-session admission (skills.mjs, mcp.mjs): a verified skill whose
  // files change, a skill that appears, or an MCP server whose tools change
  // after approval stops the session.
  let admissionBroken = null;
  const onAdmissionBroken = async (type, reason, payload = {}) => {
    if (admissionBroken || halted) {
      return;
    }
    admissionBroken = { type, reason };
    say(stderr, `${reason}; stopping claude: ${type === "skill-drift" ? "only the skills verified at launch may be loaded" : "an MCP server broke its admission"}`);
    await audit.append({ type: `claude-code.launch.${type}`, actor: "enclawed-code", level: null, payload: { nonce, reason: String(reason).slice(0, 1000), ...payload } }).catch(() => {});
    await stop();
  };
  // Routine state is said once, at the first interactive launch here (welcome.mjs).
  if (activeTerminal && stderr.isTTY) {
    const shown = welcomeOnce({ env, stderr, bypass: full.permissionMode?.source === "enclawed-default" });
    if (shown) {
      await audit.append({ type: "claude-code.launch.welcome", actor: "enclawed-code", level: null, payload: { nonce } }).catch(() => {});
    }
  }
  // Files changed outside the agent (file-integrity.mjs): compared with the
  // last audited state now, and watched while the session runs.
  let integrity = null;
  if (!plan.background && !plan.managed) {
    try {
      integrity = await startFileIntegrity({ env, projectDir: realpathNearest(path.resolve(cwd)), audit, stderr });
    } catch (err) {
      await audit.append({ type: "claude-code.launch.refused", actor: "enclawed-code", level: null, payload: { reason: "file-integrity", detail: String(err.message).slice(0, 1000) } }).catch(() => {});
      await control?.close().catch(() => {});
      await anchoring?.close().catch(() => {});
      await relay?.close();
      root?.release();
      await discardSessionLogin(login);
      await state.close?.();
      return fail(stderr, `cannot record the project's files (${err.message}); not starting claude`);
    }
  }
  const skillWatch =
    !plan.background && full.session?.skills
      ? watchSkills(full.session.skills, { projectDir: realpathNearest(path.resolve(cwd)), env, onDrift: (why) => onAdmissionBroken("skill-drift", why) })
      : null;
  const mcpWatch =
    !plan.background && full.session?.mcp
      ? watchMcpEvents(full.session.mcp.events, (ev) => onAdmissionBroken("mcp-violation", `the MCP server ${JSON.stringify(ev.server ?? "?")} ${ev.reason ?? "broke its admission"}`, { server: ev.server ?? null, kind: ev.kind ?? null }))
      : null;
  const result = await runClaude(full, {
    env,
    stderr,
    detached,
    containment,
    onStderr: droppedWatch,
    onChild: (c) => {
      child = c;
      if (control) {
        const started = Date.now();
        handshakeTimer = setInterval(async () => {
          if (control.state.handshake) {
            clearInterval(handshakeTimer);
            return;
          }
          if (Date.now() - started > timeoutS * 1000) {
            clearInterval(handshakeTimer);
            const refused = control.state.refused.length ? ` (refused: ${control.state.refused[0]})` : "";
            if (plan.print) {
              handshakeFailed = true;
              say(stderr, `Enclawed's hooks did not start within ${timeoutS} s (no verified session-start handshake${refused}); stopping claude`);
              await stop(c);
            } else {
              stderr.write(
                `ecwcode: warning: Enclawed's hooks have not started after ${timeoutS} s${refused}; every tool call waits for them and is refused without them, and a call that runs anyway stops the session\n`,
              );
            }
          }
        }, 200);
      }
    },
  });
  clearInterval(handshakeTimer);
  transcripts?.poll();
  transcripts?.stop();
  // Decision checks still in their grace period (N13) finish before the verdict.
  await Promise.all([...pendingChecks]);
  stopWatch();
  skillWatch?.stop();
  integrity?.stop();
  mcpWatch?.check();
  mcpWatch?.stop();
  relayed?.stop();
  await control?.close();
  await scripts?.close();
  // What the MCP proxies' containments reported (each proxy writes its own events file).
  forwardContainmentEvents(full.settingsDir, audit);
  if (control?.state.peerCheck?.available === false) {
    say(stderr, `note: the hook's identity could not be checked with peer credentials (${control.state.peerCheck.reason}); the handshake rested on the challenge and the audit chain only`);
  }
  // --bg: the session starts after claude returns; wait for its handshake (N6).
  if (hs && !halted && result.code === 0 && plan.args.some((a) => a === "--bg" || a === "--background")) {
    const deadline = Date.now() + timeoutS * 1000;
    while (!hs.check() && Date.now() < deadline) {
      await sleep(250);
    }
  }
  const shook = handshakeDone();

  // The relay closed (the token dropped from memory); a renewed token was already sealed by the relay.
  const loginEnd = halted ? null : await closeLoginForSession(login);
  const stateEnd = halted ? null : await state.close?.();
  if (stateEnd && !stateEnd.ok) {
    say(stderr, `the session context or tool credentials could not all be sealed and erased (${stateEnd.stores.flatMap((x) => x.remaining ?? []).slice(0, 4).join(", ") || stateEnd.ssh.failed.join(", ") || "see the audit log"}); remove what is left by hand`);
  }
  if (loginEnd) {
    await audit.append({ type: "claude-code.login.closed", actor: "enclawed-code", level: null, payload: { nonce, ok: loginEnd.ok, action: loginEnd.action, remaining: loginEnd.remaining } }).catch(() => {});
    if (loginEnd.message) {
      say(stderr, `${loginEnd.message}`);
    }
  }
  let exit = result;
  if (halted) {
    // N7b: the erase comes only after every process of the session is dead,
    // and the stop verified that nothing of it is left.
    const contained = await (haltStop ?? stop());
    // Sealing needs no device: the context and the tool credentials are sealed at a halt too.
    await state.close?.({ halted: true });
    const erase = loaded.options.onHardwareHalt.eraseClaudeCredentials;
    // What Enclawed Code set up for the session: the session's Claude Code login storage (Enclawed
    // Code's login directory, which Claude Code itself wrote and Enclawed Code never read) and the API
    // key sealed under the device. The person's own Claude Code login is never touched.
    const sessionLogin = login.action === "own-login" || login.action === "relayed";
    const r = { erased: [], remaining: [], notes: erase ? [] : ["credential erase is turned off by policy"], reappeared: 0 };
    if (erase) {
      r.notes.push("your own Claude Code login (outside Enclawed Code) was not touched");
    }
    // The relay closed; the session's login storage (written only, never read: claude-login.mjs) and the
    // sealed API key are erased, unless the policy keeps them.
    const sealedErase = await closeLoginForSession(login, { halted: erase, env });
    if (sealedErase) {
      r.erased.push(...sealedErase.erased);
      r.remaining.push(...sealedErase.remaining);
    }
    if (contained?.verified === false) {
      r.notes.push(`could NOT verify that every process of the session is gone (still running: ${contained.survivors.slice(0, 8).join(", ")}); one of them could write the login back: kill them by hand and sign out of that session at claude.ai`);
    } else if (contained?.verified === true) {
      r.notes.unshift(`every process of the session was stopped before the erase (${contained.killed} killed besides claude), and none is left`);
    }
    if (erase && sessionLogin) {
      r.notes.push("the erase is best effort: a copy of the credential taken earlier keeps working until it is revoked (sign out of the session at claude.ai, or revoke the API key in the Claude Console)");
    }
    await audit
      .append({ type: "hardware.halt.credentials-erased", actor: "enclawed-code", level: null, payload: { nonce, halt: { code: halted.code, reason: halted.reason }, contained: { verified: contained?.verified ?? null, survivors: contained?.survivors?.slice(0, 32) ?? [], killed: contained?.killed ?? 0, mode: containmentMode(containment) }, eraseEnabled: erase, erased: r.erased, remaining: r.remaining, reappeared: r.reappeared, notes: r.notes } })
      .catch(() => {});
    stderr.write(
      `ecwcode: hardware root halt (${halted.reason}); claude was stopped.\n` +
        (erase
          ? r.remaining.length === 0
            ? `ecwcode: the session's Claude Code login was erased (${r.erased.join(", ") || "nothing was stored"}).\n` + r.notes.map((n) => `ecwcode: ${n}\n`).join("")
            : `ecwcode: could NOT erase ${r.remaining.join(", ")}; remove it by hand.\n`
          : "ecwcode: the session's Claude Code login was kept (onHardwareHalt.eraseClaudeCredentials is false).\n") +
        `ecwcode: to continue: re-attach the genuine Enclaweder, run \`ecwctl recover-root\`${erase && sessionLogin ? ", then sign in again with /login inside an Enclawed Code session (or seal your API key again: ecwctl login api-key)" : ""}.\n`,
    );
    exit = EXIT_HARDWARE_HALT;
  } else if (admissionBroken) {
    exit = EXIT_ADMISSION;
  } else if (unchecked) {
    await audit.append({ type: "claude-code.launch.unchecked-tool-call", actor: "enclawed-code", level: null, payload: { nonce, reason: unchecked, handshake: shook } }).catch(() => {});
    exit = EXIT_NO_HANDSHAKE;
  } else if ((control || hs) && !shook) {
    await audit.append({ type: "claude-code.launch.no-handshake", actor: "enclawed-code", level: null, payload: { nonce, timeoutS, print: plan.print, background: plan.background, refused: control?.state.refused.slice(0, 5) ?? [] } }).catch(() => {});
    if (!handshakeFailed) {
      stderr.write("ecwcode: Enclawed's hooks never reported in this session; treat anything it did as unchecked (see: ecwctl audit reconcile)\n");
    }
    if (handshakeFailed || result.code === 0) {
      exit = EXIT_NO_HANDSHAKE;
    }
  }
  // Claude Code's own exit line says "claude --resume <id>", which would run outside Enclawed
  // Code: one line of ours on stderr after claude has exited (its own output is untouched).
  if (!halted && interactive && !plan.print && !plan.background && control?.state.sessionId) {
    say(stderr, `resume under Enclawed Code with: ecwcode --resume ${control.state.sessionId}`);
  }
  await audit
    .append({ type: "claude-code.launch.end", actor: "enclawed-code", level: null, payload: { nonce, handshake: shook, code: result.code, signal: result.signal, halted: halted ? halted.code : null, ...(ledger ? { commitments: ledger.end() } : {}) } })
    .catch(() => {});
  await audit.flush();
  if (anchoring) {
    anchoring.stop();
    if (!halted) {
      // The anchored head is routine: in the audit log and `ecwctl audit verify`, not said at every exit.
      await anchoring.flush();
    }
    await anchoring.close().catch((e) => say(stderr, `device anchor: could not close the anchor session: ${e.message}`));
  }
  await relay?.close();
  if (relay?.dir) {
    fs.rmSync(relay.dir, { recursive: true, force: true });
  }
  root?.release();
  if (full.settingsDir && !full.keepSettings) {
    fs.rmSync(full.settingsDir, { recursive: true, force: true });
  }
  return exit;
}
