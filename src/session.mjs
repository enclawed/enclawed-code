// The per-session file: everything the hook needs, resolved once by the
// launcher, so the hook takes no configuration from its own environment.
//
// Claude Code exports the `env` key of every settings file (user, project,
// local, --settings) to the processes it starts, hooks included, so a
// repository's committed .claude/settings.json could otherwise point the hook
// at another policy, state dir, audit log or hardware broker, or preload code
// into it with NODE_OPTIONS (red-team I1, I1b, I1c, I8).
//
// So:
//   - The launcher resolves the state dir, audit log, history dir, policy
//     candidates, flavor, hardware mode and the environment the framework
//     needs, from the user's own shell environment, before claude starts.
//   - It writes them to `session.json` in a private directory (0700, file
//     0600) outside the project and outside any directory the agent may
//     write without a person, and puts the file's path and its SHA-256 on the
//     hook's command line in the --settings file it generates.
//   - The hook command runs node under `env -i` (no inherited environment at
//     all: NODE_OPTIONS, NODE_PATH, LD_PRELOAD, DYLD_* and every ENCLAWED_*
//     variable from settings are gone before node starts), checks the file's
//     owner, mode and digest, and replaces its process environment with the
//     one recorded in the file before it loads the framework.
//
// The session file's checks, the hook's environment and the repository
// decisions (env, command settings) are Enclawed's (adapter kit transport.ts,
// env-trust.ts, repo-commands.ts); this module reads Claude Code's settings
// files and names Claude Code's paths and variables (data).

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { FRAMEWORK_PACKAGE } from "./framework.mjs";
import { writeProtectedInodeIndex } from "./links.mjs";
import {
  APP_ROOT,
  appConfigPath,
  appStateDir,
  auditLogPath,
  hardwareLatchPaths,
  historyDir,
  homeDir,
  realpathNearest,
  stateDir,
  userPolicyPath,
} from "./paths.mjs";

import { commandPaths } from "./settings-schema.mjs";
import { authority } from "./authority.mjs";
import { resolveGrants } from "./opt-outs.mjs";
import { CLAUDE_ENV_EXTRA } from "./claude-env.mjs";
import { kit } from "./kit.mjs";

/** The session file's version (the kit's writeSessionFile / readSessionFile use the same). */
export const SESSION_VERSION = 1;

/** Claude Code's own variables the hook needs besides the kit's HOOK_PASS_ENV (its config directories). */
const HOST_PASS_ENV = Object.freeze(["CLAUDE_CONFIG_DIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR"]);

/** Enclawed Code's own variable prefixes (current, pre-rename, gateway), for the kit's changesShellCommands. */
const HOST_ENV_PREFIXES = Object.freeze(["ECWCODE_", "CODENCLAWED_", "ENCLAWDE_", "OPENCLAW_"]);

/**
 * Settings `env` names that change what Enclawed Code itself, or the commands it
 * treats as read-only, would do (kit changesShellCommands, with Enclawed Code's
 * prefixes and Claude Code's helper variables). When a user, project or local
 * settings file names one of them, the launcher warns and pins it in the
 * generated --settings (which outranks those files) to the launcher's own value.
 */
export function isSensitiveEnvName(name) {
  const n = String(name).toUpperCase();
  return kit.changesShellCommands(n, HOST_ENV_PREFIXES) || Object.hasOwn(HELPER_ENV, n);
}

/**
 * Claude Code variables that make it run, or re-run, a command (round 4, F2):
 * the apiKeyHelper/proxy-auth refresh intervals (a settings `env` set the
 * apiKeyHelper TTL to 1 s to re-run repository code on every tick), the
 * process wrapper and shell prefix, the policy helper paths. The generated
 * --settings always pins them: to the launcher's own value when its shell
 * has one, else to the value given here (null: pinned only when a lower
 * settings file sets it, to "").
 */
export const HELPER_ENV = Object.freeze({
  CLAUDE_CODE_API_KEY_HELPER_TTL_MS: "300000",
  CLAUDE_CODE_PROXY_AUTH_HELPER_TTL_MS: "300000",
  CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER: "",
  CLAUDE_CODE_OTEL_HEADERS_HELPER_DEBOUNCE_MS: null,
  CLAUDE_CODE_PROCESS_WRAPPER: "",
  CLAUDE_CODE_SHELL_PREFIX: "",
  CLAUDE_CODE_POLICY_HELPER_PS1_PATH: "",
  CLAUDE_CODE_POLICY_HELPER_PSMODULEPATH: "",
});

/** The helper pins for the generated settings `env` (HELPER_ENV). */
export function helperEnvPins(env) {
  const pins = {};
  for (const [k, fallback] of Object.entries(HELPER_ENV)) {
    if (typeof env[k] === "string") {
      pins[k] = env[k];
    } else if (fallback !== null) {
      pins[k] = fallback;
    }
  }
  return pins;
}

/**
 * The environment the hook (and so the framework) runs with: only what the
 * launcher resolved (kit hookEnvironment: its pass list plus Claude Code's
 * config directories, the allowlisted framework variables, and these fixed
 * values; a TMPDIR inside the project falls back to the session directory).
 */
export function hookEnvironment(env, { projectDir, sessionDir }) {
  // Absolute, already-resolved locations: the framework must agree with Enclawed Code.
  const fixed = { ENCLAWED_STATE_DIR: stateDir(env), ENCLAWED_HISTORY_DIR: historyDir(env) };
  if (typeof env.HOME !== "string" || env.HOME === "") {
    fixed.HOME = homeDir(env);
  }
  // The one admin-set exception: a forensic webhook, read here from the
  // root-owned opt-out file itself, never from `env`.
  const webhook = resolveGrants(env).grants.forensicWebhook;
  if (webhook) {
    fixed.ENCLAWEDER_FORENSIC_WEBHOOK = webhook;
  }
  return kit.hookEnvironment(env, { projectDir, sessionDir, pass: HOST_PASS_ENV, fixed });
}

/** The policy files to consult, highest precedence first (see policy.mjs). */
export function policyCandidates(env, { fw } = {}) {
  const list = [{ kind: "managed", path: authority().managedPolicyPath }];
  const pinned = env.ENCLAWED_CONFIG_PATH?.trim();
  if (pinned) {
    list.push({ kind: "launcher-env", path: path.resolve(pinned.replace(/^~(?=$|[\\/])/, homeDir(env))) });
  }
  try {
    const use = JSON.parse(fs.readFileSync(appConfigPath(env), "utf8"))?.policyPath;
    if (typeof use === "string" && use) {
      list.push({ kind: "policy-use", path: path.resolve(use) });
    }
  } catch {
    /* no pointer */
  }
  list.push({ kind: "enclawed-code-user", path: userPolicyPath(env) });
  if (fw) {
    // The gateway's own lookup, with ENCLAWED_CONFIG_PATH already handled above.
    const clean = { ...env };
    delete clean.ENCLAWED_CONFIG_PATH;
    delete clean.OPENCLAW_CONFIG_PATH;
    list.push({ kind: "gateway", path: fw.resolveDefaultConfigPath({ env: clean }).path });
  } else {
    list.push({ kind: "gateway", path: path.join(stateDir(env), "enclawed.json") });
  }
  return list;
}

/**
 * Framework entry and its dependency tree, as actually resolved on disk: the
 * development build (.enclawed-dev) or the installed enclawed package with the
 * node_modules directory that holds it and its dependencies.
 */
function frameworkPaths() {
  const dev = path.join(APP_ROOT, ".enclawed-dev");
  const out = [];
  for (const p of [path.join(dev, "framework"), path.join(dev, "node_modules")]) {
    try {
      out.push(fs.realpathSync(p));
    } catch {
      /* not built */
    }
  }
  if (FRAMEWORK_PACKAGE) {
    out.push(FRAMEWORK_PACKAGE.root);
    if (FRAMEWORK_PACKAGE.nodeModules) {
      out.push(FRAMEWORK_PACKAGE.nodeModules);
    }
  }
  return out;
}

/**
 * Paths the agent must never write: Enclawed Code's own state (policy, audit log
 * and head anchor, history, session files), the gateway's state, the app's
 * code, the framework it loads and the Node binary that runs the hook.
 * Writes resolving into them are denied, not asked (I3, I4, I14).
 */
export function protectedPaths(env, { sessionDir = null, candidates = [] } = {}) {
  const real = (p) => realpathNearest(path.resolve(p));
  const list = new Set();
  for (const p of [stateDir(env), appStateDir(env), historyDir(env), auditLogPath(env), APP_ROOT, ...frameworkPaths()]) {
    list.add(real(p));
  }
  for (const c of candidates) {
    list.add(real(c.path));
  }
  try {
    list.add(fs.realpathSync(process.execPath));
  } catch {
    list.add(process.execPath);
  }
  if (sessionDir) {
    list.add(real(sessionDir));
  }
  const latch = hardwareLatchPaths(env);
  list.add(real(latch.file));
  let node = process.execPath;
  try {
    node = fs.realpathSync(process.execPath);
  } catch {
    /* keep the unresolved path */
  }
  // Enclawed Code's own state, walked first when indexing inodes (links.mjs).
  const statePaths = [auditLogPath(env), stateDir(env), appStateDir(env), ...(sessionDir ? [real(sessionDir)] : []), ...candidates.map((c) => c.path), latch.file, historyDir(env)].map(real);
  return {
    paths: [...list].sort(),
    statePaths: [...new Set(statePaths)],
    // Shell commands may name these (to run node); writes to them are still denied.
    mentionExempt: [node],
    // Per-device latches: <dir>/.enclawed-hw-root.<uid>.state
    prefixes: [{ dir: real(latch.dir), basename: ".enclawed-hw-root" }],
  };
}

/** Does any of `absPaths` resolve into a protected path (kit isProtectedPath)? */
export function isProtected(prot, absPaths) {
  return kit.isProtectedPath(prot, absPaths);
}

/**
 * A private root for session directories, outside the project (kit
 * privateSessionRoot: the first of XDG_RUNTIME_DIR, TMPDIR, the system temp
 * directory and the app state dir that is not inside the project, as a 0700
 * directory of this user's own).
 */
export function sessionRoot(env, projectDir) {
  return kit.privateSessionRoot({ env, projectDir, name: "enclawed-code", stateDir: appStateDir(env) });
}

/**
 * Create the session directory and file.
 *
 * @returns {{ dir: string, file: string, digest: string, session: object }}
 */
export function createSession({ env = process.env, cwd = process.cwd(), fw = null, hardware = null, root = null } = {}) {
  const projectDir = realpathNearest(path.resolve(cwd));
  const base = root ?? sessionRoot(env, projectDir);
  const dir = fs.mkdtempSync(path.join(base, "s-"));
  fs.chmodSync(dir, 0o700);
  const candidates = policyCandidates(env, { fw });
  const session = {
    v: SESSION_VERSION,
    nonce: randomBytes(16).toString("hex"),
    // (Round 4's noticeNonce is gone: Enclawed's notices now reach the model
    // only out of band, as hook context, so no secret tag is shown to it.)
    createdAt: Date.now(),
    launcherPid: process.pid,
    projectDir,
    sessionDir: dir,
    stateDir: stateDir(env),
    auditLog: auditLogPath(env),
    historyDir: historyDir(env),
    flavor: fw ? fw.getFlavor(env) : null,
    policyCandidates: candidates,
    env: hookEnvironment(env, { projectDir, sessionDir: dir }),
    hardware: hardware ?? { mode: "per-call" },
    protected: protectedPaths(env, { sessionDir: dir, candidates }),
  };
  const { file, digest } = kit.writeSessionFile(dir, session);
  return { dir, file, digest, session };
}

/**
 * Record the (dev, ino) of every protected file and directory in the session
 * directory (red-team round 3, bind mounts). The launcher does this once per
 * launch: it is too slow to walk large code trees on every tool call.
 */
export function indexProtectedInodes(s) {
  const inodeIndex = writeProtectedInodeIndex(s.session.protected, path.join(s.dir, "protected-inodes.json"));
  return updateSession(s, { protected: { ...s.session.protected, inodeIndex } });
}

/** Rewrite the session file (the launcher fills in the hardware relay after the root is held). */
export function updateSession(s, patch) {
  const session = { ...s.session, ...patch };
  return { ...s, session, digest: kit.rewriteSessionFile(s.file, session) };
}

/** The error a session file that cannot be trusted raises (kit's, so every check throws one class). */
export const SessionFileError = kit.SessionFileError;

/** Hook side: read and authenticate the session file named on the command line (kit readSessionFile). */
export function readSession(file, digest) {
  return kit.readSessionFile(file, digest);
}

/** Replace this process's environment (before the framework is loaded). */
export function replaceProcessEnv(next) {
  kit.replaceProcessEnv(next);
}

/** The environment for managed mode: nothing inherited, home from the OS account. */
export function managedEnvironment({ flavor = null, hardwareRoot = null } = {}) {
  // The account's own home (the suite's stand-in only through the test authority).
  let home = authority().managedHome;
  try {
    home ??= os.userInfo().homedir;
  } catch {
    home = os.homedir();
  }
  const env = {
    HOME: home,
    PATH: process.platform === "win32" ? process.env.PATH ?? "" : "/usr/local/bin:/usr/bin:/bin",
  };
  if (flavor) {
    env.ENCLAWED_FLAVOR = flavor;
  }
  if (hardwareRoot) {
    env.ENCLAWEDER_ROOT = hardwareRoot;
  }
  // A forensic webhook only from the root-owned opt-out file (opt-outs.mjs).
  const webhook = resolveGrants({}).grants.forensicWebhook;
  if (webhook) {
    env.ENCLAWEDER_FORENSIC_WEBHOOK = webhook;
  }
  return env;
}

/** The settings files below --settings that Claude Code reads (user, project, local). */
export function lowerSettingsFiles({ projectDir, env }) {
  const configDir = env.CLAUDE_CONFIG_DIR || path.join(env.HOME || os.homedir(), ".claude");
  return [
    { scope: "user", file: path.join(configDir, "settings.json") },
    { scope: "project", file: path.join(projectDir, ".claude", "settings.json") },
    { scope: "local", file: path.join(projectDir, ".claude", "settings.local.json") },
  ];
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

/**
 * Sensitive `env` names set by user, project or local settings.
 * @returns {Array<{ scope: string, file: string, name: string }>}
 */
export function sensitiveSettingsEnv({ projectDir, env }) {
  const out = [];
  for (const { scope, file } of lowerSettingsFiles({ projectDir, env })) {
    const e = readJson(file)?.env;
    if (e && typeof e === "object" && !Array.isArray(e)) {
      for (const name of Object.keys(e)) {
        if (isSensitiveEnvName(name)) {
          out.push({ scope, file, name });
        }
      }
    }
  }
  return out;
}

const envBlock = (doc) => (doc && typeof doc.env === "object" && doc.env !== null && !Array.isArray(doc.env) ? doc.env : {});

// How the kit's origin outcomes read in Enclawed Code's session.start record.
const OUTCOME = Object.freeze({ kept: "kept", "same-as-user": "the same value as yours", accepted: "accepted: it selects your own provider, region or project" });

/**
 * Variables in a repository's settings `env` (.claude/settings.json and
 * .claude/settings.local.json) that would change where Claude Code or its
 * children send traffic, what they trust, whose account they use, what they
 * load or what they export (CVE-2026-21852: a repository's
 * ANTHROPIC_BASE_URL sent the session to another server). The decision is
 * the kit's (decideRepositoryEnv): each is refused, unless its value can
 * never take effect (Claude Code's managed settings, or the user's own
 * --settings, set the same name) or is the value the session has anyway
 * (from the user's settings or shell). Launcher-owned names
 * (isSensitiveEnvName) stay pinned instead, except those of the destination,
 * trust and credential classes.
 *
 * Also returns what the user's shell, user settings, --settings and the
 * managed settings set of these classes, for the session.start audit record
 * (`origins`, values of credentials as digests).
 *
 * @returns {{ refusals: Array<{ scope: string, file: string, name: string, class: string, why: string }>, origins: object[] }}
 */
export function repositoryEnv({ projectDir, env, extra = [], managedDocs = [] }) {
  const files = lowerSettingsFiles({ projectDir, env });
  const read = (scope) => {
    const f = files.find((x) => x.scope === scope);
    return { file: f.file, env: envBlock(readJson(f.file)) };
  };
  const user = read("user");
  const project = read("project");
  const local = read("local");
  const managedEnv = Object.assign({}, ...managedDocs.map((d) => envBlock(d?.doc)));
  const flagEnv = Object.assign({}, ...extra.map((d) => envBlock(d)));
  const scopeOf = new Map([
    [project.file, "project"],
    [local.file, "local"],
  ]);
  const d = kit.decideRepositoryEnv({
    // Lowest rank first: .claude/settings.local.json outranks .claude/settings.json.
    repository: [
      { origin: project.file, env: project.env },
      { origin: local.file, env: local.env },
    ],
    higher: [
      { origin: "--settings", env: flagEnv },
      { origin: "managed-settings", env: managedEnv },
    ],
    // The user's settings outrank the shell.
    user: [
      { origin: "shell", env },
      { origin: "user-settings", env: user.env },
    ],
    launcherPinned: isSensitiveEnvName,
    extra: CLAUDE_ENV_EXTRA,
  });
  const refusals = d.refusals.map((r) => ({ scope: scopeOf.get(r.origin), file: r.origin, name: r.name, class: r.class, why: r.why }));
  const origins = d.origins.map((o) => {
    const outcome =
      o.outcome === "shadowed" ? (Object.hasOwn(managedEnv, o.name) ? "shadowed by Claude Code's managed settings" : "shadowed by your --settings") : (OUTCOME[o.outcome] ?? o.outcome);
    const { origin, ...rest } = o;
    return { ...rest, source: scopeOf.get(origin) ?? origin, outcome };
  });
  return { refusals, origins };
}

/** The refusal message for repositoryEnv's first refusal (kit). */
export function repositoryEnvMessage(refusals) {
  return kit.repositoryEnvMessage(
    refusals.map((r) => ({ origin: r.origin ?? r.file, name: r.name, class: r.class, why: r.why })),
    "ecwcode",
  );
}

// Frontmatter hooks (skills, subagents): `hooks:` with event keys below it.
const FRONTMATTER_EVENT = /^\s+["']?([A-Z][A-Za-z]+)["']?\s*:/;

function frontmatterHooks(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) {
    return [];
  }
  const lines = m[1].split(/\r?\n/);
  const events = [];
  let inHooks = false;
  for (const l of lines) {
    if (/^hooks\s*:/.test(l)) {
      inHooks = true;
      // Inline JSON/YAML flow form: hooks: { PreToolUse: [...] }
      for (const e of l.matchAll(/["']?([A-Z][A-Za-z]+)["']?\s*:/g)) {
        events.push(e[1]);
      }
      continue;
    }
    if (inHooks) {
      if (/^\S/.test(l)) {
        inHooks = false;
        continue;
      }
      const e = FRONTMATTER_EVENT.exec(l);
      if (e && /^\s{1,4}\S/.test(l)) {
        events.push(e[1]);
      }
    }
  }
  return [...new Set(events)];
}

/** The `name:` of a skill's or subagent's frontmatter, or null. */
function frontmatterName(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  const n = m ? /^name\s*:\s*["']?([^"'\r\n#]+?)["']?\s*$/m.exec(m[1]) : null;
  return n ? n[1].trim() : null;
}

function listFiles(dir, depth, pred, out = [], budget = { n: 5000 }) {
  let names;
  try {
    names = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const d of names) {
    if (budget.n-- <= 0) {
      return out;
    }
    const p = path.join(dir, d.name);
    if (d.isDirectory() && depth > 0 && d.name !== "node_modules" && d.name !== ".git") {
      listFiles(p, depth - 1, pred, out, budget);
    } else if (d.isFile() && pred(p)) {
      out.push(p);
    }
  }
  return out;
}

/**
 * Every hook another source adds to the session (red-team I9a; round 2, N3):
 * user, project and local settings and the user's --settings values, for
 * every event, plus the hook sources Claude Code also reads: project skill
 * and subagent frontmatter (`.claude/skills/<name>/SKILL.md`,
 * `.claude/agents/*.md`), the user's skills and subagents, plugin
 * `hooks/hooks.json` under the user's plugins directory, and `--plugin-dir`
 * directories. None of these can be Enclawed Code's own hook in launcher mode:
 * that one exists only in the generated --settings file, under a session
 * path created after this scan, so nothing here is skipped by name.
 *
 * `scope` is "project" for anything the repository supplies (committed
 * settings, skills, subagents), "local" for .claude/settings.local.json,
 * "user", "--settings" or "plugin" otherwise.
 *
 * @returns {Array<{ scope: string, file: string, event: string, command: string }>}
 */
export function otherHooks({ projectDir, env, extra = [], pluginDirs = [] }) {
  const out = [];
  const scan = (scope, file, doc) => {
    const hooks = doc?.hooks;
    if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) {
      return;
    }
    for (const [event, list] of Object.entries(hooks)) {
      for (const m of Array.isArray(list) ? list : []) {
        for (const h of Array.isArray(m?.hooks) ? m.hooks : []) {
          const command = typeof h?.command === "string" ? h.command : JSON.stringify(h);
          // `raw` and `matcher`: the full entry, for a per-repository grant's digest (project-grants.mjs).
          out.push({ scope, file, event, command, matcher: m?.matcher ?? null, raw: h ?? null });
        }
      }
    }
  };
  for (const { scope, file } of lowerSettingsFiles({ projectDir, env })) {
    scan(scope, file, readJson(file));
  }
  for (const [i, doc] of extra.entries()) {
    scan("--settings", `--settings value ${i + 1}`, doc);
  }
  const configDir = env.CLAUDE_CONFIG_DIR || path.join(env.HOME || os.homedir(), ".claude");
  const md = (p) => /\.md$/i.test(p);
  for (const [scope, base] of [
    ["project", path.join(projectDir, ".claude")],
    ["user", configDir],
  ]) {
    for (const f of [...listFiles(path.join(base, "skills"), 2, (p) => path.basename(p) === "SKILL.md"), ...listFiles(path.join(base, "agents"), 2, md)]) {
      let text;
      try {
        text = fs.readFileSync(f, "utf8");
      } catch {
        continue;
      }
      // What declares it (a skill or a subagent) and its name, so a launch can switch it off.
      const kind = path.basename(f) === "SKILL.md" ? "skill" : "agent";
      const name = frontmatterName(text) ?? (kind === "skill" ? path.basename(path.dirname(f)) : path.basename(f, path.extname(f)));
      for (const event of frontmatterHooks(text)) {
        out.push({ scope, file: f, event, command: "(frontmatter hook)", matcher: null, raw: text, declaredBy: { kind, name } });
      }
    }
  }
  const pluginHookFiles = [
    ...listFiles(path.join(configDir, "plugins"), 6, (p) => path.basename(p) === "hooks.json" && path.basename(path.dirname(p)) === "hooks"),
    ...pluginDirs.map((d) => path.join(d, "hooks", "hooks.json")),
  ];
  for (const f of pluginHookFiles) {
    const before = out.length;
    scan("plugin", f, readJson(f));
    // The plugin's directory (<plugin>/hooks/hooks.json), and whether it came from --plugin-dir.
    const pluginRoot = path.dirname(path.dirname(f));
    for (const h of out.slice(before)) {
      h.pluginRoot = pluginRoot;
      h.pluginDir = pluginDirs.includes(pluginRoot);
    }
  }
  return out;
}

// How the kit's reasons for a started .mcp.json server read in Enclawed Code's messages.
const ENABLED_BY = Object.freeze({ "non-interactive": "a non-interactive session", bypass: "bypass permissions" });

/**
 * Settings from the repository that make Claude Code run a command, like a
 * hook does (red-team round 4, F2), found by the kit
 * (repositoryCommandSettings): every command-valued setting in project or
 * local scope (`.claude/settings.json`, `.claude/settings.local.json`), the
 * list derived from Claude Code's own schema (settings-schema.mjs
 * commandPaths: apiKeyHelper, statusLine, fileSuggestion, otelHeadersHelper,
 * awsAuthRefresh, awsCredentialExport, gcpAuthRefresh, processWrapper, ...),
 * and the project's `.mcp.json` servers that will start: approved by
 * `enableAllProjectMcpServers` or `enabledMcpjsonServers` in any settings
 * scope (or --settings), or, as Claude Code 2.1.326 does on its own, every
 * not-disabled one in a non-interactive (-p) or bypass-permissions session.
 *
 * @returns {Array<{ scope: string, file: string, key: string, command: string, raw: any, enabledBy?: string }>}
 */
export function repositoryCommandSettings({ projectDir, env, extra = [], print = false, bypass = false, paths = commandPaths() }) {
  const settings = [
    ...lowerSettingsFiles({ projectDir, env }).map(({ scope, file }) => ({ scope, file, doc: readJson(file) })),
    ...extra.map((doc, i) => ({ scope: "settings-flag", file: `--settings value ${i + 1}`, doc })),
  ];
  const mcpFile = path.join(projectDir, ".mcp.json");
  const mcpDoc = readJson(mcpFile);
  const found = kit.repositoryCommandSettings({
    settings,
    mcpJson: mcpDoc === null ? null : { file: mcpFile, doc: mcpDoc },
    commandPaths: paths,
    session: { nonInteractive: print, bypass },
  });
  return found.map(({ value, enabledBy, ...c }) => ({ ...c, raw: value, ...(enabledBy ? { enabledBy: ENABLED_BY[enabledBy] ?? enabledBy } : {}) }));
}

/** The PreToolUse subset of otherHooks (kept for callers of the round-1 API). */
export function otherPreToolUseHooks(o) {
  return otherHooks(o).filter((h) => h.event === "PreToolUse");
}
