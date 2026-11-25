import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { enrollDemoCredential, signDemoTicket } from "../src/demo-credential.mjs";
import { matchGrant } from "../src/project-grants.mjs";
import { ledgerFileFor } from "../src/file-integrity.mjs";
import { kit } from "../src/kit.mjs";
import { realpathNearest } from "../src/paths.mjs";
import { createSession, otherHooks, repositoryCommandSettings, updateSession } from "../src/session.mjs";
import { hookCommand } from "../src/settings.mjs";
import { recordClaudeEnvironment } from "../src/shell-env.mjs";
import { makeClaudeSnapshot } from "./fixtures/claude-snapshot.mjs";
import { inUserNamespace } from "../src/userns.mjs";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const HOOK = path.join(ROOT, "bin", "ecwcode-hook.mjs");
export const LAUNCHER = path.join(ROOT, "bin", "ecwcode.mjs");
/** Enclawed Code's own commands (ecwctl). */
export const CTL = path.join(ROOT, "bin", "ecwctl.mjs");
/** The launcher with the suite's stand-in authority (test/fixtures/launcher-entry.mjs). */
export const LAUNCHER_ENTRY = path.join(ROOT, "test", "fixtures", "launcher-entry.mjs");
/** ecwctl with the suite's stand-in authority (test/fixtures/ctl-entry.mjs). */
export const CTL_ENTRY = path.join(ROOT, "test", "fixtures", "ctl-entry.mjs");
export const FAKE_CLAUDE = path.join(ROOT, "test", "fixtures", "fake-claude.mjs");

/** A throwaway HOME, project directory and PATH with a fake `claude`. */
export function sandbox() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-test-")));
  const home = path.join(dir, "home");
  const project = path.join(dir, "project");
  const bin = path.join(dir, "bin");
  // Stands in for the root-owned /etc/enclawed (src/authority.mjs
  // setTestAuthority, passed to test/fixtures/launcher-entry.mjs as an
  // argument): the administrator's grants are written here.
  const admin = path.join(dir, "admin");
  for (const d of [home, project, bin]) {
    fs.mkdirSync(d, { recursive: true });
  }
  fs.mkdirSync(admin, { mode: 0o755 });
  const grantFile = path.join(admin, "enclawed-code-opt-outs.json");
  const writeGrants = (doc) => {
    if (doc === null) {
      fs.rmSync(grantFile, { force: true });
    } else {
      fs.writeFileSync(grantFile, JSON.stringify({ v: 2, ...doc }), { mode: 0o644 });
    }
  };
  fs.symlinkSync(FAKE_CLAUDE, path.join(bin, "claude"));
  // No Enclaweder in tests: ENCLAWEDER_ROOT is unset (software-only on a
  // fresh latch; "optional" is an administrator's grant, refused from a shell).
  const env = {
    PATH: `${bin}${path.delimiter}${path.dirname(process.execPath)}${path.delimiter}/usr/bin${path.delimiter}/bin`,
    HOME: home,
    TMPDIR: dir,
  };
  const uid = process.getuid?.() ?? 0;
  // The isolation runner runs as root of its own user namespace: a deliberate
  // sandbox, as Claude Code's own IS_SANDBOX says (it refuses bypass mode for a
  // root that is not one, and Enclawed Code then does not default to it).
  if (uid === 0) {
    env.IS_SANDBOX = "1";
  }
  const sb = {
    dir,
    home,
    project,
    bin,
    env,
    admin,
    grantFile,
    /**
     * The stand-in authority for the launcher (src/authority.mjs). The fake
     * claude does not model the interactive pre-validation run (round 5), so
     * it is off here; its own test turns it on.
     */
    authority: {
      optOutDirs: [admin],
      managedPolicyPath: path.join(admin, "managed-policy.json"),
      trustedUids: [...new Set([0, uid, ...(inUserNamespace() ? [65534] : [])])],
      ignoreUserNamespace: true,
      prevalidate: false,
    },
    /** Issue a fresh signed unlock ticket before each launcherRun (see issueTestTicket). */
    autoUnlock: true,
    /** Write the administrator's grant file (v2 body without "v"); null removes it. */
    grant(doc = {}) {
      writeGrants(doc);
    },
    /** Grants for every repository hook and command in the sandbox project, as an administrator would add them. */
    repoGrants({ hooks = true, commands = true } = {}) {
      const out = { projectHooks: [], projectCommands: [] };
      if (hooks) {
        for (const h of otherHooks({ projectDir: project, env }).filter((x) => x.scope === "project" || x.scope === "local")) {
          out.projectHooks.push(matchGrant({ kind: "hook", file: h.file, event: h.event, matcher: h.matcher, value: h.raw ?? h.command }, project, []).grant);
        }
      }
      if (commands) {
        for (const c of repositoryCommandSettings({ projectDir: project, env, print: true })) {
          out.projectCommands.push(matchGrant({ kind: "command", file: c.file, key: c.key, value: c.raw ?? c.command }, project, []).grant);
        }
      }
      return out;
    },
    writePolicy(policy) {
      fs.mkdirSync(path.join(home, ".enclawed"), { recursive: true });
      fs.writeFileSync(path.join(home, ".enclawed", "enclawed.json"), JSON.stringify({ enclawed: { policy } }));
    },
    auditFile: path.join(home, ".enclawed", "claude-code", "audit.jsonl"),
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
  enrollTestKey(sb);
  return sb;
}

/**
 * A session file as the launcher writes it, for an environment and project,
 * and the exact hook command line the generated settings carry.
 */
/**
 * What the launcher does before Claude Code starts (file-integrity.mjs
 * startFileIntegrity, without the watcher): the project's file record. A
 * fixture is the project as the person left it, so each fixture session
 * starts from a fresh record of it.
 */
export function recordProject(sb, extraEnv = {}) {
  const file = ledgerFileFor({ ...sb.env, ...extraEnv }, sb.project);
  fs.rmSync(file, { force: true });
  const ledger = kit.fileIntegrityLedger(file, realpathNearest(sb.project));
  ledger.compareAtLaunch(ledger.snapshot());
}

export function hookSession(sb, extraEnv = {}, { hardware = null, patch = null, claudeShell = true } = {}) {
  let s = createSession({ env: { ...sb.env, ...extraEnv }, cwd: sb.project });
  recordProject(sb, extraEnv);
  if (hardware || patch) {
    s = updateSession(s, { ...(hardware ? { hardware } : {}), ...(patch ?? {}) });
  }
  if (claudeShell) {
    claudeShellOf(s, { ...sb.env, ...extraEnv });
  }
  return { ...s, command: hookCommand({ origin: "launcher", session: s.file, digest: s.digest }) };
}

/**
 * What a launch leaves for the hook's map of Claude Code's shell
 * (shell-env.mjs), as a real session has it: the launcher's record of the
 * environment claude starts with (its PATH ending in the session's marker
 * directory, SHLVL 1 when unset, Enclawed Code's settings file) and the shell
 * snapshot Claude Code 2.1.326 writes of the login shell (fixtures/claude-snapshot.mjs).
 */
export function claudeShellOf(s, env) {
  const pathMarker = path.join(s.dir, "no-programs");
  fs.mkdirSync(pathMarker, { recursive: true, mode: 0o500 });
  const claudeEnv = { ...env, PATH: `${env.PATH}:${pathMarker}` };
  if (!/^[0-9]{1,3}$/.test(claudeEnv.SHLVL ?? "") || Number(claudeEnv.SHLVL) < 1 || Number(claudeEnv.SHLVL) > 998) {
    claudeEnv.SHLVL = "1";
  }
  const settingsFile = path.join(s.dir, "settings.json");
  if (!fs.existsSync(settingsFile)) {
    fs.writeFileSync(settingsFile, "{}\n");
  }
  const configDir = claudeEnv.CLAUDE_CONFIG_DIR || path.join(claudeEnv.HOME, ".claude");
  makeClaudeSnapshot({ configDir, home: claudeEnv.HOME, pathValue: claudeEnv.PATH, env: claudeEnv });
  recordClaudeEnvironment({ sessionDir: s.dir, nonce: s.session.nonce, env: claudeEnv, settingsFile, settingSources: ["user"], pathMarker });
}

/**
 * Run the hook the way Claude Code does: the generated command through a
 * shell, with Claude Code's environment (the sandbox env plus `extraEnv`,
 * which also reaches the launcher-side session resolution unless
 * `claudeEnv` gives Claude Code's environment separately).
 */
export function runHook(sb, input, extraEnv = {}, { session = null, claudeEnv = null, hardware = null, patch = null } = {}) {
  const s = session ?? hookSession(sb, extraEnv, { hardware, patch });
  const res = spawnSync("/bin/sh", ["-c", s.command], {
    input: typeof input === "string" ? input : JSON.stringify(input),
    env: { ...sb.env, ...(claudeEnv ?? extraEnv), CLAUDE_PROJECT_DIR: sb.project },
    cwd: sb.project,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  let out = null;
  try {
    out = JSON.parse(res.stdout);
  } catch {
    out = null;
  }
  // `nonce`: the session's notice nonce, which tags Enclawed's notices (round 4, D3).
  return { status: res.status, stdout: res.stdout, stderr: res.stderr, out, nonce: s.session?.noticeNonce ?? null };
}

/** runLauncher with the administrator's grant file `grantDoc` for this one run. */
export function runLauncherGranted(sb, args, grantDoc, extraEnv = {}, authority = {}) {
  sb.grant(grantDoc);
  try {
    return runLauncher(sb, args, extraEnv, authority);
  } finally {
    sb.grant(null);
  }
}

/** The argv that runs the launcher with the sandbox's stand-in authority (plus `authority` overrides). */
export function launcherArgv(sb, args, authority = {}) {
  return [LAUNCHER_ENTRY, JSON.stringify({ ...sb.authority, ...authority }), ...args];
}

/** The argv that runs ecwctl with the sandbox's stand-in authority (plus `authority` overrides). */
export function ctlArgv(sb, args, authority = {}) {
  return [CTL_ENTRY, JSON.stringify({ ...sb.authority, ...authority }), ...args];
}

/** Run `ecwctl ARGS` (a fresh unlock ticket first, as runLauncher). */
export function runCtl(sb, args, extraEnv = {}, authority = {}) {
  if (sb.autoUnlock && sb.testKey) {
    issueTestTicket(sb);
  }
  return spawnSync(process.execPath, ctlArgv(sb, args, authority), {
    env: { ...sb.env, ...extraEnv },
    cwd: sb.project,
    encoding: "utf8",
  });
}

/** runCtl with the administrator's grant file `grantDoc` for this one run. */
export function runCtlGranted(sb, args, grantDoc, extraEnv = {}, authority = {}) {
  sb.grant(grantDoc);
  try {
    return runCtl(sb, args, extraEnv, authority);
  } finally {
    sb.grant(null);
  }
}

/**
 * Run the launcher; a fresh one-use unlock ticket first (two-factor is
 * mandatory), unless sb.autoUnlock is false. `authority` overrides the
 * stand-in authority for this run (e.g. { handshakeTimeoutS: 2 }).
 */
export function runLauncher(sb, args, extraEnv = {}, authority = {}) {
  if (sb.autoUnlock && sb.testKey) {
    issueTestTicket(sb);
  }
  return spawnSync(process.execPath, launcherArgv(sb, args, authority), {
    env: { ...sb.env, ...extraEnv },
    cwd: sb.project,
    encoding: "utf8",
  });
}

export function pre(sb, tool, toolInput, extra = {}) {
  return {
    session_id: "sess-1",
    transcript_path: path.join(sb.dir, "transcript.jsonl"),
    cwd: sb.project,
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: tool,
    tool_input: toolInput,
    tool_use_id: `toolu_${Math.random().toString(36).slice(2)}`,
    ...extra,
  };
}

export function auditRecords(sb) {
  if (!fs.existsSync(sb.auditFile)) {
    return [];
  }
  return fs
    .readFileSync(sb.auditFile, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

/** runHook, without blocking this process (for relays served in-process). */
export async function runHookAsync(sb, input, extraEnv = {}, opts = {}) {
  const { spawn } = await import("node:child_process");
  const s = opts.session ?? hookSession(sb, extraEnv, opts);
  return new Promise((resolve) => {
    const c = spawn("/bin/sh", ["-c", s.command], { env: { ...sb.env, ...(opts.claudeEnv ?? extraEnv), CLAUDE_PROJECT_DIR: sb.project }, cwd: sb.project });
    let stdout = "";
    let stderr = "";
    c.stdout.on("data", (d) => (stdout += d));
    c.stderr.on("data", (d) => (stderr += d));
    c.on("close", (status) => {
      let out = null;
      try {
        out = JSON.parse(stdout);
      } catch {
        out = null;
      }
      resolve({ status, stdout, stderr, out });
    });
    c.stdin.end(typeof input === "string" ? input : JSON.stringify(input));
  });
}

// ─── Two-factor test credential ──────────────────────────────────────────
// Two-factor authentication is mandatory, and the suite runs without a
// security key (and must never touch one). Each sandbox therefore enrolls a
// SOFTWARE test credential in its own throwaway state dir, and the helpers
// sign unlock tickets with it, exactly in the format the framework verifies.
// This is a test credential written by the test into the sandbox, the same
// thing a process able to rewrite the state dir could do (auth.mjs header);
// it makes no claim about authenticators. The real-key path is covered by
// the framework's live test (enclawed-oss scripts/auth-live-test.sh).

function testAuthDir(sb) {
  return path.join(sb.home, ".enclawed", "claude-code", "auth");
}

/** Enroll the sandbox's software test credential (src/demo-credential.mjs: throwaway dirs only). */
export function enrollTestKey(sb) {
  sb.testKey = enrollDemoCredential(testAuthDir(sb));
  return sb.testKey;
}

/** Sign an unlock ticket with the sandbox's test credential (the framework's format). */
export function issueTestTicket(sb, opts = {}) {
  return signDemoTicket(sb.testKey, opts);
}

// ─── libfido2 test double (interactive two-factor path) ──────────────────
const FAKE_FIDO2_DIR = path.join(ROOT, "test", "fixtures", "fake-fido2");

/**
 * Real libfido2 tools in the directories the framework searches first. When
 * present, tests that need the test double skip: they must never reach a
 * real security key.
 */
export function systemFido2ToolsPresent() {
  return ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin"].some((d) => fs.existsSync(path.join(d, "fido2-token")) || fs.existsSync(path.join(d, "fido2-assert")));
}

/** Env additions that put the fido2-* test double (signing with sb.testKey) on PATH. */
export function fakeFido2Env(sb) {
  const stateFile = path.join(sb.dir, "fake-fido2.json");
  fs.writeFileSync(
    stateFile,
    JSON.stringify({
      privateKeyJwk: sb.testKey.privateKey.export({ format: "jwk" }),
      credentialId: sb.testKey.credential.credentialId,
      aaguid: sb.testKey.credential.aaguid,
      counterFile: path.join(sb.dir, "fake-fido2.counter"),
    }),
    { mode: 0o600 },
  );
  return { PATH: `${FAKE_FIDO2_DIR}${path.delimiter}${sb.env.PATH}`, FAKE_FIDO2_STATE: stateFile };
}

export const haveScript = spawnSync("script", ["-qec", "true", "/dev/null"]).status === 0;
/** Skip reason for tests that drive the interactive two-factor path through the libfido2 test double. */
export const ttyFido2Skip = (!haveScript && "no script(1)") || (systemFido2ToolsPresent() && "real libfido2 tools are installed: tests never drive a real key") || false;

/** Run `ecwcode ARGS` at a pseudo-terminal with the libfido2 test double on PATH (output merged into stdout). */
export function ecwcodeTty(sb, args, extraEnv = {}, authority = {}) {
  return ttyRun(sb, launcherArgv(sb, args, authority), extraEnv);
}

/** Run `ecwctl ARGS` at a pseudo-terminal with the libfido2 test double on PATH (output merged into stdout). */
export function ecwctlTty(sb, args, extraEnv = {}, authority = {}) {
  return ttyRun(sb, ctlArgv(sb, args, authority), extraEnv);
}

function ttyRun(sb, argv, extraEnv) {
  const q = (a) => `'${String(a).replaceAll("'", `'\\''`)}'`;
  return spawnSync("script", ["-qec", [process.execPath, ...argv].map(q).join(" "), "/dev/null"], {
    env: { ...sb.env, ...fakeFido2Env(sb), ...extraEnv },
    cwd: sb.project,
    encoding: "utf8",
    timeout: 60_000,
  });
}

/**
 * The administrator's managed login policy, installed for real (managed-login.mjs, as root would,
 * into a throwaway managed-settings directory): the authority fragment under which Enclawed Code may
 * act on the person's own Claude Code login (login-guard.mjs). Without it, it never does.
 */
export async function managedLoginPolicyAuthority(sb) {
  const dir = fs.mkdtempSync(path.join(sb.dir, "managed-login-"));
  fs.chmodSync(dir, 0o755);
  const fragment = { managedSettingsDir: dir, trustedUids: sb.authority.trustedUids, ignoreUserNamespace: true };
  const { setTestAuthority } = await import("../src/authority.mjs");
  const { loginPolicyCommand } = await import("../src/managed-login.mjs");
  setTestAuthority(fragment);
  const quiet = { write: () => true };
  try {
    const code = await loginPolicyCommand(["install"], { out: quiet, err: quiet, uid: 0, platform: "linux" });
    if (code !== 0) {
      throw new Error("the managed login policy could not be installed in the sandbox");
    }
  } finally {
    setTestAuthority(null);
  }
  return fragment;
}
