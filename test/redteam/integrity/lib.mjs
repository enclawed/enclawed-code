// Shared helpers for the integrity red-team PoCs. Every PoC works in a fresh
// temp directory: its own project, Enclawed state dir, history dir, policy and
// hardware-latch paths, so the user's real ~/.enclawed is never touched.
import { spawnSync } from "node:child_process";
import { createSession, otherHooks, repositoryCommandSettings, updateSession } from "../../../src/session.mjs";
import { matchGrant } from "../../../src/project-grants.mjs";
import { hookCommand } from "../../../src/settings.mjs";
import { enrollDemoCredential, signDemoTicket } from "../../../src/demo-credential.mjs";
import { setTestAuthority } from "../../../src/authority.mjs";
import { appStateDir } from "../../../src/paths.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const HOOK = path.join(ROOT, "bin", "ecwcode-hook.mjs");
// The launcher with the sandbox's stand-in authority and a fresh unlock
// ticket (rt-launcher.mjs). The real bin/ecwcode.mjs reads the
// root-owned /etc/enclawed and needs a person's security key.
export const LAUNCHER = path.join(ROOT, "test", "redteam", "integrity", "rt-launcher.mjs");
export const REAL_LAUNCHER = path.join(ROOT, "bin", "ecwcode.mjs");
// ecwctl (Enclawed Code's own commands) the same way (rt-ctl.mjs).
export const CTL = path.join(ROOT, "test", "redteam", "integrity", "rt-ctl.mjs");
export const FAKE_CLAUDE = path.join(ROOT, "test", "fixtures", "fake-claude.mjs");
// Live runs may use a throwaway HOME: then name the real binary with ECWCODE_REAL_CLAUDE.
export const REAL_CLAUDE = process.env.ECWCODE_REAL_CLAUDE ?? path.join(os.homedir(), ".local", "bin", "claude");

// Never bind the real Enclaweder from a PoC (red-team H14). Isolation is
// detected from the kernel, never from the environment: the process must be in
// a non-initial user namespace (uid_map) with an empty /sys/class/hidraw and
// every /dev/hidraw* node masked by /dev/null. Otherwise this script re-runs
// itself in a user+mount namespace that hides sysfs, binds /dev/null over every
// hidraw node, and puts an empty tmpfs over /run/user (no real broker socket,
// no host D-Bus). The one exception is a deliberate live-device run, named
// ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND (scripts/test-live.mjs sets it for
// the device PoCs, under the device flock); the framework honours the same name.
export const LIVE_DEVICE = process.env.ENCLAWEDER_LIVE_DEVICE_TEST === "I_UNDERSTAND";

/** True when this process cannot reach any Enclaweder (checked on the kernel's own view). */
export function deviceIsolated() {
  if (process.platform !== "linux") {
    return false;
  }
  let map = "";
  try {
    map = fs.readFileSync("/proc/self/uid_map", "utf8").trim();
  } catch {
    return false;
  }
  if (/^0\s+0\s+4294967295$/.test(map)) {
    return false; // the initial user namespace
  }
  let sys = [];
  try { sys = fs.readdirSync("/sys/class/hidraw"); } catch { /* none */ }
  if (sys.length > 0) {
    return false;
  }
  const nul = fs.statSync("/dev/null").rdev;
  let nodes = [];
  try { nodes = fs.readdirSync("/dev").filter((n) => /^hidraw\d+$/.test(n)); } catch { /* none */ }
  return nodes.every((n) => {
    try {
      const st = fs.statSync(`/dev/${n}`);
      return !st.isCharacterDevice() || st.rdev === nul;
    } catch {
      return true;
    }
  });
}

if (process.platform === "linux" && !LIVE_DEVICE && !deviceIsolated()) {
  const q = (a) => `'${a.replaceAll("'", "'\\''")}'`;
  const cmd = [process.execPath, ...process.argv.slice(1)].map(q).join(" ");
  const env = { ...process.env };
  delete env.XDG_RUNTIME_DIR;
  delete env.DBUS_SESSION_BUS_ADDRESS;
  const r = spawnSync("unshare", ["-r", "-m", "sh", "-c", `mount -t tmpfs none /sys/class/hidraw && for n in /dev/hidraw*; do [ -e "$n" ] && mount --bind /dev/null "$n"; done; mount -t tmpfs none /run/user && exec ${cmd}`], {
    stdio: "inherit", env,
  });
  if (r.status === null || r.error) {
    console.error("refusing to run: cannot hide the Enclaweder (unshare failed)");
    process.exit(2);
  }
  process.exit(r.status);
}

export function sandbox(name = "rt") {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `enclawed-code-rt-${name}-`)));
  const project = path.join(dir, "project");
  const state = path.join(dir, "state");
  const bin = path.join(dir, "bin");
  const home = path.join(dir, "home");
  for (const d of [project, state, bin, home]) fs.mkdirSync(d, { recursive: true });
  fs.symlinkSync(FAKE_CLAUDE, path.join(bin, "claude"));
  // A neutral user policy (open flavor, nothing pre-approved).
  const userPolicy = path.join(dir, "user-policy.json");
  fs.writeFileSync(userPolicy, JSON.stringify({ enclawed: { policy: {} } }));
  const env = {
    PATH: `${bin}:${path.dirname(process.execPath)}:/usr/bin:/bin`,
    // A throwaway HOME (red-team H14 T4): never the user's forensic log, latch scan or ~/.claude.
    HOME: home,
    TMPDIR: dir,
    ENCLAWED_STATE_DIR: state,
    ENCLAWED_CONFIG_PATH: userPolicy,
    // ENCLAWEDER_ROOT unset: software-only on a fresh latch ("optional" is
    // an administrator's grant now, refused from a shell: sb.setAuthority /
    // sb.grant({ hardwareRoot: "optional" })).
    ENCLAWEDER_STATE: path.join(dir, "hw.state"),
    ENCLAWEDER_STATE_DIR: path.join(dir, "hwdir"),
    // Never the real device, the real broker or the real forensic log from a PoC (H14): a
    // sandbox-local broker socket and forensic log, and a framework-level refusal of any direct
    // device open (ENCLAWEDER_DEVICE=deny), whatever else the PoC does.
    ENCLAWEDER_DEVICE: "deny",
    ENCLAWEDER_BROKER: path.join(dir, "broker.sock"),
    // (ENCLAWEDER_FORENSIC_LOG is not passed to the framework any more; the
    // forensic log defaults to $HOME/.enclawed-forensics.jsonl: this throwaway HOME.)
    XDG_RUNTIME_DIR: dir,
  };
  // The stand-in for the root-owned /etc/enclawed (grants) and the managed
  // policy, and the throwaway two-factor credential (rt-launcher.mjs).
  const admin = path.join(dir, "admin");
  fs.mkdirSync(admin, { mode: 0o755 });
  const uid = process.getuid?.() ?? 0;
  const authority = {
    optOutDirs: [admin],
    managedPolicyPath: path.join(admin, "managed-policy.json"),
    trustedUids: [...new Set([0, uid, 65534])],
    ignoreUserNamespace: true,
    prevalidate: false,
  };
  const cred = enrollDemoCredential(path.join(appStateDir(env), "auth"));
  const credential = { authDir: cred.authDir, credential: cred.credential, privateKeyPem: cred.privateKey.export({ type: "pkcs8", format: "pem" }) };
  let current = authority;
  const writeAuthority = (patch = {}) => {
    current = { ...authority, ...patch };
    fs.writeFileSync(path.join(dir, "rt-authority.json"), JSON.stringify({ authority: current, credential }), { mode: 0o600 });
  };
  writeAuthority();
  return {
    dir, project, state, bin, env, userPolicy, admin,
    auditFile: path.join(state, "claude-code", "audit.jsonl"),
    /** Override the stand-in authority (e.g. { handshakeTimeoutS: 2 }) for the following launches. */
    setAuthority(patch) { writeAuthority(patch); },
    /** For a PoC that runs prepareLaunch/launchSession in its own process: the same stand-in authority. */
    useAuthorityInProcess() { setTestAuthority(current); },
    /** A fresh one-use unlock ticket (rt-launcher.mjs signs one before every launch by itself). */
    ticket() { return signDemoTicket(cred); },
    /**
     * Env additions for an INTERACTIVE launch: the libfido2 test double
     * (test/fixtures/fake-fido2), signing with this sandbox's credential.
     * Refused when real libfido2 tools are installed: a PoC never drives a real key.
     */
    fakeFido2Env() {
      if (["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin"].some((d) => fs.existsSync(path.join(d, "fido2-token")) || fs.existsSync(path.join(d, "fido2-assert")))) {
        throw new Error("real libfido2 tools are installed: this PoC does not drive a security key; run it where they are not");
      }
      const stateFile = path.join(dir, "fake-fido2.json");
      fs.writeFileSync(stateFile, JSON.stringify({ privateKeyJwk: cred.privateKey.export({ format: "jwk" }), credentialId: cred.credential.credentialId, aaguid: cred.credential.aaguid, counterFile: path.join(dir, "fake-fido2.counter") }), { mode: 0o600 });
      return { PATH: `${path.join(ROOT, "test", "fixtures", "fake-fido2")}:${env.PATH}`, FAKE_FIDO2_STATE: stateFile };
    },
    /** The administrator's grant file (v2 body without "v"); null removes it. */
    grant(doc) {
      const f = path.join(admin, "enclawed-code-opt-outs.json");
      if (doc === null) fs.rmSync(f, { force: true });
      else fs.writeFileSync(f, JSON.stringify({ v: 2, ...doc }), { mode: 0o644 });
    },
    /** Grant every repository hook and command in the project, as an administrator would (projectHooks/projectCommands). */
    grantRepository() {
      const g = { projectHooks: [], projectCommands: [] };
      for (const h of otherHooks({ projectDir: project, env }).filter((x) => x.scope === "project" || x.scope === "local")) {
        g.projectHooks.push(matchGrant({ kind: "hook", file: h.file, event: h.event, matcher: h.matcher, value: h.raw ?? h.command }, project, []).grant);
      }
      for (const c of repositoryCommandSettings({ projectDir: project, env, print: true })) {
        g.projectCommands.push(matchGrant({ kind: "command", file: c.file, key: c.key, value: c.raw ?? c.command }, project, []).grant);
      }
      this.grant(g);
      return g;
    },
    cleanup() { fs.rmSync(dir, { recursive: true, force: true }); },
  };
}

// Variables only Claude Code's environment carries (an attacker's settings
// `env`); everything else in extraEnv is also the user's shell, which the
// launcher resolves into the session file.
const CLAUDE_ONLY = new Set(["ECWCODE_HW_BROKER", "NODE_OPTIONS", "LD_PRELOAD"]);

/** The launcher's hook command for this environment (the session file it writes). */
export function hookCommandFor(root, env, cwd) {
  // The install at `root` (a copy of Enclawed Code elsewhere, for I4) writes its own session.
  const code = `import { createSession } from ${JSON.stringify(path.join(root, "src", "session.mjs"))};
import { hookCommand } from ${JSON.stringify(path.join(root, "src", "settings.mjs"))};
const s = createSession({ env: process.env, cwd: ${JSON.stringify(cwd)} });
process.stdout.write(hookCommand({ origin: "launcher", session: s.file, digest: s.digest }));`;
  return spawnSync(process.execPath, ["--input-type=module", "-e", code], { env, encoding: "utf8" }).stdout;
}

export function hook(sb, input, extraEnv = {}, _args = [], { root = ROOT } = {}) {
  const launcherEnv = { ...sb.env };
  for (const [k, v] of Object.entries(extraEnv)) {
    if (!CLAUDE_ONLY.has(k)) {
      launcherEnv[k] = v;
    }
  }
  const cmd = hookCommandFor(root, launcherEnv, sb.project);
  const res = spawnSync("/bin/sh", ["-c", cmd], {
    input: typeof input === "string" ? input : JSON.stringify(input),
    env: { ...sb.env, ...extraEnv, CLAUDE_PROJECT_DIR: sb.project },
    cwd: sb.project,
    encoding: "utf8",
    timeout: 20000,
  });
  let out = null;
  try { out = JSON.parse(res.stdout); } catch { /* not JSON */ }
  return { status: res.status, stdout: res.stdout, stderr: res.stderr, out, decision: out?.hookSpecificOutput?.permissionDecision ?? null };
}

export function pre(sb, tool, toolInput, extra = {}) {
  return {
    session_id: "rt-sess", transcript_path: path.join(sb.dir, "transcript.jsonl"), cwd: sb.project,
    permission_mode: "default", hook_event_name: "PreToolUse", tool_name: tool, tool_input: toolInput,
    tool_use_id: `toolu_${Math.random().toString(36).slice(2)}`, ...extra,
  };
}

export function ecwcode(sb, args, extraEnv = {}, cwd = sb.project) {
  return spawnSync(process.execPath, [LAUNCHER, ...args], { env: { ...sb.env, ...extraEnv }, cwd, encoding: "utf8", timeout: 600000 });
}

/** Environment for a live run of the real claude: the parent session's CLAUDE* vars stripped. */
export function liveEnv(sb, extra = {}) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (/^(CLAUDE|CLAUDECODE|AI_AGENT)/.test(k)) continue;
    // The host's runtime dir and session bus are not the sandbox's (red-team H14 T4).
    if (k === "XDG_RUNTIME_DIR" || k === "DBUS_SESSION_BUS_ADDRESS") continue;
    env[k] = v;
  }
  // A throwaway Claude Code config dir (no login, no real transcripts), when given.
  const cfg = process.env.ECWCODE_RT_CLAUDE_CONFIG_DIR ? { CLAUDE_CONFIG_DIR: process.env.ECWCODE_RT_CLAUDE_CONFIG_DIR } : {};
  return { ...env, ...sb.env, ...cfg, PATH: `${path.dirname(REAL_CLAUDE)}:${path.dirname(process.execPath)}:/usr/bin:/bin`, ECWCODE_CLAUDE_PATH: REAL_CLAUDE, ...extra };
}

export function liveRun(sb, prompt, { extraArgs = [], extraEnv = {}, cwd = sb.project } = {}) {
  const args = ["-p", "--permission-mode", "default", "--model", "haiku", "--max-budget-usd", "0.50", ...extraArgs, "--", prompt];
  return spawnSync(process.execPath, [LAUNCHER, ...args], { env: liveEnv(sb, extraEnv), cwd, encoding: "utf8", timeout: 300000 });
}

export function readAudit(file) {
  try {
    return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch { return []; }
}

export function result(id, ok, detail) {
  // ok === true means the ATTACK SUCCEEDED (a finding); false means Enclawed Code resisted.
  const tag = ok ? "VULNERABLE" : "RESISTED";
  process.stdout.write(`[${id}] ${tag}: ${detail}\n`);
  return ok;
}

/**
 * A simulated Enclaweder for in-process launchSession PoCs: an Ed25519 key
 * that signs the device's challenge message, with a placeholder certificate
 * (a held root must have an attestable device, red-team H15; the
 * manufacturer-certificate check is not what these PoCs attack). The same
 * double test/hardware.test.mjs uses. Nothing here opens a device.
 */
export async function simulatedSigningDevice() {
  const { generateKeyPairSync, sign } = await import("node:crypto");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const uid = Buffer.alloc(12, 7);
  return {
    getIdentity: async () => ({ uid, pubkeyRaw: pub, serial: "ENCLW-SIM" }),
    getCert: async () => Buffer.alloc(119, 1),
    challenge: async (n) => ({ uid, sig: sign(null, Buffer.concat([Buffer.from("ECW-CHALLENGE-01"), Buffer.from(Buffer.from(n).toString("hex"), "hex"), uid]), privateKey) }),
  };
}
