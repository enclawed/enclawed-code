// Shared helpers for `npm run test:live` (scripts/test-live.mjs): every live
// test runs the REAL Claude Code binary with the REAL model inside the OS
// sandbox of test/adversarial/sandbox.mjs (read-only filesystem, empty HOME,
// a throwaway overlay of ~/.claude so the login is readable and every write
// is discarded, the OAuth-expiry guard). Nothing here reads or writes the
// real ~/.claude or ~/.enclawed.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HOME, preflight, runSandboxed } from "../adversarial/sandbox.mjs";
import { enrollDemoCredential, signDemoTicket } from "../../src/demo-credential.mjs";

// ─── Two-factor in live runs (TEST ONLY) ─────────────────────────────────
// Two-factor authentication is mandatory, and live runs have no security key.
// Each run's THROWAWAY state dir (under the OS temp dir, refused anywhere else
// by src/demo-credential.mjs) gets a software test credential, the same one
// the unit and admission tests use: a headless launch gets a one-use unlock
// ticket signed by it; an interactive launch gets the libfido2 test double
// (test/fixtures/fake-fido2), which signs with it. Never a real key, never the
// real state dir.
const FAKE_FIDO2_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "fake-fido2");
const SYSTEM_FIDO2 = ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin"].some((d) => fs.existsSync(path.join(d, "fido2-token")) || fs.existsSync(path.join(d, "fido2-assert")));
/** Interactive live runs need the test double; with real libfido2 tools installed they are skipped, never driving a real key. */
export const liveInteractiveSkip = SYSTEM_FIDO2 ? "real libfido2 tools are installed: the interactive two-factor step would reach a real key" : false;

function liveTestCredential(r) {
  if (r.cred) {
    return r.cred;
  }
  const authDir = path.join(r.state, "claude-code", "auth");
  if (fs.existsSync(path.join(authDir, "factors.json"))) {
    return null; // the test enrolled its own (admission.live.mjs)
  }
  r.cred = enrollDemoCredential(authDir);
  return r.cred;
}

function liveFido2Env(r, cred) {
  const stateFile = path.join(r.runDir, "fake-fido2.json");
  fs.writeFileSync(
    stateFile,
    JSON.stringify({ privateKeyJwk: cred.privateKey.export({ format: "jwk" }), credentialId: cred.credential.credentialId, aaguid: cred.credential.aaguid, counterFile: path.join(r.runDir, "fake-fido2.counter") }),
    { mode: 0o600 },
  );
  return { FAKE_FIDO2_STATE: stateFile, FAKE_FIDO2_PATH: FAKE_FIDO2_DIR };
}

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const LAUNCHER = path.join(ROOT, "bin", "ecwcode.mjs");
export const DRIVER = path.join(ROOT, "test", "live", "pty-driver.py");
export const CLAUDE = path.join(HOME, ".local", "bin", "claude");
export const MODEL = process.env.ECWCODE_LIVE_MODEL ?? "haiku";

/** Why live runs cannot happen here, or null. */
export function liveSkipReason() {
  try {
    fs.accessSync(fs.realpathSync(CLAUDE), fs.constants.X_OK);
  } catch {
    return `no Claude Code binary at ${CLAUDE}`;
  }
  if (!fs.existsSync(path.join(HOME, ".claude", ".credentials.json"))) {
    return "no Claude Code login (~/.claude/.credentials.json)";
  }
  const p = preflight({ workdir: os.tmpdir(), minMinutes: Number(process.env.ECWCODE_LIVE_MIN_TOKEN_MINUTES ?? 30) });
  return p.length ? p.join("; ") : null;
}

/** A fresh run directory with a git project and Enclawed Code state. */
export function liveRunDir(name, files = {}) {
  const base = path.join(os.tmpdir(), "enclawed-code-live");
  fs.mkdirSync(base, { recursive: true });
  const runDir = fs.realpathSync(fs.mkdtempSync(path.join(base, `${name}-`)));
  const proj = path.join(runDir, "proj");
  const state = path.join(runDir, "state");
  const out = path.join(runDir, "out");
  for (const d of [proj, state, out]) {
    fs.mkdirSync(d, { recursive: true });
  }
  for (const [rel, content] of Object.entries({ "README.md": "# demo\n", ...files })) {
    fs.mkdirSync(path.dirname(path.join(proj, rel)), { recursive: true });
    fs.writeFileSync(path.join(proj, rel), content);
  }
  const git = (args) => execFileSync("git", ["-C", proj, ...args], { env: { PATH: process.env.PATH, HOME: proj, GIT_CONFIG_NOSYSTEM: "1" }, stdio: "ignore" });
  git(["init", "-q"]);
  git(["-c", "user.email=t@example.invalid", "-c", "user.name=t", "add", "-A"]);
  git(["-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--no-verify", "-m", "initial"]);
  fs.writeFileSync(path.join(state, "enclawed.json"), JSON.stringify({ enclawed: { policy: {} } }));
  return { runDir, proj, state, out, audit: path.join(state, "claude-code", "audit.jsonl") };
}

/**
 * Run `cmd` (argv) in the sandbox for run `r`. `interactive`: under the pty
 * driver with `answer` ("code", or text typed at Enclawed Code's prompt).
 */
export async function liveRun(r, cmd, { interactive = false, answer = "code", waitFile = "-", timeoutMs = 300_000, extraEnv = {} } = {}) {
  const cred = liveTestCredential(r);
  let fido2 = {};
  if (cred && interactive) {
    if (liveInteractiveSkip) {
      throw new Error(liveInteractiveSkip);
    }
    fido2 = liveFido2Env(r, cred);
  } else if (cred) {
    signDemoTicket(cred);
  }
  const env = {
    HOME,
    PATH: `${fido2.FAKE_FIDO2_PATH ? `${fido2.FAKE_FIDO2_PATH}:` : ""}${path.join(HOME, ".local", "bin")}:${path.dirname(process.execPath)}:/usr/bin:/bin`,
    ...(fido2.FAKE_FIDO2_STATE ? { FAKE_FIDO2_STATE: fido2.FAKE_FIDO2_STATE } : {}),
    TERM: interactive ? "xterm-256color" : "dumb",
    TMPDIR: "/tmp",
    ENCLAWED_STATE_DIR: r.state,
    ENCLAWED_CONFIG_PATH: path.join(r.state, "enclawed.json"),
    ENCLAWEDER_ROOT: "optional",
    ENCLAWEDER_STATE: path.join(r.state, "hw-root.state"),
    ENCLAWEDER_STATE_DIR: r.state,
    ENCLAWEDER_FORENSIC_LOG: path.join(r.state, "forensics.jsonl"),
    ENCLAWEDER_QUEUE_LOG: path.join(r.state, "hw-root.queue.jsonl"),
    OUT: r.out,
    PROJ: r.proj,
    ...extraEnv,
  };
  // Claude Code's per-user state (~/.claude.json, in the empty sandbox HOME):
  // onboarding done and this project trusted, so no first-run dialog.
  const seed = JSON.stringify({ hasCompletedOnboarding: true, lastOnboardingVersion: "2.1.326", theme: "dark", projects: { [r.proj]: { hasTrustDialogAccepted: true, hasCompletedProjectOnboarding: true, allowedTools: [] } } });
  const argv = interactive ? ["python3", DRIVER, path.join(r.out, "pty.log"), answer, waitFile, "--", ...cmd] : cmd;
  const script = [
    `printf '%s' ${JSON.stringify(seed).replace(/'/g, "'\\''")} > "$HOME/.claude.json"`,
    "touch /tmp/.run-start",
    '"$@"',
    "code=$?",
    'mkdir -p "$OUT/transcripts"',
    'find "$HOME/.claude/projects/$(printf %s "$PROJ" | tr -c "a-zA-Z0-9" -)" -name "*.jsonl" -newer /tmp/.run-start -exec cp {} "$OUT/transcripts/" \\; 2>/dev/null',
    'ls -la --time-style=full-iso "$HOME/.claude/projects/$(printf %s "$PROJ" | tr -c "a-zA-Z0-9" -)" > "$OUT/projects.txt" 2>&1',
    'exit "$code"',
  ].join("\n");
  const res = await runSandboxed({
    runDir: r.runDir,
    cwd: r.proj,
    argv: ["/bin/bash", "-c", script, "run", ...argv],
    env,
    appRoot: ROOT,
    stdoutFile: path.join(r.out, "stdout.txt"),
    stderrFile: path.join(r.out, "stderr.txt"),
    timeoutMs,
  });
  return { ...res, stdout: fs.readFileSync(path.join(r.out, "stdout.txt"), "utf8"), stderr: fs.readFileSync(path.join(r.out, "stderr.txt"), "utf8"), pty: interactive ? readOr(path.join(r.out, "pty.log")) : "" };
}

export function readOr(f, d = "") {
  try {
    return fs.readFileSync(f, "utf8");
  } catch {
    return d;
  }
}

export function auditOf(r) {
  return readOr(r.audit).split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

export function transcriptsOf(r) {
  const dir = path.join(r.out, "transcripts");
  const out = [];
  for (const f of fs.existsSync(dir) ? fs.readdirSync(dir) : []) {
    for (const l of readOr(path.join(dir, f)).split("\n").filter(Boolean)) {
      try {
        out.push(JSON.parse(l));
      } catch {
        /* partial line */
      }
    }
  }
  return out;
}

/** The claude argv through Enclawed Code (headless or interactive). */
export function ecwcodeArgs(prompt, { print = true, extra = [] } = {}) {
  return [process.execPath, LAUNCHER, ...(print ? ["-p"] : []), "--model", MODEL, "--permission-mode", "default", ...(print ? ["--output-format", "stream-json", "--verbose", "--max-budget-usd", "0.50"] : []), "--setting-sources", "project,local", ...extra, "--", prompt];
}

/** Every record type and decision the launcher wrote, for the report. */
export function summary(recs) {
  return recs.filter((x) => /tool\.pre|launch\.|accept/.test(x.type)).map((x) => `${x.type}${x.payload?.tool ? `:${x.payload.tool}` : ""}${x.payload?.decision ? `:${x.payload.decision}` : ""}${x.payload?.approval ? `:approved=${x.payload.approval.approved}` : ""}${x.payload?.code ? `:${x.payload.code}` : ""}`).join(", ");
}
