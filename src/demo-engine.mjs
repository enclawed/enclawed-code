// The sandbox the offline adversarial scenarios (and `ecwctl demo`)
// run in: a throwaway project and Enclawed state directory, with every path
// the framework would otherwise take from HOME pointed inside it, so nothing
// touches the user's real ~/.enclawed, audit log, history or hardware-root
// state.
//
// Every check goes through the real binaries of one ecwcode install (the
// `root`): the hook is run as Claude Code runs it (a child process, the hook
// input as JSON on stdin), and restores and verification go through the
// `ecwcode` command itself. No model is called. `root` is a parameter so the
// mutation check can point the same scenarios at a deliberately broken copy.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { enrollDemoCredential, signDemoTicket } from "./demo-credential.mjs";

export const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Run a command and collect its output; never rejects. */
export function run(cmd, args, { env, cwd, input, timeoutMs = 60_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { env, cwd, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ status: 127, stdout, stderr: `${stderr}${err.message}` });
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input ?? "");
  });
}

/** Is an Enclaweder visible to this machine (Linux: /sys/class/hidraw)? */
export function deviceVisible() {
  if (process.platform !== "linux") {
    return null; // unknown without booting; the hardware scenario boots to find out
  }
  try {
    return fs.readdirSync("/sys/class/hidraw").length > 0;
  } catch {
    return false;
  }
}

let realRoot = null;

/**
 * The REAL hardware root, held once for the whole demo the way the Enclawed Code
 * launcher holds it (the user's own environment and latch, normal operation:
 * identity, certificate and challenges only), with an authenticated relay
 * that answers each hook with the device's signature over that hook's fresh
 * nonce. Null when no Enclaweder is attached or it cannot be held. Nothing is
 * ever simulated here.
 */
export async function holdRealRoot(root = DEFAULT_ROOT) {
  if (realRoot) {
    return realRoot;
  }
  if (deviceVisible() === false) {
    realRoot = { held: false, reason: "no Enclaweder attached" };
    return realRoot;
  }
  const imp = (m) => import(new URL(`file://${path.join(root, "src", m)}`).href);
  const { loadFramework } = await imp("framework.mjs");
  const { holdSessionRoot, launcherHealth, startHardwareRelay } = await imp("hardware.mjs");
  const { attest, boundDevice } = await imp("device.mjs");
  let fw;
  try {
    ({ fw } = await loadFramework());
  } catch (err) {
    realRoot = { held: false, reason: `framework: ${err.message}` };
    return realRoot;
  }
  // Release on any exit (a held root left open would look like an interrupted
  // accredited session at the next boot), and remove the listener on release.
  let exitHandler = null;
  const held = await holdSessionRoot(fw, {
    onExit: (h) => {
      exitHandler = h;
      process.on("exit", h);
    },
  });
  if (held.mode !== "held") {
    realRoot = { held: false, mode: held.mode, reason: held.reason ?? (held.mode === "software-only" ? "no Enclaweder attached" : held.mode), release: held.release };
    return realRoot;
  }
  const device = await boundDevice(fw).catch(() => null);
  // A directory short enough for the socket under any TMPDIR (the kit's privateSocketDir).
  const dir = fw.adapterKit?.privateSocketDir ? fw.adapterKit.privateSocketDir("cn-demo-hw-", { maxName: 7 }) : fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-demo-hw-"));
  fs.chmodSync(dir, 0o700);
  const relay = await startHardwareRelay({
    socketPath: path.join(dir, "hw.sock"),
    health: async (tool, nonce) => {
      const h = launcherHealth(fw, tool);
      if (h.allowed && device && nonce) {
        h.attestation = await attest(device, nonce);
      }
      return h;
    },
  });
  realRoot = {
    held: true,
    serial: device?.serial ?? null,
    hardware: { mode: "relay", relay: { path: relay.path, secret: relay.secret }, device: device ? { pub: device.pub, uid: device.uid, serial: device.serial } : null },
    status: () => launcherHealth(fw, "demo"),
    async release() {
      await relay.close();
      fs.rmSync(dir, { recursive: true, force: true });
      held.release();
      if (exitHandler) {
        process.off("exit", exitHandler);
      }
    },
  };
  return realRoot;
}

export async function releaseRealRoot() {
  if (realRoot?.release) {
    await realRoot.release();
  }
  realRoot = null;
}

/**
 * A throwaway sandbox for one scenario.
 * @param {{ root?: string, tmpRoot?: string, name?: string }} opts
 */
export function createSandbox({ root = DEFAULT_ROOT, tmpRoot = os.tmpdir(), name = "scenario" } = {}) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmpRoot, `enclawed-code-demo-${name}-`)));
  const home = path.join(dir, "home");
  const project = path.join(dir, "project");
  const state = path.join(dir, "state");
  for (const d of [home, project, state]) {
    fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  }
  const launcherBin = path.join(root, "bin", "ecwcode.mjs");
  const ctlBin = path.join(root, "bin", "ecwctl.mjs");
  const configPath = path.join(state, "enclawed.json");
  const transcript = path.join(dir, "transcript.jsonl");
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    TMPDIR: dir,
    ENCLAWED_STATE_DIR: state,
    ENCLAWED_CONFIG_PATH: configPath,
    // Software-only: there is no Enclaweder in the demo unless a scenario
    // starts a simulated one.
    ENCLAWEDER_ROOT: "optional",
    ENCLAWEDER_STATE: path.join(state, "hw-root.state"),
    ENCLAWEDER_STATE_DIR: state,
    ENCLAWEDER_FORENSIC_LOG: path.join(state, "forensics.jsonl"),
    ENCLAWEDER_QUEUE_LOG: path.join(state, "hw-root.queue.jsonl"),
  };
  const auditFile = path.join(state, "claude-code", "audit.jsonl");
  // Two-factor is mandatory in the sandbox too: its own throwaway credential
  // signs a ticket before each launch (demo-credential.mjs).
  const demoCredential = enrollDemoCredential(path.join(state, "claude-code", "auth"));
  let n = 0;
  const runBin = (bin, args, extraEnv) => {
    // ENCLAWEDER_BROKER=off: a launch inside the demo never binds the real
    // device to the sandbox's throwaway latch.
    signDemoTicket(demoCredential);
    // ENCLAWEDER_ROOT=optional is an administrator's grant, refused from a
    // shell (env-authority.mjs): the program runs with it unset, which on
    // the sandbox's fresh latch is the same software-only start.
    const { ENCLAWEDER_ROOT: _optional, ...launchEnv } = env;
    return run(process.execPath, [bin, ...args], { env: { ...launchEnv, ENCLAWEDER_BROKER: "off", ...extraEnv }, cwd: project });
  };

  const sb = {
    dir,
    home,
    project,
    state,
    env,
    root,
    auditFile,
    transcript,
    sessionId: "demo-session",

    file(rel, content) {
      const abs = path.join(project, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, content);
      return abs;
    },
    read(rel) {
      try {
        return fs.readFileSync(path.join(project, rel), "utf8");
      } catch {
        return null;
      }
    },
    exists(rel) {
      return fs.existsSync(path.join(project, rel));
    },
    writePolicy(policy) {
      fs.writeFileSync(configPath, JSON.stringify({ enclawed: { policy } }));
    },

    /** The hook input Claude Code sends for one tool call. */
    preInput(tool, toolInput, mode, extra = {}) {
      n += 1;
      return {
        session_id: sb.sessionId,
        transcript_path: transcript,
        cwd: project,
        permission_mode: mode,
        hook_event_name: "PreToolUse",
        tool_name: tool,
        tool_input: toolInput,
        tool_use_id: `toolu_demo_${String(n).padStart(3, "0")}`,
        ...extra,
      };
    },

    /**
     * Run ecwcode-hook once with this input, exactly as Claude Code would:
     * the hook command from a session file the launcher code writes, through
     * a shell. `launcherEnv` is what the user's shell would have when starting
     * Enclawed Code; `hardware` overrides the session's hardware mode.
     */
    async hookRaw(input, launcherEnv = {}, { hardware } = {}) {
      const { createSession, updateSession } = await import(new URL(`file://${path.join(root, "src", "session.mjs")}`).href);
      const { hookCommand } = await import(new URL(`file://${path.join(root, "src", "settings.mjs")}`).href);
      let s = createSession({ env: { ...env, ...launcherEnv }, cwd: project });
      const hw = hardware !== undefined ? hardware : realRoot?.held ? realRoot.hardware : null;
      if (hw) {
        s = updateSession(s, { hardware: hw });
      }
      const command = hookCommand({ origin: "launcher", session: s.file, digest: s.digest });
      const r = await run("/bin/sh", ["-c", command], {
        env: { ...env, CLAUDE_PROJECT_DIR: project },
        cwd: project,
        input: JSON.stringify(input),
      });
      fs.rmSync(s.dir, { recursive: true, force: true });
      let out = null;
      try {
        out = JSON.parse(r.stdout);
      } catch {
        out = null;
      }
      return { ...r, out };
    },

    /** One PreToolUse call: the decision, its reason and the audited record. */
    async pre(tool, toolInput, mode, extraEnv = {}, opts = {}) {
      const input = sb.preInput(tool, toolInput, mode);
      const r = await sb.hookRaw(input, extraEnv, opts);
      const hso = r.out?.hookSpecificOutput ?? {};
      const record = sb.auditRecords().filter((x) => x.type === "claude-code.tool.pre" && x.payload?.toolUseId === input.tool_use_id).at(-1) ?? null;
      return {
        input,
        decision: hso.permissionDecision ?? null,
        reason: hso.permissionDecisionReason ?? r.stderr.trim(),
        codes: record?.payload?.codes ?? [],
        targets: record?.payload?.targets ?? [],
        exitCode: r.status,
        audited: record !== null,
      };
    },

    /** Run the `ecwcode` command of this install (a launch). */
    ecwcode(args, extraEnv = {}) {
      return runBin(launcherBin, args, extraEnv);
    },

    /** Run the `ecwctl` command of this install (history, audit, ...). */
    ecwctl(args, extraEnv = {}) {
      return runBin(ctlBin, args, extraEnv);
    },

    auditRecords() {
      try {
        return fs
          .readFileSync(auditFile, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((l) => {
            try {
              return JSON.parse(l);
            } catch {
              return null;
            }
          })
          .filter(Boolean);
      } catch {
        return [];
      }
    },

    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
  return sb;
}

/** A stand-in for the claude executable: prints a version, records how it was launched. No model. */
export function writeStandInClaude(sb) {
  const file = path.join(sb.dir, "stand-in-claude.mjs");
  const out = path.join(sb.dir, "stand-in-claude.json");
  fs.writeFileSync(
    file,
    `#!${process.execPath}
import fs from "node:fs";
const args = process.argv.slice(2);
if (args[0] === "--version") { process.stdout.write("2.1.326 (Claude Code)\\n"); process.exit(0); }
const i = args.indexOf("--settings");
const settings = i >= 0 ? JSON.parse(fs.readFileSync(args[i + 1], "utf8")) : null;
fs.writeFileSync(${JSON.stringify(out)}, JSON.stringify({ args, settings }));
`,
    { mode: 0o700 },
  );
  return {
    path: file,
    record() {
      try {
        return JSON.parse(fs.readFileSync(out, "utf8"));
      } catch {
        return null;
      }
    },
  };
}
