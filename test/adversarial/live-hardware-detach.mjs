#!/usr/bin/env node
// LIVE, REAL DEVICE: a hardware halt in the middle of an Enclawed Code session.
//
// Not part of `run.mjs --live`; run it on purpose, on a WSL host with the
// Enclaweder attached through usbipd, in a sandbox where Claude Code's config
// directory is a throwaway copy:
//
//   CLAUDE_CONFIG_DIR=/path/to/throwaway-claude-dir \
//   node test/adversarial/live-hardware-detach.mjs [--busid 7-2] [--model haiku]
//
// What it does:
//   1. a throwaway Enclawed state dir and hardware latch (the real latch in
//      $HOME is never used, so a DIRTY latch here is a throwaway one), with a
//      throwaway two-factor credential that signs each launch's unlock ticket;
//   2. `ecwcode -p` with the real claude on a slow task; once the session's
//      hooks have reported in, `usbipd.exe detach --busid <id>`: a real device event;
//   3. records: claude was stopped, Enclawed Code exited 4, the throwaway
//      .credentials.json is gone, `hardware.halt.credentials-erased` is in the log;
//   4. `usbipd.exe attach --wsl --busid <id>` (always, also on failure), then
//      shows that Enclawed Code refuses to start while the (throwaway) latch is DIRTY.
// It refuses to run when CLAUDE_CONFIG_DIR is unset or is the real ~/.claude.
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { enrollDemoCredential, signDemoTicket } from "../../src/demo-credential.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const LAUNCHER = path.join(ROOT, "bin", "ecwcode.mjs");
const arg = (n, d) => (process.argv.includes(n) ? process.argv[process.argv.indexOf(n) + 1] : d);
const busid = arg("--busid", "7-2");
const model = arg("--model", "haiku");

const cfg = process.env.CLAUDE_CONFIG_DIR;
const real = path.join(os.homedir(), ".claude");
if (!cfg || path.resolve(cfg) === path.resolve(real)) {
  console.error("refusing: set CLAUDE_CONFIG_DIR to a throwaway copy of Claude Code's config dir (never the real ~/.claude)");
  process.exit(2);
}
if (!fs.existsSync(path.join(cfg, ".credentials.json"))) {
  console.error(`refusing: ${cfg}/.credentials.json does not exist, so there is nothing to show being erased`);
  process.exit(2);
}
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-live-hw-"));
const state = path.join(dir, "state");
const project = path.join(dir, "project");
fs.mkdirSync(project, { recursive: true });
const env = {
  ...process.env,
  ENCLAWED_STATE_DIR: state,
  ENCLAWEDER_STATE: path.join(dir, "hw-root.state"),
  ENCLAWEDER_STATE_DIR: dir,
  CLAUDE_CONFIG_DIR: cfg,
};
const audit = path.join(state, "claude-code", "audit.jsonl");
const records = () => {
  try {
    return fs.readFileSync(audit, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
};
// Two-factor is mandatory: a throwaway credential in this run's state dir signs the launch's ticket.
const cred = enrollDemoCredential(path.join(state, "claude-code", "auth"));
const usbip = (...a) => spawnSync("usbipd.exe", a, { encoding: "utf8", timeout: 60_000 });

const result = { busid, model, steps: [] };
const step = (name, data) => {
  result.steps.push({ name, ...data });
  console.log(`${name}: ${JSON.stringify(data)}`);
};

signDemoTicket(cred);
step("unlock ticket", { signed: true });
const child = spawn(process.execPath, [LAUNCHER, "-p", "--model", model, "--permission-mode", "default", "--", "List the files here with the Bash tool, then wait: run `sleep 60` with Bash, then list them again."], { env, cwd: project, stdio: ["ignore", "pipe", "pipe"] });
let stderr = "";
child.stderr.on("data", (d) => (stderr += d));
const exited = new Promise((r) => child.on("exit", (code, signal) => r({ code, signal })));
let detached = false;
try {
  const t0 = Date.now();
  while (Date.now() - t0 < 60_000 && !records().some((r) => r.type === "claude-code.session.start")) {
    await new Promise((r) => setTimeout(r, 500));
  }
  step("hooks reported in", { ok: records().some((r) => r.type === "claude-code.session.start") });
  await new Promise((r) => setTimeout(r, 3000));
  const d = usbip("detach", "--busid", busid);
  detached = d.status === 0;
  step("usbipd detach", { status: d.status, at: new Date().toISOString() });
  const res = await Promise.race([exited, new Promise((r) => setTimeout(() => r({ code: "timeout" }), 120_000))]);
  const erased = records().find((r) => r.type === "hardware.halt.credentials-erased");
  step("after the halt", {
    ecwcodeExit: res.code,
    credentialsFileGone: !fs.existsSync(path.join(cfg, ".credentials.json")),
    auditRecord: erased ? { erased: erased.payload.erased, remaining: erased.payload.remaining, halt: erased.payload.halt } : null,
    stderrTail: stderr.trim().split("\n").slice(-4),
  });
} finally {
  if (detached) {
    const a = usbip("attach", "--wsl", "--busid", busid);
    step("usbipd attach", { status: a.status });
    await new Promise((r) => setTimeout(r, 4000));
  }
}
signDemoTicket(cred);
const again = spawnSync(process.execPath, [LAUNCHER, "-p", "--model", model, "--", "say hi"], { env, cwd: project, encoding: "utf8", timeout: 120_000 });
step("relaunch after re-attach", { exit: again.status, refusedUntilRecovery: again.status === 4 && /recover-root/.test(again.stderr), stderrTail: again.stderr.trim().split("\n").slice(-2) });
fs.writeFileSync(path.join(dir, "result.json"), JSON.stringify(result, null, 2));
console.log(`result: ${path.join(dir, "result.json")} (throwaway state and latch in ${dir})`);
