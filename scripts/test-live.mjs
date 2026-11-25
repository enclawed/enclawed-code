#!/usr/bin/env node
// `npm run test:live`: the release gate. Everything here runs against the
// REAL Claude Code binary with the REAL model (inside the OS sandbox of
// test/adversarial/sandbox.mjs: a throwaway overlay of ~/.claude, so the
// login is readable and nothing is written back; the OAuth-expiry guard), and,
// for the hardware checks, the REAL attached Enclaweder (under an flock, so
// no two processes hold an anchor session at once). A group is skipped,
// with the reason printed, only when the binary, the login or the device is
// absent. Exit 1 when any group that ran failed.
//
//   npm run test:live
//   ECWCODE_LIVE_ONLY=model,adversarial,integrity,device npm run test:live
//   ECWCODE_DEVICE_LOCK=/path/to/lock (default: $TMPDIR/enclaweder.lock)
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const only = process.env.ECWCODE_LIVE_ONLY ? new Set(process.env.ECWCODE_LIVE_ONLY.split(",")) : null;
const HOME = os.homedir();
const CLAUDE = path.join(HOME, ".local", "bin", "claude");
const LOCK = process.env.ECWCODE_DEVICE_LOCK ?? path.join(os.tmpdir(), "enclaweder.lock");

const have = {
  binary: (() => {
    try {
      fs.accessSync(fs.realpathSync(CLAUDE), fs.constants.X_OK);
      return null;
    } catch {
      return `no Claude Code binary at ${CLAUDE}`;
    }
  })(),
  login: fs.existsSync(path.join(HOME, ".claude", ".credentials.json")) ? null : "no Claude Code login (~/.claude/.credentials.json)",
  device: (() => {
    try {
      return fs.readdirSync("/sys/class/hidraw").length > 0 ? null : "no Enclaweder attached (/sys/class/hidraw is empty)";
    } catch {
      return "no Enclaweder attached (no /sys/class/hidraw)";
    }
  })(),
  bwrap: spawnSync("bwrap", ["--version"]).status === 0 ? null : "bubblewrap (bwrap) is not available",
  flock: spawnSync("flock", ["--version"]).status === 0 ? null : "flock is not available",
};

const results = [];
function run(group, label, argv, { env = {}, needs = [], pass = (r) => r.status === 0, timeoutMs = 3_600_000, device = false } = {}) {
  if (only && !only.has(group)) {
    return;
  }
  const missing = needs.map((n) => have[n]).filter(Boolean);
  if (missing.length) {
    results.push({ group, label, status: "SKIP", why: missing.join("; ") });
    console.log(`SKIP ${group}/${label}: ${missing.join("; ")}`);
    return;
  }
  const cmd = device ? ["flock", LOCK, ...argv] : argv;
  console.log(`\n=== ${group}/${label}: ${cmd.join(" ")}`);
  const t0 = Date.now();
  const r = spawnSync(cmd[0], cmd.slice(1), { cwd: ROOT, env: { ...process.env, ...env }, encoding: "utf8", timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024 });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  process.stdout.write(out.split("\n").filter((l) => /^#\s*(LIVE|pass|fail|SKIP)|^not ok|^ok |RESISTED|VULNERABLE|^\s+(same|DIFF) |^  \d |summary|exit /.test(l)).join("\n") + "\n");
  const ok = pass({ ...r, out });
  results.push({ group, label, status: ok ? "PASS" : "FAIL", secs: Math.round((Date.now() - t0) / 1000) });
  console.log(`${ok ? "PASS" : "FAIL"} ${group}/${label} (${Math.round((Date.now() - t0) / 1000)} s)`);
}
const node = process.execPath;
const noVulnerable = (r) => r.status === 0 && !/\bVULNERABLE\b/.test(r.out);
// The deliberate live-device opt-in (red-team H14 T1): the same name the framework honours.
const deviceEnv = { ENCLAWEDER_LIVE_DEVICE_TEST: "I_UNDERSTAND" };

// Round 5, live: real binary, real model, real pty.
run("model", "round 5 (E1-E5, N13c, binding, did-not-load guard)", [node, "--test", "--test-concurrency=1", "test/live/round5.live.mjs"], { needs: ["binary", "login", "bwrap"] });
// Workflow profiles, skill admission, MCP admission, claude.ai connectors: real binary, real model.
run("model", "admission (workflows, skills, MCP, connectors)", [node, "--test", "--test-concurrency=1", "test/live/admission.live.mjs"], { needs: ["binary", "login", "bwrap"] });
// Rounds 1-4 gate behavior, live: the adversarial suite (real model, native vs Enclawed Code, concurrency <= 2).
run("adversarial", "live suite", [node, "test/adversarial/run.mjs", "--live", "--concurrency", "2", "--sides", "ecwcode"], { needs: ["binary", "login", "bwrap"], timeoutMs: 5_400_000 });
// Rounds 1-4 integrity PoCs that use the real binary (throwaway config: everything up to authentication).
for (const f of fs.readdirSync(path.join(ROOT, "test", "redteam", "integrity")).filter((n) => /^live-.*\.mjs$/.test(n)).sort()) {
  run("integrity", f, [node, path.join("test", "redteam", "integrity", f)], { needs: ["binary"], pass: noVulnerable, timeoutMs: 900_000 });
}
// The real Enclaweder (fw 0.2), one process at a time.
for (const f of ["anchor-gate-real.mjs", "anchor-gate-launcher-real.mjs", "lease-real.mjs", "lease-alarm-real.mjs"]) {
  run("device", f, [node, path.join("test", "redteam", "integrity", f)], { needs: ["device", "flock"], env: deviceEnv, pass: noVulnerable, device: true, timeoutMs: 900_000 });
}

console.log("\n=== test:live summary");
for (const r of results) {
  console.log(`${r.status.padEnd(4)} ${r.group}/${r.label}${r.why ? ` (${r.why})` : ""}${r.secs !== undefined ? ` ${r.secs} s` : ""}`);
}
process.exit(results.some((r) => r.status === "FAIL") ? 1 : 0);
