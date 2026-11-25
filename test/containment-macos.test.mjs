import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// macOS containment (containment.mjs nets 5-7): no subreaper and no cgroups,
// so the launcher tracks claude's descendants (pid + start time) and the
// process groups they lead, and on a halt kills every member, every process
// of a session-led group and every marker carrier. The logic is tested here
// on Linux, with the same `ps` parsing (procps prints the same columns) and
// real processes; what only a real Mac can show is listed in docs/usage.md.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { killSession, markedPids, parseLstart, parsePsMarked, parsePsTable, processTracker, psTable, sessionContainment } from "../src/containment.mjs";
import { containmentMode } from "../src/launcher.mjs";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

test("ps parsing: macOS lstart (C locale, UTC), the process table and the marker column", () => {
  assert.equal(parseLstart("Sat Nov 22 16:04:05 2026"), Date.UTC(2026, 10, 22, 16, 4, 5) / 1000);
  assert.equal(parseLstart("Mon Feb  3 01:02:03 2025"), Date.UTC(2025, 1, 3, 1, 2, 3) / 1000);
  assert.equal(parseLstart("yesterday"), null);
  const t = parsePsTable("  101   100   100 Ss   Sat Nov 22 16:04:05 2026\n  102     1   102 Z    Sat Nov 22 16:04:06 2026\ngarbage\n");
  assert.deepEqual(t, [
    { pid: 101, ppid: 100, pgid: 100, state: "S", start: Date.UTC(2026, 10, 22, 16, 4, 5) / 1000 },
    { pid: 102, ppid: 1, pgid: 102, state: "Z", start: Date.UTC(2026, 10, 22, 16, 4, 6) / 1000 },
  ]);
  const out = "  7 /bin/sh -c x PATH=/usr/bin ECWCODE_SESSION_MARK=abc HOME=/h\n  8 /bin/echo ECWCODE_SESSION_MARK=abcd\n  9 sleep 1 ECWCODE_SESSION_MARK=abc\n";
  assert.deepEqual(parsePsMarked(out, "abc"), [7, 9]);
  assert.deepEqual(parsePsMarked(out, "abc", new Set([9])), [7]);
});

test("tracker: a double-forked, setsid helper stays a member after it is re-parented; its group's later children are members; recycled pids, unrelated processes and the terminal's job group are not", () => {
  let table = [];
  const tr = processTracker({ table: () => table, self: 50 });
  // The launcher (50) and the user's `| tee` (51) in the terminal's job group 50; claude 100 in it too (interactive).
  const base = [
    { pid: 50, ppid: 10, pgid: 50, state: "S", start: 1 },
    { pid: 51, ppid: 10, pgid: 50, state: "S", start: 1 },
    { pid: 100, ppid: 50, pgid: 50, state: "S", start: 2 },
    { pid: 300, ppid: 1, pgid: 300, state: "S", start: 2 }, // the user's own daemon, started elsewhere
  ];
  table = [...base, { pid: 101, ppid: 100, pgid: 50, state: "S", start: 3 }, { pid: 102, ppid: 101, pgid: 102, state: "S", start: 3 }];
  tr.start(100);
  // 101 exits; 102 (setsid) is re-parented to launchd and forks 103, never seen below claude.
  table = [...base, { pid: 102, ppid: 1, pgid: 102, state: "S", start: 3 }, { pid: 103, ppid: 1, pgid: 102, state: "S", start: 4 }];
  tr.sweep();
  const ids = (t) => tr.sessionProcs(t).map((p) => p.pid).sort((a, b) => a - b);
  assert.deepEqual(ids(table), [102, 103]);
  // pid 101 recycled by an unrelated process: not a member (start time differs).
  const recycled = [...table, { pid: 101, ppid: 1, pgid: 101, state: "S", start: 9 }];
  assert.deepEqual(ids(recycled), [102, 103]);
  // The terminal's job group (50) is never the session's, and neither is the user's daemon.
  assert.ok(!tr.groups.has(50));
  assert.ok(!ids(recycled).includes(51) && !ids(recycled).includes(300));
  // A session group whose processes are all gone is forgotten: a later group with the same number is not the session's.
  table = [...base];
  tr.sweep();
  assert.equal(tr.groups.has(102), false);
  table = [...base, { pid: 102, ppid: 1, pgid: 102, state: "S", start: 20 }];
  tr.sweep();
  assert.deepEqual(ids(table), []);
  tr.stop();
});

test("sessionContainment: tracked on macOS (no refusal there), not on Linux; the mode is recorded", () => {
  const mac = sessionContainment({}, { scope: false, reaper: null, platform: "darwin" });
  assert.equal(mac.tracked, true);
  assert.ok(mac.tracker);
  assert.equal(containmentMode(mac), "tracked+marker");
  const lin = sessionContainment({}, { scope: false, reaper: null, platform: "linux" });
  assert.equal(lin.tracked, false);
  assert.equal(containmentMode(lin), "marker");
});

/**
 * A stand-in claude: it starts a helper that double-forks with setsid,
 * clears its environment (no marker), forks a grandchild in its own group,
 * and keeps a parent alive for `holdMs` so the tracker can see it.
 */
function startSession(dir, holdMs) {
  const pidFile = path.join(dir, `pids-${holdMs}-${Math.random().toString(36).slice(2)}`);
  const helper =
    `( setsid env -i PATH=/usr/bin:/bin P="${pidFile}" sh -c 'echo $$ >> "$P"; sleep 0.4; ( sleep 60 & echo $! >> "$P"; wait ) & while :; do sleep 0.1; done' & sleep ${holdMs / 1000} )`;
  const child = spawn("/bin/sh", ["-c", `${helper}; sleep 60`], { stdio: "ignore", env: { ...process.env, ECWCODE_SESSION_MARK: "test-marker-not-used" } });
  return { child, pidFile };
}

test("macOS tracking on real processes (attack): a double-forked, setsid, env-cleared helper and its later child are killed on a halt; mutation: without the tracker they survive", async () => {
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR ?? "/tmp", "cmac-"));
  try {
    for (const withTracker of [true, false]) {
      const { child, pidFile } = startSession(dir, 600);
      const tracker = processTracker({ table: psTable, intervalMs: 50 });
      const c = sessionContainment({}, { scope: false, reaper: null, platform: "linux", tracker: withTracker ? tracker : null });
      if (withTracker) {
        tracker.start(child.pid);
      }
      // The helper's parent has exited: it is re-parented away from the stand-in claude.
      await pause(1800);
      const pids = fs.readFileSync(pidFile, "utf8").split("\n").filter(Boolean).map(Number);
      assert.equal(pids.length, 2, "the helper and its later child started");
      assert.ok(pids.every(alive));
      const r = await killSession(child.pid, c, { table: psTable, marked: markedPids, afterKillWaitMs: 1500 });
      tracker.stop();
      await pause(300);
      if (withTracker) {
        assert.equal(r.verified, true, JSON.stringify(r));
        assert.deepEqual(pids.filter(alive), [], "every process of the session is gone");
      } else {
        assert.deepEqual(pids.filter(alive).sort(), [...pids].sort(), "mutation: without tracking the escaped helper survives");
        for (const p of pids) {
          process.kill(p, "SIGKILL");
        }
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("macOS tracking (FP): a process of the user outside the session, and one in the launcher's own group, survive the halt", async () => {
  const outside = spawn("/bin/sh", ["-c", "sleep 30"], { stdio: "ignore", detached: true });
  const sameGroup = spawn("/bin/sh", ["-c", "sleep 30"], { stdio: "ignore" }); // like `| tee`: the launcher's group, not claude's
  const { child } = startSession(fs.mkdtempSync(path.join(process.env.TMPDIR ?? "/tmp", "cmac-fp-")), 600);
  const tracker = processTracker({ table: psTable, intervalMs: 50 });
  tracker.start(child.pid);
  await pause(1200);
  const c = sessionContainment({}, { scope: false, reaper: null, platform: "linux", tracker });
  const r = await killSession(child.pid, c, { table: psTable, marked: markedPids, afterKillWaitMs: 1500 });
  tracker.stop();
  assert.equal(r.verified, true);
  assert.equal(alive(outside.pid), true, "an unrelated process of the user survives");
  assert.equal(alive(sameGroup.pid), true, "the launcher's own group is not the session's");
  outside.kill("SIGKILL");
  sameGroup.kill("SIGKILL");
});
