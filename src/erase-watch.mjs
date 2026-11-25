#!/usr/bin/env node
// The detached credential watcher (red-team round 3, N7b).
//
// After a hardware halt the launcher erases Claude Code's login and re-checks
// it for a few seconds in process (launcher.mjs eraseAndRecheck). A helper
// that escaped the stop can write the login back later than that: in N7b a
// double-forked `setsid` helper wrote it back 8 s after the erase. So the
// launcher also starts this watcher, detached in its own session, which keeps
// re-checking on the kit's fixed schedule (kit.eraseWatchSchedule: 1, 2,
// 4, 8 s, then every 15 s, for 60 s) and erases the login again each time it
// reappears. It
// appends one JSON line per event to `log` (in Enclawed Code's state dir).
//
// This is BEST EFFORT, and says so everywhere it is reported. A copy of the
// token taken before the erase keeps working until it is revoked at
// claude.ai, and a process that waits out the watcher can still write the
// login back. Revoking the session at claude.ai is the real control.
//
//   node src/erase-watch.mjs <env-json-file> <ignored> <log>
import fs from "node:fs";
import { kit } from "./kit.mjs";
import { claudeCredentialLocations, eraseClaudeCredentials } from "./credentials.mjs";

/** Re-check times (ms after the start): the kit's fixed schedule (1, 2, 4, 8 s, then every 15 s, for 60 s). */
export function backoffSchedule() {
  return kit.eraseWatchSchedule();
}

/**
 * Watch and re-erase: kit.watchErased decides when to re-check and erases
 * through kit.eraseCredentials (eraseClaudeCredentials). The watch length is
 * the kit's constant, never a setting. `sleep` and `erase` are injectable for
 * tests.
 * @returns {Promise<{ reappeared: number, checks: number }>}
 */
export async function watchErased({ env, log = null, erase = eraseClaudeCredentials, sleep }) {
  const file = claudeCredentialLocations(env).file;
  const note = (rec) => {
    if (log) {
      try {
        fs.appendFileSync(log, `${JSON.stringify({ ts: Date.now(), ...rec })}\n`, { mode: 0o600 });
      } catch {
        /* best effort */
      }
    }
  };
  return kit.watchErased({ present: () => fs.existsSync(file), erase: () => erase({ env }), note, ...(sleep ? { sleep } : {}) });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // argv[3] (a watch length) is accepted for compatibility and ignored: the kit's schedule is fixed.
  const [envFile, , log] = process.argv.slice(2);
  const env = JSON.parse(fs.readFileSync(envFile, "utf8"));
  fs.rmSync(envFile, { force: true });
  await watchErased({ env, log: log || null });
}
