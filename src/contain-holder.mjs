// enclawed-code-contain-holder: holds one script containment (the kit's
// scriptContainer) for a session that has no Enclawed Code launcher (managed
// mode, or a hook started without one). The hook starts it detached, writes
// the kit's ScriptContainmentRequest on stdin, and reads one JSON line: the
// contained command, or why it could not be contained. The holder keeps the
// containment (its relay and host-side guards) open until the agent process
// it watches is gone, then closes it.
//
// Repository configuration a contained git checks out is re-admitted here
// with Enclawed Code's launch admission (launcher.mjs readmitRepository).
//
// usage: node contain-holder.mjs <watch-pid> (request JSON on stdin)

import fs from "node:fs";
import path from "node:path";
import { kit } from "./kit.mjs";
import { quarantineInto, readmitLauncherless } from "./repo-config-relay.mjs";

const POLL_MS = 2000;
// A holder never outlives a day, whatever it watches.
const MAX_LIFE_MS = 24 * 60 * 60 * 1000;

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) {
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const watch = Number(process.argv[2]);
let msg;
try {
  msg = JSON.parse(await readStdin());
} catch {
  process.stdout.write(`${JSON.stringify({ ok: false, code: "containment-setup-failed", message: "the containment request was not JSON" })}\n`);
  process.exit(0);
}
const record = (r) => {
  try {
    fs.appendFileSync(msg.eventsFile, `${JSON.stringify(r)}\n`, { mode: 0o600 });
  } catch {
    /* best effort: the launcher-less session has no other record */
  }
};
/** Enclawed Code's launch admission, again (repo-config-relay.mjs readmitLauncherless). */
const readmit = () => readmitLauncherless(msg.readmit ?? {});
/** Inadmissible files leave the project (the session's quarantine), as the launcher does. */
const quarantine = (paths) => quarantineInto(msg.stateDir, paths);
const onEvent = (e) => {
  if (!msg.eventsFile) {
    return;
  }
  // Repository configuration a contained git checked out: the session holds
  // (every call denied) while Enclawed Code's launch admission runs again here,
  // over the files as they are now, with the same rules and inputs as a
  // launch from this project; admissible, the hold is released (no restart).
  // A conflict needs a person: with no launcher prompt, the one write that
  // resolves it is asked at Claude Code's own prompt (the hook's
  // kit.askConflictResolution / kit.completeConflictResolution).
  if ((e?.code === "containment-repo-config-changed" || e?.code === "containment-repo-config-refused") && msg.holdFile) {
    void kit
      .handleRepoConfigEvent(e, { hold: kit.fileHoldStore(msg.holdFile), admit: readmit, onInadmissible: quarantine })
      .then((o) => {
        if (o.action !== "none") {
          record({ type: "claude-code.repo-config.readmission", payload: o });
        }
      })
      .catch(() => {});
  }
  try {
    const r = kit.containmentAuditOf(e);
    fs.appendFileSync(msg.eventsFile, `${JSON.stringify({ type: `claude-code.${r.type}`, payload: r.payload })}\n`, { mode: 0o600 });
  } catch {
    /* best effort: the launcher-less session has no other record */
  }
};
const holder = kit.scriptContainer({ stateDir: msg.stateDir, onEvent });
const r = await holder.contain(msg.request).catch((err) => ({ ok: false, code: "containment-setup-failed", message: err.message }));
process.stdout.write(`${JSON.stringify(r)}\n`);
if (!r.ok) {
  await holder.close();
  process.exit(0);
}
const started = Date.now();
const alive = () => {
  try {
    process.kill(watch, 0);
    return true;
  } catch {
    return false;
  }
};
const timer = setInterval(async () => {
  if (!(watch > 1) || !alive() || Date.now() - started > MAX_LIFE_MS) {
    clearInterval(timer);
    await holder.close().catch(() => {});
    process.exit(0);
  }
}, POLL_MS);
