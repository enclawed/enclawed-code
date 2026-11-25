// The launch-time device anchor gate, and `ecwctl audit accept` (round 5,
// R5-A).
//
// The problem: the launcher's chain follower (anchor-chain.mjs) takes the log
// "as found" when a session starts, and anchorFilesGuard takes the anchor
// file and history as found. A same-user process that, between sessions,
// deleted the anchor file and history and wrote a fabricated log was
// therefore laundered by the next launch: `audit verify` said MISMATCH right
// after the tampering, and "matched" once the next session had anchored the
// fabricated log (red-team round 5, on the real Enclaweder).
//
// So before claude starts, the launcher runs the same device comparison as
// `audit verify` on the log as found (checkBoundDeviceAnchor). If the
// device holds anchors and the log, its anchor file or its anchor history do
// not verify as matched (or are missing), the launch is REFUSED, with an
// audit record, until a person runs `ecwctl audit accept`. A fresh history
// is never started silently while the device holds earlier anchors. An
// operator takeover (recover-anchor) counts as an open by another session,
// so it also needs an accept.
//
// `audit accept` (interactive terminal, activation auth, the device serial
// typed in) re-baselines: it moves the old anchor file and history aside
// (kept, renamed), appends a chained `claude-code.audit.accept` record that
// names what was found and what was overridden, and anchors that record on
// the device under a fresh anchor session, so the next launch matches.
//
// What this does not cover: a same-user process that drives the device
// itself (it can open an anchor session and anchor a fabricated chain, with
// a fresh history, as accept does) is outside what any host-side check can
// stop; the device's counter and open count still show that it happened
// for anyone who kept an earlier counter (see docs, R5-L).

import fs from "node:fs";
import { segmentFiles } from "./audit.mjs";
import { anchorFile, anchorHistoryFile, checkBoundDeviceAnchor, startAnchoring } from "./device.mjs";
import { kit } from "./kit.mjs";

export const EXIT_ANCHOR_REFUSED = 6;

/** Every record hash of the log, sealed rotation segments first. */
export function logRecordHashes(file) {
  const out = [];
  for (const f of [...segmentFiles(file).map((x) => x.file), file]) {
    let text = "";
    try {
      text = fs.readFileSync(f, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n")) {
      if (!line.trim()) {
        continue;
      }
      try {
        out.push(JSON.parse(line).recordHash);
      } catch {
        out.push(null);
      }
    }
  }
  return out;
}

/**
 * Decide whether a session may start on this log with this device. The
 * device comparison is the kit's (compareAnchoredLog through
 * checkBoundDeviceAnchor, on the log as found, with the log's own launch
 * activations); the decision is the kit's too (decideAnchorGate). It spends
 * nothing on the device (a fresh ANCHOR_READ, ANCHOR_GET and the files), so
 * the launcher runs it before the launch's activation.
 * @returns {Promise<{ ok: true, status: string, detail: string } | { ok: false, status: string, code: string, detail: string, counter: string|null }>}
 */
export async function launchAnchorGate(fw, device, auditLog, { check = checkBoundDeviceAnchor, rootRequired = false } = {}) {
  // `device.canAnchor` is the kit's session-anchor decision (device.mjs withSessionAnchor).
  const canAnchor = Boolean(device?.anchor && device.canAnchor);
  const compare = canAnchor ? await check(fw, device, auditLog, logRecordHashes(auditLog)) : null;
  return kit.decideAnchorGate({ device: device ? { canAnchor } : null, rootRequired, check: compare, anchorFile: anchorFile(auditLog), anchorFilePresent: fs.existsSync(anchorFile(auditLog)) });
}

/** The refusal message the launcher prints (kit.anchorGateMessage). */
export function anchorRefusalMessage(g, auditLog) {
  return kit.anchorGateMessage(g, auditLog, "ecwctl");
}

/**
 * `ecwctl audit accept`: re-baseline the device anchor after a person has
 * looked at the mismatch. The caller has done the terminal, activation-auth
 * and serial checks. Moves the old anchor files aside, appends the accept
 * record, anchors it under a fresh session.
 * @returns {Promise<{ head: string, counter: string|null, moved: string[] }>}
 */
export async function acceptAnchorBaseline(fw, device, auditLog, { found, append, now = Date.now() }) {
  const moved = [];
  for (const f of [anchorFile(auditLog), anchorHistoryFile(auditLog)]) {
    if (fs.existsSync(f)) {
      const to = `${f}.superseded-${now}`;
      fs.renameSync(f, to);
      moved.push(to);
    }
  }
  const errors = [];
  const anchoring = startAnchoring(fw, device, auditLog, { intervalMs: 3_600_000, onError: (e) => errors.push(e), onAlarm: (e) => errors.push(e), onTamper: (e) => errors.push(e) });
  try {
    const live = await device.anchor.dev.anchorGet().catch(() => null);
    await append({
      type: "claude-code.audit.accept",
      actor: "enclawed-code",
      level: null,
      payload: {
        found: { status: found.status, code: found.code ?? null, detail: String(found.detail ?? "").slice(0, 1000) },
        deviceBefore: live ? { counter: String(live.counter), ...(live.version >= 2 ? { sess: String(live.sess), opens: String(live.opens) } : {}) } : null,
        superseded: moved,
        serial: device.serial ?? null,
      },
    });
    const a = await anchoring.flush();
    if (!a.anchored) {
      throw errors[0] ?? new Error(a.reason ?? "the accept record could not be anchored");
    }
    const after = await device.anchor.dev.anchorGet().catch(() => null);
    return { head: a.head, counter: after ? String(after.counter) : null, moved };
  } finally {
    await anchoring.close().catch(() => {});
  }
}
