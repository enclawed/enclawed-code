// Device-backed evidence, for a host that may already be compromised by
// something running as the same user.
//
//   Attestation   On every PreToolUse the hook sends a fresh random nonce
//                 through the launcher's relay to the bound Enclaweder and
//                 verifies the answer itself: the device's birth certificate
//                 against the pinned manufacturer roots (the framework's
//                 verifyCert), the uid/public-key binding, the key pinned at
//                 launch, and the challenge signature over its own nonce. A
//                 fake broker or socket claiming CLEAN, a replayed answer, or
//                 a cloned or uncertified device is refused.
//   Head anchor   The launcher (which holds the device) anchors the audit
//                 log's head in the device with the framework's
//                 enclawederHeadAnchor (signed, monotonic counter the host
//                 cannot set), every couple of seconds while the head moves
//                 and once more at the end of the session. `Enclawed Code audit
//                 verify` reads the device's anchor and checks that its head
//                 is a record of the chain: truncation, rewrite or a fully
//                 fabricated log no longer verifies. The launcher anchors only
//                 heads that extend the chain it followed during the session
//                 (anchor-chain.mjs, round 4 N14), so a log replaced while a
//                 session runs is refused, not laundered; a log and history
//                 replaced between sessions is the documented residual
//                 (docs/anchor-auth-design.md).
//   Measurements  The session-start record carries SHA-256 measurements of
//                 the hook, Enclawed Code's code, the framework bundle, the
//                 effective policy and the generated settings; it is covered
//                 by the anchor, and `audit verify` re-measures and reports drift.
//
// Limits: this makes host-level tampering detectable and keeps evidence the
// attacker cannot forge. It does not prevent a same-user attacker from acting
// on the host directly, or from replacing Enclawed Code before it is launched. With
// record v2 firmware the anchor advances only under the one authenticated
// anchor session, which the launcher holds (docs/anchor-auth-design.md); a
// head anchored under any other session fails `audit verify`
// (foreign-session). A process that opens the channel before the launcher
// makes the launch stop with an alarm (BUSY) rather than forge silently.

import { userNamespaceDeviceRisk } from "./userns.mjs";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AnchorTamper, anchorFilesGuard, followChain } from "./anchor-chain.mjs";
import { segmentFiles } from "./audit.mjs";
import { FRAMEWORK_ENTRY } from "./framework.mjs";
import { APP_ROOT, HOOK_BIN } from "./paths.mjs";

export function deviceApi(fw) {
  return typeof fw.hardwareRootSigningDevice === "function" && typeof fw.verifyChallenge === "function" && typeof fw.verifyCert === "function";
}

/** Launcher side: the bound device and its identity, or null. */
export async function boundDevice(fw) {
  if (!deviceApi(fw)) {
    return null;
  }
  const dev = fw.hardwareRootSigningDevice();
  if (!dev) {
    return null;
  }
  const id = await dev.getIdentity();
  const cert = typeof dev.getCert === "function" ? await dev.getCert().catch(() => null) : null;
  // The trust domain (Base or Pro) is the one the birth certificate proves
  // against the pinned roots; the serial prefix follows it (ENCLW- for Base,
  // ECPRO- for Pro), as in the framework's fleet view.
  let sku = null;
  try {
    sku = cert ? (fw.verifyCert(Buffer.from(cert), Buffer.from(id.uid), Buffer.from(id.pubkeyRaw))?.sku ?? null) : null;
  } catch {
    sku = null;
  }
  const uidHex = Buffer.from(id.uid).toString("hex");
  return withSessionAnchor(fw, {
    dev,
    pub: Buffer.from(id.pubkeyRaw).toString("hex"),
    uid: uidHex,
    sku,
    serial: sku === "pro" ? `ECPRO-${uidHex.toUpperCase()}` : (id.serial ?? null),
    cert: cert ? Buffer.from(cert).toString("base64") : null,
  });
}

/**
 * The session's audit anchor, decided by the kit, never here: the
 * framework's requireHardwareRootSessionAnchor (hardware-root
 * session-anchor.ts) gives this process's own device, or, for a client of the
 * machine's device owner, the authenticated anchor session relayed through
 * the owner, and refuses a bound session that cannot anchor with
 * authentication (SessionAnchorRefused). `device.anchor` is then
 * { dev, pub, relayed }: the device the kit returned and the certified key an
 * anchor session is opened against. Otherwise `anchor` is null and
 * `anchorRefused` says why; such a device cannot anchor, and a session with it
 * is refused by the launch gate (kit.decideAnchorGate). A framework build
 * without the decision cannot anchor either.
 */
export function withSessionAnchor(fw, device) {
  if (!device) {
    return device;
  }
  const refused = (code, reason) => ({ ...device, anchor: null, canAnchor: false, anchorRefused: { code, reason } });
  if (typeof fw?.requireHardwareRootSessionAnchor !== "function") {
    return refused("anchor-unavailable", "this framework build does not decide the session's audit anchor (requireHardwareRootSessionAnchor); rebuild it");
  }
  let a;
  try {
    a = fw.requireHardwareRootSessionAnchor();
  } catch (err) {
    return refused(typeof err?.code === "string" ? err.code : "anchor-unavailable", String(err?.message ?? err));
  }
  if (a?.mode !== "authenticated") {
    return refused("anchor-unavailable", "the kit found no hardware root bound to this session, so nothing anchors its audit log");
  }
  const pub = Buffer.from(a.devicePublicKey).toString("hex");
  if (typeof device.pub === "string" && pub !== device.pub) {
    // The anchor must be the device this session attested and pinned.
    return refused("anchor-unavailable", "the kit's anchor device is not the Enclaweder this session attested");
  }
  return { ...device, anchor: { dev: a.device, pub, relayed: a.relayed === true }, canAnchor: true, anchorRefused: null };
}

/** True when the framework can attest EVERY member of the hardware root (H1/H15 framework). */
export function memberAttestationApi(fw) {
  return typeof fw.attestHardwareRoot === "function" && typeof fw.verifyRootMembers === "function" && typeof fw.verifyRootAttestation === "function";
}

/**
 * Launcher side, held mode: the devices of the held root, every member of it
 * (red-team H15: a root with two members used to give `null` here, and a null
 * device meant "no attestation" instead of a refusal). With a framework that
 * attests every member, each member's certificate is verified now against the
 * pinned roots; with an older one, only a single-member root can be attested.
 * Returns null when nothing can be attested: the caller must then refuse.
 */
export async function sessionDevice(fw, { verifyOpts = {} } = {}) {
  const single = await boundDevice(fw).catch(() => null);
  if (memberAttestationApi(fw)) {
    const a = await fw.attestHardwareRoot(randomBytes(32));
    if (!a) {
      return null;
    }
    const members = fw.verifyRootMembers(a.members, verifyOpts.rootPubkey ?? null);
    const session = {
      kind: "members",
      members: members.map((m) => ({ pub: m.pubkey, uid: m.uid, serial: m.serial, sku: m.sku })),
      // The first member, as before, for the session file and for the anchor (one device).
      pub: members[0].pubkey,
      uid: members[0].uid,
      serial: members[0].serial,
      sku: members[0].sku,
      // The device itself, for a single-device root this process drives.
      ...(single && members.length === 1 && single.pub === members[0].pubkey ? { dev: single.dev, cert: single.cert } : {}),
    };
    // The anchor is the kit's decision (withSessionAnchor): this process's
    // device, or the authenticated session relayed through the owner.
    return withSessionAnchor(fw, session);
  }
  return single ? { kind: "single", ...single } : null;
}

/** Launcher side: answer one attestation request. */
export async function attest(device, nonceHex, fw = null) {
  if (device.kind === "members" && fw && memberAttestationApi(fw)) {
    // Every member's latch read, signed by its device over the hook's own nonce.
    const a = await fw.attestHardwareRoot(Buffer.from(nonceHex, "hex"));
    if (!a) {
      throw new Error("the hardware root has no device to attest");
    }
    return { kind: "members", attestation: a };
  }
  const r = await device.dev.challenge(Buffer.from(nonceHex, "hex"));
  return { uid: Buffer.from(r.uid).toString("hex"), sig: Buffer.from(r.sig).toString("base64"), pub: device.pub, cert: device.cert };
}

/**
 * Hook side: check an attestation against the nonce this process chose.
 * `verifyCert` defaults to the framework's (pinned manufacturer roots).
 * @returns {null | string} null when genuine, else why not
 */
export function checkAttestation(fw, { nonce, answer, pinnedPub, pinnedPubs = null, verifyCert = fw.verifyCert, verifyChallenge = fw.verifyChallenge, rootPubkey = null }) {
  if (answer?.kind === "members") {
    return checkMemberAttestation(fw, { nonce, attestation: answer.attestation, pinnedPubs: pinnedPubs ?? (pinnedPub ? [pinnedPub] : null), rootPubkey });
  }
  if (pinnedPubs && pinnedPubs.length !== 1) {
    return "the hardware root has several devices, and the answer attests only one";
  }
  if (!answer || typeof answer.pub !== "string" || typeof answer.uid !== "string" || typeof answer.sig !== "string") {
    return "the device gave no attestation";
  }
  if (pinnedPub && answer.pub.toLowerCase() !== pinnedPub.toLowerCase()) {
    return "the device's key is not the one bound at launch";
  }
  const pub = Buffer.from(answer.pub, "hex");
  const uid = Buffer.from(answer.uid, "hex");
  if (!answer.cert || !verifyCert(Buffer.from(answer.cert, "base64"), uid, pub)) {
    return "the device has no manufacturer certificate for this key and uid (uncertified, re-minted or counterfeit)";
  }
  if (!verifyChallenge(pub, Buffer.from(nonce, "hex"), uid, Buffer.from(answer.sig, "base64"))) {
    return "the device's signature does not cover this call's fresh challenge (replayed, cloned or forged)";
  }
  return null;
}

/**
 * Hook side: EVERY member's certificate against the pinned roots, the member
 * set against the one bound at launch, and each member's latch read, signed by
 * its device over a digest that covers this call's own nonce: CLEAR, with the
 * device's host session live (red-team H1, H15).
 * @returns {null | string} null when genuine, else why not
 */
export function checkMemberAttestation(fw, { nonce, attestation, pinnedPubs, rootPubkey = null }) {
  if (!memberAttestationApi(fw)) {
    return "this framework cannot verify a member attestation";
  }
  if (!attestation || !Array.isArray(attestation.members) || attestation.members.length === 0) {
    return "the device gave no attestation";
  }
  let members;
  try {
    members = fw.verifyRootMembers(attestation.members, rootPubkey);
  } catch (err) {
    return `a device has no manufacturer certificate for its key and uid (uncertified, re-minted or counterfeit): ${err.message}`;
  }
  if (pinnedPubs) {
    const want = new Set(pinnedPubs.map((p) => p.toLowerCase()));
    const got = new Set(members.map((m) => m.pubkey.toLowerCase()));
    if (want.size !== got.size || [...want].some((p) => !got.has(p))) {
      return "the devices are not the ones bound at launch";
    }
  }
  let states;
  try {
    states = fw.verifyRootAttestation(members, Buffer.from(nonce, "hex"), attestation);
  } catch (err) {
    return `a device's signature does not cover this call's fresh challenge (replayed, cloned or forged): ${err.message}`;
  }
  for (const m of members) {
    const st = states.get(m.uid);
    if (!st || st.state !== "CLEAR") {
      return `enclaweder ${m.serial} holds a DIRTY latch${st ? ` (${st.reason})` : ""}`;
    }
    if (!st.sessionLive || !st.armed) {
      return `enclaweder ${m.serial} has no live host session`;
    }
  }
  return null;
}

export function newNonce() {
  return randomBytes(32).toString("hex");
}

// The device's status 8 is ST_UNSUPPORTED (Enclaweder host protocol).
const UNSUPPORTED = /status 8\b/;
const FIRMWARE_NO_ANCHOR = "the attached Enclaweder's firmware does not support audit anchoring (ANCHOR_SET/ANCHOR_GET answer ST_UNSUPPORTED); the log is anchored on the host only";

export function anchorFile(auditLog) {
  return `${auditLog}.enclaweder-anchor.json`;
}

// The device holds one anchor slot, and the anchor file one copy of it, so an
// older, genuinely signed copy restored over the file (red-team round 3,
// N10b) looked like "the device was anchored again by someone else". The
// launcher therefore also appends every anchor it makes to this history. Its
// format, its writer and its verification are the kit's (hardware-root
// anchor-history.ts: one line per anchor carrying exactly the fields the
// device signed for that record's version, v1, v2 or v3, each verified on its
// own); the names here must equal the kit's anchorFilePath/anchorHistoryPath.
export function anchorHistoryFile(auditLog) {
  return `${auditLog}.enclaweder-anchors.jsonl`;
}

/** Statuses of checkDeviceAnchor that make `audit verify` fail. */
export function deviceAnchorFails(status) {
  return status === "MISMATCH" || status === "superseded";
}

/**
 * The anchor history, each line verified by the kit against the device's key
 * (kit readAnchorHistory). A framework build without it reads nothing as
 * verified: every line counts as bad.
 * @returns {{ entries: { head: string, counter: bigint, version: 1|2|3, sess: bigint|null, opens: bigint|null, bind: string|null }[], bad: number }}
 */
export function readAnchorHistory(fw, auditLog, devicePublicKeyHex) {
  if (typeof fw.readAnchorHistory !== "function") {
    let n = 0;
    try {
      n = fs.readFileSync(anchorHistoryFile(auditLog), "utf8").split("\n").filter((l) => l.trim()).length;
    } catch {
      n = 0;
    }
    return { entries: [], bad: n };
  }
  return fw.readAnchorHistory(anchorHistoryFile(auditLog), Buffer.from(devicePublicKeyHex, "hex"));
}

/**
 * Operator-quorum takeover of the anchor channel (round 4, N15; firmware
 * 0.2): ends whatever session holds it (a crashed or hostile holder) and
 * closes the new one at once, so the next Enclawed Code session can open its own.
 * `signers` are functions msg -> 64-byte Ed25519 signature, one per operator.
 */
export async function takeoverAnchor(fw, device, signers) {
  if (typeof device?.dev?.anchorTakeover !== "function") {
    throw new Error("this framework build has no anchor takeover (Enclaweder.anchorTakeover): rebuild it from enclawed-oss with the firmware 0.2 host side");
  }
  const s = await device.dev.anchorTakeover(Buffer.from(device.pub, "hex"), Buffer.from(device.uid, "hex"), signers);
  const sid = s.sid;
  await s.close();
  return { sid };
}

/**
 * Launcher side: anchor the log head in the device while the session runs.
 * The sink, and with it the framework's anchor session and its key, lives in
 * the launcher process only. `request()` anchors now (the hook asks for it
 * over the control socket). A HeadAnchorAlarm from the framework (the
 * session was BUSY or hijacked) goes to `onAlarm`.
 */
export function startAnchoring(fw, device, auditLog, { intervalMs = 2000, onError = () => {}, onAlarm = onError, onTamper = onAlarm, sinkFactory = null } = {}) {
  if (!device?.anchor || (typeof fw.enclawederHeadAnchor !== "function" && !sinkFactory)) {
    return { mode: "none", flush: async () => ({ anchored: false, reason: device?.anchorRefused?.reason ?? "this device or framework cannot anchor" }), request() {}, stop() {}, async close() {} };
  }
  // The device and key the kit decided (withSessionAnchor): the framework's
  // sink opens the authenticated anchor session (record v2) on it.
  const opts = { device: device.anchor.dev, devicePublicKey: Buffer.from(device.anchor.pub, "hex"), path: anchorFile(auditLog), serial: device.serial ?? undefined };
  const sink = sinkFactory ? sinkFactory(opts) : fw.enclawederHeadAnchor(opts);
  const mode = sinkFactory?.mode ?? "authenticated";
  let last = null;
  let unsupported = false;
  let tampered = null;
  let busy = Promise.resolve();
  // Only heads that extend the chain this launcher saw are anchored (round 4,
  // N14, anchor-chain.mjs): the log is followed from its end at the start of
  // the session, every record after that is verified, and the anchor file
  // and history must stay exactly as the launcher left them.
  const chain = followChain(auditLog);
  const files = anchorFilesGuard(anchorFile(auditLog), anchorHistoryFile(auditLog));
  const once = () => {
    if (unsupported || tampered) {
      return busy;
    }
    busy = busy
      .then(async () => {
        if (tampered) {
          return;
        }
        let t;
        try {
          files.check();
          t = { hash: chain.advance().head };
        } catch (err) {
          if (err instanceof AnchorTamper) {
            tampered = err;
            clearInterval(timer);
            onTamper(err);
            return;
          }
          throw err;
        }
        if (t.hash && t.hash !== last) {
          await sink.write(t.hash);
          last = t.hash;
          // The anchor just written (device-signed) goes into the history too (N10b),
          // written by the kit: verified first, exactly the fields its record version signs.
          try {
            if (typeof fw.appendAnchorHistory !== "function") {
              throw new Error("this framework build cannot write the anchor history (appendAnchorHistory); rebuild it");
            }
            fw.appendAnchorHistory({ anchorPath: anchorFile(auditLog), historyPath: anchorHistoryFile(auditLog), devicePublicKey: Buffer.from(device.anchor.pub, "hex") });
          } catch (err) {
            onError(new Error(`could not record the anchor in its history: ${err.message}`));
          }
          files.wrote();
        }
      })
      .catch((err) => {
        if (err?.name === "HeadAnchorAlarm") {
          onAlarm(err);
          return;
        }
        if (UNSUPPORTED.test(err?.message ?? "")) {
          // Firmware older than the anchor commands: say so once and stop.
          unsupported = true;
          clearInterval(timer);
          onError(new Error(FIRMWARE_NO_ANCHOR));
          return;
        }
        onError(err);
      });
    return busy;
  };
  const timer = setInterval(once, intervalMs);
  timer.unref?.();
  // The anchor-session lease (round 4, N15; firmware 0.2, PROTOCOL.md
  // "Lease"): the device ends a session 120 s after its last authenticated
  // refresh, so a crashed holder no longer leaves it BUSY until a replug.
  // The framework's head-anchor sink renews it (ANCHOR_KEEPALIVE every
  // ANCHOR_KEEPALIVE_INTERVAL_MS) and reopens as sid+1 after a lapse; with
  // firmware 0.1 the renewal stops silently and a BUSY alarm tells the user
  // to replug. The launcher only reports which case it is in.
  const keepalive = typeof fw.ANCHOR_LEASE_MS === "number";
  return {
    mode,
    async flush() {
      await once();
      return { anchored: last !== null, head: last, unsupported, tampered: tampered ? tampered.message : null };
    },
    request() {
      once();
    },
    keepalive,
    stop() {
      clearInterval(timer);
    },
    // End the device session (authenticated ANCHOR_CLOSE) when the framework has it.
    async close() {
      clearInterval(timer);
      await busy;
      await fw.closeHeadAnchorSessions?.();
    },
  };
}

/**
 * `audit verify`: compare the device's anchored head with the chain.
 * @returns {Promise<{ status: "matched"|"MISMATCH"|"superseded"|"unavailable", detail: string, unanchoredTail?: number }>}
 *   "superseded" and "MISMATCH" fail `audit verify` (deviceAnchorFails).
 */
export async function checkDeviceAnchor(fw, auditLog, recordHashes) {
  if (!deviceApi(fw) || typeof fw.enclawederHeadAnchor !== "function") {
    return { status: "unavailable", detail: "the framework build has no device anchor support" };
  }
  const nsRisk = userNamespaceDeviceRisk();
  if (nsRisk) {
    return { status: "unavailable", detail: nsRisk };
  }
  const notes = [];
  const orig = console.error;
  console.error = (...a) => notes.push(a.join(" "));
  try {
    try {
      await fw.bootHardwareRoot();
    } catch (err) {
      return { status: "unavailable", detail: `hardware root: ${err.message}` };
    }
    const device = await boundDevice(fw).catch(() => null);
    if (!device) {
      return { status: "unavailable", detail: "no Enclaweder is bound to this process (none attached, or another process owns it)" };
    }
    return await checkBoundDeviceAnchor(fw, device, auditLog, recordHashes);
  } finally {
    console.error = orig;
    try {
      fw.closeHardwareRootSession();
    } catch {
      /* nothing to close */
    }
  }
}

/** The launch activations the log's own records name (sealed segments first), for the kit's comparison. */
export function logActivations(fw, auditLog) {
  if (typeof fw.deviceFactorActivationsInFiles !== "function") {
    return null;
  }
  const files = [...segmentFiles(auditLog).map((x) => x.file), auditLog].filter((f) => fs.existsSync(f));
  return fw.deviceFactorActivationsInFiles(files);
}

/**
 * checkDeviceAnchor's comparison, for a device this process already holds
 * (the launcher's launch-time check, round 5 R5-A). The comparison is the
 * kit's (compareAnchoredLog: the device's fresh head, counter and open count
 * against the log, its anchor file and its history, every bound line naming
 * one of the log's own launch activations); it also reports whether the
 * device holds any anchor at all (`deviceHasAnchors`). A framework build
 * without it cannot show a match: MISMATCH, never a pass.
 */
export async function checkBoundDeviceAnchor(fw, device, auditLog, recordHashes, { activations = logActivations(fw, auditLog) } = {}) {
  if (!device.anchor) {
    return { status: "unavailable", detail: device.anchorRefused?.reason ?? "the device is driven by another process; stop it to check the anchor", deviceHasAnchors: null };
  }
  if (typeof fw.compareAnchoredLog !== "function") {
    return { status: "MISMATCH", code: "anchor-compare-unavailable", counter: null, detail: "this framework build cannot compare the device's anchor with the log (compareAnchoredLog); rebuild it", deviceHasAnchors: null };
  }
  return fw.compareAnchoredLog({
    device: device.anchor.dev,
    devicePublicKey: Buffer.from(device.anchor.pub, "hex"),
    auditLog,
    recordHashes,
    activations,
    label: device.serial ?? device.uid,
  });
}

const sha256File = (p) => {
  try {
    return createHash("sha256").update(fs.readFileSync(p)).digest("hex");
  } catch {
    return null;
  }
};

/** SHA-256 measurements of what decides tool calls. */
export function measure({ policyPath = null, settingsPath = null } = {}) {
  const src = {};
  const dir = path.join(APP_ROOT, "src");
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith(".mjs")).sort()) {
    src[`src/${f}`] = sha256File(path.join(dir, f));
  }
  return {
    hook: { path: HOOK_BIN, sha256: sha256File(HOOK_BIN) },
    src,
    framework: { path: FRAMEWORK_ENTRY, sha256: sha256File(FRAMEWORK_ENTRY) },
    policy: policyPath ? { path: policyPath, sha256: sha256File(policyPath) } : null,
    settings: settingsPath ? { path: settingsPath, sha256: sha256File(settingsPath) } : null,
  };
}

/** Compare recorded measurements with the files now (settings files are per session and skipped). */
export function measurementDrift(recorded) {
  if (!recorded) {
    return [];
  }
  const now = measure({ policyPath: recorded.policy?.path ?? null });
  const drift = [];
  if (recorded.hook?.sha256 !== now.hook.sha256) {
    drift.push(recorded.hook?.path ?? "hook");
  }
  for (const [f, h] of Object.entries(recorded.src ?? {})) {
    if (now.src[f] !== h) {
      drift.push(f);
    }
  }
  if (recorded.framework?.sha256 !== now.framework.sha256) {
    drift.push(recorded.framework?.path ?? "framework");
  }
  if (recorded.policy && recorded.policy.sha256 !== now.policy?.sha256) {
    drift.push(recorded.policy.path);
  }
  return drift;
}
