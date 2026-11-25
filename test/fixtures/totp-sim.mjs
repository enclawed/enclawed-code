// A simulated Enclaweder for device-verified TOTP, TEST-ONLY. It answers like
// a device with TOTP_VERIFY (RFC 6238 codes, each step accepted once, a verdict
// signed by the device key over the host's nonce), in the public verdict
// format of enclawed-oss hardware-root/totp-verify.ts. Alongside it, the four
// framework calls Enclawed Code's device-activation.mjs needs, implemented the
// way the framework does (enclawed-oss exports them from 8b9ebf990 on, and its
// verifyVerdictRecord accepts this simulator's records). Keys and the secret
// are per-test values. It also counts device unlocks (command set 0.4: a
// grant of N uses in a lease, each use counted BY THE DEVICE with a receipt
// it signs over the host's nonce), with the three framework calls the kit's
// issueDeviceUnlock/spendDeviceUnlock use (grantUnlock, spendUnlock,
// verifyUnlockReceipt), in a simulator-only record format.
import { createHmac, createPublicKey, generateKeyPairSync, randomBytes, sign as edSign, verify as edVerify } from "node:crypto";

const TAG = Buffer.from("enclaweder.totp-verdict.v1", "latin1");
export const PURPOSE = { "session-start": 0x01, "policy-change": 0x02, recovery: 0x03, "disable-protection": 0x04, "history-restore": 0x05, admin: 0x06, "auth-change": 0x07, "auth-test": 0x08, unlock: 0x09 };
const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const pubKey = (raw) => createPublicKey({ key: Buffer.concat([ED_SPKI, raw]), format: "der", type: "spki" });

export function hotp(secret, step) {
  const m = Buffer.alloc(8);
  m.writeBigUInt64BE(BigInt(step));
  const d = createHmac("sha1", secret).update(m).digest();
  const o = d[19] & 15;
  return (((d[o] & 0x7f) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) % 1_000_000;
}

export class SimTotpDevice {
  constructor() {
    this.key = generateKeyPairSync("ed25519");
    this.pub = Buffer.from(this.key.publicKey.export({ format: "jwk" }).x, "base64url");
    this.uid = randomBytes(12);
    this.secret = randomBytes(20);
    this.lastStep = 0;
    this.counter = 100n;
    this.enrolled = true;
    this.calls = 0;
    // Device unlock state: one live grant at a time; a restart (boot) ends it.
    this.boot = 1n;
    this.nextGid = 1n;
    this.grant = null;
  }
  code(nowS = Date.now() / 1000) {
    return String(hotp(this.secret, Math.floor(nowS / 30))).padStart(6, "0");
  }
  /** The device side: evaluate the code, sign the verdict over the host's nonce. */
  verify(nonce, code, hostTimeS, purpose) {
    this.calls++;
    const s0 = Math.floor(hostTimeS / 30);
    let step = 0;
    for (const s of [s0 - 1, s0, s0 + 1]) {
      if (step === 0 && s > this.lastStep && String(hotp(this.secret, s)).padStart(6, "0") === code) {
        step = s;
      }
    }
    if (step) {
      this.lastStep = step;
    }
    this.counter += 1n;
    const body = Buffer.alloc(32);
    body[0] = 1;
    body[1] = purpose;
    body[2] = step ? 1 : 0;
    body.writeUInt32LE(step, 4);
    body.writeBigUInt64LE(this.counter, 8);
    this.uid.copy(body, 20);
    return { pass: step !== 0, body, sig: edSign(null, Buffer.concat([TAG, nonce, body]), this.key.privateKey) };
  }
  access() {
    return { pubkeyRaw: this.pub, uid: this.uid, cert: Buffer.alloc(0), run: (fn) => fn(this) };
  }
}

const TAG_USE = Buffer.from("sim.unlock-use.v1", "latin1");

/** The framework calls (as device-activation.mjs expects them), over `dev`. */
export function totpFramework(dev, { now = () => Date.now() } = {}) {
  const verifyVerdictRecord = (rec, e) => {
    const h = (v, n) => (typeof v === "string" && v.length === 2 * n && /^[0-9a-f]+$/.test(v) ? Buffer.from(v, "hex") : null);
    const nonce = h(rec?.nonce, 32);
    const body = h(rec?.body, 32);
    const sig = h(rec?.sig, 64);
    if (!rec || rec.v !== 1 || !nonce || !body || !sig) {
      return { ok: false, reason: "malformed record" };
    }
    if (!nonce.equals(Buffer.from(e.nonce)) || h(rec.pubkey, 32)?.equals(e.pubkeyRaw) !== true || h(rec.uid, 12)?.equals(e.uid) !== true) {
      return { ok: false, reason: "another nonce or device" };
    }
    let good = false;
    try {
      good = edVerify(null, Buffer.concat([TAG, nonce, body]), pubKey(e.pubkeyRaw), sig);
    } catch {
      good = false;
    }
    if (!good) {
      return { ok: false, reason: "device signature does not verify" };
    }
    if (body[0] !== 1 || body[2] !== 1 || body[1] !== PURPOSE[e.purpose] || !body.subarray(20, 32).equals(e.uid)) {
      return { ok: false, reason: "verdict does not approve this purpose" };
    }
    return { ok: true, stepTimeS: body.readUInt32LE(4) * 30 };
  };
  return {
    hardwareRootTotpDevice: () => (dev.present === false ? null : dev.access()),
    deviceTotpEnrolled: async () => dev.enrolled,
    deviceTotpVerdict: async (access, { code, purpose, nonce }) => {
      if (!/^\d{6}$/.test(code) || PURPOSE[purpose] === undefined || nonce.length !== 32) {
        return { ok: false, code: "malformed-code" };
      }
      const r = dev.verify(Buffer.from(nonce), code, Math.floor(now() / 1000), PURPOSE[purpose]);
      if (!r.pass) {
        return { ok: false, code: "rejected" };
      }
      const record = { v: 1, purpose: PURPOSE[purpose], uid: access.uid.toString("hex"), pubkey: access.pubkeyRaw.toString("hex"), nonce: Buffer.from(nonce).toString("hex"), body: r.body.toString("hex"), sig: r.sig.toString("hex") };
      return { ok: true, record };
    },
    verifyVerdictRecord,
    // Device-counted unlock. The device checks the code (purpose unlock) and keeps the grant.
    grantUnlock: async (t, pubkeyRaw, uid, { code, uses, leaseS, scope }) => {
      const d = t.dev;
      if (!/^\d{6}$/.test(code) || scope.length !== 32 || uses < 1 || uses > 64 || leaseS < 30 || leaseS > 43_200) {
        return { ok: false, code: "malformed" };
      }
      if (!d.enrolled) {
        return { ok: false, code: "not-enrolled" };
      }
      if (!d.verify(randomBytes(32), code, Math.floor(now() / 1000), PURPOSE.unlock).pass) {
        return { ok: false, code: "rejected" };
      }
      d.grant = { gid: d.nextGid++, uses, used: 0, leaseMs: leaseS * 1000, until: now() + leaseS * 1000, scope: Buffer.from(scope) };
      const grant = { gid: d.grant.gid, boot: d.boot, uses, used: 0, leaseMs: d.grant.leaseMs };
      return { ok: true, grant, record: { v: 1, tag: "grant", gid: String(grant.gid) } };
    },
    spendUnlock: async (d, pubkeyRaw, uid, { gid, scope, nonce }) => {
      const g = d.grant;
      if (!g || now() > g.until || g.used >= g.uses) {
        d.grant = null;
        return { ok: false, code: "no-grant" };
      }
      if (g.gid !== gid || !g.scope.equals(scope)) {
        return { ok: false, code: "mismatch" };
      }
      g.used++;
      const body = Buffer.from(JSON.stringify({ kind: "use", gid: String(g.gid), boot: String(d.boot), uses: g.uses, used: g.used, useIndex: g.used, uid: d.uid.toString("hex"), scope: g.scope.toString("hex") }));
      const record = { v: 1, tag: "use", uid: d.uid.toString("hex"), pubkey: d.pub.toString("hex"), nonce: Buffer.from(nonce).toString("hex"), body: body.toString("hex"), sig: edSign(null, Buffer.concat([TAG_USE, nonce, body]), d.key.privateKey).toString("hex") };
      return { ok: true, record };
    },
    verifyUnlockReceipt: (rec, e) => {
      try {
        if (rec?.v !== 1 || rec.tag !== "use" || rec.nonce !== e.nonce.toString("hex")) {
          return null;
        }
        const raw = Buffer.from(rec.body, "hex");
        if (!edVerify(null, Buffer.concat([TAG_USE, e.nonce, raw]), pubKey(e.pubkeyRaw), Buffer.from(rec.sig, "hex"))) {
          return null;
        }
        const b = JSON.parse(raw.toString("utf8"));
        if (b.kind !== "use" || b.uid !== e.uid.toString("hex") || b.scope !== e.scope.toString("hex")) {
          return null;
        }
        return { ...b, gid: BigInt(b.gid), boot: BigInt(b.boot) };
      } catch {
        return null;
      }
    },
  };
}
