// A stand-in Enclaweder anchor, at the frame level (no hardware), for the
// conformance guarantee below and for tests (test/fixtures/anchor-sim.mjs).
//
// The DEVICE side of the Enclaweder protocol's "Monotonic audit anchor"
// (record v2, the Enclaweder host protocol): ANCHOR_OPEN with an X25519
// exchange and an Ed25519 transcript signature, ANCHOR_SET / ANCHOR_CLOSE
// checked under the HMAC-SHA3-256 session key, one session at a time, every
// open counted. A JavaScript port of enclawed-oss's
// src/enclawed/hardware-root/anchor-sim.test-support.ts. The HOST side under
// test is the framework's real AnchorSession: Enclawed Code implements none of
// this protocol itself.
//
// `{ commandSet: "0.5" }` adds what Enclaweder firmware 0.3.3 answers
// (PROTOCOL.md "Command set 0.5", as enclawed-oss cs05-standin.test-support.ts
// does): UNLOCK_USE (0x31) as the launch's activation, ANCHOR_OPEN_BOUND
// (0x37: a session bound to that activation, replacing a plain one), record v3
// for every ANCHOR_SET under a bound session (ANCHOR_GET keeps answering v2),
// and ANCHOR_READ (0x38) signed over the reader's nonce.
import { createHmac, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, sign as edSign, timingSafeEqual } from "node:crypto";

const tag = (s) => Buffer.from(s, "latin1");
const le64 = (v) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v);
  return b;
};
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");
const T = { SET: 0x17, GET: 0x18, OPEN: 0x19, CLOSE: 0x1a, UNLOCK_USE: 0x31, OPEN_BOUND: 0x37, READ: 0x38 };
const ST = { OK: 0, BAD_ARG: 1, NOT_ENROLLED: 3, AUTH: 5, BUSY: 7 };

export class SimulatedAnchorFirmware {
  constructor(fw, { commandSet = "0.4" } = {}) {
    this.fw = fw;
    this.commandSet = commandSet;
    /** Command set 0.5: activations by request nonce (hex) -> { bind, anchor }. */
    this.acts = new Map();
    this.gid = 9n;
    this.boot = 4n;
    this.useIndex = 0;
    /** The binding of the session that set the head (null: unbound). */
    this.headBind = null;
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    this.publicKey = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
    this.priv = privateKey;
    this.uid = Buffer.alloc(12, 7);
    this.counter = 0n;
    this.head = null;
    this.sess = 0n;
    this.opens = 0n;
    this.session = null;
    this.dev = null;
  }

  /** USB re-enumeration (replug, port reset): the session ends; counters persist. */
  reenumerate() {
    this.session = null;
  }

  /** Something else on the host opens the channel. */
  foreignOpen() {
    return this.fw.AnchorSession.open(this, this.publicKey);
  }

  record() {
    const body = [le64(this.counter), this.head, this.uid, le64(this.sess), le64(this.opens)];
    return Buffer.concat([Buffer.from([ST.OK, 2]), ...body, edSign(null, Buffer.concat([tag("ECW-ANCHOR-02\0\0\0"), ...body]), this.priv)]);
  }

  /** Record v3: the answer to ANCHOR_SET under a bound session. */
  recordV3(bind) {
    const body = [le64(this.counter), this.head, this.uid, le64(this.sess), le64(this.opens)];
    return Buffer.concat([Buffer.from([ST.OK, 3]), ...body, bind, edSign(null, Buffer.concat([tag("enclaweder.anchor-record.v3"), ...body, bind]), this.priv)]);
  }

  get cs05() {
    return this.commandSet === "0.5";
  }

  /** ANCHOR_OPEN / ANCHOR_OPEN_BOUND: the device's half of the exchange; `bind` null for a plain open. */
  open(payload, bind) {
    const hostPub = payload.subarray(0, 32);
    const hostNonce = payload.subarray(32, 48);
    const eph = generateKeyPairSync("x25519");
    const devPub = Buffer.from(eph.publicKey.export({ format: "der", type: "spki" }).subarray(12));
    const devNonce = randomBytes(16);
    this.opens += 1n;
    const sid = this.opens;
    const t = [bind ? tag("enclaweder.anchor-open-bound.v1") : tag("ECW-ANCHOR-OPN-1"), this.uid, le64(sid), le64(this.counter), hostPub, devPub, hostNonce, devNonce, ...(bind ? [bind] : [])];
    const sig = edSign(null, Buffer.concat(t), this.priv);
    const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: createPublicKey({ key: Buffer.concat([X25519_SPKI, hostPub]), format: "der", type: "spki" }) });
    const info = Buffer.concat([tag("ECW-ANCHOR-KDF-1"), this.uid, le64(sid), hostPub, devPub]);
    const key = Buffer.from(hkdfSync("sha3-256", shared, Buffer.concat([hostNonce, devNonce]), info, 32));
    this.session = { sid, key, lastCtr: 0n, bind };
    return { payload: Buffer.concat([Buffer.from([ST.OK]), le64(sid), le64(this.counter), devPub, devNonce, this.uid, ...(bind ? [bind] : []), sig]) };
  }

  /** UNLOCK_USE (command set 0.5): one counted use, the launch's activation. */
  use(payload) {
    const nonce = payload.subarray(0, 32);
    this.useIndex += 1;
    const b = Buffer.alloc(100);
    b[0] = 1;
    b[1] = 1;
    b[3] = 2;
    b.writeUInt16LE(10, 4);
    b.writeUInt16LE(this.useIndex, 6);
    b.writeBigUInt64LE(payload.readBigUInt64LE(32), 8);
    b.writeBigUInt64LE(this.boot, 16);
    b.writeBigUInt64LE(payload.readBigUInt64LE(40), 40);
    b.writeUInt32LE(59_999_999, 48);
    b.writeUInt16LE(this.useIndex, 52);
    this.uid.copy(b, 56);
    payload.subarray(48, 80).copy(b, 68);
    const bind = Buffer.alloc(32);
    bind[0] = 1;
    b.copy(bind, 2, 52, 54);
    b.copy(bind, 4, 48, 52);
    b.copy(bind, 8, 8, 16);
    b.copy(bind, 16, 16, 24);
    this.acts.set(nonce.toString("hex"), { bind, anchor: false });
    return { payload: Buffer.concat([Buffer.from([ST.OK]), b, edSign(null, Buffer.concat([tag("enclaweder.unlock-use.v1"), nonce, b]), this.priv)]) };
  }

  /** ANCHOR_READ (command set 0.5), signed over the reader's nonce. */
  read(nonce) {
    const s = this.session;
    const lb = s?.bind ?? null;
    const body = Buffer.alloc(112);
    body[0] = 1;
    body[1] = (this.counter > 0n ? 1 : 0) | (s ? 2 : 0) | (lb ? 4 : 0) | (s && this.counter > 0n && this.sess === s.sid ? 8 : 0);
    body.writeBigUInt64LE(this.counter, 4);
    (this.head ?? Buffer.alloc(32)).copy(body, 12);
    this.uid.copy(body, 44);
    body.writeBigUInt64LE(this.sess, 56);
    body.writeBigUInt64LE(this.opens, 64);
    body.writeBigUInt64LE(s?.sid ?? 0n, 72);
    lb?.copy(body, 80);
    return { payload: Buffer.concat([Buffer.from([ST.OK]), body, edSign(null, Buffer.concat([tag("enclaweder.anchor-read.v1"), nonce, body]), this.priv)]) };
  }

  /** Spend one counted use as the launch's activation, through the framework's own spendUnlock. */
  async activate() {
    const nonce = randomBytes(32);
    const r = await this.fw.spendUnlock(this, this.publicKey, this.uid, { gid: this.gid, scope: randomBytes(32), nonce });
    if (!r.ok) {
      throw new Error(`spend: ${r.code}`);
    }
    return { gid: this.gid, useIndex: r.receipt.useIndex, boot: this.boot };
  }

  macOk(key, parts, mac) {
    const want = createHmac("sha3-256", key).update(Buffer.concat(parts)).digest();
    return mac.length === 32 && timingSafeEqual(want, mac);
  }

  async request(type, _id, payload = Buffer.alloc(0)) {
    const st = (s) => ({ payload: Buffer.from([s]) });
    switch (type) {
      case T.OPEN: {
        if (this.session) {
          return st(ST.BUSY);
        }
        if (payload.length !== 48) {
          return st(ST.BAD_ARG);
        }
        return this.open(payload, null);
      }
      case T.OPEN_BOUND: {
        if (!this.cs05) {
          return st(8);
        }
        if (payload.length !== 80) {
          return st(ST.BAD_ARG);
        }
        if (this.session?.bind) {
          return st(ST.BUSY);
        }
        const a = this.acts.get(payload.subarray(48, 80).toString("hex"));
        if (!a || a.anchor) {
          return st(ST.AUTH);
        }
        a.anchor = true;
        // A plain session is replaced by the bound open (PROTOCOL.md "Replacement rule").
        return this.open(payload, a.bind);
      }
      case T.UNLOCK_USE:
        return this.cs05 ? this.use(payload) : st(8);
      case T.READ:
        return this.cs05 && payload.length === 32 ? this.read(payload) : st(8);
      case T.SET: {
        const s = this.session;
        if (payload.length !== 80 || !s) {
          return st(ST.AUTH); // includes the bare 32-byte v1 request
        }
        const head = payload.subarray(0, 32);
        const sid = payload.readBigUInt64LE(32);
        const ctr = payload.readBigUInt64LE(40);
        if (!(sid === s.sid && ctr > s.lastCtr && this.macOk(s.key, [tag("ECW-ANCHOR-SET-1"), this.uid, le64(sid), le64(ctr), head], payload.subarray(48, 80)))) {
          return st(ST.AUTH);
        }
        s.lastCtr = ctr;
        this.counter += 1n;
        this.head = Buffer.from(head);
        this.sess = s.sid;
        this.headBind = s.bind ?? null;
        return { payload: s.bind ? this.recordV3(s.bind) : this.record() };
      }
      case T.CLOSE: {
        const s = this.session;
        if (payload.length !== 48 || !s) {
          return st(ST.AUTH);
        }
        const sid = payload.readBigUInt64LE(0);
        const ctr = payload.readBigUInt64LE(8);
        if (!(sid === s.sid && ctr > s.lastCtr && this.macOk(s.key, [tag("ECW-ANCHOR-CLS-1"), this.uid, le64(sid), le64(ctr)], payload.subarray(16, 48)))) {
          return st(ST.AUTH);
        }
        this.session = null;
        return st(ST.OK);
      }
      case T.GET:
        return this.head === null ? st(ST.NOT_ENROLLED) : { payload: this.record() };
      default:
        return st(8);
    }
  }

  /** The device as Enclawed Code's launcher binds it (boundDevice). */
  device() {
    this.dev ??= {
      getIdentity: async () => ({ uid: this.uid, pubkeyRaw: this.publicKey, serial: "SIM" }),
      getCert: async () => null,
      challenge: async () => {
        throw new Error("unused");
      },
      anchorOpen: (pub) => this.fw.AnchorSession.open(this, pub),
      ...(this.cs05
        ? {
            anchorOpenBound: (pub, nonce) => this.fw.AnchorSession.openBound(this, pub, nonce),
            anchorRead: async (nonce) => (await this.request(T.READ, 1, nonce)).payload,
          }
        : {}),
      anchorSet: (head, session) => session.set(head),
      anchorClose: (session) => session.close(),
      anchorGet: async () => {
        const f = await this.request(T.GET, 1);
        return f.payload[0] === ST.NOT_ENROLLED ? null : this.fw.parseAnchor(f.payload);
      },
    };
    return this.dev;
  }
}

/** The kit's session-anchor decision over the stand-in (the one input a real framework takes from the device it holds). */
function withStandIn(real, sim) {
  sim.dev = null; // a new process: a new device handle, so a new anchor-session slot
  const dev = sim.device();
  const fw = new Proxy(real, {
    get(t, k) {
      if (k === "bootHardwareRoot") return async () => ({});
      if (k === "hardwareRootSigningDevice") return () => dev;
      if (k === "closeHardwareRootSession") return () => {};
      if (k === "requireHardwareRootSessionAnchor") {
        return () => {
          const d = real.decideSessionAnchor({ bound: true, device: dev, devicePublicKey: sim.publicKey });
          if (!d.ok) throw new real.SessionAnchorRefused(d.code, d.reason);
          return d;
        };
      }
      return t[k];
    },
  });
  return { fw, dev };
}

/**
 * The anchor guarantee on command set 0.5 (Enclaweder firmware 0.3.3), through
 * Enclawed Code's own launch, anchoring and verify mapping: a held session's log
 * verifies matched, and a later launch on the continuing log passes the anchor
 * gate (and verifies again). The device is the stand-in above, at command set
 * 0.5: record v3 for a session bound to the launch's activation.
 */
export function anchorChecks(real) {
  return [
    {
      id: "adapter:claude-code:anchor-v3-continuing-log",
      title: "claude-code: a held session on a 0.5 Enclaweder verifies, and the next launch on its log passes the anchor gate",
      proves:
        "through Enclawed Code's launcher anchoring, launch gate and audit verify, every anchor of a session bound to its launch's device activation is recorded as the device signed it (record v3: version, session, open count, binding), the log verifies matched with a fresh device read bound to the log's own launch, a later launch on the continuing log passes the anchor gate and its log verifies too, and a history stripped of the v3 fields refuses the launch",
      remedy: "Enclawed Code must write, read and compare the anchor history through the kit (appendAnchorHistory, readAnchorHistory, compareAnchoredLog), never with its own record format",
      run: async () => {
        const fs = (await import("node:fs")).default;
        const os = (await import("node:os")).default;
        const path = (await import("node:path")).default;
        const { anchorHistoryFile, checkDeviceAnchor, startAnchoring, withSessionAnchor } = await import("./device.mjs");
        const { launchAnchorGate, logRecordHashes } = await import("./anchor-gate.mjs");
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-conformance-anchor-"));
        try {
          const sim = new SimulatedAnchorFirmware(real, { commandSet: "0.5" });
          const log = path.join(dir, "audit.jsonl");
          const proc = () => {
            const { fw, dev } = withStandIn(real, sim);
            return { fw, device: withSessionAnchor(fw, { dev, pub: sim.publicKey.toString("hex"), uid: sim.uid.toString("hex"), serial: "STANDIN" }) };
          };
          const launch = async () => {
            const { fw, device } = proc();
            const gate = await launchAnchorGate(fw, device, log, { rootRequired: true });
            if (!gate.ok) return gate;
            const act = await sim.activate();
            const a = startAnchoring(fw, device, log, { intervalMs: 3_600_000 });
            const L = new fw.AuditLogger({ filePath: log });
            await L.append({ type: "claude-code.launch", actor: "enclawed-code", level: null, payload: { hardware: "held", rootRequired: true } });
            await L.append({ type: "claude-code.auth.device-factor", actor: "enclawed-code", level: null, payload: { purpose: "session-start", outcome: "verified", via: "device-unlock", gid: String(act.gid), useIndex: act.useIndex, boot: String(act.boot) } });
            await L.close();
            const f = await a.flush();
            await a.close();
            if (!f.anchored) throw new Error(`the session did not anchor: ${JSON.stringify(f)}`);
            return gate;
          };
          const verify = async () => {
            const { fw } = proc();
            const dev = await checkDeviceAnchor(fw, log, logRecordHashes(log));
            const records = fs.readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l));
            const verdict = fw.decideAuditAnchorVerdict({ claims: fw.launchRootClaims(records), device: dev.status, chainAnchor: null, attestation: dev.attestation ?? null, activations: fw.deviceFactorActivations(records) });
            if (dev.status !== "matched" || !verdict.ok) throw new Error(`a held session's log does not verify: ${JSON.stringify({ status: dev.status, code: dev.code, detail: dev.detail, verdict })}`);
          };
          const g1 = await launch();
          if (!g1.ok) throw new Error(`the first launch was refused: ${JSON.stringify(g1)}`);
          const lines = fs.readFileSync(anchorHistoryFile(log), "utf8").trim().split("\n").map((l) => JSON.parse(l));
          if (!lines.every((l) => l.version === 3 && /^[0-9a-f]{64}$/.test(l.bind ?? "") && l.sess && l.opens)) {
            throw new Error(`the anchor history does not record the device's v3 records as signed: ${JSON.stringify(lines[0])}`);
          }
          await verify();
          const g2 = await launch();
          if (!g2.ok) throw new Error(`a later launch on the continuing log was refused by the anchor gate: ${JSON.stringify(g2)}`);
          await verify();
          // The same history stripped of the v3 fields (as a writer that knew only v2 left it): refused.
          const hist = anchorHistoryFile(log);
          const text = fs.readFileSync(hist, "utf8");
          fs.writeFileSync(hist, text.trim().split("\n").map((l) => { const { head, counter, uid, sig, ts } = JSON.parse(l); return JSON.stringify({ head, counter, uid, sig, ts }); }).join("\n") + "\n");
          const { fw, device } = proc();
          const g3 = await launchAnchorGate(fw, device, log, { rootRequired: true });
          if (g3.ok) throw new Error("a history whose v3 records lost their signed fields passed the anchor gate");
        } finally {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      },
    },
  ];
}
