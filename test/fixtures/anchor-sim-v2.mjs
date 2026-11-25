// Firmware 0.2 anchor simulator for tests (no hardware): enclawed-oss's
// src/enclawed/hardware-root/anchor-sim.test-support.ts, transpiled to
// JavaScript (esbuild) with its two framework imports bound at run time
// (bindFramework). Command set 0.2 by default: the 120 s lease on an
// injectable clock, ANCHOR_KEEPALIVE, ERR_BUSY | wait_ms and the operator
// takeover; `commandSet: "0.1"` behaves like the earlier firmware. Regenerate
// from enclawed-oss when that file changes; do not edit by hand.
let AnchorSession;
let parseAnchor;
/** Bind the framework's AnchorSession and parseAnchor (the host side under test). */
export function bindFramework(fw) {
  AnchorSession = fw.AnchorSession;
  parseAnchor = fw.parseAnchor;
}
import {
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign as edSign,
  timingSafeEqual,
  verify as edVerify
} from "node:crypto";
const tag = (s) => Buffer.from(s, "latin1");
const le64 = (v) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v);
  return b;
};
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");
const T = {
  AUTH_CHALLENGE: 18,
  SET: 23,
  GET: 24,
  OPEN: 25,
  CLOSE: 26,
  KEEPALIVE: 27
};
const ST = { OK: 0, BAD_ARG: 1, NOT_ENROLLED: 3, AUTH: 5, BUSY: 7, UNSUPPORTED: 8 };
const SIM_LEASE_MS = 12e4;
class SimulatedAnchorFirmware {
  constructor(opts = {}) {
    this.uid = Buffer.alloc(12, 7);
    this.counter = 0n;
    this.head = null;
    this.sess = 0n;
    this.opens = 0n;
    this.offline = false;
    /** Every frame payload the host sent, for leak checks. */
    this.sent = [];
    this.clockSkewMs = 0;
    /** Operator public keys (raw Ed25519) and the quorum M, as SET_OPERATOR[_POLICY] leave them. */
    this.operators = [];
    this.quorum = 1;
    this.#opNonce = null;
    this.#session = null;
    this.#device = null;
    this.commandSet = opts.commandSet ?? "0.2";
    this.#now = opts.now ?? (() => Date.now());
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    this.publicKey = Buffer.from(
      publicKey.export({ format: "jwk" }).x,
      "base64url"
    );
    this.#priv = privateKey;
  }
  #priv;
  /** The device's monotonic tick. Defaults to Date.now(), so vitest fake timers drive it;
   *  `clockSkewMs` jumps the device clock alone (a host process that was suspended). */
  #now;
  #opNonce;
  #session;
  #device;
  #clock() {
    return this.#now() + this.clockSkewMs;
  }
  get #lease() {
    return this.commandSet === "0.2";
  }
  /** Every anchor command checks the lease first; expiry is a close. */
  #expire() {
    if (this.#lease && this.#session && this.#clock() >= this.#session.expires) {
      this.#session = null;
    }
  }
  #renew() {
    if (this.#session) {
      this.#session.expires = this.#clock() + SIM_LEASE_MS;
    }
  }
  /** The current session key, so a test can prove the host never leaks it. */
  sessionKey() {
    this.#expire();
    return this.#session ? Buffer.from(this.#session.key) : null;
  }
  get sessionOpen() {
    this.#expire();
    return this.#session !== null;
  }
  get currentSid() {
    this.#expire();
    return this.#session?.sid ?? null;
  }
  /** A fresh operator key pair for takeover tests: install `pub` in `operators`, sign with `sign`. */
  static operatorKey() {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    return {
      pub: Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url"),
      sign: (m) => edSign(null, m, privateKey)
    };
  }
  #busy() {
    if (!this.#lease || !this.#session) {
      return { payload: Buffer.from([ST.BUSY]) };
    }
    const b = Buffer.alloc(5);
    b[0] = ST.BUSY;
    b.writeUInt32LE(Math.max(0, this.#session.expires - this.#clock()), 1);
    return { payload: b };
  }
  /** The operator-quorum tail of a takeover OPEN: M distinct operator keys must verify. */
  #quorumOk(hostPart, tail) {
    const nonce = this.#opNonce;
    this.#opNonce = null;
    if (!nonce || this.operators.length === 0) {
      return false;
    }
    if (tail.length < 16 + 64 || (tail.length - 16) % 64 !== 0 || (tail.length - 16) / 64 > 8) {
      return false;
    }
    if (!timingSafeEqual(tail.subarray(0, 16), nonce)) {
      return false;
    }
    const msg = Buffer.concat([
      tag("ECW-OPER-AUTH-01"),
      nonce,
      Buffer.from([T.OPEN]),
      this.uid,
      hostPart
    ]);
    const used = /* @__PURE__ */ new Set();
    for (let off = 16; off < tail.length; off += 64) {
      const sig = tail.subarray(off, off + 64);
      const k = this.operators.findIndex(
        (pub, i) => !used.has(i) && edVerify(
          null,
          msg,
          createPublicKey({
            key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pub]),
            format: "der",
            type: "spki"
          }),
          sig
        )
      );
      if (k >= 0) {
        used.add(k);
      }
    }
    return used.size >= this.quorum;
  }
  /** USB re-enumeration (replug, port reset): the session ends; counters persist. */
  reenumerate() {
    this.#session = null;
  }
  /** Something else on the host opens the channel (it then holds the only session). */
  async foreignOpen() {
    return AnchorSession.open(this, this.publicKey);
  }
  #record() {
    const msg = Buffer.concat([
      tag("ECW-ANCHOR-02\0\0\0"),
      le64(this.counter),
      this.head,
      this.uid,
      le64(this.sess),
      le64(this.opens)
    ]);
    return Buffer.concat([
      Buffer.from([ST.OK, 2]),
      le64(this.counter),
      this.head,
      this.uid,
      le64(this.sess),
      le64(this.opens),
      edSign(null, msg, this.#priv)
    ]);
  }
  #macOk(key, parts, mac) {
    const want = createHmac("sha3-256", key).update(Buffer.concat(parts)).digest();
    return mac.length === 32 && timingSafeEqual(want, mac);
  }
  async request(type, _id, payload = Buffer.alloc(0)) {
    if (this.offline) {
      throw new Error("device not present");
    }
    this.sent.push(Buffer.from(payload));
    const st = (s) => ({ payload: Buffer.from([s]) });
    this.#expire();
    switch (type) {
      case T.AUTH_CHALLENGE: {
        this.#opNonce = randomBytes(16);
        return { payload: Buffer.concat([Buffer.from([ST.OK]), this.#opNonce]) };
      }
      case T.OPEN: {
        const takeover = this.#lease && payload.length > 48;
        if (takeover) {
          if (!this.#quorumOk(payload.subarray(0, 48), payload.subarray(48))) {
            return st(ST.AUTH);
          }
          this.#session = null;
        }
        if (this.#session) {
          return this.#busy();
        }
        if (payload.length !== 48 && !takeover) {
          return st(ST.BAD_ARG);
        }
        const hostPub = payload.subarray(0, 32);
        const hostNonce = payload.subarray(32, 48);
        const eph = generateKeyPairSync("x25519");
        const devPub = Buffer.from(
          eph.publicKey.export({ format: "der", type: "spki" }).subarray(12)
        );
        const devNonce = randomBytes(16);
        this.opens += 1n;
        const sid = this.opens;
        const sig = edSign(
          null,
          Buffer.concat([
            tag("ECW-ANCHOR-OPN-1"),
            this.uid,
            le64(sid),
            le64(this.counter),
            hostPub,
            devPub,
            hostNonce,
            devNonce
          ]),
          this.#priv
        );
        const shared = diffieHellman({
          privateKey: eph.privateKey,
          publicKey: createPublicKey({
            key: Buffer.concat([X25519_SPKI, hostPub]),
            format: "der",
            type: "spki"
          })
        });
        const info = Buffer.concat([tag("ECW-ANCHOR-KDF-1"), this.uid, le64(sid), hostPub, devPub]);
        const key = Buffer.from(
          hkdfSync("sha3-256", shared, Buffer.concat([hostNonce, devNonce]), info, 32)
        );
        this.#session = { sid, key, lastCtr: 0n, expires: this.#clock() + SIM_LEASE_MS };
        return {
          payload: Buffer.concat([
            Buffer.from([ST.OK]),
            le64(sid),
            le64(this.counter),
            devPub,
            devNonce,
            this.uid,
            sig
          ])
        };
      }
      case T.SET: {
        const s = this.#session;
        if (payload.length !== 80 || !s) {
          return st(ST.AUTH);
        }
        const head = payload.subarray(0, 32);
        const sid = payload.readBigUInt64LE(32);
        const ctr = payload.readBigUInt64LE(40);
        const ok = sid === s.sid && ctr > s.lastCtr && this.#macOk(
          s.key,
          [tag("ECW-ANCHOR-SET-1"), this.uid, le64(sid), le64(ctr), head],
          payload.subarray(48, 80)
        );
        if (!ok) {
          return st(ST.AUTH);
        }
        s.lastCtr = ctr;
        this.#renew();
        this.counter += 1n;
        this.head = Buffer.from(head);
        this.sess = s.sid;
        return { payload: this.#record() };
      }
      case T.CLOSE: {
        const s = this.#session;
        if (payload.length !== 48 || !s) {
          return st(ST.AUTH);
        }
        const sid = payload.readBigUInt64LE(0);
        const ctr = payload.readBigUInt64LE(8);
        const ok = sid === s.sid && ctr > s.lastCtr && this.#macOk(
          s.key,
          [tag("ECW-ANCHOR-CLS-1"), this.uid, le64(sid), le64(ctr)],
          payload.subarray(16, 48)
        );
        if (!ok) {
          return st(ST.AUTH);
        }
        this.#session = null;
        return st(ST.OK);
      }
      case T.KEEPALIVE: {
        if (!this.#lease) {
          return st(ST.UNSUPPORTED);
        }
        const s = this.#session;
        if (payload.length !== 48 || !s) {
          return st(ST.AUTH);
        }
        const sid = payload.readBigUInt64LE(0);
        const ctr = payload.readBigUInt64LE(8);
        const ok = sid === s.sid && ctr > s.lastCtr && this.#macOk(
          s.key,
          [tag("ECW-ANCHOR-KAL-1"), this.uid, le64(sid), le64(ctr)],
          payload.subarray(16, 48)
        );
        if (!ok) {
          return st(ST.AUTH);
        }
        s.lastCtr = ctr;
        this.#renew();
        const r = Buffer.alloc(5);
        r.writeUInt32LE(SIM_LEASE_MS, 1);
        return { payload: r };
      }
      case T.GET:
        return this.head === null ? st(ST.NOT_ENROLLED) : { payload: this.#record() };
      default:
        return st(ST.UNSUPPORTED);
    }
  }
  /** The device as the head-anchor sink sees it (one stable object per firmware). */
  device() {
    this.#device ??= {
      anchorOpen: (pub) => AnchorSession.open(this, pub),
      anchorGet: async () => {
        const f = await this.request(T.GET, 1);
        return f.payload[0] === ST.NOT_ENROLLED ? null : parseAnchor(f.payload);
      }
    };
    return this.#device;
  }
}
export {
  SIM_LEASE_MS,
  SimulatedAnchorFirmware
};
