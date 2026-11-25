// TEST DOUBLE of a device-bound platform passkey behind the kit's loopback
// page, for tests that drive Enclawed Code's passkey paths (enrollment, launch,
// sensitive commands, unlock tickets) without a browser or an authenticator.
// It answers the kit's PasskeyCeremony in the browser's wire format with a
// SOFTWARE key, so the kit's own checks run end to end; it is not a model of
// Windows Hello or any authenticator and proves nothing about one.
//
// The attestation is "packed" under the kit's own test attestation leaf, and
// the TPM statement is a real Windows Hello registration; both are copied
// verbatim from the Enclawed kit's test fixtures (enclawed-oss
// src/enclawed/auth/vectors.test-support.ts TEST_LEAF_PEM, TEST_LEAF_KEY_JWK,
// TEST_AAGUID, and platform-vectors.test-support.ts TPM_SURFACE_PRO_4, from
// py_webauthn, BSD 3-Clause, Copyright (c) 2017-2021 Duo Security, Inc.).
// The leaf key is a throwaway test key, never used outside tests.

import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";

export const TEST_LEAF_PEM = "-----BEGIN CERTIFICATE-----\nMIICDTCCAbOgAwIBAgIUXeg8ya3MYU8+xxX+/da7ny+yL44wCgYIKoZIzj0EAwIw\nJzElMCMGA1UEAwwcRW5jbGF3ZWQgVGVzdCBBdHRlc3RhdGlvbiBDQTAgFw0yNjEx\nMjIwNzU1MzdaGA8yMTI2MTAyOTA3NTUzN1owbzELMAkGA1UEBhMCVVMxFjAUBgNV\nBAoMDUVuY2xhd2VkIFRlc3QxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0\nYXRpb24xJDAiBgNVBAMMG0VuY2xhd2VkIFRlc3QgQXV0aGVudGljYXRvcjBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABJdVRptXc0ESFDebvTW3Fj1iDpZQIY3Q4giC\nBTeHsQbkmmAIK+5aMc68r1JaqqJE7Oep75ii+QnYBiF8ndibAoujczBxMAwGA1Ud\nEwEB/wQCMAAwIQYLKwYBBAGC5RwBAQQEEgQQ4cGgAH5XSqWwAQAAAAAAATAdBgNV\nHQ4EFgQU5PqXnzvqyeki3F2ON+N5qsh0Xc4wHwYDVR0jBBgwFoAUDrzSPMj9tL0T\nvZWPAC4jrrOaHXUwCgYIKoZIzj0EAwIDSAAwRQIgMlhROqyKYGRLm/hrFOfw5+wu\nOHOQJY1W+HfqYiLGYMcCIQD0TR8+kkJ57Wt78b/lVDhpKhDHNQRkBuJgr3d5Ft7c\nPg==\n-----END CERTIFICATE-----\n";
export const TEST_LEAF_KEY_JWK = {"kty":"EC","x":"l1VGm1dzQRIUN5u9NbcWPWIOllAhjdDiCIIFN4exBuQ","y":"mmAIK-5aMc68r1JaqqJE7Oep75ii-QnYBiF8ndibAos","crv":"P-256","d":"jACRLRl3gOrnf-O2l811qCWg8v-hinK8RACev9jYLNI"};
export const TEST_AAGUID = "e1c1a000-7e57-4aa5-b001-000000000001";
/** Windows Hello, Surface Pro 4 (Intel TPM): a genuine TPM statement for another credential and RP. */
export const TPM_SURFACE_PRO_4_ATTESTATION_OBJECT = "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";

export const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };

function head(major, n) {
  if (n < 24) {
    return Buffer.from([(major << 5) | n]);
  }
  if (n < 0x100) {
    return Buffer.from([(major << 5) | 24, n]);
  }
  if (n < 0x10000) {
    return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
  }
  return Buffer.from([(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

/** A small CBOR encoder (integers, strings, byte strings, arrays, maps). */
export function cbor(v) {
  if (typeof v === "number") {
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (typeof v === "string") {
    const b = Buffer.from(v, "utf8");
    return Buffer.concat([head(3, b.length), b]);
  }
  if (v instanceof Uint8Array) {
    return Buffer.concat([head(2, v.length), v]);
  }
  if (Array.isArray(v)) {
    return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  }
  const parts = [head(5, v.size)];
  for (const [k, val] of v) {
    parts.push(cbor(k), cbor(val));
  }
  return Buffer.concat(parts);
}

export function coseOf(publicKey) {
  const jwk = publicKey.export({ format: "jwk" });
  return cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
}

export function authData({ rpId, flags, signCount, attested }) {
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(signCount >>> 0);
  const parts = [createHash("sha256").update(rpId).digest(), Buffer.from([flags]), counter];
  if (attested) {
    const len = Buffer.alloc(2);
    len.writeUInt16BE(attested.credentialId.length);
    parts.push(Buffer.from(attested.aaguid.replace(/-/g, ""), "hex"), len, attested.credentialId, attested.cose);
  }
  return Buffer.concat(parts);
}

const leafDer = () => Buffer.from(TEST_LEAF_PEM.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");

/**
 * A platform passkey behind the loopback page. `flags` are the authenticator
 * flags it reports (UP|UV: a device-bound passkey that verified the user);
 * set BE for a synced (backup-eligible) one, drop UV for one that did not
 * verify the user. `ceremony` is the kit's PasskeyCeremony.
 */
export class PasskeyDouble {
  held = [];
  requests = [];
  flags = FLAGS.UP | FLAGS.UV;
  counterStep = 1;
  port = 40000 + Math.floor(Math.random() * 20000);

  get origin() {
    return `http://localhost:${this.port}`;
  }

  ceremony = async (req, say) => {
    this.requests.push(req);
    say?.(`(test double) passkey page: ${this.origin}/test`);
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: req.kind === "create" ? "webauthn.create" : "webauthn.get", challenge: Buffer.from(req.challenge).toString("base64url"), origin: this.origin, crossOrigin: false }),
    );
    const cdh = createHash("sha256").update(clientDataJSON).digest();
    if (req.kind === "create") {
      const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const id = randomBytes(32);
      this.held.push({ id, key: pair.privateKey, counter: 0 });
      const raw = authData({ rpId: "localhost", flags: this.flags | FLAGS.AT, signCount: 0, attested: { aaguid: TEST_AAGUID, credentialId: id, cose: coseOf(pair.publicKey) } });
      const sig = sign("sha256", Buffer.concat([raw, cdh]), createPrivateKey({ key: TEST_LEAF_KEY_JWK, format: "jwk" }));
      const attestationObject = cbor(new Map([["fmt", "packed"], ["attStmt", new Map([["alg", -7], ["sig", sig], ["x5c", [leafDer()]]])], ["authData", raw]]));
      return { kind: "create", origin: this.origin, credentialId: id, clientDataJSON, attestationObject };
    }
    const h = this.held.find((x) => req.allowCredentialIds.some((a) => Buffer.compare(Buffer.from(a), x.id) === 0));
    if (!h) {
      throw new Error("no matching passkey");
    }
    h.counter += this.counterStep;
    const raw = authData({ rpId: "localhost", flags: this.flags, signCount: h.counter });
    return { kind: "get", origin: this.origin, credentialId: h.id, clientDataJSON, authenticatorData: raw, signature: sign("sha256", Buffer.concat([raw, cdh]), h.key) };
  };
}
