// The demo's throwaway two-factor credential.
//
// `ecwctl demo` (and the offline adversarial suite) run every
// scenario in a throwaway state directory (demo-engine.mjs createSandbox),
// never the user's own. Two-factor authentication is mandatory there too, so
// each sandbox enrolls its own SOFTWARE credential in that throwaway
// directory and signs a fresh unlock ticket with it before each launch, in
// exactly the format the framework verifies.
//
// This does not weaken the user's install: a ticket is verified against the
// keys enrolled in the state dir it is used with, and the user's state dir
// holds only their security keys. Writing a credential into a state dir is
// something any process able to write that dir can do already (auth.mjs
// header); this file only does it inside a directory it just created. It is
// demo scaffolding, not an authenticator, and claims nothing about one.

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { RP_ID } from "./auth.mjs";

/**
 * Only inside a throwaway directory: under the OS temp directory, never one
 * that already holds an enrollment, and never this account's own state dir.
 * Anything else is refused, so this cannot enroll a software credential into
 * a real install.
 */
function assertThrowaway(authDir) {
  const tmp = fs.realpathSync(os.tmpdir());
  const parent = path.dirname(path.resolve(authDir));
  fs.mkdirSync(parent, { recursive: true });
  const real = path.join(fs.realpathSync(parent), path.basename(authDir));
  if (!real.startsWith(`${tmp}${path.sep}`)) {
    throw new Error(`refusing to enroll a test credential outside the temp directory (${real})`);
  }
  const home = os.userInfo().homedir;
  if (home && real.startsWith(`${fs.realpathSync(home)}${path.sep}`)) {
    throw new Error(`refusing to enroll a test credential under your home directory (${real})`);
  }
  if (fs.existsSync(path.join(real, "factors.json"))) {
    throw new Error(`refusing to replace an existing enrollment (${real})`);
  }
  return real;
}

const b64url = (b) => Buffer.from(b).toString("base64url");
const sha256 = (b) => createHash("sha256").update(b).digest();

function readTrim(f) {
  try {
    return fs.readFileSync(f, "utf8").trim() || null;
  } catch {
    return null;
  }
}

/** Enroll a software ES256 credential in a throwaway sandbox's auth dir (<appStateDir>/auth). */
export function enrollDemoCredential(authDirIn) {
  const authDir = assertThrowaway(authDirIn);
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  // COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
  const cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), x, Buffer.from([0x22, 0x58, 0x20]), y]);
  const aaguid = "00000000-0000-0000-0000-00000000de30";
  const credential = {
    id: "de300001",
    label: "demo sandbox",
    credentialId: b64url(randomBytes(32)),
    alg: -7,
    publicKeyCose: b64url(cose),
    signCount: 1,
    aaguid,
    attestation: { fmt: "packed", aaguid, certSha256: "0".repeat(64), certSubject: "CN=Enclawed Code demo sandbox credential", certIssuer: "CN=Enclawed Code demo", allowedAs: null },
    enrolledAt: Date.now(),
    lastUsedAt: null,
  };
  fs.mkdirSync(authDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(authDir, "factors.json"), JSON.stringify({ v: 1, rpId: RP_ID, credentials: [credential], failures: 0, lockedUntil: null }), { mode: 0o600 });
  return { authDir, privateKey, credential };
}

/** Sign a one-use, ten-minute unlock ticket for the sandbox's next launch. */
export function signDemoTicket(cred, { uses = 1, minutes = 10, now = Date.now(), body: overrides = {} } = {}) {
  const mono = process.hrtime.bigint();
  const body = {
    v: 2,
    rpId: RP_ID,
    scope: "session-start",
    nonce: randomBytes(16).toString("hex"),
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    hostname: os.hostname(),
    machineId: readTrim("/etc/machine-id") ?? readTrim("/var/lib/dbus/machine-id"),
    bootId: readTrim("/proc/sys/kernel/random/boot_id"),
    issuedAt: now,
    expiresAt: now + minutes * 60_000,
    issuedAtMono: mono.toString(),
    expiresAtMono: (mono + BigInt(minutes) * 60_000_000_000n).toString(),
    uses,
    credential: cred.credential.id,
    credentialId: cred.credential.credentialId,
    ...overrides,
  };
  const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: b64url(sha256(JSON.stringify(body))), origin: `enclawed-cli://${RP_ID}`, crossOrigin: false }));
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1);
  // UP | UV
  const authData = Buffer.concat([sha256(RP_ID), Buffer.from([0x05]), counter]);
  const signature = sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), cred.privateKey);
  fs.rmSync(path.join(cred.authDir, "unlock-ticket.used"), { force: true });
  fs.writeFileSync(
    path.join(cred.authDir, "unlock-ticket.json"),
    JSON.stringify({ body, clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(signature) }),
    { mode: 0o600 },
  );
  return body;
}
