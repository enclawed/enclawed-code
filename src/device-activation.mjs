// Device-verified activation (compromised-host attack 7, with an Enclaweder).
//
// Activation (a FIDO2 or passkey assertion, or the unlock ticket it signed for headless
// starts) is verified on this host, against the factor store on this host. A
// same-user process that rewrites that store can enroll its own credential
// and sign its own ticket, and relaunch without the person (attack 7,
// "own-credential"). With an Enclaweder bound, activation therefore also needs
// a factor this host cannot produce. Every check is the kit's
// (enclawed-oss adapter/session.ts):
//
//   interactive launch   the person types an authenticator code the DEVICE
//                        verifies (kit.deviceActivation over
//                        kit.deviceSecondFactor: a verdict signed by the
//                        device over a fresh nonce, for "session-start").
//   headless launch      one use of a device unlock (kit.spendDeviceUnlock),
//                        COUNTED BY THE DEVICE: `ecwctl auth
//                        unlock` issues it once at a terminal with a code the
//                        device verified (kit.issueDeviceUnlock); the device
//                        keeps the grant, its uses and its lease, and signs a
//                        receipt per use over a nonce this host chose. The
//                        record kept here only names the grant: editing it
//                        gains nothing.
//
// What stays here: the framework seam (deviceTotpSeam), where the grant record
// is stored, and the prompt. With a framework that lacks the device calls (or
// no device bound), device activation is "unavailable" and the launcher says
// so; nothing is faked on this host.

import { createPrivateKey, generateKeyPairSync, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { writeFileAtomic } from "./cli-util.mjs";
import { kit } from "./kit.mjs";
import { appStateDir } from "./paths.mjs";

/** The unlock scope's host id (kit.unlockScope): a grant made for another program does not unlock this one. */
export const UNLOCK_HOST = "claude-code";
export const GRANT_MAX_MINUTES = 36 * 60;
export const GRANT_MAX_USES = 65535; // the device's own maximum: the unsigned 16-bit use count

export function grantFile(env = process.env) {
  return path.join(appStateDir(env), "device-unlock.json");
}

/**
 * The framework's device seam in the kit's shape (DeviceTotpSeam), or null
 * when this build has no device-verified TOTP. `unlock` (device-counted
 * unlocks) only when the framework has those calls too.
 */
export function deviceTotpSeam(fw) {
  const need = ["hardwareRootTotpDevice", "deviceTotpEnrolled", "deviceTotpVerdict", "verifyVerdictRecord"];
  if (!fw || need.some((k) => typeof fw[k] !== "function")) {
    return null;
  }
  const hasUnlock = ["grantUnlock", "spendUnlock", "verifyUnlockReceipt"].every((k) => typeof fw[k] === "function");
  return {
    access: () => fw.hardwareRootTotpDevice(),
    enrolled: (a) => fw.deviceTotpEnrolled(a),
    verdict: (a, p) => fw.deviceTotpVerdict(a, p),
    verifyRecord: (rec, e) => fw.verifyVerdictRecord(rec, e),
    ...(hasUnlock ? { unlock: { grant: fw.grantUnlock, spend: fw.spendUnlock, verifyReceipt: fw.verifyUnlockReceipt } } : {}),
  };
}

/**
 * Enclaweder firmware 0.3.4 (command set 0.6) answers a code check whose host time disagrees
 * with the device's own tick with ERR_TIME (10); enclawed 2.0.1 maps it to "clock-disagrees".
 * The code may be right: the clocks are not. Never advise unplugging while a prompt holds the device.
 */
export const CLOCK_DISAGREES_TEXT =
  "the Enclaweder's clock and this computer's disagree: check this computer's time, or cancel this prompt (Ctrl-C), unplug and replug the Enclaweder, then try again with a new code";

/** The person's words for a device code refusal `code` (the framework's text otherwise). */
export function deviceCodeText(code, fallback = null) {
  if (code === "clock-disagrees" || code === 10 || code === "ERR_TIME") {
    return CLOCK_DISAGREES_TEXT;
  }
  return fallback ?? `the Enclaweder did not verify an authenticator code (${code})`;
}

class DeviceActivationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function readGrant(env) {
  try {
    return JSON.parse(fs.readFileSync(grantFile(env), "utf8"));
  } catch {
    return null;
  }
}

/**
 * The kit's activation options for one launch (kit.activateSession): the
 * device seam and the stored unlock record when the launcher holds an
 * Enclaweder (`held`), none otherwise. What the device must verify, and that
 * a held device that cannot be asked refuses the launch (`bound`), are the
 * kit's.
 */
export function activationOptions({ fw, env = process.env, held, interactive, job = null }) {
  if (!held) {
    return { detail: "launch", device: null, host: UNLOCK_HOST };
  }
  const unlock = interactive ? null : readGrant(env);
  // The job of THIS launch (commitments.mjs launchJob), under the name the
  // stored unlock gives: the device refuses it unless it is the unlock's job.
  const thisJob = unlock?.job && job ? job(unlock.job.name) : null;
  return { detail: "launch", device: deviceTotpSeam(fw), bound: true, host: UNLOCK_HOST, unlock, job: thisJob };
}

/** Device unlocks are bound to the unlock ticket and its credential (and, beyond one launch, to a job). */
export const GRANT_TICKET_BINDING = true;

/** The binding of a ticket: a parsed unlock-ticket.json ({ body, ... }) or a ticket body. */
export function ticketBindingOf(ticket) {
  const body = ticket?.body ?? ticket;
  if (!body || typeof body !== "object" || typeof body.credentialId !== "string") {
    throw new DeviceActivationError("no-ticket", "a device unlock is bound to an unlock ticket, and none was given");
  }
  return kit.unlockTicketBinding(body);
}

/**
 * Activation for one launch, while the launcher holds an Enclaweder.
 * Resolves { mode: "unavailable" | "verified", via? } or throws (the launch is
 * refused). The person's own two factors (FIDO2 or a passkey, or the unlock ticket) were
 * checked by the caller before this.
 */
export async function deviceActivation({ seam, interactive, readCode, env = process.env, audit = async () => {}, ticket = null, job = null }) {
  if (!seam) {
    return { mode: "unavailable", reason: "this framework build exposes no device-verified TOTP" };
  }
  // The launcher holds a bound Enclaweder: one that cannot be asked now
  // refuses the launch (the kit takes an absent device as "no device bound").
  if (!seam.access()) {
    throw new DeviceActivationError("no-device", "the bound Enclaweder cannot verify an authenticator code here (it is not CLEAN, or another process owns it); not starting");
  }
  const ctx = { readCode, audit: (e) => audit(e.payload), deviceFactor: kit.deviceSecondFactor(seam) };
  // What the caller's gate passed: an authenticator at a terminal (the kit
  // treats a security key and a passkey alike here), the unlock ticket headless.
  const gate = { via: interactive ? "fido2" : "ticket", credential: null, ...(!interactive && ticket ? { ticket: ticketBindingOf(ticket) } : {}) };
  try {
    const r = await kit.deviceActivation(gate, ctx, { seam, host: UNLOCK_HOST, unlock: interactive ? null : readGrant(env), job });
    return { mode: "verified", via: r.device };
  } catch (err) {
    const msg = err?.message ?? String(err);
    const text = err?.code === "clock-disagrees" ? CLOCK_DISAGREES_TEXT : msg;
    throw new DeviceActivationError(err?.code ?? "rejected", interactive ? text : `${text} (run: ecwctl auth unlock)`);
  }
}

/** `auth unlock` with an Enclaweder: the device issues and keeps an unlock (kit.issueDeviceUnlock); the record naming it is stored here. */
export async function issueGrant({ seam, readCode, minutes, uses, env = process.env, ticket, job = null, k = kit }) {
  if (!seam?.access()) {
    throw new DeviceActivationError("no-device", "no bound, CLEAN Enclaweder can verify the code");
  }
  // The grant is spendable only with this ticket (signed by the person's
  // credential) and, beyond one launch or ten minutes, only for `job`.
  const binding = ticketBindingOf(ticket);
  const code = String(await readCode("Authenticator code (checked by the Enclaweder): ")).trim();
  const m = Math.min(Math.max(1, minutes ?? 10), GRANT_MAX_MINUTES);
  const r = await k.issueDeviceUnlock({ host: UNLOCK_HOST, ticket: binding, job, code, uses: Math.min(Math.max(1, uses ?? 1), GRANT_MAX_USES), leaseS: m * 60, device: seam });
  if (!r.ok) {
    throw new DeviceActivationError(r.code, r.code === "clock-disagrees" ? CLOCK_DISAGREES_TEXT : r.message);
  }
  fs.mkdirSync(path.dirname(grantFile(env)), { recursive: true, mode: 0o700 });
  writeFileAtomic(grantFile(env), `${JSON.stringify(r.grant)}\n`);
  return { minutes: Math.round(r.grant.leaseMs / 60_000), uses: r.grant.uses };
}

/** Forget the stored unlock record (the device ends the grant when its lease or uses run out, or it restarts). */
export function revokeGrant(env = process.env) {
  const had = fs.existsSync(grantFile(env));
  fs.rmSync(grantFile(env), { force: true });
  return had;
}

export { DeviceActivationError };

// ------------------------------------------------------------------ one factor per verification
//
// Never two factors in one verification (the person's decision, 2026-11-24):
//   - an Enclaweder attached (held): ONLY the authenticator code the device verifies
//     (its signed verdict is the factor); no passkey or security-key prompt;
//   - no Enclaweder: ONLY the enrolled passkey or security key, verified on this host.
// Where the device's own rules ask for more (the latch clear's code plus a one-time
// recovery code) that is the device's rule, kept. An attached device whose code check
// cannot run refuses: nothing falls back to the passkey.
//
// The framework's gate is run over a factor store of its own for the device's code
// (<state>/device-factor/auth): it holds no passkey or key, so the gate asks only the
// device, with its own lock and backoff. A headless start spends a device-counted
// unlock bound to a ticket signed in that store at `auth unlock` by a key this
// installation made for it (not a factor: the device's grant is).

/** The state root of the device-code factor store. */
export function deviceAuthRoot(env = process.env) {
  return path.join(appStateDir(env), "device-factor");
}

/** Why the attached device cannot be the factor now, or null. */
export async function deviceFactorProblem(seam) {
  if (!seam) {
    return "this Enclawed framework build cannot ask the Enclaweder to check an authenticator code";
  }
  if (!seam.access()) {
    return "the attached Enclaweder cannot check an authenticator code here (it is not CLEAN, or another process owns it)";
  }
  const factor = kit.deviceSecondFactor(seam);
  if (!factor || !(await factor.enrolled().catch(() => false))) {
    return "the attached Enclaweder has no authenticator enrolled (enroll it on the device first)";
  }
  return null;
}

/** The refusal when an attached device cannot be the factor: said, never a silent passkey. */
export function deviceFactorRefusal(problem) {
  return new DeviceActivationError("device-factor-unavailable", `${problem}. With an Enclaweder attached its authenticator code is the only factor, so your passkey or security key is not asked instead; nothing was done`);
}

const NO_KEY_TRANSPORT = Object.freeze({ listDevices: () => [] });

/** The framework context for the device's code alone (no passkey, no key). */
export function deviceOnlyContext(ctx, seam, env = process.env) {
  const { passkey: _p, transport: _t, ...rest } = ctx;
  return { ...rest, stateDir: deviceAuthRoot(env), deviceFactor: kit.deviceSecondFactor(seam), transport: NO_KEY_TRANSPORT };
}

/**
 * A launch's activation under the one-factor rule (kit.activateSession):
 * `held` (an Enclaweder attached and held): the device's code at a terminal, or a
 * device-counted unlock headless; otherwise the host's passkey or key (or its ticket).
 */
export async function activateLaunch(ctx, { fw, env = process.env, held, interactive, job = null, detail = "launch", allowTicket = true }) {
  if (!held) {
    return kit.activateSession(ctx, { ...activationOptions({ fw, env, held: false, interactive }), detail, allowTicket });
  }
  const seam = deviceTotpSeam(fw);
  const problem = await deviceFactorProblem(seam);
  if (problem) {
    throw deviceFactorRefusal(problem);
  }
  return kit.activateSession(deviceOnlyContext(ctx, seam, env), { ...activationOptions({ fw, env, held: true, interactive, job }), detail, allowTicket });
}

const SIGNER_KEY = "ticket-signer.pem";

/**
 * The key this installation signs device-unlock tickets with (in the device-code factor
 * store, made on first use). Not a factor: with an Enclaweder the device's counted grant,
 * issued after the code it verified, is what starts a headless launch, and the grant is
 * bound to this ticket. Any process of the user could read this key, exactly as it could
 * enroll its own credential (attack 7): it gains nothing without the device's grant.
 */
export async function deviceTicketSigner(env = process.env) {
  const { RP_ID } = await import("./auth.mjs");
  const authDir = path.join(deviceAuthRoot(env), "auth");
  const factors = path.join(authDir, "factors.json");
  const keyFile = path.join(authDir, SIGNER_KEY);
  try {
    const store = JSON.parse(fs.readFileSync(factors, "utf8"));
    const credential = store.credentials?.find((c) => c.id === "ec0d0001");
    if (credential && fs.existsSync(keyFile)) {
      return { authDir, credential, privateKey: createPrivateKey(fs.readFileSync(keyFile, "utf8")) };
    }
  } catch {
    /* made below */
  }
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), Buffer.from(jwk.x, "base64url"), Buffer.from([0x22, 0x58, 0x20]), Buffer.from(jwk.y, "base64url")]);
  const aaguid = "00000000-0000-0000-0000-0000000ec0d0";
  const credential = {
    id: "ec0d0001",
    label: "device-unlock ticket signer (not a factor)",
    credentialId: randomBytes(32).toString("base64url"),
    alg: -7,
    publicKeyCose: cose.toString("base64url"),
    signCount: 1,
    aaguid,
    attestation: { fmt: "packed", aaguid, certSha256: "0".repeat(64), certSubject: "CN=Enclawed Code device-unlock ticket signer", certIssuer: "CN=Enclawed Code", allowedAs: null },
    enrolledAt: Date.now(),
    lastUsedAt: null,
  };
  fs.mkdirSync(authDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  writeFileAtomic(factors, JSON.stringify({ v: 1, rpId: RP_ID, credentials: [credential], failures: 0, lockedUntil: null }), { mode: 0o600 });
  return { authDir, credential, privateKey };
}

/**
 * `auth unlock` with an Enclaweder attached: one factor, the code the device verifies. The
 * ticket is signed by deviceTicketSigner (no prompt), then the device issues its counted grant
 * bound to it after the code; a refused code leaves no usable ticket.
 */
export async function deviceOnlyUnlock({ seam, readCode, minutes = 10, uses = 1, env = process.env, job = null }) {
  const problem = await deviceFactorProblem(seam);
  if (problem) {
    throw deviceFactorRefusal(problem);
  }
  const { signDemoTicket } = await import("./demo-credential.mjs");
  const signer = await deviceTicketSigner(env);
  const body = signDemoTicket(signer, { uses, minutes });
  try {
    const g = await issueGrant({ seam, readCode, minutes, uses, env, ticket: body, job });
    return { ticket: body, grant: g };
  } catch (err) {
    fs.rmSync(path.join(signer.authDir, "unlock-ticket.json"), { force: true });
    throw err;
  }
}

/**
 * Run `fn(seam)` when an Enclaweder is attached (booted here and answering), and return its
 * result; null when none is attached. An attached device whose code check cannot run refuses
 * (device-activation.mjs deviceFactorProblem): never a silent fall back to the passkey.
 */
export async function withAttachedDevice(f, fn) {
  let booted = false;
  try {
    await f.bootHardwareRoot();
    booted = true;
  } catch {
    /* no device */
  }
  try {
    // Attached: the framework bound a device (hardwareRootInfo anchored), healthy or not.
    const info = booted && typeof f.hardwareRootInfo === "function" ? f.hardwareRootInfo() : null;
    const seam = deviceTotpSeam(f);
    const attached = Boolean(seam?.access()) || info?.anchored === true;
    if (!attached) {
      return null;
    }
    return await fn(seam);
  } finally {
    try {
      f.closeHardwareRootSession();
    } catch {
      /* nothing to close */
    }
  }
}

