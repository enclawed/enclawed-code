// Activation: the person at the keyboard proves who they are before
// Enclawed Code starts a session or runs one of its sensitive commands
// (`recover-root`, `recover-anchor`, `audit accept`, policy changes,
// `history restore`, turning off the credential erase).
//
// Two-factor authentication is mandatory, and it is the Enclawed framework's
// own gate (enclawed/framework assertSecondFactor), not a separate
// implementation. The second factor is either
//   - a roaming FIDO2 security key (YubiKey, Titan, ...), through libfido2's
//     tools, or
//   - this computer's DEVICE-BOUND platform passkey (Windows Hello on a TPM,
//     Apple's or Android's secure hardware), through the framework's
//     one-time loopback page in the person's browser,
// with user presence and user verification (PIN, fingerprint, face) on every
// use. This machine keeps only the credential's public key and id. At
// enrollment the framework verifies the attestation against its pinned
// vendor roots (tpm, apple, android-key, or a key's packed statement); a
// synced (backup-eligible) passkey, one without user verification and a
// platform credential without such an attestation are refused. The counter
// must increase on every use, except for a passkey whose enrollment proved a
// non-exportable TPM key (the framework re-verifies that proof each time).
// Every outcome is audited. Enclawed Code only opens the page and keeps the
// prompts; every check is the framework's.
//
// Not accepted, alone or as the second factor: Touch ID or the macOS account
// password unlocking a key kept on this computer, sudo, an Enclawed Code
// passphrase, TOTP, a synced passkey. Their secret (or key) would live on
// this computer or in a vendor cloud, which the deployment assumes is
// already compromised. (An earlier Enclawed Code
// offered an unattested "windows-hello" / "macos" method that unlocked a
// key on this computer; such installs are refused at the next start until a
// security key or a device-bound passkey is enrolled.)
//
// Headless (`-p`, no TTY): a launch is admitted only with an unlock ticket
// from `ecwctl auth unlock`, which the security key or the
// passkey itself signs (the assertion's challenge is the hash of the ticket
// body: uid, host, boot id, expiry, uses). A ticket cannot be forged or
// extended without the authenticator (audit row 17). Sensitive commands
// always need a person and a touch or a verification.
//
// What this does not do: it gates Enclawed Code, not a plain `claude` run with
// valid credentials (managed settings and the credential erase on a hardware
// halt address that). In a software-only install, a process running as this
// user that can rewrite Enclawed Code's protected state dir could replace the
// enrolled public key itself; the enrollment is audited (hash-chained), and
// an Enclaweder moves verification off this host.

import fs from "node:fs";
import path from "node:path";
import { loadFramework } from "./framework.mjs";
import { appStateDir } from "./paths.mjs";
import { say as sayLine } from "./program.mjs";

/**
 * The relying party id Enclawed Code's credentials are created for. It keeps
 * the pre-rename name on purpose: a FIDO2 credential is bound to its RP id,
 * so changing it would invalidate every enrolled security key.
 */
export const RP_ID = "enclawde.local";
export const METHODS = ["fido2", "passkey"];
/** Methods an earlier release accepted; an auth.json naming one is refused with migration steps. */
export const RETIRED_METHODS = ["windows-hello", "macos", "sudo", "passphrase"];

export class AuthError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.name = "AuthError";
  }
}

/** The framework's auth state dir for ecwcode: <app state dir>/auth. */
export function authDir(env = process.env) {
  return path.join(appStateDir(env), "auth");
}

export function authFile(env = process.env) {
  return path.join(authDir(env), "factors.json");
}

export function ticketFile(env = process.env) {
  return path.join(authDir(env), "unlock-ticket.json");
}

/** The pre-FIDO2 activation state file (read only, for migration messages). */
export function legacyAuthFile(env = process.env) {
  return path.join(appStateDir(env), "auth.json");
}

export const ENROLL_STEPS = [
  "Enclawed Code requires two-factor authentication: this computer's device-bound passkey, or a FIDO2 security key with a PIN.",
  "This computer's passkey (Windows Hello on a TPM, or Apple's or Android's secure hardware; a synced passkey is refused):",
  "  ecwctl auth enroll",
  "  (a page opens in your browser; confirm with your PIN, fingerprint or face)",
  "Then enroll a backup: this account's passkey on another device you sign in from, or a security key.",
  "Or a FIDO2 security key (for example a YubiKey 5 or a Google Titan key):",
  "  1. install libfido2's tools (Debian/Ubuntu: sudo apt install fido2-tools; macOS: brew install libfido2)",
  "  2. set a PIN on the key if it has none: fido2-token -S <device from fido2-token -L>",
  "  3. ecwctl auth enroll --security-key --label primary",
].join("\n");

/**
 * What is enrolled, read straight from the framework's store (no framework
 * load, display only: the framework validates the store when it checks):
 * `{ method: "fido2" | "passkey" | "fido2+passkey", keys: N, securityKeys,
 * passkeys }`, or null when nothing is.
 */
export function readAuthState(env = process.env) {
  try {
    const s = JSON.parse(fs.readFileSync(authFile(env), "utf8"));
    const creds = Array.isArray(s?.credentials) ? s.credentials : [];
    const passkeys = creds.filter((c) => c?.kind === "passkey").length;
    const securityKeys = creds.length - passkeys;
    if (creds.length === 0) {
      return null;
    }
    const method = securityKeys && passkeys ? "fido2+passkey" : passkeys ? "passkey" : "fido2";
    return { method, keys: creds.length, securityKeys, passkeys, failures: s.failures ?? 0, lockedUntil: s.lockedUntil ?? null };
  } catch {
    return null;
  }
}

/** A pre-FIDO2 method this install was set up with, if any (for migration messages). */
export function legacyMethod(env = process.env) {
  try {
    const m = JSON.parse(fs.readFileSync(legacyAuthFile(env), "utf8"))?.method;
    return RETIRED_METHODS.includes(m) ? m : null;
  } catch {
    return null;
  }
}

/** The unlock ticket's signed body, for display only (validity is the framework's call). */
export function validTicket(env = process.env, now = Date.now()) {
  try {
    const t = JSON.parse(fs.readFileSync(ticketFile(env), "utf8"));
    return t?.body && now < t.body.expiresAt ? t.body : null;
  } catch {
    return null;
  }
}

/** Two-factor authentication is mandatory: every launch and sensitive command needs it. */
export function authRequired() {
  return true;
}

// Enclawed Code's purposes, mapped onto the framework's closed purpose set.
const PURPOSES = {
  launch: "session-start",
  "history-restore": "history-restore",
  "audit-accept": "recovery",
  "recover-root": "recovery",
  "recover-anchor": "recovery",
  "policy-change": "policy-change",
  "policy-use": "policy-change",
  // Turning on the evaluation-only review judge (review.mjs): it sends call text to a model.
  "review-enable": "policy-change",
  "policy-erase-off": "disable-protection",
  "auth-change": "auth-change",
  test: "auth-test",
  unlock: "unlock",
};

/** A libfido2 transport that lists no security key (frameworkAuthContext: the passkey first). */
const NO_KEY_TRANSPORT = Object.freeze({
  listDevices: () => [],
  deviceInfo: () => {
    throw new Error("no security key is used while a passkey is enrolled");
  },
});

/**
 * The framework's lines, phrased as what the person does (the passkey page is
 * opened in the browser where possible; its address stays as the fallback).
 */
export function authLine(line) {
  let m = /^Your browser opens a page for the passkey\. If it did not, open: (\S+)$/.exec(line);
  if (m) {
    return `confirm with your passkey: a page opened in your browser (if it didn't, open ${m[1]})`;
  }
  m = /^Open this page in your browser to use your passkey: (\S+)$/.exec(line);
  if (m) {
    return `confirm with your passkey: open ${m[1]} in your browser`;
  }
  return line;
}

/**
 * The framework context Enclawed Code verifies with: its own state dir, RP id
 * and audit log. A passkey is asked through the framework's own loopback
 * ceremony (it opens the page and prints its URL); `passkey` replaces that
 * ceremony only for the test doubles and the conformance stand-in, which
 * answer in the browser's wire format so every check is still the
 * framework's.
 */
export function frameworkAuthContext({ env = process.env, audit, interactive, say, passkey, preferPasskey = false } = {}) {
  // Verification without an Enclaweder: the enrolled passkey first; a security key only when no
  // passkey is enrolled. The framework tries a plugged-in key first, so with a passkey enrolled
  // it is shown no key to try (its libfido2 transport lists none).
  const passkeyFirst = preferPasskey && (readAuthState(env)?.passkeys ?? 0) > 0;
  return {
    env,
    stateDir: appStateDir(env),
    rpId: RP_ID,
    interactive,
    ...(passkey ? { passkey } : {}),
    ...(passkeyFirst ? { transport: NO_KEY_TRANSPORT } : {}),
    say: say ?? ((line) => sayLine(process.stderr, authLine(line))),
    audit: async (e) => {
      const type = e.type === "auth.second-factor" ? "claude-code.auth.attempt" : `claude-code.${e.type}`;
      await audit({ type, actor: "enclawed-code", level: null, payload: e.payload });
    },
  };
}

/**
 * The context the launcher hands the kit's activation (kit.activateSession):
 * Enclawed Code's state dir, RP id and audit log, and, at a terminal, the
 * prompt that reads a device-verified code. Throws AuthError for the retired
 * --passphrase-fd flag (audited), which is no factor at all.
 */
export async function launchAuthContext({ env = process.env, interactive, passphraseFd = null, audit, readCode, passkey }) {
  if (passphraseFd !== null && passphraseFd !== undefined) {
    await audit({ type: "claude-code.auth.attempt", actor: "enclawed-code", level: null, payload: { purpose: "session-start", requested: "launch", outcome: "refused", code: "passphrase-retired" } });
    throw new AuthError(
      "passphrase-retired",
      "--passphrase-fd is no longer accepted: a passphrase is not a second factor. For a headless launch, a person issues an unlock ticket first: ecwctl auth unlock",
    );
  }
  return { ...frameworkAuthContext({ env, audit, interactive, passkey, preferPasskey: true }), ...(interactive && readCode ? { readCode } : {}) };
}

/** The kit's activation refusal in Enclawed Code's words (the enrollment steps when nothing is enrolled). */
export function launchAuthMessage(err, env = process.env) {
  if (err?.code === "not-enrolled" || err?.code === "not-configured") {
    const legacy = legacyMethod(env);
    return `${legacy ? `this install was set up with "${legacy}", which no longer satisfies two-factor authentication. ` : ""}${ENROLL_STEPS}`;
  }
  return err?.message ?? String(err);
}

export function toAuthError(err) {
  if (err instanceof AuthError) {
    return err;
  }
  return new AuthError(err?.code ?? "error", err?.message ?? String(err));
}

/**
 * Verify the person. Throws AuthError when refused.
 *
 * @param {{ purpose: string, env?: object, interactive: boolean, passphraseFd?: string|null,
 *           audit: (record: object) => Promise<unknown>, allowTicket?: boolean, fw?: object,
 *           passkey?: Function }} o (passkey: test doubles and the conformance stand-in only)
 */
export async function verifyUser(o) {
  const env = o.env ?? process.env;
  const purpose = PURPOSES[o.purpose];
  // Every refusal is audited (never a secret), including the ones that
  // happen before the framework's gate runs; an audit that cannot be
  // written refuses too (the audit call's rejection propagates).
  const refused = async (code, extra = {}) =>
    o.audit({ type: "claude-code.auth.attempt", actor: "enclawed-code", level: null, payload: { purpose: purpose ?? null, requested: o.purpose, outcome: "refused", code, ...extra } });
  if (!purpose) {
    await refused("bad-purpose");
    throw new AuthError("bad-purpose", `unknown activation purpose ${o.purpose}`);
  }
  if (o.passphraseFd !== null && o.passphraseFd !== undefined) {
    await refused("passphrase-retired");
    throw new AuthError(
      "passphrase-retired",
      "--passphrase-fd is no longer accepted: a passphrase is not a second factor. For a headless launch, a person issues an unlock ticket first: ecwctl auth unlock",
    );
  }
  let fw;
  try {
    fw = o.fw ?? (await (o.loadFramework ?? loadFramework)()).fw;
  } catch (err) {
    await refused("framework-unavailable");
    throw new AuthError("framework-unavailable", `the Enclawed framework could not be loaded, so nothing can be verified: ${err?.message ?? err}`);
  }
  if (typeof fw?.assertSecondFactor !== "function") {
    await refused("framework-unavailable");
    throw new AuthError("framework-unavailable", "the built Enclawed framework has no two-factor gate; rebuild it (npm run build:framework)");
  }
  // One factor per verification (device-activation.mjs): with an Enclaweder attached, only the
  // code it verifies; an attached device that cannot check one refuses (never the passkey instead).
  // `o.device`: a caller's own seam (it holds the device), false: the caller knows none is attached.
  const { deviceFactorProblem, deviceOnlyContext, withAttachedDevice } = await import("./device-activation.mjs");
  const viaDevice = async (seam) => {
    const problem = await deviceFactorProblem(seam);
    if (problem) {
      await refused("device-factor-unavailable");
      throw new AuthError("device-factor-unavailable", `${problem}. With an Enclaweder attached its authenticator code is the only factor, so your passkey or security key is not asked instead; nothing was done`);
    }
    if (!o.interactive) {
      await refused("headless");
      throw new AuthError("headless", `${o.purpose} needs a person at a terminal with the Enclaweder's authenticator`);
    }
    try {
      const ctx = deviceOnlyContext(frameworkAuthContext({ env, audit: o.audit, interactive: true, say: o.say }), seam, env);
      const r = await fw.assertSecondFactor({ ...ctx, ...(o.readCode ? { readCode: o.readCode } : {}) }, { purpose, detail: o.purpose, allowTicket: false });
      return { method: "device", via: r.via };
    } catch (err) {
      throw toAuthError(err);
    }
  };
  if (o.device) {
    return viaDevice(o.device);
  }
  if (o.device !== false) {
    const d = await withAttachedDevice(fw, (seam) => viaDevice(seam));
    if (d) {
      return d;
    }
  }
  if (!readAuthState(env)) {
    const legacy = legacyMethod(env);
    const prefix = legacy ? `this install was set up with "${legacy}", which no longer satisfies two-factor authentication. ` : "";
    await refused("not-enrolled", legacy ? { legacy } : {});
    throw new AuthError("not-configured", `${prefix}${ENROLL_STEPS}`);
  }
  try {
    const r = await fw.assertSecondFactor(frameworkAuthContext({ env, audit: o.audit, interactive: o.interactive, say: o.say, passkey: o.passkey, preferPasskey: true }), {
      purpose,
      detail: o.purpose,
      allowTicket: o.allowTicket,
    });
    return { method: r.via === "passkey" ? "passkey" : "fido2", via: r.via };
  } catch (err) {
    throw toAuthError(err);
  }
}
