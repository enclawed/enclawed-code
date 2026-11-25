// `ecwctl auth enroll|set|status|test|unlock|lock|remove` and
// `ecwctl recover-root` / `recover-anchor`.
//
// The second factor is the framework's gate (see auth.mjs): a FIDO2 security
// key or this computer's device-bound passkey. Enclawed Code keeps the prompts
// and messages, the framework does every check (the passkey page is the
// framework's own loopback ceremony).

import fs from "node:fs";
import path from "node:path";
import { AuthError, ENROLL_STEPS, METHODS, RETIRED_METHODS, frameworkAuthContext, legacyMethod, readAuthState, toAuthError, verifyUser } from "./auth.mjs";
import { UsageError, ask, isInteractive, parseFlags, positiveInt } from "./cli-util.mjs";
import { loadFramework } from "./framework.mjs";
import { LAUNCH_KINDS, currentEffectivePolicy, launchJob, measureLaunch } from "./commitments.mjs";
import { deviceAuthRoot, deviceOnlyUnlock, deviceTotpSeam, revokeGrant, withAttachedDevice } from "./device-activation.mjs";
import { offlineSigners, operatorAuthorization } from "./operator-keys.mjs";
import { hardwareLatchPaths } from "./paths.mjs";
import { userNamespaceDeviceRisk } from "./userns.mjs";

export const AUTH_HELP = `usage:
  ecwctl auth enroll [--label NAME]                     register this computer's device-bound passkey (Windows Hello on a TPM,
                                                         Apple's or Android's secure hardware) through a page in your browser (--passkey: the same)
  ecwctl auth enroll --security-key [--label NAME] [--alg es256|eddsa]
                                                         register a FIDO2 security key instead (PIN or on-key biometric; needs libfido2's tools)
  ecwctl auth status [--json]
  ecwctl auth test                            one full check (touch + PIN, or the passkey's verification), audited
  ecwctl auth unlock [--minutes N] [--uses N] [--job NAME [--project DIR] [--kind headless:print|headless]]
                                                         a ticket, signed by your key or passkey, for headless launches (default 10 minutes, 1 use).
                                                         With an Enclaweder, more than 1 use or 10 minutes delegates ONE job: launches of
                                                         this Enclawed Code, under this policy, in this project, of this kind (--job names it)
  ecwctl auth lock                            revoke the unlock ticket now
  ecwctl auth remove ID                       unenroll a key or passkey (the last one cannot be removed)
Two-factor authentication is mandatory; the accepted factors are a FIDO2 security key and a device-bound passkey, never a synced one (methods: ${METHODS.join(", ")}).
`;

/** The two explicit enrollment commands, for messages. */
export const ENROLL_CHOICES = "ecwctl auth enroll (this computer's device-bound passkey: Windows Hello, Apple or Android), or ecwctl auth enroll --security-key (a FIDO2 security key with a PIN)";

/**
 * @param {string[]} args after "auth"
 * @param {{ out, err, env, audit, options, fw? }} ctx
 */
export async function authCommand(args, { out, err, env, audit, options, fw: fwIn, readLine = null, interactive: interactiveIn, passkey }) {
  const sub = args[0];
  const rest = args.slice(1);
  const fw = async () => fwIn ?? (await loadFramework()).fw;
  // `interactive` and `passkey` replace the terminal check and the browser
  // ceremony for the test doubles only; the framework decides either way.
  const interactive = () => interactiveIn ?? isInteractive();
  const context = () => frameworkAuthContext({ env, audit, interactive: interactive(), passkey });
  // Verifying (not enrolling): the enrolled passkey first.
  const verifyContext = () => frameworkAuthContext({ env, audit, interactive: interactive(), passkey, preferPasskey: true });
  try {
    switch (sub) {
      case "status": {
        const { flags } = parseFlags(rest, { bool: ["--json"], maxPositionals: 0 });
        const s = await (await fw()).secondFactorStatus(context());
        const legacy = legacyMethod(env);
        if (flags["--json"]) {
          out.write(`${JSON.stringify({ ...s, configured: s.credentials.length > 0, legacyMethod: legacy }, null, 2)}\n`);
          return 0;
        }
        const passkeys = s.credentials.filter((c) => c.kind === "passkey").length;
        out.write(`activation auth (two-factor, mandatory): ${s.credentials.length - passkeys} security key(s) and ${passkeys} device-bound passkey(s) enrolled\n`);
        for (const c of s.credentials) {
          const counter = c.counterPolicy === "tpm-non-exportable" ? `counter ${c.signCount} (TPM key, non-exportable)` : `counter ${c.signCount}`;
          out.write(`  ${c.id}  ${c.label}  ${c.kind === "passkey" ? `passkey (${c.attestation.fmt})` : "security key"}  ${counter}  ${c.attestation.certSubject}\n`);
        }
        out.write(`  unlock ticket: ${s.ticket ? `${s.ticket.valid ? "valid" : "not valid here"} until ${new Date(s.ticket.expiresAt).toLocaleTimeString()}, ${s.ticket.usesLeft} use(s) left` : "none"}\n`);
        if (s.failures) {
          out.write(`  consecutive failures: ${s.failures}${s.lockedUntil ? `, locked until ${new Date(s.lockedUntil).toLocaleTimeString()}` : ""}\n`);
        }
        if (legacy && s.credentials.length === 0) {
          out.write(`  note: this install was set up with "${legacy}", which no longer satisfies two-factor authentication\n`);
        }
        for (const w of s.warnings) {
          out.write(`  warning: ${w}\n`);
        }
        return 0;
      }
      case "test": {
        parseFlags(rest, { maxPositionals: 0 });
        await verifyUser({ purpose: "test", env, interactive: interactive(), audit, allowTicket: false, passkey });
        out.write("verified\n");
        return 0;
      }
      case "unlock": {
        const { flags } = parseFlags(rest, { value: ["--minutes", "--uses", "--passphrase-fd", "--job", "--project", "--kind"], maxPositionals: 0 });
        if (flags["--passphrase-fd"] !== undefined) {
          throw new AuthError("passphrase-retired", "--passphrase-fd is no longer accepted; unlock with your security key or passkey at a terminal");
        }
        if (!interactive()) {
          throw new AuthError("headless", "unlock needs a person at the terminal with the security key or passkey");
        }
        const minutes = flags["--minutes"] !== undefined ? positiveInt(flags["--minutes"], "--minutes") : options?.auth?.unlockMinutes;
        const uses = flags["--uses"] !== undefined ? positiveInt(flags["--uses"], "--uses") : undefined;
        const f = await fw();
        const jobName = flags["--job"];
        if (jobName !== undefined && !/^[A-Za-z0-9._-]{1,64}$/.test(jobName)) {
          throw new UsageError("--job is a name of letters, digits, . _ - (at most 64)");
        }
        const kind = flags["--kind"] ?? "headless:print";
        if (!LAUNCH_KINDS.includes(kind)) {
          throw new UsageError(`--kind is one of ${LAUNCH_KINDS.join(", ")}`);
        }
        // The job: this Enclawed Code's measured code, the effective policy, the
        // project and the launch kind, under the name the person chose.
        const job = jobName === undefined ? null : launchJob({ name: jobName, measurementDigest: measureLaunch().digest, policyDigest: currentEffectivePolicy(f, env).digest, projectDir: flags["--project"] ?? process.cwd(), kind });
        // One factor: with an Enclaweder attached, only the code it verifies (its counted grant);
        // without one, only your passkey or security key (it signs the ticket).
        const dev = await withAttachedDevice(f, async (seam) => {
          const d = await deviceOnlyUnlock({ seam, readCode: readLine ?? ((q) => ask(q)), minutes: minutes ?? 10, uses: uses ?? 1, env, job });
          out.write(`device unlock: ${d.grant.uses} headless launch(es) for ${d.grant.minutes} min from the code's time, this boot only, counted and signed by the Enclaweder\n`);
          return true;
        });
        if (dev) {
          return 0;
        }
        const t = await f.unlockForHeadlessStart(verifyContext(), { minutes, uses });
        out.write(`unlocked: ${t.usesLeft} headless launch(es) until ${new Date(t.expiresAt).toLocaleTimeString()}, this boot only (ticket signed by your passkey or security key)\n`);
        return 0;
      }
      case "lock": {
        parseFlags(rest, { maxPositionals: 0 });
        revokeGrant(env);
        fs.rmSync(path.join(deviceAuthRoot(env), "auth", "unlock-ticket.json"), { force: true });
        const had = await (await fw()).revokeUnlockTicket(context());
        out.write(had ? "unlock ticket revoked\n" : "no unlock ticket to revoke\n");
        return 0;
      }
      case "remove": {
        const { positionals } = parseFlags(rest, { maxPositionals: 1 });
        if (!positionals[0]) {
          throw new UsageError("auth remove needs the key's or passkey's id (see: ecwctl auth status)");
        }
        const r = await (await fw()).removeSecurityKey(context(), { id: positionals[0] });
        out.write(`removed ${positionals[0]}; ${r.remaining} second factor(s) remain enrolled\n`);
        return 0;
      }
      case "set":
      case "enroll": {
        const { flags } = parseFlags(rest, { value: ["--label", "--alg", "--method", "--passphrase-fd"], bool: ["--passkey", "--security-key", "--fido2"], maxPositionals: 0 });
        const asKey = flags["--security-key"] === true || flags["--fido2"] === true;
        if (flags["--passkey"] && asKey) {
          throw new UsageError("--passkey enrolls a passkey; --security-key a security key: choose one");
        }
        let method = flags["--method"] ?? (asKey ? "fido2" : undefined);
        if (method !== undefined && !METHODS.includes(method) && method !== "auto") {
          throw new UsageError(
            method === "windows-hello"
              ? `the earlier windows-hello method (an unattested key on this computer) is retired. Windows Hello on a TPM is accepted as a device-bound passkey: ecwctl auth enroll --passkey`
              : RETIRED_METHODS.includes(method)
                ? `${method} no longer satisfies two-factor authentication: its secret or key lives on this computer. Enroll a FIDO2 security key or a device-bound passkey instead.\n${ENROLL_STEPS}`
                : `--method takes ${METHODS.join(" or ")}`,
          );
        }
        if (flags["--passphrase-fd"] !== undefined) {
          throw new AuthError("passphrase-retired", "--passphrase-fd is no longer accepted; a passphrase is not a second factor");
        }
        // No method named: this computer's device-bound passkey, the default; a security key only when asked for.
        if (method === undefined || method === "auto") {
          method = "passkey";
        }
        const asPasskey = flags["--passkey"] === true || method === "passkey";
        if (asPasskey && method === "fido2") {
          throw new UsageError("--passkey enrolls a passkey; --method fido2 a security key: choose one");
        }
        if (asPasskey && flags["--alg"] !== undefined) {
          throw new UsageError("--alg applies to security keys; a passkey uses its device's algorithm");
        }
        if (flags["--alg"] !== undefined && flags["--alg"] !== "es256" && flags["--alg"] !== "eddsa") {
          throw new UsageError("--alg takes es256 or eddsa");
        }
        if (!interactive()) {
          throw new AuthError("headless", `enrolling a ${asPasskey ? "passkey" : "security key"} needs a person at the terminal: ${ENROLL_CHOICES}`);
        }
        const before = readAuthState(env);
        if (asPasskey) {
          // The framework's enrollment: it opens its loopback page, verifies
          // the attestation (tpm, apple, android-key or packed), UP, UV and
          // that the passkey is not synced, and audits the outcome.
          if (before) {
            out.write("First confirm with a second factor that is already enrolled.\n");
          }
          out.write("Enrolling this computer's passkey (for a FIDO2 security key instead: ecwctl auth enroll --security-key). A page opens in your browser: create the passkey on this device and confirm it with your PIN, fingerprint or face. A passkey that syncs to a cloud account is refused.\n");
          const r = await (await fw()).enrollPasskey(context(), { label: flags["--label"] ?? "passkey" });
          out.write(`enrolled ${r.credential.label} (id ${r.credential.id}; device-bound passkey, ${r.credential.attestation.fmt} attestation; ${r.credential.attestation.certSubject})\n`);
          if (r.total === 1) {
            out.write("Only one second factor is enrolled. Enroll a backup, since a passkey dies with this device: this account's passkey on another device you sign in from (ecwctl auth enroll there), or a FIDO2 security key here (ecwctl auth enroll --security-key --label backup)\n");
          }
          return 0;
        }
        out.write("Plug in the security key to enroll. Touch it when it blinks, and enter its PIN when asked.\n");
        const r = await (await fw()).enrollSecurityKey(context(), { label: flags["--label"] ?? (before ? "backup" : "primary"), alg: flags["--alg"] });
        out.write(`enrolled ${r.credential.label} (id ${r.credential.id}; ${r.credential.attestation.certSubject})\n`);
        if (r.total === 1) {
          out.write("Only one second factor is enrolled. Enroll a backup: this computer's passkey (ecwctl auth enroll), or a second security key kept somewhere safe (ecwctl auth enroll --security-key --label backup)\n");
        }
        return 0;
      }
      default:
        err.write(AUTH_HELP);
        return 2;
    }
  } catch (e) {
    if (e instanceof UsageError) {
      throw e;
    }
    throw toAuthError(e);
  }
}

/** Latch files the framework keeps (read only: the framework's recovery API is the only writer). */
export function latchCandidates(env = process.env) {
  const { file, dir } = hardwareLatchPaths(env);
  const seen = new Set();
  const out = [];
  const consider = (p) => {
    if (seen.has(p)) {
      return;
    }
    seen.add(p);
    try {
      out.push({ path: p, state: JSON.parse(fs.readFileSync(p, "utf8")) });
    } catch {
      /* unreadable or absent: nothing to recover from */
    }
  };
  consider(file);
  try {
    for (const f of fs.readdirSync(dir)) {
      if (/^\.enclawed-hw-root(\.\d+|\.[0-9a-f]{24})?\.state$/.test(f)) {
        consider(path.join(dir, f));
      }
    }
  } catch {
    /* no directory listing */
  }
  return out;
}

/**
 * Clear a DIRTY latch with the genuine bound device present, the same way the
 * open core's installer does: interactive terminal only, the operator types
 * the serial printed on the device, then the framework's recovery checks the
 * device identity and a fresh challenge-response before it clears anything.
 */
export async function recoverRoot(args, { out, err, env, fw, audit, options, readLine }) {
  // Thin caller of the framework's `enclawed hardware-root recover` (device-held latch, N17/N18):
  // the Enclaweder holds the latch and clears it only with two factors it verifies itself (an
  // authenticator code AND a one-time recovery code) or with the operator quorum. The serial typed
  // back (ENCLW- or ECPRO- with the full 24-hex uid) and the factor prompts happen there.
  void readLine;
  const { flags } = parseFlags(args, { value: ["--passphrase-fd", "--fido", "--operator-offline"], multi: ["--operator-key"], maxPositionals: 0 });
  // Operator keys stay off this host (R5-L): no key file is accepted, and the
  // operator-quorum path refuses while one is found here.
  const opRefusal = await operatorPathRefusal("recover-root", { flags, env, err, audit: (ev) => audit({ type: "claude-code.hardware.recover", actor: "enclawed-code", level: null, payload: ev }) });
  if (opRefusal !== null) {
    return opRefusal;
  }
  const candidates = latchCandidates(env);
  const dirty = candidates.filter((c) => c.state?.status === "DIRTY");
  if (dirty.length === 0 && !isInteractive()) {
    out.write("No DIRTY hardware-root latch to clear on this host. The Enclaweder holds its own latch: run this at a terminal to check and recover the device.\n");
    for (const c of candidates) {
      out.write(`  ${c.path}: ${c.state?.status ?? "unknown"}\n`);
    }
    return 0;
  }
  if (dirty.length > 1) {
    err.write(`ecwctl: more than one DIRTY latch; recover them one at a time:\n${dirty.map((c) => `  ${c.path}`).join("\n")}\n`);
    return 1;
  }
  const nsRiskRoot = userNamespaceDeviceRisk();
  if (nsRiskRoot) {
    err.write(`ecwctl: ${nsRiskRoot}\n`);
    return 1;
  }
  const target = dirty[0] ?? candidates[0];
  if (!isInteractive()) {
    err.write("ecwctl: recovery requires an interactive terminal; run this yourself at a console, with the device plugged in\n");
    await audit({ type: "claude-code.hardware.recover", actor: "enclawed-code", level: null, payload: { statePath: target?.path ?? null, outcome: "refused", code: "no-tty" } });
    return 1;
  }
  if (typeof fw.hardwareRootRecoverCli !== "function") {
    err.write("ecwctl: this framework build predates the device-held latch; rebuild it (npm run build:framework) after the Enclaweder firmware update\n");
    return 1;
  }
  // One factor per verification: the device's own rule decides (the authenticator code and a one-time recovery code it verifies itself, or the operator quorum); no passkey on top.
  if (flags["--passphrase-fd"] !== undefined) {
    throw new AuthError("passphrase-retired", "--passphrase-fd is no longer accepted; a passphrase is not a second factor");
  }
  return fw.hardwareRootRecoverCli({
    statePath: target?.path,
    fido: flags["--fido"],
    operatorOffline: flags["--operator-offline"] ? Number(flags["--operator-offline"]) : undefined,
    audit: (ev) => audit({ type: "claude-code.hardware.recover", actor: "enclawed-code", level: null, payload: { statePath: target?.path ?? null, ...ev } }),
  });
}

/**
 * R5-L: refuse an operator-quorum operation that would rest on a key on this
 * host. Whether it may run is the kit's decision (decideOperatorAuthorization:
 * an --operator-key file is never accepted, and the operator path is refused
 * while an operator private key is found on this host). Null: go on.
 */
async function operatorPathRefusal(command, { flags, env, err, audit }) {
  const keyFiles = flags["--operator-key"] ?? [];
  if (keyFiles.length === 0 && flags["--operator-offline"] === undefined) {
    return null;
  }
  const { policyCandidates } = await import("./session.mjs");
  const policyFiles = policyCandidates(env).map((c) => c.path).filter((p) => fs.existsSync(p));
  const d = operatorAuthorization(command, { env, policyFiles, keyFiles });
  if (d.ok) {
    return null;
  }
  err.write(d.message);
  await audit({ outcome: "refused", code: d.code, keys: keyFiles.length || d.found.length });
  return 1;
}

/** What to do about a BUSY anchor channel without operator keys on this host (round 4, N15). */
export const RECOVER_ANCHOR_PROCEDURE = `The Enclaweder's anchor channel is BUSY: another process holds its one anchor session, or one exited without closing it.
Without operator keys on this machine, recover it like this:
  1. Stop every Enclawed Code session on this machine (and anything else that drives the Enclaweder).
  2. Firmware 0.2 or later: wait for the holder's lease to run out (at most 120 s after its last renewal; the BUSY alarm prints the time left), then start Enclawed Code again.
     Firmware 0.1 (no lease): unplug the Enclaweder and plug it back in; the device ends an anchor session only when it is re-enumerated.
  3. If the channel is BUSY again right away, something on this machine is opening it: investigate before you continue (ecwctl audit verify).
With firmware 0.2 and the operators of the device's quorum (their keys never on this machine), take the channel over at once:
  ecwctl recover-anchor --operator-offline N
  (N operators; each signs the printed message on their own device and pastes the signature)
`;

/**
 * `ecwctl recover-anchor --operator-offline N`: an operator-quorum
 * takeover of the anchor channel (firmware 0.2, PROTOCOL.md "Operator
 * takeover"), gated like recover-root: an interactive terminal, activation
 * auth, and the serial printed on the device typed in. The host-side gates are
 * a convenience, not a control (round 5, R5-L): the device's operator-signature
 * quorum is the control, so no operator key may be on this host. Each operator
 * signs the printed message on their own device and pastes the signature;
 * `--operator-key FILE` is refused, and so is the whole command while an
 * operator private key is found on this host (operator-keys.mjs).
 */
export async function recoverAnchor(args, { out, err, env, fw, audit, options, readLine }) {
  const { flags } = parseFlags(args, { value: ["--passphrase-fd", "--operator-offline"], multi: ["--operator-key"], maxPositionals: 0 });
  const keyFiles = flags["--operator-key"] ?? [];
  if (keyFiles.length === 0 && flags["--operator-offline"] === undefined) {
    out.write(RECOVER_ANCHOR_PROCEDURE);
    return 1;
  }
  const refused = await operatorPathRefusal("recover-anchor", { flags, env, err, audit: (ev) => audit({ type: "claude-code.hardware.anchor-takeover", actor: "enclawed-code", level: null, payload: ev }) });
  if (refused !== null) {
    return refused;
  }
  const count = positiveInt(flags["--operator-offline"], "--operator-offline");
  if (count > 8) {
    throw new UsageError("--operator-offline: at most 8 operators");
  }
  const nsRisk = userNamespaceDeviceRisk();
  if (nsRisk) {
    err.write(`ecwctl: ${nsRisk}\n`);
    return 1;
  }
  if (!isInteractive()) {
    err.write("ecwctl: recover-anchor requires an interactive terminal; run it yourself at a console, with the device plugged in\n");
    await audit({ type: "claude-code.hardware.anchor-takeover", actor: "enclawed-code", level: null, payload: { outcome: "refused", code: "no-tty" } });
    return 1;
  }
  const signers = offlineSigners(count, { out, readLine });
  // One factor per verification: the device's own rule decides (the operator quorum, or the factors it verifies itself); no passkey on top.
  if (flags["--passphrase-fd"] !== undefined) {
    throw new AuthError("passphrase-retired", "--passphrase-fd is no longer accepted; a passphrase is not a second factor");
  }
  const { boundDevice, takeoverAnchor } = await import("./device.mjs");
  try {
    await fw.bootHardwareRoot();
    const device = await boundDevice(fw);
    if (!device) {
      err.write("ecwctl: no Enclaweder is bound to this process (none attached, or another process owns it)\n");
      return 1;
    }
    out.write(`Operator takeover of the anchor channel of ${device.serial ?? device.uid}: whatever session holds it now is ended.\n`);
    const typed = (await readLine("Type the device's serial to proceed (anything else aborts): ")).trim();
    if (!device.serial || typed.toUpperCase() !== device.serial.toUpperCase()) {
      out.write("Aborted: the serial did not match. Nothing was changed.\n");
      await audit({ type: "claude-code.hardware.anchor-takeover", actor: "enclawed-code", level: null, payload: { outcome: "aborted", code: "serial-mismatch" } });
      return 1;
    }
    const r = await takeoverAnchor(fw, device, signers);
    await audit({ type: "claude-code.hardware.anchor-takeover", actor: "enclawed-code", level: null, payload: { outcome: "taken-over", serial: device.serial, sid: String(r.sid), operators: signers.length } });
    out.write(`Taken over and closed (session ${r.sid}). The anchor channel is free: start Enclawed Code again. The takeover is counted on the device as an open by another session, so the next launch refuses to start until you accept the log as the new baseline: ecwctl audit accept\n`);
    return 0;
  } catch (e) {
    await audit({ type: "claude-code.hardware.anchor-takeover", actor: "enclawed-code", level: null, payload: { outcome: "refused", detail: String(e?.message ?? e).slice(0, 500) } });
    err.write(`ecwctl: takeover REFUSED: ${e?.message ?? e}\n${/auth/i.test(String(e?.code ?? e?.message)) ? "The operator signatures did not make the device's quorum, or the device has no operator key installed.\n" : ""}`);
    return 1;
  } finally {
    try {
      fw.closeHardwareRootSession();
    } catch {
      /* nothing to close */
    }
  }
}
