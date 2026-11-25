// Claude Code's login, sealed at rest under the Enclaweder and never a
// readable file while Enclawed Code runs (attack 6).
//
// Erasing the login on a halt (credentials.mjs) does not stop a copy of
// ~/.claude/.credentials.json taken before the session, and a login file
// opened for the session is readable by any process of this user while it
// runs. With an Enclaweder bound, therefore:
//
//   - the login is kept sealed under the key the device derives (the kit's
//     login-seal.ts and credential-keys.ts), in Enclawed Code's protected state:
//     <state>/claude-code/credentials/claude-login.sealed.json. It is made by
//     `ecwctl login seal`, or by the first launch with the
//     device (which seals the one plaintext login claude would have used and
//     erases it). A plaintext login found next to the sealed one is refused,
//     never adopted;
//   - at launch it is opened into the launcher's memory only, and claude gets
//     no credential at all: it reaches the model through the kit's auth relay
//     (auth-relay.ts) on a unix socket in a private directory of the session,
//     with a fixed placeholder credential; the relay adds the real token and
//     sends the request over verified TLS to the provider. A refreshed token
//     is sealed again by the relay before it is used. Claude never holds a
//     real token, and nothing readable holds one on disk.
//
// What Claude Code 2.1.326 does (read from its own code, then run against a
// stand-in relay with no real account):
//   - ANTHROPIC_UNIX_SOCKET=<socket> with CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder
//     (and no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN) is its `claude ssh`
//     tunnel mode: every model request goes over the socket, as TLS for
//     api.anthropic.com (verified, so the relay's session CA is given in
//     NODE_EXTRA_CA_CERTS), with `Authorization: Bearer ssh-placeholder`;
//     some calls (policy limits) go over the socket as plain HTTP.
//   - Its login file: `.credentials.json` in CLAUDE_SECURESTORAGE_CONFIG_DIR
//     when set (empty: ~/.claude), else CLAUDE_CONFIG_DIR, else ~/.claude.
//     The session points it at an empty private directory, so no login on
//     disk is read or written.
//   - It refreshes at https://platform.claude.com/v1/oauth/token (JSON
//     refresh_token grant, its client id below); the relay does the same.
//
// macOS: Claude Code keeps its login in the login Keychain; the seal does not
// apply there (the Keychain is the platform's store).

import fs from "node:fs";
import path from "node:path";
import { claudeCredentialLocations } from "./credentials.mjs";
import { guardedLoginFiles, personLoginFiles } from "./login-guard.mjs";
import { kit } from "./kit.mjs";
import { appStateDir } from "./paths.mjs";
import { parseFlags, UsageError } from "./cli-util.mjs";
import { program } from "./program.mjs";
import { deviceCodeText } from "./device-activation.mjs";

/** What the sealed record is for (bound into it as associated data). */
export const LOGIN_LABEL = "claude-code.login";
/** The empty private directory claude's secure storage points at. */
export const SECURE_SUBDIR = "claude-secure";

/** Claude Code's provider, its tunnel placeholder and routes (host data, from 2.1.326). */
export const CLAUDE_RELAY = Object.freeze({
  upstreamHost: "api.anthropic.com",
  placeholderEnv: { CLAUDE_CODE_OAUTH_TOKEN: "ssh-placeholder" },
  placeholder: { header: "authorization", value: "Bearer ssh-placeholder" },
  credentialHeader: { header: "authorization", prefix: "Bearer " },
  routes: Object.freeze([
    { method: "POST", path: /^\/v1\/messages$/, credential: true },
    { method: "POST", path: /^\/v1\/messages\/count_tokens$/, credential: true },
    { method: "GET", path: /^\/api\/claude_code\/policy_limits$/, credential: false },
  ]),
  tokenUrl: "https://platform.claude.com/v1/oauth/token",
  clientId: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
  /** Variables that would give claude a credential or another endpoint: removed. */
  removeEnv: Object.freeze([
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_CUSTOM_HEADERS",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_GATEWAY",
    "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST",
    "CLAUDE_CODE_HOST_AUTH_ENV_VAR",
    "CLAUDE_CODE_HOST_CREDS_FILE",
  ]),
});

/** The sealed login, in Enclawed Code's protected state. */
export function sealedLoginFile(env = process.env) {
  return path.join(appStateDir(env), "credentials", "claude-login.sealed.json");
}

/** The seal's fallback key file (the credential store's; a device seals, never this, with a device bound). */
function keyFileFor(env) {
  return path.join(appStateDir(env), "credentials", "remote-mcp.key");
}

/** Where the person's own plaintext login would be found: this environment's location, and the default one (login-guard.mjs). */
export function plainLoginFiles(env = process.env) {
  return personLoginFiles(env);
}

/** The session's (empty) secure-storage login file: what CLAUDE_SECURESTORAGE_CONFIG_DIR points claude at. */
export function sessionLoginFile(sessionDir) {
  return path.join(sessionDir, SECURE_SUBDIR, ".credentials.json");
}

/**
 * The seal's keys: the bound device's (kit.credentialStoreKeys; no OS keyring
 * is touched). On command set 0.5 the kit derives it with KEY_DERIVE on the
 * launch's device-verified activation, never CHALLENGE; with the root
 * required, nothing else.
 */
export async function loginSealKeys({ env = process.env, k = kit, device = k.frameworkCredentialKeyDevice(), rootRequired = env.ENCLAWEDER_ROOT === "required" } = {}) {
  return k.credentialStoreKeys({ keyFile: keyFileFor(env), device, keyring: null, rootRequired });
}

/** Why a bound device gave no key, for the person (the kit's reason), or "". */
function deviceKeyProblem(keys) {
  return keys?.device?.problem ? ` (${keys.device.problem})` : "";
}

/**
 * The key device: the framework's signing seam (as the seal command uses),
 * else the attested session device itself (the same device, uid and
 * signature: the same key).
 */
export function sessionKeyDevice(device, k = kit) {
  const fwDev = k.frameworkCredentialKeyDevice();
  if (fwDev || !device?.dev || typeof device.uid !== "string") {
    return fwDev;
  }
  return { uid: device.uid, sign: async (m) => Buffer.from((await device.dev.challenge(m)).sig) };
}

/** Claude Code's stored login (claudeAiOauth) as the relay keeps it, or null. */
export function oauthLoginOf(doc) {
  const o = doc?.claudeAiOauth;
  if (!o || typeof o.accessToken !== "string" || o.accessToken === "") {
    return null;
  }
  return {
    accessToken: o.accessToken,
    refreshToken: typeof o.refreshToken === "string" && o.refreshToken ? o.refreshToken : null,
    expiresAt: typeof o.expiresAt === "number" ? o.expiresAt : null,
    scopes: Array.isArray(o.scopes) ? o.scopes.filter((s) => typeof s === "string") : [],
  };
}

/**
 * Before the launch's activation (which spends a device-counted unlock use): the login decisions that
 * need no device key. A launch the kit's login decision refuses (a plaintext login beside the sealed
 * one, two plaintext logins, a sealed login with no device), or whose memory other processes of this
 * user can read, is refused here, so the refusal spends nothing. openLoginForSession checks the same
 * again after the activation (the files may change in between).
 * @returns {{ ok: true } | { ok: false, code: string, message: string }}
 */
export function loginLaunchPrecheck({ env = process.env, deviceBound, platform = process.platform, k = kit }) {
  if (platform === "darwin") {
    return { ok: true };
  }
  // The person's own login counts only under the administrator's managed login policy (login-guard.mjs).
  const status = k.loginSealStatus({ sealedFile: sealedLoginFile(env), plainFiles: guardedLoginFiles(env) });
  const decision = k.loginLaunchDecision({ deviceBound, status });
  if (decision.action === "refuse") {
    const how = decision.code === "plaintext-beside-seal" ? " (if it is your own current login: ecwctl login seal --replace)" : "";
    return { ok: false, code: decision.code, message: `${decision.message}${how}` };
  }
  if (decision.action === "unseal" && !status.sealed.present) {
    return { ok: false, code: "no-login", message: NO_LOGIN_MESSAGE };
  }
  if (decision.action !== "pass") {
    const shield = k.processMemoryShielded();
    if (!shield.shielded) {
      return { ok: false, code: "memory-not-shielded", message: `the login would be held in memory that other processes of this user can read (${shield.reason}); set kernel.yama.ptrace_scope to 1 or more (sysctl), or detach the Enclaweder` };
    }
  }
  return { ok: true };
}

/** With an Enclaweder bound and no login of Enclawed Code's own yet. */
export const NO_LOGIN_MESSAGE =
  "Enclawed Code has no Claude login of its own yet (with an Enclaweder its sessions use their own login, sealed under the device; your own Claude Code login is not used or touched). Sign in once inside Enclawed Code: ecwctl login new";

/** A short socket path (a unix socket path is limited to about 100 bytes). */
const SOCKET_PATH_MAX = 100;

/**
 * At launch, after the session directory exists: the kit's decision (the
 * first launch with a device seals the one plaintext login), then the login
 * opened into this process's memory and the relay started. `device`: the
 * attested Enclaweder the launcher holds (device.mjs sessionDevice), or null.
 * @returns {Promise<{ ok: true, action: "pass" } | { ok: true, action: "relayed", applyEnv: (env: object) => object, relay: object, sealedFile: string, sessionFile: string, sealedNow: boolean } | { ok: false, code: string, message: string }>}
 */
export async function openLoginForSession({ env = process.env, sessionDir, device = null, deviceBound = Boolean(device), platform = process.platform, k = kit, keys = null, rootRequired = env.ENCLAWEDER_ROOT === "required", audit = async () => {}, reactivate = null, relayOptionsForTest = {} }) {
  if (platform === "darwin" || !sessionDir) {
    // macOS keeps the login in the Keychain; managed mode has no session directory.
    return { ok: true, action: "pass" };
  }
  const sealedFile = sealedLoginFile(env);
  // Enclawed Code's own login only: the person's login is never taken, unless the managed login policy says so (login-guard.mjs).
  const status = k.loginSealStatus({ sealedFile, plainFiles: guardedLoginFiles(env) });
  const decision = k.loginLaunchDecision({ deviceBound, status });
  if (decision.action === "pass") {
    return { ok: true, action: "pass" };
  }
  if (decision.action === "refuse") {
    const how = decision.code === "plaintext-beside-seal" ? " (if it is your own current login: ecwctl login seal --replace)" : "";
    return { ok: false, code: decision.code, message: `${decision.message}${how}` };
  }
  // The token will live in this process's memory: only where no other process of this user can read it.
  const shield = k.processMemoryShielded();
  if (!shield.shielded) {
    return { ok: false, code: "memory-not-shielded", message: `the login would be held in memory that other processes of this user can read (${shield.reason}); set kernel.yama.ptrace_scope to 1 or more (sysctl), or detach the Enclaweder` };
  }
  const ks = keys ?? (await loginSealKeys({ env, k, device: sessionKeyDevice(device, k), rootRequired }));
  // Records of this module go to Enclawed Code's audit log under its prefix (never a secret).
  const record = (r) => audit({ type: `claude-code.${r.type}`, actor: "enclawed-code", level: null, payload: r.payload });
  // Command set 0.5: a login sealed under the earlier (CHALLENGE) key is moved to the derived key once, audited.
  // Command set 0.5: the launch's login box (the kit's credential-keys boxes.login). Sealed to it, the
  // login opens only at the start of a launch; after that this process holds its public key alone.
  const box = ks.device?.boxes?.login ?? null;
  const moved = await k.migrateLegacyLoginSeal({ sealedFile, keys: ks, deviceBound: true, label: LOGIN_LABEL, audit: record, box });
  if (!moved.ok) {
    return { ok: false, code: moved.code, message: `Claude Code's sealed login could not be moved to the Enclaweder's derived key: ${moved.message}` };
  }
  const keyState = { keyDerivation: ks.device?.derivation ?? null, residual: ks.device?.residual ?? null };
  let sealedNow = false;
  if (decision.action === "seal-then-unseal") {
    // The first launch with the device: the login claude would have used is sealed, its plaintext erased.
    const s = k.sealLoginFile({ plainFile: decision.plainFile, sealedFile, keys: ks, deviceBound: true, label: LOGIN_LABEL, box });
    if (!s.ok) {
      return { ok: false, code: s.code, message: `Claude Code's login could not be sealed under the Enclaweder: ${s.message}${deviceKeyProblem(ks)}` };
    }
    if (!s.plaintextErased) {
      return { ok: false, code: "plaintext-left", message: `Claude Code's login was sealed, but its plaintext ${decision.plainFile} could not be erased; remove it by hand` };
    }
    sealedNow = true;
  }
  // A crash dump of this process would be a plaintext copy of the token at rest: core dumps go off first.
  const dumps = typeof k.processCoreDumpsOff === "function" ? k.processCoreDumpsOff() : { off: false, reason: "this kit cannot turn core dumps off" };
  if (!dumps.off) {
    await record({ type: "auth.core-dumps-on", payload: { reason: dumps.reason } });
  }
  const m = k.unsealLoginToMemory({ sealedFile, keys: ks, deviceBound: true, label: LOGIN_LABEL, box });
  if (!m.ok) {
    return {
      ok: false,
      code: m.code,
      message: m.code === "no-login" ? NO_LOGIN_MESSAGE : `Claude Code's sealed login cannot be opened: ${m.message}${deviceKeyProblem(ks)}`,
    };
  }
  // A login sealed under the symmetric device key (earlier versions) is sealed to the box now, once.
  if (box && m.keyId !== box.id) {
    const b = k.sealLoginBytes({ plain: m.plain, sealedFile, keys: ks, deviceBound: true, label: LOGIN_LABEL, box });
    if (!b.ok) {
      m.plain.fill(0);
      return { ok: false, code: b.code, message: `Claude Code's sealed login could not be sealed to the Enclaweder's login box: ${b.message}` };
    }
    await record({ type: "auth.login-seal.boxed", payload: { label: LOGIN_LABEL, fromKey: String(m.keyId), toKey: box.id } });
  }
  let doc;
  try {
    doc = JSON.parse(m.plain.toString("utf8"));
  } catch {
    doc = null;
  } finally {
    m.plain.fill(0);
  }
  const login = oauthLoginOf(doc);
  if (!login) {
    return { ok: false, code: "no-oauth-login", message: "Enclawed Code's sealed login holds no account login (claudeAiOauth); sign in again inside Enclawed Code: ecwctl login new --replace" };
  }
  // The stored document is kept without its tokens: the relay holds them (with a vault, not the refresh token).
  const { accessToken: _at, refreshToken: _rt, ...oauthRest } = doc.claudeAiOauth;
  doc = { ...doc, claudeAiOauth: oauthRest };
  // A renewed token is sealed again (the whole stored document, with the new tokens) before it is used.
  const onRotate = (next) => {
    const whole = { ...doc, claudeAiOauth: { ...doc.claudeAiOauth, accessToken: next.accessToken, refreshToken: next.refreshToken, expiresAt: next.expiresAt, scopes: [...next.scopes] } };
    const bytes = Buffer.from(JSON.stringify(whole), "utf8");
    const r = k.sealLoginBytes({ plain: bytes, sealedFile, keys: ks, deviceBound: true, label: LOGIN_LABEL, box });
    bytes.fill(0);
    if (!r.ok) {
      throw new Error(r.message);
    }
  };
  // The hardware root required: the refresh token is not held in memory. It stays sealed to the login
  // box and is opened for the instant of a refresh, after a new device-verified activation of this
  // launch (`reactivate`: a device-counted unlock use, headless); without one the refresh fails
  // (audited) and model access ends when the access token expires (relaunch with -c).
  const refreshVault =
    rootRequired && box
      ? k.boxRefreshVault({
          box,
          reopen: async () => {
            k.forgetLaunchCredentialKeys();
            if (!reactivate || !(await reactivate().catch(() => false))) {
              return null;
            }
            const again = await loginSealKeys({ env, k, device: sessionKeyDevice(device, k), rootRequired });
            return again.device?.boxes?.login ?? null;
          },
          forget: () => k.forgetLaunchCredentialKeys(),
        })
      : null;
  const credential = k.oauthRelayCredential({ login, tokenUrl: CLAUDE_RELAY.tokenUrl, clientId: CLAUDE_RELAY.clientId, onRotate, refreshVault, ...(relayOptionsForTest.credential ?? {}) });
  // The socket, in a fresh private directory beside the session's (short enough for a unix socket path).
  const sockDir = fs.mkdtempSync(path.join(path.dirname(sessionDir), "a-"));
  fs.chmodSync(sockDir, 0o700);
  const socketPath = path.join(sockDir, "a.sock");
  if (Buffer.byteLength(socketPath) > SOCKET_PATH_MAX) {
    credential.drop();
    fs.rmSync(sockDir, { recursive: true, force: true });
    return { ok: false, code: "socket-path-too-long", message: `the relay's socket path ${socketPath} is too long for a unix socket` };
  }
  // Every token refresh, and every failed one, is a record of the audit log (the kit's, never token material).
  const relayAudit = k.auditedAuthRelayEvents(record);
  let relay;
  try {
    relay = await k.startAuthRelay({
      socketPath,
      upstreamHost: CLAUDE_RELAY.upstreamHost,
      placeholder: CLAUDE_RELAY.placeholder,
      credentialHeader: CLAUDE_RELAY.credentialHeader,
      routes: CLAUDE_RELAY.routes,
      credential,
      onEvent: relayAudit.onEvent,
      ...(relayOptionsForTest.relay ?? {}),
    });
  } catch (err) {
    credential.drop();
    fs.rmSync(sockDir, { recursive: true, force: true });
    return { ok: false, code: "relay-failed", message: `the login relay could not start (${err.message})` };
  }
  // Claude trusts the relay's session CA (name-constrained to the provider) besides its usual ones.
  const caFile = path.join(sessionDir, "claude-relay-ca.pem");
  let extra = "";
  try {
    extra = env.NODE_EXTRA_CA_CERTS ? fs.readFileSync(env.NODE_EXTRA_CA_CERTS, "utf8") : "";
  } catch {
    extra = "";
  }
  const sessionFile = sessionLoginFile(sessionDir);
  try {
    fs.writeFileSync(caFile, `${extra}${extra && !extra.endsWith("\n") ? "\n" : ""}${relay.caCertPem}`, { mode: 0o644, flag: "wx" });
    fs.mkdirSync(path.dirname(sessionFile), { mode: 0o700 });
  } catch (err) {
    // The relay is never left running behind a launch that cannot use it.
    await relay.close().catch(() => {});
    credential.drop();
    fs.rmSync(sockDir, { recursive: true, force: true });
    return { ok: false, code: "session-dir", message: `the session's login files could not be written (${err.message})` };
  }
  const applyEnv = (e) => {
    const out = { ...e };
    for (const name of CLAUDE_RELAY.removeEnv) {
      delete out[name];
    }
    return { ...out, ...CLAUDE_RELAY.placeholderEnv, ANTHROPIC_UNIX_SOCKET: socketPath, NODE_EXTRA_CA_CERTS: caFile, CLAUDE_SECURESTORAGE_CONFIG_DIR: path.dirname(sessionFile) };
  };
  // keys: the launch's device keys (forgotten after the start); box: the login box, which seals a login that appears in the session.
  return { ok: true, action: "relayed", applyEnv, relay, relayAudit, sockDir, sealedFile, sessionFile, sealedNow, keys: ks, box, boxes: ks.device?.boxes ?? null, refreshVaulted: refreshVault !== null, ...keyState };
}

/**
 * The end of the session: the relay is closed (the token dropped), and the
 * session's secure-storage directory erased (a login made inside the session
 * is not kept). On a halt (`halted`, with the policy's erase on), the sealed
 * login is erased too: a fresh login to the account is needed.
 * @returns {Promise<null | { ok: boolean, action: string, erased: string[], remaining: string[], message: string | null }>}
 */
export async function closeLoginForSession(opened, opts = {}) {
  const { halted = false, k = kit } = opts;
  if (!opened || opened.action !== "relayed") {
    return null;
  }
  await opened.relay.close().catch(() => {});
  // The refresh records written so far are in the log before the session is reported closed.
  await opened.relayAudit?.settled();
  const auditFailures = opened.relayAudit?.failures() ?? 0;
  fs.rmSync(opened.sockDir, { recursive: true, force: true });
  // A login made inside the session (/login writes to the session's own storage, CLAUDE_SECURESTORAGE_CONFIG_DIR):
  // it is Enclawed Code's, so it becomes the sealed login (the launch's login box seals; nothing opens it here).
  let kept = null;
  if (!halted && fs.existsSync(opened.sessionFile)) {
    kept = k.sealLoginFile({ plainFile: opened.sessionFile, sealedFile: opened.sealedFile, keys: opened.keys ?? {}, deviceBound: true, label: LOGIN_LABEL, ...(opened.box ? { box: opened.box } : {}) });
    await opts.audit?.({ type: "claude-code.login.session-login-sealed", actor: "enclawed-code", level: null, payload: kept.ok ? { ok: true, sealedFile: opened.sealedFile } : { ok: false, code: kept.code } }).catch(() => {});
  }
  const r = k.eraseSessionLogin({ sessionFile: opened.sessionFile });
  const erased = r.erased.map((f) => `file ${f}`);
  const remaining = r.remaining.map((f) => `file ${f}`);
  if (halted) {
    const gone = k.eraseSealedLogin({ sealedFile: opened.sealedFile });
    (gone ? erased : remaining).push(`sealed login ${opened.sealedFile}`);
  }
  return {
    ok: remaining.length === 0 && auditFailures === 0,
    action: halted ? "erased" : "closed",
    erased,
    remaining,
    message: remaining.length
      ? `could NOT erase ${remaining.join(", ")}; remove it by hand`
      : auditFailures
        ? `${auditFailures} token refresh record(s) of the login relay could not be written to the audit log`
        : kept && !kept.ok
          ? `a login made inside the session could not be sealed (${kept.message}); it was erased: sign in again with: ecwctl login new`
          : kept?.ok
            ? "the login made inside the session is now Enclawed Code's sealed login"
            : null,
  };
}

/** A launch refused after the relay started (claude never ran): close it, keep the sealed login. */
export async function discardSessionLogin(opened, { k = kit } = {}) {
  await closeLoginForSession(opened, { halted: false, k });
}

export const LOGIN_HELP = `usage:
  ecwctl login status            where Claude Code's login is, and whether it is sealed
  ecwctl login seal [--replace]  seal the login under the bound Enclaweder and erase the plaintext
`;

/**
 * `ecwctl login status|seal`. `hold(fw)` holds the hardware
 * root (hardware.mjs holdSessionRoot); `k` is the kit. Never prints a secret.
 */
export async function loginCommand(args, { out, err, env = process.env, fw, audit = async () => {}, hold, k = kit, platform = process.platform, device = null, readCode = null }) {
  const sub = args[0];
  const sealedFile = sealedLoginFile(env);
  if (sub === "status") {
    parseFlags(args.slice(1), { maxPositionals: 0 });
    const s = k.loginSealStatus({ sealedFile, plainFiles: plainLoginFiles(env) });
    out.write(`sealed login: ${s.sealed.present ? `${sealedFile} (${s.sealed.readable ? `sealed with a ${s.sealed.keySource} key` : "not a sealed login"})` : "none"}\n`);
    out.write(`plaintext login: ${s.plaintext.length ? s.plaintext.join(", ") : "none"}\n`);
    return 0;
  }
  if (sub !== "seal") {
    throw new UsageError(LOGIN_HELP.trim());
  }
  const { flags } = parseFlags(args.slice(1), { bool: ["--replace"], maxPositionals: 0 });
  if (platform === "darwin") {
    err.write(`${program()}: on macOS Claude Code keeps its login in the login Keychain; there is no login file to seal\n`);
    return 1;
  }
  const plainFile = claudeCredentialLocations(env, "linux").file;
  if (fs.existsSync(sealedFile) && !flags["--replace"]) {
    err.write(`${program()}: a sealed login is already there (${sealedFile}); to put the plaintext login at ${plainFile} in its place, run: ecwctl login seal --replace\n`);
    return 1;
  }
  const root = device ? null : await hold(fw);
  try {
    const dev = device ?? (root?.mode === "held" ? k.frameworkCredentialKeyDevice() : null);
    if (!dev) {
      err.write(`${program()}: no Enclaweder is bound${root?.reason ? ` (${root.reason})` : ""}; the login is sealed only under the device. Nothing was changed\n`);
      return 1;
    }
    // Command set 0.5: the key is derived only on a device-verified activation; the person gives one here.
    if (dev.keyDerivation && readCode && (await dev.keyDerivation.commandSet().catch(() => null))?.status === "proven") {
      const factor = k.deviceSecondFactor();
      const code = factor ? String(await readCode(`${factor.label}: `).catch(() => "")).trim() : "";
      const v = factor ? await factor.verify({ purpose: "session-start", code }).catch(() => ({ ok: false, code: "device-error" })) : { ok: false, code: "no-device" };
      if (!v.ok) {
        err.write(`${program()}: ${deviceCodeText(v.code)}; the login is sealed only under a key the device derives on one. Nothing was changed\n`);
        return 1;
      }
    }
    const keys = await loginSealKeys({ env, k, device: dev });
    if (keys.write?.source !== "device") {
      err.write(`${program()}: the Enclaweder's key could not be derived${deviceKeyProblem(keys)}; the login is sealed only under the device. Nothing was changed\n`);
      return 1;
    }
    const r = k.sealLoginFile({ plainFile, sealedFile, keys, deviceBound: true, label: LOGIN_LABEL });
    await Promise.resolve()
      .then(() => audit({ type: "claude-code.login.sealed", actor: "enclawed-code", level: null, payload: r.ok ? { ok: true, key: String(r.keyId).split(":")[0], plaintextErased: r.plaintextErased } : { ok: false, code: r.code } }))
      .catch(() => {});
    if (!r.ok) {
      err.write(`${program()}: ${r.message}. Nothing was changed\n`);
      return 1;
    }
    out.write(`Claude Code's login is sealed under the Enclaweder: ${sealedFile}\n`);
    if (!r.plaintextErased) {
      err.write(`${program()}: could NOT erase the plaintext login ${plainFile}; remove it by hand\n`);
      return 1;
    }
    out.write(`the plaintext login ${plainFile} was erased. Enclawed Code opens the login only inside its sessions, and only with this device attached.\n`);
    out.write("A copy taken before now still works until it is revoked: sign out of other Claude Code sessions at claude.ai, then log in once more inside Enclawed Code.\n");
    return 0;
  } finally {
    root?.release?.();
  }
}
