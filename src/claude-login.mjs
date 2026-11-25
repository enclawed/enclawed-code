// How Claude Code's sessions under Enclawed Code authenticate.
//
// For Claude subscription logins, Enclawed Code follows Anthropic's terms
// (https://code.claude.com/docs/en/legal-and-compliance, "Authentication and
// credential use"): the login stays with Claude Code, signed in through
// Anthropic's own flow (`/login` inside Claude Code), and Enclawed Code never
// collects, stores, seals, opens, reads, relays or moves it. With an API key,
// the customer's own key management, Enclawed Code can seal the key under the
// Enclaweder and serve it through the kit's auth relay, so even a compromised
// computer cannot use it without the device.
//
// With an Enclaweder bound (Linux and macOS):
//   - without a sealed API key, claude runs with CLAUDE_SECURESTORAGE_CONFIG_DIR
//     pointed at Enclawed Code's Claude Code login directory
//     (<state>/claude-code/claude-login). The person signs in there with
//     Claude Code's own /login; Claude Code writes and reads its credential
//     itself (`.credentials.json` there, or on macOS the login Keychain item
//     Claude Code keys to that directory). Enclawed Code never opens a file in
//     that directory. On a hardware halt, after every process of the session
//     is stopped, the directory's files are overwritten and removed, and the
//     Keychain item is deleted (closeLoginForSession), without being read: a
//     host that keeps running after the device is detached has no login of the
//     session's left to use. The person's own Claude Code login (the one plain
//     `claude` uses) is never touched;
//   - with an API key sealed (`ecwctl login api-key`, Linux): the key is opened
//     into the launcher's memory only, and claude reaches the model through the
//     relay on a unix socket in a private directory of the session, holding a
//     fixed placeholder; the relay adds the key (x-api-key) and sends the request
//     over verified TLS to api.anthropic.com. Usage is billed to the key's owner.
//
// What is an API key is decided deterministically (credentialKind): only a
// string of Anthropic's API key format is one. Everything else, including
// OAuth access and refresh tokens, is treated as a subscription credential and
// is refused: never sealed, never relayed.
//
// Earlier builds sealed a Claude subscription login (`claude-login.sealed.json`)
// or held a copy of one (`credentials/pending/`). Those stores are erased
// without being opened (eraseLegacySubscriptionStores).

import fs from "node:fs";
import path from "node:path";
import { eraseClaudeCredentials } from "./credentials.mjs";
import { kit } from "./kit.mjs";
import { appStateDir } from "./paths.mjs";
import { parseFlags, UsageError } from "./cli-util.mjs";
import { program } from "./program.mjs";
import { deviceCodeText } from "./device-activation.mjs";

/** What the sealed record is for (bound into it as associated data). */
export const API_KEY_LABEL = "claude-code.api-key";

/**
 * Anthropic API keys (Claude Console): "sk-ant-api" + two digits + "-" + the key body.
 * OAuth tokens of a Claude subscription ("sk-ant-oat01-...", "sk-ant-ort01-...") do not match.
 */
export const API_KEY_PATTERN = /^sk-ant-api\d{2}-[A-Za-z0-9_-]{20,400}$/;

/**
 * "api-key" only for a string positively in Anthropic's API key format; anything else is
 * "subscription" (fail toward compliance: never sealed, never relayed).
 * @returns {"api-key" | "subscription"}
 */
export function credentialKind(secret) {
  return typeof secret === "string" && API_KEY_PATTERN.test(secret) ? "api-key" : "subscription";
}

/** Claude Code's provider and the relay's routes and placeholder (host data). */
export const CLAUDE_RELAY = Object.freeze({
  upstreamHost: "api.anthropic.com",
  placeholderEnv: { CLAUDE_CODE_OAUTH_TOKEN: "ssh-placeholder" },
  placeholder: { header: "authorization", value: "Bearer ssh-placeholder" },
  credentialHeader: { header: "x-api-key", prefix: "" },
  routes: Object.freeze([
    { method: "POST", path: /^\/v1\/messages$/, credential: true },
    { method: "POST", path: /^\/v1\/messages\/count_tokens$/, credential: true },
  ]),
  /** Variables that would give claude another credential or endpoint while the relay serves the key: removed. */
  removeEnv: Object.freeze([
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_CUSTOM_HEADERS",
    "CLAUDE_CODE_OAUTH_TOKEN",
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

/** Enclawed Code's Claude Code login directory: Claude Code's own secure storage for its sessions. */
export function claudeLoginDir(env = process.env) {
  return path.join(appStateDir(env), "claude-login");
}

/** The sealed API key, in Enclawed Code's protected state. */
export function sealedApiKeyFile(env = process.env) {
  return path.join(appStateDir(env), "credentials", "anthropic-api-key.sealed.json");
}

/** Stores of earlier builds that held a Claude subscription login: erased, never opened. */
export function legacySubscriptionStores(env = process.env) {
  const c = path.join(appStateDir(env), "credentials");
  return [path.join(c, "claude-login.sealed.json"), path.join(c, "pending")];
}

/** The seal's fallback key file (the credential store's; with a device bound, a device key seals, never this). */
function keyFileFor(env) {
  return path.join(appStateDir(env), "credentials", "remote-mcp.key");
}

/**
 * The launch's device keys (kit.credentialStoreKeys; no OS keyring is touched). On command
 * set 0.5 the kit derives them with KEY_DERIVE on the launch's device-verified activation;
 * their boxes seal the API key, the session's context and its tool logins.
 */
export async function loginSealKeys({ env = process.env, k = kit, device = k.frameworkCredentialKeyDevice(), rootRequired = env.ENCLAWEDER_ROOT === "required" } = {}) {
  return k.credentialStoreKeys({ keyFile: keyFileFor(env), device, keyring: null, rootRequired });
}

/** Why a bound device gave no key, for the person (the kit's reason), or "". */
function deviceKeyProblem(keys) {
  return keys?.device?.problem ? ` (${keys.device.problem})` : "";
}

/** The key device: the framework's signing seam, else the attested session device itself. */
export function sessionKeyDevice(device, k = kit) {
  const fwDev = k.frameworkCredentialKeyDevice();
  if (fwDev || !device?.dev || typeof device.uid !== "string") {
    return fwDev;
  }
  return { uid: device.uid, sign: async (m) => Buffer.from((await device.dev.challenge(m)).sig) };
}

function present(p) {
  try {
    fs.lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

/**
 * Erase the stores of earlier builds that held a Claude subscription login, without opening
 * them: every file is overwritten and removed (the kit's eraseSessionLogin / eraseSealedLogin).
 * @returns {Promise<{ erased: string[], remaining: string[] }>}
 */
export async function eraseLegacySubscriptionStores({ env = process.env, k = kit, audit = async () => {} } = {}) {
  const [sealed, pending] = legacySubscriptionStores(env);
  const erased = [];
  const remaining = [];
  if (present(sealed)) {
    (k.eraseSealedLogin({ sealedFile: sealed }) ? erased : remaining).push(sealed);
  }
  if (present(pending)) {
    const r = k.eraseSessionLogin({ sessionFile: path.join(pending, ".none") });
    erased.push(...r.erased);
    remaining.push(...r.remaining);
    if (present(pending)) {
      fs.rmSync(pending, { recursive: true, force: true });
    }
    (present(pending) ? remaining : erased).push(pending);
  }
  if (erased.length || remaining.length) {
    await audit({ type: "claude-code.login.legacy-erased", actor: "enclawed-code", level: null, payload: { erased, remaining } }).catch(() => {});
  }
  return { erased, remaining };
}

/** The notice for erased legacy stores, or null. */
function legacyNotice(r) {
  if (!r.erased.length && !r.remaining.length) {
    return null;
  }
  return r.remaining.length
    ? `could NOT erase a Claude login an earlier Enclawed Code build stored (${r.remaining.join(", ")}); remove it by hand`
    : "a Claude login an earlier Enclawed Code build stored was erased without being opened; sign in with /login inside an Enclawed Code session";
}

/**
 * Before the launch's activation (which spends a device-counted unlock use): the decisions that
 * need no device key. With a sealed API key, or the session's context to seal, the launch's keys
 * will be in this process's memory: refused where other processes of this user can read it.
 * @returns {{ ok: true } | { ok: false, code: string, message: string }}
 */
export function loginLaunchPrecheck({ deviceBound, platform = process.platform, k = kit }) {
  if (platform === "darwin" || !deviceBound) {
    return { ok: true };
  }
  const shield = k.processMemoryShielded();
  if (!shield.shielded) {
    return { ok: false, code: "memory-not-shielded", message: memoryMessage(shield) };
  }
  return { ok: true };
}

function memoryMessage(shield) {
  return `the launch's device keys would be held in memory that other processes of this user can read (${shield.reason}); set kernel.yama.ptrace_scope to 1 or more (sysctl), or detach the Enclaweder`;
}

/** A short socket path (a unix socket path is limited to about 100 bytes). */
const SOCKET_PATH_MAX = 100;

/** The session's own Claude Code login directory, made private (0700) if needed. */
function ensureLoginDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink()) {
    throw new Error(`${dir} is not a directory`);
  }
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    throw new Error(`${dir} is not owned by this user`);
  }
  fs.chmodSync(dir, 0o700);
}

/**
 * At launch, after the session directory exists.
 *   - no device: { action: "pass" } (claude uses whatever login Claude Code holds, as plain claude does);
 *   - a device and no sealed API key: { action: "own-login" } (Claude Code's own login in Enclawed Code's
 *     login directory, never read here), with the launch's boxes for the session's context and tool logins;
 *   - a device and a sealed API key (Linux): { action: "relayed" }, the key opened into this
 *     process's memory and the relay started.
 * `device`: the attested Enclaweder the launcher holds (device.mjs sessionDevice), or null.
 */
export async function openLoginForSession({ env = process.env, sessionDir, device = null, deviceBound = Boolean(device), platform = process.platform, k = kit, keys = null, rootRequired = env.ENCLAWEDER_ROOT === "required", audit = async () => {}, relayOptionsForTest = {} }) {
  if (!deviceBound || !sessionDir) {
    // No device, or managed mode (no session directory): Claude Code's own login, as plain claude uses it.
    return { ok: true, action: "pass" };
  }
  const record = (r) => audit({ type: `claude-code.${r.type}`, actor: "enclawed-code", level: null, payload: r.payload });
  const legacy = await eraseLegacySubscriptionStores({ env, k, audit });
  const notice = legacyNotice(legacy);
  const loginDir = claudeLoginDir(env);
  try {
    ensureLoginDir(loginDir);
  } catch (e) {
    return { ok: false, code: "login-dir", message: `Claude Code's login directory for Enclawed Code sessions could not be prepared (${e.message})` };
  }
  const ownLoginEnv = (e) => ({ ...e, CLAUDE_SECURESTORAGE_CONFIG_DIR: loginDir });
  if (platform === "darwin") {
    // macOS: the login Keychain item Claude Code keys to this directory; no sealed key, no relay.
    return { ok: true, action: "own-login", loginDir, applyEnv: ownLoginEnv, boxes: null, notice };
  }
  const shield = k.processMemoryShielded();
  if (!shield.shielded) {
    return { ok: false, code: "memory-not-shielded", message: memoryMessage(shield) };
  }
  const ks = keys ?? (await loginSealKeys({ env, k, device: sessionKeyDevice(device, k), rootRequired }));
  const keyState = { keyDerivation: ks.device?.derivation ?? null, residual: ks.device?.residual ?? null };
  const box = ks.device?.boxes?.login ?? null;
  const sealedFile = sealedApiKeyFile(env);
  if (!present(sealedFile)) {
    return { ok: true, action: "own-login", loginDir, applyEnv: ownLoginEnv, keys: ks, box, boxes: ks.device?.boxes ?? null, notice, ...keyState };
  }
  // A sealed API key: opened into this process's memory only. A crash dump would be a copy of it: core dumps go off first.
  const dumps = typeof k.processCoreDumpsOff === "function" ? k.processCoreDumpsOff() : { off: false, reason: "this kit cannot turn core dumps off" };
  if (!dumps.off) {
    await record({ type: "auth.core-dumps-on", payload: { reason: dumps.reason } });
  }
  const m = k.unsealLoginToMemory({ sealedFile, keys: ks, deviceBound: true, label: API_KEY_LABEL, box });
  if (!m.ok) {
    return { ok: false, code: m.code, message: `the API key sealed under the Enclaweder cannot be opened: ${m.message}${deviceKeyProblem(ks)} (to remove it: ecwctl login api-key --remove)` };
  }
  let apiKey = null;
  try {
    const doc = JSON.parse(m.plain.toString("utf8"));
    apiKey = doc?.kind === "anthropic-api-key" && typeof doc.apiKey === "string" ? doc.apiKey : null;
  } catch {
    apiKey = null;
  } finally {
    m.plain.fill(0);
  }
  if (credentialKind(apiKey) !== "api-key") {
    // Not positively an API key: treated as a subscription credential, never relayed.
    apiKey = null;
    await record({ type: "login.api-key.refused", payload: { reason: "not-an-api-key" } });
    return { ok: false, code: "not-an-api-key", message: "the sealed credential store does not hold an Anthropic API key; Enclawed Code serves only API keys, never a Claude subscription login (to remove it: ecwctl login api-key --remove)" };
  }
  let current = apiKey;
  apiKey = null;
  const credential = {
    current: () => current,
    refresh: async () => false,
    expiresSoon: () => false,
    drop: () => {
      current = null;
    },
  };
  const sockDir = fs.mkdtempSync(path.join(path.dirname(sessionDir), "a-"));
  fs.chmodSync(sockDir, 0o700);
  const socketPath = path.join(sockDir, "a.sock");
  if (Buffer.byteLength(socketPath) > SOCKET_PATH_MAX) {
    credential.drop();
    fs.rmSync(sockDir, { recursive: true, force: true });
    return { ok: false, code: "socket-path-too-long", message: `the relay's socket path ${socketPath} is too long for a unix socket` };
  }
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
    return { ok: false, code: "relay-failed", message: `the API key relay could not start (${err.message})` };
  }
  // Claude trusts the relay's session CA (name-constrained to the provider) besides its usual ones.
  const caFile = path.join(sessionDir, "claude-relay-ca.pem");
  let extra = "";
  try {
    extra = env.NODE_EXTRA_CA_CERTS ? fs.readFileSync(env.NODE_EXTRA_CA_CERTS, "utf8") : "";
  } catch {
    extra = "";
  }
  try {
    fs.writeFileSync(caFile, `${extra}${extra && !extra.endsWith("\n") ? "\n" : ""}${relay.caCertPem}`, { mode: 0o644, flag: "wx" });
  } catch (err) {
    await relay.close().catch(() => {});
    credential.drop();
    fs.rmSync(sockDir, { recursive: true, force: true });
    return { ok: false, code: "session-dir", message: `the relay's CA file could not be written (${err.message})` };
  }
  const applyEnv = (e) => {
    const out = { ...e };
    for (const name of CLAUDE_RELAY.removeEnv) {
      delete out[name];
    }
    return { ...out, ...CLAUDE_RELAY.placeholderEnv, ANTHROPIC_UNIX_SOCKET: socketPath, NODE_EXTRA_CA_CERTS: caFile, CLAUDE_SECURESTORAGE_CONFIG_DIR: loginDir };
  };
  return { ok: true, action: "relayed", applyEnv, relay, relayAudit, sockDir, loginDir, sealedFile, keys: ks, box, boxes: ks.device?.boxes ?? null, notice, credential, ...keyState };
}

/**
 * The end of the session. The relay (if any) is closed and the key dropped. On a halt (`halted`,
 * with the policy's erase on): the session's Claude Code login storage (Enclawed Code's login
 * directory, and on macOS the Keychain item Claude Code keys to it) is erased without being read,
 * and the sealed API key too. The person's own Claude Code login is never touched.
 * @returns {Promise<null | { ok: boolean, action: string, erased: string[], remaining: string[], message: string | null }>}
 */
export async function closeLoginForSession(opened, opts = {}) {
  const { halted = false, k = kit, platform = process.platform } = opts;
  if (!opened?.ok || opened.action === "pass") {
    return null;
  }
  let auditFailures = 0;
  if (opened.action === "relayed") {
    await opened.relay.close().catch(() => {});
    opened.credential?.drop();
    await opened.relayAudit?.settled();
    auditFailures = opened.relayAudit?.failures() ?? 0;
    fs.rmSync(opened.sockDir, { recursive: true, force: true });
  }
  const erased = [];
  const remaining = [];
  if (halted) {
    const r = eraseSessionClaudeLogin(opened.loginDir, { k, platform, env: opts.env });
    erased.push(...r.erased);
    remaining.push(...r.remaining);
    if (opened.action === "relayed") {
      (k.eraseSealedLogin({ sealedFile: opened.sealedFile }) ? erased : remaining).push(`sealed API key ${opened.sealedFile}`);
    }
  }
  return {
    ok: remaining.length === 0 && auditFailures === 0,
    action: halted ? "erased" : "closed",
    erased,
    remaining,
    message: remaining.length
      ? `could NOT erase ${remaining.join(", ")}; remove it by hand`
      : auditFailures
        ? `${auditFailures} record(s) of the API key relay could not be written to the audit log`
        : null,
  };
}

/**
 * Erase the session's Claude Code login storage without reading it: every file of Enclawed
 * Code's login directory is overwritten and removed (the kit's eraseSessionLogin opens files
 * write-only), and on macOS the Keychain item Claude Code keys to that directory is deleted.
 * @returns {{ erased: string[], remaining: string[] }}
 */
export function eraseSessionClaudeLogin(loginDir, { k = kit, platform = process.platform, env = process.env } = {}) {
  const r = k.eraseSessionLogin({ sessionFile: path.join(loginDir, ".credentials.json") });
  const erased = r.erased.map((f) => `file ${f}`);
  const remaining = r.remaining.map((f) => `file ${f}`);
  if (platform === "darwin") {
    // The files are gone first, so only the Keychain item is left for this call (deleted, never read).
    const kc = eraseClaudeCredentials({ env: { HOME: env.HOME, USER: env.USER, CLAUDE_SECURESTORAGE_CONFIG_DIR: loginDir }, platform });
    erased.push(...kc.erased);
    remaining.push(...kc.remaining);
  }
  return { erased, remaining };
}

/** A launch refused after the relay started (claude never ran): close it, keep the sealed key. */
export async function discardSessionLogin(opened, { k = kit } = {}) {
  await closeLoginForSession(opened, { halted: false, k });
}

export const LOGIN_HELP = `usage:
  ecwctl login status                     how Enclawed Code sessions authenticate, and whether an API key is sealed
  ecwctl login api-key [--replace]        seal an Anthropic API key under the bound Enclaweder (read from standard input)
  ecwctl login api-key --remove           erase the sealed API key

For Claude subscription logins, Enclawed Code follows Anthropic's terms: the login stays with Claude Code,
signed in through Anthropic's own flow (/login inside an ecwcode session), and Enclawed Code never stores
or relays it. Such a login is kept where Claude Code keeps it, readable by programs running as you. With an
API key, Enclawed Code can seal the credential under the Enclaweder, so even a compromised computer cannot
use it without the device. Organizations that need that protection use an API key.
`;

/** Read one line from standard input; with a terminal, without echoing it. */
async function readSecretLine(prompt, { stdin = process.stdin, stderr = process.stderr } = {}) {
  if (stdin.isTTY && typeof stdin.setRawMode === "function") {
    stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    try {
      return await new Promise((resolve, reject) => {
        let s = "";
        const onData = (d) => {
          for (const ch of d.toString("utf8")) {
            if (ch === "\r" || ch === "\n") {
              stdin.off("data", onData);
              resolve(s);
              return;
            }
            if (ch === "\u0003") {
              stdin.off("data", onData);
              reject(new Error("interrupted"));
              return;
            }
            s = ch === "\u007f" ? s.slice(0, -1) : s + ch;
          }
        };
        stdin.on("data", onData);
      });
    } finally {
      stdin.setRawMode(false);
      stdin.pause();
      stderr.write("\n");
    }
  }
  const chunks = [];
  for await (const c of stdin) {
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString("utf8").split(/\r?\n/)[0] ?? "";
}

/**
 * The device's keys on a device-verified activation (the person gives a code the Enclaweder
 * verifies); or a refusal written to `err`.
 */
async function activatedKeys({ env, fw, hold, k, device, readCode, err }) {
  const root = device ? null : await hold(fw);
  const dev = device ?? (root?.mode === "held" ? k.frameworkCredentialKeyDevice() : null);
  if (!dev) {
    root?.release?.();
    err.write(`${program()}: no Enclaweder is bound${root?.reason ? ` (${root.reason})` : ""}; an API key is sealed only under the device. Nothing was changed\n`);
    return null;
  }
  // Command set 0.5 derives the key only on a device-verified activation: the person gives a code here.
  if (dev.keyDerivation && (await dev.keyDerivation.commandSet().catch(() => null))?.status === "proven") {
    const factor = k.deviceSecondFactor();
    const code = factor && readCode ? String(await readCode(`${factor.label}: `).catch(() => "")).trim() : "";
    const v = factor ? await factor.verify({ purpose: "session-start", code }).catch(() => ({ ok: false, code: "device-error" })) : { ok: false, code: "no-device" };
    if (!v.ok) {
      root?.release?.();
      err.write(`${program()}: ${deviceCodeText(v.code)}; nothing was changed\n`);
      return null;
    }
  }
  const keys = await loginSealKeys({ env, k, device: dev });
  if (keys.write?.source !== "device") {
    root?.release?.();
    err.write(`${program()}: the Enclaweder's key could not be derived${deviceKeyProblem(keys)}; nothing was changed\n`);
    return null;
  }
  return { keys, box: keys.device?.boxes?.login ?? null, release: () => root?.release?.() };
}

/**
 * `ecwctl login status|api-key`. `hold(fw)` holds the hardware root (hardware.mjs
 * holdSessionRoot); `k` is the kit; `readSecret(prompt)` reads the key (tests). Never prints a secret.
 */
export async function loginCommand(args, { out, err, env = process.env, fw, audit = async () => {}, hold, k = kit, platform = process.platform, device = null, readCode = null, readSecret = readSecretLine }) {
  const sub = args[0];
  const sealedFile = sealedApiKeyFile(env);
  if (sub === "status") {
    parseFlags(args.slice(1), { maxPositionals: 0 });
    const legacy = await eraseLegacySubscriptionStores({ env, k, audit });
    const notice = legacyNotice(legacy);
    if (notice) {
      err.write(`${program()}: ${notice}\n`);
    }
    out.write("Claude subscription login: stays with Claude Code (sign in with /login inside a session); Enclawed Code never stores or relays it\n");
    out.write(`  with an Enclaweder, Claude Code keeps the sessions' login in ${claudeLoginDir(env)}, erased on a hardware halt\n`);
    out.write(`sealed API key: ${present(sealedFile) ? sealedFile : "none"}\n`);
    return 0;
  }
  if (sub !== "api-key") {
    throw new UsageError(LOGIN_HELP.trim());
  }
  const { flags } = parseFlags(args.slice(1), { bool: ["--replace", "--remove"], maxPositionals: 0 });
  if (flags["--remove"]) {
    const gone = !present(sealedFile) || k.eraseSealedLogin({ sealedFile });
    await audit({ type: "claude-code.login.api-key.removed", actor: "enclawed-code", level: null, payload: { ok: gone } }).catch(() => {});
    out.write(gone ? "no API key is sealed\n" : "");
    if (!gone) {
      err.write(`${program()}: could NOT erase ${sealedFile}; remove it by hand\n`);
    }
    return gone ? 0 : 1;
  }
  if (platform === "darwin") {
    err.write(`${program()}: sealing an API key under the Enclaweder is available on Linux; on macOS configure the key as Claude Code documents (ANTHROPIC_API_KEY or apiKeyHelper)\n`);
    return 1;
  }
  if (present(sealedFile) && !flags["--replace"]) {
    err.write(`${program()}: an API key is already sealed (${sealedFile}); to put another in its place: ecwctl login api-key --replace\n`);
    return 1;
  }
  let secret = String(await readSecret("Anthropic API key: ").catch(() => "")).trim();
  if (credentialKind(secret) !== "api-key") {
    // Never sealed: only an Anthropic API key is the customer's own key to manage here.
    secret = "";
    await audit({ type: "claude-code.login.api-key.sealed", actor: "enclawed-code", level: null, payload: { ok: false, code: "not-an-api-key" } }).catch(() => {});
    err.write(`${program()}: that is not an Anthropic API key (sk-ant-api...). Claude subscription logins are never stored by Enclawed Code: sign in with /login inside a session. Nothing was changed\n`);
    return 1;
  }
  const act = await activatedKeys({ env, fw, hold, k, device, readCode, err });
  if (!act) {
    secret = "";
    return 1;
  }
  try {
    const bytes = Buffer.from(JSON.stringify({ kind: "anthropic-api-key", apiKey: secret }), "utf8");
    secret = "";
    const s = k.sealLoginBytes({ plain: bytes, sealedFile, keys: act.keys, deviceBound: true, label: API_KEY_LABEL, ...(act.box ? { box: act.box } : {}) });
    bytes.fill(0);
    await audit({ type: "claude-code.login.api-key.sealed", actor: "enclawed-code", level: null, payload: s.ok ? { ok: true, key: String(s.keyId).split(":")[0] } : { ok: false, code: s.code } }).catch(() => {});
    if (!s.ok) {
      err.write(`${program()}: the API key could not be sealed: ${s.message}. Nothing was changed\n`);
      return 1;
    }
    out.write(`the API key is sealed under the Enclaweder (${sealedFile}); Enclawed Code sessions reach Claude with it through the relay, and claude never holds it\n`);
    return 0;
  } finally {
    act.release();
  }
}
