// Only under the administrator's managed login policy (login-guard.mjs): a
// plaintext Claude Code login appearing in the person's storage is not left
// readable for plain `claude`. Without that policy nothing here touches the
// person's own login: no sweep, no watcher process, no in-session watch, and
// logins an earlier build held are reported as the person's, never a reason
// to refuse a launch (`login resolve --discard` erases those copies).
//
// Enclawed Code keeps Claude Code's login sealed under the Enclaweder
// (login-seal.mjs). A person who signs in with plain `claude` writes a
// plaintext login to Claude Code's credentials file, which plain `claude` can
// use until Enclawed Code's next launch. This module runs the kit's watcher
// (host-credential-watch.ts: the decision, the move, the bound) on Claude
// Code's credential locations:
//
//   - inside every Enclawed Code session that holds the device, in the launcher:
//     a login that appears is sealed under the device at once, with the
//     launch's device-verified activation, into a pending sealed record;
//   - otherwise, in a watcher process of this user (`ecwctl
//     login watch`, started by a systemd user service from `login watch
//     install`, and by every launch when it is not running): a background
//     process holds no activation, so a login that appears is quarantined
//     (moved into Enclawed Code's protected state, out of Claude Code's reach);
//   - at every launch and every Enclawed Code command, a pending login is
//     reported, and a launch is refused until the person resolves it (`login
//     resolve`: adopt it as the sealed login with a code the Enclaweder
//     verifies, or discard it).
//
// Where Claude Code 2.1.326 writes its login on Linux (read from its code and
// observed while it signs in): `.credentials.json` in its secure-storage
// directory (CLAUDE_SECURESTORAGE_CONFIG_DIR, else CLAUDE_CONFIG_DIR, else
// ~/.claude), written as `.credentials.json.tmp.<hex>` then renamed. A Console
// (API key) sign-in also keeps `primaryApiKey` in ~/.claude.json, which this
// watcher does not move (docs/enterprise.md, limits); macOS keeps the login in
// the Keychain and is not watched.
//
// A watcher of this user can be stopped by any process of this user. On a
// managed install the managed login policy (managed-login.mjs) is what makes
// plain `claude` unable to sign in at all.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { authority, testAuthorityActive } from "./authority.mjs";
import { parseFlags, UsageError } from "./cli-util.mjs";
import { kit } from "./kit.mjs";
import {
  closeLoginForSession as closeSealedLogin,
  CLAUDE_RELAY,
  discardSessionLogin as discardSealedLogin,
  LOGIN_LABEL,
  loginSealKeys,
  openLoginForSession as openSealedLogin,
  plainLoginFiles,
  sealedLoginFile,
} from "./login-seal.mjs";
import * as loginSeal from "./login-seal.mjs";
import { APP_ROOT, appStateDir, homeDir } from "./paths.mjs";
import { trustedBinary } from "./trusted-bin.mjs";
import { program } from "./program.mjs";
import { deviceCodeText } from "./device-activation.mjs";
import { personLoginFiles, personLoginGuarded } from "./login-guard.mjs";

/** Claude Code's login files this installation may act on (none without the managed login policy) and its transient write files (host data, 2.1.326). */
export function claudeCredentialSpec(env = process.env, { guarded = personLoginGuarded() } = {}) {
  return { files: guarded ? personLoginFiles(env) : [], transientSuffixes: [".tmp."] };
}

/** Where a login that appeared is held until the person resolves it. */
export function pendingDir(env = process.env) {
  return path.join(appStateDir(env), "credentials", "pending");
}

/** The pending logins (sealed or quarantined), oldest first. */
export function pendingLogins(env = process.env) {
  return kit.pendingHostCredentials(pendingDir(env), LOGIN_LABEL);
}

/** A device is bound to this installation: a login is sealed under it, or one is pending. */
export function sealBound(env = process.env) {
  return fs.existsSync(sealedLoginFile(env)) || pendingLogins(env).length > 0;
}

/**
 * The person-facing line about held logins, or null. Under the managed login
 * policy they block a launch until resolved; without it they are copies of
 * the person's own login an earlier build took, reported (heldCopiesNotice).
 */
export function pendingNotice(env = process.env) {
  const p = pendingLogins(env);
  if (p.length === 0) {
    return null;
  }
  if (!personLoginGuarded()) {
    return heldCopiesNotice(p.length, env);
  }
  const kinds = p.map((x) => (x.sealed ? "sealed under the Enclaweder" : "quarantined")).join(", ");
  return `${p.length} Claude Code login(s) made outside Enclawed Code are held (${kinds}); plain \`claude\` cannot use them. Resolve: ecwctl login resolve (adopt it, with a code the Enclaweder verifies) or login resolve --discard. If you did not sign in yourself, discard it and sign out of other Claude Code sessions at claude.ai`;
}

/** Copies of the person's own login an earlier build held: never Enclawed Code's, never a reason to refuse a launch. */
export function heldCopiesNotice(n, env = process.env) {
  return `${n} cop${n === 1 ? "y" : "ies"} of your own Claude Code login, taken by an earlier Enclawed Code build, ${n === 1 ? "is" : "are"} held in ${pendingDir(env)}; they are not Enclawed Code's and are never used. Erase them with: ecwctl login resolve --discard`;
}

/** Do held logins refuse a launch? Only under the managed login policy. */
export function heldLoginsBlock(env = process.env) {
  return personLoginGuarded() && pendingLogins(env).length > 0;
}

function auditEvent(audit, e, where) {
  if (!e.result.ok) {
    return audit({ type: "claude-code.login.watch.failed", actor: "enclawed-code", level: null, payload: { where, file: e.found.file, kind: e.found.kind, code: e.result.code } });
  }
  if (e.result.action === "left") {
    return Promise.resolve();
  }
  return audit({ type: `claude-code.login.watch.${e.result.action}`, actor: "enclawed-code", level: null, payload: { where, file: e.found.file, kind: e.found.kind, pending: e.result.pendingFile } });
}

/**
 * The handler: the kit's decision and move for one found login. `keys`: the
 * launch's device keys (a device-verified activation) and, on command set
 * 0.5, `sealOptions.box` (the launch's login box, which only seals): sealed;
 * null: quarantined. A forgotten key with no box cannot seal: quarantined.
 */
export function secureFound(found, { env = process.env, keys = null, k = kit, sealOptions = {} } = {}) {
  const seal = keys ? (held, sealed) => k.sealLoginFile({ plainFile: held, sealedFile: sealed, keys, deviceBound: true, label: LOGIN_LABEL, ...sealOptions }) : null;
  return k.secureHostCredential({ found, sealBound: Boolean(keys) || sealBound(env), pendingDir: pendingDir(env), label: LOGIN_LABEL, seal });
}

/** One pass now (doctor, launch, `login watch --once`). */
export async function sweepLogins({ env = process.env, keys = null, audit = async () => {}, where = "sweep", k = kit, guarded = personLoginGuarded() } = {}) {
  const events = [];
  for (const found of k.findHostCredentials(claudeCredentialSpec(env, { guarded }))) {
    const result = secureFound(found, { env, keys, k });
    const e = { found, result };
    events.push(e);
    await auditEvent(audit, e, where).catch(() => {});
  }
  return events;
}

/**
 * The launch's login precheck, before the launch's activation (so a refusal spends nothing on
 * the Enclaweder): a plaintext login that appeared beside the sealed one is first taken out of
 * Claude Code's reach (the kit's decision and move; synchronous), a held login refuses the launch
 * (login-pending), then login-seal.mjs's own precheck runs.
 * @returns {{ ok: true } | { ok: false, code: string, message: string }}
 */
export function loginLaunchPrecheck({ env = process.env, deviceBound, platform = process.platform, k = kit, audit = async () => {} }) {
  if (platform !== "darwin" && sealBound(env)) {
    for (const found of k.findHostCredentials(claudeCredentialSpec(env))) {
      const result = secureFound(found, { env, k });
      void auditEvent(audit, { found, result }, "launch-precheck").catch(() => {});
    }
  }
  if (platform !== "darwin" && heldLoginsBlock(env)) {
    return { ok: false, code: "login-pending", message: pendingNotice(env) };
  }
  // login-seal.mjs's precheck (the seal's own refusals before activation), where this build has it.
  return typeof loginSeal.loginLaunchPrecheck === "function" ? loginSeal.loginLaunchPrecheck({ env, deviceBound, platform, k }) : { ok: true };
}

/** The watcher (kit watchHostCredentials) on Claude Code's locations. */
export function startLoginWatch({ env = process.env, keys = null, audit = async () => {}, onEvent = () => {}, where = "watcher", keepAlive = false, k = kit, sealOptions = {}, guarded = personLoginGuarded() } = {}) {
  return k.watchHostCredentials({
    spec: claudeCredentialSpec(env, { guarded }),
    keepAlive,
    handle: (found) => secureFound(found, { env, keys, k, sealOptions }),
    onEvent: (e) => {
      void auditEvent(audit, e, where).catch(() => {});
      onEvent(e);
    },
  });
}

// ------------------------------------------------------------ the watcher process

/** How often the watcher process checks that it is still this state directory's watcher. */
const WATCHER_OWNERSHIP_CHECK_MS = 2000;

/** The watcher process's record: pid and start time (so a reused pid is not taken for it). */
function pidFile(env) {
  return path.join(appStateDir(env), "login-watch.pid");
}

function processStart(pid) {
  try {
    return fs.readFileSync(`/proc/${pid}/stat`, "utf8").split(") ")[1].split(" ")[19];
  } catch {
    return null;
  }
}

/** Is the watcher process of this state directory running? */
export function watcherRunning(env = process.env) {
  try {
    const rec = JSON.parse(fs.readFileSync(pidFile(env), "utf8"));
    if (!Number.isInteger(rec.pid) || rec.pid <= 1) {
      return false;
    }
    const cmd = fs.readFileSync(`/proc/${rec.pid}/cmdline`, "utf8");
    return processStart(rec.pid) === rec.start && cmd.includes("login\0watch");
  } catch {
    return false;
  }
}

/**
 * Login watcher processes of this user that are not this installation's
 * current watcher: started by an earlier build (codenclawed, enclawde), from
 * a program that no longer exists, or a second one. Read from /proc (Linux);
 * nothing is signalled here.
 * @returns {Array<{ pid: number, command: string, why: string }>}
 */
export function strayWatchers(env = process.env, { procDir = "/proc", uid = typeof process.getuid === "function" ? process.getuid() : null } = {}) {
  if (process.platform !== "linux") {
    return [];
  }
  let current = null;
  try {
    current = JSON.parse(fs.readFileSync(pidFile(env), "utf8")).pid;
  } catch {
    current = null;
  }
  const out = [];
  let names = [];
  try {
    names = fs.readdirSync(procDir).filter((n) => /^\d+$/.test(n));
  } catch {
    return [];
  }
  for (const n of names) {
    const pid = Number(n);
    if (pid === process.pid) {
      continue;
    }
    let argv;
    try {
      if (uid !== null && fs.statSync(path.join(procDir, n)).uid !== uid) {
        continue;
      }
      argv = fs.readFileSync(path.join(procDir, n, "cmdline"), "utf8").split("\0").filter(Boolean);
    } catch {
      continue;
    }
    const at = argv.findIndex((a, i) => a === "login" && argv[i + 1] === "watch" && argv[i + 2] === undefined);
    const script = argv.slice(0, Math.max(at, 0)).find((a) => /\.m?js$/.test(a));
    if (at < 0 || !script || !/(codenclawed|enclawde|ecwctl|ecwcode)[^/]*\.m?js$/.test(script)) {
      continue;
    }
    const why = /codenclawed|enclawde/.test(script)
      ? "started by an earlier build (codenclawed / enclawde)"
      : !fs.existsSync(script)
        ? "its program no longer exists"
        : pid !== current
          ? "not this state directory's watcher"
          : !personLoginGuarded()
            ? "not needed: the managed login policy is not in force"
            : null;
    if (why) {
      out.push({ pid, command: argv.join(" ").slice(0, 200), why });
    }
  }
  return out;
}

/**
 * At launch (with a sealed login, or a session that holds the device): start
 * the watcher process when it is not running. Under the test suite nothing is
 * spawned unless its stand-in asks (authority.mjs).
 */
export function ensureLoginWatcher({ env = process.env } = {}) {
  // Not needed without the managed login policy: then nothing guards the person's storage.
  if (!personLoginGuarded()) {
    return { started: false, running: watcherRunning(env), notNeeded: true };
  }
  if (process.platform !== "linux" || watcherRunning(env)) {
    return { started: false, running: process.platform === "linux" };
  }
  if (testAuthorityActive()) {
    const seam = authority().loginWatchSpawn;
    seam?.({ env });
    return { started: Boolean(seam), running: false };
  }
  const child = spawn(process.execPath, [path.join(APP_ROOT, "bin", "ecwctl.mjs"), "login", "watch"], { env, detached: true, stdio: "ignore" });
  child.unref();
  return { started: true, running: true };
}

const UNIT_NAME = "enclawed-code-login-watch.service";
// The unit an earlier release installed: its ExecStart names a program that no
// longer exists, so install and remove take it out too.
const LEGACY_UNIT_NAMES = Object.freeze(["codenclawed-login-watch.service"]);

/** The systemd user unit: the watcher, restarted whenever it stops. */
export function unitFile(env = process.env) {
  const base = env.XDG_CONFIG_HOME && path.isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : path.join(homeDir(env), ".config");
  return path.join(base, "systemd", "user", UNIT_NAME);
}

/** Units an earlier release installed for this account (still present). */
export function legacyUnitFiles(env = process.env) {
  const dir = path.dirname(unitFile(env));
  return LEGACY_UNIT_NAMES.map((name) => ({ name, file: path.join(dir, name) })).filter((u) => fs.existsSync(u.file));
}

function removeLegacyUnits(env, run) {
  const removed = [];
  for (const u of legacyUnitFiles(env)) {
    systemctl(["disable", "--now", u.name], run);
    fs.rmSync(u.file, { force: true });
    removed.push(u.file);
  }
  return removed;
}

export function unitText() {
  const q = (s) => `"${s.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
  return `[Unit]
Description=Enclawed Code: a plaintext Claude Code login is sealed or quarantined, never left for plain claude

[Service]
Type=simple
ExecStart=${q(process.execPath)} ${q(path.join(APP_ROOT, "bin", "ecwctl.mjs"))} login watch
Restart=on-failure
RestartSec=1

[Install]
WantedBy=default.target
`;
}

function systemctl(args, run) {
  const bin = trustedBinary("systemctl");
  if (!bin) {
    return { ok: false, detail: "systemctl was not found in the system directories" };
  }
  const r = run(bin, ["--user", ...args], { encoding: "utf8", timeout: 30_000 });
  return { ok: r.status === 0, detail: (r.stderr || r.stdout || "").trim().split("\n")[0] ?? "" };
}

// ------------------------------------------------------------ commands

export const WATCH_HELP = `usage:
  ecwctl login watch [--once]            run the watcher (foreground; --once: one pass)
  ecwctl login watch install|remove|status   the systemd user service that keeps it running
  ecwctl login resolve [--replace|--discard] a login made outside Enclawed Code: adopt it as the sealed login, or discard it
  ecwctl login new [--replace]           sign in to Claude inside Enclawed Code; the login is sealed under the Enclaweder at once
`;

/** `login watch ...` */
export async function watchCommand(args, { out, err, env = process.env, audit = async () => {}, run = spawnSync, k = kit, signal = null }) {
  const sub = args[0];
  if (sub === "install" || sub === "remove" || sub === "status") {
    parseFlags(args.slice(1), { maxPositionals: 0 });
    const file = unitFile(env);
    if (sub === "status") {
      out.write(`watcher service: ${fs.existsSync(file) ? file : "not installed"}\n`);
      out.write(`watcher process: ${watcherRunning(env) ? "running" : "not running"}\n`);
      for (const u of legacyUnitFiles(env)) {
        out.write(`earlier release's service: ${u.file} (its program no longer exists; login watch install or remove takes it out)\n`);
      }
      return 0;
    }
    if (sub === "remove") {
      systemctl(["disable", "--now", UNIT_NAME], run);
      fs.rmSync(file, { force: true });
      for (const f of removeLegacyUnits(env, run)) {
        out.write(`removed ${f}\n`);
      }
      systemctl(["daemon-reload"], run);
      await audit({ type: "claude-code.login.watch.service-removed", actor: "enclawed-code", level: null, payload: { file } }).catch(() => {});
      out.write(`removed ${file}\n`);
      return 0;
    }
    if (!personLoginGuarded()) {
      for (const f of removeLegacyUnits(env, run)) {
        out.write(`removed ${f}\n`);
      }
      err.write(`${program()}: the login watcher is only for the managed login policy (sudo ecwctl managed login-policy install), which is not in force here; without it Enclawed Code never touches your own Claude Code login. Nothing was installed\n`);
      return 1;
    }
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    for (const f of removeLegacyUnits(env, run)) {
      out.write(`removed ${f}\n`);
    }
    fs.writeFileSync(file, unitText(), { mode: 0o600 });
    out.write(`wrote ${file}\n`);
    const reload = systemctl(["daemon-reload"], run);
    const enable = reload.ok ? systemctl(["enable", "--now", UNIT_NAME], run) : reload;
    await audit({ type: "claude-code.login.watch.service-installed", actor: "enclawed-code", level: null, payload: { file, enabled: enable.ok } }).catch(() => {});
    if (!enable.ok) {
      err.write(`${program()}: the service could not be enabled (${enable.detail}); every Enclawed Code launch still starts the watcher when it is not running\n`);
      return 1;
    }
    out.write("the watcher runs now and after every login of this account\n");
    return 0;
  }
  const { flags } = parseFlags(args, { bool: ["--once"], maxPositionals: 0 });
  const report = (e) => {
    if (e.result.ok && e.result.action !== "left") {
      out.write(`${new Date().toISOString()} ${e.result.action}: ${e.found.file}\n`);
      if (e.result.action !== "link-removed") {
        err.write(`${program()}: ${pendingNotice(env) ?? ""}\n`);
      }
    } else if (!e.result.ok) {
      err.write(`${program()}: ${e.result.message}\n`);
    }
  };
  if (flags["--once"]) {
    for (const e of await sweepLogins({ env, audit, where: "once", k })) {
      report(e);
    }
    return 0;
  }
  if (!personLoginGuarded()) {
    // Without the managed login policy there is nothing for a watcher to guard: the person's login is theirs.
    out.write("the login watcher is not needed: without the managed login policy Enclawed Code never touches your own Claude Code login\n");
    return 0;
  }
  fs.mkdirSync(appStateDir(env), { recursive: true, mode: 0o700 });
  fs.writeFileSync(pidFile(env), JSON.stringify({ pid: process.pid, start: processStart(process.pid) }), { mode: 0o600 });
  const w = startLoginWatch({ env, audit, onEvent: report, keepAlive: true, k });
  await audit({ type: "claude-code.login.watch.started", actor: "enclawed-code", level: null, payload: { pid: process.pid, boundMs: k.CREDENTIAL_WATCH_BOUND_MS } }).catch(() => {});
  await new Promise((resolve) => {
    const stop = () => {
      clearInterval(owned);
      resolve();
    };
    // The watcher of this state directory ends when its record names another process (a newer
    // watcher took over) or the state directory is gone (a removed install, a test sandbox):
    // it never outlives what it watches for.
    const owned = setInterval(() => {
      let mine = false;
      try {
        mine = JSON.parse(fs.readFileSync(pidFile(env), "utf8")).pid === process.pid;
      } catch {
        mine = false;
      }
      // ... and when the managed login policy is gone: then it has nothing to guard.
      if (!mine || !personLoginGuarded()) {
        stop();
      }
    }, WATCHER_OWNERSHIP_CHECK_MS);
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    signal?.addEventListener("abort", stop, { once: true });
  });
  w.close();
  try {
    if (JSON.parse(fs.readFileSync(pidFile(env), "utf8")).pid === process.pid) {
      fs.rmSync(pidFile(env), { force: true });
    }
  } catch {
    /* gone */
  }
  return 0;
}

/**
 * The device's keys on a device-verified activation (the person gives a code
 * the Enclaweder verifies), as `login seal` takes them; or a refusal.
 */
async function activatedKeys({ env, fw, hold, k, device, readCode, err }) {
  const root = device ? null : await hold(fw);
  const dev = device ?? (root?.mode === "held" ? k.frameworkCredentialKeyDevice() : null);
  if (!dev) {
    root?.release?.();
    err.write(`${program()}: no Enclaweder is bound${root?.reason ? ` (${root.reason})` : ""}; nothing was changed\n`);
    return null;
  }
  // As `login seal`: command set 0.5 derives the key only on a device-verified activation, so the person gives a code here.
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
    err.write(`${program()}: the Enclaweder's key could not be derived; nothing was changed\n`);
    return null;
  }
  return { keys, box: keys.device?.boxes?.login ?? null, release: () => root?.release?.() };
}

/** `login resolve [--replace|--discard]` */
export async function resolveCommand(args, { out, err, env = process.env, fw, audit = async () => {}, hold, k = kit, device = null, readCode = null }) {
  const { flags } = parseFlags(args, { bool: ["--replace", "--discard"], maxPositionals: 0 });
  const pending = pendingLogins(env);
  if (pending.length === 0) {
    out.write("no login made outside Enclawed Code is held\n");
    return 0;
  }
  if (flags["--discard"]) {
    const gone = pending.filter((p) => k.discardPendingCredential(p.file));
    await audit({ type: "claude-code.login.watch.discarded", actor: "enclawed-code", level: null, payload: { files: gone.map((p) => p.file), remaining: pending.length - gone.length } }).catch(() => {});
    out.write(`discarded ${gone.length} held login(s). Sign out of other Claude Code sessions at claude.ai if you did not make them.\n`);
    return gone.length === pending.length ? 0 : 1;
  }
  if (pending.length > 1) {
    err.write(`${program()}: ${pending.length} logins are held; Enclawed Code adopts only one it can tell is yours: discard them (login resolve --discard) and sign in with: ecwctl login new\n`);
    return 1;
  }
  const sealedFile = sealedLoginFile(env);
  if (fs.existsSync(sealedFile) && !flags["--replace"]) {
    err.write(`${program()}: a sealed login is already there (${sealedFile}); to put the held login in its place: ecwctl login resolve --replace (or discard it: --discard)\n`);
    return 1;
  }
  const act = await activatedKeys({ env, fw, hold, k, device, readCode, err });
  if (!act) {
    return 1;
  }
  try {
    const p = pending[0];
    let r;
    if (p.sealed) {
      // Sealed in a session under this device: it must open with the device's key before it is adopted.
      const m = k.unsealLoginToMemory({ sealedFile: p.file, keys: act.keys, deviceBound: true, label: LOGIN_LABEL, box: act.box });
      if (!m.ok) {
        err.write(`${program()}: the held login does not open with this Enclaweder (${m.code}); discard it: ecwctl login resolve --discard\n`);
        return 1;
      }
      m.plain.fill(0);
      fs.renameSync(p.file, sealedFile);
      r = { ok: true, plaintextErased: true };
    } else {
      r = k.sealLoginFile({ plainFile: p.file, sealedFile, keys: act.keys, deviceBound: true, label: LOGIN_LABEL, box: act.box });
    }
    await audit({ type: "claude-code.login.watch.adopted", actor: "enclawed-code", level: null, payload: r.ok ? { ok: true, from: p.sealed ? "sealed" : "quarantined", plaintextErased: r.plaintextErased } : { ok: false, code: r.code } }).catch(() => {});
    if (!r.ok) {
      err.write(`${program()}: ${r.message}. Nothing was changed\n`);
      return 1;
    }
    out.write(`the held login is now Claude Code's sealed login (${sealedFile}); Enclawed Code opens it only inside its sessions\n`);
    return r.plaintextErased ? 0 : 1;
  } finally {
    act.release();
  }
}

/** Claude Code's sign-in, as data (2.1.326: its claude.ai authorize URL, manual redirect, token URL, client id and scopes). */
export const CLAUDE_SIGN_IN = Object.freeze({
  authorizeUrl: "https://claude.com/cai/oauth/authorize",
  tokenUrl: CLAUDE_RELAY.tokenUrl,
  redirectUri: "https://platform.claude.com/oauth/code/callback",
  clientId: CLAUDE_RELAY.clientId,
  scopes: ["org:create_api_key", "user:profile", "user:inference", "user:sessions:claude_code", "user:mcp_servers", "user:file_upload", "user:plugins", "user:privacy_consents:write"],
  authorizeParams: { code: "true" },
});

/** `login new [--replace]`: sign in inside Enclawed Code; the login goes straight under the device's seal. */
export async function newLoginCommand(args, { out, err, env = process.env, fw, audit = async () => {}, hold, k = kit, device = null, readCode = null, signInForTest = {} }) {
  const { flags } = parseFlags(args, { bool: ["--replace"], maxPositionals: 0 });
  const sealedFile = sealedLoginFile(env);
  if (fs.existsSync(sealedFile) && !flags["--replace"]) {
    err.write(`${program()}: a sealed login is already there (${sealedFile}); to sign in again in its place: ecwctl login new --replace\n`);
    return 1;
  }
  const act = await activatedKeys({ env, fw, hold, k, device, readCode, err });
  if (!act) {
    return 1;
  }
  try {
    const r = await k.oauthCodeLogin(CLAUDE_SIGN_IN, {
      show: (url) => out.write(`Open this address in a browser, sign in, and paste the code it shows:\n${url}\n`),
      readCode: () => readCode("Code: "),
      ...signInForTest,
    });
    if (!r.ok) {
      await audit({ type: "claude-code.login.new", actor: "enclawed-code", level: null, payload: { ok: false, code: r.code } }).catch(() => {});
      err.write(`${program()}: not signed in: ${r.message}\n`);
      return 1;
    }
    const doc = { claudeAiOauth: { accessToken: r.login.accessToken, refreshToken: r.login.refreshToken, expiresAt: r.login.expiresAt, scopes: [...r.login.scopes], subscriptionType: null } };
    const bytes = Buffer.from(JSON.stringify(doc), "utf8");
    const s = k.sealLoginBytes({ plain: bytes, sealedFile, keys: act.keys, deviceBound: true, label: LOGIN_LABEL, box: act.box });
    bytes.fill(0);
    await audit({ type: "claude-code.login.new", actor: "enclawed-code", level: null, payload: s.ok ? { ok: true, key: String(s.keyId).split(":")[0] } : { ok: false, code: s.code } }).catch(() => {});
    if (!s.ok) {
      err.write(`${program()}: signed in, but the login could not be sealed: ${s.message}\n`);
      return 1;
    }
    out.write(`signed in; the login is sealed under the Enclaweder (${sealedFile}) and never written in plaintext\n`);
    return 0;
  } finally {
    act.release();
  }
}

/** `ecwctl login watch|resolve|new ...` */
export async function loginWatchCommand(args, ctx) {
  switch (args[0]) {
    case "watch":
      return watchCommand(args.slice(1), ctx);
    case "resolve":
      return resolveCommand(args.slice(1), ctx);
    case "new":
      return newLoginCommand(args.slice(1), ctx);
    default:
      throw new UsageError(WATCH_HELP.trim());
  }
}

// ------------------------------------------------------------ the launcher's session

/**
 * The launcher's login for a session (login-seal.mjs openLoginForSession),
 * with the watcher around it: a launch is refused while a login made outside
 * Enclawed Code is held, a plaintext login found now is taken out of Claude
 * Code's reach first, and while a session holds the device every login that
 * appears is sealed under it at once (the launch's activation).
 */
export async function openLoginForSession(o) {
  const env = o.env ?? process.env;
  const audit = o.audit ?? (async () => {});
  const guarded = personLoginGuarded();
  if (guarded && sealBound(env)) {
    // Managed login policy: a login that appeared since the last launch, out of Claude Code's reach before anything else.
    await sweepLogins({ env, audit, where: "launch" });
  }
  if (heldLoginsBlock(env)) {
    return { ok: false, code: "login-pending", message: pendingNotice(env) };
  }
  const opened = await openSealedLogin(o);
  if (opened.ok && opened.action === "relayed") {
    opened.env = env;
    opened.audit = audit;
  }
  if (opened.ok && opened.action === "relayed" && guarded) {
    ensureLoginWatcher({ env });
    // Command set 0.5: the launch's login box (it can only seal; the symmetric key is forgotten after start).
    // Without a box the forgotten key cannot seal (key-unavailable): the kit then quarantines instead.
    if (opened.box || opened.keys) {
      opened.loginWatch = startLoginWatch({ env, keys: opened.keys ?? {}, audit, where: "session", sealOptions: opened.box ? { box: opened.box } : {} });
    }
  }
  return opened;
}

function stopWatch(opened) {
  opened?.loginWatch?.close();
  if (opened) {
    opened.loginWatch = null;
  }
}

export async function closeLoginForSession(opened, opts) {
  stopWatch(opened);
  const r = await closeSealedLogin(opened, { ...(opts ?? {}), audit: opts?.audit ?? opened?.audit });
  if (r && opts?.halted && personLoginGuarded()) {
    // A halt asks for a fresh login: what the session held for the person goes too.
    for (const p of pendingLogins(opened.env ?? process.env)) {
      (kit.discardPendingCredential(p.file) ? r.erased : r.remaining).push(`held login ${p.file}`);
    }
  }
  return r;
}

export async function discardSessionLogin(opened, opts) {
  stopWatch(opened);
  return discardSealedLogin(opened, opts);
}
