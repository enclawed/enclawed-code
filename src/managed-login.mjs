// Plain `claude` cannot sign in or use a stored login on a managed install.
//
// With an Enclaweder bound, Enclawed Code keeps Claude Code's login sealed under
// the device and opens it only inside its own sessions, where claude reaches
// the provider through the kit's auth relay with a placeholder credential
// (login-seal.mjs). A person who signs in with plain `claude` leaves a
// plaintext login at rest that plain `claude` itself can use. On a machine
// whose administrator manages Claude Code's settings, this module installs a
// managed-settings drop-in that closes that for good; whether the documents
// Claude Code reads put it in force is the kit's decision
// (managed-login-policy.ts), the key names and values below are Claude Code's.
//
// What Claude Code 2.1.326 does (read from its own code, then run: the real
// binary in a private user, mount and network namespace with a private /etc,
// an isolated HOME holding a planted login, a stand-in provider; see
// test/managed-login.test.mjs and docs/enterprise.md):
//   - forceLoginOrgUUID set to [] in managed settings: every session with a
//     login of its own (stored, CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_API_KEY,
//     --bare) is refused at startup ("No organizations are permitted"), and a
//     completed `claude auth login` is refused before the new login is saved.
//     A session whose requests go over ANTHROPIC_UNIX_SOCKET (Enclawed Code's
//     relay) is not judged by it (its organization check returns kind
//     "unix_socket"). The machine's own managed file's organization pin
//     applies ahead of server-managed settings.
//   - env.CLAUDE_SECURESTORAGE_CONFIG_DIR pinned (managed env values replace
//     the user's, also against --settings): Claude Code reads and writes its
//     login only in that directory, which is empty and writable only by root,
//     so a login in ~/.claude (or CLAUDE_CONFIG_DIR) is never read or sent,
//     not even on the 401 recovery that otherwise adopts the stored login.
//   - env.DISABLE_LOGIN_COMMAND=1: /login is not offered.
//   - allowedProviders is NOT set: under it Claude Code refuses every session
//     over ANTHROPIC_UNIX_SOCKET, which would refuse Enclawed Code's relay.

import fs from "node:fs";
import path from "node:path";
import { authority } from "./authority.mjs";
import { parseFlags, UsageError } from "./cli-util.mjs";
import { kit } from "./kit.mjs";
import { readManagedSettings } from "./managed.mjs";
import { checkAdminFile } from "./opt-outs.mjs";

/** The drop-in's name: after the hooks template (50-enclawed-code.json), so its env pins win over earlier files. */
export const LOGIN_POLICY_FILE = "90-enclawed-code-login.json";
/** The empty, root-only directory Claude Code's login storage is pinned to (inside the managed-settings directory). */
export const NO_LOGIN_DIR = "enclawed-code-no-login";

/** What an earlier release installed under its own name (install and remove take it out). */
export const LEGACY_LOGIN_POLICY = Object.freeze([{ file: "90-codenclawed-login.json", dir: "codenclawed-no-login" }]);

/** Claude Code's pins (host data, from 2.1.326). */
export function loginPolicySpec(dir = authority().managedSettingsDir) {
  return {
    orgPinKey: "forceLoginOrgUUID",
    envKey: "env",
    storageDirVar: "CLAUDE_SECURESTORAGE_CONFIG_DIR",
    storageDir: path.join(dir, NO_LOGIN_DIR),
    envPins: { DISABLE_LOGIN_COMMAND: "1" },
  };
}

/** The drop-in file this command manages. */
export function loginPolicyFile(dir = authority().managedSettingsDir) {
  return path.join(dir, "managed-settings.d", LOGIN_POLICY_FILE);
}

/** The kit's decision over what Claude Code would read here. */
export function managedLoginPolicyStatus(dir = authority().managedSettingsDir) {
  const a = authority();
  return kit.managedLoginPolicyStatus(readManagedSettings(dir), loginPolicySpec(dir), {
    policyFile: loginPolicyFile(dir),
    fileCheck: (f) => checkAdminFile(f),
    dirProblem: (d) => kit.adminOnlyEmptyDirProblem(d, a.trustedUids),
  });
}

export const LOGIN_POLICY_HELP = `usage:
  ecwctl managed login-policy print     what install writes (nothing is changed)
  ecwctl managed login-policy status    whether Claude Code on this machine can sign in or use a stored login
  sudo ecwctl managed login-policy install   write it (root; idempotent; recorded in root's audit log)
  sudo ecwctl managed login-policy remove    take it out again (only what install wrote)

With it, plain \`claude\` can neither sign in nor use a login stored on this machine; Enclawed Code sessions reach
Claude through Enclawed Code's relay with the login sealed under the Enclaweder (needs the device bound). The person
signs in with: ecwctl login new
`;

/**
 * An earlier release's drop-in and storage directory, taken out only when the
 * file is exactly what that release's install wrote (and the directory empty).
 * @returns {{ removed: string[], kept: string[] }}
 */
function removeLegacyLoginPolicy(dir, spec, err) {
  const removed = [];
  const kept = [];
  for (const l of LEGACY_LOGIN_POLICY) {
    const file = path.join(dir, "managed-settings.d", l.file);
    const storageDir = path.join(dir, l.dir);
    let current = null;
    try {
      current = fs.readFileSync(file, "utf8");
    } catch {
      current = null;
    }
    if (current !== null) {
      const text = kit.planManagedLoginPolicy({ ...spec, storageDir }, { policyFile: file }).text;
      if (current !== text) {
        err.write(`ecwctl: ${file} (an earlier release's) is not the file its install wrote; remove it by hand after reviewing it\n`);
        kept.push(file);
        continue;
      }
      fs.rmSync(file);
      removed.push(file);
    }
    try {
      fs.rmdirSync(storageDir); // only when empty
      removed.push(storageDir);
    } catch (e) {
      if (e.code !== "ENOENT") {
        kept.push(storageDir);
      }
    }
  }
  return { removed, kept };
}

function describePlan(spec, file, plan) {
  const lines = [];
  lines.push(`${plan.dir === "create" ? "create" : "keep"} directory ${spec.storageDir} (owner root, mode 0555, stays empty)`);
  lines.push(`${plan.file === "write" ? "write" : "keep (unchanged)"} ${file} (owner root, mode 0644):`);
  lines.push(...plan.text.trimEnd().split("\n").map((l) => `    ${l}`));
  return `${lines.join("\n")}\n`;
}

/**
 * `ecwctl managed login-policy print|status|install|remove`.
 * `uid`: the effective uid (a test passes its own); `audit`: root's audit log.
 */
export async function loginPolicyCommand(args, { out, err, audit = async () => {}, uid = typeof process.geteuid === "function" ? process.geteuid() : -1, platform = process.platform }) {
  const sub = args[0];
  parseFlags(args.slice(1), { maxPositionals: 0 });
  const dir = authority(platform).managedSettingsDir;
  const spec = loginPolicySpec(dir);
  const file = loginPolicyFile(dir);
  if (sub === "status") {
    const s = managedLoginPolicyStatus(dir);
    out.write(s.installed ? `managed login policy: in force (${s.reason})\n` : `managed login policy: not in force (${s.reason})\n`);
    return s.installed ? 0 : 1;
  }
  if (sub !== "print" && sub !== "install" && sub !== "remove") {
    throw new UsageError(LOGIN_POLICY_HELP.trim());
  }
  if (platform !== "linux") {
    err.write("ecwctl: the managed login policy is for Linux (on macOS Claude Code keeps its login in the login Keychain; on Windows deliver managed settings through the Windows chain)\n");
    return 1;
  }
  const plan = kit.planManagedLoginPolicy(spec, { policyFile: file });
  if (sub === "print") {
    out.write(describePlan(spec, file, plan));
    return 0;
  }
  if (uid !== 0) {
    err.write(`ecwctl: ${sub} writes Claude Code's managed settings, which only root can: run it with sudo. Nothing was changed\n`);
    return 1;
  }
  if (sub === "remove") {
    let current = null;
    try {
      current = fs.readFileSync(file, "utf8");
    } catch {
      current = null;
    }
    if (current !== null && current !== plan.text) {
      err.write(`ecwctl: ${file} is not the file install writes (it was changed); remove it by hand after reviewing it. Nothing was changed\n`);
      return 1;
    }
    const removed = [];
    if (current !== null) {
      fs.rmSync(file);
      removed.push(file);
    }
    removed.push(...removeLegacyLoginPolicy(dir, spec, err).removed);
    try {
      fs.rmdirSync(spec.storageDir); // only when empty
      removed.push(spec.storageDir);
    } catch (e) {
      if (e.code !== "ENOENT") {
        err.write(`ecwctl: ${spec.storageDir} was kept (${e.code}): it is not empty; review it\n`);
      }
    }
    await audit({ type: "claude-code.managed.login-policy.removed", actor: "enclawed-code", level: null, payload: { file, removed } }).catch(() => {});
    out.write(removed.length ? `removed: ${removed.join(", ")}\nplain \`claude\` can sign in on this machine again\n` : "nothing to remove: the managed login policy is not installed\n");
    return 0;
  }
  // install
  out.write(describePlan(spec, file, plan));
  if (fs.existsSync(spec.storageDir)) {
    const p = kit.adminOnlyEmptyDirProblem(spec.storageDir, authority(platform).trustedUids);
    if (p) {
      err.write(`ecwctl: ${p}; it must be root's, empty and writable by nobody else (remove it and run install again). Nothing was changed\n`);
      return 1;
    }
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o755 });
  if (plan.dir === "create") {
    fs.mkdirSync(spec.storageDir, { mode: 0o555 });
    fs.chmodSync(spec.storageDir, 0o555);
  }
  if (plan.file === "write") {
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, plan.text, { mode: 0o644, flag: "wx" });
    fs.chmodSync(tmp, 0o644);
    fs.renameSync(tmp, file);
  }
  const legacy = removeLegacyLoginPolicy(dir, spec, err);
  for (const f of legacy.removed) {
    out.write(`removed the earlier release's ${f}\n`);
  }
  const s = managedLoginPolicyStatus(dir);
  await audit({ type: "claude-code.managed.login-policy.installed", actor: "enclawed-code", level: null, payload: { file, wrote: plan.file === "write", madeDir: plan.dir === "create", inForce: s.installed, code: s.code } }).catch(() => {});
  if (!s.installed) {
    err.write(`ecwctl: written, but the policy is NOT in force: ${s.reason}\n`);
    return 1;
  }
  out.write(plan.file === "none" && plan.dir === "none" ? "already installed; nothing changed\n" : "installed\n");
  out.write("plain `claude` on this machine can no longer sign in or use a stored login. People sign in with: ecwctl login new\n");
  out.write("Logins already made outside Enclawed Code still work elsewhere until revoked: ask people to sign out of other Claude Code sessions at claude.ai.\n");
  return 0;
}
