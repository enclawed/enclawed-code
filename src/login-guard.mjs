// Whose Claude Code login Enclawed Code may act on.
//
// Enclawed Code never takes, moves, seals, quarantines or erases a login it did
// not create. The person's own Claude Code login in their own storage
// (`.credentials.json` in CLAUDE_SECURESTORAGE_CONFIG_DIR, else
// CLAUDE_CONFIG_DIR, else ~/.claude, of the person's environment) is shared
// by every plain `claude` they run; Enclawed Code's sessions use their own
// login, sealed under the Enclaweder (login-seal.mjs, `ecwctl login new`).
//
// The one exception is an administrator's choice: the managed login policy
// (managed-login.mjs: a root-owned drop-in in Claude Code's managed settings,
// installed with `sudo ecwctl managed login-policy install`), under which
// plain `claude` cannot sign in or use a stored login on this machine. Only
// while that policy is in force does Enclawed Code keep a plaintext login out
// of the person's storage (the watcher, the launch sweep, the halt erase).
// A user-level launch never turns it on.

import { claudeCredentialLocations } from "./credentials.mjs";
import { managedLoginPolicyStatus } from "./managed-login.mjs";

/** Is the administrator's managed login policy in force (the only thing that lets Enclawed Code act on the person's login)? */
export function personLoginGuarded() {
  try {
    return managedLoginPolicyStatus().installed === true;
  } catch {
    return false;
  }
}

/** The person's own Claude Code login files: this environment's location, and the default one. */
export function personLoginFiles(env = process.env) {
  return [...new Set([claudeCredentialLocations(env, "linux").file, claudeCredentialLocations({ HOME: env.HOME }, "linux").file])].sort();
}

/** The person's login files Enclawed Code may act on: none, unless the managed login policy is in force. */
export function guardedLoginFiles(env = process.env) {
  return personLoginGuarded() ? personLoginFiles(env) : [];
}
