// Where Claude Code keeps its login, and erasing it without reading it. On a
// hardware halt Enclawed Code erases only the session's own login storage
// (claude-login.mjs: the directory Claude Code was given for Enclawed Code's
// sessions), never the person's own login: after an Enclaweder is detached
// (or reports tampering), restoring needs the genuine device and the operator
// (`ecwctl recover-root`), Enclawed Code's activation auth, and a fresh
// sign-in through Claude Code's own /login.
//
// Where Claude Code keeps its login (read from Claude Code 2.1.326's own code,
// not assumed):
//   - a file `.credentials.json` in its secure-storage dir: CLAUDE_SECURESTORAGE_CONFIG_DIR
//     when set (empty means ~/.claude), else CLAUDE_CONFIG_DIR, else ~/.claude;
//   - on macOS, the login Keychain item with account $USER and service
//     "Claude Code-credentials", suffixed with "-" and the first 8 hex digits
//     of sha256(dir) when CLAUDE_CONFIG_DIR (or CLAUDE_SECURESTORAGE_CONFIG_DIR)
//     is set.
// The locations are resolved from the LAUNCHER's environment, never from a
// settings file's `env`.
//
// Limits, stated plainly: the file is overwritten once with random bytes and
// then removed, but on SSDs, copy-on-write and journaling filesystems an
// overwrite is not guaranteed to reach the old blocks. Erasing the local copy
// does not revoke the token at Anthropic: a copy taken earlier keeps working
// until it is revoked at claude.ai. It logs out every Claude Code session on
// this machine that uses the same storage, not only Enclawed Code's. API keys in
// the environment (ANTHROPIC_API_KEY) or an apiKeyHelper are not touched.

import { spawnSync } from "node:child_process";
import { kit } from "./kit.mjs";
import { trustedBinary } from "./trusted-bin.mjs";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";

/** The storage dir and Keychain service Claude Code uses for this environment. */
export function claudeCredentialLocations(env = process.env, platform = process.platform) {
  const home = env.HOME || os.homedir();
  const secure = env.CLAUDE_SECURESTORAGE_CONFIG_DIR;
  const dir =
    secure !== undefined
      ? (secure || path.join(home, ".claude")).normalize("NFC")
      : (env.CLAUDE_CONFIG_DIR || path.join(home, ".claude")).normalize("NFC");
  const suffixed = secure !== undefined ? Boolean(secure) : Boolean(env.CLAUDE_CONFIG_DIR);
  const service = `Claude Code-credentials${suffixed ? `-${createHash("sha256").update(dir).digest("hex").slice(0, 8)}` : ""}`;
  let account = env.USER;
  if (!account) {
    try {
      account = os.userInfo().username;
    } catch {
      account = "claude-code-user";
    }
  }
  if (!/^[a-zA-Z0-9._-]+$/.test(account)) {
    account = "claude-code-user";
  }
  return {
    file: path.join(dir, ".credentials.json"),
    keychain: platform === "darwin" ? { service, account } : null,
  };
}

/**
 * Erase and verify (the kit's eraseCredentials decides what is erased and
 * checks it is gone; the macOS Keychain call is Claude Code's platform
 * store). Never returns secret values.
 * @returns {{ erased: string[], remaining: string[], notes: string[] }}
 */
export function eraseClaudeCredentials({ env = process.env, platform = process.platform, run = spawnSync } = {}) {
  const loc = claudeCredentialLocations(env, platform);
  const r = kit.eraseCredentials({ files: [loc.file], ...(loc.keychain ? { platform: { erase: () => eraseKeychain(loc.keychain, platform, run) } } : {}) });
  const notes = [];
  if (env.ANTHROPIC_API_KEY) {
    notes.push("ANTHROPIC_API_KEY is set in the environment; Enclawed Code cannot erase it");
  }
  return { erased: r.erased, remaining: r.remaining, notes };
}

// The login Keychain item (macOS): /usr/bin/security only (trusted-bin.mjs), never a PATH lookup.
function eraseKeychain({ service, account }, platform, run) {
  const erased = [];
  const remaining = [];
  const security = trustedBinary("security", { platform }) ?? "/usr/bin/security";
  for (let i = 0; i < 10; i++) {
    const r = run(security, ["delete-generic-password", "-a", account, "-s", service], { stdio: "ignore", timeout: 10_000 });
    if (r.status !== 0) {
      break;
    }
    if (i === 0) {
      erased.push(`keychain ${service} (${account})`);
    }
  }
  const still = run(security, ["find-generic-password", "-a", account, "-s", service], { stdio: "ignore", timeout: 10_000 });
  if (still.status === 0) {
    remaining.push(`keychain ${service} (${account})`);
  }
  return { erased, remaining };
}
