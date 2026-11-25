// Helpers (systemd-run, systemctl, python3, perl, git, ps, ss, security) are
// run from fixed system directories, never looked up on the user's PATH: a
// `python3` shim early on PATH used to stand in for the subreaper wrapper and
// skip it, and a `git` shim could answer "tracked" for every file.
//
// Whether a helper is trusted is the kit's decision (trustedBinary,
// untrustedBinaryReason: the file it resolves to and every directory above
// both the link and the target owned by a system uid and not writable by
// group or other; inside a user namespace the overflow uid counts too). The
// suite's stand-in uids come from the test authority (authority.mjs
// testOwnership). One process caches each answer.

import { testOwnership } from "./authority.mjs";
import { kit } from "./kit.mjs";

const SYSTEM_BIN_DIRS = Object.freeze({
  linux: ["/usr/bin", "/bin", "/usr/sbin", "/sbin"],
  darwin: ["/usr/bin", "/bin", "/usr/sbin", "/sbin"],
});

const cache = new Map();

/** Why `file` is not a trusted executable, or null when it is (kit). */
export function untrustedReason(file, uids = kit.systemBinaryUids(testOwnership()?.trustedUids ?? [])) {
  return kit.untrustedBinaryReason(file, uids);
}

/**
 * The absolute path of a system helper, or null when none of the fixed
 * system directories holds a trusted copy (kit trustedBinary).
 */
export function trustedBinary(name, { platform = process.platform, dirs = SYSTEM_BIN_DIRS[platform] ?? [] } = {}) {
  const key = `${platform}\0${dirs.join("\0")}\0${name}`;
  if (cache.has(key)) {
    return cache.get(key);
  }
  const found = kit.trustedBinary(name, dirs, { testUids: testOwnership(platform)?.trustedUids ?? [] });
  cache.set(key, found);
  return found;
}

/** Forget cached answers (tests). */
export function clearTrustedBinaryCache() {
  cache.clear();
}
