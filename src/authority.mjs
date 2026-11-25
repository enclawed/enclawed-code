// Where Enclawed Code's admin decisions come from, and the one test seam.
//
// Premise: the host is compromised at the uid that runs Enclawed Code, so
// nothing that uid can set (its environment, its files) decides an admin
// question. The admin's decisions live in root-owned files at fixed paths
// (opt-outs.mjs, policy.mjs); this module names those paths and the uids that
// count as root.
//
// The test seam. The suite needs its own stand-ins for /etc/enclawed and the
// managed policy (it cannot write there), and shorter timings than a real
// halt. They are set by `setTestAuthority`, a function call: no environment
// variable and no file reaches it, so a user install cannot turn it on (an
// earlier seam, ECWCODE_TEST_OPT_OUT_DIR, was an environment variable and
// was honored by every git-clone install). Only the suite's own entry points
// (test/fixtures/launcher-entry.mjs, and test files that run the launcher in
// process) call it; test/authority.test.mjs checks that nothing under src/ or
// bin/ does.

import { managedPolicyPath, managedSettingsDir } from "./paths.mjs";
import { kit } from "./kit.mjs";

/** The root-owned Enclawed policy directory. */
export const SYSTEM_POLICY_DIR = "/etc/enclawed";

/** Internal constants (not settings): see docs/commands.md, "Fixed behavior". */
// The security timings are Enclawed's (adapter kit constants), never Enclawed Code's.
export const HANDSHAKE_TIMEOUT_S = kit.HANDSHAKE_TIMEOUT_S;
export const ERASE_RECHECKS = kit.ERASE_RECHECKS;
export const ERASE_WATCH_S = kit.ERASE_WATCH_S;
export const APPROVAL_TTY = "/dev/tty";

let testAuthority = null;

function boundedInt(name, v, min, max) {
  if (!Number.isInteger(v) || v < min || v > max) {
    throw new TypeError(`test authority: ${name} must be an integer from ${min} to ${max}`);
  }
  return v;
}

/**
 * Test seam (see the header). `null` restores the real authority.
 * @param {null | { optOutDirs?: string[], managedPolicyPath?: string, managedSettingsDir?: string, managedHome?: string, trustedUids?: number[], ignoreUserNamespace?: boolean,
 *   prevalidate?: boolean, handshakeTimeoutS?: number, eraseRechecks?: number, eraseWatchS?: number, approvalTty?: string, approvalTimeoutS?: number,
 *   remoteConnect?: (host: string, port: number) => { host: string, port: number, ca?: string|Buffer }, loginWatchSpawn?: (o: { env: object }) => void }} cfg
 */
export function setTestAuthority(cfg) {
  if (cfg === null) {
    testAuthority = null;
    return;
  }
  const out = {};
  for (const [k, v] of Object.entries(cfg)) {
    switch (k) {
      case "optOutDirs":
        if (!Array.isArray(v) || v.some((d) => typeof d !== "string" || d === "")) {
          throw new TypeError("test authority: optOutDirs must be a list of directories");
        }
        out[k] = [...v];
        break;
      case "managedPolicyPath":
      case "managedSettingsDir":
      case "managedHome":
      case "approvalTty":
        if (typeof v !== "string" || v === "") {
          throw new TypeError(`test authority: ${k} must be a path`);
        }
        out[k] = v;
        break;
      case "trustedUids":
        if (!Array.isArray(v) || v.some((u) => !Number.isInteger(u) || u < 0)) {
          throw new TypeError("test authority: trustedUids must be a list of uids");
        }
        out[k] = [...v];
        break;
      case "ignoreUserNamespace":
      case "prevalidate":
        if (typeof v !== "boolean") {
          throw new TypeError(`test authority: ${k} must be true or false`);
        }
        out[k] = v;
        break;
      case "handshakeTimeoutS":
        out[k] = boundedInt(k, v, 1, 120);
        break;
      case "eraseRechecks":
        out[k] = boundedInt(k, v, 0, 30);
        break;
      case "eraseWatchS":
        out[k] = boundedInt(k, v, 0, 3600);
        break;
      case "approvalTimeoutS":
        out[k] = boundedInt(k, v, 1, 300);
        break;
      case "loginWatchSpawn":
        // The suite's stand-in for starting the login watcher process (login-watch.mjs); none is spawned under the suite otherwise.
        if (typeof v !== "function") {
          throw new TypeError("test authority: loginWatchSpawn must be a function");
        }
        out[k] = v;
        break;
      case "remoteConnect":
        // Where the remote MCP transport connects for a host (the suite's
        // HTTPS stand-in and its CA): the kit's RemoteConnect seam.
        if (typeof v !== "function") {
          throw new TypeError("test authority: remoteConnect must be a function");
        }
        out[k] = v;
        break;
      default:
        throw new TypeError(`test authority: unknown key ${k}`);
    }
  }
  testAuthority = Object.freeze(out);
}

/** True while a test authority is set. */
export function testAuthorityActive() {
  return testAuthority !== null;
}

/**
 * The effective authority: the real fixed paths and constants, or the test
 * stand-ins.
 */
export function authority(platform = process.platform) {
  const t = testAuthority ?? {};
  return {
    optOutDirs: t.optOutDirs ?? [SYSTEM_POLICY_DIR, managedSettingsDir(platform)],
    managedPolicyPath: t.managedPolicyPath ?? managedPolicyPath(platform),
    // Claude Code's managed-settings directory, and the home a managed hook
    // runs in (the account's own; the suite's stand-ins keep its hooks away
    // from the real ones).
    managedSettingsDir: t.managedSettingsDir ?? managedSettingsDir(platform),
    managedHome: t.managedHome ?? null,
    trustedUids: t.trustedUids ?? [0],
    ignoreUserNamespace: t.ignoreUserNamespace === true,
    prevalidate: t.prevalidate ?? true,
    handshakeTimeoutS: t.handshakeTimeoutS ?? HANDSHAKE_TIMEOUT_S,
    eraseRechecks: t.eraseRechecks ?? ERASE_RECHECKS,
    eraseWatchS: t.eraseWatchS ?? ERASE_WATCH_S,
    approvalTty: t.approvalTty ?? APPROVAL_TTY,
    // Only the suite shortens the prompt's wait (a function call, never a setting).
    approvalTimeoutMs: t.approvalTimeoutS ? t.approvalTimeoutS * 1000 : kit.APPROVAL_TIMEOUT_MS,
    remoteConnect: t.remoteConnect ?? null,
    loginWatchSpawn: t.loginWatchSpawn ?? null,
  };
}

/**
 * The suite's stand-in for root, in the kit's shape (kit TestOwnership), or
 * null outside the suite. Which uids own a trusted file, and what a non-initial
 * user namespace means, are the kit's rules (rootOwnedFileCheck,
 * trustedBinary); only the suite's stand-in uids come from here.
 */
export function testOwnership(platform = process.platform) {
  if (!testAuthorityActive()) {
    return null;
  }
  const a = authority(platform);
  return { trustedUids: a.trustedUids, ignoreUserNamespace: a.ignoreUserNamespace };
}
