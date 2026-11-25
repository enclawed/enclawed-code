// The administrator's grants: read only from a root-owned file, never from the
// user's shell or home directory. What a grant file may grant, whether it is
// trusted, and how several merge are Enclawed's (adapter kit:
// `parseAdminGrantDoc`, `resolveAdminGrants`, `rootOwnedFileCheck` over the
// framework's checkRootOwnedFile, `adminGrantWarnings`). Enclawed Code names
// where its files live and which retired variables it warns about:
//
//   /etc/enclawed/enclawed-code-opt-outs.json            (root-owned Enclawed policy dir)
//   <managed settings dir>/enclawed-code-opt-outs.json   (Claude Code's managed dir,
//                                                    /etc/claude-code on Linux;
//                                                    Claude Code ignores this file)
//
// and the pre-rename file names codenclawed-opt-outs.json and
// enclawde-opt-outs.json, under the same rules.
// The document (v 2): projectHooks / projectCommands (one repository entry by
// digest, project-grants.mjs), hooks (one user, plugin or --settings hook by
// digest), reducedContainment, hardwareRoot: "optional", forensicWebhook
// (https only) and loaderEnv. A file with an unknown key, a wrong type or
// another version grants nothing (reported; the launch goes on with the
// defaults). Every grant used is printed and recorded in the audit log.
//
// The env-var opt-outs of earlier builds (RETIRED_ENV) are gone: that
// behavior is fixed. A shell that still sets one gets a warning saying so.

import { SYSTEM_POLICY_DIR, authority, testOwnership } from "./authority.mjs";
import { kit } from "./kit.mjs";

export { SYSTEM_POLICY_DIR };
export const OPT_OUT_FILENAME = "enclawed-code-opt-outs.json";
/** The pre-rename file names, still read (compatibility; see the header). */
export const LEGACY_OPT_OUT_FILENAMES = Object.freeze(["codenclawed-opt-outs.json", "enclawde-opt-outs.json"]);
/** The oldest pre-rename file name (kept for callers of the single-name export). */
export const LEGACY_OPT_OUT_FILENAME = "enclawde-opt-outs.json";
export const GRANT_FILE_VERSION = kit.ADMIN_GRANT_VERSION;

/** Variables earlier builds read; now fixed behavior. The value is what replaced each. */
export const RETIRED_ENV = Object.freeze({
  CODENCLAWED_SCOPE: "the systemd scope is always used where available",
  CODENCLAWED_SUBREAPER: "the subreaper wrapper is always used where available",
  CODENCLAWED_APPROVAL_TTY: "approvals are always answered at /dev/tty",
  CODENCLAWED_ALLOW_PROJECT_OVERLAP: "a project directory that contains Enclawed Code's install or state is always refused",
  CODENCLAWED_ALLOW_PROJECT_HOOKS: `a repository hook needs a per-repository grant (projectHooks in ${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME})`,
  CODENCLAWED_ALLOW_PROJECT_COMMANDS: `a repository command needs a per-repository grant (projectCommands in ${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME})`,
  CODENCLAWED_ERASE_RECHECKS: "the credential re-check after a halt is fixed (5 checks)",
  CODENCLAWED_ERASE_WATCH_S: "the detached watch after a halt is fixed (60 s)",
  CODENCLAWED_HANDSHAKE_TIMEOUT_S: "the hook handshake timeout is fixed (30 s)",
  CODENCLAWED_APPROVAL_TIMEOUT_S: "the approval timeout is fixed (5 minutes): a security parameter is never a setting",
  CODENCLAWED_PREVALIDATE: "the interactive pre-validation always runs",
  CODENCLAWED_TEST_OPT_OUT_DIR: "the test suite's stand-in opt-out directory is not an environment variable any more; only /etc/enclawed and the managed settings directory are read",
});

/**
 * The admin-file check every root-owned input of Enclawed Code uses (the grant
 * files here, the managed policy in policy.mjs): the kit's (rootOwnedFileCheck
 * over the framework's checkRootOwnedFile: root ownership, never inside a user
 * namespace, nothing on Windows). While a test authority is set, the kit
 * applies the same rules to the suite's stand-in uids (authority.mjs
 * testOwnership).
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
export function checkAdminFile(file, { platform = process.platform } = {}) {
  return kit.rootOwnedFileCheck(platform, testOwnership(platform))(file);
}

/** Validate a forensic webhook URL: https, a host, no credentials (kit). */
export function parseForensicWebhook(v) {
  return kit.parseForensicWebhook(v);
}

/** Parse one grant document; throws on anything not exactly as documented (kit). */
export function parseGrantDoc(doc) {
  return kit.parseAdminGrantDoc(doc);
}

/**
 * Resolve the administrator's grants (kit resolveAdminGrants over Enclawed Code's
 * directories and file names).
 *
 * @returns {{ grants: { projectHooks: object[], projectCommands: object[], hooks: object[], reducedContainment: boolean, hardwareRoot: "optional"|null, forensicWebhook: string|null, loaderEnv: string[] },
 *   files: string[], retired: {name: string, value: string}[], notes: string[], sources: object, grantFiles: object }}
 */
export function resolveGrants(env = process.env, { platform = process.platform } = {}) {
  if (platform === "win32") {
    // No root-ownership check on Windows: no file is trusted, none is read.
    return kit.resolveAdminGrants({ dirs: [], fileNames: [], env, retiredEnv: RETIRED_ENV });
  }
  return kit.resolveAdminGrants({
    dirs: authority(platform).optOutDirs,
    fileNames: [OPT_OUT_FILENAME, ...LEGACY_OPT_OUT_FILENAMES],
    check: (file) => checkAdminFile(file, { platform }),
    env,
    retiredEnv: RETIRED_ENV,
  });
}

/** One-line warnings for the launcher's stderr (kit). */
export function grantWarnings(r) {
  return kit.adminGrantWarnings(r, RETIRED_ENV);
}
