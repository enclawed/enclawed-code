// The permission mode ecwcode starts Claude Code in.
//
// Enclawed Code's hooks decide every tool call deterministically. Claude Code's
// own gates are not deterministic (2.1.331 starts in "auto" mode, where a model
// classifier decides), so by default ecwcode starts Claude Code in
// bypassPermissions: Claude Code then asks nothing and decides nothing, and every
// call is allowed or denied by Enclawed's PreToolUse hook (an "ask" goes to
// Enclawed Code's own prompt, never to Claude Code's; with nobody to ask, -p or
// a background session, it is denied). Claude Code honors a PreToolUse deny in
// every mode, bypassPermissions included (test/bypass-real.test.mjs, with the
// real binary).
//
// The person's own choice wins (--permission-mode, --dangerously-skip-permissions
// on the command line), as with plain claude; Shift+Tab in the session stays
// theirs. An administrator's managed settings win over the default: with
// permissions.disableBypassPermissionsMode "disable", Claude Code starts in its
// default mode and its own prompts appear in addition to Enclawed Code's.

import { launchedPermissionMode } from "./launch-context.mjs";

export const DEFAULT_MODE = "bypassPermissions";

/** Do the managed settings turn bypassPermissions off? */
export function bypassDisabledBy(managedDocs = []) {
  return managedDocs.some((d) => d?.doc?.permissions?.disableBypassPermissionsMode === "disable");
}

/**
 * The mode ecwcode starts Claude Code in, and what it adds to claude's arguments.
 * @returns {{ mode: string|null, source: "person"|"enclawed-default"|"managed", add: string[], acceptBypass: boolean }}
 */
export function effectivePermissionMode(args = [], { managedDocs = [], env = process.env, uid = process.getuid?.() ?? null } = {}) {
  const chosen = launchedPermissionMode(args).mode;
  if (chosen) {
    return { mode: chosen, source: "person", add: [], acceptBypass: false };
  }
  if (bypassDisabledBy(managedDocs)) {
    return { mode: null, source: "managed", add: [], acceptBypass: false };
  }
  // Claude Code refuses bypass mode for root outside a deliberate sandbox
  // (2.1.331: uid 0 without IS_SANDBOX=1 or CLAUDE_CODE_BUBBLEWRAP exits).
  if (uid === 0 && env.IS_SANDBOX !== "1" && !env.CLAUDE_CODE_BUBBLEWRAP) {
    return { mode: null, source: "root", add: [], acceptBypass: false };
  }
  // The one-time bypass-mode confirmation is pre-accepted in this session's own
  // settings file only (flag settings, skipDangerousModePermissionPrompt), never
  // in the person's ~/.claude.
  return { mode: DEFAULT_MODE, source: "enclawed-default", add: ["--permission-mode", DEFAULT_MODE], acceptBypass: true };
}

/** One line for a launch where the administrator turned bypass off (said once), and for ecwctl doctor. */
export const MANAGED_NO_BYPASS_TEXT =
  "Claude Code starts in its own default permission mode, because the administrator's managed settings turn bypass mode off (permissions.disableBypassPermissionsMode): Claude Code's own permission prompts appear in addition to Enclawed Code's; to change it, an administrator edits the managed settings";

export const ROOT_NO_BYPASS_TEXT =
  "Claude Code starts in its own default permission mode, because it runs as root and Claude Code refuses bypass mode for root: Claude Code's own permission prompts appear in addition to Enclawed Code's; to change it, run ecwcode as your own user";

/** How ecwctl doctor names the effective mode. */
export function modeDoctorLine(m) {
  if (m.source === "managed") {
    return `permission mode: Claude Code's default. ${MANAGED_NO_BYPASS_TEXT}`;
  }
  if (m.source === "root") {
    return `permission mode: Claude Code's default. ${ROOT_NO_BYPASS_TEXT}`;
  }
  return `permission mode: ${DEFAULT_MODE} unless you pass --permission-mode (Claude Code's own gates decide nothing; Enclawed Code's hooks decide every call, and its own prompt asks you)`;
}
