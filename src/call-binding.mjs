// Binding a hook decision to the tool call it was made for (red-team round
// 3, N9 c).
//
// The launcher's control socket used to accept "I decided tool_use X" from
// any verified hook process. In N9 a process run as a descendant of claude
// ran Enclawed Code's GENUINE hook command on a fabricated `Read README.md` input
// carrying the id of a Bash call it read from the transcript: the peer check
// passed (real node, exact argv), the launcher marked the Bash call decided,
// and the log said Read where a Bash command ran.
//
// So the hook now reports, with the id, the tool name and a digest of each
// top-level key of the tool input it decided on, and the launcher accepts
// the decision only for a tool_use it has seen in the transcript with the
// same name and the same input. Claude Code hands hooks a slightly different
// input than it writes to the transcript (its backfillObservableInput turns a
// relative or ~ `file_path`/`notebook_path` into an absolute one, and some
// tools add derived fields), so the comparison is per key: every key the
// transcript's input has must be in the hook's input with an equal value,
// where a path key may instead be the absolute form of the transcript's
// relative or ~ path (the hook sends those path values themselves). Extra
// keys the hook sees are allowed. A forger therefore has to hand the genuine
// hook the call's real input, and then the decision is the real one.
//
// The binding and both comparisons are the kit's (bindingOf, bindingMatches,
// contextMatches); this file keeps Claude Code's specifics: the hook input's
// field names and the launch context (its permission modes and its
// scratchpad layout) as data.

import path from "node:path";
import { MODE_ORDER } from "./claude-prompt.mjs";
import { kit } from "./kit.mjs";

/**
 * What the hook reports about the input it decided on: a digest per
 * top-level key, and the raw value of the path keys (kit.bindingOf).
 * @returns {{ keys: Record<string, string>, paths: Record<string, string> }}
 */
export function bindingOf(toolInput) {
  return kit.bindingOf(toolInput);
}

/**
 * Does the hook's report match the transcript's tool_use? (kit.bindingMatches)
 * @param {{ tool: string|null, binding: { keys: object, paths: object } }} reported
 * @param {{ name: string|null, input: unknown, cwd?: string|null }} seen
 * @returns {{ ok: true } | { ok: false, code: "tool-name-mismatch"|"tool-input-mismatch", reason: string }}
 */
export function bindingMatches(reported, seen, { cwd = null, home = null } = {}) {
  return kit.bindingMatches(reported, seen, { cwd, home });
}

// ------------------------------------------------------------------ call context (round 5)

/**
 * What the hook reports about the context it decided in, besides the input:
 * the working directory, the permission mode and the scratchpad (sent with
 * every `pre`; this is the control socket's wire shape).
 */
export function contextOf(input) {
  const str = (v) => (typeof v === "string" ? v.slice(0, 4096) : null);
  return { cwd: str(input?.cwd), permissionMode: str(input?.permission_mode), scratchpadDir: str(input?.scratchpad_dir), sessionId: str(input?.session_id) };
}

/** Claude Code's launch context (launch-context.mjs) as the kit's LaunchContext. */
export function kitLaunchContext(launch) {
  return {
    cwd: launch.cwd,
    realpath: launch.realpath,
    modes: launch.modes,
    bypassMode: "bypassPermissions",
    bypassAvailable: launch.bypassAvailable,
    launchedMode: launch.launchedMode ?? null,
    planMode: "plan",
    // A stricter mode than launched (Claude Code fell back by itself, e.g. auto
    // unavailable for the model) is a downgrade, not a mismatch.
    modeOrder: MODE_ORDER,
    headless: Boolean(launch.print),
    // Claude Code's scratchpad: <tmp>/claude-<uid>/<slug of the session dir>/<session id>/scratchpad.
    scratchpadFor: (sid) => (launch.uid === null || launch.uid === undefined ? null : (launch.scratchRoots ?? []).map((root) => path.join(root, `claude-${launch.uid}`, launch.slug(launch.cwd), sid, "scratchpad"))),
  };
}

/**
 * Does the reported context match what the launcher knows? (kit.contextMatches)
 * @param {{ cwd: string|null, permissionMode: string|null, scratchpadDir: string|null, sessionId: string|null }} reported
 * @param {{ cwd?: string|null, sessionId?: string|null }} seen
 * @param {{ cwd: string, realpath: (p: string) => string, modes: string[], launchedMode: string|null, print: boolean, bypassAvailable: boolean, scratchRoots: string[], uid: number|null, slug: (d: string) => string }} launch
 * @returns {{ ok: true, downgraded?: { launched: string, reported: string } } | { ok: false, code: "context-mismatch", reason: string }}
 */
export function contextMatches(reported, seen, launch) {
  const r = reported ? { cwd: reported.cwd ?? null, mode: reported.permissionMode ?? null, scratchpadDir: reported.scratchpadDir ?? null, sessionId: reported.sessionId ?? null } : null;
  return kit.contextMatches(r, seen, kitLaunchContext(launch));
}
