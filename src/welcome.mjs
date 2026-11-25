// What a launch says about routine, default state: nothing, except once.
//
// A launch prints only what the person must act on (a passkey page, a refusal,
// a question) or must know (something switched off for this session, a change
// made outside the agent). The default state (claude.ai connectors off, a
// project's files recorded at its first session) is said once, at the first
// interactive launch on this installation, and from then on by `ecwctl doctor`;
// each launch records it in the audit log.

import fs from "node:fs";
import path from "node:path";
import { appStateDir } from "./paths.mjs";
import { say } from "./program.mjs";

export const CONNECTORS_OFF_LINE =
  "claude.ai connectors are off (they would let tools act outside Enclawed's checks); to allow some, list them under enclawedCode.claudeAiConnectors with: ecwctl policy edit";

export const BYPASS_WELCOME_LINE =
  "Claude Code runs in bypass permissions mode (shown in its footer): its own permission gates decide nothing, and Enclawed Code's checks decide every call; choose another mode with --permission-mode, or with Shift+Tab in the session";

export const WELCOME_LINES = [
  "Enclawed Code checks every tool call before it runs; actions that cannot be undone are asked about at its own prompt in this terminal. This note is shown once; ecwctl doctor shows the setup any time.",
  CONNECTORS_OFF_LINE,
  BYPASS_WELCOME_LINE,
  "each project's files are recorded at its first session, so a change made outside the agent is reported at the next launch (review it with: ecwctl files)",
];

export function welcomeMarkerPath(env = process.env) {
  return path.join(appStateDir(env), "welcomed");
}

/**
 * The first interactive launch on this installation: the welcome block, and the
 * marker that keeps it from being shown again. Returns whether it was shown.
 */
export function welcomeOnce({ env = process.env, stderr, bypass = true }) {
  const marker = welcomeMarkerPath(env);
  if (fs.existsSync(marker)) {
    return false;
  }
  try {
    fs.mkdirSync(path.dirname(marker), { recursive: true, mode: 0o700 });
    fs.writeFileSync(marker, `${new Date().toISOString()}\n`, { mode: 0o600, flag: "wx" });
  } catch {
    // Written by another launch at the same time, or not writable: say nothing.
    return false;
  }
  for (const line of WELCOME_LINES.filter((l) => bypass || l !== BYPASS_WELCOME_LINE)) {
    say(stderr, line);
  }
  return true;
}

/** Say something once on this installation (marker <state>/claude-code/noted-<key>). */
export function noteOnce(env, key, fn) {
  const marker = path.join(appStateDir(env), `noted-${key}`);
  try {
    fs.mkdirSync(path.dirname(marker), { recursive: true, mode: 0o700 });
    fs.writeFileSync(marker, `${new Date().toISOString()}\n`, { mode: 0o600, flag: "wx" });
  } catch {
    return false;
  }
  fn();
  return true;
}
