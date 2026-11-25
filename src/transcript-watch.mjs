// Watch Claude Code's transcript for tool calls (red-team round 2, N1/N4).
//
// If Claude Code drops the settings file Enclawed Code generated (a value it
// rejects, a flag, a crash in its loader), no Enclawed Code hook runs at all, so
// nothing in the hook can notice. The launcher can: Claude Code writes every
// tool call to the session transcript (`<config dir>/projects/<cwd with
// every non-alphanumeric character replaced by "-">/<session>.jsonl`, and
// subagent transcripts below it). Each tool_use block carries the id that
// the PreToolUse hook would have reported to the launcher's control socket.
//
// The launcher stops claude when a tool call shows up
//   - before the session-start handshake: the hooks are not running;
//   - after it, when no verified hook reported that call's id and the call
//     produced a result that is not an error (a call refused before any hook
//     ran, such as an input that fails validation, is not a bypass).
//
// The transcript is written after the call starts, so this detects the
// first unchecked call; it does not prevent it. Launch modes without a
// transcript (`--no-session-persistence`) are refused by the launcher.

import { kit } from "./kit.mjs";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Claude Code's projects-directory name for a working directory. */
export function projectSlug(dir) {
  return dir.replace(/[^a-zA-Z0-9]/g, "-");
}

export function transcriptRoots(env, cwd) {
  const config = env.CLAUDE_CONFIG_DIR || path.join(env.HOME || os.homedir(), ".claude");
  const projects = path.join(config, "projects");
  const slugs = new Set([projectSlug(cwd)]);
  try {
    slugs.add(projectSlug(fs.realpathSync(cwd)));
  } catch {
    /* keep the plain form */
  }
  // Long paths are shortened by Claude Code (a prefix plus a hash): match on the prefix.
  return { projects, prefixes: [...slugs].map((s) => s.slice(0, 200)) };
}

function jsonlFiles(dir, depth, out = []) {
  let names;
  try {
    names = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const d of names) {
    const p = path.join(dir, d.name);
    if (d.isDirectory() && depth > 0) {
      jsonlFiles(p, depth - 1, out);
    } else if (d.isFile() && d.name.endsWith(".jsonl")) {
      out.push(p);
    }
  }
  return out;
}

/** tool_use ids and tool_result outcomes in one transcript line. */
export function parseTranscriptLine(line) {
  let r;
  try {
    r = JSON.parse(line);
  } catch {
    return { uses: [], results: [] };
  }
  const content = Array.isArray(r?.message?.content) ? r.message.content : [];
  const uses = [];
  const results = [];
  for (const b of content) {
    if (b?.type === "tool_use" && typeof b.id === "string") {
      uses.push({ id: b.id, name: typeof b.name === "string" ? b.name : null, input: b.input, cwd: typeof r?.cwd === "string" ? r.cwd : null, sessionId: typeof r?.sessionId === "string" ? r.sessionId : null });
    } else if (b?.type === "tool_result" && typeof b.tool_use_id === "string") {
      results.push({ id: b.tool_use_id, isError: b.is_error === true });
    }
  }
  return { uses, results, sessionId: typeof r?.sessionId === "string" ? r.sessionId : null };
}

/**
 * @param {{ env: object, cwd: string, onUse: (u: {id: string, name: string|null, file: string}) => void,
 *           onResult: (r: {id: string, isError: boolean, file: string}) => void, intervalMs?: number }} o
 * @returns {{ poll: () => void, stop: () => void }}
 */
export function watchTranscripts(o) {
  // Which transcript lines are this session's, read whole, is the kit's
  // (transcript-watch.ts); the directories and the line format are Claude Code's.
  const { projects, prefixes } = transcriptRoots(o.env, o.cwd);
  return kit.watchTranscripts({
    dirs: () => kit.prefixedDirs(projects, prefixes),
    depth: 3,
    extension: ".jsonl",
    parseLine: parseTranscriptLine,
    onUse: o.onUse,
    onResult: o.onResult,
  });
}
