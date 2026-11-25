// The input cleaner: PostToolUse removes hidden characters from what a tool
// returned, before the model reads it.
//
// The cleaning, the work caps, the fail-safe withholding, the audit record
// and the out-of-band notice are the Enclawed adapter kit's `cleanToolResult`
// (adapter/output-cleaner.ts). Enclawed Code supplies only Claude Code data:
// which tools' results reach the model and get cleaned. The hook delivers the
// returned `note` as PostToolUse `additionalContext` (never inside the tool
// output) and `output` as `hookSpecificOutput.updatedToolOutput`.
//
// Out of reach of any hook: CLAUDE.md and other context Claude Code loads
// itself, the user's own prompt, and images. The action gate still decides on
// what the agent then tries to do, whatever the channel.

import { kit } from "./kit.mjs";

export const CLEANER_MODES = kit.CLEANER_MODES;
export const DEFAULT_CLEANER_MODE = kit.DEFAULT_CLEANER_MODE;

// Claude Code tools whose results the cleaner reads (data, not a decision).
const CLEANED_TOOLS = new Set(["Read", "WebFetch", "WebSearch", "Bash"]);
const CLEANED_PREFIXES = ["mcp__"];

/** Tools whose results the cleaner reads. */
export function cleanerApplies(tool) {
  return typeof tool === "string" && (CLEANED_TOOLS.has(tool) || CLEANED_PREFIXES.some((p) => tool.startsWith(p)));
}

/** Enclawed's out-of-band notice about a cleaned result (round 5, E1/E5). */
export function cleanerNotice(tool, r) {
  return kit.cleanerNotice(tool, r);
}

/**
 * Clean one tool result.
 * @param {string} tool
 * @param {unknown} response  the PostToolUse `tool_response`
 * @param {"on"|"off"|"audit"} mode
 * @param {{ maxLeafChars?: number, maxCallChars?: number, callBudgetMs?: number, leafBudgetMs?: number }} [limits]
 * @returns {{ changed: boolean, output?: unknown, note?: string, audit: object|null }}
 */
export function cleanToolResponse(tool, response, mode = DEFAULT_CLEANER_MODE, limits = {}) {
  if (!cleanerApplies(tool)) {
    return { changed: false, audit: null };
  }
  const { maxLeafChars, maxCallChars, callBudgetMs, leafBudgetMs } = limits ?? {};
  return kit.cleanToolResult(tool, response, mode, { maxLeafChars, maxCallChars, callBudgetMs, leafBudgetMs });
}
