// Rendering agent-controlled values inside Enclawed's own messages (round 5,
// E2): approval prompts, deny reasons and system messages. A path, command
// word, option, tool name or config line the agent supplied must never add
// lines or wording to that text.
//
// The rules (strip hidden and bidi code points, neutralize notice imitations,
// cap the length with a digest, JSON-quote with C1/separator escapes) are the
// Enclawed adapter kit's (adapter/untrusted.ts); this module only keeps the
// names Enclawed Code's modules import.

import { kit } from "./kit.mjs";

/**
 * One agent-controlled value, rendered safely for Enclawed's own messages.
 * @param {unknown} value
 * @param {{ max?: number }} [opts]  cap in code points
 * @returns {string} a JSON string literal, possibly followed by a note in parentheses
 */
export function quoteUntrusted(value, opts = {}) {
  return kit.quoteUntrusted(value, opts);
}

/** A path Enclawed computed: bare when plain printable ASCII, JSON-quoted otherwise. */
export function showPath(p) {
  return kit.showPath(p);
}

/** Free text mixing Enclawed's wording with outside values: hidden characters stripped, controls escaped, capped. Not quoted. */
export function sanitizeText(value, opts = {}) {
  return kit.sanitizeText(value, opts);
}
