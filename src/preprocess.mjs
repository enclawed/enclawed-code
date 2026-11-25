// The input cleaner's text pass: strips or flags hidden channels in text an
// agent reads (tag characters, invisible runs, bidi overrides, terminal
// escapes and overwrites, notice imitations; hidden HTML is flagged). The
// cleaner is the Enclawed adapter kit's `cleanText` (adapter/text-cleaner.ts),
// so every adapter cleans the same way; this module keeps the names
// Enclawed Code's tests and the steganography suite (test/stego) import.

import { kit } from "./kit.mjs";

/** What the model sees in place of content the cleaner could not finish. */
export const WITHHELD_MARKER = kit.WITHHELD_MARKER;

/** The technique families the cleaner is designed to catch. */
export const COVERED = kit.CLEANER_COVERED;

/** Kept for callers of the round-4 API: the plain "Enclawed" (no nonce is shown). */
export function noticeTag() {
  return "Enclawed";
}

/** The withheld marker (round-4 API; the nonce argument is ignored). */
export function withheldMarker() {
  return WITHHELD_MARKER;
}

/**
 * Clean one string.
 * @param {string} text
 * @param {{ budgetMs?: number, deadline?: number, maxRounds?: number }} [opts]
 * @returns {{ clean: string, findings: {type: string, index: number, count: number, note?: string}[], withheld?: true }}
 */
export function preprocess(text, opts = {}) {
  const { budgetMs, deadline, maxRounds } = opts;
  return kit.cleanText(text, { budgetMs, deadline, maxRounds });
}

/** Prefix "quoted-" to text imitating an Enclawed notice. @returns {{ text: string, at: number, count: number }} */
export function neutralizeNotices(s) {
  return kit.neutralizeNotices(s);
}
