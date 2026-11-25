#!/usr/bin/env node
// Release gate: refuse to publish Enclawed Code when a legal page it was
// reviewed against has changed since the review (docs/legal-review.md).
//
// legal/reviewed-terms.json lists each reviewed page with the SHA-256 of what
// it says, in one of two forms (`form`):
//   - "raw": the raw bytes the URL serves, for a page published in a stable
//     plain form (Claude Code's docs serve each page as Markdown at <page>.md);
//   - "html-text-v1": the normalized text of an HTML page (below), for pages
//     with no plain form (anthropic.com/legal serves HTML only).
// This script fetches every page, takes the same form and compares. Any difference, or a page that cannot be fetched, fails the
// check and names the page: the review is redone (docs/legal-review.md, "How a
// review is triggered and recorded") before the next publish. It runs from
// scripts/check-pack.mjs (npm's prepack, so every `npm pack` and `npm publish`)
// and from scripts/publish-public.sh. The runtime never fetches these pages.
//
// Normalization "html-text-v1" (deterministic, documented in docs/legal-review.md):
//   1. the page's <main> element when it has one, else its <body>, else the whole document;
//   2. HTML comments and every <script>, <style>, <noscript>, <template>, <svg>,
//      <iframe>, <head>, <nav>, <header> and <footer> element are removed with their content;
//   3. every remaining tag becomes a space; character references are decoded;
//   4. Unicode NFC, then every run of whitespace becomes one space, trimmed.
// The SHA-256 is of the UTF-8 bytes of that text. Scripts (which carry build ids
// and nonces), navigation, headers and footers are outside it; two fetches an
// hour apart gave the same fingerprints when the review was recorded.
//
//   node scripts/check-legal-terms.mjs            check (exit 0 all unchanged, 1 otherwise)
//   node scripts/check-legal-terms.mjs --print    print the current fingerprints (recording a new review)

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const TERMS_FILE = path.join(root, "legal", "reviewed-terms.json");
export const NORMALIZATION = "per-page-form-v1";
/** The forms a fingerprint may be taken in. */
export const FORMS = Object.freeze(["raw", "html-text-v1"]);
const FETCH_TIMEOUT_MS = 30_000;

const NAMED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", mdash: "—", ndash: "–", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", hellip: "…", copy: "©", reg: "®", trade: "™" };

function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (m, e) => {
    if (e[0] === "#") {
      const n = e[1] === "x" || e[1] === "X" ? Number.parseInt(e.slice(2), 16) : Number.parseInt(e.slice(1), 10);
      return Number.isInteger(n) && n >= 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
    }
    return NAMED[e] ?? m;
  });
}

/** The page's text under normalization text-v1 (see the header). */
export function normalizeTermsText(html) {
  let s = String(html);
  const region = /<main\b[^>]*>([\s\S]*)<\/main>/i.exec(s) ?? /<body\b[^>]*>([\s\S]*)<\/body>/i.exec(s);
  if (region) {
    s = region[1];
  }
  s = s.replace(/<!--[\s\S]*?-->/g, " ");
  for (const tag of ["script", "style", "noscript", "template", "svg", "iframe", "head", "nav", "header", "footer"]) {
    s = s.replace(new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}\\s*>`, "gi"), " ");
  }
  s = s.replace(/<[^>]*>/g, " ");
  s = decodeEntities(s).normalize("NFC");
  return s.replace(/\s+/g, " ").trim();
}

export function fingerprint(text) {
  return createHash("sha256").update(text, typeof text === "string" ? "utf8" : undefined).digest("hex");
}

/** The fingerprint of a fetched page (a Buffer) in `form`. */
export function pageFingerprint(bytes, form) {
  if (form === "raw") {
    return fingerprint(Buffer.from(bytes));
  }
  if (form === "html-text-v1") {
    return fingerprint(normalizeTermsText(Buffer.from(bytes).toString("utf8")));
  }
  throw new Error(`unknown fingerprint form ${JSON.stringify(form)}`);
}

/** The reviewed-terms record (legal/reviewed-terms.json). */
export function readReviewedTerms(file = TERMS_FILE) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

async function fetchPage(url) {
  const res = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), headers: { "user-agent": "enclawed-code-legal-terms-check" } });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

/**
 * Compare every reviewed page with what it is now. `fetchText(url)` returns the page's bytes
 * or text (the network by default). Returns the pages that differ or could not be fetched.
 * @returns {Promise<{ ok: boolean, pages: { url: string, ok: boolean, expected: string, actual: string | null, error: string | null }[] }>}
 */
export async function checkTerms({ terms = readReviewedTerms(), fetchText = fetchPage } = {}) {
  if (terms.normalization !== NORMALIZATION) {
    return { ok: false, pages: [{ url: "(legal/reviewed-terms.json)", ok: false, expected: NORMALIZATION, actual: String(terms.normalization), error: "recorded with another normalization" }] };
  }
  const pages = [];
  for (const p of terms.pages) {
    try {
      const actual = pageFingerprint(await fetchText(p.url), p.form);
      pages.push({ url: p.url, ok: actual === p.sha256, expected: p.sha256, actual, error: null });
    } catch (e) {
      pages.push({ url: p.url, ok: false, expected: p.sha256, actual: null, error: e?.message ?? String(e) });
    }
  }
  return { ok: pages.length > 0 && pages.every((x) => x.ok), pages };
}

async function main(argv) {
  const terms = readReviewedTerms();
  if (argv.includes("--print")) {
    for (const p of terms.pages) {
      const bytes = await fetchPage(p.url);
      process.stdout.write(`${pageFingerprint(bytes, p.form)}  ${p.form}  ${bytes.length} bytes  ${p.url}\n`);
    }
    return 0;
  }
  const r = await checkTerms({ terms });
  if (r.ok) {
    process.stdout.write(`check-legal-terms: ${r.pages.length} reviewed page(s) unchanged since the review of ${terms.reviewed}\n`);
    return 0;
  }
  const lines = r.pages.filter((x) => !x.ok).map((x) => (x.error ? `  - ${x.url}: could not be checked (${x.error})` : `  - ${x.url}: changed since the review of ${terms.reviewed} (now ${x.actual}, reviewed ${x.expected})`));
  process.stderr.write(`check-legal-terms: refusing to publish until the legal review is redone (docs/legal-review.md):\n${lines.join("\n")}\n`);
  return 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(await main(process.argv.slice(2)));
}
