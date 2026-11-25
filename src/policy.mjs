// Load the Enclawed policy for Claude Code: the `enclawed.policy` block of a
// policy file, layered on the flavor default (open: allowlists not enforced;
// enclaved: deny by default), with Enclawed Code's options from the top-level
// `enclawedCode` block. Which file governs, how a user file layers over the
// organization's, and what a user file may not widen are Enclawed's (adapter
// kit `layerPolicies`, `layerUserPolicy` over the framework's tightenPolicy,
// `parseAdapterOptions`, `tightenAdapterOptions`).
//
// The files (the launcher resolves the list once; see session.mjs
// policyCandidates):
//   managed           the organization-wide policy (paths.mjs managedPolicyPath).
//                     It must be root-owned (opt-outs.mjs checkAdminFile); a
//                     managed file that exists but fails the check refuses the
//                     start. Only this file may set the flavor:
//                     { "enclawedCode": { "flavor": "enclaved" } }.
//   then the user's own policy, the first of these that exists:
//   launcher-env      ENCLAWED_CONFIG_PATH in the environment `ecwcode` was
//                     started from (the user's own shell).
//   policy-use        the file named by `ecwctl policy use <path>`.
//   enclawed-code-user  ~/.enclawed/claude-code/enclawed.json, Enclawed Code's own
//                     policy (written by `ecwctl policy init`).
//   gateway           the Enclawed gateway's config lookup (~/.enclawed/enclawed.json
//                     and its legacy names); read, never written, by Enclawed Code.
//                     Shared with another program: in the open flavor a broken
//                     one falls back to the base instead of refusing the start.
//
// Enclawed Code's options block:
//   { "enclawedCode": { "onHardwareHalt": { "eraseClaudeCredentials": false }, "inputCleaner": "on",
//                      "auth": {...}, "skills": {...}, "claudeAiConnectors": [...],
//                      "overwritablePaths": [...], "workflows": {...}, "projectWorkflows": {...} } }
// (the pre-rename names `codenclawed` and `enclawde` are still read). The kit's options are
// mapped to and from this block's names here.

import os from "node:os";
import { kit } from "./kit.mjs";
import { checkAdminFile } from "./opt-outs.mjs";

// The options block's names before the renames (see optionsBlock), newest first.
const LEGACY_OPTIONS_KEYS = Object.freeze(["codenclawed", "enclawde"]);
const LOWERCASED_LISTS = ["allowedTools", "allowedHosts", "preApprovedIrreversibleTools"];

/** How Enclawed Code's options block names the kit's options (host data). */
const OPTION_NAMES = Object.freeze({
  block: "enclawedCode",
  legacyBlocks: [...LEGACY_OPTIONS_KEYS],
  eraseKey: "eraseClaudeCredentials",
  connectorsKey: "claudeAiConnectors",
  // claude.ai connectors (account-level MCP servers, tools mcp__claude_ai_*).
  connectorPattern: /^mcp__claude_ai_[^*]+__(\*|[^*]+)$/,
});

/** Policy candidate kinds shared with another program (the gateway's config). */
const SHARED_KINDS = Object.freeze(["gateway"]);

/**
 * Lowercase the lists of a policy document (for writers: `policy init`
 * writes them as they are compared). The framework's loader normalizes them
 * the same way when it reads a file.
 */
export function normalizePolicyDoc(doc) {
  const policy = doc?.enclawed?.policy;
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    return doc;
  }
  const next = { ...policy };
  for (const key of LOWERCASED_LISTS) {
    if (Array.isArray(next[key])) {
      next[key] = next[key].map((v) => (typeof v === "string" ? v.trim().toLowerCase() : v));
    }
  }
  return { ...doc, enclawed: { ...doc.enclawed, policy: next } };
}

/**
 * Parse a policy document over the flavor default (kit parsePolicyDocument:
 * the framework's loader, with the history limits bounded by the kit's
 * internal constants). `_fw` is kept for callers that pass the framework.
 */
export function parsePolicyDoc(_fw, doc, flavor) {
  return kit.parsePolicyDocument(doc, flavor === "enclaved" ? "enclaved" : "open");
}

/** The kit's options in Enclawed Code's names (what the launcher, the hook and the CLI read). */
function fromKitOptions(o) {
  return {
    onHardwareHalt: { eraseClaudeCredentials: o.eraseCredentialsOnHalt },
    auth: { method: o.authMethod, required: true, unlockMinutes: o.unlockMinutes },
    inputCleaner: o.inputCleaner,
    skills: { ...o.skills },
    claudeAiConnectors: [...o.connectors],
    workflows: { ...o.workflows },
    projectWorkflows: { ...o.projectWorkflows },
    overwritablePaths: [...o.overwritablePaths],
    flavor: o.flavor,
  };
}

export const DEFAULT_OPTIONS = Object.freeze(fromKitOptions(kit.DEFAULT_ADAPTER_OPTIONS));

/**
 * The top-level options block: `enclawedCode`, or, in a policy file written
 * before a rename, `codenclawed` or `enclawde` (still read; a file with more
 * than one is an error, since nothing says which one is meant).
 */
export function optionsBlock(doc) {
  const has = (k) => doc && typeof doc === "object" && Object.hasOwn(doc, k);
  const present = ["enclawedCode", ...LEGACY_OPTIONS_KEYS].filter(has);
  if (present.length > 1) {
    throw new Error(`the policy file has more than one options block (${present.join(", ")}); merge them into enclawedCode`);
  }
  return present.length ? doc[present[0]] : undefined;
}

/** A copy of `doc` whose pre-rename options block is now the `enclawedCode` block (for writers). */
export function migrateOptionsBlock(doc) {
  if (!doc || typeof doc !== "object" || Object.hasOwn(doc, "enclawedCode")) {
    return doc;
  }
  const legacy = LEGACY_OPTIONS_KEYS.filter((k) => Object.hasOwn(doc, k));
  if (legacy.length !== 1) {
    return doc;
  }
  const { [legacy[0]]: block, ...rest } = doc;
  return { ...rest, enclawedCode: block };
}

/** Enclawed Code's own options from the top-level `enclawedCode` block (kit parseAdapterOptions); throws on a wrong type. `managed`: the organization's file, the only one that may set `flavor`. */
export function parseOptions(doc, { managed = false } = {}) {
  return fromKitOptions(kit.parseAdapterOptions(optionsBlock(doc), { ...OPTION_NAMES, managed }));
}

// The kit names a refused option by its own name; the user's file has Enclawed Code's.
const connectorsRefused = new RegExp(`^${OPTION_NAMES.block}\\.connectors\\b`);

/**
 * @param {any} fw
 * @param {{ candidates: Array<{kind: string, path: string}>, flavor?: "open"|"enclaved"|null }} opts
 *   `flavor`: what the user's shell asks for (env-authority.mjs shellFlavor); it can only raise the managed policy's.
 * @returns {{ policy: any, options: any, flavor: string, source: string, kind: string|null, note: string|null, refused: string[], baseSource: string }}
 */
export function loadPolicy(fw, { candidates, flavor = null }) {
  const r = kit.layerPolicies({ candidates, shellFlavor: flavor, names: OPTION_NAMES, sharedKinds: SHARED_KINDS, check: (file) => checkAdminFile(file) });
  return {
    policy: r.policy,
    options: fromKitOptions(r.options),
    flavor: r.flavor,
    source: r.source,
    kind: r.kind,
    note: r.note,
    refused: r.refused.map((x) => x.replace(connectorsRefused, `${OPTION_NAMES.block}.${OPTION_NAMES.connectorsKey}`)),
    baseSource: r.baseSource,
  };
}

/**
 * The policy with Claude Code's session scratchpad added to its scratch
 * paths, where history is irrelevant; which candidates are safe is the kit's
 * decision (isSafeScratchDir: never the project, a protected path, the home
 * directory or the root, nor anything containing them).
 */
export function withScratch(_fw, policy, extra, { home = os.homedir(), projectDir = null, protectedList = [] } = {}) {
  return kit.withScratchPaths(policy, extra, { home, projectDir, protectedPaths: protectedList });
}
