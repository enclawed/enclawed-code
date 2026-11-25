// "Potentially malicious" warnings at Enclawed Code's prompt and in a denial.
//
// Only deterministic signals the kit and the framework already compute; never
// a model's judgment. A warning never changes a decision: the rule decides, and
// the warning only tells the person what the call looks like.
//
//   planted-instruction  a tool result Claude read earlier in this session held
//                        instruction-override text (the framework's DLP scanner,
//                        prompt-injection family; English phrasing only)
//   hidden-characters    ... or hidden characters the input cleaner removed
//   secret-target        the call reads or changes a credential or secret file
//                        (the kit's credential paths)
//   exec-config          the call changes execution configuration: code that
//                        runs later (git hooks, .envrc, .husky, .mcp.json,
//                        Claude settings: the kit's exec-config paths)
//   secret-send          the input of a call that leaves the machine (a fetch, a
//                        search, an MCP tool, a command) carries credential-shaped
//                        text (the kit's credential finder), or the kit's decision
//                        names a credential destination, a secret in the
//                        arguments or an environment dump

import path from "node:path";
import { framework, kit } from "./kit.mjs";
import { realpathNearest } from "./paths.mjs";
import { sanitizeText } from "./untrusted.mjs";

// The DLP scanner's patterns that address an agent's instructions (high precision on
// ordinary code and docs; template markers, credential mentions and `${...}` are not used).
const PLANTED_IDS = new Set([
  "prompt-injection-instruction",
  "prompt-injection-new-instructions",
  "prompt-injection-identity-override",
  "prompt-injection-agent-gaslighting",
  "prompt-injection-step-delegation",
  "prompt-injection-elevated-identity-claim",
  "prompt-injection-hidden-prompt-phrase",
  "prompt-injection-canonical-leak-phrase",
  "prompt-injection-comment-smuggled",
  "prompt-injection-jailbreak-tags",
  "prompt-injection-roleplay-as-malicious",
  "prompt-injection-exfiltration-request",
  "prompt-injection-cot-extraction",
]);
// Cleaner findings that are content hidden from a reader.
const HIDDEN_KINDS = new Set(["unicode-tag", "zero-width-run", "variation-selector-run", "bidi-control", "ansi-conceal", "ansi-cursor", "control-overwrite", "spoofed-notice", "hidden-html"]);
// Decision codes the kit gives a call that would carry secrets somewhere.
const SEND_CODES = new Set(["credential-destination", "secret-in-arguments", "environment-dump"]);
const LEAVES_MACHINE = new Set(["fetch", "search", "mcp", "shell"]);
const FILE_TOOLS = new Set(["Read", "Write", "Edit", "MultiEdit", "NotebookEdit"]);
const SCAN_MAX = 256 * 1024;

function leaves(v, out = [], depth = 0) {
  if (typeof v === "string") {
    out.push(v);
  } else if (v && typeof v === "object" && depth < 8) {
    for (const x of Array.isArray(v) ? v : Object.values(v)) {
      leaves(x, out, depth + 1);
    }
  }
  return out;
}

const lineAt = (text, index) => text.slice(0, Math.max(0, index)).split("\n").length;

/** Where a tool result came from, as the person would name it. */
function sourceOf(tool, input, cwd) {
  const i = input && typeof input === "object" ? input : {};
  if (FILE_TOOLS.has(tool) && typeof i.file_path === "string") {
    return { label: cwd && i.file_path.startsWith(`${cwd}/`) ? path.relative(cwd, i.file_path) : i.file_path, file: true };
  }
  if (typeof i.url === "string") {
    return { label: i.url, file: false };
  }
  if (typeof i.command === "string") {
    return { label: `the output of \`${i.command.slice(0, 60)}\``, file: false };
  }
  return { label: `the result of ${tool}`, file: false };
}

/**
 * The signals in one tool result Claude read (PostToolUse, before cleaning).
 * @returns {Array<{ kind: "planted-instruction"|"hidden-characters", source: string, line: number|null, ids: string[] }>}
 */
export function readSignals(tool, input, response, { cwd = null } = {}) {
  if (typeof tool !== "string") {
    return [];
  }
  const src = sourceOf(tool, input, cwd);
  const start = Number.isInteger(response?.file?.startLine) ? response.file.startLine : 1;
  const out = [];
  for (const kind of ["planted-instruction", "hidden-characters"]) {
    for (const text of leaves(response)) {
      const t = text.slice(0, SCAN_MAX);
      const found =
        kind === "planted-instruction"
          ? framework.dlpScan(t, { onOversize: "truncate" }).filter((f) => PLANTED_IDS.has(f.id))
          : kit.cleanText(t).findings.filter((f) => HIDDEN_KINDS.has(f.type));
      if (found.length) {
        const first = found.reduce((a, b) => (b.index < a.index ? b : a));
        out.push({
          kind,
          source: sanitizeText(src.label, { max: 200 }),
          line: src.file ? start - 1 + lineAt(t, first.index) : null,
          ids: [...new Set(found.map((f) => f.id ?? f.type))].sort(),
        });
        break;
      }
    }
  }
  return out;
}

/**
 * The signals of a call about to be decided (PreToolUse), from its own input.
 * @returns {Array<{ kind: "secret-target"|"exec-config"|"secret-send", path?: string, what?: string, kinds?: string[] }>}
 */
export function actionSignals(tool, input, { kind = null, cwd = null, home = null } = {}) {
  const i = input && typeof input === "object" ? input : {};
  const out = [];
  const abs = typeof i.file_path === "string" ? path.resolve(cwd ?? "/", i.file_path) : typeof i.notebook_path === "string" ? path.resolve(cwd ?? "/", i.notebook_path) : null;
  if (abs) {
    const hit = kit.credentialPathOf(abs, home);
    if (hit) {
      out.push({ kind: "secret-target", path: hit.path, what: hit.what });
    }
    if (tool !== "Read" && kit.isExecConfigPath(abs)) {
      out.push({ kind: "exec-config", path: abs });
    }
  } else if (typeof i.command === "string") {
    try {
      const hit = kit.commandReachesCredential({ realpathNearest }, i.command, cwd ?? "/", home);
      if (hit) {
        out.push({ kind: "secret-target", path: hit.path, what: hit.what });
      }
    } catch {
      /* a command the finder cannot read gives no signal */
    }
  }
  if (LEAVES_MACHINE.has(kind)) {
    const kinds = kit.redactCredentials(leaves(i).join("\n").slice(0, SCAN_MAX)).kinds;
    if (kinds.length) {
      out.push({ kind: "secret-send", kinds: [...new Set(kinds)].sort() });
    }
  }
  return out;
}

/** Signals from the kit's decision codes (known only once it decided). */
export function decisionSignals(codes = []) {
  const send = codes.filter((c) => SEND_CODES.has(c));
  return send.length ? [{ kind: "secret-send", codes: [...new Set(send)].sort() }] : [];
}

/** One merged, ordered list (one entry per kind; the latest planted read). */
export function mergeSignals(...lists) {
  const by = new Map();
  for (const s of lists.flat()) {
    if (s && typeof s.kind === "string" && !by.has(s.kind)) {
      by.set(s.kind, s);
    }
  }
  const order = ["planted-instruction", "hidden-characters", "secret-send", "secret-target", "exec-config"];
  return order.filter((k) => by.has(k)).map((k) => by.get(k));
}

const tilde = (p, home) => (home && typeof p === "string" && p.startsWith(`${home}/`) ? `~/${p.slice(home.length + 1)}` : p);

/** The prompt's warning lines, plain words: what it means. */
export function warningLines(signals, { home = null, cwd = null } = {}) {
  const rel = (p) => (cwd && typeof p === "string" && p.startsWith(`${cwd}/`) ? path.relative(cwd, p) : tilde(p, home));
  return signals.map((s) => {
    const when = s.last ? "just before this" : "earlier in this session";
    const at = s.line ? ` (line ${s.line})` : "";
    switch (s.kind) {
      case "planted-instruction":
        return `possible planted instruction: Claude read ${s.source} ${when}, and it contains text addressed to coding agents${at}. If you did not ask for this, deny it.`;
      case "hidden-characters":
        return `Claude read ${s.source} ${when}, and it held hidden text${at} (removed before Claude saw it). Such text is how instructions are planted; if you did not ask for this, deny it.`;
      case "secret-send":
        return "this call would send what looks like a credential off this machine. If you did not ask for this, deny it.";
      case "secret-target":
        return `this call reaches ${s.what ?? "a credential"} (${rel(s.path)}); planted instructions often aim at secrets.`;
      case "exec-config":
        return `this call changes ${rel(s.path)}, which holds code that runs later (execution configuration), outside this prompt.`;
      default:
        return null;
    }
  }).filter(Boolean);
}

/** The few words added to a denial's line for the person. */
export function denialSuffix(signals) {
  const k = new Set(signals.map((s) => s.kind));
  if (k.has("planted-instruction") || k.has("hidden-characters")) {
    return "it looked like a planted instruction";
  }
  if (k.has("secret-send")) {
    return "it looked like sending a credential off this machine";
  }
  if (k.has("secret-target")) {
    return "it reached a credential";
  }
  if (k.has("exec-config")) {
    return "it changed code that runs later";
  }
  return null;
}

/** What the audit record keeps (no content, no secret). */
export function signalRecord(signals) {
  return signals.map((s) => ({ kind: s.kind, ...(s.source ? { source: s.source } : {}), ...(s.line ? { line: s.line } : {}), ...(s.ids ? { ids: s.ids } : {}), ...(s.path ? { path: s.path } : {}), ...(s.what ? { what: s.what } : {}), ...(s.kinds ? { kinds: s.kinds } : {}), ...(s.codes ? { codes: s.codes } : {}) }));
}
