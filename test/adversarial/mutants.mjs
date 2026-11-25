// Mutation check for the offline layer: copy this install, break one piece
// of the gate on purpose, and run the same offline scenarios against the
// broken copy. A harness that still passes against a broken gate proves
// nothing, so every mutant here must make at least one scenario fail.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Each mutant: a file, an exact string that must be present, and what replaces it. */
// Every security decision is Enclawed's (the adapter kit inside the built
// framework), so the decision mutants break the KIT in a copy of the built
// framework: if Enclawed Code still passed with them, it would not be passing
// because of Enclawed. The remaining mutants break what Enclawed Code itself
// owns: its Claude Code tool table, its no-person mode, its settings, its
// audit sink, its transcript reconcile.
const KIT_DIR = ".enclawed-dev/framework";
// The bundler splits the framework into chunks; each mutant names the chunk
// that holds the code it breaks (found by that code), so a re-chunked build
// does not silently stop mutating it.
const APP = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
function kitFileWith(text) {
  try {
    for (const f of fs.readdirSync(path.join(APP, KIT_DIR)).filter((n) => n.endsWith(".js")).sort()) {
      if (fs.readFileSync(path.join(APP, KIT_DIR, f), "utf8").includes(text)) {
        return `${KIT_DIR}/${f}`;
      }
    }
  } catch {
    /* not built: the mutant reports its code missing */
  }
  return `${KIT_DIR}/framework.js`;
}

export const MUTANTS = [
  {
    id: "kit-force-allow",
    what: "the kit's decidePreAction answers allow for every call",
    file: kitFileWith("async function decidePreAction(event, opts) {\n\tvalidatePreAction(event);"),
    find: "async function decidePreAction(event, opts) {\n\tvalidatePreAction(event);",
    replace: 'async function decidePreAction(event, opts) {\n\treturn { outcome: "allow", reason: "mutant", codes: ["mutant"], capability: null, reversible: true };\n\tvalidatePreAction(event);',
  },
  {
    id: "kit-no-exec-config",
    what: "the kit's isExecConfigPath is always false (git hooks, settings, .envrc treated as ordinary files)",
    file: kitFileWith("function isExecConfigPath(absPath, extra = {}) {\n"),
    find: "function isExecConfigPath(absPath, extra = {}) {\n",
    replace: "function isExecConfigPath(absPath, extra = {}) {\n\treturn false;\n",
  },
  {
    id: "bypass-asks",
    what: "bypassPermissions is not mapped to a session with no person to ask",
    file: "src/gate.mjs",
    find: "const NO_PERSON_MODES = new Set(MODE_ORDER.noPersonModes);",
    replace: "const NO_PERSON_MODES = new Set([]);",
  },
  {
    id: "kit-ignore-hardware",
    what: "the kit ignores the hardware root's answer",
    file: kitFileWith("\treturn hw.allowed ? null : deny([hw.code], `hardware root halt:"),
    find: "\treturn hw.allowed ? null : deny([hw.code], `hardware root halt:",
    replace: "\treturn true ? null : deny([hw.code], `hardware root halt:",
  },
  {
    id: "kit-shell-all-readonly",
    what: "the kit classifies every shell command read-only",
    file: kitFileWith('\tif (verdict.readOnly) return allow(["read-only-command"]'),
    find: '\tif (verdict.readOnly) return allow(["read-only-command"]',
    replace: '\tif (true) return allow(["read-only-command"]',
  },
  {
    id: "kit-no-snapshot",
    what: "the kit allows writes without keeping the previous content",
    file: kitFileWith("\tconst outcome = await (opts.history.prepare ?? prepareFsWriteHistory)({"),
    find: "\tconst outcome = await (opts.history.prepare ?? prepareFsWriteHistory)({",
    replace: '\tconst outcome = { reversible: true, targets: resolved.map(() => ({ basis: "scratch", reversible: true })) };\n\tconst _unused = await (async () => ({}))({',
  },
  {
    id: "mcp-allowed",
    what: "Enclawed Code's tool table maps MCP tools to reads",
    file: "src/tools.mjs",
    find: '  if (name.startsWith("mcp__")) {\n    return "mcp";\n',
    replace: '  if (name.startsWith("mcp__")) {\n    return "read";\n',
  },
  {
    id: "kit-webfetch-no-allowlist",
    what: "the kit's retrieval rule ignores enclawed.policy.allowedHosts",
    file: kitFileWith("\tif (policy.enforceAllowlists || policy.allowedHosts.size > 0) return deny([\"host-not-allowlisted\"]"),
    find: "\tif (policy.enforceAllowlists || policy.allowedHosts.size > 0) return deny([\"host-not-allowlisted\"]",
    replace: "\tif (false) return deny([\"host-not-allowlisted\"]",
  },
  {
    id: "hooks-can-be-disabled",
    what: "the generated settings no longer force disableAllHooks off",
    file: "src/settings.mjs",
    find: "  merged.disableAllHooks = false;\n",
    replace: "",
  },
  {
    id: "no-audit",
    what: "Enclawed Code's audit sink drops the kit's records",
    file: "src/hook.mjs",
    find: "        return await ctx.audit.append({\n          type: rec.type,",
    replace: "        return null;\n        void ({\n          type: rec.type,",
  },
  {
    id: "reconcile-blind",
    what: "reconcile does not compare transcripts with the log",
    file: "src/reconcile.mjs",
    find: "          if (!pre) {\n            findings.push({ session: s.id, severity: \"error\", code: \"transcript-call-without-decision\"",
    replace: "          if (!pre) {\n            continue;\n            findings.push({ session: s.id, severity: \"error\", code: \"transcript-call-without-decision\"",
  },
];

/** A copy of the install at `root` with one mutant applied. Returns its root. */
export function buildMutant(root, mutant, tmpRoot = os.tmpdir()) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmpRoot, `enclawed-code-mutant-${mutant.id}-`)));
  for (const d of ["bin", "src", "managed", "docs"]) {
    if (fs.existsSync(path.join(root, d))) {
      fs.cpSync(path.join(root, d), path.join(dir, d), { recursive: true });
    }
  }
  fs.copyFileSync(path.join(root, "package.json"), path.join(dir, "package.json"));
  // The framework build: copied when the mutant breaks the kit, shared otherwise.
  if (fs.existsSync(path.join(root, ".enclawed-dev"))) {
    if (mutant.file.startsWith(".enclawed-dev/")) {
      fs.mkdirSync(path.join(dir, ".enclawed-dev"));
      fs.cpSync(path.join(root, ".enclawed-dev", "framework"), path.join(dir, ".enclawed-dev", "framework"), { recursive: true });
      fs.symlinkSync(fs.realpathSync(path.join(root, ".enclawed-dev", "node_modules")), path.join(dir, ".enclawed-dev", "node_modules"));
    } else {
      fs.symlinkSync(path.join(root, ".enclawed-dev"), path.join(dir, ".enclawed-dev"));
    }
  }
  if (fs.existsSync(path.join(root, "node_modules"))) {
    fs.symlinkSync(path.join(root, "node_modules"), path.join(dir, "node_modules"));
  }
  const file = path.join(dir, mutant.file);
  const text = fs.readFileSync(file, "utf8");
  if (!text.includes(mutant.find)) {
    throw new Error(`mutant ${mutant.id}: the code it breaks is no longer in ${mutant.file}; update the mutant`);
  }
  fs.writeFileSync(file, text.replace(mutant.find, mutant.replace));
  return dir;
}
