// `ecwctl policy ...`: create and change Enclawed Code's own policy
// file (~/.enclawed/claude-code/enclawed.json by default), at install time
// with non-interactive flags or later. It never writes the Enclawed
// gateway's config (~/.enclawed/enclawed.json) or the managed policy.
//
// Every change is validated exactly as the hook will load it (the framework's
// loader, after the same normalization), written atomically with mode 0600,
// and recorded in the audit log with the digests of the file before and after.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { AuthError, METHODS, readAuthState, verifyUser } from "./auth.mjs";
import { approveCurrent } from "./commitments.mjs";
import { UsageError, ask, askYesNo, isInteractive, parseFlags, positiveInt, writeFileAtomic } from "./cli-util.mjs";
import { appConfigPath, userPolicyPath } from "./paths.mjs";
import { loadPolicy, migrateOptionsBlock, normalizePolicyDoc, parseOptions, parsePolicyDoc } from "./policy.mjs";
import { shellFlavor } from "./env-authority.mjs";
import { policyCandidates } from "./session.mjs";
import { allProfiles, describeProfile, selectWorkflow } from "./workflow.mjs";
import { realpathNearest } from "./paths.mjs";

/** The tools Claude Code offers (tools reference), with Enclawed Code's default pick. */
export const CLAUDE_TOOLS = [
  ["Read", true],
  ["Glob", true],
  ["Grep", true],
  ["LS", true],
  ["Write", true],
  ["Edit", true],
  ["MultiEdit", true],
  ["NotebookEdit", true],
  ["Bash", true],
  ["Agent", true],
  ["Task", true],
  ["TodoWrite", true],
  ["TaskCreate", true],
  ["TaskGet", true],
  ["TaskList", true],
  ["TaskUpdate", true],
  ["AskUserQuestion", true],
  ["ExitPlanMode", true],
  ["EnterPlanMode", true],
  ["WebSearch", true],
  ["WebFetch", false],
  ["PowerShell", false],
  ["Monitor", false],
];

const sha = (t) => (t === null ? null : createHash("sha256").update(t).digest("hex"));

/** Validate a document as the hook would load it. Throws with the loader's message. */
export function validateDoc(fw, doc, flavor) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error("the policy file must be a JSON object");
  }
  const p = doc.enclawed?.policy ?? {};
  for (const key of ["allowedTools", "allowedHosts", "preApprovedIrreversibleTools", "scratchPaths"]) {
    if (Array.isArray(p[key]) && p[key].some((v) => typeof v === "string" && v.trim() === "*")) {
      throw new Error(`enclawed.policy.${key} may not contain "*"`);
    }
  }
  const policy = parsePolicyDoc(fw, doc, flavor);
  const options = parseOptions(doc);
  return { policy, options };
}

function readDoc(file) {
  let text = null;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return { text: null, doc: null };
  }
  try {
    return { text, doc: JSON.parse(text) };
  } catch (err) {
    throw new Error(`${file} is not valid JSON: ${err.message}`, { cause: err });
  }
}

function setList(doc, key, values) {
  const next = structuredClone(doc ?? {});
  next.enclawed ??= {};
  next.enclawed.policy ??= {};
  if (values.length === 0) {
    delete next.enclawed.policy[key];
  } else {
    next.enclawed.policy[key] = values;
  }
  return next;
}

function getList(doc, key) {
  return Array.isArray(doc?.enclawed?.policy?.[key]) ? [...doc.enclawed.policy[key]] : [];
}

/** The doc `policy init` builds from its answers. */
export function buildInitDoc({ tools = null, hosts = [], enforce = false, scratch = [], preApprove = [], maxFileBytes, maxTotalBytes, maxAgeDays, eraseCredentials = true, authMethod = null, inputCleaner = "on" }) {
  const policy = { enforceAllowlists: enforce };
  if (tools && tools.length) {
    policy.allowedTools = tools;
  }
  if (hosts.length) {
    policy.allowedHosts = hosts;
  }
  if (scratch.length) {
    policy.scratchPaths = scratch;
  }
  if (preApprove.length) {
    policy.preApprovedIrreversibleTools = preApprove;
  }
  const history = {};
  if (maxFileBytes !== undefined) {
    history.maxFileBytes = maxFileBytes;
  }
  if (maxTotalBytes !== undefined) {
    history.maxTotalBytes = maxTotalBytes;
  }
  if (maxAgeDays !== undefined) {
    history.maxAgeDays = maxAgeDays;
  }
  if (Object.keys(history).length) {
    policy.history = history;
  }
  const doc = normalizePolicyDoc({ enclawed: { policy } });
  doc.enclawedCode = { onHardwareHalt: { eraseClaudeCredentials: eraseCredentials }, inputCleaner };
  if (authMethod) {
    doc.enclawedCode.auth = { method: authMethod };
  }
  return doc;
}

async function splitAnswer(q, def) {
  const a = await ask(q, { def });
  return a.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
}

/**
 * Gate a write: two-factor authentication, always (mandatory). A change that
 * turns off the credential erase is audited as disabling a protection.
 */
async function authorize({ before, after, env, audit, passphraseFd }) {
  const turnsOffErase = (before ? parseOptions(before) : parseOptions(undefined)).onHardwareHalt.eraseClaudeCredentials && !parseOptions(after).onHardwareHalt.eraseClaudeCredentials;
  await verifyUser({ purpose: turnsOffErase ? "policy-erase-off" : "policy-change", env, interactive: isInteractive(), passphraseFd, audit, allowTicket: false });
}

async function writePolicy({ file, before, beforeText, after, fw, flavor, audit, env, command, passphraseFd }) {
  validateDoc(fw, after, flavor);
  await authorize({ before, after, env, audit, passphraseFd });
  const text = `${JSON.stringify(after, null, 2)}\n`;
  writeFileAtomic(file, text);
  await audit({ type: "claude-code.policy.change", actor: "enclawed-code", level: null, payload: { file, command, before: sha(beforeText), after: sha(text) } });
  await approveWritten({ fw, env, audit });
  return text;
}

/**
 * After a policy write: with an Enclaweder bound, the person approves the new
 * effective policy with a code the device checks (commitments.mjs); launches
 * with the hardware root required refuse a policy without that approval.
 */
async function approveWritten({ fw, env, audit, out = process.stderr }) {
  try {
    const r = await approveCurrent({ kind: "policy", fw, env, readCode: (q) => ask(q), out, ifBound: true });
    if (!r.skipped) {
      await audit({ type: "claude-code.policy.approved", actor: "enclawed-code", level: null, payload: { digest: r.digest } });
      out.write(`ecwctl: the effective policy ${r.digest.slice(0, 16)}… is approved by the Enclaweder\n`);
    }
  } catch (err) {
    out.write(`ecwctl: the policy was saved, but it is not approved by the Enclaweder (${err.message}); with the hardware root required, launches are refused until: ecwctl policy approve\n`);
  }
}

export const POLICY_HELP = `usage:
  ecwctl policy init [--tool T]... [--host H]... [--enforce] [--scratch DIR]... [--pre-approve T]...
                                [--max-file-bytes N] [--max-total-bytes N] [--max-age-days N]
                                [--erase-credentials-on-halt yes|no] [--auth-method M] [--input-cleaner on|audit|off]
                                [--file P] [--force] [--yes] [--json]
  ecwctl policy show [--json]           the policy in effect and where it comes from
  ecwctl policy path                    the file policy commands change
  ecwctl policy approve                 approve the policy in effect with an authenticator code the Enclaweder checks
                                                (needed with the hardware root required; every policy change asks for it)
  ecwctl policy edit [--file P]         edit in $EDITOR, validated before it is saved
  ecwctl policy add-tool|remove-tool T...
  ecwctl policy add-host|remove-host H...
  ecwctl policy validate [FILE]
  ecwctl policy use PATH | --clear      read another policy file instead of Enclawed Code's own
  ecwctl policy workflow list            the workflow profiles (built-in and the policy's)
  ecwctl policy workflow show NAME       one profile in full
  ecwctl policy workflow bind NAME [--project DIR]   run that project only under NAME
  ecwctl policy workflow unbind [--project DIR]
`;

/**
 * @param {string[]} args  after "policy"
 * @param {{ out: any, err: any, fw: any, env: object, audit: (r: object) => Promise<unknown> }} ctx
 */
export async function policyCommand(args, { out, err, fw, env, audit }) {
  const sub = args[0];
  const rest = args.slice(1);
  // The shell can only raise the flavor; the managed policy decides it (policy.mjs).
  const flavor = shellFlavor(env).flavor ?? "open";
  const common = ["--file", "--passphrase-fd"];
  const target = (flags) => path.resolve(flags["--file"] ?? userPolicyPath(env));
  switch (sub) {
    case "approve": {
      // The person approves the effective policy with a code the Enclaweder checks.
      parseFlags(rest, { maxPositionals: 0 });
      if (!isInteractive()) {
        throw new UsageError("policy approve needs a person at the terminal (an authenticator code the Enclaweder checks)");
      }
      const r = await approveCurrent({ kind: "policy", fw, env, readCode: (q) => ask(q), out });
      await audit({ type: "claude-code.policy.approved", actor: "enclawed-code", level: null, payload: { digest: r.digest } });
      out.write(`approved by the Enclaweder: policy ${r.digest}\n`);
      return 0;
    }
    case "path": {
      parseFlags(rest, { maxPositionals: 0 });
      out.write(`${userPolicyPath(env)}\n`);
      return 0;
    }
    case "show": {
      const { flags } = parseFlags(rest, { bool: ["--json"], maxPositionals: 0 });
      const candidates = policyCandidates(env, { fw });
      const loaded = loadPolicy(fw, { candidates, flavor });
      const doc = loaded.kind ? readDoc(loaded.source).doc : null;
      const summary = {
        source: loaded.source,
        kind: loaded.kind,
        flavor: loaded.flavor,
        refused: loaded.refused,
        precedence: candidates.map((c) => ({ ...c, exists: fs.existsSync(c.path) })),
        effective: {
          enforceAllowlists: loaded.policy.enforceAllowlists,
          allowedTools: [...loaded.policy.allowedTools],
          allowedHosts: [...loaded.policy.allowedHosts],
          preApprovedIrreversibleTools: [...loaded.policy.preApprovedIrreversibleTools],
          scratchPaths: [...loaded.policy.scratchPaths],
          history: { maxFileBytes: loaded.policy.history.maxFileBytes, maxTotalBytes: loaded.policy.history.maxTotalBytes, maxAgeDays: loaded.policy.history.maxAgeDays },
        },
        enclawedCode: loaded.options,
        workflow: (() => {
          const sel = selectWorkflow({ requested: null, options: loaded.options, projectDir: realpathNearest(process.cwd()) });
          return sel.ok && sel.profile ? { active: sel.profile.name, source: sel.source, boundTo: sel.boundTo } : { active: null };
        })(),
        note: loaded.note,
        document: doc,
      };
      if (flags["--json"]) {
        out.write(`${JSON.stringify(summary, null, 2)}\n`);
        return 0;
      }
      out.write(`policy: ${summary.source}${summary.kind ? ` (${summary.kind})` : ""}, flavor ${summary.flavor}\n`);
      for (const r of summary.refused ?? []) {
        out.write(`  ignored (a user file can only tighten ${loaded.baseSource}): ${r}\n`);
      }
      out.write(`  allowlists ${summary.effective.enforceAllowlists ? "enforced" : "not enforced"}\n`);
      out.write(`  allowed tools: ${summary.effective.allowedTools.join(", ") || "(any)"}\n`);
      out.write(`  allowed hosts: ${summary.effective.allowedHosts.join(", ") || "(none: WebFetch asks)"}\n`);
      out.write(`  pre-approved irreversible tools: ${summary.effective.preApprovedIrreversibleTools.join(", ") || "none"}\n`);
      out.write(`  scratch paths: ${summary.effective.scratchPaths.join(", ") || "none"}\n`);
      out.write(`  on hardware halt: ${summary.enclawedCode.onHardwareHalt.eraseClaudeCredentials ? "erase the session's Claude Code login storage and the sealed API key (never your own Claude Code login)" : "keep the session's Claude Code login and the sealed API key"}\n`);
      out.write(`  activation auth method: ${summary.enclawedCode.auth?.method ?? readAuthState(env)?.method ?? "not set"}\n`);
      out.write(
        `  input cleaner: ${{ on: "on (hidden characters are removed from tool results)", audit: "audit only (recorded, not removed)", off: "off" }[summary.enclawedCode.inputCleaner] ?? summary.enclawedCode.inputCleaner}\n`,
      );
      out.write(
        `  workflow profile here: ${summary.workflow.active ? `${summary.workflow.active} (bound to ${summary.workflow.boundTo})` : "none bound (base policy only; select one at launch with --workflow NAME)"}\n`,
      );
      out.write(`  workflow profiles: ${Object.keys(allProfiles(loaded.options.workflows)).sort().join(", ")}\n`);
      const bindings = Object.entries(loaded.options.projectWorkflows ?? {});
      for (const [dir, name] of bindings) {
        out.write(`    ${dir} -> ${name}\n`);
      }
      out.write(`  claude.ai connectors: ${loaded.options.claudeAiConnectors.length ? `only ${loaded.options.claudeAiConnectors.join(", ")}` : "off"}\n`);
      out.write(`  skills: unverified ones ${loaded.options.skills.unverified === "exclude" ? "are switched off" : "refuse the launch"}; bundled skills ${loaded.options.skills.bundled}\n`);
      if (summary.note) {
        out.write(`  note: ${summary.note}\n`);
      }
      out.write("precedence (first existing file wins):\n");
      for (const c of summary.precedence) {
        out.write(`  ${c.exists ? "*" : " "} ${c.kind.padEnd(14)} ${c.path}\n`);
      }
      return 0;
    }
    case "validate": {
      const { positionals } = parseFlags(rest, { maxPositionals: 1 });
      const file = path.resolve(positionals[0] ?? userPolicyPath(env));
      const { doc } = readDoc(file);
      if (!doc) {
        err.write(`ecwctl: ${file} does not exist\n`);
        return 1;
      }
      try {
        validateDoc(fw, doc, flavor);
      } catch (e) {
        err.write(`ecwctl: ${file}: ${e.message}\n`);
        return 1;
      }
      out.write(`${file}: valid\n`);
      return 0;
    }
    case "use": {
      const { positionals, flags } = parseFlags(rest, { bool: ["--clear"], value: ["--passphrase-fd"], maxPositionals: 1 });
      const cfgFile = appConfigPath(env);
      const cfg = readDoc(cfgFile).doc ?? {};
      if (flags["--clear"]) {
        delete cfg.policyPath;
      } else {
        if (!positionals[0]) {
          throw new UsageError("policy use needs a path (or --clear)");
        }
        const p = path.resolve(positionals[0]);
        const { doc } = readDoc(p);
        if (!doc) {
          throw new UsageError(`${p} does not exist`);
        }
        validateDoc(fw, doc, flavor);
        cfg.policyPath = p;
      }
      await verifyUser({ purpose: "policy-use", env, interactive: isInteractive(), passphraseFd: flags["--passphrase-fd"], audit, allowTicket: false });
      writeFileAtomic(cfgFile, `${JSON.stringify(cfg, null, 2)}\n`);
      await audit({ type: "claude-code.policy.use", actor: "enclawed-code", level: null, payload: { policyPath: cfg.policyPath ?? null } });
      await approveWritten({ fw, env, audit });
      out.write(cfg.policyPath ? `Enclawed Code now reads ${cfg.policyPath}\n` : "Enclawed Code reads its own policy file again\n");
      return 0;
    }
    case "init": {
      const { flags } = parseFlags(rest, {
        bool: ["--enforce", "--yes", "--json", "--force"],
        value: [...common, "--max-file-bytes", "--max-total-bytes", "--max-age-days", "--erase-credentials-on-halt", "--auth-method", "--input-cleaner"],
        multi: ["--tool", "--host", "--scratch", "--pre-approve"],
        maxPositionals: 0,
      });
      const file = target(flags);
      const { doc: before, text: beforeText } = readDoc(file);
      if (before && !flags["--force"]) {
        err.write(`ecwctl: ${file} already exists; change it with \`ecwctl policy edit\` or the add/remove commands, or pass --force to replace it\n`);
        return 1;
      }
      const erase = flags["--erase-credentials-on-halt"];
      if (erase !== undefined && !["yes", "no"].includes(erase)) {
        throw new UsageError("--erase-credentials-on-halt takes yes or no");
      }
      if (flags["--input-cleaner"] !== undefined && !["on", "audit", "off"].includes(flags["--input-cleaner"])) {
        throw new UsageError("--input-cleaner takes on, audit or off");
      }
      if (flags["--auth-method"] !== undefined && ![...METHODS, "auto"].includes(flags["--auth-method"])) {
        throw new UsageError(`--auth-method takes one of auto, ${METHODS.join(", ")}`);
      }
      const answers = {
        tools: flags["--tool"] ?? null,
        hosts: flags["--host"] ?? [],
        enforce: flags["--enforce"] === true,
        scratch: (flags["--scratch"] ?? []).map((p) => path.resolve(p)),
        preApprove: flags["--pre-approve"] ?? [],
        maxFileBytes: flags["--max-file-bytes"] !== undefined ? positiveInt(flags["--max-file-bytes"], "--max-file-bytes") : undefined,
        maxTotalBytes: flags["--max-total-bytes"] !== undefined ? positiveInt(flags["--max-total-bytes"], "--max-total-bytes") : undefined,
        maxAgeDays: flags["--max-age-days"] !== undefined ? positiveInt(flags["--max-age-days"], "--max-age-days") : undefined,
        eraseCredentials: erase !== "no",
        authMethod: flags["--auth-method"] ?? null,
        inputCleaner: flags["--input-cleaner"] ?? "on",
      };
      if (!flags["--yes"] && isInteractive()) {
        out.write(`Setting up Enclawed Code's policy in ${file}\n`);
        answers.enforce = await askYesNo("Enforce a tool allowlist (unlisted tools are refused)?", answers.enforce);
        if (answers.enforce) {
          const def = CLAUDE_TOOLS.filter(([, on]) => on).map(([t]) => t).join(",");
          out.write(`Claude Code tools: ${CLAUDE_TOOLS.map(([t]) => t).join(", ")}\n`);
          answers.tools = await splitAnswer("Allowed tools (comma-separated)?", (answers.tools ?? []).join(",") || def);
        }
        answers.hosts = await splitAnswer("Hosts WebFetch may reach without asking (comma-separated, empty for none)?", answers.hosts.join(","));
        answers.preApprove = await splitAnswer("Tools pre-approved for irreversible calls (they run without asking; empty for none)?", answers.preApprove.join(","));
        answers.scratch = (await splitAnswer("Scratch directories (no history kept; empty for none)?", answers.scratch.join(","))).map((p) => path.resolve(p));
        answers.eraseCredentials = await askYesNo("On a hardware-root halt, erase the session's Claude Code login storage and the sealed API key (never your own Claude Code login)?", answers.eraseCredentials);
        for (;;) {
          const c = await ask("Remove hidden characters from tool results before the model reads them (on, audit, off)?", { def: answers.inputCleaner });
          if (["on", "audit", "off"].includes(c)) {
            answers.inputCleaner = c;
            break;
          }
          out.write("ecwctl: answer on, audit or off\n");
        }
      }
      const doc = buildInitDoc(answers);
      if (answers.authMethod && ![...METHODS, "auto"].includes(answers.authMethod)) {
        throw new UsageError(`unknown auth method ${answers.authMethod}`);
      }
      const text = await writePolicy({ file, before, beforeText, after: doc, fw, flavor, audit, env, command: "init", passphraseFd: flags["--passphrase-fd"] });
      if (flags["--json"]) {
        out.write(text);
      } else {
        out.write(`wrote ${file}\n`);
        if (!readAuthState(env)?.method) {
          out.write("next: enroll this computer's device-bound passkey (two-factor is mandatory): ecwctl auth enroll (a FIDO2 security key instead: ecwctl auth enroll --security-key)\n");
        }
      }
      return 0;
    }
    case "add-tool":
    case "remove-tool":
    case "add-host":
    case "remove-host": {
      const { positionals, flags } = parseFlags(rest, { value: common });
      if (positionals.length === 0) {
        throw new UsageError(`policy ${sub} needs at least one value`);
      }
      const file = target(flags);
      const { doc: before, text: beforeText } = readDoc(file);
      const key = sub.endsWith("tool") ? "allowedTools" : "allowedHosts";
      const vals = positionals.map((v) => v.trim().toLowerCase());
      let list = getList(before, key).map((v) => v.toLowerCase());
      if (sub.startsWith("add")) {
        for (const v of vals) {
          if (!list.includes(v)) {
            list.push(v);
          }
        }
      } else {
        list = list.filter((v) => !vals.includes(v));
      }
      const after = setList(before ?? { enclawed: { policy: {} } }, key, list);
      await writePolicy({ file, before, beforeText, after, fw, flavor, audit, env, command: sub, passphraseFd: flags["--passphrase-fd"] });
      out.write(`${file}: ${key} = ${list.join(", ") || "(empty)"}\n`);
      return 0;
    }
    case "workflow": {
      const wsub = rest[0];
      const wrest = rest.slice(1);
      const loaded = loadPolicy(fw, { candidates: policyCandidates(env, { fw }), flavor });
      const profiles = allProfiles(loaded.options.workflows);
      if (wsub === "list") {
        const { flags } = parseFlags(wrest, { bool: ["--json"], maxPositionals: 0 });
        if (flags["--json"]) {
          out.write(`${JSON.stringify({ profiles, bindings: loaded.options.projectWorkflows }, null, 2)}\n`);
          return 0;
        }
        for (const p of Object.values(profiles).sort((a, b) => (a.name < b.name ? -1 : 1))) {
          out.write(`${p.name.padEnd(10)} ${p.origin.padEnd(8)} ${p.description}\n`);
        }
        for (const [dir, name] of Object.entries(loaded.options.projectWorkflows ?? {})) {
          out.write(`bound: ${dir} -> ${name}\n`);
        }
        return 0;
      }
      if (wsub === "show") {
        const { positionals, flags } = parseFlags(wrest, { bool: ["--json"], maxPositionals: 1 });
        const p = profiles[positionals[0]];
        if (!p) {
          throw new UsageError(`unknown workflow ${JSON.stringify(positionals[0] ?? "")}; known: ${Object.keys(profiles).sort().join(", ")}`);
        }
        out.write(flags["--json"] ? `${JSON.stringify(p, null, 2)}\n` : `${describeProfile(p)}\n`);
        return 0;
      }
      if (wsub === "bind" || wsub === "unbind") {
        const { positionals, flags } = parseFlags(wrest, { value: [...common, "--project"], maxPositionals: wsub === "bind" ? 1 : 0 });
        const project = realpathNearest(path.resolve(flags["--project"] ?? process.cwd()));
        if (wsub === "bind" && !Object.hasOwn(profiles, positionals[0] ?? "")) {
          throw new UsageError(`unknown workflow ${JSON.stringify(positionals[0] ?? "")}; known: ${Object.keys(profiles).sort().join(", ")}`);
        }
        const file = target(flags);
        const { doc: before, text: beforeText } = readDoc(file);
        const after = migrateOptionsBlock(structuredClone(before ?? { enclawed: { policy: {} } }));
        after.enclawedCode ??= {};
        after.enclawedCode.projectWorkflows ??= {};
        if (wsub === "bind") {
          after.enclawedCode.projectWorkflows[project] = positionals[0];
        } else {
          delete after.enclawedCode.projectWorkflows[project];
          if (Object.keys(after.enclawedCode.projectWorkflows).length === 0) {
            delete after.enclawedCode.projectWorkflows;
          }
        }
        await writePolicy({ file, before, beforeText, after, fw, flavor, audit, env, command: `workflow-${wsub}`, passphraseFd: flags["--passphrase-fd"] });
        await audit({ type: "claude-code.workflow.binding", actor: "enclawed-code", level: null, payload: { file, project, workflow: wsub === "bind" ? positionals[0] : null } });
        out.write(wsub === "bind" ? `${project} now runs only under the workflow "${positionals[0]}"\n` : `${project} is no longer bound to a workflow\n`);
        return 0;
      }
      err.write(POLICY_HELP);
      return 2;
    }
    case "edit": {
      const { flags } = parseFlags(rest, { value: common, maxPositionals: 0 });
      const file = target(flags);
      const { doc: before, text: beforeText } = readDoc(file);
      const editor = process.env.VISUAL || process.env.EDITOR || "vi";
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-policy-"));
      const tmp = path.join(dir, "enclawed.json");
      try {
        fs.writeFileSync(tmp, beforeText ?? `${JSON.stringify({ enclawed: { policy: {} } }, null, 2)}\n`, { mode: 0o600 });
        const r = spawnSync(editor, [tmp], { stdio: "inherit", shell: true });
        if (r.status !== 0) {
          err.write("ecwctl: the editor did not exit cleanly; nothing was changed\n");
          return 1;
        }
        let after;
        try {
          after = JSON.parse(fs.readFileSync(tmp, "utf8"));
        } catch (e) {
          err.write(`ecwctl: not valid JSON (${e.message}); nothing was changed\n`);
          return 1;
        }
        try {
          await writePolicy({ file, before, beforeText, after, fw, flavor, audit, env, command: "edit", passphraseFd: flags["--passphrase-fd"] });
        } catch (e) {
          err.write(`ecwctl: ${e.message}; nothing was changed\n`);
          return 1;
        }
        out.write(`saved ${file}\n`);
        return 0;
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
    default:
      err.write(POLICY_HELP);
      return 2;
  }
}
