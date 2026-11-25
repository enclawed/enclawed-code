// Files changed outside the agent (Claude Code mapping only).
//
// Enclawed's kit (enclawed-oss adapter/file-integrity.ts) keeps the record of
// the project's files at the last audited state and decides every use of a
// file changed by anyone but the gated agent. This module only maps Claude
// Code onto it:
//
//   - where the record lives: Enclawed Code's state directory, one file per
//     project (out of the agent's reach: the state directory is protected);
//   - launch (launcher.mjs): snapshot the project, compare it with the record
//     the previous session left, put the findings in the audit log and on
//     stderr, start the watcher (its events go to the record);
//   - PreToolUse (hook.mjs): the record is the engine's `fileIntegrity`
//     option; an allowed call whose file effects are not known by path
//     (Bash, MCP tools, skills, unknown tools) opens a checked action;
//   - PostToolUse / PostToolUseFailure (hook.mjs): a Write/Edit/MultiEdit/
//     NotebookEdit is a gated write (the file's new digest is recorded); a
//     checked action closes (what it changed is the agent's); a call that ran
//     after an "ask" spends the person's approval;
//   - session end (launcher.mjs): the watcher stops and the record keeps the
//     state for the next session's comparison.
//
// The kit functions are injected (deps.kit) so tests can use the kit source
// directly; by default they come from the framework bundle (kit.mjs). A
// bundle without them cannot keep the record: startFileIntegrity throws, and
// the launcher refuses to start (fail closed).

import { createHash } from "node:crypto";
import path from "node:path";
import { appStateDir, realpathNearest } from "./paths.mjs";
import { program, say } from "./program.mjs";

const WRITE_TOOLS = new Map([
  ["Write", "write"],
  ["Edit", "edit"],
  ["MultiEdit", "edit"],
  ["NotebookEdit", "edit"],
]);

const REQUIRED = ["fileIntegrityLedger", "bracketsAuditedAction", "watchProject"];

async function kitOf(deps) {
  const k = deps?.kit ?? (await import("./kit.mjs")).kit;
  const missing = REQUIRED.filter((n) => typeof k?.[n] !== "function");
  if (missing.length) {
    throw new Error(`the Enclawed framework in use has no file-integrity record (${missing.join(", ")} missing); rebuild it (npm run build:framework)`);
  }
  return k;
}

/** The record's file for a project: Enclawed Code's state directory, keyed by the project's real path. */
export function ledgerFileFor(env, projectDir) {
  const real = realpathNearest(path.resolve(projectDir));
  const id = createHash("sha256").update(real).digest("hex").slice(0, 32);
  return path.join(appStateDir(env), "file-integrity", `${id}.json`);
}

/** The kit's audit callback: each record event as an Enclawed Code audit record (no content, only digests and counts). */
function auditOf(audit, actor = "enclawed-code") {
  if (!audit) {
    return null;
  }
  return (e) =>
    audit.append({ type: `claude-code.file-integrity.${e.type}`, actor, level: null, payload: { paths: e.paths.slice(0, 50), detail: e.detail, at: e.at } });
}

/** The project's record (the engine's `fileIntegrity` option, and what the hooks note into). */
export async function openFileIntegrity({ env = process.env, projectDir, audit = null, actor, deps } = {}) {
  const k = await kitOf(deps);
  const root = realpathNearest(path.resolve(projectDir));
  return k.fileIntegrityLedger(deps?.file ?? ledgerFileFor(env, root), root, { audit: auditOf(audit, actor) });
}

function noticeOf(comparison) {
  const list = (cs) => cs.slice(0, 8).map((c) => c.path).join(", ") + (cs.length > 8 ? `, and ${cs.length - 8} more` : "");
  const lines = [];
  // A first session in a project is routine: recorded in the audit log, not said at every launch.
  if (comparison.found.length) {
    lines.push(`${program()}: ${comparison.found.length} file(s) changed since the last session, by no action Enclawed checked: ${list(comparison.found)}`);
  }
  const older = comparison.outstanding.filter((c) => !comparison.found.includes(c));
  if (older.length) {
    lines.push(`${program()}: still changed outside the agent from earlier: ${list(older)}`);
  }
  if (comparison.found.length || older.length) {
    lines.push(`${program()}: the agent is asked before reading a changed plain file and may not use a changed executable or execution configuration; put such a file back, or review it and accept it: ecwctl files accept <path>`);
  }
  if (comparison.incomplete) {
    lines.push(`${program()}: the project is too large to record completely (${comparison.incomplete}): files it could not cover are treated as changed`);
  }
  return lines;
}

/**
 * Launch: snapshot the project, compare with the previous session's record,
 * audit and show the findings, start the watcher. Returns the record and a
 * stop() for session end.
 */
export async function startFileIntegrity({ env = process.env, projectDir, audit = null, stderr = null, deps } = {}) {
  const k = await kitOf(deps);
  const ledger = await openFileIntegrity({ env, projectDir, audit, deps: { ...deps, kit: k } });
  const comparison = ledger.compareAtLaunch(ledger.snapshot(ledger.state().files));
  if (audit) {
    await audit
      .append({
        type: "claude-code.file-integrity.launch",
        actor: "enclawed-code",
        level: null,
        payload: {
          firstRun: comparison.firstRun,
          incomplete: comparison.incomplete,
          found: comparison.found.slice(0, 50).map((c) => ({ path: c.path, summary: k.changeSummary ? k.changeSummary(c) : null })),
          outstanding: comparison.outstanding.length,
        },
      })
      .catch(() => {});
  }
  for (const line of noticeOf(comparison)) {
    say(stderr, line.slice(`${program()}: `.length));
  }
  let lost = null;
  const watcher = k.watchProject(
    ledger.root,
    (rel) => {
      try {
        ledger.noteOutsideChange(rel);
      } catch (err) {
        lost ??= err; // every use verifies again: a missed event is caught there
      }
    },
    { onError: (err) => (lost ??= err) },
  );
  return {
    ledger,
    comparison,
    watchError: () => lost,
    stop() {
      watcher.stop();
      try {
        ledger.endSession();
      } catch {
        /* the next launch compares against the record as it is */
      }
    },
  };
}

/** PreToolUse, once the call is allowed: a call whose file effects are not known by path opens a checked action. */
export async function fileIntegrityPre({ ledger, input, kind, answer, deps }) {
  if (!ledger || answer !== "allow" || typeof input?.tool_use_id !== "string") {
    return;
  }
  const k = await kitOf(deps);
  if (k.bracketsAuditedAction(kind)) {
    ledger.beginAuditedAction(input.tool_use_id);
  }
}

/** PostToolUse or PostToolUseFailure: the gated write's digest, the checked action's changes, the approval spent. */
export async function fileIntegrityPost({ ledger, input, kind, deps }) {
  if (!ledger) {
    return;
  }
  const k = await kitOf(deps);
  const id = typeof input?.tool_use_id === "string" ? input.tool_use_id : null;
  const op = WRITE_TOOLS.get(input?.tool_name);
  const ti = input?.tool_input ?? {};
  const target = ti.file_path ?? ti.notebook_path;
  if (op && typeof target === "string") {
    const cwd = typeof input.cwd === "string" ? input.cwd : ledger.root;
    ledger.noteGatedWrite(path.resolve(cwd, target), op);
  }
  if (id && k.bracketsAuditedAction(kind)) {
    ledger.endAuditedAction(id);
  }
  if (id && input?.hook_event_name !== "PostToolUseFailure") {
    ledger.noteCallRan(id);
  }
}

const FILES_HELP = `usage:
  ecwctl files [list] [--json]       the project's files changed outside the agent
  ecwctl files accept <path>... | --all
      make the changes part of the recorded state, after you reviewed them;
      needs your security key or passkey (two-factor), never a ticket. The only way,
      besides putting a file back, to let the agent use a changed
      executable, script, source file or execution configuration again.
`;

/**
 * `ecwctl files`: a person, outside the agent, reviews the
 * changes made outside it and accepts them into the record (the kit's
 * acceptByPerson). Accepting needs the person's second factor (a security
 * key touch, FIDO2, or a device-bound passkey's verification), which no tool
 * call of the agent can give.
 */
export async function filesCommand(args, { out, err, env = process.env, cwd = process.cwd(), audit, verify = null, deps } = {}) {
  const sub = args[0] ?? "list";
  if (sub === "help" || sub === "--help") {
    out.write(FILES_HELP);
    return 0;
  }
  const k = await kitOf(deps);
  const ledger = await openFileIntegrity({ env, projectDir: cwd, audit, deps: { ...deps, kit: k } });
  const changed = Object.values(ledger.state().changed).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const classOf = (c) => (typeof k.execClassOf === "function" ? k.execClassOf(path.join(ledger.root, c.path), c.path, c.after, { projectDir: ledger.root }) : null);
  if (sub === "list") {
    if (args.includes("--json")) {
      out.write(`${JSON.stringify(changed.map((c) => ({ path: c.path, summary: k.changeSummary(c), neverApprovable: classOf(c) })), null, 2)}\n`);
      return 0;
    }
    if (!changed.length) {
      out.write("no file of this project is changed outside the agent\n");
      return 0;
    }
    for (const c of changed) {
      const cls = classOf(c);
      out.write(`${c.path}: ${k.changeSummary(c)}${cls ? ` [${cls}: the agent may not use it until accepted]` : " [plain: the agent asks before reading it]"}\n`);
    }
    return 0;
  }
  if (sub !== "accept") {
    err.write(FILES_HELP);
    return 2;
  }
  const all = args.includes("--all");
  const named = args.slice(1).filter((a) => a !== "--all");
  if (all === named.length > 0 || (!all && !named.length)) {
    err.write(`${program()}: name the files to accept, or --all (not both)\n`);
    return 2;
  }
  const rels = all ? changed.map((c) => c.path) : named.map((p) => ledger.relOf(path.resolve(cwd, p)));
  const unknown = named.filter((_p, i) => !rels[i] || !changed.some((c) => c.path === rels[i]));
  if (unknown.length) {
    err.write(`${program()}: not changed outside the agent (nothing to accept): ${unknown.join(", ")}\n`);
    return 1;
  }
  if (!rels.length) {
    out.write("nothing to accept\n");
    return 0;
  }
  for (const c of changed.filter((x) => rels.includes(x.path))) {
    out.write(`accepting ${c.path}: ${k.changeSummary(c)}\n`);
  }
  try {
    if (verify) {
      await verify();
    } else {
      const { verifyUser } = await import("./auth.mjs");
      const { isInteractive } = await import("./cli-util.mjs");
      await verifyUser({ purpose: "policy-change", env, interactive: isInteractive(), audit, allowTicket: false });
    }
  } catch (e) {
    err.write(`${program()}: not accepted: ${e?.message ?? e}\n`);
    return 1;
  }
  const done = ledger.acceptByPerson(rels, "accepted by a person with a second factor (Enclawed Code files accept)");
  out.write(`accepted ${done.length} file(s) into the recorded state\n`);
  return 0;
}
