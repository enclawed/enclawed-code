// The PreToolUse decision, made by Enclawed's adapter kit (kit.decidePreAction):
// hardware halt, MCP and skill admission, the workflow profile, the tool
// allowlist, secret and credential reads, search-argument injection,
// network-origin taint, and the reversibility of the call by kind (history,
// protected paths, hard links, symlinks, exec-config files, untracked
// overwrites, the read-only shell allowlist, git config, retrieval hosts).
//
// Enclawed Code only maps Claude Code's hook input onto the kit's PreActionEvent
// (preActionEventOf) and its session onto the kit's options (engineOptionsOf),
// and maps the kit's Decision back (decision = outcome). Nothing here decides
// whether a call may run.

import path from "node:path";
import { MODE_ORDER } from "./claude-prompt.mjs";
import { kit } from "./kit.mjs";
import { fsWriteSpec, mcpNameOf, policyIds, readTargetsOf, shellDialect, toolKind } from "./tools.mjs";

export class MalformedHookInput extends Error {
  constructor(message) {
    super(message);
    this.name = "MalformedHookInput";
  }
}

export const REASON_PREFIX = kit.REASON_PREFIX;

/**
 * @typedef {{
 *   decision: "allow"|"deny"|"ask",
 *   reason: string,
 *   codes: string[],
 *   capability: string|null,
 *   reversible: boolean|null,
 *   targets?: unknown[],
 *   contain?: { kind: string, label: string, tool: string|null },
 * }} GateDecision
 */

/** Validate the fields PreToolUse needs; throw MalformedHookInput otherwise. */
export function validatePreToolUseInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new MalformedHookInput("hook input is not a JSON object");
  }
  if (input.hook_event_name !== "PreToolUse") {
    throw new MalformedHookInput(`expected a PreToolUse event, got ${String(input.hook_event_name)}`);
  }
  if (typeof input.tool_name !== "string" || input.tool_name.length === 0) {
    throw new MalformedHookInput("tool_name is missing");
  }
  const ti = input.tool_input ?? {};
  if (typeof ti !== "object" || Array.isArray(ti) || ti === null) {
    throw new MalformedHookInput("tool_input is not an object");
  }
  return { tool: input.tool_name, toolInput: ti };
}

// Permission modes in which a hook "ask" might not reach a person. The
// Claude Code docs say auto mode still shows prompts forced by a hook, so
// auto keeps "ask". They do not say what bypassPermissions does with a
// hook's "ask", so there no person is assumed (the kit then denies). In
// dontAsk, and in -p runs without a permission prompt tool, Claude Code
// itself turns the prompt into a denial.
const NO_PERSON_MODES = new Set(MODE_ORDER.noPersonModes);

const str = (v) => (typeof v === "string" && v !== "" ? v : null);

/** The kit's actor for a Claude Code call: the session and, for a subagent, its id. */
export function actorRefOf(input) {
  return { sessionId: str(input?.session_id), subagentId: str(input?.agent_id) };
}

/**
 * Claude Code's PreToolUse input as the kit's PreActionEvent: the tool's kind
 * and policy ids from the tool table, its targets, command, URL, MCP server
 * and tool, skill, and who can answer an ask.
 */
export function preActionEventOf(input, { projectDir, enclawedPrompt = false }) {
  const { tool, toolInput: ti } = validatePreToolUseInput(input);
  const cwd = typeof input.cwd === "string" && path.isAbsolute(input.cwd) ? input.cwd : projectDir;
  const kind = toolKind(tool);
  const mode = str(input.permission_mode);
  const event = {
    type: "pre-action",
    actor: actorRefOf(input),
    callId: str(input.tool_use_id),
    tool,
    policyIds: policyIds(tool),
    kind,
    params: ti,
    cwd,
    // Enclawed Code's own prompt (an interactive launcher session) answers an ask
    // in every Claude Code mode, bypassPermissions included: the ask never goes
    // to Claude Code (it gets allow or deny).
    approvalRoute: !enclawedPrompt && mode && NO_PERSON_MODES.has(mode) ? "no-person" : "person",
    hostMode: mode,
  };
  switch (kind) {
    case "read": {
      const { reads, literalParams } = readTargetsOf(tool, ti, cwd);
      return { ...event, reads, literalParams };
    }
    case "fetch":
      return { ...event, ...(typeof ti.url === "string" ? { url: ti.url } : {}) };
    case "fs-write": {
      const spec = fsWriteSpec(tool);
      const raw = spec.fields.map((f) => ti[f]).find((v) => typeof v === "string" && v.length > 0);
      return { ...event, writes: [{ path: raw ?? "", op: spec.op }] };
    }
    case "shell":
      return { ...event, command: { text: typeof ti.command === "string" ? ti.command : "", dialect: shellDialect(tool) } };
    case "mcp": {
      const m = mcpNameOf(tool);
      return { ...event, ...(m ? { mcp: m } : {}) };
    }
    case "skill":
      return { ...event, skill: typeof ti.skill === "string" ? ti.skill : typeof ti.command === "string" ? ti.command : "" };
    default:
      return event;
  }
}

/** The git state of a file (the kit's git lookup, from a system git, repository config neutralized). */
export function gitTracking(realPath, opts = {}) {
  return kit.gitTrackingOf(realPath, opts);
}

/**
 * The kit's engine options for this session. `deps` is what the hook context
 * holds: the framework's policy and history store, the hardware gate, the
 * project, Enclawed Code's protected and secret paths (data), the settings
 * variable risk, the verified skills, admitted MCP servers and workflow
 * profile (kit objects), and the operator's overwritable paths.
 */
export function engineOptionsOf(deps) {
  const probe = kit.nodeFsProbe(deps.protectedWalkBudget ? { budget: deps.protectedWalkBudget } : {});
  return {
    host: "claude-code",
    // The kit's undo hint names Enclawed Code's own command.
    historyRestoreCommand: "ecwctl history restore",
    policy: deps.policy,
    projectDir: deps.projectDir,
    home: deps.home ?? null,
    history: { store: deps.historyStore },
    hardware: deps.hardware,
    protected: deps.protected ?? null,
    secretPaths: deps.secretPaths ?? [],
    overwritablePaths: deps.overwritablePaths ?? [],
    shellEnvRisk: deps.shellEnvRisk ?? null,
    // The URLs the person named on the command line (kit personUrlsOf): a fetch of exactly one of them is the person's own.
    personUrls: deps.personUrls ?? [],
    // The complete environment Claude Code's Bash tool runs this call with (shell-env.mjs), only when it is
    // known exactly; otherwise null (never the hook's own environment), and the kit asks where it needs it.
    environment: deps.environment ?? null,
    // The aliases and functions of the shell Claude Code's Bash tool runs the command in (shell-env.mjs:
    // the person's login shell, as its snapshot carries them); "unknown" when they are not established,
    // and the kit then decides no command word as the program of its name.
    shellDefinitions: deps.shellDefinitions ?? "unknown",
    workflow: deps.workflow ?? null,
    skills: deps.skills ?? null,
    mcp: deps.mcp ?? null,
    fs: deps.gitTracking ? { ...probe, gitTracking: deps.gitTracking } : probe,
    ...(deps.credentials ? { credentials: deps.credentials } : {}),
    ...(deps.taint ? { taint: deps.taint } : {}),
    ...(deps.repoConfigHold ? { repoConfigHold: deps.repoConfigHold } : {}),
    ...(deps.conflictGrants ? { conflictGrants: deps.conflictGrants } : {}),
    ...(deps.hostPrompt ? { hostPrompt: deps.hostPrompt } : {}),
    ...(deps.containScripts !== undefined ? { containScripts: deps.containScripts } : {}),
    ...(deps.audit !== undefined ? { audit: deps.audit } : {}),
    ...(deps.decided ? { decided: deps.decided } : {}),
    ...(deps.cleanerMode ? { cleanerMode: deps.cleanerMode } : {}),
    // Held root: the device commits every decision (commitments.mjs).
    ...(deps.commit ? { commit: deps.commit } : {}),
    ...(deps.fileIntegrity ? { fileIntegrity: deps.fileIntegrity } : {}),
  };
}

/** The kit's Decision in the shape the hook writes back (decision = the kit's outcome). */
export function gateDecisionOf(d) {
  return {
    decision: d.outcome,
    reason: d.reason,
    codes: [...d.codes],
    capability: d.capability,
    reversible: d.reversible,
    ...(d.targets ? { targets: d.targets } : {}),
    ...(d.contain ? { contain: d.contain } : {}),
  };
}

/**
 * The PreToolUse decision for one Claude Code call (kit.decidePreAction).
 * Throws MalformedHookInput on an input that is not a PreToolUse call.
 * @returns {Promise<GateDecision>}
 */
export async function decidePreToolUse(input, deps) {
  const event = preActionEventOf(input, deps);
  return gateDecisionOf(await kit.decidePreAction(event, engineOptionsOf(deps)));
}

/**
 * The agent id kept in history entries: the Claude Code session, plus the
 * subagent when there is one, so a later call can tell which files this
 * session created (the kit's historyAgentId).
 */
export function historyAgentOf(input) {
  return kit.historyAgentId("claude-code", actorRefOf(input));
}

export function agentOf(input) {
  return typeof input?.agent_id === "string" && input.agent_id
    ? `claude-code:${input.agent_id}`
    : typeof input?.session_id === "string"
      ? `claude-code:${input.session_id}`
      : "claude-code";
}
