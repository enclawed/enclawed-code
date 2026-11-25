// Workflow profiles: a named allowlist that narrows what one session may do.
//
// A profile lists the tool classes and tool names, the path scopes, the shell
// command patterns, the MCP tools and the skills a workflow needs; anything
// outside it is DENIED (not asked) with a reason naming the profile. The
// purpose is to make a hallucinated but technically permitted destructive
// action impossible for the workflow at hand: under `review`, `rm
// data/dummy_1.txt` is denied in every permission mode, bypassPermissions
// included.
//
// A profile can only narrow the base policy, never widen it: the gate checks
// the profile first and, when the profile admits the call, the ordinary
// decision (allowlists, protected paths, reversibility, pre-approval) still
// runs and still decides. A profile never turns a deny or an ask into an
// allow.
//
// Profiles come from two places: the built-in ones below, and the
// `enclawedCode.workflows` block of the policy file (a policy profile with a
// built-in name replaces the built-in one). A session selects one at launch
// (`ecwcode --workflow review`), or the policy binds one to a project
// (`enclawedCode.projectWorkflows`: { "<project dir>": "<profile>" }); a bound
// project cannot be started under another profile. The resolved profile is
// written into the session file, so the hook never re-reads it.
//
// Every decision is the kit's (enclawed-oss adapter/workflow.ts: parseProfile,
// selectWorkflow, workflowVerdict, ...). Its tool classes are the kit's
// action kinds (read, web, write, shell, agent, session, skill, mcp), so a
// class names the kinds Claude Code's tools map to (tools.mjs). This file
// keeps the policy block's name (Enclawed Code.*), the --workflow flag's
// messages, and the mapping of one Claude Code call to the kit's event.
//
//   "workflows": {
//     "<name>": {
//       "description": "...",
//       "tools":    ["read", "session", "shell", "Bash", ...],   classes or exact tool names
//       "paths":    { "read": ["**"], "write": ["docs/**"] },     globs, project-relative or absolute
//       "commands": ["@read-only", "npm test", "make *"],         shell command patterns
//       "mcpTools": ["mcp__github__get_issue", "mcp__github__*"],
//       "skills":   ["*"] | ["name", ...]
//     }
//   }

import path from "node:path";
import { kit } from "./kit.mjs";
import { fsWriteSpec, mcpNameOf, policyIds, readTargetsOf, shellDialect, toolKind } from "./tools.mjs";

/** Tool classes a profile may name: the kit's (each class is a set of action kinds). */
export const TOOL_CLASSES = kit.TOOL_CLASSES;

/** The shell commands the read-only classifier accepts. */
export const READ_ONLY = kit.WORKFLOW_READ_ONLY;

/** The built-in profiles (the kit's). A policy profile with the same name replaces one. */
export const BUILTIN_WORKFLOWS = kit.BUILTIN_WORKFLOWS;

const WHERE = "enclawedCode.workflows";

/** Validate one profile definition; returns a normalized copy. Throws on anything unknown. */
export function parseProfile(name, def) {
  return kit.parseProfile(name, def, WHERE);
}

/** Every profile available: built-in, then the policy's (which replace by name). */
export function allProfiles(workflowsBlock) {
  // Validate under Enclawed Code's block name first, so errors name it.
  for (const [n, d] of Object.entries(workflowsBlock ?? {})) {
    kit.parseProfile(n, d, WHERE);
  }
  return kit.allProfiles(workflowsBlock);
}

/** Parse the `enclawedCode.workflows` and `enclawedCode.projectWorkflows` blocks; throws on error. */
export function parseWorkflowOptions(block) {
  const workflows = block?.workflows;
  if (workflows && typeof workflows === "object" && !Array.isArray(workflows)) {
    allProfiles(workflows);
  }
  try {
    return kit.parseWorkflowOptions(block);
  } catch (err) {
    throw new Error(`Enclawed Code.${err.message}`);
  }
}

/** The canonical digest of a resolved profile (recorded in the audit log). */
export function profileDigest(profile) {
  return kit.profileDigest(profile ?? null);
}

/** The project binding that covers `projectDir` (the nearest bound ancestor), or null. */
export function boundWorkflow(bindings, projectDir) {
  return kit.boundWorkflow(bindings, projectDir, kit.realpathNearestSync);
}

/**
 * Which profile a launch runs under (kit.selectWorkflow). The profile is the
 * kit's WorkflowProfile: what the session file carries and the engine's
 * `workflow` option takes.
 * @returns {{ ok: true, profile: object|null, source: "flag"|"project-binding"|null, boundTo?: string }
 *         | { ok: false, message: string }}
 */
export function selectWorkflow({ requested, options, projectDir }) {
  const r = kit.selectWorkflow({ requested, options, projectDir, realpathNearest: kit.realpathNearestSync });
  if (r.ok) {
    return r;
  }
  // The CLI hint only (the kit decided): unknown name, or a bound project.
  const known = Object.hasOwn(kit.allProfiles(options?.workflows), requested);
  return { ...r, message: `${r.message} (${known ? "change the binding with: ecwctl policy workflow bind" : "see: ecwctl policy workflow list"})` };
}

// ------------------------------------------------------------------ matching (the kit's)

export const pathGlobRegExp = (glob) => kit.pathGlobRegExp(glob);
export const pathAllowed = (globs, p, { projectDir, home = null }) => kit.pathAllowed(globs, p, { projectDir, home });
export const simpleWords = (command) => kit.simpleWords(command);
export const commandMatches = (pattern, words) => kit.commandMatches(pattern, words);

/**
 * One Claude Code call as the kit's PreActionEvent (the tool table is
 * tools.mjs). Used by the wrappers below; gate.mjs builds the full event for
 * the engine.
 */
export function claudeCodeEvent(tool, ti, { cwd, approvalRoute = "person" }) {
  const kind = toolKind(tool);
  const params = ti && typeof ti === "object" && !Array.isArray(ti) ? ti : {};
  const event = { type: "pre-action", actor: { sessionId: null, subagentId: null }, callId: null, tool, policyIds: policyIds(tool), kind, params, cwd, approvalRoute };
  switch (kind) {
    case "read":
      return { ...event, ...readTargetsOf(tool, params, cwd) };
    case "fs-write": {
      const spec = fsWriteSpec(tool);
      const raw = spec.fields.map((f) => params[f]).find((v) => typeof v === "string" && v.length > 0);
      return { ...event, writes: raw ? [{ path: raw, op: spec.op }] : [] };
    }
    case "shell":
      return { ...event, command: { text: typeof params.command === "string" ? params.command : "", dialect: shellDialect(tool) } };
    case "fetch":
      return { ...event, ...(typeof params.url === "string" ? { url: params.url } : {}) };
    case "mcp": {
      const m = mcpNameOf(tool);
      return { ...event, ...(m ? { mcp: m } : {}) };
    }
    case "skill": {
      const name = typeof params.skill === "string" ? params.skill : typeof params.command === "string" ? params.command : "";
      return { ...event, skill: name };
    }
    default:
      return event;
  }
}

/**
 * The profile's verdict on one call (kit.workflowVerdict): null when the
 * profile admits it (the ordinary decision then still applies), else
 * { code, reason } to deny.
 *
 * @param {object|null} profile  the resolved profile (session.workflow.profile)
 * @param {string} tool
 * @param {object} ti  tool_input
 * @param {{ cwd: string, projectDir: string, home?: string }} ctx
 */
export function workflowVerdict(profile, tool, ti, { cwd, projectDir, home = null }) {
  const at = typeof cwd === "string" && path.isAbsolute(cwd) ? cwd : projectDir;
  const v = kit.workflowVerdict(profile ?? null, claudeCodeEvent(tool, ti, { cwd: at }), { cwd: at, projectDir, home, fs: { realpathNearest: kit.realpathNearestSync } });
  return v ? { code: v.code, reason: `${v.reason} (see: ecwctl policy workflow show ${profile.name})` } : null;
}

/** A profile as one line per field, for `policy workflow show` and doctor. */
export function describeProfile(p) {
  return kit.describeProfile(p);
}
