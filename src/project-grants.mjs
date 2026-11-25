// Grants for hooks and repository commands (opt-outs.mjs `projectHooks`,
// `projectCommands`, `hooks`).
//
// A repository's hook, command-valued setting (apiKeyHelper, statusLine, ...)
// or enabled .mcp.json server runs the repository's code inside the session,
// outside Enclawed's checks; so does a hook from the user's settings, a
// plugin, a user skill or subagent, or a --settings value. Enclawed Code refuses
// to start with one unless the root-owned opt-out file grants that exact entry
// (for a repository entry, for that exact repository). The digest and the
// grant decision are Enclawed's (adapter kit `hookDigest` / `decideHooks`,
// `commandSettingDigest` / `decideRepositoryCommands`): the digest covers the
// entry as Claude Code reads it and the content of the files it names, so
// editing the hook, the setting or the script it runs needs a new grant.
//
// Enclawed Code maps Claude Code's entries onto the kit's: the scope names, and
// which variables Claude Code expands before running a hook command
// ($CLAUDE_PROJECT_DIR, $CLAUDE_PLUGIN_ROOT, with `~` and $HOME): the kit
// expands them (HookEntry.expand), so the digest covers the files the command
// really runs.

import path from "node:path";
import { kit } from "./kit.mjs";
import { realpathNearest } from "./paths.mjs";

/** Claude Code's variable for the project directory in hook and helper commands. */
const PROJECT_VARS = Object.freeze(["CLAUDE_PROJECT_DIR"]);

/** The kit scope of an Enclawed Code hook scope. */
function kitScope(scope) {
  return scope === "--settings" ? "settings-flag" : scope;
}

/** A repository hook's scope, from its file (settings.local.json is "local"). */
function repoScope(file) {
  return path.basename(file) === "settings.local.json" ? "local" : "project";
}

/** The kit's hook entry for a repository hook (`{ kind: "hook", file, event, matcher, value }`). */
function repoHookEntry(entry) {
  return { scope: repoScope(entry.file), file: entry.file, event: entry.event, matcher: entry.matcher ?? null, value: entry.value ?? null };
}

/**
 * The grant digest of one repository entry (kit).
 * @param {{ kind: "hook"|"command", file: string, event?: string, key?: string, matcher?: any, value: any }} entry
 */
export function grantDigest(entry, projectDir) {
  const o = { projectDir: realpathNearest(path.resolve(projectDir)), projectVars: PROJECT_VARS };
  if (entry.kind === "hook") {
    return kit.hookDigest(repoHookEntry(entry), o);
  }
  return kit.commandSettingDigest({ file: entry.file, key: entry.key, value: entry.value ?? null }, o);
}

/**
 * Is this repository entry granted for this repository? The kit decides
 * (decideHooks / decideRepositoryCommands); `grant` is the entry an
 * administrator adds.
 * @returns {{ granted: boolean, digest: string|null, error: string|null, grant: { repo: string, digest: string }|null }}
 */
export function matchGrant(entry, projectDir, grants) {
  const o = { projectDir: realpathNearest(path.resolve(projectDir)), projectVars: PROJECT_VARS };
  const repoGrants = grants.map((g) => ({ repo: g.repo, digest: g.digest }));
  if (entry.kind === "hook") {
    const d = kit.decideHooks([repoHookEntry(entry)], repoGrants, o);
    if (d.ok) {
      const digest = kit.hookDigest(repoHookEntry(entry), o);
      return { granted: true, digest, error: null, grant: { repo: o.projectDir, digest } };
    }
    const r = d.refusals[0];
    return r.digest === null ? { granted: false, digest: null, error: r.why, grant: null } : { granted: false, digest: r.digest, error: null, grant: r.grant };
  }
  const setting = { scope: "project", file: entry.file, key: entry.key, command: "", value: entry.value ?? null };
  const d = kit.decideRepositoryCommands([setting], repoGrants, o);
  if (d.ok) {
    const grant = d.granted[0];
    return { granted: true, digest: grant.digest, error: null, grant };
  }
  const r = d.refusals[0];
  return r.digest === null ? { granted: false, digest: null, error: r.why, grant: null } : { granted: false, digest: r.digest, error: null, grant: r.grant };
}

/** The kit's hook entry for a hook outside the repository (otherHooks: user, plugin, --settings). */
function otherHookEntry(h, { home, projectDir }) {
  const settingsValue = /^--settings value \d+$/.test(h.file);
  const file = settingsValue ? h.file : realpathNearest(path.resolve(h.file));
  // A plugin's hooks live in <plugin root>/hooks/hooks.json.
  const pluginRoot = h.scope === "plugin" ? path.dirname(path.dirname(file)) : null;
  return {
    scope: kitScope(h.scope),
    file,
    event: h.event,
    matcher: h.matcher ?? null,
    value: h.raw ?? h.command ?? null,
    // The words Claude Code expands before it runs the command: the kit
    // expands them, so the digest covers the files the command really runs.
    expand: { home, vars: { CLAUDE_PROJECT_DIR: projectDir, CLAUDE_PLUGIN_ROOT: pluginRoot } },
  };
}

/**
 * The grant digest of a hook from the user's settings, a plugin, a skill or
 * subagent of the user, or a --settings value (opt-outs.mjs `hooks`; kit
 * hookDigest). Not bound to a repository: such a hook runs in every session.
 */
export function hookGrantDigest(h, { home, projectDir }) {
  const real = realpathNearest(path.resolve(projectDir));
  return kit.hookDigest(otherHookEntry(h, { home, projectDir: real }), { projectDir: real, projectVars: PROJECT_VARS });
}

/** Is this non-repository hook granted? (kit decideHooks) */
export function matchHookGrant(h, { home, projectDir, grants }) {
  const real = realpathNearest(path.resolve(projectDir));
  const entry = otherHookEntry(h, { home, projectDir: real });
  const o = { projectDir: real, projectVars: PROJECT_VARS };
  const d = kit.decideHooks([entry], (grants ?? []).map((g) => ({ digest: g.digest })), o);
  if (d.ok) {
    return { granted: true, digest: kit.hookDigest(entry, o), error: null, grant: { digest: kit.hookDigest(entry, o) } };
  }
  const r = d.refusals[0];
  // The grant file's `hooks` entries are { digest } only.
  return r.digest === null ? { granted: false, digest: null, error: r.why, grant: null } : { granted: false, digest: r.digest, error: null, grant: { digest: r.digest } };
}

/**
 * Hook grants of the root-owned opt-out file that match no hook present now
 * for this project (kit staleHookGrants: their hook changed, the digest rule
 * changed, or the hook is gone). `hooks`: otherHooks' entries (every scope).
 * @returns {{ projectHooks: { repo: string, digest: string }[], hooks: { digest: string }[] }}
 */
export function staleGrants(hooks, { home, projectDir, grants }) {
  const real = realpathNearest(path.resolve(projectDir));
  const o = { projectDir: real, projectVars: PROJECT_VARS };
  const repo = hooks.filter((h) => h.scope === "project" || h.scope === "local").map((h) => repoHookEntry({ file: h.file, event: h.event, matcher: h.matcher, value: h.raw ?? h.command }));
  const other = hooks.filter((h) => h.scope !== "project" && h.scope !== "local").map((h) => otherHookEntry(h, { home, projectDir: real }));
  return {
    projectHooks: kit.staleHookGrants(repo, (grants.projectHooks ?? []).map((g) => ({ repo: g.repo, digest: g.digest })), o),
    hooks: kit.staleHookGrants(other, (grants.hooks ?? []).map((g) => ({ digest: g.digest })), o),
  };
}
