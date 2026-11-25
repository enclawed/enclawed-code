// Environment variables that change WHERE Claude Code (or a process it
// starts) sends traffic, WHAT it trusts, WHOSE account it uses, WHAT code it
// loads, or WHAT it exports as telemetry.
//
// Claude Code applies the `env` block of every settings file it merges to its
// own process and to everything it starts, and a repository's
// `.claude/settings.json` / `.claude/settings.local.json` is one of those
// files (CVE-2026-21852: a committed ANTHROPIC_BASE_URL sent the session to an
// attacker). The classification is Enclawed's (adapter kit `classifyEnv`,
// with Claude Code's own names from `hostEnvExtra("claude-code")`); this
// module only adds the Claude Code names the kit's table does not carry yet
// and keeps the export names the rest of Enclawed Code uses. The table for
// every name the Claude Code binary reads is pinned in
// test/fixtures/claude-env-names-*.json and checked by the tests.

import { kit } from "./kit.mjs";

/** Classes whose repository-supplied value refuses the launch. */
export const REFUSED_CLASSES = kit.REFUSED_ENV_CLASSES;

/** Loader-injection variables (LD_PRELOAD, LD_AUDIT, DYLD_INSERT_LIBRARIES): removed from claude's environment unless an administrator grants them. */
export const LOADER_INJECTION_ENV = kit.LOADER_INJECTION_ENV;

/**
 * Claude Code switches whose effect on hooks, plugins or feature
 * configuration is not documented: treated as weakening (trust) until shown
 * otherwise. Host data the kit's claude-code table does not list.
 */
const CLAUDE_TRUST_NAMES = Object.freeze([
  "CLAUDE_CODE_DISABLE_HOOK_FORWARDING",
  "CLAUDE_CODE_DISABLE_PLUGIN_FORWARDING",
  "CLAUDE_CODE_EVAL_ALLOW_FLAG_OVERRIDES",
  "CLAUDE_INTERNAL_FC_OVERRIDES",
]);

/** Claude Code's names for the kit's classifier (its known table plus the ones above). */
export const CLAUDE_ENV_EXTRA = Object.freeze(kit.hostEnvExtra("claude-code", { trust: CLAUDE_TRUST_NAMES }));

/** Is `name` credential-shaped (its value is never written to the audit log)? */
export function credentialLike(name) {
  return kit.credentialLike(String(name), CLAUDE_ENV_EXTRA);
}

/**
 * The class of one variable (only model and provider-selection variables look at the value).
 * @returns {{ class: "destination"|"trust"|"credential"|"load"|"telemetry"|"provider"|"benign", why: string }}
 */
export function classifyEnv(name, value = undefined) {
  return kit.classifyEnv(String(name), value, CLAUDE_ENV_EXTRA);
}

export function isRefusedClass(c) {
  return kit.REFUSED_ENV_CLASSES.includes(c);
}

/** What the audit log may hold of a value: userinfo removed from URLs, bounded; credentials as a digest only. */
export function recordableValue(name, value) {
  return kit.recordableEnvValue(String(name), value);
}
