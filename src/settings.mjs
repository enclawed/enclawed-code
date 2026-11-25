// The settings Enclawed Code hands claude through `--settings`.
//
// Claude Code merges hook entries across settings levels instead of letting
// one replace another, so hooks given with `--settings` run in addition to
// the user's, project's and organization's own hooks. Claude Code reads one
// `--settings` value (a second one replaces the first), so when the user
// passes their own, Enclawed Code parses it, validates it, and merges it into the
// file it generates: the user's keys are kept, their hook entries are kept
// next to Enclawed's, and the result is passed as the single `--settings`.
//
// `--settings` ranks above user, project and local settings, so the
// generated file also sets `disableAllHooks: false`, which keeps a
// `disableAllHooks: true` in those files from switching Enclawed off, and
// pins (in its `env`) any sensitive variable those files set.
//
// Claude Code drops a whole settings file when one value in it is invalid,
// hooks included (red-team I2, round 3 N9), so a user's --settings is checked
// before it is merged, and the launcher also waits for proof that the hooks
// run (the session-start handshake).
//
// Claude Code reads one --settings value: with two, only the last is loaded
// (tested on 2.1.326), and no other settings source can carry Enclawed's
// hooks and pins without being outranked by --settings. So the user's values
// cannot be kept in a separate file whose invalidity would spare Enclawed's;
// they are merged, and only keys whose constraint Enclawed Code checks exactly (or
// more strictly) are accepted. The constraints are Claude Code 2.1.326's own
// zod settings schema, read from the binary by
// scripts/claude-settings-schema.mjs (its output is pinned in
// test/fixtures/claude-settings-schema-2.1.326.json), and
// test/claude-settings.test.mjs checks against the real binary that a file
// holding every accepted key really loads (its hooks run).

import fs from "node:fs";
import path from "node:path";
import { SESSION_UPDATE_ENV } from "./claude-terms.mjs";
import { HOOK_BIN } from "./paths.mjs";
import { SCHEMA, SCHEMA_KEYS, validateAgainstSchema } from "./settings-schema.mjs";

export const HOOK_EVENTS_WITH_MATCHER = ["PreToolUse", "PostToolUse", "PostToolUseFailure"];
export const HOOK_EVENTS_NO_MATCHER = ["SessionStart", "SessionEnd", "SubagentStop", "ConfigChange"];

export const PRE_TOOL_TIMEOUT_S = 10;
// Interactive sessions: an "ask" waits for the person at Enclawed Code's own
// prompt (approval.mjs, up to 5 minutes), so the hook gets that long.
export const PRE_TOOL_APPROVAL_TIMEOUT_S = 330;
export const OTHER_TIMEOUT_S = 10;

function quotePosix(s) {
  return `'${String(s).replaceAll("'", `'\\''`)}'`;
}

function quoteWindows(s) {
  return `"${String(s).replaceAll('"', '\\"')}"`;
}

/** The absolute `env` program, used to start the hook with an empty environment. */
export function envProgram() {
  for (const p of ["/usr/bin/env", "/bin/env"]) {
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {
      /* try the next */
    }
  }
  return null;
}

/**
 * The shell command line that runs the hook with this Node and this install.
 *
 * On POSIX it is `env -i CLAUDE_PROJECT_DIR="$CLAUDE_PROJECT_DIR" <node> <hook> ...`:
 * nothing from Claude Code's environment reaches node (no NODE_OPTIONS,
 * NODE_PATH, LD_PRELOAD, DYLD_*, ENCLAWED_*), only the project directory
 * Claude Code itself sets. Launcher mode adds `--session FILE --digest SHA256`;
 * managed mode may add `--flavor` and `--hardware-root`.
 */
export function hookCommand({
  node = process.execPath,
  hookBin = HOOK_BIN,
  origin = "launcher",
  session = null,
  digest = null,
  flavor = null,
  hardwareRoot = null,
  platform = process.platform,
  env = envProgram(),
} = {}) {
  const q = platform === "win32" ? quoteWindows : quotePosix;
  const parts = [q(node), q(hookBin), "--origin", origin];
  if (session) {
    parts.push("--session", q(session), "--digest", digest);
  }
  if (flavor) {
    parts.push("--flavor", flavor);
  }
  if (hardwareRoot) {
    parts.push("--hardware-root", hardwareRoot);
  }
  if (platform === "win32" || !env) {
    // No `env` program: the environment cannot be emptied here (see docs/enterprise.md).
    return parts.join(" ");
  }
  return [q(env), "-i", 'CLAUDE_PROJECT_DIR="$CLAUDE_PROJECT_DIR"', ...parts].join(" ");
}

/** The `hooks` block: every tool event and the session boundaries. */
export function enclawedHooks(command, { preToolTimeoutS = PRE_TOOL_TIMEOUT_S } = {}) {
  const hooks = {};
  for (const event of HOOK_EVENTS_WITH_MATCHER) {
    const handler = {
      type: "command",
      command,
      timeout: event === "PreToolUse" ? preToolTimeoutS : OTHER_TIMEOUT_S,
    };
    if (event === "PreToolUse") {
      // A crash, a timeout or an unexpected exit code blocks the call (Claude Code 2.1.295+).
      handler.onFailure = "block";
    }
    hooks[event] = [{ matcher: "*", hooks: [handler] }];
  }
  for (const event of HOOK_EVENTS_NO_MATCHER) {
    hooks[event] = [{ hooks: [{ type: "command", command, timeout: OTHER_TIMEOUT_S }] }];
  }
  return hooks;
}

/** Parse one `--settings` value: a JSON object string, or a path to a JSON file. */
export function readSettingsValue(value, cwd = process.cwd()) {
  const trimmed = value.trim();
  let text;
  let from;
  if (trimmed.startsWith("{")) {
    text = trimmed;
    from = "the --settings JSON string";
  } else {
    from = path.resolve(cwd, value);
    try {
      text = fs.readFileSync(from, "utf8");
    } catch (err) {
      throw new Error(`cannot read --settings file ${from}: ${err.message}`, { cause: err });
    }
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`${from} is not valid JSON: ${err.message}`, { cause: err });
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${from} is not a JSON object`);
  }
  const problems = validateSettings(parsed);
  if (problems.length > 0) {
    throw new Error(
      `${from} has settings Claude Code would reject, and Claude Code then drops the whole file, Enclawed's hooks included: ${problems.join("; ")}`,
    );
  }
  return parsed;
}

// The validator is generated from Claude Code's own zod schema (round 4,
// F1): src/settings-schema.mjs parses the pinned definitions in
// src/claude-settings-schema.json (= test/fixtures/claude-settings-schema-
// <version>.json) and checks every key, nested key and value against them.
// A key outside the pinned list, or a value the parser cannot check, is
// refused: Claude Code would drop the whole merged file, hooks included.

/** The permission modes Claude Code accepts for permissions.defaultMode (from the schema). */
export const PERMISSION_MODES = JSON.parse(SCHEMA.nested.permissionModes);
/** Every hook event Claude Code defines (from the schema). */
export const KNOWN_HOOK_EVENTS = new Set(JSON.parse(SCHEMA.nested.hookEvents));
/** Top-level keys Enclawed Code can check before merging: every key the pinned schema lists. */
export const MERGEABLE_KEYS = SCHEMA_KEYS;

/** @returns {string[]} problems; empty when Claude Code loads the document */
export function validateSettings(s) {
  return validateAgainstSchema(s);
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Later settings win for scalars; objects merge; hook lists concatenate per event. */
function mergeSettings(base, over, parent = null) {
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) {
    if (parent === "permissions" && Array.isArray(v) && Array.isArray(out[k])) {
      // Permission rules from several sources add up, as in Claude Code.
      out[k] = [...new Set([...out[k], ...v])];
    } else if (k === "hooks" && isPlainObject(v) && isPlainObject(out.hooks)) {
      const hooks = { ...out.hooks };
      for (const [event, list] of Object.entries(v)) {
        hooks[event] = [...(Array.isArray(hooks[event]) ? hooks[event] : []), ...(Array.isArray(list) ? list : [])];
      }
      out.hooks = hooks;
    } else if (isPlainObject(v) && isPlainObject(out[k])) {
      out[k] = mergeSettings(out[k], v, k);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * The settings object Enclawed Code generates: the user's `--settings` values in
 * order, then Enclawed's hooks appended, with `disableAllHooks` forced off
 * and `pins` (sensitive env names lower settings set) fixed in `env`.
 *
 * @returns {{ settings: object, warnings: string[] }}
 */
export function buildSettings(userSettingsList, command, { pins = {}, preToolTimeoutS = PRE_TOOL_TIMEOUT_S, skills = null, disableClaudeAiConnectors = false } = {}) {
  const warnings = [];
  let merged = {};
  for (const s of userSettingsList) {
    merged = mergeSettings(merged, s);
  }
  if (merged.disableAllHooks === true) {
    warnings.push("ignoring disableAllHooks from --settings: it would switch Enclawed off");
  }
  merged = mergeSettings(merged, { hooks: enclawedHooks(command, { preToolTimeoutS }) });
  if (!isPlainObject(merged.hooks)) {
    merged.hooks = enclawedHooks(command, { preToolTimeoutS });
  }
  merged.disableAllHooks = false;
  if (skills) {
    // Skill admission (skills.mjs): a skill that did not verify is switched
    // off (Claude Code's skillOverrides, schema 2.1.326), the inline shell
    // commands of skill prompts are off (they run when a skill loads, not
    // as a tool call the hook checks), and so are the bundled skills unless
    // the policy turns them on.
    const overrides = { ...(isPlainObject(merged.skillOverrides) ? merged.skillOverrides : {}), ...skills.overrides };
    if (Object.keys(overrides).length > 0) {
      merged.skillOverrides = overrides;
    }
    merged.disableSkillShellExecution = true;
    // Skills and plugins synced from the claude.ai account are not on disk
    // for Enclawed Code to verify before the session: not synced.
    merged.syncClaudeAiSkills = false;
    merged.syncClaudeAiPlugins = false;
    if (skills.bundled !== "on") {
      merged.disableBundledSkills = true;
    }
  }
  if (disableClaudeAiConnectors) {
    // claude.ai connectors (account-level MCP servers) are off unless the
    // policy admits their tools (mcp.mjs); the env pin backs the setting up.
    merged.disableClaudeAiConnectors = true;
    pins = { ...pins, ENABLE_CLAUDEAI_MCP_SERVERS: "false" };
  }
  // Claude Code's automatic updates are off in Enclawed Code's sessions (claude-terms.mjs): a session
  // stays on the reviewed Claude Code version it started with. Only this session's settings carry it.
  pins = { ...pins, ...SESSION_UPDATE_ENV };
  merged.env = { ...(isPlainObject(merged.env) ? merged.env : {}), ...pins };
  return { settings: merged, warnings };
}

/** Write the settings into the (private) session directory. */
export function writeSessionSettings(settings, dir) {
  const file = path.join(dir, "settings.json");
  fs.writeFileSync(file, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return { file, dir };
}

/** Settings files below `--settings` that set disableAllHooks: true (for a warning). */
export function findDisableAllHooks({ cwd = process.cwd(), env = process.env } = {}) {
  const configDir = env.CLAUDE_CONFIG_DIR || path.join(env.HOME || "", ".claude");
  const files = [
    path.join(configDir, "settings.json"),
    path.join(cwd, ".claude", "settings.json"),
    path.join(cwd, ".claude", "settings.local.json"),
  ];
  return files.filter((f) => {
    try {
      return JSON.parse(fs.readFileSync(f, "utf8"))?.disableAllHooks === true;
    } catch {
      return false;
    }
  });
}
