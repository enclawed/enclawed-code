// Where Enclawed Code keeps its own state, resolved in exactly one place.
//
// Everything lives under the Enclawed state directory in a `claude-code/`
// subdirectory, so the app never writes into the gateway's own audit log: two
// independent writers on one hash chain would break it.
//
// The state directory is resolved the way the open core resolves it
// (resolveStateDir in enclawed-oss), so Enclawed Code and the framework agree:
//   1. ENCLAWED_STATE_DIR, when set (a leading ~ is expanded);
//   2. otherwise <home>/.enclawed, where <home> is ENCLAWED_HOME, else HOME,
//      else USERPROFILE, else the OS home directory;
//   3. when <home>/.enclawed does not exist but the legacy <home>/.clawdbot
//      does, the legacy directory.
// The history directory is ENCLAWED_HISTORY_DIR, else <state>/history.
//
// These functions read whatever environment they are given. Only the
// launcher and Enclawed Code's own commands pass the user's real environment.
// The hook never resolves anything from its own environment: it reads the
// values the launcher resolved from the protected session file (session.mjs),
// or, in managed mode, uses the OS account's home directory.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const HOOK_BIN = path.join(APP_ROOT, "bin", "ecwcode-hook.mjs");

const LEGACY_STATE_DIRNAMES = [".clawdbot"];

function trimmed(v) {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : null;
}

function osHome() {
  try {
    return os.homedir();
  } catch {
    return null;
  }
}

/** The home directory the framework would use for this environment. */
export function homeDir(env = process.env) {
  const base = trimmed(env.HOME) ?? trimmed(env.USERPROFILE) ?? osHome() ?? process.cwd();
  const explicit = trimmed(env.ENCLAWED_HOME);
  if (explicit) {
    return path.resolve(explicit === "~" || /^~[\\/]/.test(explicit) ? explicit.replace(/^~/, base) : explicit);
  }
  return path.resolve(base);
}

function expandHome(p, env) {
  if (p === "~" || /^~[\\/]/.test(p)) {
    return path.join(homeDir(env), p.slice(1));
  }
  return p;
}

export function stateDir(env = process.env) {
  const override = trimmed(env.ENCLAWED_STATE_DIR);
  if (override) {
    return path.resolve(expandHome(override, env));
  }
  const home = homeDir(env);
  const newDir = path.join(home, ".enclawed");
  if (env.ENCLAWED_TEST_FAST === "1" || fs.existsSync(newDir)) {
    return newDir;
  }
  for (const name of LEGACY_STATE_DIRNAMES) {
    const legacy = path.join(home, name);
    if (fs.existsSync(legacy)) {
      return legacy;
    }
  }
  return newDir;
}

export function historyDir(env = process.env) {
  const explicit = trimmed(env.ENCLAWED_HISTORY_DIR);
  return explicit ? path.resolve(expandHome(explicit, env)) : path.join(stateDir(env), "history");
}

export function appStateDir(env = process.env) {
  return path.join(stateDir(env), "claude-code");
}

/** The hash-chained audit log this app writes. */
export function auditLogPath(env = process.env) {
  return path.join(appStateDir(env), "audit.jsonl");
}

/** Enclawed Code's own user-level policy file (see policy.mjs for precedence). */
export function userPolicyPath(env = process.env) {
  return path.join(appStateDir(env), "enclawed.json");
}

/** Enclawed Code's own settings (currently: the `policy use` pointer). */
export function appConfigPath(env = process.env) {
  return path.join(appStateDir(env), "config.json");
}

/** The hardware-root latch locations the framework uses (hardware-root/index.ts). */
export function hardwareLatchPaths(env = process.env) {
  const home = trimmed(env.HOME) ?? "/var/lib/enclawed";
  return {
    file: trimmed(env.ENCLAWEDER_STATE) ?? path.join(home, ".enclawed-hw-root.state"),
    dir: trimmed(env.ENCLAWEDER_STATE_DIR) ?? home,
  };
}

/** Where Claude Code reads file-based managed settings, per the Claude Code docs. */
export function managedSettingsDir(platform = process.platform) {
  if (platform === "darwin") {
    return "/Library/Application Support/ClaudeCode";
  }
  if (platform === "win32") {
    return "C:\\Program Files\\ClaudeCode";
  }
  return "/etc/claude-code";
}

/**
 * An optional organization-wide Enclawed policy for Claude Code. When this
 * file exists it is used instead of every other policy, so a user cannot
 * loosen it. It has the same shape as the enclawed config file
 * (`{ "enclawed": { "policy": { ... } } }`).
 */
export function managedPolicyPath(platform = process.platform) {
  if (platform === "darwin") {
    return "/Library/Application Support/Enclawed/claude-code/policy.json";
  }
  if (platform === "win32") {
    return "C:\\ProgramData\\Enclawed\\claude-code\\policy.json";
  }
  return "/etc/enclawed/claude-code/policy.json";
}

/** realpath of the longest existing prefix, with the rest appended (like the framework's realpathOrNearest). */
export function realpathNearest(abs) {
  let probe = abs;
  const rest = [];
  for (;;) {
    try {
      const real = fs.realpathSync(probe);
      return rest.length ? path.join(real, ...rest.reverse()) : real;
    } catch {
      const parent = path.dirname(probe);
      if (parent === probe) {
        return abs;
      }
      rest.push(path.basename(probe));
      probe = parent;
    }
  }
}

/** Normalized form for path comparison: NFC, and case-folded (see isInside). */
export function comparablePath(p) {
  return path.resolve(p).normalize("NFC").toLowerCase();
}

/**
 * True when `child` is `dir` or inside it. The comparison is Unicode NFC and
 * case-insensitive on every platform: on macOS and Windows the filesystem
 * ignores case, and on Linux a false match only makes a check stricter.
 */
export function isInside(dir, child) {
  const d = comparablePath(dir);
  const c = comparablePath(child);
  if (c === d) {
    return true;
  }
  const rel = path.relative(d, c);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}
