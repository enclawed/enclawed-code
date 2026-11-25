// Find the user's own Claude Code installation. Enclawed Code never bundles or
// modifies Claude Code; it runs whatever `claude` the user installed.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { APP_ROOT, appStateDir } from "./paths.mjs";

/** Lowest Claude Code version with `"onFailure": "block"` on hooks. */
export const MIN_CLAUDE_VERSION = "2.1.295";

function realpathOrNull(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

function isExecutable(p) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile()) {
      return false;
    }
    if (process.platform === "win32") {
      return true;
    }
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** True when `p` is this app (or another copy of it), so we never run ourselves. */
function isEcwcode(real) {
  if (real.startsWith(path.join(APP_ROOT, "bin") + path.sep)) {
    return true;
  }
  // Another install of Enclawed Code, e.g. a global one shadowing this checkout.
  try {
    const fd = fs.openSync(real, "r");
    try {
      const buf = Buffer.alloc(2048);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      // The pre-rename markers too: an older install is still never run as claude.
      const head = buf.subarray(0, n).toString("latin1");
      return head.includes("@enclawed-code-launcher") || head.includes("@codenclawed-launcher") || head.includes("@enclawde-launcher");
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return false;
  }
}

/**
 * The first `claude` on PATH that is not Enclawed Code itself, or the explicit
 * ECWCODE_CLAUDE_PATH. Returns null when there is none.
 */
export function locateClaude(env = process.env) {
  const explicit = env.ECWCODE_CLAUDE_PATH?.trim();
  if (explicit) {
    const real = realpathOrNull(explicit);
    return real && isExecutable(real) && !isEcwcode(real) ? explicit : null;
  }
  const names = process.platform === "win32" ? ["claude.exe", "claude.cmd", "claude"] : ["claude"];
  const dirs = (env.PATH ?? "").split(path.delimiter).filter(Boolean);
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (!isExecutable(candidate)) {
        continue;
      }
      const real = realpathOrNull(candidate);
      if (real && !isEcwcode(real)) {
        return candidate;
      }
    }
  }
  return null;
}

export function parseVersion(text) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(text));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export function versionAtLeast(v, min) {
  const a = parseVersion(v);
  const b = parseVersion(min);
  if (!a || !b) {
    return false;
  }
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) {
      return a[i] > b[i];
    }
  }
  return true;
}

/**
 * The installed claude's version, cached per executable (path, size, mtime)
 * so a launch does not pay for an extra `claude --version` every time;
 * `cached: false` asks claude every time (the reviewed-version gate).
 */
export function claudeVersion(claudePath, env = process.env, { cached = true } = {}) {
  const real = realpathOrNull(claudePath) ?? claudePath;
  let key = null;
  try {
    const st = fs.statSync(real);
    // The reviewed-version gate (claude-terms.mjs) asks Claude Code itself every time: a cache file
    // in the account's state is not something a compliance decision rests on.
    key = cached ? `${real}|${st.size}|${st.mtimeMs}` : null;
  } catch {
    /* uncacheable */
  }
  const cacheFile = path.join(appStateDir(env), "claude-version.json");
  if (key) {
    try {
      const cached = JSON.parse(fs.readFileSync(cacheFile, "utf8"));
      if (cached.key === key && typeof cached.version === "string") {
        return cached.version;
      }
    } catch {
      /* no cache yet */
    }
  }
  const res = spawnSync(claudePath, ["--version"], { encoding: "utf8", timeout: 30_000, env });
  const version = parseVersion(res.stdout) ? res.stdout.trim().split(/\s+/)[0] : null;
  if (version && key) {
    try {
      fs.mkdirSync(path.dirname(cacheFile), { recursive: true, mode: 0o700 });
      fs.writeFileSync(cacheFile, JSON.stringify({ key, version }), { mode: 0o600 });
    } catch {
      /* cache is best-effort */
    }
  }
  return version;
}
