// The Claude Code versions Enclawed Code was reviewed with (a compliance control).
//
// Enclawed Code runs Claude Code under Anthropic's terms, reviewed in
// docs/legal-review.md. A newer Claude Code may come with new terms that
// Enclawed Code has not reviewed, so a session starts only with a Claude Code
// version listed in legal/reviewed-terms.json (`claudeCode.versions`, part of
// this installation's measured code). Any other version, and a version that
// cannot be read, refuses (fail closed). No environment variable, setting or
// opt-out changes this.
//
// Inside its own sessions Enclawed Code turns off Claude Code's automatic
// updates with Claude Code's documented variables (DISABLE_AUTOUPDATER and
// DISABLE_UPDATES, https://code.claude.com/docs/en/setup#disable-auto-updates),
// in the session's environment and its generated --settings. The person's own
// settings are never changed.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { APP_ROOT } from "./paths.mjs";

/** The reviewed-terms record shipped with this installation. */
export const REVIEWED_TERMS_FILE = path.join(APP_ROOT, "legal", "reviewed-terms.json");

/** Claude Code's documented variables that stop its updates (set only inside Enclawed Code's sessions). */
export const SESSION_UPDATE_ENV = Object.freeze({ DISABLE_AUTOUPDATER: "1", DISABLE_UPDATES: "1" });

const VERSION_RE = /^\d+\.\d+\.\d+$/;

/** The reviewed Claude Code versions, or null when the record is unreadable or malformed. */
export function reviewedClaudeVersions(file = REVIEWED_TERMS_FILE) {
  try {
    const doc = JSON.parse(fs.readFileSync(file, "utf8"));
    const v = doc?.claudeCode?.versions;
    if (!Array.isArray(v) || v.length === 0 || !v.every((x) => typeof x === "string" && VERSION_RE.test(x))) {
      return null;
    }
    return [...v];
  } catch {
    return null;
  }
}

function newest(versions) {
  return [...versions].sort((a, b) => {
    const x = a.split(".").map(Number);
    const y = b.split(".").map(Number);
    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
  })[versions.length - 1];
}

/**
 * How to install `version` for the installation at `claudePath` (Claude Code's documented
 * commands, https://code.claude.com/docs/en/setup#install-a-specific-version and #install-with-npm).
 */
export function installReviewedCommand(claudePath, version) {
  let real = claudePath ?? "";
  try {
    real = fs.realpathSync(claudePath);
  } catch {
    /* as given */
  }
  const native = `curl -fsSL https://claude.ai/install.sh | bash -s ${version}`;
  const npm = `npm install -g @anthropic-ai/claude-code@${version}`;
  if (real.includes(`${path.sep}.local${path.sep}share${path.sep}claude${path.sep}versions${path.sep}`)) {
    return `this is a native installation: ${native}`;
  }
  if (real.includes(`node_modules${path.sep}@anthropic-ai${path.sep}claude-code`)) {
    return `this is an npm installation: ${npm}`;
  }
  return `with Claude Code's native installer: ${native} (or, for an npm installation: ${npm})`;
}

/**
 * The gate. `version`: what `claude --version` printed (claude.mjs claudeVersion), or null.
 * @returns {{ ok: true, version: string } | { ok: false, code: "claude-version-unreadable" | "claude-version-unreviewed" | "reviewed-terms-unreadable", message: string }}
 */
export function claudeVersionGate(version, claudePath, { file = REVIEWED_TERMS_FILE } = {}) {
  const reviewed = reviewedClaudeVersions(file);
  if (!reviewed) {
    return { ok: false, code: "reviewed-terms-unreadable", message: `the list of reviewed Claude Code versions (${file}) cannot be read; reinstall Enclawed Code` };
  }
  const list = reviewed.join(", ");
  const how = installReviewedCommand(claudePath, newest(reviewed));
  if (typeof version !== "string" || !VERSION_RE.test(version)) {
    return {
      ok: false,
      code: "claude-version-unreadable",
      message: `the version of Claude Code at ${claudePath} could not be read, so Enclawed Code cannot tell whether it runs under terms it has reviewed. Enclawed Code was reviewed with Claude Code ${list}. To install a reviewed version, ${how}`,
    };
  }
  if (!reviewed.includes(version)) {
    return {
      ok: false,
      code: "claude-version-unreviewed",
      message: `Claude Code ${version} (${claudePath}) is not a version Enclawed Code has reviewed; reviewed: ${list}. A newer Claude Code may come with new terms that Enclawed Code has not reviewed yet (docs/legal-review.md), so Enclawed Code does not start a session with it. To install a reviewed version, ${how}`,
    };
  }
  return { ok: true, version };
}

const NOT_CLAUDE = new Set(["sh", "bash", "dash", "zsh", "ksh", "fish", "busybox", "env", "node", "nodejs", "bun", "timeout", "nice", "nohup", "stdbuf"]);

function parentOf(pid, run) {
  if (process.platform === "linux") {
    try {
      const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
      return Number.isInteger(ppid) ? ppid : null;
    } catch {
      return null;
    }
  }
  const r = run("/bin/ps", ["-o", "ppid=", "-p", String(pid)], { encoding: "utf8", timeout: 5000 });
  const ppid = Number(String(r.stdout ?? "").trim());
  return Number.isInteger(ppid) && ppid > 0 ? ppid : null;
}

function exeOf(pid, run) {
  if (process.platform === "linux") {
    try {
      return fs.readlinkSync(`/proc/${pid}/exe`);
    } catch {
      return null;
    }
  }
  const r = run("/bin/ps", ["-o", "comm=", "-p", String(pid)], { encoding: "utf8", timeout: 5000 });
  const exe = String(r.stdout ?? "").trim();
  return exe.startsWith("/") ? exe : null;
}

/**
 * The executable of the Claude Code that runs this hook (managed mode, where no launcher started
 * it): the nearest ancestor process that is not a shell, `env` or a JavaScript runtime. Null when
 * none is found.
 */
export function claudeAncestorExecutable({ run = null } = {}) {
  const runner = run ?? spawnSync;
  let pid = process.ppid;
  for (let i = 0; i < 8 && pid && pid > 1; i++) {
    const exe = exeOf(pid, runner);
    if (exe && !NOT_CLAUDE.has(path.basename(exe).replace(/\.exe$/i, ""))) {
      return exe;
    }
    pid = parentOf(pid, runner);
  }
  return null;
}

/**
 * The gate for a managed hook (no launcher): the version of the Claude Code that runs it.
 * `version`: the suite's stand-in (authority.mjs managedClaudeVersion), else read from the ancestor.
 */
export function managedClaudeVersionGate({ env = process.env, testVersion = undefined, readVersion }) {
  if (testVersion !== undefined) {
    return claudeVersionGate(testVersion, "(the suite's Claude Code)");
  }
  const exe = claudeAncestorExecutable();
  return claudeVersionGate(exe ? readVersion(exe, env) : null, exe ?? "(the Claude Code that runs this hook)");
}
