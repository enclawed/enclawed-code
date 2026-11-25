// What the launcher knows about the session it starts, for binding a hook's
// decision to the context it was made in (round 5): the session directory,
// the permission mode claude was started in, and where Claude Code puts the
// session scratchpad. See contextMatches (call-binding.mjs).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { realpathNearest } from "./paths.mjs";
import { lowerSettingsFiles } from "./session.mjs";
import { PERMISSION_MODES } from "./settings.mjs";
import { projectSlug } from "./transcript-watch.mjs";

/**
 * The permission mode claude's arguments start it in (null when they do not
 * say: settings `permissions.defaultMode` then decides), and whether
 * bypassPermissions is available at all.
 */
export function launchedPermissionMode(args) {
  const pre = args.slice(0, args.includes("--") ? args.indexOf("--") : args.length);
  let mode = null;
  for (let i = 0; i < pre.length; i++) {
    const a = pre[i];
    if (a === "--permission-mode" && i + 1 < pre.length) {
      mode = pre[i + 1];
    } else if (a.startsWith("--permission-mode=")) {
      mode = a.slice("--permission-mode=".length);
    }
  }
  if (pre.includes("--dangerously-skip-permissions")) {
    mode = "bypassPermissions";
  }
  const bypassAvailable = mode === "bypassPermissions" || pre.includes("--allow-dangerously-skip-permissions");
  return { mode, bypassAvailable };
}

/** Temp roots Claude Code may put `claude-<uid>/...` under. */
export function scratchRoots(env) {
  const out = new Set();
  for (const r of [env.CLAUDE_CODE_TMPDIR, env.TMPDIR, os.tmpdir(), "/tmp"]) {
    if (typeof r === "string" && path.isAbsolute(r)) {
      out.add(path.normalize(r));
      out.add(realpathNearest(r));
    }
  }
  return [...out];
}

/** permissions.defaultMode from the settings files claude reads (the last one set wins), or null. */
export function settingsDefaultMode({ cwd, env, userSettings = [] }) {
  let mode = null;
  const files = lowerSettingsFiles({ projectDir: realpathNearest(path.resolve(cwd)), env });
  const objs = files.map(({ file }) => {
    try {
      return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      return null;
    }
  });
  for (const s of [...objs, ...userSettings]) {
    const m = s?.permissions?.defaultMode;
    if (typeof m === "string") {
      mode = m;
    }
  }
  return mode;
}

/** The launch facts contextMatches needs. */
export function launchContext({ args, env, cwd, print, userSettings = [] }) {
  const fromArgs = launchedPermissionMode(args);
  const fromSettings = settingsDefaultMode({ cwd, env, userSettings });
  // The settings mode is only used for availability: managed settings may differ.
  const mode = fromArgs.mode;
  const bypassAvailable = fromArgs.bypassAvailable || fromSettings === "bypassPermissions";
  return {
    cwd: realpathNearest(path.resolve(cwd)),
    realpath: (p) => realpathNearest(p),
    modes: PERMISSION_MODES,
    launchedMode: mode,
    print,
    bypassAvailable,
    scratchRoots: scratchRoots(env),
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    slug: projectSlug,
  };
}
