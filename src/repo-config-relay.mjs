// Repository configuration that a contained git checks out inside an MCP
// server's containment (the proxy's, not the launcher's) is re-admitted by
// the launcher, with the same inputs as at launch, and a conflict is resolved
// at the launcher's own prompt. This module only carries the events and the
// approved writes between the processes, through the private session
// directory (0700, Enclawed Code's protected state):
//
//   <session>/repo-config-relay/requests/<id>.json    proxy -> launcher: the
//                                                      containment's event
//   <session>/repo-config-relay/writes/<origin>/<id>   launcher -> proxy: one
//                                                      approved write of a path
//
// Nothing here decides. The hold is the kit's (handleRepoConfigEvent: the
// proxy holds the session at once, the launcher's admission releases it),
// the conflict approval is the kit's (approveConflictResolution, a single-use
// grant), and the containment lets a write through only for a path it
// reported conflicted (approveRepoConfigWrite). A forged request can only
// hold the session or ask the person a question; a forged write approval
// names a path the containment does not have conflicted and is ignored, or
// one it has, which a person already saw as a conflict.

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const DIR = "repo-config-relay";
const POLL_MS = 250;

const originDir = (origin) => String(origin).replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 80) || "_";

function writeOnce(dir, body) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const f = path.join(dir, `${Date.now()}-${process.pid}-${randomBytes(6).toString("hex")}.json`);
  const tmp = `${f}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(body), { mode: 0o600 });
  fs.renameSync(tmp, f);
  return f;
}

function drain(dir, each) {
  let names;
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith(".json")).sort();
  } catch {
    return;
  }
  for (const n of names) {
    const f = path.join(dir, n);
    let body = null;
    try {
      body = JSON.parse(fs.readFileSync(f, "utf8"));
    } catch {
      /* torn or foreign: dropped */
    }
    fs.rmSync(f, { force: true });
    if (body && typeof body === "object") {
      each(body);
    }
  }
}

function poller(fn, intervalMs) {
  const t = setInterval(fn, intervalMs);
  t.unref?.();
  return { check: fn, stop: () => clearInterval(t) };
}

/** Proxy side: hand a containment's repository-configuration event to the launcher. */
export function forwardRepoConfigEvent(sessionDir, origin, event) {
  return writeOnce(path.join(sessionDir, DIR, "requests"), { origin: String(origin), event });
}

/** Launcher side: every forwarded event, once, as `onEvent(origin, event)`. */
export function watchRepoConfigRequests(sessionDir, onEvent, { intervalMs = POLL_MS } = {}) {
  const dir = path.join(sessionDir, DIR, "requests");
  return poller(() => drain(dir, (b) => typeof b.origin === "string" && b.event && onEvent(b.origin, b.event)), intervalMs);
}

/** Launcher side: a person approved one write of `p` in `origin`'s containment. */
export function approveRepoConfigWriteIn(sessionDir, origin, p) {
  writeOnce(path.join(sessionDir, DIR, "writes", originDir(origin)), { path: String(p) });
  return true;
}

/** Proxy side: apply each write the launcher approved for this origin (`apply(path)`, the containment's approveRepoConfigWrite). */
export function watchRepoConfigWrites(sessionDir, origin, apply, { intervalMs = POLL_MS } = {}) {
  const dir = path.join(sessionDir, DIR, "writes", originDir(origin));
  return poller(
    () =>
      drain(dir, (b) => {
        if (typeof b.path === "string") {
          try {
            apply(b.path);
          } catch {
            /* not a conflicted file of this containment: nothing is let through */
          }
        }
      }),
    intervalMs,
  );
}

/**
 * A session with no launcher (managed mode, a contain-holder): Enclawed Code's
 * launch admission run again over the project as it is now (launcher.mjs
 * readmitRepository, the same rules and inputs as a launch from it).
 */
export async function readmitLauncherless({ env, projectDir }) {
  if (typeof projectDir !== "string" || !env || typeof env !== "object") {
    return { ok: false, refusals: ["the session does not say how it was admitted"] };
  }
  const [{ readmitRepository }, { loadFramework }, { LockedAuditLog }, { loadPolicy }, { policyCandidates }, { shellFlavor }, { auditLogPath }] = await Promise.all([
    import("./launcher.mjs"),
    import("./framework.mjs"),
    import("./audit.mjs"),
    import("./policy.mjs"),
    import("./session.mjs"),
    import("./env-authority.mjs"),
    import("./paths.mjs"),
  ]);
  const { fw } = await loadFramework();
  const loaded = loadPolicy(fw, { candidates: policyCandidates(env, { fw }), flavor: shellFlavor(env).flavor });
  const said = [];
  return readmitRepository({ env, cwd: projectDir, fw, loaded, audit: new LockedAuditLog(fw, auditLogPath(env)), stderr: { write: (t) => said.push(String(t).trim()) } });
}

/** Inadmissible files leave the project, into the session's quarantine. */
export function quarantineInto(sessionDir, paths) {
  const q = path.join(sessionDir, "quarantine");
  fs.mkdirSync(q, { recursive: true, mode: 0o700 });
  for (const p of paths) {
    try {
      fs.renameSync(p, path.join(q, `${Date.now()}-${path.basename(p)}`));
    } catch {
      /* gone already */
    }
  }
}
