// The person's Claude Code session context and the credentials the session's tools make, sealed
// at rest between sessions under the Enclaweder (the root takeover: root runs plain `claude`,
// `claude -c` or `gh`, `npm`, `aws` ... with the person's context and the session's logins).
//
// Every decision is the kit's (enclawed-oss adapter/context-seal.ts, tool-credentials.ts,
// sealed-box.ts; the boxes are credential-keys.ts boxes.context and boxes.tools, derived with the
// login's KEY_DERIVE on the launch's device-verified activation). What is here is Claude Code's
// map:
//
//   - claude runs with CLAUDE_CONFIG_DIR pointed at a directory private to the session, under
//     the session root (XDG_RUNTIME_DIR first: memory-backed). Its context there (the names in
//     CONTEXT below: transcripts and per-project memory, todos, plans, prompt history, file
//     backups, pasted content) is opened from the sealed store at launch and sealed again at the
//     end (and at a halt); the configuration Enclawed Code admitted at launch (settings, CLAUDE.md,
//     skills, plugins, agents, commands ...) is linked from the person's own config directory;
//     Claude Code's global state file (.claude.json) is a copy, discarded at the end; shell
//     snapshots, session-env scripts, jobs and caches never outlive the session.
//   - the session's tools are redirected into a second private directory (the kit's
//     TOOL_REDIRECTS, git's own global config, no keyring bus), sealed the same way under the
//     tools box; the kit's floor sweep catches what a tool wrote into the person's home anyway.
//   - the stores' digests are records of Enclawed Code's device-anchored audit log
//     (claude-code.context.sealed / .adopted / .discarded); a store that is not what the log
//     last recorded is refused at launch.
//
// What stays: during a live session root can read both directories (and the launcher's memory).

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { segmentFiles } from "./audit.mjs";
import { claudeStateFile } from "./mcp.mjs";
import { kit } from "./kit.mjs";
import { appStateDir, auditLogPath, homeDir } from "./paths.mjs";
import { sessionRoot } from "./session.mjs";

/** Labels of the two stores (bound into every record). */
export const CONTEXT_LABEL = "claude-code.context";
export const TOOLS_LABEL = "claude-code.tool-credentials";

/** Claude Code 2.1.326's context names in its config directory. */
export const CONTEXT = Object.freeze(["projects", "todos", "plans", "file-history", "history.jsonl", "tasks", "teams", "paste-cache", "image-cache", "backups", "debug"]);
/** Its configuration names, linked from the person's own config directory (what admission read). */
export const LINKED = Object.freeze(["settings.json", "CLAUDE.md", "agents", "commands", "skills", "plugins", "output-styles", "keybindings.json", "rules", "hooks"]);

/** The person's own Claude Code config directory. */
export function personConfigDir(env = process.env) {
  return env.CLAUDE_CONFIG_DIR || path.join(homeDir(env), ".claude");
}

export function contextLayout(env = process.env) {
  const src = personConfigDir(env);
  return {
    context: [...CONTEXT],
    linked: Object.fromEntries(LINKED.map((n) => [n, path.join(src, n)])),
    copied: { ".claude.json": claudeStateFile(env) },
  };
}

export function contextStoreDir(env = process.env) {
  return path.join(appStateDir(env), "context", "sealed");
}
export function toolStoreDir(env = process.env) {
  return path.join(appStateDir(env), "tool-credentials", "sealed");
}

/** Names at the top of the home directory the floor sweep never touches (Claude Code's and Enclawed's state). */
export function sweepExcluded(env = process.env) {
  const home = homeDir(env);
  let names = [];
  try {
    names = fs.readdirSync(home);
  } catch {
    names = [];
  }
  const own = names.filter((n) => n.startsWith(".enclawed") || n === ".clawdbot");
  const cfg = path.relative(home, personConfigDir(env)).split(path.sep)[0];
  return [...new Set([".claude", ".claude.json", ...own, ...(cfg && !cfg.startsWith("..") ? [cfg] : [])])];
}

async function auditRecords(file) {
  const out = [];
  for (const f of [...segmentFiles(file).map((s) => s.file), file]) {
    if (!fs.existsSync(f)) {
      continue;
    }
    const rl = readline.createInterface({ input: fs.createReadStream(f, "utf8"), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) {
        continue;
      }
      try {
        const r = JSON.parse(line);
        if (typeof r?.type === "string" && r.type.startsWith("claude-code.context.")) {
          out.push(r);
        }
      } catch {
        /* chain verification reports bad lines */
      }
    }
  }
  return out;
}

/** The digests Enclawed Code's audit log last recorded for the two stores. */
export async function recordedDigests(env = process.env) {
  const recs = await auditRecords(auditLogPath(env));
  return { context: kit.lastRecordedContextDigest(recs, CONTEXT_LABEL), tools: kit.lastRecordedContextDigest(recs, TOOLS_LABEL) };
}

/**
 * Before the launch's activation: a sealed store that is not what the audit log last recorded
 * refuses the launch here, so the refusal spends no device-unlock use (openSessionState checks it
 * again after the activation).
 * @returns {Promise<{ ok: true } | { ok: false, code: string, message: string }>}
 */
export async function sessionStatePrecheck({ env = process.env, k = kit } = {}) {
  const recorded = await recordedDigests(env);
  for (const [name, dir, rec] of [
    ["session context", contextStoreDir(env), recorded.context],
    ["tool credentials", toolStoreDir(env), recorded.tools],
  ]) {
    const v = k.contextSealVerdict({ sealedDir: dir, recorded: rec });
    if (!v.ok) {
      return { ok: false, code: `context-${v.code}`, message: `the sealed ${name} cannot be opened: ${v.message} (to start afresh, discarding it: ecwctl context discard)` };
    }
  }
  return { ok: true };
}

const record = (audit, kind, label, payload) => audit({ type: `claude-code.${kit.CONTEXT_SEAL_RECORD[kind]}`, actor: "enclawed-code", level: null, payload: { label, ...payload } });

/**
 * At launch, after the login is open (`boxes`: the launch's open boxes, credential-keys.ts):
 * stale session directories are sealed, both stores opened into fresh private directories after
 * the audit check, the person's tool configuration seeded, the floor snapshotted. Returns
 * applyEnv (claude's CLAUDE_CONFIG_DIR and the tools' variables) and close().
 * @returns {Promise<{ ok: true, action: "pass" } | { ok: true, action: "sealed", applyEnv: (e: object) => object, close: (o?: { halted?: boolean }) => Promise<object>, contextDir: string, toolDir: string, plaintextOutside: string[] } | { ok: false, code: string, message: string }>}
 */
export async function openSessionState({ env = process.env, cwd = process.cwd(), boxes, audit = async () => {}, k = kit }) {
  if (!boxes?.context || !boxes?.tools) {
    return { ok: true, action: "pass" };
  }
  const parent = sessionRoot(env, cwd);
  const ctx = { sealedDir: contextStoreDir(env), box: boxes.context, label: CONTEXT_LABEL, layout: contextLayout(env) };
  const tools = { sealedDir: toolStoreDir(env), box: boxes.tools, label: TOOLS_LABEL, layout: k.toolCredentialLayout() };
  // A session that ended without sealing (killed, the computer stopped): sealed now, recorded.
  for (const s of [ctx, tools]) {
    await k.recoverContextDirs({ parent, ...s, onSealed: (r) => record(audit, "sealed", s.label, { digest: r.digest, sealed: r.sealed, kept: r.kept, removed: r.removed, recovered: true }) });
  }
  const recorded = await recordedDigests(env);
  const opened = [];
  const undo = () => {
    for (const o of opened) {
      k.eraseTree(o.dir);
    }
  };
  for (const [s, rec] of [
    [ctx, recorded.context],
    [tools, recorded.tools],
  ]) {
    const p = k.prepareContextDir({ parent, layout: s.layout });
    if (!p.ok) {
      undo();
      return { ok: false, code: p.code, message: p.message };
    }
    const o = await k.withContextLock(s.sealedDir, () => k.openContextInto({ ...s, dir: p.dir, recorded: rec }));
    if (!o.ok) {
      k.eraseTree(p.dir);
      undo();
      await record(audit, "refused", s.label, { code: o.code }).catch(() => {});
      const fix = o.code === "not-as-recorded" || o.code === "unrecorded" || o.code === "store-invalid" ? " (to start afresh, discarding it: ecwctl context discard)" : "";
      return { ok: false, code: `context-${o.code}`, message: `the sealed ${s === ctx ? "session context" : "tool credentials"} cannot be opened: ${o.message}${fix}` };
    }
    opened.push({ ...s, dir: p.dir, baseline: o.baseline });
  }
  const [c, t] = opened;
  t.baseline = k.seedToolCredentials({ dir: t.dir, home: homeDir(env), baseline: t.baseline });
  const floor = k.snapshotCredentialFloor({ home: homeDir(env), excluded: sweepExcluded(env) });
  const agentBefore = k.sshAgentIdentities(env);
  const plaintextOutside = k.plaintextContextAt({ sourceDir: personConfigDir(env), layout: ctx.layout });
  let closed = null;
  const close = async ({ halted = false } = {}) => {
    if (closed) {
      return closed;
    }
    const swept = k.sweepCredentialFloor({ snapshot: floor, into: t.dir, excluded: sweepExcluded(env) });
    const ssh = k.removeAddedSshIdentities(env, agentBefore);
    const out = { ok: true, swept, ssh, stores: [] };
    for (const s of [t, c]) {
      // Sealing needs only the box's public key: no device, so a halt seals too.
      const r = await k.withContextLock(s.sealedDir, async () => {
        const res = k.sealContextFrom({ dir: s.dir, sealedDir: s.sealedDir, box: s.box, label: s.label, layout: s.layout, baseline: s.baseline });
        if (res.ok) {
          await record(audit, "sealed", s.label, { digest: res.digest, sealed: res.sealed, kept: res.kept, removed: res.removed, skipped: res.skipped.length, halted, ...(s === t ? { swept: swept.map((f) => ({ path: f.rel, change: f.change, why: f.why })), sshRemoved: ssh.removed, sshNotRemoved: ssh.failed } : {}) });
        }
        return res;
      });
      out.stores.push({ label: s.label, ...r });
      if (!r.ok || r.remaining.length) {
        out.ok = false;
      }
    }
    if (ssh.failed.length) {
      out.ok = false;
    }
    closed = out;
    return out;
  };
  const applyEnv = (e) => ({ ...k.toolCredentialEnv({ dir: t.dir, home: homeDir(env), env: e }), CLAUDE_CONFIG_DIR: c.dir });
  return { ok: true, action: "sealed", applyEnv, close, contextDir: c.dir, toolDir: t.dir, plaintextOutside };
}

export const CONTEXT_HELP = `usage:
  ecwctl context status    the sealed stores, and any plaintext context left in Claude Code's own directory
  ecwctl context discard   erase both sealed stores (recorded); the next launch starts with no context
`;

/** `ecwctl context status|discard`. Never prints content. */
export async function contextCommand(args, { out, err, env = process.env, audit = async () => {}, k = kit }) {
  const sub = args[0];
  const recorded = await recordedDigests(env);
  const stores = [
    { name: "session context", label: CONTEXT_LABEL, dir: contextStoreDir(env), rec: recorded.context },
    { name: "tool credentials", label: TOOLS_LABEL, dir: toolStoreDir(env), rec: recorded.tools },
  ];
  if (sub === "status") {
    for (const s of stores) {
      const v = k.contextSealVerdict({ sealedDir: s.dir, recorded: s.rec });
      const count = fs.existsSync(s.dir) ? fs.readdirSync(s.dir).filter((n) => n.endsWith(".ctx")).length : 0;
      out.write(`${s.name}: ${count} sealed record(s) in ${s.dir}; ${v.ok ? "as the audit log last recorded" : `REFUSED (${v.code}): ${v.message}`}\n`);
    }
    const plain = k.plaintextContextAt({ sourceDir: personConfigDir(env), layout: contextLayout(env) });
    out.write(`plaintext context in ${personConfigDir(env)}: ${plain.length ? `${plain.join(", ")} (made outside Enclawed Code; readable by any process of this user)` : "none"}\n`);
    return 0;
  }
  if (sub !== "discard") {
    err.write(CONTEXT_HELP);
    return 2;
  }
  let ok = true;
  for (const s of stores) {
    await k.withContextLock(s.dir, async () => {
      const r = k.discardSealedContext(s.dir);
      ok &&= r.remaining.length === 0;
      await record(audit, "discarded", s.label, { digest: k.EMPTY_CONTEXT_DIGEST, erased: r.erased });
    });
  }
  out.write(ok ? "both sealed stores were erased; the next launch starts with no session context and no session tool logins\n" : "some sealed records could not be erased\n");
  return ok ? 0 : 1;
}
