// `ecwctl history`: the file versions kept before writes, authenticated by
// the hash-chained audit log.
//
// The history store's index (history/index.jsonl) is a plain file with no
// integrity of its own, so anyone who can write it could plant an entry that
// makes `history restore` write chosen content anywhere (red-team I12). The
// entries Enclawed Code lists and restores therefore come from the audit log: each
// PreToolUse record names its target's real path, its snapshot hash, the
// project directory and the file's mode, and the record's own hash is the
// entry's id. A restore takes an id (or a hash that names exactly one path,
// I13), checks the audit chain, restores only to the recorded path inside the
// recorded project unless `--to` says otherwise, keeps what it replaces, puts
// the original file mode back, and records itself in the audit log.
//
// Index entries with no audit record (the Enclawed gateway's own snapshots,
// which share the store, including its sandbox snapshots) are listed only
// with --all, marked unverified, and restorable only with --unverified --to.

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import readline from "node:readline";
import { segmentFiles } from "./audit.mjs";
import { isInside } from "./paths.mjs";

const HASH = /^[0-9a-f]{64}$/;

async function* auditRecords(file) {
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
        yield JSON.parse(line);
      } catch {
        /* chain verification reports bad lines */
      }
    }
  }
}

/** History entries confirmed by audit records, oldest first. */
export async function verifiedEntries(auditFile) {
  const out = [];
  for await (const r of auditRecords(auditFile)) {
    const p = r.payload ?? {};
    if (r.type === "claude-code.tool.pre" && Array.isArray(p.targets)) {
      p.targets.forEach((t, i) => {
        if (t && t.basis === "snapshot") {
          out.push({
            id: p.targets.length > 1 ? `${r.recordHash.slice(0, 12)}.${i}` : r.recordHash.slice(0, 12),
            ts: r.ts,
            hash: t.snapshot ?? null,
            realPath: t.realPath,
            path: t.path,
            mode: typeof t.mode === "number" ? t.mode : null,
            projectDir: p.projectDir ?? p.cwd ?? null,
            tool: p.tool,
            toolUseId: p.toolUseId ?? null,
            sessionId: p.sessionId ?? null,
            op: t.op,
            verified: true,
          });
        }
      });
    } else if (r.type === "claude-code.history.restore" && p.outcome === "restored" && p.replacedSnapshot) {
      out.push({
        id: r.recordHash.slice(0, 12),
        ts: r.ts,
        hash: p.replacedSnapshot,
        realPath: p.to,
        path: p.to,
        mode: p.replacedMode ?? null,
        projectDir: null,
        tool: "history.restore",
        toolUseId: null,
        sessionId: null,
        op: "restore",
        verified: true,
      });
    }
  }
  return out;
}

/** Index entries that no audit record confirms. */
export async function unverifiedEntries(store, verified) {
  const known = new Set(verified.map((e) => `${e.hash}|${e.realPath}`));
  return (await store.list())
    .filter((e) => !known.has(`${e.hash}|${e.realPath}`))
    .map((e, i) => ({ ...e, id: `u${String(i).padStart(4, "0")}`, verified: false }));
}

export class HistoryError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.name = "HistoryError";
  }
}

/** Resolve a restore argument (id, id prefix, or snapshot hash) to one entry. */
export function resolveEntry(entries, ref) {
  if (typeof ref !== "string" || ref === "") {
    throw new HistoryError("usage", "name a history entry id (see: ecwctl history list)");
  }
  const r = ref.toLowerCase();
  if (HASH.test(r)) {
    const byHash = entries.filter((e) => e.hash === r);
    if (byHash.length === 0) {
      throw new HistoryError("unknown", `no recorded version has hash ${r.slice(0, 12)}…`);
    }
    const paths = new Set(byHash.map((e) => e.realPath));
    if (paths.size > 1) {
      throw new HistoryError(
        "ambiguous",
        `hash ${r.slice(0, 12)}… was kept for ${paths.size} different files; restore by id instead: ${byHash.map((e) => `${e.id} (${e.realPath})`).join(", ")}`,
      );
    }
    return byHash.at(-1);
  }
  if (!/^[0-9a-fu][0-9a-f.]{5,}$/.test(r)) {
    throw new HistoryError("usage", `${ref} is not a history entry id or snapshot hash`);
  }
  const hits = entries.filter((e) => e.id === r || e.id.startsWith(r));
  if (hits.length === 0) {
    throw new HistoryError("unknown", `no history entry ${ref} (see: ecwctl history list)`);
  }
  if (hits.length > 1) {
    throw new HistoryError("ambiguous", `${ref} matches ${hits.length} entries; give more of the id`);
  }
  return hits[0];
}

/**
 * Restore one entry.
 * @returns {Promise<{ id: string, hash: string, to: string, replacedSnapshot: string|null, mode: number|null }>}
 */
export async function restoreEntry({ entry, to, store, audit }) {
  const fail = async (code, message) => {
    await audit({ type: "claude-code.history.restore", actor: "enclawed-code", level: null, payload: { id: entry?.id ?? null, hash: entry?.hash ?? null, outcome: "refused", code, to: to ?? null } });
    throw new HistoryError(code, message);
  };
  if (!entry.hash) {
    return fail("no-content", `entry ${entry.id} records that ${entry.realPath} did not exist yet; there is no content to restore (delete the file to undo its creation)`);
  }
  if (entry.sandbox) {
    return fail(
      "sandbox",
      `entry ${entry.id} came from an Enclawed gateway sandbox (${entry.sandbox.backendId ?? "sandbox"}), which Enclawed Code cannot open; restore it on this machine with: ecwctl history restore ${entry.hash} --unverified --to <path>`,
    );
  }
  if (!entry.verified && !to) {
    return fail("unverified", `entry ${entry.id} has no audit record, so its recorded path is not trusted; pass --to <path> to choose where it goes`);
  }
  let target;
  if (to) {
    target = path.resolve(to);
  } else {
    target = entry.realPath;
    if (entry.projectDir && !isInside(entry.projectDir, target)) {
      return fail("path-binding", `entry ${entry.id} names ${target}, outside its recorded project ${entry.projectDir}; pass --to <path> to restore it deliberately`);
    }
  }
  let content;
  try {
    content = await store.readVerified(entry.hash);
  } catch (err) {
    return fail(err?.code === "tampered" ? "tampered" : "missing", err?.code === "tampered" ? err.message : `the kept version ${entry.hash.slice(0, 12)}… is no longer in ${store.dir}`);
  }
  let replacedSnapshot = null;
  let replacedMode = null;
  try {
    const st = await fsp.lstat(target);
    if (st.isFile()) {
      replacedMode = st.mode & 0o7777;
      const current = await fsp.readFile(target);
      const put = await store.put(current);
      if (put.ok) {
        replacedSnapshot = put.hash;
        await store.record({ path: target, realPath: target, op: "restore", hash: put.hash, size: current.length, tool: "history.restore", toolCallId: null, agentId: null });
      }
    }
  } catch {
    /* nothing there yet */
  }
  const mode = entry.mode ?? replacedMode ?? null;
  try {
    await fsp.mkdir(path.dirname(target), { recursive: true });
    const tmp = `${target}.${randomBytes(6).toString("hex")}.restore.tmp`;
    await fsp.writeFile(tmp, content, { flag: "wx", ...(mode !== null ? { mode } : {}) });
    if (mode !== null) {
      await fsp.chmod(tmp, mode);
    }
    await fsp.rename(tmp, target);
  } catch (err) {
    return fail("write-failed", `could not write ${target}: ${err.message}`);
  }
  await audit({
    type: "claude-code.history.restore",
    actor: "enclawed-code",
    level: null,
    payload: { id: entry.id, hash: entry.hash, outcome: "restored", to: target, replacedSnapshot, replacedMode, mode, verifiedEntry: entry.verified },
  });
  return { id: entry.id, hash: entry.hash, to: target, replacedSnapshot, mode };
}
