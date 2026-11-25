// Appends to the hash-chained audit log from many short-lived processes.
//
// Claude Code runs one hook process per event, and runs matching hooks in
// parallel. The framework's AuditLogger chains each record to the previous
// one it knows about, so two processes appending at once would both chain to
// the same predecessor and break the chain. Every append therefore takes an
// exclusive lock file beside the log, opens a fresh AuditLogger (which reads
// the current head from the file), appends, and closes.
//
// Continuity: the AuditLogger chains onto whatever the file's last record
// is, so truncating the log and letting the next append re-anchor the head
// would heal the damage silently (red-team I5); deleting the log would start a
// fresh chain (I6). Before every append, under the lock, the file's tail is
// compared with the head anchor `audit.jsonl.head`. When they disagree a
// `claude-code.audit.gap` record is written first, naming both hashes, and
// `ecwctl audit verify` fails for as long as the log holds a gap record.
// This detects removal; it cannot stop someone who can write both the log
// and its anchor from fabricating a whole new history (see docs/commands.md
// on the audit log's limits): the Enclaweder anchoring is the remedy for that.

import fsSync from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";

// Well inside the 10 s PreToolUse hook timeout.
const LOCK_WAIT_MS = 4000;
const LOCK_STALE_MS = 30_000;
export const GAP_TYPE = "claude-code.audit.gap";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Take the lock or throw by the deadline. Every path sleeps and checks the deadline (R1). */
export async function acquireLock(lockPath, waitMs = LOCK_WAIT_MS) {
  // The deadline is on the monotonic clock: a wall clock that steps (WSL2
  // steps it by seconds) must not stretch a stalled hook past its budget.
  const deadline = performance.now() + waitMs;
  for (let attempt = 0; ; attempt++) {
    try {
      const fh = await fs.open(lockPath, "wx", 0o600);
      await fh.writeFile(`${process.pid}\n`);
      await fh.close();
      return;
    } catch (err) {
      if (err.code !== "EEXIST") {
        throw err;
      }
    }
    let st = null;
    try {
      st = await fs.lstat(lockPath);
    } catch {
      /* released meanwhile: retry after the pause below */
    }
    if (st && !st.isFile()) {
      // Only Enclawed Code creates this lock, always as a regular file.
      throw new Error(`audit lock ${lockPath} is not a regular file; refusing to proceed unaudited`);
    }
    // A holder that died leaves its lock behind; a live holder finishes in
    // milliseconds, so a lock this old is abandoned.
    if (st && Date.now() - st.mtimeMs > LOCK_STALE_MS) {
      await fs.rm(lockPath, { force: true });
    }
    if (performance.now() > deadline) {
      throw new Error(`audit log is locked (${lockPath}); refusing to proceed unaudited`);
    }
    await sleep(Math.min(50, 5 + attempt * 2));
  }
}

/** recordHash of the file's last record, null for an empty or missing file. */
export async function tailHash(file) {
  let fh;
  try {
    fh = await fs.open(file, "r");
  } catch {
    return { exists: false, hash: null };
  }
  try {
    const { size } = await fh.stat();
    if (size === 0) {
      return { exists: true, hash: null };
    }
    const buf = Buffer.alloc(Math.min(65536, size));
    await fh.read(buf, 0, buf.length, Math.max(0, size - buf.length));
    const lines = buf.toString("utf8").split("\n").filter(Boolean);
    try {
      const h = JSON.parse(lines[lines.length - 1]).recordHash;
      return { exists: true, hash: typeof h === "string" ? h : "unparseable" };
    } catch {
      return { exists: true, hash: "unparseable" };
    }
  } finally {
    await fh.close();
  }
}

export async function readHeadAnchor(logFile) {
  try {
    const raw = (await fs.readFile(`${logFile}.head`, "utf8")).trim();
    return { exists: true, hash: /^[0-9a-f]{64}$/.test(raw) ? raw : null };
  } catch {
    return { exists: false, hash: null };
  }
}

/** Sealed rotation segments beside the log (audit.1.jsonl, ...). */
export function segmentFiles(logFile) {
  const dir = path.dirname(logFile);
  const base = path.basename(logFile);
  const ext = path.extname(base);
  const prefix = `${base.slice(0, base.length - ext.length)}.`;
  let names = [];
  try {
    names = fsSync.readdirSync(dir);
  } catch {
    return [];
  }
  return names
    .filter((n) => n.startsWith(prefix) && n.endsWith(ext) && /^\d+$/.test(n.slice(prefix.length, n.length - ext.length)))
    .map((n) => ({ seq: Number(n.slice(prefix.length, n.length - ext.length)), file: path.join(dir, n) }))
    .sort((a, b) => a.seq - b.seq);
}

/**
 * Does the log continue where the anchor says it ended? Returns null when it
 * does, or the gap to record.
 */
export async function continuityGap(logFile) {
  const head = await readHeadAnchor(logFile);
  let tail = await tailHash(logFile);
  if (tail.hash === null) {
    // An empty current file continues from the newest sealed segment.
    const segs = segmentFiles(logFile);
    if (segs.length > 0) {
      tail = { exists: true, hash: (await tailHash(segs.at(-1).file)).hash };
    }
  }
  if (head.hash !== null && tail.hash !== head.hash) {
    return {
      reason: tail.hash === null ? (tail.exists ? "log-emptied" : "log-deleted") : "tail-does-not-match-head",
      expectedHead: head.hash,
      foundTail: tail.hash,
    };
  }
  if (head.hash === null && tail.hash !== null) {
    return { reason: head.exists ? "head-anchor-cleared" : "head-anchor-deleted", expectedHead: null, foundTail: tail.hash };
  }
  return null;
}

export class LockedAuditLog {
  /**
   * @param {{ AuditLogger: new (opts: { filePath: string }) => any }} fw
   * @param {string} filePath
   */
  constructor(fw, filePath) {
    this.fw = fw;
    this.filePath = filePath;
    this.pending = new Set();
    this.queue = Promise.resolve();
    /** Gaps found (and recorded) by this process. */
    this.gaps = [];
  }

  /** Same signature as AuditLogger.append, so it can serve as the runtime's audit. */
  append(record, { waitMs } = {}) {
    const run = this.queue.then(() => this.appendLocked(record, waitMs));
    this.queue = run.catch(() => undefined);
    this.pending.add(run);
    run.then(
      () => this.pending.delete(run),
      () => this.pending.delete(run),
    );
    return run;
  }

  async appendLocked(record, waitMs) {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    const lockPath = `${this.filePath}.lock`;
    await acquireLock(lockPath, waitMs);
    try {
      const gap = await continuityGap(this.filePath);
      // Create the log (and its head anchor) private before the logger opens them.
      for (const f of [this.filePath, `${this.filePath}.head`]) {
        await (await fs.open(f, "a", 0o600)).close();
      }
      const logger = new this.fw.AuditLogger({ filePath: this.filePath });
      try {
        if (gap) {
          this.gaps.push(gap);
          await logger.append({ type: GAP_TYPE, actor: "enclawed-code", level: null, payload: { ...gap, detectedBy: process.pid } });
        }
        return await logger.append(record);
      } finally {
        await logger.close();
      }
    } finally {
      await fs.rm(lockPath, { force: true });
    }
  }

  /** Wait for every append started so far, including fire-and-forget ones. */
  async flush() {
    while (this.pending.size > 0) {
      await Promise.allSettled([...this.pending]);
    }
  }

  async close() {
    await this.flush();
  }
}

/**
 * Register a framework runtime whose audit log is this app's log, so the
 * framework functions that audit through the runtime (hardware halts,
 * restores) write to it.
 */
export function installRuntime(fw, { audit, policy, flavor }) {
  fw.setRuntime(
    Object.freeze({
      flavor,
      policy,
      audit,
      restoreFetch: () => {},
      fipsRequired: false,
      moduleDecisions: null,
    }),
  );
}

/**
 * Verify the log: the framework's chain and anchor check, plus Enclawed Code's
 * own rules: a head anchor or sealed segment with no log is a failure (I6),
 * and so is any recorded gap (I5).
 *
 * @returns {Promise<object>} the framework's result, with `ok` possibly turned false
 */
export async function verifyAuditLog(fw, file) {
  const exists = fsSync.existsSync(file);
  if (!exists) {
    const head = await readHeadAnchor(file);
    const segs = segmentFiles(file);
    if (head.hash !== null || segs.length > 0) {
      return {
        ok: false,
        file,
        count: 0,
        brokenAt: null,
        reason: `the log is missing but ${head.hash !== null ? "its head anchor" : "sealed segments"} prove records existed`,
        gaps: [],
      };
    }
    return { ok: true, empty: true, file, count: 0, gaps: [] };
  }
  const r = await fw.verifyHistory(file);
  if (!r.ok) {
    return { ...r, gaps: [] };
  }
  const gaps = [];
  for (const f of [...segmentFiles(file).map((s) => s.file), file]) {
    const text = fsSync.readFileSync(f, "utf8");
    for (const line of text.split("\n")) {
      if (line.includes(GAP_TYPE)) {
        try {
          const rec = JSON.parse(line);
          if (rec.type === GAP_TYPE) {
            gaps.push({ ts: rec.ts, ...rec.payload });
          }
        } catch {
          /* chain verification already parsed every line */
        }
      }
    }
  }
  if (gaps.length > 0) {
    return {
      ...r,
      ok: false,
      gaps,
      reason: `${gaps.length} gap record(s): records were removed, or the log or its head anchor was replaced, outside Enclawed Code`,
    };
  }
  return { ...r, gaps };
}
