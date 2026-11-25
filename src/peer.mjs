// Who is on the other end of a unix socket, and the process tree.
//
// Node has no SO_PEERCRED. On Linux the same kernel answer is available
// through sock_diag, which `ss` (iproute2) prints: for each unix socket its
// own inode and its peer's inode. A socket's inode is
// readlink(/proc/self/fd/N) = "socket:[INODE]", and the process holding the
// peer end is the one with an fd that links to the peer's inode. So
//   our fd -> our inode -> (ss) peer inode -> (/proc/<pid>/fd) peer pid,
// then /proc/<pid>/exe and /proc/<pid>/cmdline say what that process is.
//
// Elsewhere (macOS, Windows, or Linux without `ss`) `peerOf` reports
// { available: false }; callers decide what that means and say so.

import { spawnSync } from "node:child_process";
import { trustedBinary } from "./trusted-bin.mjs";
import fs from "node:fs";
import path from "node:path";


function ssProgram() {
  if (process.platform !== "linux") {
    return null;
  }
  return trustedBinary("ss");
}

export function peerCheckAvailable() {
  return ssProgram() !== null && fs.existsSync("/proc/self/fd");
}

/** The inode of a connected net.Socket, or null. */
export function socketInode(sock) {
  const fd = sock?._handle?.fd;
  if (typeof fd !== "number" || fd < 0) {
    return null;
  }
  try {
    const m = /^socket:\[(\d+)\]$/.exec(fs.readlinkSync(`/proc/self/fd/${fd}`));
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/** The peer inode of the unix socket with local inode `ino` (from `ss -xnH`). */
export function peerInode(ino, { socketPath = null } = {}) {
  const ss = ssProgram();
  if (!ss) {
    return null;
  }
  const args = socketPath ? ["-xnH", "src", socketPath] : ["-xnH"];
  const r = spawnSync(ss, args, { encoding: "utf8", timeout: 3000, maxBuffer: 32 * 1024 * 1024 });
  if (r.status !== 0 || typeof r.stdout !== "string") {
    return null;
  }
  for (const line of r.stdout.split("\n")) {
    // ... <local addr> <local inode> <peer addr> <peer inode>; the local
    // address may contain spaces, so read from the end.
    const t = line.trim().split(/\s+/);
    if (t.length >= 4 && t[t.length - 3] === ino) {
      return t[t.length - 1];
    }
  }
  return null;
}

/** Does `pid` hold an fd linked to socket inode `ino`? */
export function holdsSocket(pid, ino) {
  let fds;
  try {
    fds = fs.readdirSync(`/proc/${pid}/fd`);
  } catch {
    return false;
  }
  const want = `socket:[${ino}]`;
  return fds.some((fd) => {
    try {
      return fs.readlinkSync(`/proc/${pid}/fd/${fd}`) === want;
    } catch {
      return false;
    }
  });
}

/** The parent pid of every process (Linux /proc). */
export function parentMap() {
  const map = new Map();
  let names = [];
  try {
    names = fs.readdirSync("/proc");
  } catch {
    return map;
  }
  for (const n of names) {
    if (!/^\d+$/.test(n)) {
      continue;
    }
    try {
      const stat = fs.readFileSync(`/proc/${n}/stat`, "utf8");
      // comm may contain spaces and parens: fields after the last ")".
      const rest = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      map.set(Number(n), Number(rest[1]));
    } catch {
      /* gone */
    }
  }
  return map;
}

export function isDescendant(pid, ancestor, parents = parentMap()) {
  let p = pid;
  for (let i = 0; i < 256 && p > 1; i++) {
    p = parents.get(p);
    if (p === ancestor) {
      return true;
    }
    if (p === undefined) {
      return false;
    }
  }
  return false;
}

/** The process holding the other end of `sock`, among `candidates` (pids) or all descendants of `root`. */
export function peerProcess(sock, { socketPath = null, root = null, candidates = null } = {}) {
  if (!peerCheckAvailable()) {
    return { available: false, reason: process.platform === "linux" ? "ss (iproute2) is not installed" : `no peer-credential lookup on ${process.platform}` };
  }
  const mine = socketInode(sock);
  if (!mine) {
    return { available: true, pid: null, reason: "cannot read this end's socket inode" };
  }
  const peer = peerInode(mine, { socketPath });
  if (!peer) {
    return { available: true, pid: null, reason: "the kernel reports no peer for this connection" };
  }
  let pids = candidates;
  const parents = parentMap();
  if (!pids) {
    pids = [...parents.keys()].filter((p) => root === null || isDescendant(p, root, parents));
  }
  const pid = pids.find((p) => holdsSocket(p, peer)) ?? null;
  return { available: true, pid, peerInode: peer, parents, reason: pid === null ? "no expected process holds the other end" : null };
}

export function processExe(pid) {
  try {
    return fs.readlinkSync(`/proc/${pid}/exe`);
  } catch {
    return null;
  }
}

export function processArgv(pid) {
  try {
    const raw = fs.readFileSync(`/proc/${pid}/cmdline`, "utf8");
    return raw.split("\0").slice(0, -1);
  } catch {
    return null;
  }
}

// Environment variables that make node (or the dynamic loader) run other
// code: every NODE_* (NODE_OPTIONS --require/--import/--loader, NODE_PATH,
// NODE_REPL_EXTERNAL_MODULE, ...), the loader's LD_PRELOAD / LD_AUDIT /
// LD_LIBRARY_PATH, and macOS DYLD_*. Enclawed Code's genuine hook command starts
// node with `env -i`, so its environment has none of them.
const ENV_RISK = /^(NODE_[A-Z0-9_]*|LD_PRELOAD|LD_AUDIT|LD_LIBRARY_PATH|DYLD_[A-Z_]*)$/;

/**
 * The first code-loading variable in a process's initial environment
 * (/proc/<pid>/environ), or null. An environment that cannot be read counts
 * as a risk (fail closed).
 * @returns {string|null}
 */
export function processEnvRisk(pid, { read = (p) => fs.readFileSync(`/proc/${p}/environ`) } = {}) {
  let raw;
  try {
    raw = read(pid);
  } catch (err) {
    return `an unreadable environment (${err.code ?? err.message})`;
  }
  for (const entry of raw.toString("latin1").split("\0")) {
    const eq = entry.indexOf("=");
    const name = eq < 0 ? entry : entry.slice(0, eq);
    if (ENV_RISK.test(name)) {
      return name;
    }
  }
  return null;
}

export function realExecPath() {
  try {
    return fs.realpathSync(process.execPath);
  } catch {
    return path.resolve(process.execPath);
  }
}

/**
 * All processes, from `ps` (Linux and macOS): pid, ppid, pgid, command.
 * @returns {Array<{ pid: number, ppid: number, pgid: number, command: string }>}
 */
export function processTable() {
  if (process.platform === "win32") {
    return [];
  }
  const ps = trustedBinary("ps");
  if (!ps) {
    return [];
  }
  const r = spawnSync(ps, ["-axo", "pid=,ppid=,pgid=,command="], { encoding: "utf8", timeout: 5000, maxBuffer: 32 * 1024 * 1024 });
  if (r.status !== 0 || typeof r.stdout !== "string") {
    return [];
  }
  const out = [];
  for (const line of r.stdout.split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/.exec(line);
    if (m) {
      out.push({ pid: Number(m[1]), ppid: Number(m[2]), pgid: Number(m[3]), command: m[4] });
    }
  }
  return out;
}

/** `root` and every process below it, with the process groups they lead or joined. */
export function processTree(root, table = processTable()) {
  const kids = new Map();
  for (const p of table) {
    if (!kids.has(p.ppid)) {
      kids.set(p.ppid, []);
    }
    kids.get(p.ppid).push(p);
  }
  const out = [];
  const seen = new Set();
  const stack = [root];
  while (stack.length > 0) {
    const pid = stack.pop();
    if (seen.has(pid)) {
      continue;
    }
    seen.add(pid);
    const self = table.find((p) => p.pid === pid);
    if (self) {
      out.push(self);
    }
    for (const k of kids.get(pid) ?? []) {
      stack.push(k.pid);
    }
  }
  return out;
}

/** Other Claude Code processes on this machine (not in `exclude`), for the shared-login warning (N7). */
export function otherClaudeProcesses(exclude = new Set(), table = processTable()) {
  return table.filter((p) => {
    if (exclude.has(p.pid) || p.pid === process.pid) {
      return false;
    }
    const argv0 = p.command.split(/\s+/)[0] ?? "";
    return path.basename(argv0) === "claude" || /@anthropic-ai\/claude-code|\/claude-code\/(cli|bin)|\.local\/share\/claude\/versions\//.test(p.command);
  });
}
