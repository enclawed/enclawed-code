// Containing claude's processes for a halt (red-team round 3, N12; N7b).
//
// On a halt, EVERY process the session started must be dead before Claude
// Code's login is erased, or one of them can write the login back (N7b: a
// double-forked `setsid` helper restored it 8 s after the erase). A process
// that double-forks with `setsid` is re-parented away from claude's tree, so
// the tree as seen at the halt is not enough. The nets, used together:
//
//   1. claude is its own child subreaper. On Linux claude is started through
//      a one-line wrapper (python3 or perl) that sets PR_SET_CHILD_SUBREAPER
//      on itself and then execs claude, so the attribute stays on claude's
//      pid. Every orphan in claude's subtree (a double fork, a `setsid`
//      daemon, a cleared environment) is re-parented to claude, not to init,
//      so it stays a descendant of claude for as long as claude lives. On a
//      halt claude is stopped first (SIGSTOP: alive, so still the reaper, but
//      it cannot start anything), then its whole subtree is frozen and killed
//      until nothing is left, and only then claude itself.
//   2. A transient systemd scope. When `systemd-run --user --scope` works,
//      claude runs in its own scope (Enclawed Code-<marker>.scope); the kernel's
//      member list of that cgroup (cgroup.procs) is read and every member is
//      killed, and `systemctl --user kill` is sent as well. Cgroup membership
//      is inherited and cannot be left without privilege.
//   3. A session marker, in the environment and the cgroup. claude's
//      environment carries ECWCODE_SESSION_MARK=<random>; a halt also
//      kills every process of this user whose environment carries it, or
//      whose cgroup is this session's scope.
//   4. The launcher's own children. A direct child of claude can create a
//      sibling of claude (clone with CLONE_PARENT), whose parent is then the
//      launcher; with a cleared environment and no scope it carries no
//      marker. The launcher, run as its own process, kills every child of
//      its own that started after claude and is not claude.
//
// Then it VERIFIES: nothing is left in claude's subtree, in the scope, with
// the marker, or among the launcher's late children (zombies excepted: they
// cannot run). The launcher erases the login only after this, and says so
// when the verification failed (survivors are listed and recorded).
//
// macOS has neither a child subreaper nor cgroups (and no unprivileged
// kernel container a process cannot leave: an audit session needs root, a
// resource coalition needs launchd). There the nets are (sessionContainment
// `tracked`):
//
//   5. Descendant tracking. While claude runs, the launcher reads the process
//      table (ps, pid/ppid/pgid/start time) every TRACK_INTERVAL_MS and keeps
//      every process it ever saw below claude, identified by pid AND start
//      time, so one re-parented to launchd by a double fork stays a member
//      and a recycled pid never is.
//   6. Session-led process groups. Every process group whose leader was a
//      member (a `setsid`/`setpgid` by a session process) is the session's:
//      a child of a `setsid` helper inherits its group even when it was never
//      seen in claude's tree. Groups not led by a member (the terminal's job
//      group, which can hold the user's own `| tee`) are never taken.
//   7. The marker (3), read with `ps -E` (the initial environment, as on
//      Linux), and on a halt: claude frozen first, every member, every
//      process of a session-led group and every marker carrier frozen and
//      killed, re-read and swept until none is left, then verified.
//
// What macOS tracking cannot see: a process that, between two reads of the
// table, both leaves claude's tree (double fork: its parent exits before the
// next read) and leaves every session-led group (its own setsid) and clears
// its environment. The launcher says so in the audit record (containment
// "tracked"); docs/usage.md lists what must be verified on a real Mac.
//
// What stays outside (docs/usage.md): work handed to a service that is not
// part of the session before the halt: `at`/`batch`, cron or a systemd user
// timer, a new `systemd-run --user` unit, an already running tmux/screen
// server, a container daemon, or an ssh to another host. None of these is on
// the read-only allowlist, so a person approved the command that started
// it. Without the subreaper wrapper (no python3 or perl, or not Linux) and
// without a scope, a process that clears its environment after leaving the
// tree is not found; the launcher says so at the start of such a session.

import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { trustedBinary } from "./trusted-bin.mjs";

export const MARK_VAR = "ECWCODE_SESSION_MARK";

// PR_SET_CHILD_SUBREAPER (36) on the wrapper's own process, then exec: the
// attribute survives execve, so claude (same pid) is the subreaper. Exit 125
// without starting claude when the kernel refuses.
//
// Both interpreters are run from a fixed system directory (trusted-bin.mjs),
// never from the user's PATH. python3 runs isolated (-I -S: no PYTHON*
// variables, no user site). perl has no such switch, so its own variables
// (PERL5OPT, PERL5LIB, ...: a planted syscall.ph could make the prctl a no-op)
// are moved out of its environment and put back, unchanged, for claude.
// python3 itself sets LC_CTYPE=C.UTF-8 in its environment when the locale is
// C or POSIX (PEP 538 locale coercion; -I does not stop it), which claude
// would inherit: LC_CTYPE is moved aside too (or named as unset) and put back
// exactly, so claude starts with the environment the launcher recorded
// (shell-env.mjs).
const PY_SUBREAPER =
  "import ctypes,os,sys\n" +
  "l=ctypes.CDLL(None,use_errno=True)\n" +
  "if l.prctl(36,1,0,0,0)!=0:\n sys.stderr.write('ecwcode: cannot make claude a child subreaper\\n'); sys.exit(125)\n" +
  "e=os.environ\n" +
  "for k in [k for k in e if k.startswith('ECWCODE_WRAP_RESTORE_')]: e[k[len('ECWCODE_WRAP_RESTORE_'):]]=e.pop(k)\n" +
  "for k in e.pop('ECWCODE_WRAP_UNSET','').split(','):\n if k: e.pop(k,None)\n" +
  "os.execvp(sys.argv[1],sys.argv[1:])";
const RESTORE_PREFIX = "ECWCODE_WRAP_RESTORE_";
const UNSET_VAR = "ECWCODE_WRAP_UNSET";
// What python3 may change in its own environment before the exec.
const PYTHON_SETS = Object.freeze(["LC_CTYPE"]);

/** The environment for the python3 wrapper: what python3 changes in it is moved aside, to be restored for claude. */
export function pythonWrapperEnv(env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    if (!k.startsWith(RESTORE_PREFIX) && k !== UNSET_VAR) {
      out[k] = v;
    }
  }
  const unset = [];
  for (const k of PYTHON_SETS) {
    if (typeof env[k] === "string") {
      out[`${RESTORE_PREFIX}${k}`] = env[k];
    } else {
      unset.push(k);
    }
  }
  if (unset.length) {
    out[UNSET_VAR] = unset.join(",");
  }
  return out;
}
const PL_SUBREAPER =
  'require "syscall.ph"; if (syscall(&SYS_prctl, 36, 1, 0, 0, 0) != 0) { print STDERR "ecwcode: cannot make claude a child subreaper\n"; exit 125 } ' +
  `for my $k (keys %ENV) { if ($k =~ /^${RESTORE_PREFIX}(\\w+)$/) { $ENV{$1} = delete $ENV{$k} } } ` +
  "exec { $ARGV[0] } @ARGV or exit 127";
const PERL_ENV = /^(PERL5OPT|PERL5LIB|PERLLIB|PERL5DB|PERL5DB_THREADED|PERL_.*)$/;

/** The environment for the perl wrapper: its own variables moved aside, to be restored for claude. */
export function perlWrapperEnv(env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    if (k.startsWith(RESTORE_PREFIX)) {
      continue;
    }
    if (PERL_ENV.test(k)) {
      out[`${RESTORE_PREFIX}${k}`] = v;
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * The subreaper wrapper this machine can run, as { argv, env } (env: a
 * function from claude's environment to the wrapper's), or null. Probed once
 * per launch by running it around `true`.
 * @returns {{ argv: string[], env: (e: object) => object } | null}
 */
export function subreaperWrapper(env = process.env, { run = spawnSync, binary = trustedBinary, platform = process.platform } = {}) {
  if (platform !== "linux") {
    return null;
  }
  const py = binary("python3");
  const pl = binary("perl");
  const candidates = [
    ...(py ? [{ argv: [py, "-I", "-S", "-c", PY_SUBREAPER], env: pythonWrapperEnv }] : []),
    ...(pl ? [{ argv: [pl, "-e", PL_SUBREAPER], env: perlWrapperEnv }] : []),
  ];
  const trueBin = binary("true") ?? "/bin/true";
  for (const w of candidates) {
    const r = run(w.argv[0], [...w.argv.slice(1), trueBin], { env: w.env(env), stdio: "ignore", timeout: 5000 });
    if (r.status === 0) {
      return w;
    }
  }
  return null;
}

/** Can this environment start a transient user scope? (systemd-run from a system directory only.) */
export function scopeAvailable(env = process.env, { run = spawnSync, binary = trustedBinary, platform = process.platform } = {}) {
  if (platform !== "linux") {
    return false;
  }
  const systemdRun = binary("systemd-run");
  if (!systemdRun || !binary("systemctl")) {
    return false;
  }
  const r = run(systemdRun, ["--user", "--scope", "--quiet", "--collect", "--", binary("true") ?? "/bin/true"], { env, stdio: "ignore", timeout: 5000 });
  return r.status === 0;
}

/** How often the macOS tracker reads the process table (ms). */
export const TRACK_INTERVAL_MS = 100;

const C_ENV = { LC_ALL: "C", TZ: "UTC", PATH: "/usr/bin:/bin" };
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** `ps -o lstart` in the C locale and UTC ("Sat Nov 22 16:04:05 2026") as seconds since the epoch, or null. */
export function parseLstart(text) {
  const m = /^\s*\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s*$/.exec(text);
  if (!m || MONTHS[m[1]] === undefined) {
    return null;
  }
  return Date.UTC(Number(m[6]), MONTHS[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])) / 1000;
}

/** Parse `ps -axo pid=,ppid=,pgid=,stat=,lstart=` output. */
export function parsePsTable(stdout) {
  const out = [];
  for (const line of String(stdout).split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$/.exec(line);
    if (!m) {
      continue;
    }
    const start = parseLstart(m[5]);
    if (start === null) {
      continue;
    }
    out.push({ pid: Number(m[1]), ppid: Number(m[2]), pgid: Number(m[3]), state: m[4][0], start });
  }
  return out;
}

/** macOS (and any BSD ps): every process with its parent, group, state and start time (seconds). */
export function psTable({ run = spawnSync, binary = trustedBinary } = {}) {
  const ps = binary("ps");
  if (!ps) {
    return [];
  }
  const r = run(ps, ["-axo", "pid=,ppid=,pgid=,stat=,lstart="], { encoding: "utf8", env: C_ENV, timeout: 5000, maxBuffer: 32 * 1024 * 1024 });
  return r.status === 0 ? parsePsTable(r.stdout) : [];
}

/** Parse `ps -E -ww -axo pid=,command=` output: pids whose environment carries the marker. */
export function parsePsMarked(stdout, marker, exclude = new Set()) {
  const want = `${MARK_VAR}=${marker}`;
  const out = [];
  for (const line of String(stdout).split("\n")) {
    const m = /^\s*(\d+)\s(.*)$/.exec(line);
    if (m && !exclude.has(Number(m[1])) && m[2].split(/\s+/).includes(want)) {
      out.push(Number(m[1]));
    }
  }
  return out;
}

/** macOS: pids of this user whose initial environment carries the marker (`ps -E` shows it for one's own processes). */
export function psMarkedPids(marker, { exclude = new Set([process.pid]), run = spawnSync, binary = trustedBinary } = {}) {
  const ps = binary("ps");
  if (!ps) {
    return [];
  }
  const r = run(ps, ["-E", "-ww", "-axo", "pid=,command="], { encoding: "utf8", env: C_ENV, timeout: 5000, maxBuffer: 64 * 1024 * 1024 });
  return r.status === 0 ? parsePsMarked(r.stdout, marker, exclude) : [];
}

/**
 * The macOS descendant tracker (nets 5 and 6 in the header). `table` reads
 * the process table; `start(rootPid)` begins polling, `sweep()` reads once.
 * Members are kept by pid and start time; session-led groups by their
 * leader's pid and start time.
 */
export function processTracker({ table = psTable, intervalMs = TRACK_INTERVAL_MS, self = process.pid } = {}) {
  const members = new Map(); // pid -> start
  const groups = new Map(); // pgid (a member's pid) -> the leader's start
  let root = null;
  let timer = null;
  const isMember = (p) => members.has(p.pid) && members.get(p.pid) === p.start;
  const sweep = (t = table()) => {
    if (root === null) {
      return t;
    }
    const byPid = new Map(t.map((p) => [p.pid, p]));
    const rootProc = byPid.get(root.pid);
    if (rootProc && rootProc.start === root.start) {
      members.set(rootProc.pid, rootProc.start);
    }
    // Members' children, transitively (several passes: the table is unordered).
    let grew = true;
    while (grew) {
      grew = false;
      for (const p of t) {
        if (p.pid === self || isMember(p)) {
          continue;
        }
        const parent = byPid.get(p.ppid);
        if ((parent && isMember(parent)) || groups.has(p.pgid)) {
          members.set(p.pid, p.start);
          grew = true;
        }
      }
    }
    // Groups a member leads (it called setsid or setpgid): the session's.
    for (const p of t) {
      if (isMember(p) && p.pgid === p.pid && p.pid !== root.pid) {
        groups.set(p.pgid, p.start);
      }
    }
    // A group with no process left is over; its number may be reused by
    // an unrelated group later, which must never be taken for the session's.
    const live = new Set(t.map((p) => p.pgid));
    for (const g of [...groups.keys()]) {
      if (!live.has(g)) {
        groups.delete(g);
      }
    }
    return t;
  };
  return {
    get members() {
      return members;
    },
    get groups() {
      return groups;
    },
    sweep,
    /** The session's processes in table `t` (alive or not), claude's own pid excluded. */
    sessionProcs(t) {
      return t.filter((p) => !(root && p.pid === root.pid) && p.pid !== self && (isMember(p) || groups.has(p.pgid)));
    },
    start(pid, startTime = null) {
      const t = table();
      const st = startTime ?? t.find((p) => p.pid === pid)?.start ?? null;
      root = { pid, start: st };
      sweep(t);
      timer = setInterval(() => {
        try {
          sweep();
        } catch {
          /* the next read */
        }
      }, intervalMs);
      timer.unref?.();
    },
    stop() {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    },
  };
}

/**
 * The containment for one launch.
 * @returns {{ marker: string, unit: string|null, reaper: boolean, tracked: boolean, tracker: object|null, env: object, wrapEnv: (e: object) => object, command: (cmd: string, args: string[]) => [string, string[]] }}
 */
export function sessionContainment(env = process.env, { scope = scopeAvailable(env), reaper = subreaperWrapper(env), binary = trustedBinary, platform = process.platform, tracker = undefined } = {}) {
  const marker = randomBytes(12).toString("hex");
  const unit = scope ? `enclawed-code-${marker}.scope` : null;
  const systemdRun = unit ? binary("systemd-run") : null;
  const wrap = (cmd, args) => (reaper ? [reaper.argv[0], [...reaper.argv.slice(1), cmd, ...args]] : [cmd, args]);
  // macOS: descendant tracking with session-led groups (header, nets 5-7).
  const track = tracker !== undefined ? tracker : platform === "darwin" ? processTracker() : null;
  return {
    marker,
    unit: systemdRun ? unit : null,
    reaper: reaper !== null,
    tracked: track !== null,
    tracker: track,
    platform,
    startedAfter: null,
    env: { [MARK_VAR]: marker },
    wrapEnv: reaper ? reaper.env : (e) => e,
    command: (cmd, args) => {
      const [c, a] = wrap(cmd, args);
      return systemdRun ? [systemdRun, ["--user", "--scope", "--quiet", "--collect", `--unit=${unit}`, "--", c, ...a]] : [c, a];
    },
  };
}

/** A process's start time (clock ticks since boot), or null. */
export function procStartTime(pid, { procDir = "/proc" } = {}) {
  try {
    const stat = fs.readFileSync(`${procDir}/${pid}/stat`, "latin1");
    return Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19]);
  } catch {
    return null;
  }
}

/** Linux /proc: every process with its parent, state and start time (clock ticks). */
export function procTable({ procDir = "/proc" } = {}) {
  const out = [];
  let names = [];
  try {
    names = fs.readdirSync(procDir);
  } catch {
    return out;
  }
  for (const n of names) {
    if (!/^\d+$/.test(n)) {
      continue;
    }
    try {
      const stat = fs.readFileSync(`${procDir}/${n}/stat`, "latin1");
      // pid (comm) state ppid pgrp ... starttime is field 22; comm may hold spaces and parens.
      const rest = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      out.push({ pid: Number(n), state: rest[0], ppid: Number(rest[1]), pgid: Number(rest[2]), start: Number(rest[19]) });
    } catch {
      /* gone */
    }
  }
  return out;
}

function descendantsOf(root, table) {
  const kids = new Map();
  for (const p of table) {
    if (!kids.has(p.ppid)) {
      kids.set(p.ppid, []);
    }
    kids.get(p.ppid).push(p);
  }
  const out = [];
  const stack = [...(kids.get(root) ?? [])];
  const seen = new Set([root]);
  while (stack.length > 0) {
    const p = stack.pop();
    if (seen.has(p.pid)) {
      continue;
    }
    seen.add(p.pid);
    out.push(p);
    stack.push(...(kids.get(p.pid) ?? []));
  }
  return out;
}

/** The pids in this session's scope, from the kernel's cgroup member list (empty without a scope). */
export function scopePids(c, { claudePid = null, procDir = "/proc", cgroupRoot = "/sys/fs/cgroup" } = {}) {
  if (!c?.unit) {
    return [];
  }
  const want = `/${c.unit}`;
  let rel = c.cgroup ?? null;
  if (!rel && claudePid) {
    try {
      const line = fs.readFileSync(`${procDir}/${claudePid}/cgroup`, "latin1").split("\n").find((l) => l.startsWith("0::"));
      if (line && line.slice(3).endsWith(want)) {
        rel = line.slice(3);
        c.cgroup = rel;
      }
    } catch {
      /* gone */
    }
  }
  if (!rel) {
    return [];
  }
  try {
    return fs.readFileSync(`${cgroupRoot}${rel}/cgroup.procs`, "latin1").split("\n").filter(Boolean).map(Number);
  } catch {
    return [];
  }
}

/** Pids whose initial environment carries this session's marker, or whose cgroup is this session's scope (`unit`). */
export function markedPids(marker, { exclude = new Set([process.pid]), procDir = "/proc", unit = null } = {}) {
  const want = `${MARK_VAR}=${marker}`;
  const out = [];
  let names = [];
  try {
    names = fs.readdirSync(procDir);
  } catch {
    return out;
  }
  for (const n of names) {
    if (!/^\d+$/.test(n) || exclude.has(Number(n))) {
      continue;
    }
    if (unit) {
      try {
        if (fs.readFileSync(`${procDir}/${n}/cgroup`, "latin1").includes(`/${unit}\n`)) {
          out.push(Number(n));
          continue;
        }
      } catch {
        /* gone */
      }
    }
    let raw;
    try {
      raw = fs.readFileSync(`${procDir}/${n}/environ`, "latin1");
    } catch {
      continue; // gone, or another user's
    }
    if (raw.includes(want) && raw.split("\0").includes(want)) {
      out.push(Number(n));
    }
  }
  return out;
}

/**
 * Signal everything in the containment: the scope's cgroup and every
 * process carrying the marker.
 * @returns {{ scope: boolean, marked: number[] }}
 */
export function signalContainment(c, sig, { env = process.env, run = spawnSync, kill = process.kill.bind(process) } = {}) {
  if (!c) {
    return { scope: false, marked: [] };
  }
  let scope = false;
  if (c.unit) {
    const systemctl = trustedBinary("systemctl");
    const r = systemctl ? run(systemctl, ["--user", "kill", `--signal=${sig}`, c.unit], { env, stdio: "ignore", timeout: 5000 }) : { status: 1 };
    scope = r.status === 0;
  }
  const marked = markedPids(c.marker, { unit: c.unit });
  for (const pid of marked) {
    try {
      kill(pid, sig);
    } catch {
      /* gone */
    }
  }
  return { scope, marked };
}

const pause = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Kill every process of the session, claude last, and verify that none is
 * left (N7b). `claudePid` is claude's pid (the subreaper when the wrapper ran).
 * `launcherChildren`: also kill this process's own children that started
 * after claude (a CLONE_PARENT sibling of claude); only for the launcher run
 * as its own process. Zombies are not survivors: they cannot run.
 * @returns {Promise<{ verified: boolean, survivors: number[], killed: number }>}
 */
export async function killSession(
  claudePid,
  c,
  { launcherChildren = false, graceMs = 0, rounds = 60, intervalMs = 50, table = c?.tracker ? psTable : procTable, marked = c?.tracker ? (m, o) => psMarkedPids(m, o) : markedPids, kill = process.kill.bind(process), env = process.env, run = spawnSync, afterKillWaitMs = 2000 } = {},
) {
  const self = process.pid;
  const tracker = c?.tracker ?? null;
  const alive = (p) => p.state !== "Z" && p.state !== "X";
  const claudeStart = () => table().find((p) => p.pid === claudePid)?.start ?? null;
  if (claudePid && c && c.startedAfter === null) {
    c.startedAfter = claudeStart();
  }
  const sig = (pid, s) => {
    try {
      kill(pid, s);
      return true;
    } catch {
      return false;
    }
  };
  /** Everything of the session except claude and this process. */
  const sessionSet = () => {
    const t = table();
    const set = new Map();
    if (tracker) {
      // macOS: everything ever seen below claude, and session-led groups (nets 5-6).
      tracker.sweep(t);
      for (const p of tracker.sessionProcs(t)) {
        set.set(p.pid, p);
      }
    }
    if (claudePid) {
      for (const p of descendantsOf(claudePid, t)) {
        set.set(p.pid, p);
      }
    }
    const byPid = new Map(t.map((p) => [p.pid, p]));
    if (c) {
      for (const pid of [...marked(c.marker, { exclude: new Set([self]), unit: c.unit }), ...scopePids(c, { claudePid })]) {
        if (byPid.has(pid)) {
          set.set(pid, byPid.get(pid));
        }
      }
    }
    if (launcherChildren && c?.startedAfter !== null && c?.startedAfter !== undefined) {
      for (const p of t) {
        if (p.ppid === self && p.pid !== claudePid && p.start >= c.startedAfter) {
          set.set(p.pid, p);
          for (const d of descendantsOf(p.pid, t)) {
            set.set(d.pid, d);
          }
        }
      }
    }
    set.delete(self);
    set.delete(claudePid);
    return [...set.values()].filter(alive);
  };
  // claude stays alive (so, as the subreaper, it keeps adopting orphans) but cannot start anything new.
  if (claudePid) {
    sig(claudePid, "SIGSTOP");
  }
  let killed = 0;
  const sweepOnce = () => {
    const left = sessionSet();
    // macOS: whole session-led groups at once (a member forked after the
    // table was read is in its parent's group), only while the group still
    // holds a process of the session (sessionSet just pruned ended groups).
    const liveGroups = tracker ? [...tracker.groups.keys()].filter((g) => g !== self && g !== claudePid && left.some((p) => p.pgid === g)) : [];
    for (const g of liveGroups) {
      sig(-g, "SIGSTOP");
    }
    for (const p of left) {
      sig(p.pid, "SIGSTOP"); // freeze first: a frozen process cannot fork while the rest is killed
    }
    for (const g of liveGroups) {
      sig(-g, "SIGKILL");
    }
    for (const p of left) {
      if (sig(p.pid, "SIGKILL")) {
        killed++;
      }
    }
    if (left.length > 0 && c?.unit) {
      // Scope members are killed by pid above; the unit-wide kill is the second net.
      const systemctl = trustedBinary("systemctl");
      if (systemctl) {
        run(systemctl, ["--user", "kill", "--signal=SIGKILL", c.unit], { env, stdio: "ignore", timeout: 5000 });
      }
    }
    return left.length;
  };
  for (let i = 0; i < rounds; i++) {
    if (sweepOnce() === 0) {
      break;
    }
    await pause(intervalMs);
  }
  const claudeAlive = () => (claudePid ? table().some((p) => p.pid === claudePid && alive(p)) : false);
  if (claudePid && graceMs > 0) {
    // Everything it started is gone: claude may now end cleanly (an
    // interactive Claude Code restores the terminal on SIGTERM). It is still
    // the subreaper while it lives, so whatever it starts meanwhile stays in
    // its subtree and is swept.
    sig(claudePid, "SIGTERM");
    sig(claudePid, "SIGCONT");
    const end = Date.now() + graceMs;
    while (Date.now() < end && claudeAlive()) {
      sweepOnce();
      await pause(intervalMs);
    }
    sweepOnce();
  }
  if (claudePid) {
    sig(claudePid, "SIGKILL");
    sig(claudePid, "SIGCONT");
  }
  // Verify: wait for claude to be gone, then nothing of the session may be left.
  const deadline = Date.now() + afterKillWaitMs;
  let survivors = [];
  for (;;) {
    survivors = sessionSet().map((p) => p.pid);
    if (claudeAlive()) {
      survivors.push(claudePid);
    }
    if (survivors.length === 0 || Date.now() > deadline) {
      break;
    }
    for (const pid of survivors) {
      sig(pid, "SIGKILL");
    }
    await pause(intervalMs);
  }
  return { verified: survivors.length === 0, survivors, killed };
}
