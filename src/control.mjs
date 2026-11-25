// The launcher's control socket: how the launcher knows that the REAL
// Enclawed Code hook is running for this session (red-team round 2, N2, N1/N4).
//
// Round 1 trusted any session.start line in the audit log that carried the
// launch nonce, and the nonce sits in session.json, which a repository's own
// SessionStart hook could read and replay. Now:
//
//   - The launcher listens on a unix socket in the private session
//     directory. It keeps a per-launch key in memory only; nothing the
//     session's processes can read holds it.
//   - Every connection is checked with the kernel's peer credentials (Linux,
//     peer.mjs): the connecting process must be a descendant of the claude
//     process the launcher spawned, run this Node binary, and have exactly the
//     hook command line the launcher generated (node, ecwcode-hook,
//     --origin launcher, --session <this session file>, --digest <digest>).
//     The hook, in turn, checks that the socket's other end is the launcher
//     process named in the session file.
//   - SessionStart: the verified hook gets a challenge (an HMAC of a counter
//     under the in-memory key), writes its session.start record carrying that
//     challenge into the hash-chained audit log, and sends back the record's
//     hash. The launcher reads the record, recomputes its hash, checks it
//     links to the records before it (back to this launch's own record when
//     it is in the same file), and only then counts the handshake as done. A
//     raw line with the nonce counts for nothing.
//   - PreToolUse: the verified hook reports the tool_use_id it is deciding,
//     with the tool name and a per-key digest of the input it decided on
//     (call-binding.mjs), and is held until the handshake is done (or
//     refused after `holdMs`). The decision counts only for a tool_use the
//     launcher has already seen in the transcript (it waits up to `holdMs`
//     for the line) with the same name and input (round 3, N9: a genuine
//     hook fed a fabricated input no longer marks a different call decided).
//     An id the transcript never shows is refused; a name or input mismatch
//     is refused and stops claude (`onMismatch`). The launcher also stops
//     claude when a call ran without a decision (transcript-watch.mjs).
//   - After deciding, the verified hook reports the decision itself (allow,
//     ask or deny; round 4, N13), and after the call its PostToolUse. A
//     call whose transcript result is a success although the decision was
//     deny, or ask with no sign that a person answered it, stops claude
//     (launcher.mjs, claude-code.launch.decision-violated).
//   - The hardware relay's secret is no longer written to session.json; the
//     verified hook receives it here.

import { createHash, createHmac, randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import { bindingMatches, contextMatches } from "./call-binding.mjs";
import { peerProcess, processArgv, processEnvRisk, processExe, realExecPath } from "./peer.mjs";

/** A value's canonical JSON (sorted keys), so one input is one key whatever its key order. */
function canonical(v) {
  if (Array.isArray(v)) {
    return v.map(canonical);
  }
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
  }
  return v;
}

const MAX_LINE = 64 * 1024;
const PROTO_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function canonicalize(v) {
  if (v === null || typeof v !== "object") {
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    return `[${v.map(canonicalize).join(",")}]`;
  }
  return `{${Object.keys(v)
    .filter((k) => !PROTO_KEYS.has(k))
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`)
    .join(",")}}`;
}

/** The framework's record hash (AuditLogger.buildRecord). */
export function recordHashOf(rec) {
  const body = { ts: rec.ts, type: rec.type, actor: rec.actor, level: rec.level, payload: rec.payload };
  return createHash("sha256").update(rec.prevHash ?? "").update("|").update(canonicalize(body)).digest("hex");
}

/**
 * Find the record with `hash` in the audit log and check it is a genuine
 * link of the chain: its own hash recomputes, it links to the record before
 * it, and every record from `fromHash` (when present in the file) to it links.
 * @returns {{ ok: true, record: object } | { ok: false, reason: string }}
 */
export function verifyChainedRecord(auditFile, hash, { fromHash = null } = {}) {
  let text;
  try {
    text = fs.readFileSync(auditFile, "utf8");
  } catch (err) {
    return { ok: false, reason: `cannot read the audit log (${err.code ?? err.message})` };
  }
  const lines = text.split("\n").filter(Boolean);
  const recs = [];
  let at = -1;
  for (const [i, l] of lines.entries()) {
    let r;
    try {
      r = JSON.parse(l);
    } catch {
      r = null;
    }
    recs.push(r);
    if (r?.recordHash === hash) {
      at = i;
    }
  }
  if (at < 0) {
    return { ok: false, reason: "the record is not in the audit log" };
  }
  let start = at;
  if (fromHash) {
    const f = recs.findIndex((r) => r?.recordHash === fromHash);
    if (f >= 0 && f < at) {
      start = f;
    }
  }
  for (let i = start; i <= at; i++) {
    const r = recs[i];
    if (!r || recordHashOf(r) !== r.recordHash) {
      return { ok: false, reason: `audit record ${i + 1} does not hash to its recordHash` };
    }
    if (i > 0 && recs[i - 1]?.recordHash !== r.prevHash) {
      return { ok: false, reason: `audit record ${i + 1} does not link to the record before it` };
    }
  }
  return { ok: true, record: recs[at] };
}

function lineReader(sock, onLine) {
  let buf = "";
  sock.on("data", (d) => {
    buf += d;
    for (;;) {
      const nl = buf.indexOf("\n");
      if (nl < 0) {
        if (buf.length > MAX_LINE) {
          sock.destroy();
        }
        return;
      }
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        sock.destroy();
        return;
      }
      onLine(msg);
    }
  });
}

/**
 * Launcher side.
 * @param {{
 *   socketPath: string,
 *   expectedArgv: () => string[],
 *   claudePid: () => number|null,
 *   nonce: string,
 *   auditFile: string,
 *   launchHash?: () => string|null,
 *   relaySecret?: string|null,
 *   holdMs?: number,
 *   peer?: (sock: net.Socket) => object,
 *   pollTranscripts?: () => void,
 *   onAnchorRequest?: () => void,
 *   onMismatch?: (m: { id: string, code: string, reason: string }) => void,
 *   onModeDowngrade?: (d: { id: string, launched: string, reported: string }) => void,
 *   onDecision?: (d: { id: string, decision: "allow"|"ask"|"deny" }) => void,
 *   cwd?: string|null,
 *   home?: string|null,
 * }} o
 */
export function startControl(o) {
  const key = randomBytes(32);
  let counter = 0;
  const issued = new Set();
  const decided = new Set();
  // What the verified hook decided for each call that passed `pre` (round 4,
  // N13): "pending" until its `decision` message, then allow, ask or deny.
  const decisions = new Map();
  // Calls whose PostToolUse the verified hook reported (the call ran through
  // Claude Code's permission flow with Enclawed's hooks loaded).
  const posts = new Set();
  // Interactive "ask" calls put to the person at the launcher's own prompt,
  // and those the person approved there (round 5, N13c).
  const prompted = new Set();
  const approved = new Set();
  // Calls the person denied at the prompt (tool and canonical input), for this session.
  const deniedByPerson = new Set();
  // What tool results Claude read held (warning-signals.mjs readSignals): the
  // latest per kind, with the number of the result it came in. Only for the
  // person's warnings; never part of a decision.
  const planted = new Map();
  let postCount = 0;
  const plantedNow = () =>
    [...planted.values()].map((s) => ({ ...s.signal, last: s.at === postCount }));
  const signalsOf = (v) =>
    (Array.isArray(v) ? v : [])
      .filter((x) => x && typeof x === "object" && typeof x.kind === "string")
      .slice(0, 8)
      .map((x) => ({
        kind: String(x.kind).slice(0, 40),
        ...(typeof x.source === "string" ? { source: x.source.slice(0, 200) } : {}),
        ...(Number.isInteger(x.line) ? { line: x.line } : {}),
        ...(Array.isArray(x.ids) ? { ids: x.ids.filter((i) => typeof i === "string").slice(0, 16) } : {}),
        ...(typeof x.path === "string" ? { path: x.path.slice(0, 4096) } : {}),
        ...(typeof x.what === "string" ? { what: x.what.slice(0, 120) } : {}),
        ...(Array.isArray(x.kinds) ? { kinds: x.kinds.filter((i) => typeof i === "string").slice(0, 16) } : {}),
      }));
  // Calls that run as a contained command: tool_use_id -> that command.
  const contained = new Map();
  // tool_use blocks the transcript showed: id -> { name, input }.
  const seen = new Map();
  const seenWaiters = new Map();
  // Interactive: reports for calls the transcript did not show yet (deferBinding).
  const pendingBindings = new Map();
  // A report checked against the transcript's call: null, or the mismatch (recorded).
  const checkBinding = (id, report, call) => {
    const m = bindingMatches({ tool: report.tool, binding: report.binding }, call, { cwd: o.cwd ?? null, home: o.home ?? null });
    let bad = m.ok ? null : { id, code: m.code, reason: m.reason };
    // The context the hook decided in (cwd, permission mode, scratchpad;
    // round 5): a forged input must not change what the decision means.
    if (!bad && o.context) {
      const launch = o.context();
      const c = contextMatches(report.context, call, { ...launch, launchedMode: launch.launchedMode ?? (launch.print ? state.firstMode : null) });
      if (!c.ok) {
        bad = { id, code: c.code, reason: c.reason };
      } else {
        // A headless mode cannot change: the first one reported is the session's.
        state.firstMode ??= report.context?.permissionMode ?? null;
        // Claude Code runs stricter than launched (it fell back by itself):
        // accepted, recorded once per mode it reports.
        if (c.downgraded && !state.downgrades.some((d) => d.reported === c.downgraded.reported)) {
          const d = { id, launched: c.downgraded.launched, reported: c.downgraded.reported };
          state.downgrades.push(d);
          o.onModeDowngrade?.(d);
        }
      }
    }
    if (bad) {
      state.mismatches.push(bad);
    }
    return bad;
  };
  const waiters = new Set();
  const state = { handshake: false, handshakeRecord: null, peerCheck: null, refused: [], mismatches: [], downgrades: [], firstMode: null };
  const holdMs = o.holdMs ?? 7000;

  const verifyPeer = (sock) => {
    const p = o.peer ? o.peer(sock) : peerProcess(sock, { socketPath: o.socketPath, root: o.claudePid() });
    if (!p.available) {
      state.peerCheck = { available: false, reason: p.reason };
      return { ok: true, verified: false, reason: p.reason };
    }
    state.peerCheck = { available: true };
    if (o.claudePid() === null) {
      return { ok: false, reason: "claude has not started" };
    }
    if (!p.pid) {
      return { ok: false, reason: p.reason ?? "unknown peer" };
    }
    const exe = processExe(p.pid);
    if (exe !== realExecPath()) {
      return { ok: false, reason: `peer ${p.pid} runs ${exe}, not this Node` };
    }
    const argv = processArgv(p.pid);
    const want = o.expectedArgv();
    if (!argv || argv.length !== want.length || argv.some((a, i) => a !== want[i])) {
      return { ok: false, reason: `peer ${p.pid} is not running Enclawed Code's hook command for this session` };
    }
    // The genuine hook starts with an emptied environment (env -i): a peer
    // carrying NODE_OPTIONS or another NODE_* variable that can load code was
    // started some other way (round 3).
    const risk = processEnvRisk(p.pid);
    if (risk) {
      return { ok: false, reason: `peer ${p.pid} carries ${risk} in its environment, which can load other code into node` };
    }
    return { ok: true, verified: true, pid: p.pid };
  };

  // A tool_use the transcript watch saw (launcher.mjs).
  const noteUse = (u) => {
    if (typeof u?.id !== "string" || seen.has(u.id)) {
      return;
    }
    seen.set(u.id, { name: u.name ?? null, input: u.input, cwd: u.cwd ?? null, sessionId: u.sessionId ?? null });
    const pending = pendingBindings.get(u.id);
    if (pending) {
      pendingBindings.delete(u.id);
      const bad = checkBinding(u.id, pending, seen.get(u.id));
      if (bad) {
        o.onMismatch?.(bad);
      }
    }
    for (const w of seenWaiters.get(u.id) ?? []) {
      w(true);
    }
    seenWaiters.delete(u.id);
  };
  // Wait until the transcript shows tool_use `id` (polling it meanwhile).
  const waitSeen = (id, ms) =>
    seen.has(id)
      ? Promise.resolve(true)
      : new Promise((resolve) => {
          const list = seenWaiters.get(id) ?? [];
          seenWaiters.set(id, list);
          let done = false;
          const finish = (v) => {
            if (done) {
              return;
            }
            done = true;
            clearTimeout(t);
            clearInterval(tick);
            resolve(v);
          };
          list.push(finish);
          const t = setTimeout(() => finish(seen.has(id)), ms);
          const tick = setInterval(() => {
            o.pollTranscripts?.();
            if (seen.has(id)) {
              finish(true);
            }
          }, 100);
          o.pollTranscripts?.();
        });

  const waitHandshake = (ms) =>
    state.handshake
      ? Promise.resolve(true)
      : new Promise((resolve) => {
          const w = (v) => {
            clearTimeout(t);
            waiters.delete(w);
            resolve(v);
          };
          const t = setTimeout(() => w(false), ms);
          waiters.add(w);
        });

  const conns = new Set();
  const server = net.createServer((sock) => {
    conns.add(sock);
    sock.on("close", () => conns.delete(sock));
    sock.on("error", () => {});
    sock.setTimeout(holdMs + 5000, () => sock.destroy());
    const peer = verifyPeer(sock);
    const send = (m) => sock.write(`${JSON.stringify(m)}\n`);
    if (!peer.ok) {
      state.refused.push(peer.reason);
      send({ ok: false, reason: `Enclawed Code launcher refused this connection: ${peer.reason}` });
      sock.end();
      return;
    }
    let challenge = null;
    lineReader(sock, async (msg) => {
      if (msg?.op === "session-start") {
        challenge = createHmac("sha256", key).update(`challenge|${o.nonce}|${counter++}`).digest("hex");
        issued.add(challenge);
        send({ ok: true, challenge, relaySecret: o.relaySecret ?? null, peerVerified: peer.verified });
      } else if (msg?.op === "started" && challenge && typeof msg.recordHash === "string") {
        const v = verifyChainedRecord(o.auditFile, msg.recordHash, { fromHash: o.launchHash?.() ?? null });
        const r = v.ok ? v.record : null;
        const good = r && r.type === "claude-code.session.start" && r.payload?.launcherNonce === o.nonce && r.payload?.handshake === challenge && issued.has(challenge);
        if (good) {
          issued.delete(challenge);
          state.handshake = true;
          state.handshakeRecord = msg.recordHash;
          // Claude Code's session id, for the exit hint (resume under Enclawed Code).
          state.sessionId = typeof r.payload?.sessionId === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(r.payload.sessionId) ? r.payload.sessionId : state.sessionId ?? null;
          for (const w of [...waiters]) {
            w(true);
          }
          send({ ok: true });
        } else {
          state.refused.push(v.ok ? "the session.start record does not carry this launch's nonce and challenge" : v.reason);
          send({ ok: false, reason: v.ok ? "record does not match the challenge" : v.reason });
        }
        sock.end();
      } else if (msg?.op === "anchor") {
        // The verified hook asks the launcher to anchor the head now (N10):
        // the launcher holds the device's anchor session.
        o.onAnchorRequest?.();
        send({ ok: true });
        sock.end();
      } else if (msg?.op === "pre") {
        const id = typeof msg.toolUseId === "string" ? msg.toolUseId : null;
        const done = await waitHandshake(holdMs);
        if (!done) {
          send({ ok: false, reason: `Enclawed's session-start handshake did not complete within ${Math.round(holdMs / 1000)} s` });
          sock.end();
          return;
        }
        // Bind the decision to the call (call-binding.mjs). Headless, Claude
        // Code writes the tool_use line before it runs the PreToolUse hook, so
        // the line is waited for. Interactive Claude Code 2.1.326 writes it only
        // after the hook has answered (found live, round 5), so there
        // (`deferBinding`) the report is kept and checked as soon as the line
        // appears; a mismatch then stops claude the same way.
        if (!id) {
          state.refused.push("the hook reported no tool_use_id");
          send({ ok: false, reason: "the hook reported no tool_use_id" });
          sock.end();
          return;
        }
        const report = { tool: typeof msg.tool === "string" ? msg.tool : null, binding: msg.binding, context: msg.context };
        const deferred = o.deferBinding?.() === true;
        if (!(await waitSeen(id, deferred ? Math.min(holdMs, 300) : holdMs))) {
          if (!deferred) {
            const reason = `the transcript shows no tool call ${id}; a decision is accepted only for a call Claude Code wrote there`;
            state.refused.push(reason);
            send({ ok: false, reason });
            sock.end();
            return;
          }
          if (!pendingBindings.has(id)) {
            pendingBindings.set(id, report);
          }
        } else {
          const bad = checkBinding(id, report, seen.get(id));
          if (bad) {
            send({ ok: false, reason: `${bad.reason}; this decision is not for that call` });
            sock.end();
            o.onMismatch?.(bad);
            return;
          }
        }
        decided.add(id);
        if (!decisions.has(id)) {
          decisions.set(id, "pending");
        }
        send({ ok: true, relaySecret: o.relaySecret ?? null });
        sock.end();
      } else if (msg?.op === "decision") {
        // The hook's decision for a call that passed `pre` (round 4, N13).
        // Only the first one counts: a later run of the genuine hook for the
        // same id cannot turn a deny into an allow.
        const id = typeof msg.toolUseId === "string" ? msg.toolUseId : null;
        const d = msg.decision;
        if (!id || decisions.get(id) !== "pending" || !["allow", "ask", "deny"].includes(d)) {
          send({ ok: false, reason: id && decisions.has(id) ? `a decision for ${id} was already reported` : "no pending call for this decision" });
        } else {
          decisions.set(id, d);
          o.onDecision?.({ id, decision: d });
          send({ ok: true });
        }
        sock.end();
      } else if (msg?.op === "approve") {
        // Interactive "ask" (round 5, N13c): the launcher asks the person on
        // its own terminal. Only for a call whose reported decision is "ask",
        // and only once per call; the answer is the launcher's, not the hook's.
        const id = typeof msg.toolUseId === "string" ? msg.toolUseId : null;
        if (!o.onApprove || !id || decisions.get(id) !== "ask" || prompted.has(id)) {
          send({ ok: false, approved: false, reason: !o.onApprove ? "this session has no Enclawed Code prompt" : id && prompted.has(id) ? `call ${id} was already put to the person` : "no call decided ask matches this request" });
          sock.end();
          return;
        }
        prompted.add(id);
        sock.setTimeout(0);
        // An identical call (same tool, same input) the person already denied in this session is
        // denied again without asking. Only a denial is repeated, never an approval.
        const call = seen.get(id) ?? null;
        const same = call ? createHash("sha256").update(JSON.stringify([call.name ?? null, canonical(call.input)])).digest("hex") : null;
        // The call's own signals (the hook's), and what Claude read earlier in this session.
        const signals = [...plantedNow(), ...signalsOf(msg.signals)];
        if (same && deniedByPerson.has(same)) {
          send({ ok: true, approved: false, deniedByPerson: true, repeat: true, reason: "you already denied this in this session", signals });
          sock.end();
          return;
        }
        let r;
        try {
          r = await o.onApprove({ id, tool: seen.get(id)?.name ?? pendingBindings.get(id)?.tool ?? null, reason: typeof msg.reason === "string" ? msg.reason : "", ...(typeof msg.code === "string" ? { code: msg.code } : {}), ...(msg.effect && typeof msg.effect === "object" ? { effect: msg.effect } : {}), signals });
        } catch (err) {
          r = { approved: false, reason: `the prompt failed (${err.message})` };
        }
        if (r.approved) {
          approved.add(id);
        } else if (r.deniedByPerson && same) {
          deniedByPerson.add(same);
        }
        send({ ok: true, approved: Boolean(r.approved), reason: r.reason ?? null, ...(r.deniedByPerson ? { deniedByPerson: true } : {}), signals });
        sock.end();
      } else if (msg?.op === "contain") {
        // A project script or install the kit marked (Decision.contain): the
        // launcher opens the containment (kit.scriptContainer; its relay lives
        // here) and answers with the contained command. Once per pending call.
        const id = typeof msg.toolUseId === "string" ? msg.toolUseId : null;
        const req = msg.request && typeof msg.request === "object" ? msg.request : null;
        // The call is still being decided, or it was an "ask" the person
        // approved at this launcher's prompt (the kit contains it only after
        // the answer).
        const open = decisions.get(id) === "pending" || (decisions.get(id) === "ask" && approved.has(id));
        if (!o.onContain || !id || !open || contained.has(id) || !req || typeof req.command !== "string") {
          send({ ok: false, code: o.onContain ? "containment-setup-failed" : "containment-unavailable", reason: !o.onContain ? "this session has no containment for what the agent runs" : "no pending call matches this containment request" });
          sock.end();
          return;
        }
        sock.setTimeout(0);
        let r;
        try {
          r = await o.onContain(req);
        } catch (err) {
          r = { ok: false, code: "containment-setup-failed", message: err.message };
        }
        if (r?.ok) {
          contained.set(id, r.command);
          send({ ok: true, command: r.command });
        } else {
          send({ ok: false, code: r?.code ?? "containment-setup-failed", reason: r?.message ?? "the containment could not be opened" });
        }
        sock.end();
      } else if (msg?.op === "post") {
        // PostToolUse for a call: Claude Code ran it with Enclawed's hooks
        // loaded, after its own permission flow (an "ask" was answered).
        const id = typeof msg.toolUseId === "string" ? msg.toolUseId : null;
        const call = id ? seen.get(id) : null;
        // A contained call runs as the command the launcher's containment gave it.
        const expected = call && contained.has(id) && call.input && typeof call.input === "object" ? { ...call, input: { ...call.input, command: contained.get(id) } } : call;
        const m = call ? bindingMatches({ tool: typeof msg.tool === "string" ? msg.tool : null, binding: msg.binding }, expected, { cwd: o.cwd ?? null, home: o.home ?? null }) : { ok: false };
        if (id && decided.has(id) && m.ok) {
          posts.add(id);
          postCount++;
          for (const s of signalsOf(msg.planted)) {
            planted.set(s.kind, { signal: s, at: postCount });
          }
          send({ ok: true });
        } else {
          send({ ok: false, reason: "no decided call matches this result" });
        }
        sock.end();
      } else if (msg?.op === "signals") {
        // What Claude read earlier in this session held (for a denial's warning).
        send({ ok: true, signals: plantedNow() });
        sock.end();
      } else {
        sock.destroy();
      }
    });
  });

  return new Promise((resolve, reject) => {
    fs.rmSync(o.socketPath, { force: true });
    server.once("error", reject);
    server.listen(o.socketPath, () => {
      try {
        fs.chmodSync(o.socketPath, 0o600);
      } catch {
        /* the directory is 0700 anyway */
      }
      resolve({
        path: o.socketPath,
        state,
        decided,
        decisions,
        posts,
        prompted,
        approved,
        contained,
        seen,
        pendingBindings,
        noteUse,
        waitHandshake,
        close: () =>
          new Promise((r) => {
            server.close(() => r());
            for (const c of conns) {
              c.destroy();
            }
            for (const w of [...waiters]) {
              w(false);
            }
          }),
      });
    });
  });
}

/**
 * Hook side: a conversation with the launcher's control socket. The other
 * end must be the launcher process named in the session file (when the
 * platform can tell).
 */
export function openControl({ path: socketPath }, { launcherPid, timeoutMs = 9000, peer = null } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(socketPath);
    const replies = [];
    const pending = [];
    let closed = false;
    const timer = setTimeout(() => {
      sock.destroy();
      fail(new Error("the Enclawed Code launcher did not answer in time"));
    }, timeoutMs);
    const fail = (err) => {
      closed = true;
      while (pending.length) {
        pending.shift().reject(err);
      }
    };
    sock.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`cannot reach the Enclawed Code launcher (${err.code ?? err.message})`));
      fail(err);
    });
    sock.on("close", () => {
      clearTimeout(timer);
      fail(new Error("the Enclawed Code launcher closed the connection"));
    });
    lineReader(sock, (m) => {
      if (pending.length) {
        pending.shift().resolve(m);
      } else {
        replies.push(m);
      }
    });
    sock.on("connect", () => {
      const p = peer ? peer(sock) : peerProcess(sock, { candidates: [launcherPid] });
      if (p.available && p.pid !== launcherPid) {
        sock.destroy();
        reject(new Error(`the control socket is not served by the Enclawed Code launcher (pid ${launcherPid})`));
        return;
      }
      resolve({
        peerVerified: p.available,
        ask(msg) {
          if (replies.length) {
            return Promise.resolve(replies.shift());
          }
          if (closed) {
            return Promise.reject(new Error("the Enclawed Code launcher closed the connection"));
          }
          return new Promise((res, rej) => {
            pending.push({ resolve: res, reject: rej });
            if (msg) {
              sock.write(`${JSON.stringify(msg)}\n`);
            }
          });
        },
        close() {
          clearTimeout(timer);
          sock.destroy();
        },
      });
    });
  });
}
