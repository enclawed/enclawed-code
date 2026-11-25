// Reconcile the audit log against itself and against Claude Code's own
// transcripts: which sessions lack a start or end record, which tool calls
// ran without a recorded decision, which allowed calls have no recorded
// result. A session whose hooks were switched off shows up here, because its
// transcript contains tool calls the log never saw, and so does a launch
// whose hooks never reported in (no session-start with the launch's nonce).
// A call whose input changed between the decision and the run (another hook
// rewrote it) is an error too. Subagent transcripts are read as well; a
// transcript that is gone is reported, not skipped silently.

import path from "node:path";
import { bindingMatches } from "./call-binding.mjs";

import fs from "node:fs";
import readline from "node:readline";

async function* records(file) {
  if (!fs.existsSync(file)) {
    return;
  }
  const rl = readline.createInterface({ input: fs.createReadStream(file, "utf8"), crlfDelay: Infinity });
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

/** Tool-use ids in a Claude Code transcript (JSONL), best effort. */
export async function transcriptToolUseIds(file) {
  const calls = await transcriptToolUses(file);
  return calls === null ? null : new Set(calls.keys());
}

/**
 * Tool calls in a transcript: id -> { name, input, cwd, ran }, where `cwd`
 * is the working directory Claude Code recorded on that line and `ran` is
 * true when a tool_result for it is not an error (round 4, N13).
 */
export async function transcriptToolUses(file) {
  const ids = new Map();
  const ran = new Set();
  if (!file || !fs.existsSync(file)) {
    return null;
  }
  let lineCwd = null;
  const visit = (v) => {
    if (Array.isArray(v)) {
      v.forEach(visit);
    } else if (v && typeof v === "object") {
      if (v.type === "tool_use" && typeof v.id === "string" && !ids.has(v.id)) {
        ids.set(v.id, { name: typeof v.name === "string" ? v.name : null, input: v.input, cwd: lineCwd, ran: false });
      } else if (v.type === "tool_result" && typeof v.tool_use_id === "string" && v.is_error !== true) {
        ran.add(v.tool_use_id);
      }
      for (const x of Object.values(v)) {
        if (x && typeof x === "object") {
          visit(x);
        }
      }
    }
  };
  for await (const rec of records(file)) {
    lineCwd = typeof rec?.cwd === "string" ? rec.cwd : null;
    visit(rec);
  }
  for (const id of ran) {
    if (ids.has(id)) {
      ids.get(id).ran = true;
    }
  }
  return ids;
}

/**
 * The transcripts to read: the recorded ones plus the subagent transcripts
 * Claude Code keeps beside a session transcript (<session>/subagents/*.jsonl).
 */
export function subagentTranscripts(set) {
  const out = new Set(set);
  for (const t of set) {
    const dir = path.join(t.replace(/\.jsonl$/, ""), "subagents");
    try {
      for (const f of fs.readdirSync(dir)) {
        if (f.endsWith(".jsonl")) {
          out.add(path.join(dir, f));
        }
      }
    } catch {
      /* no subagents */
    }
  }
  return out;
}

export async function reconcile(auditFile, { checkTranscripts = true } = {}) {
  const sessions = new Map();
  const get = (id) => {
    const key = id ?? "(none)";
    if (!sessions.has(key)) {
      sessions.set(key, { id: key, start: null, end: false, transcripts: new Set(), pre: new Map(), post: new Set(), postDigest: new Map() });
    }
    return sessions.get(key);
  };
  const launches = new Map();
  const nonces = new Set();
  const extraFindings = [];
  for await (const r of records(auditFile)) {
    const p = r.payload ?? {};
    if (typeof r.type !== "string" || !r.type.startsWith("claude-code.")) {
      continue;
    }
    if (r.type === "claude-code.launch") {
      if (p.nonce && !p.managed && !p.background) {
        launches.set(p.nonce, { ts: r.ts, cwd: p.cwd });
      }
      continue;
    }
    if (r.type === "claude-code.audit.gap") {
      extraFindings.push({ session: "(log)", severity: "error", code: "audit-gap", detail: `${p.reason} at ${new Date(r.ts).toISOString()}` });
      continue;
    }
    if (r.type === "claude-code.launch.decision-violated") {
      extraFindings.push({ session: "(launch)", severity: "error", code: "decision-violated", detail: `${p.toolUseId} ran although Enclawed decided ${p.decision} (the launcher stopped claude)` });
      continue;
    }
    if (r.type === "claude-code.launch.anchor-tamper") {
      extraFindings.push({ session: "(launch)", severity: "error", code: "anchor-tamper", detail: p.reason ?? "the audit log or its anchor changed during a session" });
      continue;
    }
    if (r.type === "claude-code.launch.settings-dropped") {
      extraFindings.push({ session: "(launch)", severity: "error", code: "settings-dropped", detail: p.detail ?? "Claude Code did not load Enclawed Code's settings" });
      continue;
    }
    if (r.type.startsWith("claude-code.launch.") || r.type.startsWith("claude-code.auth.") || r.type.startsWith("claude-code.policy.") || r.type.startsWith("claude-code.history.") || r.type.startsWith("claude-code.hardware.")) {
      continue;
    }
    const s = get(p.sessionId);
    switch (r.type) {
      case "claude-code.session.start":
        s.start ??= r.ts;
        if (p.transcriptPath) {
          s.transcripts.add(p.transcriptPath);
        }
        if (p.launcherNonce) {
          nonces.add(p.launcherNonce);
        }
        break;
      case "claude-code.subagent.stop":
        if (p.agentTranscriptPath) {
          s.transcripts.add(p.agentTranscriptPath);
        }
        break;
      case "claude-code.session.end":
        s.end = true;
        break;
      case "claude-code.tool.pre":
      case "claude-code.hook.error":
        if (p.toolUseId) {
          s.pre.set(p.toolUseId, { decision: p.decision, tool: p.tool, inputDigest: p.inputDigest ?? null, binding: p.binding ?? null, projectDir: p.projectDir ?? null });
        }
        break;
      case "claude-code.tool.post":
      case "claude-code.tool.failure":
        if (p.toolUseId) {
          s.post.add(p.toolUseId);
          if (p.inputDigest) {
            s.postDigest.set(p.toolUseId, p.inputDigest);
          }
        }
        break;
      default:
        break;
    }
  }
  const findings = [...extraFindings];
  for (const [nonce, l] of launches) {
    if (!nonces.has(nonce)) {
      findings.push({ session: "(launch)", severity: "error", code: "launch-without-hooks", detail: `Enclawed Code launched claude in ${l.cwd} at ${new Date(l.ts).toISOString()} but its hooks never reported in` });
    }
  }
  for (const s of sessions.values()) {
    if (s.start === null) {
      findings.push({ session: s.id, severity: "warn", code: "no-session-start", detail: "tool calls recorded without a session start" });
    }
    if (!s.end) {
      findings.push({ session: s.id, severity: "info", code: "no-session-end", detail: "still running, or ended without its end hook" });
    }
    for (const id of s.post) {
      if (!s.pre.has(id)) {
        findings.push({ session: s.id, severity: "error", code: "ran-without-decision", detail: id });
      } else if (s.pre.get(id).decision === "deny") {
        findings.push({ session: s.id, severity: "error", code: "ran-despite-deny", detail: id });
      } else if (s.pre.get(id).inputDigest && s.postDigest.has(id) && s.postDigest.get(id) !== s.pre.get(id).inputDigest) {
        findings.push({ session: s.id, severity: "error", code: "input-changed-after-decision", detail: `${id} (${s.pre.get(id).tool})` });
      }
    }
    for (const [id, pre] of s.pre) {
      if (pre.decision === "allow" && !s.post.has(id)) {
        findings.push({ session: s.id, severity: "info", code: "allowed-no-result", detail: `${id} (${pre.tool})` });
      }
    }
    if (checkTranscripts) {
      for (const t of subagentTranscripts(s.transcripts)) {
        const calls = await transcriptToolUses(t);
        if (calls === null) {
          findings.push({ session: s.id, severity: "warn", code: "transcript-missing", detail: t });
          continue;
        }
        for (const [id, call] of calls) {
          const pre = s.pre.get(id);
          if (!pre) {
            findings.push({ session: s.id, severity: "error", code: "transcript-call-without-decision", detail: id });
            continue;
          }
          // A call that ran although the decision was deny, or ask with no
          // result recorded by Enclawed's PostToolUse (round 4, N13).
          if (call.ran && (pre.decision === "deny" || (pre.decision === "ask" && !s.post.has(id)))) {
            findings.push({ session: s.id, severity: "error", code: "ran-despite-decision", detail: `${id} (${call.name}) ran although Enclawed decided ${pre.decision}` });
          }
          // The decision recorded for this id must be for this call (round 3, N9).
          if (pre.tool !== call.name) {
            findings.push({ session: s.id, severity: "error", code: "tool-name-mismatch", detail: `${id}: the log records ${pre.tool}, the transcript ${call.name}` });
          } else if (pre.binding) {
            const m = bindingMatches({ tool: pre.tool, binding: pre.binding }, call, { cwd: pre.projectDir, home: process.env.HOME ?? null });
            if (!m.ok) {
              findings.push({ session: s.id, severity: "error", code: "tool-input-mismatch", detail: `${id} (${call.name}): ${m.reason}` });
            }
          }
        }
      }
    }
  }
  return { sessions: sessions.size, launches: launches.size, findings };
}
