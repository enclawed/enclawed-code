// `ecwctl review`: an opt-in, evaluation-only model judge over
// calls the gate already decided.
//
// After the fact, never inline: it reads the decided calls in the audit log
// (claude-code.tool.pre records), asks a model to classify each one by the
// paper's definitions and to say whether it agrees with the gate (the kit's
// review-judge.ts), and shows the person ONLY the disagreements, to label:
// agree with the gate, the judge is right, or unsure. The labels are kept
// here (and audited) as candidates for refining the rules; refining them is
// a person's change through the usual policy and release path.
//
// It never influences a decision. The hook (bin/ecwcode-hook.mjs) and
// everything it imports exclude this module and review-model.mjs, and never
// call the kit's review functions (test/review.test.mjs and the conformance
// check adapter:claude-code:review-cannot-influence); nothing here writes a
// policy, a grant, an approval or a pin.
//
// Off by default. Turning it on needs the person's second factor and is
// audited. A run uses only an Anthropic API key sealed under the Enclaweder,
// through Enclawed Code's relay (review-model.mjs); a Claude subscription login
// is never used. Without a sealed API key, nothing is sent. A model is sent only the call's normalized text, built
// from what the audit log records about the call (a written file's content is
// recorded only as its digest, so none is sent); the kit refuses a call
// holding anything credential-shaped, and such a call is skipped, never sent.
// Every bound (calls per run, pacing, answer length) is an internal constant;
// a run prints its cap and needs the person's confirmation before anything
// is sent. A run is resumable: a judged or skipped call is not sent again.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { segmentFiles } from "./audit.mjs";
import { verifyUser } from "./auth.mjs";
import { UsageError, parseFlags, writeFileAtomic } from "./cli-util.mjs";
import { kit } from "./kit.mjs";
import { appStateDir, auditLogPath } from "./paths.mjs";

/** At most this many calls are sent to the model in one run. */
export const REVIEW_MAX_CALLS_PER_RUN = 40;
/** At least this long between two model requests. */
export const REVIEW_MIN_INTERVAL_MS = 2000;
/** The longest answer asked of the model (output tokens). */
export const REVIEW_MAX_OUTPUT_TOKENS = 300;
/** A run stops after this many model errors in a row. */
export const REVIEW_MAX_CONSECUTIVE_ERRORS = 3;
/** The printed cost estimate: input tokens per call (prompt with definitions, plus the call). */
const EST_INPUT_TOKENS_PER_CALL = 1200;

export const PERSON_LABELS = Object.freeze({ a: "agree-with-gate", j: "judge-right", u: "unsure" });

export const REVIEW_HELP = `Experimental feature: the review judge is not yet calibrated against a live model.

usage:
  ecwctl review [status]          whether the review judge is on; calls judged, disagreements, labels
  ecwctl review enable            turn it on (your security key or passkey; audited). Off by default
  ecwctl review disable           turn it off (audited)
  ecwctl review run               judge decided calls from the audit log, after the fact (prints its cap; asks first)
  ecwctl review label             label each disagreement: agree with the gate, the judge is right, or unsure
  ecwctl review export [--out F]  write the labeled disagreements as CSV (refinement candidates)

The judge never changes a decision: it only shows where a model and the gate disagree.
`;

export function reviewDir(env = process.env) {
  return path.join(appStateDir(env), "review");
}
const settingsFile = (env) => path.join(reviewDir(env), "settings.json");
const judgedFile = (env) => path.join(reviewDir(env), "judged.jsonl");
const labelsFile = (env) => path.join(reviewDir(env), "labels.jsonl");

function ensureDir(env) {
  fs.mkdirSync(reviewDir(env), { recursive: true, mode: 0o700 });
}

/** The setting: { enabled }. Anything but a well-formed "on" record is off. */
export function reviewSettings(env = process.env) {
  try {
    const doc = JSON.parse(fs.readFileSync(settingsFile(env), "utf8"));
    return { enabled: doc?.v === 1 && doc.enabled === true, since: typeof doc?.at === "string" ? doc.at : null };
  } catch {
    return { enabled: false, since: null };
  }
}

function readJsonl(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return [];
  }
  const out = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) {
      continue;
    }
    try {
      out.push(JSON.parse(line));
    } catch {
      /* a torn last line from an interrupted run: that call is judged again */
    }
  }
  return out;
}

function appendJsonl(file, obj) {
  fs.appendFileSync(file, `${JSON.stringify(obj)}\n`, { mode: 0o600 });
}

/** The call's text as recorded (summarize.mjs): what the call itself carries, never file content. */
export function recordedCallText(tool, input) {
  const i = input && typeof input === "object" ? input : {};
  const str = (v) => (typeof v === "string" ? v : null);
  const content = (d, what) => (d && typeof d === "object" && Number.isInteger(d.bytes) ? `\n<${what}: ${d.bytes} bytes, not shown>` : "");
  switch (tool) {
    case "Bash":
    case "Monitor":
    case "PowerShell":
      return str(i.command) ?? "";
    case "Read":
      return [str(i.filePath), i.offset != null ? `offset ${i.offset}` : null, i.limit != null ? `limit ${i.limit}` : null].filter(Boolean).join(" ");
    case "Write":
      return `${str(i.filePath) ?? ""}${content(i.content, "content")}`;
    case "Edit":
    case "MultiEdit":
      return `${str(i.filePath) ?? ""}${content(i.oldString, "old text")}${content(i.newString, "new text")}${i.replaceAll ? "\n<replace all>" : ""}`;
    case "NotebookEdit":
      return `${str(i.filePath) ?? ""}${content(i.input, "edit")}`;
    case "Glob":
    case "Grep":
      return [str(i.pattern), str(i.path) ? `in ${i.path}` : null].filter(Boolean).join(" ");
    case "WebFetch":
      return str(i.url) ?? "";
    case "WebSearch":
      return str(i.query) ?? "";
    case "Agent":
    case "Task":
      return [str(i.subagentType), str(i.description), content(i.prompt, "prompt").trim()].filter(Boolean).join(": ");
    default:
      return Array.isArray(i.keys) ? `arguments: ${i.keys.join(", ")}${content(i.input, "arguments")}` : "";
  }
}

const DECISIONS = new Set(["allow", "ask", "deny"]);

/** Every decided tool call in the audit log (sealed segments first), oldest first. */
export function decidedCalls(env = process.env) {
  const file = auditLogPath(env);
  const out = [];
  for (const f of [...segmentFiles(file).map((s) => s.file), file]) {
    for (const r of readJsonl(f)) {
      const p = r?.payload;
      if (r?.type !== "claude-code.tool.pre" || !p || !DECISIONS.has(p.decision) || typeof r.recordHash !== "string" || typeof p.tool !== "string") {
        continue;
      }
      out.push({
        id: r.recordHash,
        tool: p.tool,
        kind: typeof p.kind === "string" ? p.kind : null,
        decision: p.decision,
        codes: Array.isArray(p.codes) ? p.codes.filter((c) => typeof c === "string") : [],
        mode: typeof p.permissionMode === "string" ? p.permissionMode : null,
        projectDir: typeof p.projectDir === "string" ? p.projectDir : null,
        raw: recordedCallText(p.tool, p.input),
      });
    }
  }
  return out;
}

/** A person can be asked in this mode (the paper's "person reachable"). */
const personReachable = (mode) => mode !== "bypassPermissions";

function userName() {
  try {
    return os.userInfo().username;
  } catch {
    return null;
  }
}

/** The kit's review judge in this framework build, or null. */
function judgeKit(k) {
  const need = ["prepareReviewText", "reviewOf", "reviewPrompt", "runReview"];
  return need.every((n) => typeof k?.[n] === "function") ? k : null;
}

function state(env) {
  const judged = new Map(readJsonl(judgedFile(env)).filter((j) => typeof j?.id === "string").map((j) => [j.id, j]));
  const labels = new Map(readJsonl(labelsFile(env)).filter((l) => typeof l?.id === "string").map((l) => [l.id, l]));
  return { judged, labels };
}

function disagreements(env) {
  const { judged, labels } = state(env);
  return [...judged.values()].filter((j) => j.status === "disagree").map((j) => ({ ...j, label: labels.get(j.id)?.label ?? null }));
}

/**
 * The command. `deps` (tests and the conformance stand-in): `openModel`
 * (review-model.mjs openRelayedModel by default), `confirm` and `choose`
 * (the person's answers), `interactive`, `k` (the kit), `verify` (the
 * second factor), `sleep`.
 */
export async function reviewCommand(args, { out, err, env = process.env, audit, deps = {} }) {
  const sub = args[0] ?? "status";
  const say = (s) => out.write(s);
  const k = deps.k ?? kit;
  switch (sub) {
    case "help":
      out.write(REVIEW_HELP);
      return 0;
    case "status": {
      parseFlags(args.slice(1), { maxPositionals: 0 });
      const s = reviewSettings(env);
      const { judged, labels } = state(env);
      const calls = decidedCalls(env);
      const d = disagreements(env);
      say(`review judge (experimental feature): ${s.enabled ? `on (since ${s.since ?? "unknown"})` : "off (ecwctl review enable)"}\n`);
      say(`decided calls in the audit log: ${calls.length}; judged or skipped: ${calls.filter((c) => judged.has(c.id)).length}\n`);
      say(`disagreements: ${d.length}; labeled: ${d.filter((x) => labels.has(x.id)).length}\n`);
      return 0;
    }
    case "enable": {
      parseFlags(args.slice(1), { maxPositionals: 0 });
      if (reviewSettings(env).enabled) {
        say("the review judge is already on\n");
        return 0;
      }
      const verify = deps.verify ?? ((o) => verifyUser(o));
      await verify({ purpose: "review-enable", env, interactive: deps.interactive ?? Boolean(process.stdin.isTTY), audit, allowTicket: false });
      ensureDir(env);
      const at = new Date().toISOString();
      writeFileAtomic(settingsFile(env), `${JSON.stringify({ v: 1, enabled: true, at })}\n`);
      await audit({ type: "claude-code.review.enabled", actor: "enclawed-code", level: null, payload: { at } });
      say("the review judge (experimental feature) is on. It runs only when you run: ecwctl review run\n");
      return 0;
    }
    case "disable": {
      parseFlags(args.slice(1), { maxPositionals: 0 });
      ensureDir(env);
      writeFileAtomic(settingsFile(env), `${JSON.stringify({ v: 1, enabled: false, at: new Date().toISOString() })}\n`);
      await audit({ type: "claude-code.review.disabled", actor: "enclawed-code", level: null, payload: {} });
      say("the review judge is off\n");
      return 0;
    }
    case "run":
      parseFlags(args.slice(1), { maxPositionals: 0 });
      return runCommand({ out, err, env, audit, k, deps });
    case "label":
      parseFlags(args.slice(1), { maxPositionals: 0 });
      return labelCommand({ out, err, env, audit, deps });
    case "export": {
      const { flags } = parseFlags(args.slice(1), { value: ["--out"], maxPositionals: 0 });
      return exportCommand({ out, env, audit, file: flags["--out"] ?? null });
    }
    default:
      throw new UsageError(REVIEW_HELP.trim());
  }
}

async function runCommand({ out, err, env, audit, k, deps }) {
  if (!reviewSettings(env).enabled) {
    err.write("ecwctl: the review judge is off; nothing was sent (turn it on with: ecwctl review enable)\n");
    return 1;
  }
  const judge = judgeKit(k);
  if (!judge) {
    err.write("ecwctl: this Enclawed framework build has no review judge; nothing was sent\n");
    return 1;
  }
  ensureDir(env);
  const { judged } = state(env);
  const home = env.HOME ?? null;
  const user = userName();
  // Prepare in order; a call the kit refuses (a credential in it) is recorded as skipped and never sent.
  const batch = [];
  let skipped = 0;
  let pending = 0;
  for (const c of decidedCalls(env)) {
    if (judged.has(c.id)) {
      continue;
    }
    pending++;
    if (batch.length >= REVIEW_MAX_CALLS_PER_RUN) {
      continue;
    }
    const p = judge.prepareReviewText(c.raw, { home, projectDir: c.projectDir, user });
    if (!p.ok) {
      skipped++;
      appendJsonl(judgedFile(env), { id: c.id, status: "skipped", code: p.code, findings: p.findings, at: new Date().toISOString() });
      continue;
    }
    batch.push({ c, call: { tool: c.tool, kind: c.kind, text: p.text, decision: c.decision, codes: c.codes, personReachable: personReachable(c.mode) } });
  }
  if (batch.length === 0) {
    out.write(`nothing to review (${skipped} call(s) skipped: they hold something credential-shaped and are never sent)\n`);
    return 0;
  }
  out.write(
    `This run sends at most ${batch.length} call(s) to the model (${pending} not yet reviewed; at most ${REVIEW_MAX_CALLS_PER_RUN} per run), one every ${REVIEW_MIN_INTERVAL_MS / 1000} s: about ${batch.length * EST_INPUT_TOKENS_PER_CALL} input and at most ${batch.length * REVIEW_MAX_OUTPUT_TOKENS} output tokens on your Claude account. Only each call's normalized text is sent (no file content; calls holding anything credential-shaped are skipped: ${skipped}).\n`,
  );
  const confirm = deps.confirm ?? (async () => (await import("./cli-util.mjs")).ask("Send them? Type yes to continue: "));
  const yes = String((await confirm().catch(() => "")) ?? "").trim().toLowerCase() === "yes";
  if (!yes) {
    out.write("not confirmed; nothing was sent\n");
    return 1;
  }
  const openModel = deps.openModel ?? (async (o) => (await import("./review-model.mjs")).openRelayedModel(o));
  const model = await openModel({ env, err, audit }).catch((e) => ({ ok: false, reason: e?.message ?? String(e) }));
  if (!model?.ok) {
    err.write(`ecwctl: the review judge cannot reach a model (${model?.reason ?? "unknown"}); nothing was sent\n`);
    await audit({ type: "claude-code.review.run", actor: "enclawed-code", level: null, payload: { sent: 0, unavailable: String(model?.reason ?? "unknown").slice(0, 300) } });
    return 1;
  }
  let summary;
  try {
    summary = await judge.runReview(
      batch.map((b) => b.call),
      (prompt) => model.send(prompt, { maxTokens: REVIEW_MAX_OUTPUT_TOKENS }),
      {
        limit: REVIEW_MAX_CALLS_PER_RUN,
        minIntervalMs: REVIEW_MIN_INTERVAL_MS,
        maxConsecutiveErrors: REVIEW_MAX_CONSECUTIVE_ERRORS,
        ...(deps.sleep ? { sleep: deps.sleep } : {}),
        onResult: (i, r) => {
          const { c, call } = batch[i];
          if (r.status === "no-verdict" && r.noVerdict === "model-error") {
            return; // not judged: the next run sends it again
          }
          appendJsonl(judgedFile(env), {
            id: c.id,
            status: r.status,
            ...(r.status === "no-verdict" ? { noVerdict: r.noVerdict } : { judge: r.verdict, expected: r.expected }),
            // What the person sees when labeling (already in the audit log, normalized).
            ...(r.status === "disagree" ? { tool: c.tool, mode: c.mode, decision: c.decision, codes: c.codes, text: call.text } : {}),
            at: new Date().toISOString(),
          });
        },
      },
    );
  } finally {
    await model.close?.().catch(() => {});
  }
  await audit({ type: "claude-code.review.run", actor: "enclawed-code", level: null, payload: { model: model.model ?? null, sent: summary.sent, agree: summary.agree, disagree: summary.disagree, noVerdict: summary.noVerdict, skipped, stoppedOnErrors: summary.stoppedOnErrors } });
  out.write(`sent ${summary.sent}: the judge agrees with the gate on ${summary.agree}, disagrees on ${summary.disagree}, no verdict on ${summary.noVerdict}${summary.stoppedOnErrors ? " (stopped: the model failed repeatedly; run again later to resume)" : ""}\n`);
  const open = disagreements(env).filter((d) => !d.label).length;
  if (open > 0) {
    out.write(`disagreements to label: ${open} (ecwctl review label)\n`);
  }
  return 0;
}

async function labelCommand({ out, err, env, audit, deps }) {
  const interactive = deps.interactive ?? Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const open = disagreements(env).filter((d) => !d.label);
  if (open.length === 0) {
    out.write("no disagreements to label\n");
    return 0;
  }
  if (!interactive) {
    err.write("ecwctl: labeling needs a person at a terminal\n");
    return 1;
  }
  const choose = deps.choose ?? (async (q) => (await import("./cli-util.mjs")).ask(q));
  ensureDir(env);
  let n = 0;
  for (const d of open) {
    out.write(
      [
        "",
        `call ${d.id.slice(0, 12)}  ${d.tool}${d.mode ? ` (${d.mode})` : ""}`,
        `  gate:  ${d.decision}${d.codes?.length ? ` [${d.codes.join(", ")}]` : ""}`,
        `  judge: ${d.judge?.label} (a correct gate would ${d.expected?.join(" or ")}): ${kit.quoteUntrusted(d.judge?.rationale ?? "", { max: 600 })}`,
        `  call:  ${kit.quoteUntrusted(d.text ?? "", { max: 1500 })}`,
        "",
      ].join("\n"),
    );
    const a = String((await choose("[a] agree with the gate  [j] the judge is right  [u] unsure  [s] skip  [q] quit: ").catch(() => "q")) ?? "q").trim().toLowerCase();
    if (a === "q") {
      break;
    }
    const label = PERSON_LABELS[a];
    if (!label) {
      continue;
    }
    const at = new Date().toISOString();
    appendJsonl(labelsFile(env), { id: d.id, label, at });
    await audit({ type: "claude-code.review.labeled", actor: "enclawed-code", level: null, payload: { id: d.id, label } });
    n++;
  }
  out.write(`labeled ${n}\n`);
  return 0;
}

/** One CSV field: quoted, and a leading formula character neutralized (a spreadsheet would run it). */
export function csvField(v) {
  let s = v === null || v === undefined ? "" : Array.isArray(v) ? v.join(" ") : String(v);
  if (/^[=+\-@\t\r]/.test(s)) {
    s = `'${s}`;
  }
  return `"${s.replaceAll('"', '""')}"`;
}

export const CSV_COLUMNS = ["id", "tool", "mode", "gate_decision", "gate_codes", "judge_label", "judge_expected", "person_label", "call_text", "judge_rationale", "labeled_at"];

async function exportCommand({ out, env, audit, file }) {
  const { labels } = state(env);
  const rows = disagreements(env).filter((d) => d.label);
  const lines = [CSV_COLUMNS.join(",")];
  for (const d of rows) {
    lines.push([d.id, d.tool, d.mode, d.decision, d.codes, d.judge?.label, d.expected, d.label, d.text, d.judge?.rationale, labels.get(d.id)?.at].map(csvField).join(","));
  }
  const text = `${lines.join("\n")}\n`;
  if (file) {
    const dest = path.resolve(file);
    fs.writeFileSync(dest, text, { mode: 0o600 });
    out.write(`wrote ${rows.length} labeled disagreement(s) to ${dest}\n`);
  } else {
    out.write(text);
  }
  await audit({ type: "claude-code.review.exported", actor: "enclawed-code", level: null, payload: { rows: rows.length, file: file ? path.resolve(file) : null } });
  return 0;
}
