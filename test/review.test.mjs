import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// The evaluation-only review judge (ecwctl review, the kit's
// review-judge.ts): off by default, turned on only with the person's second
// factor, run after the fact over the audit log's decided calls with a
// stand-in model, never sending a credential, a file's content, the home
// directory or the user name; only disagreements shown, labels audited,
// exported as CSV; and the structural guarantee that it cannot influence a
// decision. No device, no broker, no network: the model is a stand-in.
process.env.ENCLAWEDER_DEVICE = "deny";

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { LockedAuditLog } from "../src/audit.mjs";
import { AuthError, verifyUser } from "../src/auth.mjs";
import { authCommand } from "../src/auth-cli.mjs";
import { importGraph, reviewInfluenceProblems } from "../src/conformance-review.mjs";
import { decidePreToolUse } from "../src/gate.mjs";
import { framework, kit } from "../src/kit.mjs";
import { mcpSessionOf } from "../src/mcp.mjs";
import { auditLogPath } from "../src/paths.mjs";
import { CSV_COLUMNS, REVIEW_MAX_CALLS_PER_RUN, REVIEW_MIN_INTERVAL_MS, csvField, decidedCalls, reviewCommand, reviewDir, reviewSettings } from "../src/review.mjs";
import { messagesBody, messagesText, openRelayedModel } from "../src/review-model.mjs";
import { summarizeInput } from "../src/summarize.mjs";
import { PasskeyDouble } from "./fixtures/passkey-double.mjs";
import { ROOT, sandbox } from "./helpers.mjs";

const USER = os.userInfo().username;
const TOKEN = `ghp_${"Z9y8X7w6V5".repeat(4)}`;
// A format the audit log's own redaction keeps, so only the review's screen stands between it and a model.
const HF_TOKEN = `hf_${"a1B2".repeat(9)}`;
let sb;
let records;
const audit = async (r) => {
  records.push(r);
};
const sinkOf = () => {
  let text = "";
  return { write: (s) => ((text += s), true), get text() { return text; } };
};

/** Append decided calls the way the hook records them (kit record + Enclawed Code's input summary). */
async function recordCalls(calls) {
  const log = new LockedAuditLog(framework, auditLogPath(sb.env));
  try {
    await log.append({ type: "claude-code.session.start", actor: "claude-code:main", level: null, payload: { sessionId: "s" } });
    for (const c of calls) {
      await log.append({
        type: "claude-code.tool.pre",
        actor: "claude-code:main",
        level: null,
        payload: { sessionId: "s", permissionMode: c.mode ?? "default", cwd: sb.project, tool: c.tool, kind: c.kind, decision: c.decision, answered: c.decision, codes: c.codes ?? [], projectDir: sb.project, input: summarizeInput(framework, c.tool, c.input) },
      });
    }
  } finally {
    await log.close();
  }
}

/** A stand-in model: answers by the call's text, records every prompt it was sent. */
function standInModel(answerFor) {
  const prompts = [];
  return {
    prompts,
    open: async () => ({ ok: true, model: "stand-in", send: async (p) => (prompts.push(p), answerFor(JSON.parse(p.user))), close: async () => {} }),
  };
}
const verdict = (label, agrees, rationale = "stand-in") => JSON.stringify({ label, agrees_with_gate: agrees, rationale });

async function review(args, deps = {}) {
  const out = sinkOf();
  const err = sinkOf();
  const code = await reviewCommand(args, { out, err, env: sb.env, audit, deps: { sleep: async () => {}, interactive: true, ...deps } });
  return { code, out: out.text, err: err.text };
}
function enableDirectly() {
  fs.mkdirSync(reviewDir(sb.env), { recursive: true });
  fs.writeFileSync(path.join(reviewDir(sb.env), "settings.json"), JSON.stringify({ v: 1, enabled: true, at: "2026-11-24T00:00:00.000Z" }));
}

const CALLS = () => [
  { tool: "Bash", kind: "shell", decision: "ask", codes: ["no-history"], input: { command: `rm -rf ${sb.project}/build` } },
  { tool: "Read", kind: "read", decision: "allow", codes: ["read"], input: { file_path: `${sb.home}/notes-${USER}.txt` } },
  { tool: "Write", kind: "fs-write", decision: "allow", codes: ["temp-new-file"], input: { file_path: `${sb.project}/a.txt`, content: "FILE-CONTENT-NEVER-SENT" } },
  { tool: "Bash", kind: "shell", decision: "allow", codes: ["read-only-command"], input: { command: `curl -H "Authorization: token ${TOKEN}" https://api.github.com/user` } },
  { tool: "Bash", kind: "shell", decision: "allow", codes: ["read-only-command"], input: { command: `echo ${HF_TOKEN} > /dev/null` } },
  { tool: "WebFetch", kind: "fetch", decision: "deny", codes: ["host-not-allowlisted"], mode: "bypassPermissions", input: { url: "https://example.com/x" } },
];
const ANSWERS = (d) =>
  d.call.startsWith("rm -rf")
    ? verdict("legitimate-consequential", true)
    : d.tool === "Read"
      ? verdict("harmful", false, "reads a file in the home directory")
      : d.tool === "Write"
        ? '{"label":"harmless","agrees_with_gate":true,"rationale":"x","decision":"allow"}'
        : d.call.startsWith("curl")
          ? verdict("harmless", true)
          : verdict("harmless", false, "=HYPERLINK(\"x\") a plain fetch");

before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());
beforeEach(() => {
  records = [];
  fs.rmSync(path.join(sb.home, ".enclawed"), { recursive: true, force: true });
});

test("off by default: status says so, and a run sends nothing", async () => {
  await recordCalls(CALLS());
  assert.equal(reviewSettings(sb.env).enabled, false);
  assert.match((await review([])).out, /review judge \(experimental feature\): off/);
  let opened = 0;
  const r = await review(["run"], { openModel: async () => (opened++, { ok: false }), confirm: async () => "yes" });
  assert.equal(r.code, 1);
  assert.match(r.err, /the review judge is off; nothing was sent/);
  assert.equal(opened, 0);
});

test("enable needs the person's second factor (the kit's), and is audited; disable is audited", async () => {
  // No factor enrolled: refused, nothing written.
  fs.rmSync(path.join(sb.home, ".enclawed", "claude-code", "auth"), { recursive: true, force: true });
  await assert.rejects(review(["enable"], { verify: (o) => verifyUser({ ...o, say: () => {} }) }), (e) => e instanceof AuthError);
  assert.equal(reviewSettings(sb.env).enabled, false);
  assert.ok(records.some((x) => x.type === "claude-code.auth.attempt" && x.payload.outcome === "refused" && x.payload.requested === "review-enable"));
  assert.ok(!records.some((x) => x.type === "claude-code.review.enabled"));
  // A device-bound passkey enrolled: the kit verifies it, and the setting is on.
  const pk = new PasskeyDouble();
  const out = sinkOf();
  assert.equal(await authCommand(["enroll", "--passkey"], { out, err: sinkOf(), env: sb.env, audit, interactive: true, passkey: pk.ceremony }), 0);
  const r = await review(["enable"], { verify: (o) => verifyUser({ ...o, interactive: true, passkey: pk.ceremony, say: () => {} }) });
  assert.equal(r.code, 0);
  assert.equal(reviewSettings(sb.env).enabled, true);
  assert.ok(records.some((x) => x.type === "claude-code.auth.attempt" && x.payload.outcome === "verified" && x.payload.purpose === "policy-change"));
  assert.ok(records.some((x) => x.type === "claude-code.review.enabled"));
  assert.equal((await review(["disable"])).code, 0);
  assert.equal(reviewSettings(sb.env).enabled, false);
  assert.ok(records.some((x) => x.type === "claude-code.review.disabled"));
  // A setting file that is not the well-formed "on" record is off.
  fs.writeFileSync(path.join(reviewDir(sb.env), "settings.json"), JSON.stringify({ enabled: true }));
  assert.equal(reviewSettings(sb.env).enabled, false);
});

test("a run: cap printed and confirmed first; only normalized call text sent, never a credential, file content, home or user name; only disagreements kept", async () => {
  await recordCalls(CALLS());
  enableDirectly();
  const m = standInModel(ANSWERS);
  // Not confirmed: nothing sent, nothing opened.
  let opened = 0;
  const no = await review(["run"], { openModel: async () => (opened++, m.open()), confirm: async () => "no" });
  assert.equal(no.code, 1);
  assert.match(no.out, /sends at most 5 call\(s\) to the model .*at most 40 per run.*one every 2 s.*skipped: 1/s);
  assert.match(no.out, /not confirmed; nothing was sent/);
  assert.equal(opened, 0);
  assert.equal(m.prompts.length, 0);
  // Confirmed.
  const r = await review(["run"], { openModel: m.open, confirm: async () => "yes" });
  assert.equal(r.code, 0, r.err);
  assert.equal(m.prompts.length, 5);
  const sent = JSON.stringify(m.prompts);
  for (const secret of [TOKEN, HF_TOKEN, "FILE-CONTENT-NEVER-SENT", sb.home, sb.project, sb.dir]) {
    assert.ok(!sent.includes(secret), `the model was sent ${secret}`);
  }
  assert.ok(!new RegExp(`(?<![A-Za-z0-9_])${USER}(?![A-Za-z0-9_])`).test(sent), "the model was sent the user name");
  const data = m.prompts.map((p) => JSON.parse(p.user));
  assert.deepEqual(
    data.map((d) => [d.tool, d.call, d.gateDecision, d.personReachable]),
    [
      ["Bash", "rm -rf <PROJ>/build", "ask", true],
      ["Read", "~/notes-<USER>.txt", "allow", true],
      ["Write", "<PROJ>/a.txt\n<content: 23 bytes, not shown>", "allow", true],
      ["Bash", 'curl -H "Authorization: token [REDACTED]" https://api.github.com/user', "allow", true],
      ["WebFetch", "https://example.com/x", "deny", false],
    ],
  );
  assert.match(r.out, /sent 5: the judge agrees with the gate on 2, disagrees on 2, no verdict on 1/);
  assert.match(r.out, /disagreements to label: 2/);
  const run = records.find((x) => x.type === "claude-code.review.run");
  assert.deepEqual(run.payload, { model: "stand-in", sent: 5, agree: 2, disagree: 2, noVerdict: 1, skipped: 0, stoppedOnErrors: false } /* skipped (and recorded) by the unconfirmed run */);
  const skipped = fs.readFileSync(path.join(reviewDir(sb.env), "judged.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((j) => j.status === "skipped");
  // The audit log already removed the Hugging Face token from the recorded call (enclawed 2.0.0);
  // the review still refuses that call, naming the removed secret, and never sends it.
  assert.deepEqual(skipped.map((j) => [j.code, j.findings]), [["secret-in-call", ["secret-removed-from-record"]]]);
  assert.ok(!JSON.stringify(records).includes(HF_TOKEN) && !fs.readFileSync(path.join(reviewDir(sb.env), "judged.jsonl"), "utf8").includes(HF_TOKEN));
  // Resumable: a second run sends nothing; a new decided call is the only one sent.
  const again = await review(["run"], { openModel: m.open, confirm: async () => "yes" });
  assert.match(again.out, /nothing to review/);
  assert.equal(m.prompts.length, 5);
  await recordCalls([{ tool: "Bash", kind: "shell", decision: "allow", codes: ["read-only-command"], input: { command: "git status" } }]);
  await review(["run"], { openModel: m.open, confirm: async () => "yes" });
  assert.equal(m.prompts.length, 6);
  assert.equal(JSON.parse(m.prompts[5].user).call, "git status");
});

test("label: only disagreements are shown; labels are kept and audited; export writes CSV with formulas neutralized", async () => {
  await recordCalls(CALLS());
  enableDirectly();
  const m = standInModel(ANSWERS);
  await review(["run"], { openModel: m.open, confirm: async () => "yes" });
  assert.equal((await review(["label"], { interactive: false })).code, 1);
  const shown = [];
  const answers = ["j", "a"];
  const r = await review(["label"], { choose: async () => answers.shift() });
  assert.equal(r.code, 0);
  shown.push(r.out);
  assert.match(r.out, /labeled 2/);
  assert.match(r.out, /Read .*\n {2}gate: {2}allow \[read\]\n {2}judge: harmful \(a correct gate would ask or deny\)/);
  assert.match(r.out, /WebFetch \(bypassPermissions\)/);
  assert.doesNotMatch(r.out, /rm -rf/); // an agreement is never shown
  assert.deepEqual(records.filter((x) => x.type === "claude-code.review.labeled").map((x) => x.payload.label), ["judge-right", "agree-with-gate"]);
  assert.match((await review(["label"])).out, /no disagreements to label/);
  const file = path.join(sb.dir, "refine.csv");
  assert.equal((await review(["export", "--out", file])).code, 0);
  const csv = fs.readFileSync(file, "utf8").trim().split("\n");
  assert.equal(csv[0], CSV_COLUMNS.join(","));
  assert.equal(csv.length, 3);
  assert.match(csv[1], /^"[0-9a-f]{64}","Read","default","allow","read","harmful","ask deny","judge-right","~\/notes-<USER>.txt"/);
  assert.match(csv[2], /"agree-with-gate"/);
  assert.match(csv[2], /"'=HYPERLINK\(""x""\) a plain fetch"/);
  assert.equal(csvField("@SUM(1)"), `"'@SUM(1)"`);
  assert.ok(records.some((x) => x.type === "claude-code.review.exported" && x.payload.rows === 2));
});

test("bounded: at most the per-run cap is sent, paced by the internal interval; a failing model stops the run and it resumes later", async () => {
  await recordCalls(Array.from({ length: REVIEW_MAX_CALLS_PER_RUN + 5 }, (_, i) => ({ tool: "Bash", kind: "shell", decision: "allow", codes: ["read-only-command"], input: { command: `echo ${i}` } })));
  enableDirectly();
  const m = standInModel(() => verdict("harmless", true));
  const slept = [];
  const r = await review(["run"], { openModel: m.open, confirm: async () => "yes", sleep: async (ms) => slept.push(ms) });
  assert.equal(r.code, 0);
  assert.equal(m.prompts.length, REVIEW_MAX_CALLS_PER_RUN);
  assert.match(r.out, /sends at most 40 call\(s\) to the model \(45 not yet reviewed/);
  assert.equal(slept.length, REVIEW_MAX_CALLS_PER_RUN - 1);
  assert.ok(slept.every((ms) => ms > 0 && ms <= REVIEW_MIN_INTERVAL_MS));
  let n = 0;
  const failing = { open: async () => ({ ok: true, send: async () => (n++, Promise.reject(new Error("down"))), close: async () => {} }) };
  const f = await review(["run"], { openModel: failing.open, confirm: async () => "yes" });
  assert.match(f.out, /stopped: the model failed repeatedly/);
  assert.equal(n, 3);
  const later = await review(["run"], { openModel: m.open, confirm: async () => "yes" });
  // The calls the failing model never answered are not judged: the next run sends them.
  assert.match(later.out, /sent 5/);
});

test("no model access (no device, or only a Claude subscription login): nothing is sent, and the device is released", async () => {
  await recordCalls(CALLS());
  enableDirectly();
  const r = await review(["run"], { openModel: async () => ({ ok: false, reason: "no Enclaweder is held" }), confirm: async () => "yes" });
  assert.equal(r.code, 1);
  assert.match(r.err, /cannot reach a model \(no Enclaweder is held\); nothing was sent/);
  assert.deepEqual(records.find((x) => x.type === "claude-code.review.run").payload, { sent: 0, unavailable: "no Enclaweder is held" });
  // The production opener: software-only (no device held) is unavailable before any login is touched.
  let released = 0;
  let touched = 0;
  const base = { fw: {}, hasApiKey: async () => true, openLogin: async () => (touched++, { ok: false }), sessionDevice: async () => (touched++, null) };
  const soft = await openRelayedModel({ env: sb.env, deps: { ...base, hold: async () => ({ mode: "software-only", release: () => released++ }) } });
  assert.equal(soft.ok, false);
  assert.match(soft.reason, /no Enclaweder is held/);
  assert.equal(touched, 0);
  // Held but not attested: unavailable, released.
  const held = await openRelayedModel({ env: sb.env, deps: { ...base, hold: async () => ({ mode: "held", release: () => released++ }) } });
  assert.match(held.reason, /could not be attested/);
  assert.equal(released, 2);
  // Only a Claude subscription login (Claude Code's own; no API key sealed): said so before anything is held or activated, nothing sent.
  let posted = 0;
  let activated = 0;
  let holds = 0;
  const noKey = await openRelayedModel({
    env: sb.env,
    deps: { fw: {}, hold: async () => (holds++, { mode: "held", release: () => released++ }), sessionDevice: async () => ({}), precheck: () => ({ ok: true }), activate: async () => activated++, openLogin: async () => ({ ok: true, action: "own-login" }), closeLogin: async () => {}, post: async () => (posted++, { status: 200, body: "{}" }) },
  });
  assert.equal(noKey.ok, false);
  assert.match(noKey.reason, /runs only with an Anthropic API key sealed under the Enclaweder \(ecwctl login api-key\); a Claude subscription login stays with Claude Code, and Enclawed Code does not use it/);
  assert.deepEqual([posted, activated, holds], [0, 0, 0]);
  // A sealed API key that turns out not to open into a relay (the session uses Claude Code's own login): unavailable, no request.
  const pass = await openRelayedModel({
    env: sb.env,
    deps: { fw: {}, hasApiKey: async () => true, hold: async () => ({ mode: "held", release: () => released++ }), sessionDevice: async () => ({}), precheck: () => ({ ok: true }), activate: async () => {}, openLogin: async () => ({ ok: true, action: "own-login" }), closeLogin: async () => {}, post: async () => (posted++, { status: 200, body: "{}" }) },
  });
  assert.equal(pass.ok, false);
  assert.match(pass.reason, /runs only with an Anthropic API key/);
  assert.equal(posted, 0);
  assert.equal(released, 3);
  // Relayed: requests go to the relay's socket with its CA, the placeholder credential, the Messages body; close releases.
  const seen = [];
  const relayed = await openRelayedModel({
    env: sb.env,
    deps: {
      fw: {},
      hasApiKey: async () => true,
      hold: async () => ({ mode: "held", release: () => released++ }),
      sessionDevice: async () => ({}),
      precheck: () => ({ ok: true }),
      activate: async () => {},
      openLogin: async () => ({ ok: true, action: "relayed", relay: { socketPath: "/x/a.sock", caCertPem: "CA" } }),
      closeLogin: async () => {},
      post: async (o) => (seen.push(o), { status: 200, body: JSON.stringify({ content: [{ type: "text", text: verdict("harmless", true) }] }) }),
    },
  });
  assert.equal(relayed.ok, true);
  assert.equal(await relayed.send({ system: "S", user: "U" }, { maxTokens: 300 }), verdict("harmless", true));
  assert.deepEqual(seen[0], { socketPath: "/x/a.sock", caCertPem: "CA", body: { model: "claude-sonnet-4-6", max_tokens: 300, temperature: 0, system: "S", messages: [{ role: "user", content: "U" }] } });
  await relayed.close();
  assert.equal(released, 4);
  assert.deepEqual(messagesBody({ system: "s", user: "u" }, { maxTokens: 5 }).messages, [{ role: "user", content: "u" }]);
  assert.throws(() => messagesText(401, "{}"), /HTTP 401/);
  assert.throws(() => messagesText(200, JSON.stringify({ content: [] })), /not one text block/);
});

test("the review judge cannot influence a decision: outside the hook's import graph, never loaded by the gate, decisions unchanged by a run", async () => {
  assert.deepEqual(reviewInfluenceProblems(), []);
  const hook = importGraph("bin/ecwcode-hook.mjs");
  assert.ok(hook.has("src/gate.mjs") && hook.has("src/hook.mjs"));
  assert.ok(!hook.has("src/review.mjs") && !hook.has("src/review-model.mjs") && !hook.has("src/admin.mjs"));
  // What the decision path actually loads, recorded by a module hook in a child process.
  const probe = `
    import { registerHooks } from "node:module";
    const loaded = new Set();
    registerHooks({ load(url, ctx, next) { loaded.add(url); return next(url, ctx); } });
    const { decidePreToolUse } = await import(${JSON.stringify(new URL("../src/gate.mjs", import.meta.url).href)});
    const { framework } = await import(${JSON.stringify(new URL("../src/kit.mjs", import.meta.url).href)});
    const policy = framework.defaultOpenPolicy();
    for (const [tool, input] of [["Read", { file_path: "/tmp/x" }], ["Bash", { command: "rm -rf /tmp/y" }]]) {
      await decidePreToolUse({ hook_event_name: "PreToolUse", session_id: "p", tool_use_id: "toolu_p", tool_name: tool, tool_input: input, cwd: "/tmp", permission_mode: "default" }, { fw: framework, policy, hardware: async () => ({ allowed: true }), projectDir: "/tmp", home: "/tmp", protected: { paths: [], prefixes: [] }, secretPaths: [] }).catch(() => {});
    }
    process.stdout.write(JSON.stringify([...loaded].filter((u) => u.startsWith("file:"))));
  `;
  const c = spawnSync(process.execPath, ["--input-type=module", "-e", probe], { encoding: "utf8", env: { ...sb.env, ENCLAWEDER_DEVICE: "deny" } });
  assert.equal(c.status, 0, c.stderr);
  const loaded = JSON.parse(c.stdout);
  assert.ok(loaded.some((u) => u.endsWith("/src/gate.mjs")));
  assert.deepEqual(loaded.filter((u) => /\/src\/(?:review|review-model|admin)\.mjs$/.test(u)), []);
  // Decisions before and after a run with a model that disagrees with everything are the same.
  const decide = async () => {
    const policy = framework.defaultOpenPolicy();
    const out = [];
    for (const [tool, input] of [["Read", { file_path: path.join(sb.project, "a.txt") }], ["Bash", { command: `rm -rf ${sb.project}/build` }], ["WebFetch", { url: "https://example.com/" }]]) {
      const d = await decidePreToolUse(
        { hook_event_name: "PreToolUse", session_id: "r", tool_use_id: `toolu_r_${tool}`, tool_name: tool, tool_input: input, cwd: sb.project, permission_mode: "default" },
        { fw: framework, policy, hardware: async () => ({ allowed: true }), historyStore: new framework.HistoryStore({ dir: path.join(sb.dir, "hist"), limits: policy.history }), projectDir: sb.project, home: sb.home, protected: { paths: [], prefixes: [] }, secretPaths: [], mcp: mcpSessionOf({ servers: {} }) },
      );
      out.push([d.decision, d.codes]);
    }
    return out;
  };
  const beforeRun = await decide();
  await recordCalls(CALLS());
  enableDirectly();
  const contrary = standInModel((d) => (d.gateDecision === "allow" ? verdict("harmful", false) : verdict("harmless", false)));
  await review(["run"], { openModel: contrary.open, confirm: async () => "yes" });
  assert.ok(contrary.prompts.length > 0);
  assert.deepEqual(await decide(), beforeRun);
});

test("the no-influence guard finds a decision-path import or an authority name (mutations)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "review-guard-"));
  try {
    for (const d of ["bin", "src"]) {
      fs.cpSync(path.join(ROOT, d), path.join(tmp, d), { recursive: true });
    }
    assert.deepEqual(reviewInfluenceProblems(tmp), []);
    const gate = path.join(tmp, "src", "gate.mjs");
    const orig = fs.readFileSync(gate, "utf8");
    fs.writeFileSync(gate, `import { reviewCommand } from "./review.mjs";\n${orig}`);
    const p = reviewInfluenceProblems(tmp);
    assert.ok(p.includes("the hook loads src/review.mjs before it decides"), p.join("; "));
    assert.ok(p.includes("src/gate.mjs imports src/review.mjs (only the CLI dispatcher may)"));
    fs.writeFileSync(gate, `${orig}\nexport const j = (k) => k.reviewOf;\n`);
    assert.deepEqual(reviewInfluenceProblems(tmp), ["src/gate.mjs names a kit review function"]);
    fs.writeFileSync(gate, orig);
    const rev = path.join(tmp, "src", "review.mjs");
    fs.appendFileSync(rev, '\nimport { userPolicyPath } from "./paths.mjs";\n');
    assert.match(reviewInfluenceProblems(tmp).join("; "), /review\.mjs names userPolicyPath/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("decidedCalls reads only decided tool calls (sealed segments too)", async () => {
  await recordCalls(CALLS());
  const calls = decidedCalls(sb.env);
  assert.equal(calls.length, 6);
  assert.deepEqual(calls.map((c) => c.decision), ["ask", "allow", "allow", "allow", "allow", "deny"]);
  assert.ok(calls.every((c) => /^[0-9a-f]{64}$/.test(c.id)));
  assert.equal(typeof kit.reviewOf, "function");
});
