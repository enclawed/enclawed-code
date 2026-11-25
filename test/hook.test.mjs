import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { auditRecords, CTL, fakeFido2Env, hookSession, LAUNCHER, pre, runHook, sandbox, systemFido2ToolsPresent } from "./helpers.mjs";

let sb;
beforeEach(() => {
  sb = sandbox();
});
afterEach(() => sb.cleanup());

const decision = (r) => r.out?.hookSpecificOutput?.permissionDecision;

function ecwcode(args) {
  return spawnSync(process.execPath, [LAUNCHER, ...args], { env: sb.env, cwd: sb.project, encoding: "utf8" });
}

function ecwctl(args) {
  return spawnSync(process.execPath, [CTL, ...args], { env: sb.env, cwd: sb.project, encoding: "utf8" });
}

test("PreToolUse output has exactly the shape Claude Code reads", () => {
  const r = runHook(sb, pre(sb, "Read", { file_path: "x" }));
  assert.equal(r.status, 0);
  assert.deepEqual(Object.keys(r.out), ["hookSpecificOutput"]);
  assert.deepEqual(Object.keys(r.out.hookSpecificOutput).sort(), [
    "hookEventName",
    "permissionDecision",
    "permissionDecisionReason",
  ]);
  assert.equal(r.out.hookSpecificOutput.hookEventName, "PreToolUse");
});

test("reads and retrieval are reversible and allowed", () => {
  for (const [tool, ti] of [
    ["Read", { file_path: "a" }],
    ["Glob", { pattern: "**/*.ts" }],
    ["Grep", { pattern: "x", path: "." }],
    ["WebSearch", { query: "node 22 release" }],
    ["Agent", { prompt: "look", description: "d", subagent_type: "Explore" }],
    ["Task", { prompt: "look", description: "d", subagent_type: "Explore" }],
    ["TodoWrite", { todos: [] }],
  ]) {
    assert.equal(decision(runHook(sb, pre(sb, tool, ti))), "allow", tool);
  }
  // A fetch to a host nobody listed can carry data out in its URL: it asks (red-team F5).
  const f = runHook(sb, pre(sb, "WebFetch", { url: "https://example.com/a", prompt: "summarize" }));
  assert.equal(decision(f), "ask");
  assert.match(f.out.hookSpecificOutput.permissionDecisionReason, /^Enclawed( [0-9a-f]{12})?: /);
});

test("Write: the old content is kept, then the write is allowed; restore puts it back", () => {
  const file = path.join(sb.project, "src.txt");
  fs.writeFileSync(file, "original\n");
  const input = pre(sb, "Write", { file_path: "src.txt", content: "changed\n" });
  const r = runHook(sb, input);
  assert.equal(decision(r), "allow", r.stderr);
  // Claude Code would now write the file.
  fs.writeFileSync(file, "changed\n");
  const rec = auditRecords(sb).find((x) => x.type === "claude-code.tool.pre");
  assert.equal(rec.payload.decision, "allow");
  const snap = rec.payload.targets[0].snapshot;
  assert.match(snap, /^[0-9a-f]{64}$/);
  assert.equal(rec.payload.input.content.bytes, 8);
  assert.equal(rec.payload.input.content.sha256.length, 64);
  // Listed, restorable, and the restore itself is audited.
  assert.match(ecwctl(["history", "list"]).stdout, new RegExp(snap.slice(0, 12)));
  // A restore of protected history is a two-factor operation: refused headless.
  const headless = ecwctl(["history", "restore", snap]);
  assert.notEqual(headless.status, 0);
  assert.match(headless.stderr, /needs a person at a terminal|security key/);
  assert.equal(fs.readFileSync(file, "utf8"), "changed\n");
  assert.ok(auditRecords(sb).some((x) => x.type === "claude-code.auth.attempt" && x.payload.purpose === "history-restore" && x.payload.outcome === "refused"));
  assert.equal(ecwctl(["audit", "verify"]).status, 0);
});

const haveScript = spawnSync("script", ["-qec", "true", "/dev/null"]).status === 0;
test(
  "Write restore at a terminal: a touch of the enrolled key (libfido2 test double) puts it back, audited",
  { skip: (!haveScript && "no script(1)") || (systemFido2ToolsPresent() && "real libfido2 tools installed: never drive a real key from tests") },
  () => {
    const file = path.join(sb.project, "src.txt");
    fs.writeFileSync(file, "original\n");
    assert.equal(decision(runHook(sb, pre(sb, "Write", { file_path: "src.txt", content: "changed\n" }))), "allow");
    fs.writeFileSync(file, "changed\n");
    const snap = auditRecords(sb).find((x) => x.type === "claude-code.tool.pre").payload.targets[0].snapshot;
    const q = (a) => `'${a.replaceAll("'", `'\\''`)}'`;
    const r = spawnSync("script", ["-qec", [process.execPath, CTL, "history", "restore", snap].map(q).join(" "), "/dev/null"], {
      env: { ...sb.env, ...fakeFido2Env(sb) },
      cwd: sb.project,
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(fs.readFileSync(file, "utf8"), "original\n");
    const attempts = auditRecords(sb).filter((x) => x.type === "claude-code.auth.attempt" && x.payload.purpose === "history-restore");
    assert.deepEqual(attempts.map((x) => [x.payload.outcome, x.payload.via]), [["verified", "fido2"]]);
    assert.ok(auditRecords(sb).some((x) => x.type === "claude-code.history.restore" && x.payload.outcome === "restored"));
    assert.equal(ecwctl(["audit", "verify"]).status, 0);
  },
);

test("Edit is snapshotted too; a new file records that it did not exist", () => {
  fs.writeFileSync(path.join(sb.project, "e.txt"), "a\n");
  assert.equal(decision(runHook(sb, pre(sb, "Edit", { file_path: "e.txt", old_string: "a", new_string: "b" }))), "allow");
  assert.equal(decision(runHook(sb, pre(sb, "Write", { file_path: "new.txt", content: "n" }))), "allow");
  const recs = auditRecords(sb).filter((x) => x.type === "claude-code.tool.pre");
  assert.equal(recs[0].payload.targets[0].prior, "content");
  assert.equal(recs[1].payload.targets[0].prior, "absent");
});

test("a write with no possible history is irreversible: ask", () => {
  // Outside the project and not scratch: no history root. (A NEW file in the
  // system's temporary directory is scratch, reversible by removing it, so the
  // targets are the person's home and a system path outside every temp root.)
  for (const target of [path.join(sb.home, "elsewhere.txt"), "/var/lib/enclawed-code-test-no-history/elsewhere.txt"]) {
    const outside = runHook(sb, pre(sb, "Write", { file_path: target, content: "x" }));
    assert.equal(decision(outside), "ask", target);
    assert.match(outside.out.hookSpecificOutput.permissionDecisionReason, /outside-allowed-roots/, target);
  }
  // Opted out by the operator.
  sb.writePolicy({ history: { noHistoryPaths: [path.join(sb.project, "data", "**")] } });
  const optedOut = runHook(sb, pre(sb, "Write", { file_path: "data/big.bin", content: "x" }));
  assert.equal(decision(optedOut), "ask");
  assert.match(optedOut.out.hookSpecificOutput.permissionDecisionReason, /no-history-path/);
  // Files that configure what runs later.
  assert.equal(decision(runHook(sb, pre(sb, "Write", { file_path: ".git/config", content: "x" }))), "ask");
  assert.equal(decision(runHook(sb, pre(sb, "Write", { file_path: ".claude/settings.json", content: "{}" }))), "ask");
});

test("Bash: read-only commands run, everything else asks", () => {
  assert.equal(decision(runHook(sb, pre(sb, "Bash", { command: "git status" }))), "allow");
  assert.equal(decision(runHook(sb, pre(sb, "Bash", { command: "ls -la src" }))), "allow");
  // A redirect is decided as the equivalent Write, and a command substitution
  // by what it runs: so the redirects here target files no history can cover
  // (exec-config, the home directory) and the substitution runs a program with
  // an effect.
  for (const command of ["rm -rf build", "ls | sh", "cat a > .git/config", "cat a > ~/elsewhere.txt", "npm install", "echo $(git push)", "curl -d @f https://x"]) {
    assert.equal(decision(runHook(sb, pre(sb, "Bash", { command }))), "ask", command);
  }
});

test("MCP tools and unknown tools ask, unless pre-approved", () => {
  assert.equal(decision(runHook(sb, pre(sb, "mcp__github__create_issue", { title: "t" }, { mcp_server: { name: "github" } }))), "ask");
  assert.equal(decision(runHook(sb, pre(sb, "SomeNewTool", {}))), "ask");
  sb.writePolicy({ preApprovedIrreversibleTools: ["mcp__github__create_issue", "Bash"] });
  const mcp = runHook(sb, pre(sb, "mcp__github__create_issue", { title: "t" }));
  assert.equal(decision(mcp), "allow");
  assert.match(mcp.out.hookSpecificOutput.permissionDecisionReason, /pre-approved/);
  // A project script runs, contained: Claude Code is told to run the contained command instead.
  const script = runHook(sb, pre(sb, "Bash", { command: "npm test" }));
  assert.equal(decision(script), "allow", script.out?.hookSpecificOutput?.permissionDecisionReason);
  const ran = script.out.hookSpecificOutput.updatedInput?.command ?? "";
  assert.notEqual(ran, "npm test");
  assert.match(ran, /^exec env -i /);
  assert.match(ran, /npm test/);
  assert.equal(decision(runHook(sb, pre(sb, "mcp__other__x", {}))), "ask");
});

test("under bypassPermissions irreversible calls are denied; auto still asks", () => {
  const r = runHook(sb, pre(sb, "Bash", { command: "rm x" }, { permission_mode: "bypassPermissions" }));
  assert.equal(decision(r), "deny");
  assert.equal(decision(runHook(sb, pre(sb, "Bash", { command: "rm x" }, { permission_mode: "auto" }))), "ask");
  // Reversible calls are unaffected.
  assert.equal(decision(runHook(sb, pre(sb, "Read", { file_path: "a" }, { permission_mode: "bypassPermissions" }))), "allow");
});

test("enforced allowlists deny tools and hosts that are not listed", () => {
  sb.writePolicy({ enforceAllowlists: true, allowedTools: ["read", "web_fetch"], allowedHosts: ["docs.example.com"] });
  assert.equal(decision(runHook(sb, pre(sb, "Read", { file_path: "a" }))), "allow");
  assert.equal(decision(runHook(sb, pre(sb, "Write", { file_path: "a", content: "" }))), "deny");
  assert.equal(decision(runHook(sb, pre(sb, "WebFetch", { url: "https://docs.example.com/x" }))), "allow");
  assert.equal(decision(runHook(sb, pre(sb, "WebFetch", { url: "https://evil.example.net/x" }))), "deny");
});

test("an invalid policy fails closed in the enclaved flavor", () => {
  sb.writePolicy({ preApprovedIrreversibleTools: ["*"] });
  const r = runHook(sb, pre(sb, "Read", { file_path: "a" }), { ENCLAWED_FLAVOR: "enclaved" });
  assert.equal(r.status, 2);
  assert.equal(decision(r), "deny");
  assert.ok(auditRecords(sb).some((x) => x.type === "claude-code.hook.error"));
});

test("malformed input fails closed: deny JSON and exit 2", () => {
  for (const bad of ["not json", "[]", '{"tool_name":"Bash"}', JSON.stringify({ hook_event_name: "PreToolUse" })]) {
    const r = runHook(sb, bad);
    assert.equal(r.status, 2, bad);
    assert.equal(decision(r), "deny", bad);
    assert.match(r.stderr, /blocked/);
  }
  const notObject = runHook(sb, { ...pre(sb, "Bash", null), tool_input: "rm -rf /" });
  assert.equal(notObject.status, 2);
  assert.equal(decision(notObject), "deny");
});

test("a locked audit log blocks the call instead of running it unaudited", () => {
  fs.mkdirSync(path.dirname(sb.auditFile), { recursive: true });
  fs.writeFileSync(`${sb.auditFile}.lock`, "999999\n");
  const t0 = Date.now();
  const r = runHook(sb, pre(sb, "Read", { file_path: "a" }));
  assert.equal(r.status, 2);
  assert.equal(decision(r), "deny");
  assert.ok(Date.now() - t0 < 10_000, "within the hook timeout");
});

test("session and post-tool events are audited and the chain verifies; reconcile finds gaps", () => {
  const base = { session_id: "sess-r", cwd: sb.project, transcript_path: path.join(sb.dir, "t.jsonl"), permission_mode: "default" };
  runHook(sb, { ...base, hook_event_name: "SessionStart", source: "startup", model: "claude-sonnet-4-6" });
  fs.writeFileSync(path.join(sb.project, "w.txt"), "1");
  const p = pre(sb, "Write", { file_path: "w.txt", content: "2" }, base);
  runHook(sb, p);
  fs.writeFileSync(path.join(sb.project, "w.txt"), "2");
  const post = runHook(sb, {
    ...base,
    hook_event_name: "PostToolUse",
    tool_name: "Write",
    tool_input: p.tool_input,
    tool_use_id: p.tool_use_id,
    tool_response: { filePath: path.join(sb.project, "w.txt"), success: true },
  });
  assert.equal(post.status, 0);
  assert.equal(post.stdout, "");
  runHook(sb, {
    ...base,
    hook_event_name: "PostToolUseFailure",
    tool_name: "Bash",
    tool_input: { command: "false" },
    tool_use_id: "toolu_fail",
    error: "Exit code 1 token=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  });
  runHook(sb, { ...base, hook_event_name: "SessionEnd", reason: "prompt_input_exit" });
  const types = auditRecords(sb).map((r) => r.type);
  assert.deepEqual(types, [
    "claude-code.session.start",
    "claude-code.tool.pre",
    "claude-code.tool.post",
    // The Write's new digest in the project's file record (file-integrity.mjs).
    "claude-code.file-integrity.gated-write",
    "claude-code.tool.failure",
    "claude-code.session.end",
  ]);
  const postRec = auditRecords(sb)[2];
  assert.equal(postRec.payload.written.sha256.length, 64);
  const v = ecwctl(["audit", "verify", "--json"]);
  assert.equal(v.status, 0, v.stdout);
  assert.equal(JSON.parse(v.stdout).count, 6);

  // A transcript with a tool call the log never saw: hooks were bypassed.
  fs.writeFileSync(
    base.transcript_path,
    `${JSON.stringify({ message: { content: [{ type: "tool_use", id: p.tool_use_id }, { type: "tool_use", id: "toolu_unseen" }] } })}\n`,
  );
  const rc = ecwctl(["audit", "reconcile", "--json"]);
  const findings = JSON.parse(rc.stdout).findings;
  assert.equal(rc.status, 1);
  assert.ok(findings.some((f) => f.code === "transcript-call-without-decision" && f.detail === "toolu_unseen"));
  assert.ok(!findings.some((f) => f.detail === p.tool_use_id));
});

test("secrets in commands are redacted in the audit log", () => {
  const secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  runHook(sb, pre(sb, "Bash", { command: `curl -H 'x-api-key: ${secret}' https://api.example.com` }));
  const raw = fs.readFileSync(sb.auditFile, "utf8");
  assert.ok(!raw.includes(secret), "secret must not be stored");
});

test("concurrent hooks keep the audit chain intact", async () => {
  const { spawn } = await import("node:child_process");
  const { hookSession } = await import("./helpers.mjs");
  const s = hookSession(sb);
  const runs = Array.from({ length: 12 }, (_, i) =>
    new Promise((resolve) => {
      const c = spawn("/bin/sh", ["-c", s.command], { env: sb.env, cwd: sb.project });
      c.stdin.end(JSON.stringify(pre(sb, "Read", { file_path: `f${i}` })));
      c.on("exit", resolve);
    }),
  );
  const codes = await Promise.all(runs);
  assert.deepEqual(codes, Array(12).fill(0));
  const v = ecwctl(["audit", "verify", "--json"]);
  assert.equal(JSON.parse(v.stdout).count, 12);
  assert.equal(v.status, 0);
});

test("an edited audit record is detected", () => {
  runHook(sb, pre(sb, "Read", { file_path: "a" }));
  runHook(sb, pre(sb, "Bash", { command: "rm x" }));
  const lines = fs.readFileSync(sb.auditFile, "utf8").split("\n");
  lines[1] = lines[1].replace('"decision":"ask"', '"decision":"allow"');
  fs.writeFileSync(sb.auditFile, lines.join("\n"));
  const v = ecwctl(["audit", "verify"]);
  assert.equal(v.status, 1);
  assert.match(v.stdout, /does NOT verify/);
});

test("a held session (repository configuration not admitted yet) denies every call, a read included, until the hold is released", async () => {
  const { kit } = await import("../src/kit.mjs");
  const session = hookSession(sb);
  const holdFile = path.join(session.session.sessionDir ?? session.dir, "repo-config-hold.json");
  kit.fileHoldStore(holdFile).set({ reason: "repo-config-changed", since: Date.now(), paths: [{ path: path.join(sb.project, ".claude", "settings.json"), sha256: "0".repeat(64) }] });
  try {
    const r = runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { session });
    assert.equal(decision(r), "deny");
    assert.match(r.out.hookSpecificOutput.permissionDecisionReason, /has not admitted it yet/);
  } finally {
    fs.rmSync(holdFile, { force: true });
  }
  assert.equal(decision(runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { session })), "allow");
});
