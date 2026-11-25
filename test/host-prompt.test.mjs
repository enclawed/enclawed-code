import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// Managed mode (no launcher): an Enclawed "ask" goes to Claude Code's own
// permission prompt. Claude Code 2.1.326 re-checks a pending call when its
// permission context changes while the prompt is open (shift+tab into
// acceptEdits) and runs it with no answer when its own check now allows it.
// The kit (host-prompt guard; claude-prompt.mjs maps Claude Code's data)
// asks there only what Claude Code cannot approve by itself, or a write it
// can put back, and checks the PostToolUse. End to end: a fake claude plays
// the managed hooks and the re-check; the hook runs as a separate process in
// managed mode (test/fixtures/hook-entry.mjs, the suite's stand-in authority).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { PROMPT_ANSWERER_SPEC, claudePromptGuard, claudeSelfApproval } from "../src/claude-prompt.mjs";
import { kit } from "../src/kit.mjs";
import { managedTemplate } from "../src/managed.mjs";
import { FAKE_CLAUDE, ROOT, auditRecords, pre, sandbox } from "./helpers.mjs";

let sb;
let managedDir;
let hookCmd;
before(() => {
  sb = sandbox();
  const g = (...a) => assert.equal(spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main", "-c", "core.hooksPath=/dev/null", ...a], { cwd: sb.project, env: { PATH: process.env.PATH, HOME: sb.project, GIT_CONFIG_NOSYSTEM: "1" } }).status, 0);
  fs.writeFileSync(path.join(sb.project, "README.md"), "# x\n");
  g("init", "-q");
  g("add", "-A");
  g("commit", "-q", "-m", "initial");
  managedDir = path.join(sb.admin, "claude-code");
  fs.mkdirSync(managedDir);
  const authority = { managedSettingsDir: managedDir, managedHome: sb.home, optOutDirs: [sb.admin], managedPolicyPath: path.join(sb.admin, "managed-policy.json"), trustedUids: sb.authority.trustedUids, ignoreUserNamespace: true };
  const q = (s) => `'${String(s).replaceAll("'", `'\\''`)}'`;
  hookCmd = [process.execPath, path.join(ROOT, "test", "fixtures", "hook-entry.mjs"), JSON.stringify(authority), "--origin", "managed"].map(q).join(" ");
});
after(() => sb.cleanup());

/** Install the managed settings (the template with the suite's hook command), patched by `patch`. */
function installManaged(patch = (t) => t) {
  fs.writeFileSync(path.join(managedDir, "managed-settings.json"), JSON.stringify(patch(managedTemplate({ command: hookCmd }))));
}

let sessionN = 0;
/** Play `calls` through the fake claude in managed mode; returns its results, one per call. */
function play(calls) {
  const out = path.join(sb.dir, `fake-${++sessionN}.json`);
  const sid = `managed-${sessionN}`;
  const input = calls.map((c) => ({ ...c, input: { ...c.input, session_id: sid } }));
  const r = spawnSync(process.execPath, [FAKE_CLAUDE], {
    cwd: sb.project,
    env: { ...sb.env, FAKE_CLAUDE_MANAGED: path.join(managedDir, "managed-settings.json"), FAKE_CLAUDE_MANAGED_CALLS: JSON.stringify(input), FAKE_CLAUDE_OUT: out },
    encoding: "utf8",
    timeout: 120_000,
  });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(fs.readFileSync(out, "utf8")).results;
}

const NEW = "overwritten by the agent\n";
const writeNotes = (mode = "default") => pre(sb, "Write", { file_path: path.join(sb.project, "notes.txt"), content: NEW }, { permission_mode: mode });
const readme = () => pre(sb, "Read", { file_path: path.join(sb.project, "README.md") });
const freshNotes = () => fs.writeFileSync(path.join(sb.project, "notes.txt"), "my notes, not committed\n");
const notesNow = () => fs.readFileSync(path.join(sb.project, "notes.txt"), "utf8");

test("attack (e2e): an untracked file's overwrite asked in default mode, then Claude Code re-checks it after a switch to acceptEdits and runs it with no answer: put back from the snapshot, the write quarantined, approval-not-from-person audited, and the session held", { timeout: 200_000 }, () => {
  installManaged();
  freshNotes();
  const [w, next] = play([{ input: writeNotes(), prompt: "recheck:acceptEdits" }, { input: readme() }]);
  assert.equal(w.decision, "ask", JSON.stringify(w.pre));
  assert.equal(w.ranIn, "acceptEdits");
  assert.equal(notesNow(), "my notes, not committed\n", "the file is put back");
  assert.match(JSON.stringify(w.post), /ran without one/);
  assert.equal(next.decision, "deny", "held: every further call is refused");
  assert.match(next.pre.hookSpecificOutput.permissionDecisionReason, /this session is held/);
  const recs = auditRecords(sb);
  const v = recs.find((r) => r.type === "claude-code.tool.approval-not-from-person");
  assert.ok(v, "audited");
  assert.equal(v.payload.hostMode, "acceptEdits");
  assert.equal(fs.readFileSync(v.payload.quarantined[0].to, "utf8"), NEW, "what the call wrote is kept in quarantine");
});

test("attack (e2e): an irreversible call Claude Code's prompt can approve by itself (rm, a file command acceptEdits allows) is denied up front; nothing runs", { timeout: 200_000 }, () => {
  installManaged();
  fs.mkdirSync(path.join(sb.project, "build"), { recursive: true });
  fs.writeFileSync(path.join(sb.project, "build", "keep"), "x");
  const [r] = play([{ input: pre(sb, "Bash", { command: "rm -rf build" }), prompt: "recheck:acceptEdits" }]);
  assert.equal(r.decision, "deny", JSON.stringify(r.pre));
  assert.match(r.pre.hookSpecificOutput.permissionDecisionReason, /can approve this call by itself/);
  assert.equal(r.ranIn, null);
  assert.ok(fs.existsSync(path.join(sb.project, "build", "keep")));
});

test("FP (e2e): a person approves the overwrite in default mode; it runs in default mode and stands, and the session goes on", { timeout: 200_000 }, () => {
  installManaged();
  freshNotes();
  const [w, next] = play([{ input: writeNotes(), prompt: "person" }, { input: readme() }]);
  assert.equal(w.decision, "ask");
  assert.equal(w.ranIn, "default");
  assert.equal(notesNow(), NEW);
  assert.doesNotMatch(JSON.stringify(w.post ?? {}), /ran without one/);
  assert.equal(next.decision, "allow", JSON.stringify(next.pre));
});

test("FP (e2e): in an acceptEdits session, edits that need no ask run unchanged (no grant, nothing put back)", { timeout: 200_000 }, () => {
  installManaged();
  const f = path.join(sb.project, "src", "new.js");
  const [w, w2, next] = play([
    { input: pre(sb, "Write", { file_path: f, content: "export const n = 1;\n" }, { permission_mode: "acceptEdits" }) },
    { input: pre(sb, "Write", { file_path: f, content: "export const n = 2;\n" }, { permission_mode: "acceptEdits" }) },
    { input: readme() },
  ]);
  assert.equal(w.decision, "allow", JSON.stringify(w.pre));
  assert.equal(w2.decision, "allow", JSON.stringify(w2.pre));
  assert.equal(fs.readFileSync(f, "utf8"), "export const n = 2;\n");
  assert.equal(next.decision, "allow");
});

test("FP (e2e): a call Claude Code cannot approve by itself (git push) stays an ask; the person's answer holds whatever mode it then runs in", { timeout: 200_000 }, () => {
  installManaged();
  // A remote that is a local bare repository: pushing there is irreversible to the kit, harmless here.
  const bare = path.join(sb.dir, "remote.git");
  spawnSync("git", ["init", "-q", "--bare", bare]);
  // Answered by the person, then run after a switch to acceptEdits: no check fires, the session goes on.
  const [r, next] = play([{ input: pre(sb, "Bash", { command: `git push -q ${bare} HEAD` }), prompt: "recheck:acceptEdits" }, { input: readme() }]);
  assert.equal(r.decision, "ask", JSON.stringify(r.pre));
  assert.equal(r.ranIn, "acceptEdits");
  assert.doesNotMatch(JSON.stringify(r.post ?? {}), /ran without one/);
  assert.equal(next.decision, "allow", JSON.stringify(next.pre));
});

test("attack (e2e): managed settings without the hook lock (a PermissionRequest hook from another settings file could answer the prompt): every ask is denied", { timeout: 200_000 }, () => {
  installManaged((t) => ({ ...t, allowManagedHooksOnly: false }));
  freshNotes();
  const [w] = play([{ input: writeNotes(), prompt: "person" }]);
  assert.equal(w.decision, "deny", JSON.stringify(w.pre));
  assert.match(w.pre.hookSpecificOutput.permissionDecisionReason, /answered by something other than the person/);
  assert.equal(notesNow(), "my notes, not committed\n");
});

test("the managed template locks the prompt to the person (kit.hostPromptAnswerer); a managed PermissionRequest hook or plugin, or autoAllowBashIfSandboxed, unlocks it", () => {
  const doc = (d) => [{ file: "/m.json", doc: d }];
  const t = managedTemplate({ command: "/opt/x/ecwcode-hook --origin managed" });
  assert.equal(kit.hostPromptAnswerer(doc(t), PROMPT_ANSWERER_SPEC), null);
  assert.match(kit.hostPromptAnswerer(doc({ ...t, hooks: { ...t.hooks, PermissionRequest: [{ hooks: [{ type: "command", command: "yes" }] }] } }), PROMPT_ANSWERER_SPEC), /PermissionRequest/);
  assert.match(kit.hostPromptAnswerer(doc({ ...t, enabledPlugins: { "x@y": true } }), PROMPT_ANSWERER_SPEC), /plugins/);
  assert.match(kit.hostPromptAnswerer(doc({ ...t, sandbox: { ...t.sandbox, autoAllowBashIfSandboxed: true } }), PROMPT_ANSWERER_SPEC), /autoAllowBashIfSandboxed/);
});

test("Claude Code's data: allow rules outside the managed settings may name any tool; managed rules name theirs (an MCP server rule names its tools)", () => {
  assert.deepEqual(claudeSelfApproval([{ file: "/m", doc: {} }]).ruleTools, ["*"]);
  const locked = claudeSelfApproval([{ file: "/m", doc: { allowManagedPermissionRulesOnly: true, permissions: { allow: ["Bash(npm test:*)", "mcp__notes", "WebFetch(domain:example.com)"] } } }]);
  assert.deepEqual(locked.ruleTools.sort(), ["Bash", "WebFetch", "mcp__notes"]);
  assert.deepEqual(locked.ruleToolPrefixes, ["mcp__notes__"]);
  const g = claudePromptGuard({ stateRoot: "/s", sessionId: "a", docs: [], answerer: null });
  assert.notEqual(g.dir, claudePromptGuard({ stateRoot: "/s", sessionId: "b", docs: [], answerer: null }).dir, "one directory per Claude Code session");
});

test("attack (e2e): shift+tab twice (default -> acceptEdits -> plan) while the prompt is open: Claude Code approves the write on the way through acceptEdits and the PostToolUse reports plan; plan is not a person-held mode, so it is put back and the session held", { timeout: 200_000 }, () => {
  installManaged();
  freshNotes();
  const [w, next] = play([{ input: writeNotes(), prompt: "recheck:plan" }, { input: readme() }]);
  assert.equal(w.decision, "ask");
  assert.equal(w.ranIn, "plan");
  assert.equal(notesNow(), "my notes, not committed\n");
  assert.match(JSON.stringify(w.post), /ran without one/);
  assert.equal(next.decision, "deny");
});
