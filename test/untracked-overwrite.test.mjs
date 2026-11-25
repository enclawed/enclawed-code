import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// Overwriting an existing file that git does not track (or ignores) waits for
// a person (gate.mjs untrackedOverwrite; benchmark scenario
// overwrite-untracked-config), while every legitimate case stays allowed:
// tracked files, new files, scratch paths, operator-declared overwritable
// paths, files this session created, and projects outside git.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { loadFramework } from "../src/framework.mjs";
import { decidePreToolUse, gitTracking } from "../src/gate.mjs";
import { createHookContext, disposeHookContext, runHook } from "../src/hook.mjs";
import { parseOptions, parsePolicyDoc } from "../src/policy.mjs";
import { pre, sandbox } from "./helpers.mjs";

let sb;
let fw;
let repo;
const clean = async () => ({ allowed: true });

function git(cwd, ...args) {
  const r = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main", "-c", "core.hooksPath=/dev/null", ...args], { cwd, encoding: "utf8", env: { PATH: process.env.PATH, HOME: cwd, GIT_CONFIG_NOSYSTEM: "1" } });
  assert.equal(r.status, 0, r.stderr);
}

function put(rel, content) {
  fs.mkdirSync(path.dirname(path.join(repo, rel)), { recursive: true });
  fs.writeFileSync(path.join(repo, rel), content);
}

before(async () => {
  sb = sandbox();
  ({ fw } = await loadFramework());
  repo = sb.project;
  put(".gitignore", ".env.local\nconfig/local.json\nbuild/\n");
  put("src/a.js", "export const a = 1;\n");
  put("src/dirty.js", "export const d = 1;\n");
  put("README.md", "# x\n");
  put("data/x.json", "{}\n");
  git(repo, "init", "-q");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "initial");
  // After the commit: changes git does not have.
  put("src/dirty.js", "export const d = 2;\n");
  put("config/local.json", '{ "token": "LOCAL-CANARY" }\n');
  put(".env.local", "TOKEN=local\n");
  put("notes.txt", "my notes, not committed\n");
  put("build/out.js", "generated\n");
  // A literal name that is also a pathspec pattern matching a tracked file.
  put("data/*.json", "untracked, named like a pattern\n");
});
after(() => sb.cleanup());

function deps(extra = {}, policy = fw.defaultOpenPolicy()) {
  return {
    fw,
    policy,
    hardware: clean,
    historyStore: new fw.HistoryStore({ dir: path.join(sb.dir, "hist"), limits: policy.history }),
    projectDir: repo,
    ...extra,
  };
}

const p = (rel) => path.join(repo, rel);
const write = (rel, extra) => pre(sb, "Write", { file_path: p(rel), content: "{}" }, extra);

test("gitTracking classifies tracked, untracked, ignored, outside-git and unknown files", () => {
  assert.equal(gitTracking(p("src/a.js")), "tracked");
  assert.equal(gitTracking(p("src/dirty.js")), "tracked");
  assert.equal(gitTracking(p("notes.txt")), "untracked");
  assert.equal(gitTracking(p("config/local.json")), "ignored");
  assert.equal(gitTracking(p("build/out.js")), "ignored");
  // The name is literal: "data/*.json" is not matched as a pattern against data/x.json.
  assert.equal(gitTracking(p("data/*.json")), "untracked");
  const outside = path.join(sb.dir, "no-git");
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(outside, "f.txt"), "x");
  assert.equal(gitTracking(path.join(outside, "f.txt")), "no-repo");
  assert.equal(gitTracking(p("notes.txt"), { run: () => ({ error: new Error("ENOENT"), status: null }) }), "unknown");
});

test("Write, Edit, MultiEdit and NotebookEdit over an existing untracked file ask, and the snapshot is kept", async () => {
  const d = deps();
  for (const [tool, ti] of [
    ["Write", { file_path: p("notes.txt"), content: "{}" }],
    ["Edit", { file_path: p("notes.txt"), old_string: "my", new_string: "" }],
    ["MultiEdit", { file_path: p("notes.txt"), edits: [] }],
    ["NotebookEdit", { notebook_path: p("notes.txt"), new_source: "x" }],
  ]) {
    const r = await decidePreToolUse(pre(sb, tool, ti), d);
    assert.equal(r.decision, "ask", `${tool}: ${r.reason}`);
    assert.deepEqual(r.codes, ["untracked-overwrite", "git-untracked"], tool);
    assert.equal(r.reversible, false);
    assert.match(r.reason, /existing file that git does not track/);
    assert.match(r.reason, /kept as snapshot [0-9a-f]{12}/);
    assert.match(r.reason, /history restore/);
  }
  const entries = await d.historyStore.list(p("notes.txt"));
  assert.ok(entries.some((e) => e.hash !== null), "the snapshot of the prior content is kept");
});

test("the benchmark's target: overwriting an ignored config/local.json asks (git-ignored), as does .env.local", async () => {
  for (const rel of ["config/local.json", ".env.local"]) {
    const r = await decidePreToolUse(write(rel), deps());
    assert.equal(r.decision, "ask", rel);
    assert.deepEqual(r.codes, ["untracked-overwrite", "git-ignored"], rel);
    assert.match(r.reason, /git ignores/);
  }
});

test("a name that is also a pathspec pattern is matched literally (asks)", async () => {
  const r = await decidePreToolUse(write("data/*.json"), deps());
  assert.equal(r.decision, "ask", r.reason);
  assert.ok(r.codes.includes("git-untracked"));
});

test("headless: with no person to ask (bypassPermissions) the untracked overwrite is denied", async () => {
  const r = await decidePreToolUse(write("config/local.json", { permission_mode: "bypassPermissions" }), deps());
  assert.equal(r.decision, "deny");
  assert.ok(r.codes.includes("untracked-overwrite"));
  assert.ok(r.codes.includes("no-person:bypassPermissions"));
});

test("acceptEdits does not make it a reversible edit: still ask", async () => {
  const r = await decidePreToolUse(write("config/local.json", { permission_mode: "acceptEdits" }), deps());
  assert.equal(r.decision, "ask");
});

test("unchanged: a tracked file (committed, or with uncommitted changes) is snapshotted and allowed", async () => {
  for (const rel of ["src/a.js", "src/dirty.js"]) {
    const r = await decidePreToolUse(write(rel), deps());
    assert.equal(r.decision, "allow", `${rel}: ${r.reason}`);
    assert.deepEqual(r.codes, ["history:snapshot"]);
  }
});

test("unchanged: a new file is allowed (prior state: absent)", async () => {
  const r = await decidePreToolUse(write("src/new-file.js"), deps());
  assert.equal(r.decision, "allow", r.reason);
  assert.match(r.reason, /new file/);
});

test("legitimate: a file this session created earlier may be overwritten; another session's file may not", async () => {
  const d = deps();
  const first = await decidePreToolUse(write("gen/report.txt"), d);
  assert.equal(first.decision, "allow");
  put("gen/report.txt", "written by the agent\n"); // the write ran
  const again = await decidePreToolUse(write("gen/report.txt"), d);
  assert.equal(again.decision, "allow", again.reason);
  // A subagent of the same session also counts as this session.
  const sub = await decidePreToolUse(write("gen/report.txt", { agent_id: "agent-7" }), d);
  assert.equal(sub.decision, "allow", sub.reason);
  const other = await decidePreToolUse(write("gen/report.txt", { session_id: "sess-other" }), d);
  assert.equal(other.decision, "ask", "a file created by another session is untracked data to this one");
});

test("legitimate: a subagent's creation counts for its session", async () => {
  const d = deps();
  assert.equal((await decidePreToolUse(write("gen/sub.txt", { agent_id: "agent-9" }), d)).decision, "allow");
  put("gen/sub.txt", "x\n");
  assert.equal((await decidePreToolUse(write("gen/sub.txt"), d)).decision, "allow");
});

test("legitimate: operator-declared overwritable paths (file or directory) are allowed, with the snapshot kept", async () => {
  const d = deps({ overwritablePaths: [p("build"), p(".env.local")] });
  for (const rel of ["build/out.js", ".env.local"]) {
    const r = await decidePreToolUse(write(rel), d);
    assert.equal(r.decision, "allow", `${rel}: ${r.reason}`);
    assert.deepEqual(r.codes, ["history:snapshot"]);
  }
  // Only what is declared: config/local.json still asks.
  assert.equal((await decidePreToolUse(write("config/local.json"), d)).decision, "ask");
  // An allowance never matches by case folding.
  assert.equal((await decidePreToolUse(write("config/local.json"), deps({ overwritablePaths: [p("CONFIG")] }))).decision, "ask");
});

test("legitimate: policy scratch paths stay allowed (no history needed there)", async () => {
  const policy = parsePolicyDoc(fw, { enclawed: { policy: { scratchPaths: [p("build")] } } }, "open");
  const r = await decidePreToolUse(write("build/out.js"), deps({}, policy));
  assert.equal(r.decision, "allow", r.reason);
  assert.deepEqual(r.codes, ["history:scratch"]);
});

test("outside any git work tree the snapshot rule applies as before (allowed)", async () => {
  const outside = path.join(sb.dir, "plain-project");
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(outside, "conf.json"), "{}");
  const d = { ...deps(), projectDir: outside };
  const r = await decidePreToolUse(pre(sb, "Write", { file_path: path.join(outside, "conf.json"), content: "x" }, { cwd: outside }), d);
  assert.equal(r.decision, "allow", r.reason);
});

test("fail closed: when git cannot classify the file, the overwrite asks", async () => {
  const r = await decidePreToolUse(write("src/a.js"), deps({ gitTracking: () => "unknown" }));
  assert.equal(r.decision, "ask");
  assert.deepEqual(r.codes, ["untracked-overwrite", "git-state-unknown"]);
});

test("every shell write to an untracked file asks, and is denied with no person (Bash write paths)", async () => {
  for (const command of [
    "echo {} > config/local.json",
    "echo x >> config/local.json",
    "printf '{}' | tee config/local.json",
    "cp README.md config/local.json",
    "mv README.md config/local.json",
    "sed -i s/LOCAL/X/ config/local.json",
    "truncate -s 0 config/local.json",
    "dd if=/dev/null of=config/local.json",
    "rm -f notes.txt",
    ": > notes.txt",
  ]) {
    const a = await decidePreToolUse(pre(sb, "Bash", { command }), deps());
    assert.equal(a.decision, "ask", command);
    const b = await decidePreToolUse(pre(sb, "Bash", { command }, { permission_mode: "bypassPermissions" }), deps());
    assert.equal(b.decision, "deny", command);
  }
});

test("through the hook: the policy's enclawedCode.overwritablePaths allows the declared file; the rest still asks", async () => {
  const policyFile = path.join(sb.dir, "ow-policy.json");
  fs.writeFileSync(policyFile, JSON.stringify({ enclawedCode: { overwritablePaths: [".env.local"] } }));
  const run = async (rel) => {
    const input = write(rel);
    const ctx = await createHookContext({
      env: sb.env,
      input,
      overrides: { fw, hardware: clean, auditPath: path.join(sb.dir, "ow.jsonl"), candidates: [{ kind: "launcher-env", path: policyFile }] },
    });
    const r = await runHook(input, ctx);
    await disposeHookContext(ctx);
    return r.stdout.hookSpecificOutput;
  };
  assert.equal((await run(".env.local")).permissionDecision, "allow");
  const o = await run("config/local.json");
  assert.equal(o.permissionDecision, "ask");
  assert.match(o.permissionDecisionReason, /git ignores/);
});

test("policy: overwritablePaths must be a list of real paths; '.', '/', '' and '..' are refused", () => {
  assert.deepEqual(parseOptions({ enclawedCode: { overwritablePaths: ["dist", ".env.local", "/srv/out"] } }).overwritablePaths, ["dist", ".env.local", "/srv/out"]);
  assert.deepEqual(parseOptions({}).overwritablePaths, []);
  for (const bad of [["."], ["/"], [""], ["../x"], ["a/../b"], "dist", [3]]) {
    assert.throws(() => parseOptions({ enclawedCode: { overwritablePaths: bad } }), /overwritablePaths/, JSON.stringify(bad));
  }
});
