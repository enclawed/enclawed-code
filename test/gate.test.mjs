import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { setTestAuthority } from "../src/authority.mjs";
import { loadFramework } from "../src/framework.mjs";
import { MalformedHookInput, decidePreToolUse } from "../src/gate.mjs";
import { createHookContext, disposeHookContext, runHook } from "../src/hook.mjs";
import { pre, sandbox } from "./helpers.mjs";

let sb;
let fw;
before(async () => {
  sb = sandbox();
  ({ fw } = await loadFramework());
});
after(() => sb.cleanup());

const dirty = async () => ({ allowed: false, code: "hardware-dirty", reason: "hardware root DIRTY: device removed" });
const clean = async () => ({ allowed: true });

function deps(hardware, policy = fw.defaultOpenPolicy()) {
  return {
    fw,
    policy,
    hardware,
    historyStore: new fw.HistoryStore({ dir: path.join(sb.dir, "hist"), limits: policy.history }),
    projectDir: sb.project,
  };
}

test("a DIRTY hardware root denies every call, reads included", async () => {
  for (const [tool, ti] of [
    ["Read", { file_path: "a" }],
    ["Bash", { command: "ls" }],
    ["Write", { file_path: "a", content: "" }],
    ["mcp__x__y", {}],
  ]) {
    const d = await decidePreToolUse(pre(sb, tool, ti), deps(dirty));
    assert.equal(d.decision, "deny", tool);
    assert.deepEqual(d.codes, ["hardware-dirty"]);
    assert.match(d.reason, /DIRTY/);
  }
});

test("a missing required device denies", async () => {
  const missing = async () => ({
    allowed: false,
    code: "hardware-required-missing",
    reason: "ENCLAWEDER_ROOT=required but no Enclaweder is bound",
  });
  const d = await decidePreToolUse(pre(sb, "Read", { file_path: "a" }), deps(missing));
  assert.equal(d.decision, "deny");
});

test("the hardware check is consulted with the tool name before anything else", async () => {
  const seen = [];
  const spy = async (tool) => {
    seen.push(tool);
    return { allowed: true };
  };
  await decidePreToolUse(pre(sb, "Glob", { pattern: "*" }), deps(spy));
  assert.deepEqual(seen, ["Glob"]);
});

test("malformed input is rejected, not guessed", async () => {
  await assert.rejects(decidePreToolUse({ hook_event_name: "PreToolUse" }, deps(clean)), MalformedHookInput);
  await assert.rejects(decidePreToolUse(null, deps(clean)), MalformedHookInput);
  await assert.rejects(
    decidePreToolUse({ ...pre(sb, "Bash", {}), tool_input: [1] }, deps(clean)),
    MalformedHookInput,
  );
});

test("a hardware halt is audited as a denial through the hook", async () => {
  const auditPath = path.join(sb.dir, "gate-audit.jsonl");
  const input = pre(sb, "Read", { file_path: "a" });
  const ctx = await createHookContext({
    env: sb.env,
    input,
    overrides: { fw, hardware: dirty, auditPath, managedPolicyPath: null },
  });
  const r = await runHook(input, ctx);
  await disposeHookContext(ctx);
  assert.equal(r.exitCode, 0);
  assert.equal(r.stdout.hookSpecificOutput.permissionDecision, "deny");
  const rec = JSON.parse(fs.readFileSync(auditPath, "utf8").trim().split("\n").at(-1));
  assert.equal(rec.payload.decision, "deny");
  assert.deepEqual(rec.payload.codes, ["hardware-dirty"]);
  const v = await fw.verifyHistory(auditPath);
  assert.equal(v.ok, true);
});

test("a managed policy file is the base: the user's policy cannot widen it", async () => {
  const managed = path.join(sb.dir, "managed-policy.json");
  fs.writeFileSync(managed, JSON.stringify({ enclawed: { policy: { enforceAllowlists: true, allowedTools: ["read"] } } }), { mode: 0o644 });
  // The managed file must be root-owned: the suite's stand-in authority trusts its own uid.
  setTestAuthority(sb.authority);
  sb.writePolicy({ enforceAllowlists: false });
  const input = pre(sb, "Bash", { command: "ls" });
  const ctx = await createHookContext({
    env: sb.env,
    input,
    overrides: {
      fw,
      hardware: clean,
      auditPath: path.join(sb.dir, "m.jsonl"),
      candidates: [
        { kind: "managed", path: managed },
        { kind: "gateway", path: path.join(sb.home, ".enclawed", "enclawed.json") },
      ],
    },
  });
  setTestAuthority(null);
  const r = await runHook(input, ctx);
  await disposeHookContext(ctx);
  assert.equal(r.stdout.hookSpecificOutput.permissionDecision, "deny");
  assert.match(r.stdout.hookSpecificOutput.permissionDecisionReason, /allowedTools/);
});

test("Claude Code's session scratchpad counts as scratch (no history needed)", async () => {
  const scratch = path.join(sb.dir, "scratchpad");
  fs.mkdirSync(scratch);
  const input = pre(sb, "Write", { file_path: path.join(scratch, "notes.md"), content: "x" }, { scratchpad_dir: scratch });
  const ctx = await createHookContext({
    env: sb.env,
    input,
    overrides: { fw, hardware: clean, auditPath: path.join(sb.dir, "s.jsonl") },
  });
  const r = await runHook(input, ctx);
  await disposeHookContext(ctx);
  assert.equal(r.stdout.hookSpecificOutput.permissionDecision, "allow");
  assert.match(r.stdout.hookSpecificOutput.permissionDecisionReason, /scratch/);
});
