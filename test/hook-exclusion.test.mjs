import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// Hooks with no grant that the person chose, at launch, to start without
// (src/hook-exclusion.mjs): what each kind of source turns into for the session.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { applyToSettings, excludeHooks, groupBySource, questionText, withoutHooks } from "../src/hook-exclusion.mjs";
import { otherHooks } from "../src/session.mjs";
import { sandbox } from "./helpers.mjs";

let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());

test("a --settings hook is dropped from that --settings value only; the rest of it stays", () => {
  const mine = { type: "command", command: "echo mine" };
  const other = { type: "command", command: "echo other" };
  const doc = { model: "opus", hooks: { PreToolUse: [{ matcher: "Bash", hooks: [mine, other] }], Stop: [{ hooks: [mine] }] } };
  const hooks = otherHooks({ projectDir: sb.project, env: sb.env, extra: [doc] }).filter((h) => h.scope === "--settings" && h.event === "PreToolUse" && h.command === "echo mine");
  assert.equal(hooks.length, 1);
  const ex = excludeHooks({ args: ["-p", "x"], userSettings: [doc], pluginDirs: [] }, hooks, { cwd: sb.project, configDir: path.join(sb.home, ".claude") });
  assert.equal(ex.ok, true);
  assert.deepEqual(ex.plan.userSettings[0], { model: "opus", hooks: { PreToolUse: [{ matcher: "Bash", hooks: [other] }], Stop: [{ hooks: [mine] }] } });
  assert.deepEqual(doc.hooks.PreToolUse[0].hooks, [mine, other], "the caller's document is not changed");
  assert.deepEqual(withoutHooks({ hooks: { Stop: [{ hooks: [mine] }] } }, [{ event: "Stop", raw: mine }]), {});
});

test("a user skill's or subagent's frontmatter hook switches that skill off and denies that subagent; a --plugin-dir plugin is not passed", () => {
  const cfg = path.join(sb.home, ".claude");
  fs.mkdirSync(path.join(cfg, "skills", "deployer"), { recursive: true });
  fs.writeFileSync(path.join(cfg, "skills", "deployer", "SKILL.md"), "---\nname: deployer\nhooks:\n  PreToolUse:\n    - matcher: Bash\n---\nbody\n");
  fs.mkdirSync(path.join(cfg, "agents"), { recursive: true });
  fs.writeFileSync(path.join(cfg, "agents", "reviewer.md"), "---\nname: code-reviewer\nhooks:\n  Stop:\n    - x\n---\nbody\n");
  const pd = path.join(sb.dir, "my-plugin");
  fs.mkdirSync(path.join(pd, "hooks"), { recursive: true });
  fs.writeFileSync(path.join(pd, "hooks", "hooks.json"), JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: "command", command: "echo p" }] }] } }));
  try {
    const hooks = otherHooks({ projectDir: sb.project, env: sb.env, pluginDirs: [pd] }).filter((h) => h.scope !== "project");
    const ex = excludeHooks({ args: ["--plugin-dir", pd, "--model", "x", "--", "--plugin-dir", pd], userSettings: [], pluginDirs: [pd] }, hooks, { cwd: sb.project, configDir: cfg });
    assert.equal(ex.ok, true);
    assert.deepEqual(ex.plan.args, ["--model", "x", "--", "--plugin-dir", pd], "only the option is dropped, never a prompt after --");
    const settings = applyToSettings({ permissions: { deny: ["Bash(rm *)"] } }, ex.plan.hookExclusion);
    assert.deepEqual(settings.skillOverrides, { deployer: "off" });
    assert.deepEqual(settings.permissions.deny, ["Bash(rm *)", "Agent(code-reviewer)", "Task(code-reviewer)"]);
    assert.deepEqual(ex.record.sources.map((x) => x.kind).sort(), ["agent", "plugin", "skill"]);
    const q = questionText(groupBySource(hooks, { configDir: cfg }), "/etc/enclawed/enclawed-code-opt-outs.json");
    assert.match(q, /  skill deployer \(.*SKILL\.md\):\n    PreToolUse: \(frontmatter hook\)/);
    assert.match(q, /  subagent code-reviewer \(.*reviewer\.md\):\n    Stop: \(frontmatter hook\)/);
    assert.match(q, /\[y\/N\] $/);
  } finally {
    fs.rmSync(path.join(cfg, "skills"), { recursive: true, force: true });
    fs.rmSync(path.join(cfg, "agents"), { recursive: true, force: true });
  }
});
