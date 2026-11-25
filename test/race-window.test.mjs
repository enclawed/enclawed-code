import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// The window between the decision and the run, end to end through the hook:
// a file the agent's call reads is changed by a process outside the agent
// after the call was checked, before (or after) it runs. A secret path that
// did not exist is created as a file or as a link to a real credential store;
// an existing clean file is swapped for such a link, or its content replaced
// by a secret. The kit's file-integrity rule never credits the change to the
// call, the call's output is withheld from the model (PostToolUse), and every
// later use of the file is decided by the file-integrity rule.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { auditRecords, hookSession, pre, runHook, sandbox } from "./helpers.mjs";

const CANARY = "CANARYrace7f3a9c";

const outsideChange = {
  // A missing secret path created by a process outside the agent.
  "a missing .env created as a plain file": { rel: ".env", existing: false, run: (sb) => spawnSync("/bin/sh", ["-c", `printf 'AWS_SECRET_ACCESS_KEY=%s\\n' ${CANARY} > .env`], { cwd: sb.project }) },
  "a missing .env created as a link to ~/.aws/credentials": { rel: ".env", existing: false, run: (sb) => spawnSync("ln", ["-s", path.join(sb.home, ".aws", "credentials"), ".env"], { cwd: sb.project }) },
  // The general case: an existing, clean, recorded file.
  "an existing clean notes.txt swapped for a link to ~/.aws/credentials": { rel: "notes.txt", existing: true, run: (sb) => spawnSync("/bin/sh", ["-c", `rm notes.txt && ln -s '${path.join(sb.home, ".aws", "credentials")}' notes.txt`], { cwd: sb.project }) },
  "an existing clean notes.txt's content replaced by a secret": { rel: "notes.txt", existing: true, run: (sb) => spawnSync("/bin/sh", ["-c", `printf 'deploy_token = %sab12\\n' ${CANARY} > notes.txt`], { cwd: sb.project }) },
};

for (const [name, c] of Object.entries(outsideChange)) {
  for (const timing of ["before the read runs", "after the read ran"]) {
    test(`race: ${name}, ${timing}: never credited to the agent, the output never reaches the model, later use blocked`, () => {
      const sb = sandbox();
      try {
        fs.mkdirSync(path.join(sb.home, ".aws"), { recursive: true });
        fs.writeFileSync(path.join(sb.home, ".aws", "credentials"), `[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = ${CANARY}wJalrXUtnFEMI\n`, { mode: 0o600 });
        if (c.existing) {
          fs.writeFileSync(path.join(sb.project, c.rel), "plain notes\n");
        }
        const s = hookSession(sb); // the launcher's record of the project, as it was
        const hook = (input) => runHook(sb, input, {}, { session: s }).out?.hookSpecificOutput ?? null;
        const call = pre(sb, "Bash", { command: `cat ${c.rel}` }, { tool_use_id: "toolu_race" });
        const d = hook(call);
        assert.equal(d?.permissionDecision, "allow", `checked clean: ${d?.permissionDecisionReason}`);
        if (timing === "before the read runs") {
          c.run(sb);
        }
        const ran = spawnSync("/bin/sh", ["-c", `cat ${c.rel}`], { cwd: sb.project, encoding: "utf8" });
        const post = hook({ ...call, hook_event_name: "PostToolUse", tool_response: { stdout: ran.stdout, stderr: ran.stderr, interrupted: false, isImage: false } });
        if (timing === "after the read ran") {
          c.run(sb);
        }
        // What the model reads from the call that ran: never the secret.
        const modelSees = JSON.stringify(post?.updatedToolOutput ?? { stdout: ran.stdout, stderr: ran.stderr });
        assert.ok(!modelSees.includes(CANARY), `the secret reached the model: ${modelSees}`);
        if (timing === "before the read runs") {
          assert.match(modelSees, /withheld by Enclawed/, "the output is withheld, not just cleaned");
          assert.match(post?.additionalContext ?? "", /file-changed-outside-agent/);
        }
        // Never laundered into the record as the agent's own change.
        const recs = auditRecords(sb);
        assert.ok(!recs.some((r) => r.type === "claude-code.file-integrity.agent-action" && r.payload.paths.includes(c.rel)), `${c.rel} was recorded as the agent's checked action`);
        // Every later use by the agent is blocked by the file-integrity rule.
        for (const command of [`cat ${c.rel}`, `grep -c . ${c.rel}`, `source ${c.rel}`]) {
          const n = hook(pre(sb, "Bash", { command }, { tool_use_id: `toolu_n${command.length}` }));
          assert.notEqual(n?.permissionDecision, "allow", command);
          assert.match(n?.permissionDecisionReason ?? "", /changed outside the agent/, `${command}: decided by file integrity`);
        }
        const r = hook(pre(sb, "Read", { file_path: path.join(sb.project, c.rel) }, { tool_use_id: "toolu_nr" }));
        assert.notEqual(r?.permissionDecision, "allow", "Read");
      } finally {
        sb.cleanup();
      }
    });
  }
}

test("race: the Read tool's file swapped for a link between the decision and the read: withheld", () => {
  const sb = sandbox();
  try {
    fs.mkdirSync(path.join(sb.home, ".aws"), { recursive: true });
    fs.writeFileSync(path.join(sb.home, ".aws", "credentials"), `[default]\naws_secret_access_key = ${CANARY}wJalrXUtnFEMI\n`, { mode: 0o600 });
    fs.writeFileSync(path.join(sb.project, "notes.txt"), "plain notes\n");
    const s = hookSession(sb);
    const hook = (input) => runHook(sb, input, {}, { session: s }).out?.hookSpecificOutput ?? null;
    const file = path.join(sb.project, "notes.txt");
    const call = pre(sb, "Read", { file_path: file }, { tool_use_id: "toolu_read" });
    assert.equal(hook(call)?.permissionDecision, "allow");
    fs.rmSync(file);
    fs.symlinkSync(path.join(sb.home, ".aws", "credentials"), file);
    const content = fs.readFileSync(file, "utf8");
    const post = hook({ ...call, hook_event_name: "PostToolUse", tool_response: { type: "text", file: { filePath: file, content } } });
    assert.ok(!JSON.stringify(post?.updatedToolOutput ?? content).includes(CANARY));
    assert.match(JSON.stringify(post?.updatedToolOutput ?? ""), /withheld by Enclawed/);
  } finally {
    sb.cleanup();
  }
});

test("FP: a clean read, and a read while an unrelated file changes, show their output unchanged", () => {
  const sb = sandbox();
  try {
    fs.writeFileSync(path.join(sb.project, "notes.txt"), "plain notes\n");
    fs.writeFileSync(path.join(sb.project, "other.txt"), "other\n");
    const s = hookSession(sb);
    const hook = (input) => runHook(sb, input, {}, { session: s }).out?.hookSpecificOutput ?? null;
    const call = pre(sb, "Bash", { command: "cat notes.txt" }, { tool_use_id: "toolu_fp" });
    assert.equal(hook(call)?.permissionDecision, "allow");
    fs.writeFileSync(path.join(sb.project, "other.txt"), "the person edits another file meanwhile\n");
    const post = hook({ ...call, hook_event_name: "PostToolUse", tool_response: { stdout: "plain notes\n", stderr: "", interrupted: false, isImage: false } });
    assert.equal(post?.updatedToolOutput, undefined, JSON.stringify(post));
    // The person's edit is still a change outside the agent, decided at its use.
    const n = hook(pre(sb, "Bash", { command: "cat other.txt" }, { tool_use_id: "toolu_fp2" }));
    assert.equal(n?.permissionDecision, "ask");
  } finally {
    sb.cleanup();
  }
});
