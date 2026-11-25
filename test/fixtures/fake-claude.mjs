#!/usr/bin/env node
// A stand-in for Claude Code in tests. It records how it was invoked, can
// play one hook event through the PreToolUse command from --settings the way
// Claude Code would (sh -c, JSON on stdin), and exits as told.
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
// Like Claude Code, a hook input carries the mode the session runs in: the
// launched --permission-mode (ecwcode's default is bypassPermissions) replaces a
// test input's plain "default".
const launchedMode = (() => {
  const pre = args.includes("--") ? args.slice(0, args.indexOf("--")) : args;
  const i = pre.lastIndexOf("--permission-mode");
  return i >= 0 ? pre[i + 1] : null;
})();
const asLaunched = (text) => {
  // FAKE_CLAUDE_KEEP_MODE: the input reports the mode the test gave (a session reporting another mode than launched).
  if (!launchedMode || !text || process.env.FAKE_CLAUDE_KEEP_MODE) {
    return text;
  }
  const o = JSON.parse(text);
  return o.permission_mode === "default" ? JSON.stringify({ ...o, permission_mode: launchedMode }) : text;
};
const HOOK_INPUT = asLaunched(process.env.FAKE_CLAUDE_HOOK_INPUT);
const HOOK_INPUT_2 = asLaunched(process.env.FAKE_CLAUDE_HOOK_INPUT_2);
if (args[0] === "--version") {
  process.stdout.write(`${process.env.FAKE_CLAUDE_VERSION ?? "2.1.326"} (Claude Code)\n`);
  process.exit(0);
}
if (args[0] === "--help") {
  process.stdout.write("Usage: claude\n\nCommands:\n  doctor   Check\n  mcp      Configure\n");
  process.exit(0);
}
// Claude Code writes its shell snapshot of the login shell at start (fixtures/claude-snapshot.mjs), into its config directory.
if (!process.env.FAKE_CLAUDE_NO_SNAPSHOT && process.platform === "linux" && process.env.HOME) {
  const { makeClaudeSnapshot } = await import("./claude-snapshot.mjs");
  makeClaudeSnapshot({ configDir: process.env.CLAUDE_CONFIG_DIR || path.join(process.env.HOME, ".claude"), home: process.env.HOME, pathValue: process.env.PATH ?? "", env: { ...process.env } });
}
const record = { argv: args, settings: null, hookOutput: null, isTTY: process.stdin.isTTY ?? false, env: { ECWCODE_SESSION: process.env.ECWCODE_SESSION ?? null, ECWCODE_HW_BROKER: process.env.ECWCODE_HW_BROKER ?? null, LD_PRELOAD: process.env.LD_PRELOAD ?? null, LD_AUDIT: process.env.LD_AUDIT ?? null, DYLD_INSERT_LIBRARIES: process.env.DYLD_INSERT_LIBRARIES ?? null, LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH ?? null } };
const si = args.indexOf("--settings");
if (si >= 0) {
  const v = args[si + 1];
  record.settingsPath = v;
  record.settingsMode = (fs.statSync(v).mode & 0o777).toString(8);
  record.settings = JSON.parse(fs.readFileSync(v, "utf8"));
  // The launcher's record of this process's environment (shell-env.mjs), next to the settings file.
  if (process.env.FAKE_CLAUDE_FULL_ENV) {
    record.processEnv = { ...process.env };
    try {
      record.claudeEnvRecord = JSON.parse(fs.readFileSync(path.join(path.dirname(v), "claude-env.json"), "utf8"));
    } catch {
      record.claudeEnvRecord = null;
    }
  }
}
const hookEnv = { ...process.env, CLAUDE_PROJECT_DIR: process.cwd() };
if (process.env.FAKE_CLAUDE_MANAGED) {
  // Managed mode: Claude Code runs the hooks of its managed settings (no
  // --settings, no launcher). FAKE_CLAUDE_MANAGED_CALLS plays tool calls in
  // order: the PreToolUse hook decides; a "deny" does not run; an "ask" is
  // shown at Claude Code's prompt, and `prompt` says what happens there:
  // "person" (the person approves; the call runs in the mode it was asked in)
  // or "recheck:<mode>" (the person switches to <mode> while the prompt is
  // open, and Claude Code re-checks the pending call and runs it with no
  // answer, as Claude Code 2.1.326 does). A call that runs applies its Write
  // or Bash, then the PostToolUse hook runs with the mode it ran in.
  const managed = JSON.parse(fs.readFileSync(process.env.FAKE_CLAUDE_MANAGED, "utf8"));
  const hookOf = (ev) => managed.hooks?.[ev]?.at(-1)?.hooks?.[0]?.command;
  const runEvent = (ev, input) => execSync(hookOf(ev), { input: JSON.stringify(input), shell: "/bin/sh", encoding: "utf8", env: hookEnv });
  const results = [];
  for (const call of JSON.parse(process.env.FAKE_CLAUDE_MANAGED_CALLS ?? "[]")) {
    const out = runEvent("PreToolUse", call.input);
    const decision = JSON.parse(out || "null")?.hookSpecificOutput?.permissionDecision ?? null;
    let ranIn = null;
    if (decision === "allow") {
      ranIn = call.input.permission_mode;
    } else if (decision === "ask") {
      ranIn = call.prompt === "person" ? call.input.permission_mode : typeof call.prompt === "string" && call.prompt.startsWith("recheck:") ? call.prompt.slice(8) : null;
    }
    let post = null;
    if (ranIn) {
      const ti = call.input.tool_input;
      if (call.input.tool_name === "Write") {
        // Like Claude Code's Write: missing parent folders are created.
        fs.mkdirSync(path.dirname(ti.file_path), { recursive: true });
        fs.writeFileSync(ti.file_path, ti.content);
      } else if (call.input.tool_name === "Bash") {
        execSync(ti.command, { shell: "/bin/sh", cwd: process.cwd(), stdio: "ignore" });
      }
      post = runEvent("PostToolUse", { ...call.input, hook_event_name: "PostToolUse", permission_mode: ranIn, tool_response: { ok: true } });
    }
    results.push({ decision, ranIn, pre: JSON.parse(out || "null"), post: post ? JSON.parse(post) : null });
  }
  fs.writeFileSync(process.env.FAKE_CLAUDE_OUT, JSON.stringify({ argv: args, results }));
  process.exit(0);
}
// Like Claude Code, start the session by running the SessionStart hooks
// (Enclawed Code's launcher waits for that handshake), unless told not to.
if (record.settings && !process.env.FAKE_CLAUDE_NO_HOOKS) {
  const start = record.settings.hooks?.SessionStart?.at(-1)?.hooks?.[0]?.command;
  if (start) {
    // FAKE_CLAUDE_START_TRANSCRIPT: name the session transcript, as Claude Code does.
    const tp = process.env.FAKE_CLAUDE_START_TRANSCRIPT ? path.join(process.env.CLAUDE_CONFIG_DIR || path.join(process.env.HOME, ".claude"), "projects", process.cwd().replace(/[^a-zA-Z0-9]/g, "-"), "fake-session.jsonl") : null;
    const input = JSON.stringify({ hook_event_name: "SessionStart", session_id: "fake-session", cwd: process.cwd(), source: "startup", transcript_path: tp });
    try {
      execSync(start, { input, shell: "/bin/sh", encoding: "utf8", env: hookEnv });
    } catch {
      /* a failing SessionStart hook does not stop Claude Code */
    }
  }
}
// Like Claude Code, write the tool call to the session transcript (the call
// in FAKE_CLAUDE_HOOK_INPUT, or a Bash call that no hook sees: what a session
// whose settings were dropped looks like to the launcher), then run the
// PreToolUse hook, then write the result when asked. Claude Code writes the
// tool_use line while the call's PreToolUse hook runs; the launcher binds a
// decision to that line (round 3, N9).
const hookInput = HOOK_INPUT ? JSON.parse(HOOK_INPUT) : null;
const transcriptDir = () => {
  const config = process.env.CLAUDE_CONFIG_DIR || path.join(process.env.HOME, ".claude");
  const dir = path.join(config, "projects", process.cwd().replace(/[^a-zA-Z0-9]/g, "-"));
  fs.mkdirSync(dir, { recursive: true });
  return dir;
};
const appendTranscript = (lines) => fs.appendFileSync(path.join(transcriptDir(), "fake-session.jsonl"), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
// A hook input's call is written too, as Claude Code would (unless told not to).
if (process.env.FAKE_CLAUDE_HELPER_SH) {
  // N7b: a background helper started by a tool call (same process group,
  // not detached), running the given shell script.
  const { spawn } = await import("node:child_process");
  spawn("/bin/sh", ["-c", process.env.FAKE_CLAUDE_HELPER_SH], { stdio: "ignore" });
}
if (process.env.FAKE_CLAUDE_SETSID_CANARY) {
  // N12: a tool call's `setsid sh -c 'sleep N; touch canary' &`, which leaves
  // claude's process tree (re-parented to init) before any halt.
  const { spawn } = await import("node:child_process");
  spawn("setsid", ["sh", "-c", `sleep ${process.env.FAKE_CLAUDE_SETSID_DELAY_S ?? 3}; touch '${process.env.FAKE_CLAUDE_SETSID_CANARY}'`], { detached: true, stdio: "ignore" }).unref();
}
const tid = process.env.FAKE_CLAUDE_TRANSCRIPT_TOOL ?? (process.env.FAKE_CLAUDE_NO_TRANSCRIPT ? undefined : hookInput?.tool_use_id);
if (tid) {
  await new Promise((r) => setTimeout(r, Number(process.env.FAKE_CLAUDE_TRANSCRIPT_DELAY_MS ?? 0)));
  // The transcript's call: the hook input's unless told otherwise (a forger's
  // fabricated hook input differs from the call Claude Code really runs).
  const name = process.env.FAKE_CLAUDE_TRANSCRIPT_NAME ?? hookInput?.tool_name ?? "Bash";
  const input = process.env.FAKE_CLAUDE_TRANSCRIPT_INPUT ? JSON.parse(process.env.FAKE_CLAUDE_TRANSCRIPT_INPUT) : (hookInput?.tool_input ?? { command: "touch canary" });
  // Like Claude Code: the transcript line carries the session's id, which the hook input carries too.
  appendTranscript([{ type: "assistant", sessionId: hookInput?.session_id ?? "fake-session", message: { role: "assistant", content: [{ type: "tool_use", id: tid, name, input }] } }]);
}
if (hookInput && record.settings) {
  const cmd = record.settings.hooks.PreToolUse.at(-1).hooks[0].command;
  record.hookOutput = execSync(cmd, { input: HOOK_INPUT, shell: "/bin/sh", encoding: "utf8", env: hookEnv });
}
if (process.env.FAKE_CLAUDE_RUN_UPDATED && record.hookOutput) {
  // Like Claude Code's Bash tool: run the command the hook answered with
  // (its updatedInput, e.g. the contained form of a project script), then,
  // when given, play a second tool call (whether the session goes on).
  let updated = null;
  try {
    updated = JSON.parse(record.hookOutput)?.hookSpecificOutput?.updatedInput?.command ?? null;
  } catch {
    updated = null;
  }
  if (updated) {
    try {
      record.ran = { status: 0, output: execSync(updated, { shell: "/bin/sh", encoding: "utf8", cwd: process.cwd(), timeout: 90_000, stdio: ["ignore", "pipe", "pipe"] }) };
    } catch (err) {
      record.ran = { status: err.status ?? null, output: `${err.stdout ?? ""}${err.stderr ?? ""}` };
    }
  }
  if (HOOK_INPUT_2) {
    await new Promise((r) => setTimeout(r, Number(process.env.FAKE_CLAUDE_SECOND_DELAY_MS ?? 0)));
    const second = JSON.parse(HOOK_INPUT_2);
    appendTranscript([{ type: "assistant", sessionId: second.session_id ?? "fake-session", message: { role: "assistant", content: [{ type: "tool_use", id: second.tool_use_id, name: second.tool_name, input: second.tool_input }] } }]);
    const cmd = record.settings.hooks.PreToolUse.at(-1).hooks[0].command;
    record.hookOutput2 = execSync(cmd, { input: HOOK_INPUT_2, shell: "/bin/sh", encoding: "utf8", env: hookEnv });
  }
}
if (process.env.FAKE_CLAUDE_DROP_STDERR && record.settingsPath) {
  // Claude Code 2.1.326's message for a settings file it did not load (round 4, F1).
  process.stderr.write(`These settings files did not load, so nothing in them is in effect, including hooks and permission rules. Each loads again once the problem listed for it is fixed:\n  ${record.settingsPath} ($schema): Expected string, but received number\n`);
}
if (tid && process.env.FAKE_CLAUDE_TRANSCRIPT_RESULT) {
  // Like Claude Code in -p: a call the hook denied or asked about does not
  // run (an error result), unless the test says it runs anyway (round 4, N13:
  // what a session whose hooks were dropped does).
  let decision = null;
  try {
    decision = JSON.parse(record.hookOutput ?? "null")?.hookSpecificOutput?.permissionDecision ?? null;
  } catch {
    decision = null;
  }
  const refused = (decision === "deny" || decision === "ask") && !process.env.FAKE_CLAUDE_RUN_ANYWAY;
  appendTranscript([{ type: "user", sessionId: hookInput?.session_id ?? "fake-session", message: { role: "user", content: [{ type: "tool_result", tool_use_id: tid, content: "", is_error: refused }] } }]);
}
if (process.env.FAKE_CLAUDE_SLEEP_MS) {
  // Stay alive like an interactive session (handshake and halt tests).
  await new Promise((r) => setTimeout(r, Number(process.env.FAKE_CLAUDE_SLEEP_MS)));
}
if (process.env.FAKE_CLAUDE_OUT) {
  fs.writeFileSync(process.env.FAKE_CLAUDE_OUT, JSON.stringify(record));
}
if (process.env.FAKE_CLAUDE_SIGNAL) {
  process.kill(process.pid, process.env.FAKE_CLAUDE_SIGNAL);
  setTimeout(() => {}, 5000);
} else {
  process.exit(Number(process.env.FAKE_CLAUDE_EXIT ?? 0));
}
