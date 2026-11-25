import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { extractSettingsArgs, routeArgs } from "../src/args.mjs";
import { buildSettings, enclawedHooks } from "../src/settings.mjs";
import { expectedManagedHooks, managedTemplate } from "../src/managed.mjs";
import { pre, runCtl, runLauncher, sandbox } from "./helpers.mjs";
import { hookGrantDigest } from "../src/project-grants.mjs";

let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());

function launch(args, env = {}) {
  const out = path.join(sb.dir, `claude-${Math.random().toString(36).slice(2)}.json`);
  const res = runLauncher(sb, args, { FAKE_CLAUDE_OUT: out, ...env });
  const record = fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf8")) : null;
  return { ...res, record };
}

test("routing: ecwcode reserves no word; whether claude starts a session decides only the hooks", () => {
  for (const w of ["history", "audit", "managed", "ecwcode", "ecwctl", "codenclawed", "policy", "auth", "demo", "probe", "--version", "--help"]) {
    assert.equal(routeArgs([w, "list"]).kind, "passthrough", w);
  }
  assert.equal(routeArgs(["-p", "history"]).kind, "passthrough");
  assert.equal(routeArgs(["mcp", "list"]).session, false);
  assert.equal(routeArgs(["doctor"]).session, false);
  assert.equal(routeArgs(["--version"]).session, false);
  assert.equal(routeArgs(["history"]).session, true);
  assert.equal(routeArgs(["-p", "hi"]).session, true);
});

test("ecwcode passes the words that used to be Enclawed Code's own straight to claude", () => {
  // A session-starting prompt: claude gets the words after Enclawed Code's injected settings.
  for (const args of [["history", "list"], ["audit", "verify"], ["demo"], ["managed", "print"], ["policy", "show"], ["ecwcode", "doctor"], ["codenclawed", "doctor"]]) {
    const { status, record, stderr } = launch(args);
    assert.equal(status, 0, `${args.join(" ")}: ${stderr}`);
    assert.deepEqual(record.argv.slice(-args.length), args, args.join(" "));
    assert.equal(record.argv[0], "--settings", args.join(" "));
  }
  // Claude Code's own non-session commands: exactly the arguments, nothing injected.
  for (const args of [["doctor"], ["mcp", "list"], ["update"], ["auth", "status"], ["plugin", "list"]]) {
    const { status, record, stderr } = launch(args);
    assert.equal(status, 0, `${args.join(" ")}: ${stderr}`);
    assert.deepEqual(record.argv, args, args.join(" "));
  }
});

test("settings args are extracted in both spellings, but not after --", () => {
  const r = extractSettingsArgs(["--settings", "a.json", "-p", "x", "--settings={}", "--", "--settings", "lit"]);
  assert.deepEqual(r.values, ["a.json", "{}"]);
  assert.deepEqual(r.rest, ["-p", "x", "--", "--settings", "lit"]);
});

test("all arguments pass through unchanged, after the injected --settings", () => {
  const args = ["-p", "fix the test", "--model", "sonnet", "--allowedTools", "Bash(git *)", "--", "--weird arg"];
  const { status, record } = launch(args);
  assert.equal(status, 0);
  assert.equal(record.argv[0], "--settings");
  // After --settings: only the user's own settings are read live
  // (--setting-sources=user; the repository's admitted settings are in the
  // session file), then Enclawed Code's --mcp-config FILE --strict-mcp-config.
  assert.equal(record.argv[2], "--setting-sources=user");
  assert.match(record.argv[3], /^--mcp-config=.*mcp\.json$/);
  assert.equal(record.argv[4], "--strict-mcp-config");
  // Then Enclawed Code's default permission mode (permission-mode.mjs: the person passed none).
  assert.deepEqual(record.argv.slice(5, 7), ["--permission-mode", "bypassPermissions"]);
  assert.deepEqual(record.argv.slice(7), args);
  assert.equal(record.settingsMode, "600");
  assert.equal(record.env.ECWCODE_SESSION, "1");
  assert.deepEqual(Object.keys(record.settings.hooks).sort(), Object.keys(enclawedHooks("x")).sort());
  const preHook = record.settings.hooks.PreToolUse[0].hooks[0];
  assert.equal(preHook.onFailure, "block");
  assert.equal(preHook.timeout, 10);
  // The hook runs with an empty environment and reads only its session file.
  assert.match(preHook.command, /^'\/(usr\/)?bin\/env' -i CLAUDE_PROJECT_DIR="\$CLAUDE_PROJECT_DIR" '.*ecwcode-hook\.mjs' --origin launcher --session '[^']+' --digest [0-9a-f]{64}$/);
  assert.equal(record.settings.disableAllHooks, false);
  // The per-session settings file is removed when claude exits.
  assert.equal(fs.existsSync(record.settingsPath), false);
});

test("the user's own --settings is merged, not dropped", () => {
  const userFile = path.join(sb.dir, "user-settings.json");
  fs.writeFileSync(
    userFile,
    JSON.stringify({
      model: "opus",
      permissions: { allow: ["Bash(npm test)"] },
      hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo mine" }] }] },
    }),
  );
  const args = ["--settings", userFile, "--settings={\"theme\":\"dark\",\"disableAllHooks\":true}", "-p", "x"];
  // A --settings hook needs an administrator's grant by digest (closure plan M7).
  const refused = launch(args);
  assert.equal(refused.status, 2, refused.stderr);
  assert.match(refused.stderr, /--settings value 1 \(--settings\) adds a PreToolUse hook \(echo mine\).*"hooks"/);
  const digest = hookGrantDigest({ scope: "--settings", file: "--settings value 1", event: "PreToolUse", matcher: "Bash", raw: { type: "command", command: "echo mine" } }, { home: sb.home, projectDir: sb.project });
  sb.grant({ hooks: [{ digest }] });
  const { status, record, stderr } = launch(args);
  sb.grant(null);
  assert.equal(status, 0, stderr);
  assert.match(stderr, /adds a PreToolUse hook \(echo mine\); granted by/);
  assert.deepEqual(record.argv.slice(5), ["--permission-mode", "bypassPermissions", "-p", "x"]);
  assert.equal(record.argv.filter((a) => a === "--settings").length, 1);
  const s = record.settings;
  assert.equal(s.model, "opus");
  assert.equal(s.theme, "dark");
  assert.deepEqual(s.permissions.allow, ["Bash(npm test)"]);
  assert.equal(s.hooks.PreToolUse.length, 2);
  assert.equal(s.hooks.PreToolUse[0].hooks[0].command, "echo mine");
  assert.equal(s.disableAllHooks, false);
  assert.match(stderr, /ignoring disableAllHooks/);
});

test("an unreadable --settings refuses to launch", () => {
  const r = launch(["--settings", "/nonexistent/settings.json", "-p", "x"]);
  assert.equal(r.status, 2);
  assert.equal(r.record, null);
  assert.match(r.stderr, /cannot read --settings file/);
});

test("the exit code of claude is propagated", () => {
  assert.equal(launch(["-p", "x"], { FAKE_CLAUDE_EXIT: "7" }).status, 7);
});

test("a signal that kills claude kills Enclawed Code the same way", () => {
  const r = launch(["-p", "x"], { FAKE_CLAUDE_SIGNAL: "SIGTERM" });
  assert.equal(r.signal, "SIGTERM");
});

test("flags that switch hooks off are refused", () => {
  for (const flag of ["--bare", "--safe-mode"]) {
    const r = launch([flag, "-p", "x"]);
    assert.equal(r.status, 2);
    assert.equal(r.record, null);
    assert.match(r.stderr, /switch Enclawed off/);
  }
});

test("claude subcommands that start no session pass through without hooks", () => {
  const { record } = launch(["mcp", "list"]);
  assert.deepEqual(record.argv, ["mcp", "list"]);
});

test("--version passes through to claude", () => {
  const r = runLauncher(sb, ["--version"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /2\.1\.326 \(Claude Code\)/);
});

test("ecwctl's commands never reach claude; ecwcode --version and --help are claude's", () => {
  const v = launch(["--version"]);
  assert.equal(v.status, 0);
  assert.match(v.stdout, /\(Claude Code\)/);
  const h = launch(["--help"]);
  assert.equal(h.status, 0);
  assert.match(h.stdout, /^Usage: claude/);
  const out = path.join(sb.dir, "ctl-claude.json");
  const cv = runCtl(sb, ["--version"], { FAKE_CLAUDE_OUT: out });
  assert.equal(cv.status, 0, cv.stderr);
  assert.match(cv.stdout, /^\d+\.\d+\.\d+/);
  const a = runCtl(sb, ["audit", "path"], { FAKE_CLAUDE_OUT: out });
  assert.equal(a.status, 0, a.stderr);
  assert.match(a.stdout, /claude-code\/audit\.jsonl/);
  assert.equal(fs.existsSync(out), false, "ecwctl never started claude");
  const passed = launch(["--", "history"]);
  assert.deepEqual(passed.record.argv.slice(5), ["--permission-mode", "bypassPermissions", "--", "history"]);
});

test("a claude too old to block on hook failure is refused (it is not a reviewed version either)", () => {
  const r = runLauncher(sb, ["-p", "x"], {
    FAKE_CLAUDE_VERSION: "2.1.200",
    ENCLAWED_STATE_DIR: path.join(sb.dir, "state-old"),
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Claude Code 2\.1\.200 .* is not a version Enclawed Code has reviewed/);
});

test("Enclawed Code never runs itself as claude", () => {
  const selfBin = path.join(sb.dir, "selfbin");
  fs.mkdirSync(selfBin);
  fs.symlinkSync(path.resolve("bin/ecwcode.mjs"), path.join(selfBin, "claude"));
  const r = runLauncher(sb, ["-p", "x"], { PATH: `${selfBin}${path.delimiter}${sb.env.PATH}` });
  // It skips the symlink to itself and finds the fake claude behind it.
  assert.equal(r.status, 0, r.stderr);
  const none = runLauncher(sb, ["-p", "x"], { PATH: `${selfBin}${path.delimiter}${path.dirname(process.execPath)}` });
  assert.equal(none.status, 127);
  assert.match(none.stderr, /cannot find your Claude Code/);
});

test("the injected hook command really runs the hook (as Claude Code would)", () => {
  fs.writeFileSync(path.join(sb.project, "note.txt"), "before\n");
  const input = pre(sb, "Write", { file_path: "note.txt", content: "after\n" });
  const { record, status, stderr } = launch(["-p", "x"], { FAKE_CLAUDE_HOOK_INPUT: JSON.stringify(input) });
  assert.equal(status, 0, stderr);
  const out = JSON.parse(record.hookOutput);
  assert.equal(out.hookSpecificOutput.permissionDecision, "allow");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /previous content kept/);
});

test("the managed template carries exactly the launcher's hooks", () => {
  const t = managedTemplate({ command: "/opt/x/ecwcode-hook" });
  assert.equal(t.allowManagedHooksOnly, true);
  assert.equal(t.permissions.disableBypassPermissionsMode, "disable");
  assert.equal(t.permissions.disableAutoMode, "disable");
  assert.equal(t.hooks.PreToolUse[0].hooks[0].command, "/opt/x/ecwcode-hook");
  assert.equal(t.hooks.PreToolUse[0].hooks[0].onFailure, "block");
  const raw = JSON.parse(fs.readFileSync(new URL("../managed/enclawed-code.json", import.meta.url), "utf8"));
  assert.deepEqual(raw.hooks, expectedManagedHooks());
});

test("buildSettings with no user settings is just Enclawed's hooks and Claude Code's update switches", () => {
  const { settings } = buildSettings([], "cmd");
  assert.deepEqual(settings, { hooks: enclawedHooks("cmd"), disableAllHooks: false, env: { DISABLE_AUTOUPDATER: "1", DISABLE_UPDATES: "1" } });
});

test("the repository's settings are never read live: claude gets --setting-sources=user and the admitted copy in the session file", () => {
  // Claude Code reloads settings files that change (its ConfigChange event);
  // with project and local excluded from its sources, a later write to them
  // reaches the session only through Enclawed Code's admission at the next launch.
  fs.mkdirSync(path.join(sb.project, ".claude"), { recursive: true });
  fs.writeFileSync(path.join(sb.project, ".claude", "settings.json"), JSON.stringify({ permissions: { deny: ["Bash(rm:*)"] } }));
  fs.writeFileSync(path.join(sb.project, ".claude", "settings.local.json"), JSON.stringify({ permissions: { deny: ["Bash(curl:*)"] } }));
  try {
    const { status, record, stderr } = launch(["-p", "x"]);
    assert.equal(status, 0, stderr);
    assert.ok(record.argv.includes("--setting-sources=user"));
    assert.ok(!record.argv.some((a) => /^--setting-sources(=|$)/.test(a) && a !== "--setting-sources=user"));
    assert.ok(record.settings.permissions.deny.includes("Bash(rm:*)"), "the admitted project settings are in the session file");
    assert.ok(record.settings.permissions.deny.includes("Bash(curl:*)"), "and the local ones");
    // The person's own choice of sources narrows what is read live and what is materialized.
    const only = launch(["--setting-sources", "user,local", "-p", "x"]);
    assert.equal(only.status, 0, only.stderr);
    assert.ok(only.record.argv.includes("--setting-sources=user"));
    assert.ok(!only.record.argv.includes("user,local"), "the person's flag is replaced, not passed through");
    assert.ok(!only.record.settings.permissions.deny.includes("Bash(rm:*)"), "project excluded by the person");
    assert.ok(only.record.settings.permissions.deny.includes("Bash(curl:*)"));
    const none = launch(["--setting-sources=project", "-p", "x"]);
    assert.ok(none.record.argv.includes("--setting-sources="), "user excluded by the person: no source is read live");
  } finally {
    fs.rmSync(path.join(sb.project, ".claude"), { recursive: true, force: true });
  }
});
