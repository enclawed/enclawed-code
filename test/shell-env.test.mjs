import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// The complete environment of Claude Code's Bash tool (shell-env.mjs): the
// kit gets it only when it is known exactly, from the launcher's record of
// claude's environment, the settings and Claude Code's own shell snapshot of
// this session; otherwise null, and the kit asks wherever it needs it.
//
// The snapshots here are made the way Claude Code 2.1.326 makes them
// (fixtures/claude-snapshot.mjs: a login bash that sources ~/.bashrc).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { CLAUDE_ENV_RECORD, commandWords, managedShellDefinitions, mayInvoke, parseShellSnapshot, readClaudeEnvironment, recordClaudeEnvironment, shellEnvironment } from "../src/shell-env.mjs";
import { makeClaudeSnapshot } from "./fixtures/claude-snapshot.mjs";
import { hookSession, pre, runHook, runLauncher, sandbox } from "./helpers.mjs";

const linux = process.platform === "linux";
let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());

const SESSION_ID = "0b6c2f6e-5d1a-4c55-9a43-7f1e2d3c4b5a";
const decisionOf = (r) => r?.out?.hookSpecificOutput ?? null;

/**
 * A launcher session as the launcher leaves it right before claude starts:
 * the session file, a private Claude Code config directory with this
 * session's shell snapshot, Enclawed Code's settings file and the record of
 * claude's environment. `home` files (.bashrc, .profile) are written first.
 */
function session({ rc = null, profile = null, extraEnv = {}, userSettings = null, flagEnv = {}, snapshot = true, marker = true, cfg: sharedCfg = null, patch = null } = {}) {
  const base = fs.mkdtempSync(path.join(sb.dir, "s-"));
  const home = path.join(base, "home");
  fs.mkdirSync(home, { recursive: true });
  for (const [name, text] of [
    [".bashrc", rc],
    [".profile", profile],
  ]) {
    if (text !== null) {
      fs.writeFileSync(path.join(home, name), text);
    }
  }
  const cfg = sharedCfg ?? path.join(base, "ctx");
  fs.mkdirSync(cfg, { recursive: true });
  if (userSettings) {
    fs.writeFileSync(path.join(cfg, "settings.json"), JSON.stringify(userSettings));
  }
  const env = { ...sb.env, HOME: home, SHLVL: "1", CLAUDE_CONFIG_DIR: cfg, ECWCODE_SESSION: "1", ...extraEnv };
  for (const [k, v] of Object.entries(extraEnv)) {
    if (v === undefined) {
      delete env[k];
    }
  }
  const s = hookSession(sb, { HOME: home }, { claudeShell: false, ...(patch ? { patch } : {}) });
  const settingsFile = path.join(s.dir, "settings.json");
  // The launcher's marker: an empty directory of the session, the last PATH entry.
  const pathMarker = path.join(s.dir, "no-programs");
  fs.mkdirSync(pathMarker, { mode: 0o500 });
  if (marker) {
    env.PATH = `${env.PATH}:${pathMarker}`;
  }
  fs.writeFileSync(settingsFile, JSON.stringify({ env: flagEnv }));
  if (snapshot) {
    makeClaudeSnapshot({ configDir: cfg, home, pathValue: env.PATH, env });
  }
  recordClaudeEnvironment({ sessionDir: s.dir, nonce: s.session.nonce, env, settingsFile, settingSources: ["user"], pathMarker });
  return { s, home, cfg, env };
}

const bash = (command, extra = {}) => pre(sb, "Bash", { command }, { session_id: SESSION_ID, ...extra });
const decide = (ses, command, extra) => decisionOf(runHook(sb, bash(command, extra), { HOME: ses.home }, { session: ses.s }));
const envFor = (ses, command = "true") => shellEnvironment({ record: readClaudeEnvironment(ses.s.session), input: bash(command), managedDocs: [] });

const GH = ["gh auth status", "gh issue list -R acme/public-site", "gh pr view 7 --json title,body,files"];
const DUMP = 'env | grep -i github || echo "No GitHub environment variables found"';

test("FP: the honest case: no credential anywhere, the session's snapshot as Claude Code wrote it: gh's read verbs and a filtered env print run", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const ses = session({ rc: "export HISTSIZE=1000\n" });
  const e = envFor(ses);
  assert.ok(e.environment, e.why);
  for (const c of [...GH, DUMP]) {
    const d = decide(ses, c);
    assert.equal(d.permissionDecision, "allow", `${c}: ${d.permissionDecisionReason}`);
  }
});

test("the environment is what bash itself runs the command with: the record, the settings, Claude Code's own names and the snapshot's PATH", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const ses = session({ rc: "export FROM_RC=1\nmyfn() { export FROM_FN=1; }\n", profile: "export GH_TOKEN=ghp_profile_export_000000000000000000\n", userSettings: { env: { FROM_USER_SETTINGS: "u" } }, flagEnv: { FROM_FLAG: "f" } });
  const { environment } = envFor(ses);
  assert.ok(environment);
  assert.equal(environment.FROM_USER_SETTINGS, "u");
  assert.equal(environment.FROM_FLAG, "f");
  assert.equal(environment.CLAUDE_CODE_SESSION_ID, SESSION_ID);
  // What Claude Code's command line does (buildExecCommand, no sandbox): source the snapshot, then the command.
  const snap = fs.readdirSync(path.join(ses.cfg, "shell-snapshots"))[0];
  const spawnEnv = { ...ses.env, FROM_USER_SETTINGS: "u", FROM_FLAG: "f", CLAUDECODE: "1", CLAUDE_CODE_SESSION_ID: SESSION_ID, CLAUDE_CODE_CHILD_SESSION: "1", GIT_EDITOR: "true", COREPACK_ENABLE_AUTO_PIN: "0", NoDefaultCurrentDirectoryInExePath: "1" };
  // stdin a socket, as a spawned pipe is here: at SHLVL 1 bash does not read ~/.bashrc for it.
  const r = spawnSync("/bin/bash", ["-c", `source ${JSON.stringify(path.join(ses.cfg, "shell-snapshots", snap))} 2>/dev/null || true && eval 'env -0'`], { env: spawnEnv, encoding: "utf8", input: "" });
  const actual = Object.fromEntries(r.stdout.split("\0").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  // The login shell's exports (.profile's GH_TOKEN, .bashrc's FROM_RC) never reach the command, and the map says so.
  assert.deepEqual(["GH_TOKEN", "FROM_RC", "FROM_FN"].filter((k) => k in actual), [], r.stderr);
  for (const [k, v] of Object.entries(environment)) {
    assert.equal(actual[k], v, k);
  }
  // Left out, as unknown: bash's own names and Claude Code's own (it may change them), never a credential-shaped one.
  for (const k of Object.keys(actual)) {
    assert.ok(k in environment || ["PWD", "SHLVL", "_", "OLDPWD"].includes(k) || (/^CLAUDE_/.test(k) && !/TOKEN|KEY|SECRET|AUTH/.test(k)), `${k} is in bash's environment but not in the map`);
  }
});

test("attack: a login-shell export that does reach the shell (Claude Desktop's entrypoint takes them; no snapshot runs a login shell): gh is not proven credential-less, it asks", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const profile = "export GH_TOKEN=ghp_profile_export_000000000000000000\n";
  const desktop = session({ profile, extraEnv: { CLAUDE_CODE_ENTRYPOINT: "claude-desktop" } });
  assert.equal(envFor(desktop).environment, null);
  assert.match(envFor(desktop).why, /login shell's exports/);
  // bash -c with a socket for stdin at shell level 1 (no SHLVL) sources ~/.bashrc itself, exports and all.
  const level1 = session({ rc: profile, extraEnv: { SHLVL: undefined } });
  assert.match(envFor(level1).why, /SHLVL/);
  const viaSocket = spawnSync("/bin/bash", ["-c", "printenv GH_TOKEN"], { env: { ...level1.env }, encoding: "utf8", input: "" });
  assert.equal(viaSocket.stdout.trim(), "ghp_profile_export_000000000000000000");
  const noSnapshot = session({ profile, snapshot: false });
  assert.match(envFor(noSnapshot).why, /login shell/);
  // That fallback is real: a login bash takes .profile's export.
  const r = spawnSync("/bin/bash", ["-l", "-c", "printenv GH_TOKEN"], { env: { ...noSnapshot.env }, encoding: "utf8" });
  assert.equal(r.stdout.trim(), "ghp_profile_export_000000000000000000");
  for (const ses of [desktop, level1, noSnapshot]) {
    for (const c of GH) {
      const d = decide(ses, c);
      assert.notEqual(d.permissionDecision, "allow", `${c}: ${d.permissionDecisionReason}`);
    }
    assert.notEqual(decide(ses, DUMP).permissionDecision, "allow");
  }
});

test("attack: the login shell's alias or function for gh carries a token: that call asks; a call that cannot reach it still runs", { skip: !linux && "Claude Code's Linux shell" }, () => {
  for (const rc of ["alias gh='GH_TOKEN=ghp_alias_0000000000000000000000000000 gh'\n", "gh() { GH_TOKEN=ghp_fn_00000000000000000000000000000000 command gh \"$@\"; }\n", "ghx() { export GH_TOKEN=ghp_fn_00000000000000000000000000000000; }\n"]) {
    const ses = session({ rc });
    const name = /^(?:alias )?([a-z]+)/.exec(rc)[1];
    for (const c of [...GH, `${name} && gh auth status`, "$(printf gh) auth status", "eval 'gh auth status'", "x=\"$(gh api user)\""]) {
      const r = envFor(ses, c);
      if (!mayInvoke(c, [name])) {
        // gh itself is not what the login shell redefined here: known, and allowed.
        assert.ok(r.environment, `${c}: ${r.why}`);
        if (GH.includes(c)) {
          assert.equal(decide(ses, c).permissionDecision, "allow", c);
        }
        continue;
      }
      assert.equal(r.environment, null, c);
      assert.notEqual(decide(ses, c).permissionDecision, "allow", c);
    }
    assert.equal(decide(ses, DUMP).permissionDecision, "allow", rc);
  }
});

test("attack: a token in the settings env, the session's tool redirect or a hook's session-environment file: gh asks", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const user = session({ userSettings: { env: { GH_TOKEN: "ghp_user_settings_0000000000000000000000" } } });
  assert.equal(envFor(user).environment.GH_TOKEN, "ghp_user_settings_0000000000000000000000");
  const flag = session({ flagEnv: { GITHUB_TOKEN: "ghp_flag_settings_0000000000000000000000" } });
  const shellVar = session({ extraEnv: { GH_TOKEN: "ghp_shell_000000000000000000000000000000" } });
  const hooked = session();
  const dir = path.join(hooked.cfg, "session-env", SESSION_ID);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "sessionstart-hook-0.sh"), "export GH_TOKEN=ghp_hook_000000000000000000000000000000\n");
  assert.match(envFor(hooked).why, /session environment/);
  const envFile = session({ extraEnv: { CLAUDE_ENV_FILE: path.join(sb.dir, "env.sh") } });
  assert.match(envFor(envFile).why, /CLAUDE_ENV_FILE/);
  for (const ses of [user, flag, shellVar, hooked, envFile]) {
    for (const c of GH) {
      assert.notEqual(decide(ses, c).permissionDecision, "allow", c);
    }
  }
  // The token is in the environment: printing lines that match it asks.
  assert.notEqual(decide(user, "env | grep -i gh").permissionDecision, "allow");
});

test("the person's own config directory, shared with other sessions: this session's snapshot is the one with its marker; another session's aliases do not count", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const shared = path.join(sb.dir, "shared-claude");
  const other = session({ cfg: shared, rc: "alias gh='GH_TOKEN=ghp_other_session_000000000000000000000 gh'\n" });
  const ses = session({ cfg: shared, rc: "export HISTSIZE=1000\n" });
  assert.equal(fs.readdirSync(path.join(shared, "shell-snapshots")).length, 2);
  assert.ok(envFor(ses, "gh auth status").environment);
  assert.equal(decide(ses, "gh auth status").permissionDecision, "allow");
  assert.equal(envFor(other, "gh auth status").environment, null);
  assert.notEqual(decide(other, "gh auth status").permissionDecision, "allow");
});

test("fail closed: no marker, two snapshots with this session's marker, a snapshot that is not Claude Code's, another platform, sandbox, remote, or a record that is not the launcher's", { skip: !linux && "Claude Code's Linux shell" }, () => {
  assert.match(envFor(session({ marker: false })).why, /marker/);
  assert.match(envFor(session({ snapshot: false })).why, /no shell snapshot/);
  const two = session();
  makeClaudeSnapshot({ configDir: two.cfg, home: two.home, pathValue: two.env.PATH, env: two.env, now: 1 });
  assert.match(envFor(two).why, /more than one/);
  for (const tail of ["export GH_TOKEN=ghp_tamper_00000000000000000000000000\n", "set -o allexport\n", "eval $'f () \\n{ \\n    :\\n}\\nexport GH_TOKEN=x' > /dev/null 2>&1\n", "alias -- x='y'; export GH_TOKEN=x\n", "export PATH=/tmp/evil:$PATH\n"]) {
    const ses = session();
    const snap = path.join(ses.cfg, "shell-snapshots", fs.readdirSync(path.join(ses.cfg, "shell-snapshots"))[0]);
    fs.appendFileSync(snap, tail);
    assert.equal(envFor(ses).environment, null, tail);
    assert.notEqual(decide(ses, "gh auth status").permissionDecision, "allow", tail);
  }
  const ok = session();
  const rec = readClaudeEnvironment(ok.s.session);
  assert.match(shellEnvironment({ record: rec, input: bash("true"), platform: "darwin" }).why, /Linux/);
  assert.match(shellEnvironment({ record: rec, input: bash("true"), managedDocs: [{ file: "m.json", doc: { sandbox: { enabled: true } } }] }).why, /sandbox/);
  assert.match(shellEnvironment({ record: rec, input: bash("true"), managedDocs: [{ file: "m.json", doc: null, invalid: true }] }).why, /managed/);
  assert.match(shellEnvironment({ record: { ...rec, env: { ...rec.env, CLAUDE_CODE_REMOTE: "true" } }, input: bash("true") }).why, /CLAUDE_CODE_REMOTE/);
  assert.match(shellEnvironment({ record: { ...rec, settingSources: ["user", "project"] }, input: bash("true") }).why, /setting sources/);
  assert.match(shellEnvironment({ record: rec, input: pre(sb, "PowerShell", { command: "gh auth status" }, { session_id: SESSION_ID }) }).why, /PowerShell/);
  fs.writeFileSync(path.join(ok.cfg, "remote-settings.json"), "{}");
  assert.match(envFor(ok).why, /server-managed/);
  // The record: only the launcher's, for this session.
  const file = path.join(ok.s.dir, CLAUDE_ENV_RECORD);
  fs.chmodSync(file, 0o644);
  assert.equal(readClaudeEnvironment(ok.s.session), null);
  fs.chmodSync(file, 0o600);
  assert.equal(readClaudeEnvironment({ ...ok.s.session, nonce: "another" }), null);
  assert.ok(readClaudeEnvironment(ok.s.session));
});

test("FP: a URL the person named, fetched by Python's standard library, runs", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const url = "http://127.0.0.1:8765/docs";
  const ses = session({ patch: { personUrls: [url] } });
  const cmd = `python3 << 'EOF'\nimport urllib.request\nresponse = urllib.request.urlopen('${url}')\nprint(response.read().decode('utf-8'))\nEOF`;
  const d = decide(ses, cmd);
  assert.equal(d.permissionDecision, "allow", d.permissionDecisionReason);
  // PYTHONPATH in the user settings: not the standard library any more.
  const py = session({ patch: { personUrls: [url] }, userSettings: { env: { PYTHONPATH: path.join(sb.project, "lib") } } });
  assert.notEqual(decide(py, cmd).permissionDecision, "allow");
});

test("the snapshot parser and the command words", () => {
  if (linux) {
    const home = fs.mkdtempSync(path.join(sb.dir, "h-"));
    fs.writeFileSync(path.join(home, ".bashrc"), "alias ll='ls -alF'\nalias sp='sudo '\nf() { echo \"}\"; }\n");
    for (const flagRws of [false, true]) {
      const cfg = fs.mkdtempSync(path.join(sb.dir, "c-"));
      const p = parseShellSnapshot(fs.readFileSync(makeClaudeSnapshot({ configDir: cfg, home, pathValue: "/usr/bin:/bin:/a b", flagRws }), "utf8"));
      assert.ok(p.ok, p.why);
      assert.equal(p.path, "/usr/bin:/bin:/a b");
      assert.ok(p.userNames.includes("ll") && p.userNames.includes("f") && p.expandsNext);
      assert.ok(!p.userNames.includes("grep") && !p.userNames.includes("rg"), "Claude Code's own shadows are not the person's");
    }
  }
  const words = (c) => [...commandWords(c).words];
  assert.deepEqual(words("ls -la && (gh auth status 2>&1 | head -5 || true)"), ["ls", "gh", "head", "true"]);
  assert.deepEqual(words('cd "$PWD" && git log'), ["cd", "git"]);
  assert.deepEqual(words("A=1 2>/dev/null gh x"), ["gh"]);
  for (const c of ["$(printf gh) x", "g''h x", "\\gh x", "x=$(gh api user)", "echo `gh x`", "{g,}h x", "cat <<EOF\n$(gh x)\nEOF", "eval 'gh x'", "if gh x; then :; fi", "cat <(gh x)"]) {
    assert.equal(mayInvoke(c, ["gh"]), true, c);
  }
  assert.equal(mayInvoke('[ "$ok" = 1 ] && ls', ["gh"]), false);
  assert.equal(mayInvoke("[gh]h x", ["gh"]), true);
  for (const c of ["env | grep -i github", 'cd "$PWD" && ls', "python3 << 'EOF'\nprint('gh')\nEOF", "echo gh"]) {
    assert.equal(mayInvoke(c, ["gh"]), false, c);
  }
  assert.equal(mayInvoke("echo gh", ["sp", "gh"], { everyWord: true }), true);
  assert.equal(mayInvoke("ls", ["command_not_found_handle"]), true);
});

test("the launcher records exactly the environment claude starts with, its PATH marker and a SHLVL of 1; with no snapshot of the session the hook gives the kit none", () => {
  const out = path.join(sb.dir, "claude-launch.json");
  const call = { ...bash("gh auth status"), session_id: SESSION_ID };
  const res = runLauncher(sb, ["-p", "check gh"], { SHLVL: "1", FAKE_CLAUDE_FULL_ENV: "1", FAKE_CLAUDE_NO_SNAPSHOT: "1", FAKE_CLAUDE_OUT: out, FAKE_CLAUDE_HOOK_INPUT: JSON.stringify(call) });
  assert.equal(res.status, 0, res.stderr);
  const rec = JSON.parse(fs.readFileSync(out, "utf8"));
  assert.ok(rec.claudeEnvRecord, "claude-env.json is written before claude starts");
  assert.deepEqual(rec.claudeEnvRecord.env, rec.processEnv);
  assert.deepEqual(rec.claudeEnvRecord.settingSources, ["user"]);
  assert.equal(rec.claudeEnvRecord.settingsFile, rec.settingsPath);
  assert.equal(rec.claudeEnvRecord.pathMarker, path.join(path.dirname(rec.settingsPath), "no-programs"));
  assert.ok(rec.processEnv.PATH.endsWith(`:${rec.claudeEnvRecord.pathMarker}`));
  assert.equal(rec.processEnv.SHLVL, "1");
  // The stand-in claude writes no shell snapshot: a command would run in a login shell, so the environment stays unknown and gh
  // is irreversible: in -p, in the default bypass mode, nobody can be asked, so it is denied.
  assert.equal(JSON.parse(rec.hookOutput).hookSpecificOutput.permissionDecision, "deny");
  assert.match(JSON.parse(rec.hookOutput).hookSpecificOutput.permissionDecisionReason, /needs a person/);
  // Without SHLVL in the shell that started Enclawed Code, claude gets 1 (bash then reads no startup file per command).
  const res2 = runLauncher(sb, ["-p", "check gh"], { SHLVL: "0", FAKE_CLAUDE_FULL_ENV: "1", FAKE_CLAUDE_NO_SNAPSHOT: "1", FAKE_CLAUDE_OUT: out, FAKE_CLAUDE_HOOK_INPUT: JSON.stringify(call) });
  assert.equal(res2.status, 0, res2.stderr);
  assert.equal(JSON.parse(fs.readFileSync(out, "utf8")).processEnv.SHLVL, "1");
});


test("attack: a function exported in claude's environment (BASH_FUNC_gh%%) is the shell's gh: gh asks; Claude Code's own names are unknown, never absent when credential-shaped", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const fn = '() {  GH_TOKEN=ghp_exported_fn_0000000000000000000000 command gh "$@"\n}';
  const ses = session({ extraEnv: { "BASH_FUNC_gh%%": fn } });
  // bash imports it: the command's gh is the function.
  const r = spawnSync("/bin/bash", ["-c", "type -t gh"], { env: { ...ses.env }, encoding: "utf8", input: "" });
  assert.equal(r.stdout.trim(), "function");
  for (const c of GH) {
    assert.equal(envFor(ses, c).environment, null, c);
    assert.notEqual(decide(ses, c).permissionDecision, "allow", c);
  }
  assert.ok(envFor(ses, "ls").environment);
  const managed = session({ extraEnv: { CLAUDE_CODE_SHOWN_PLUGINS_DIR: "/opt/shown", ANTHROPIC_BASE_URL: "https://example.invalid", ANTHROPIC_API_KEY: "sk-ant-placeholder-000000000000" } });
  const e = envFor(managed).environment;
  assert.ok(!("CLAUDE_CODE_SHOWN_PLUGINS_DIR" in e) && !("ANTHROPIC_BASE_URL" in e), "Claude Code may change or remove them: unknown");
  assert.equal(e.ANTHROPIC_API_KEY, "sk-ant-placeholder-000000000000");
});

// ---- the shell's aliases and functions (EngineOptions.shellDefinitions) ----

/** Allowed to run as given in the person's shell (not rewritten into a containment). */
const runsBare = (d, c) => d.permissionDecision === "allow" && (d.updatedInput?.command ?? c) === c;
/** What real bash prints for `line` after sourcing this session's snapshot, as Claude Code's Bash tool does. */
function inSnapshotShell(ses, line) {
  const dir = path.join(ses.cfg, "shell-snapshots");
  const snap = path.join(dir, fs.readdirSync(dir).find((n) => n.startsWith("snapshot-bash-")));
  const r = spawnSync("/bin/bash", ["-c", `source ${JSON.stringify(snap)}; eval ${JSON.stringify(line)}`], { env: { ...ses.env }, encoding: "utf8", input: "", cwd: sb.project });
  return `${r.stdout}${r.stderr}`;
}

test("attack: the login shell aliases ls to a deletion: the snapshot's ls is the alias, so ls is never read-only; \\ls is the real ls", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const ses = session({ rc: "alias ls='echo WOULD-RM-RF-HOME'\nshopt -s expand_aliases\n" });
  assert.match(inSnapshotShell(ses, "ls -la"), /WOULD-RM-RF-HOME/);
  // The person's alias, as the snapshot carries it (the login shell's system functions, such as /etc/profile.d's, come along).
  assert.equal(envFor(ses).definitions.aliases.ls, "echo WOULD-RM-RF-HOME");
  for (const c of ["ls -la", "ls; cat README.md", "git status && ls"]) {
    const d = decide(ses, c);
    assert.equal(runsBare(d, c), false, `${c}: ${d.permissionDecision} ${d.permissionDecisionReason}`);
  }
  assert.doesNotMatch(inSnapshotShell(ses, "\\ls -d /"), /WOULD/);
  assert.equal(decide(ses, "\\ls -la").permissionDecision, "allow");
});

test("attack: the login shell defines ls as a function that sends files out: quoted or not, ls is never read-only", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const ses = session({ rc: "ls() { echo WOULD-CURL; }\n" });
  assert.match(inSnapshotShell(ses, "\\ls"), /WOULD-CURL/);
  assert.ok(envFor(ses).definitions.functions.includes("ls"));
  for (const c of ["ls -la", "\\ls -la", "'ls' -la", "cat README.md | ls"]) {
    const d = decide(ses, c);
    assert.equal(runsBare(d, c), false, `${c}: ${d.permissionDecision} ${d.permissionDecisionReason}`);
  }
  assert.equal(decide(ses, "cat README.md").permissionDecision, "allow");
});

test("attack: a function exported in claude's environment (BASH_FUNC_ls%%) is the shell's ls: ls is never read-only", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const ses = session({ extraEnv: { "BASH_FUNC_ls%%": "() {  echo WOULD-EXFIL\n}" } });
  assert.match(inSnapshotShell(ses, "ls"), /WOULD-EXFIL/);
  assert.ok(envFor(ses).definitions.functions.includes("ls"));
  assert.equal(runsBare(decide(ses, "ls -la"), "ls -la"), false);
});

test("attack: a person's function named after a builtin Claude Code's own shadows call (command) runs inside them: grep and find are the person's code too", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const ses = session({ rc: 'command() { echo WOULD-RUN >&2; builtin command "$@"; }\n' });
  assert.match(inSnapshotShell(ses, "grep -c x README.md"), /WOULD-RUN/);
  const defs = envFor(ses).definitions;
  assert.ok(["command", "grep", "find", "rg"].every((n) => defs.functions.includes(n)), JSON.stringify(defs));
  assert.equal(runsBare(decide(ses, "grep -n x README.md"), "grep -n x README.md"), false);
});

test("fail closed: with the shell's definitions unknown (no snapshot: a login shell runs the command) no command word is the program of its name", { skip: !linux && "Claude Code's Linux shell" }, () => {
  const ses = session({ snapshot: false });
  assert.equal(envFor(ses).definitions, "unknown");
  for (const c of ["ls -la", "cat README.md", "git status"]) {
    const d = decide(ses, c);
    assert.notEqual(d.permissionDecision, "allow", `${c}: ${d.permissionDecisionReason}`);
  }
});

test("FP: nothing defined, or ls='ls --color=auto': ls, cat, grep, find and git stay read-only", { skip: !linux && "Claude Code's Linux shell" }, () => {
  for (const rc of ["export HISTSIZE=1000\n", "alias ls='ls --color=auto'\n"]) {
    const ses = session({ rc });
    for (const c of ["ls -la", "cat README.md", "grep -n x README.md", "find . -name '*.md'", "git status"]) {
      const d = decide(ses, c);
      assert.equal(runsBare(d, c), true, `${rc} ${c}: ${d.permissionDecision} ${d.permissionDecisionReason}`);
    }
  }
});

test("managed mode: every bash snapshot in claude's config directory counts, and anything the hook cannot see is unknown", () => {
  const base = fs.mkdtempSync(path.join(sb.dir, "m-"));
  const cfg = path.join(base, "cfg");
  const proj = path.join(base, "proj");
  fs.mkdirSync(path.join(cfg, "shell-snapshots"), { recursive: true });
  fs.mkdirSync(path.join(proj, ".claude"), { recursive: true });
  const home = path.join(base, "home");
  fs.mkdirSync(home);
  const claudeEnv = { HOME: home, PATH: "/usr/bin:/bin", SHLVL: "1", CLAUDE_CONFIG_DIR: cfg };
  const m = (extra = {}) => managedShellDefinitions({ claudeEnv, claudeArgs: [], projectDir: proj, sessionId: SESSION_ID, managedDocs: [], platform: "linux", ...extra });
  assert.equal(m().definitions, "unknown", "no snapshot: a login shell");
  fs.writeFileSync(path.join(home, ".bashrc"), "alias ll='ls -l'\n");
  makeClaudeSnapshot({ configDir: cfg, home, pathValue: claudeEnv.PATH, env: claudeEnv });
  fs.writeFileSync(path.join(home, ".bashrc"), "stat() { :; }\n");
  makeClaudeSnapshot({ configDir: cfg, home, pathValue: claudeEnv.PATH, env: claudeEnv, now: Date.now() + 1 });
  const both = m().definitions;
  assert.equal(both.aliases.ll, "ls -l", JSON.stringify(m()));
  assert.ok(both.functions.includes("stat") && !both.functions.includes("git"), JSON.stringify(both));
  fs.writeFileSync(path.join(proj, ".claude", "settings.json"), JSON.stringify({ env: { "BASH_FUNC_git%%": "() { :; }" } }));
  assert.ok(m().definitions.functions.includes("git"));
  for (const [why, extra] of [
    ["CLAUDE_ENV_FILE", { claudeEnv: { ...claudeEnv, CLAUDE_ENV_FILE: "/tmp/x" } }],
    ["--settings", { claudeArgs: ["--settings", "/tmp/s.json"] }],
    ["SHLVL", { claudeEnv: { ...claudeEnv, SHLVL: "0" } }],
    ["platform", { platform: "darwin" }],
    ["environ", { claudeEnv: null }],
  ]) {
    assert.equal(m(extra).definitions, "unknown", why);
  }
  fs.writeFileSync(path.join(cfg, "shell-snapshots", "snapshot-zsh-1-abc.sh"), "# zsh\n");
  assert.equal(m().definitions, "unknown", "a zsh snapshot");
});
