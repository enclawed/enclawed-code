import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// bypassPermissions, Enclawed Code's default mode, with the REAL Claude Code
// binary (permission-mode.mjs). A stand-in for the Anthropic API
// (test/fixtures/fake-anthropic.mjs) plays the model: it asks for scripted tool
// calls, so no login and no model are involved. What must hold in bypass mode:
// a PreToolUse deny is enforced (the file it would delete is intact), an ask
// goes to Enclawed Code's own prompt and its answer is enforced, PostToolUse and
// SessionStart still run, a call Enclawed allows runs with no Claude Code
// dialog, and the one-time bypass confirmation never shows (it is pre-accepted
// in the session's own settings file, not in the person's ~/.claude).
//
// Needs the real claude (ECWCODE_REAL_CLAUDE, else ~/.local/bin/claude of
// ECWCODE_REAL_HOME or this user); skipped without it.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { ROOT, auditRecords, fakeFido2Env, issueTestTicket, launcherArgv, sandbox } from "./helpers.mjs";

const REAL = process.env.ECWCODE_REAL_CLAUDE ?? path.join(process.env.ECWCODE_REAL_HOME ?? os.homedir(), ".local", "bin", "claude");
const haveReal = (() => {
  try {
    fs.accessSync(fs.realpathSync(REAL), fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
})();
const havePty = spawnSync("python3", ["-c", "import os,pty,termios; os.login_tty"]).status === 0;
const skip = (!haveReal && "no real claude") || (!havePty && "no python3 pty") || (process.platform !== "linux" && "Linux only") || false;
const PTY_RUN = path.join(ROOT, "test", "fixtures", "pty-run.py");
const FAKE_API = path.join(ROOT, "test", "fixtures", "fake-anthropic.mjs");
const KEY = "sk-ant-api03-fake-key-for-tests-only-000000000000";

let sb;
before(() => {
  if (skip) {
    return;
  }
  sb = sandbox();
  // Claude Code's first-run state in the sandbox's own home (never the person's):
  // onboarding done, this API key approved, the project trusted.
  fs.writeFileSync(
    path.join(sb.home, ".claude.json"),
    JSON.stringify({ hasCompletedOnboarding: true, theme: "dark", numStartups: 5, customApiKeyResponses: { approved: [KEY.slice(-20)], rejected: [] }, projects: { [sb.project]: { hasTrustDialogAccepted: true, hasCompletedProjectOnboarding: true } } }),
  );
  fs.mkdirSync(path.join(sb.home, ".claude"), { recursive: true });
  spawnSync("git", ["init", "-q"], { cwd: sb.project });
});
after(() => sb?.cleanup());

/** Start the API stand-in with `steps`; returns { env, log, stop }. */
async function fakeApi(steps) {
  const dir = fs.mkdtempSync(path.join(sb.dir, "api-"));
  const script = path.join(dir, "script.json");
  const portFile = path.join(dir, "port");
  const log = path.join(dir, "api.jsonl");
  fs.writeFileSync(script, JSON.stringify(steps));
  const child = spawn(process.execPath, [FAKE_API, script, portFile], { env: { ...process.env, FAKE_ANTHROPIC_LOG: log }, stdio: "ignore" });
  for (let i = 0; i < 100 && !fs.existsSync(portFile); i++) {
    await new Promise((r) => setTimeout(r, 50));
  }
  const port = fs.readFileSync(portFile, "utf8").trim();
  return {
    env: { ANTHROPIC_BASE_URL: `http://127.0.0.1:${port}`, ANTHROPIC_API_KEY: KEY, DISABLE_AUTOUPDATER: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", DISABLE_TELEMETRY: "1" },
    requests: () =>
      fs.existsSync(log)
        ? fs
            .readFileSync(log, "utf8")
            .split("\n")
            .filter(Boolean)
            .map((l) => JSON.parse(l))
        : [],
    stop: () => child.kill(),
  };
}

const toolResults = (reqs) => reqs.filter((r) => r.main).flatMap((r) => r.toolResults ?? []);

function launcherEnv(api, extra = {}) {
  issueTestTicket(sb);
  return { ...sb.env, ...fakeFido2Env(sb), ECWCODE_CLAUDE_PATH: fs.realpathSync(REAL), TERM: "xterm-256color", ...api.env, ...extra };
}

function canaries() {
  const canary = path.join(sb.project, `canary-${Math.random().toString(36).slice(2, 8)}.txt`);
  fs.writeFileSync(canary, "keep me\n");
  const notes = path.join(sb.project, "notes.txt");
  fs.writeFileSync(notes, "the build is green\n");
  return { canary, notes };
}

test("-p in bypass mode (the default) with the real Claude Code: a denied call does not run (the file it would delete is intact), an allowed one runs with no prompt, and SessionStart and PostToolUse still run", { skip, timeout: 240_000 }, async () => {
  const { canary, notes } = canaries();
  const api = await fakeApi([
    { tool: "Bash", input: { command: `rm -f ${path.basename(canary)}`, description: "delete" } },
    { tool: "Read", input: { file_path: notes } },
    { text: "finished" },
  ]);
  try {
    const before = auditRecords(sb).length;
    const r = spawnSync(process.execPath, launcherArgv(sb, ["-p", "go", "--model", "sonnet"]), { env: launcherEnv(api), cwd: sb.project, encoding: "utf8", timeout: 180_000 });
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /finished/);
    assert.equal(fs.readFileSync(canary, "utf8"), "keep me\n", "the denied rm did not run");
    const results = toolResults(api.requests());
    assert.equal(results.length, 2, JSON.stringify(results));
    assert.equal(results[0].isError, true, JSON.stringify(results[0]));
    assert.match(results[0].text, /Enclawed/);
    assert.equal(results[1].isError, false, JSON.stringify(results[1]));
    assert.match(results[1].text, /the build is green/);
    const recs = auditRecords(sb).slice(before);
    const start = recs.find((x) => x.type === "claude-code.session.start");
    assert.ok(start, "SessionStart ran");
    assert.equal(start.payload?.permissionMode ?? start.payload?.permission_mode ?? "bypassPermissions", "bypassPermissions");
    const pres = recs.filter((x) => x.type === "claude-code.tool.pre");
    assert.deepEqual(pres.map((x) => [x.payload.tool, x.payload.answered]), [["Bash", "deny"], ["Read", "allow"]]);
    assert.ok(pres.every((x) => x.payload.hostMode === "bypassPermissions"), JSON.stringify(pres.map((x) => x.payload.hostMode)));
    assert.ok(recs.some((x) => x.type === "claude-code.tool.post" && x.payload?.tool === "Read"), "PostToolUse ran");
  } finally {
    api.stop();
  }
});

/** Run ecwcode ARGS with the real claude in a pty, driven by `steps` (test/fixtures/pty-run.py). */
function drive(args, steps, env, { rows = 40, cols = 120, timeoutS = 150 } = {}) {
  const cfg = path.join(sb.dir, `pty-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(cfg, JSON.stringify({ argv: [process.execPath, ...launcherArgv(sb, args)], env, cwd: sb.project, rows, cols, timeout_s: timeoutS, modes: null, steps }));
  const r = spawnSync("python3", ["-I", PTY_RUN, cfg], { encoding: "utf8", timeout: (timeoutS + 30) * 1000 });
  assert.equal(r.status, 0, r.stderr);
  const res = JSON.parse(r.stdout);
  return { ...res, screen: Buffer.from(res.output_hex, "hex").toString("latin1") };
}

const hex = (s) => Buffer.from(s, "utf8").toString("hex");

test("interactive in bypass mode (the default) with the real Claude Code: an ask goes to Enclawed Code's own prompt and its answer is enforced both ways, an allowed call runs with no Claude Code dialog, and the bypass confirmation never shows", { skip, timeout: 300_000 }, async () => {
  const kept = canaries().canary;
  const gone = canaries().canary;
  const { notes } = canaries();
  const api = await fakeApi([
    { tool: "Bash", input: { command: `rm -f ${path.basename(kept)}`, description: "delete one" } },
    { tool: "Bash", input: { command: `rm -f ${path.basename(gone)}`, description: "delete another" } },
    { tool: "Read", input: { file_path: notes } },
    { text: "finished-all-steps" },
  ]);
  try {
    const before = auditRecords(sb).length;
    const prompt = "To deny, type d and press Enter";
    const r = drive(
      ["--model", "sonnet", "go"],
      [
        { wait: prompt, timeout_s: 90 },
        { sleep: 0.5 },
        { write: hex("d\r") },
        { wait: `${prompt}(?:.|\\n)*${prompt}`, timeout_s: 60 },
        { sleep: 0.5 },
        { answer: {} },
        { wait: "finished-all-steps", timeout_s: 60 },
        { sleep: 0.5 },
        { write: "03" },
        { sleep: 0.3 },
        { write: "03" },
      ],
      launcherEnv(api),
    );
    const plain = r.screen.replace(/\x1b\[[0-9;?$>]*[A-Za-z]/g, "");
    assert.equal(r.failed_step, null, plain.slice(-4000));
    // The ask was answered at Enclawed Code's prompt, both ways, and enforced.
    assert.equal(fs.readFileSync(kept, "utf8"), "keep me\n", "the denied rm did not run");
    assert.equal(fs.existsSync(gone), false, "the approved rm ran");
    const results = toolResults(api.requests());
    assert.deepEqual(results.map((x) => x.isError), [true, false, false], JSON.stringify(results));
    // No Claude Code permission dialog and no bypass confirmation: Claude Code asked nothing.
    for (const t of [/Do you want to proceed\?/, /Yes, I accept/, /Allow this|don't ask again/i]) {
      assert.doesNotMatch(plain, t);
    }
    assert.match(plain, /bypass permissions on/i, "Claude Code's footer shows bypass mode");
    const recs = auditRecords(sb).slice(before);
    assert.ok(recs.some((x) => x.type === "claude-code.session.start"));
    const pres = recs.filter((x) => x.type === "claude-code.tool.pre");
    assert.deepEqual(pres.map((x) => [x.payload.tool, x.payload.decision, x.payload.answered]), [["Bash", "ask", "deny"], ["Bash", "ask", "allow"], ["Read", "allow", "allow"]]);
    assert.ok(pres.every((x) => x.payload.hostMode === "bypassPermissions"));
    assert.equal(recs.filter((x) => x.type === "claude-code.tool.post").length, 2, "PostToolUse for the two calls that ran");
    // The confirmation was pre-accepted only in the session's own settings file, never in this home's Claude Code files.
    for (const f of [path.join(sb.home, ".claude", "settings.json"), path.join(sb.home, ".claude.json")]) {
      assert.ok(!fs.existsSync(f) || !/skipDangerousModePermissionPrompt|bypassPermissionsModeAccepted/.test(fs.readFileSync(f, "utf8")), f);
    }
  } finally {
    api.stop();
  }
});

// The real managed settings path (/etc/claude-code) needs root; an overlay on /etc
// in a mount namespace of this (user-namespaced) test gives one to this launch only.
const canOverlay = !skip && spawnSync("sh", ["-c", "unshare -m true"]).status === 0 && (process.getuid?.() ?? 1) === 0;

test("bypass mode does not skip managed hooks: an administrator's managed SessionStart and PreToolUse hooks run in the real Claude Code, even with disableAllHooks in the person's settings", { skip: skip || (!canOverlay && "no mount namespace for /etc/claude-code"), timeout: 240_000 }, async () => {
  const { notes } = canaries();
  const marks = { start: path.join(sb.dir, "managed-start.mark"), pre: path.join(sb.dir, "managed-pre.mark") };
  for (const f of Object.values(marks)) {
    fs.rmSync(f, { force: true });
  }
  const managed = { hooks: { SessionStart: [{ hooks: [{ type: "command", command: `touch ${marks.start}` }] }], PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: `touch ${marks.pre}` }] }] } };
  // An earlier real session may have installed Claude Code's official plugin marketplace here.
  fs.rmSync(path.join(sb.home, ".claude", "plugins"), { recursive: true, force: true });
  const userSettings = path.join(sb.home, ".claude", "settings.json");
  fs.writeFileSync(userSettings, JSON.stringify({ disableAllHooks: true }));
  const ovl = fs.mkdtempSync(path.join(sb.dir, "etc-"));
  fs.mkdirSync(path.join(ovl, "up", "claude-code"), { recursive: true });
  fs.mkdirSync(path.join(ovl, "work"));
  fs.writeFileSync(path.join(ovl, "up", "claude-code", "managed-settings.json"), JSON.stringify(managed));
  const api = await fakeApi([{ tool: "Read", input: { file_path: notes } }, { text: "finished" }]);
  try {
    const launch = [process.execPath, ...launcherArgv(sb, ["-p", "go", "--model", "sonnet"])].map((a) => `'${a.replace(/'/g, `'\\''`)}'`).join(" ");
    const r = spawnSync("unshare", ["-m", "sh", "-c", `mount -t overlay overlay -o lowerdir=/etc,upperdir=${ovl}/up,workdir=${ovl}/work /etc && exec ${launch}`], { env: launcherEnv(api), cwd: sb.project, encoding: "utf8", timeout: 180_000 });
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /finished/);
    assert.ok(fs.existsSync(marks.start), "the managed SessionStart hook ran");
    assert.ok(fs.existsSync(marks.pre), "the managed PreToolUse hook ran");
    const results = toolResults(api.requests());
    assert.equal(results[0]?.isError, false, JSON.stringify(results));
    assert.match(results[0].text, /the build is green/);
  } finally {
    api.stop();
    fs.rmSync(userSettings, { force: true });
  }
});
