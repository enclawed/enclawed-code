#!/usr/bin/env node
// A stand-in for Claude Code's interactive, full-screen UI (test/interactive-parity.test.mjs).
// It records how it was started (argv, which of stdin/stdout/stderr are
// terminals, the terminal's size, its whole environment), then behaves like a
// full-screen UI: raw mode, cursor hidden, bracketed paste on, and it records
// every byte it reads, every SIGWINCH (with the size it then reads), SIGINT
// (handled: it goes on, as Claude Code does) and SIGCONT. It ends on the byte
// Ctrl-] (0x1d) with exit code TTY_CLAUDE_EXIT (default 0).
//
// Like Claude Code it runs the SessionStart hook of its --settings first
// (Enclawed Code's launcher waits for that handshake), and, with
// TTY_CLAUDE_HOOK_INPUT, runs one PreToolUse call through the hook while the
// UI owns the terminal (asynchronously, as Claude Code does), writing the call
// to the session transcript first.
//
// TTY_CLAUDE_LOG: the JSON-lines file every event goes to.
import { execSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
if (args[0] === "--version") {
  process.stdout.write("2.1.326 (Claude Code)\n");
  process.exit(0);
}
const logFile = process.env.TTY_CLAUDE_LOG;
const log = (event) => fs.appendFileSync(logFile, `${JSON.stringify({ t: Date.now(), ...event })}\n`);
const size = () => ({ columns: process.stdout.columns ?? null, rows: process.stdout.rows ?? null });

if (process.platform === "linux" && process.env.HOME) {
  const { makeClaudeSnapshot } = await import("./claude-snapshot.mjs");
  makeClaudeSnapshot({ configDir: process.env.CLAUDE_CONFIG_DIR || path.join(process.env.HOME, ".claude"), home: process.env.HOME, pathValue: process.env.PATH ?? "", env: { ...process.env } });
}
process.on("SIGWINCH", () => setImmediate(() => log({ event: "winch", size: size() })));
process.on("SIGINT", () => log({ event: "sigint" }));
process.on("SIGCONT", () => log({ event: "sigcont" }));
process.stdout.on("resize", () => log({ event: "resize", size: size() }));
// Whether this process's group owns the terminal (the foreground group), as `ps` reports it.
const ps = spawnSync("ps", ["-o", "pgid=,tpgid=", "-p", String(process.pid)], { encoding: "utf8" }).stdout.trim().split(/\s+/).map(Number);
log({ event: "start", foreground: ps.length === 2 && ps[0] === ps[1], argv: args, tty: { stdin: Boolean(process.stdin.isTTY), stdout: Boolean(process.stdout.isTTY), stderr: Boolean(process.stderr.isTTY) }, size: size(), env: { ...process.env }, pid: process.pid, ppid: process.ppid });

const si = args.indexOf("--settings");
const settings = si >= 0 ? JSON.parse(fs.readFileSync(args[si + 1], "utf8")) : null;
log({ event: "settings", settings });
const hookEnv = { ...process.env, CLAUDE_PROJECT_DIR: process.cwd() };
const transcript = path.join(process.env.CLAUDE_CONFIG_DIR || path.join(process.env.HOME, ".claude"), "projects", process.cwd().replace(/[^a-zA-Z0-9]/g, "-"), "fake-session.jsonl");
// Like Claude Code, every other SessionStart hook of the session runs too: the user's settings
// (when --setting-sources has "user"), --settings, enabled plugins (installed_plugins.json and
// enabledPlugins, --settings over user) and --plugin-dir plugins. A test's hook writes a marker.
const readJson = (f) => {
  try {
    return JSON.parse(fs.readFileSync(f, "utf8"));
  } catch {
    return null;
  }
};
const configDir = process.env.CLAUDE_CONFIG_DIR || path.join(process.env.HOME, ".claude");
const ssArg = args.find((a) => a.startsWith("--setting-sources="));
const sources = ssArg === undefined ? ["user", "project", "local"] : ssArg.slice("--setting-sources=".length).split(",").filter(Boolean);
const userDoc = sources.includes("user") ? readJson(path.join(configDir, "settings.json")) : null;
const otherStarts = [];
const startsOf = (doc) => (doc?.hooks?.SessionStart ?? []).flatMap((m) => m?.hooks ?? []).map((h) => h?.command).filter((c) => typeof c === "string");
otherStarts.push(...startsOf(userDoc));
const enabled = { ...(userDoc?.enabledPlugins ?? {}), ...(settings?.enabledPlugins ?? {}) };
const installed = readJson(path.join(configDir, "plugins", "installed_plugins.json"))?.plugins ?? {};
const pluginRoots = Object.entries(enabled)
  .filter(([, on]) => on === true)
  .flatMap(([id]) => (Array.isArray(installed[id]) ? installed[id] : installed[id] ? [installed[id]] : []).map((e) => e.installPath));
args.forEach((a, i) => {
  if (a === "--plugin-dir" && args[i + 1]) {
    pluginRoots.push(path.resolve(args[i + 1]));
  }
});
for (const r of pluginRoots) {
  otherStarts.push(...startsOf(readJson(path.join(r, "hooks", "hooks.json"))));
}
const ownStart = settings?.hooks?.SessionStart?.at(-1)?.hooks?.[0]?.command;
for (const c of [...startsOf(settings).filter((c) => c !== ownStart), ...otherStarts]) {
  try {
    execSync(c, { shell: "/bin/sh", stdio: "ignore", env: hookEnv });
  } catch {
    /* a failing hook does not stop Claude Code */
  }
}
log({ event: "other-hooks", count: otherStarts.length + startsOf(settings).filter((c) => c !== ownStart).length });
if (settings) {
  const start = settings.hooks?.SessionStart?.at(-1)?.hooks?.[0]?.command;
  if (start) {
    try {
      execSync(start, { input: JSON.stringify({ hook_event_name: "SessionStart", session_id: "fake-session", cwd: process.cwd(), source: "startup", transcript_path: transcript }), shell: "/bin/sh", encoding: "utf8", env: hookEnv });
    } catch {
      /* a failing SessionStart hook does not stop Claude Code */
    }
  }
}


if (args.includes("-p") || args.includes("--print")) {
  // Headless, like `claude -p`: no full-screen UI; it answers and ends (after TTY_CLAUDE_PRINT_WAIT_MS).
  process.stdout.write("PRINT-ANSWER\n");
  setTimeout(() => {
    log({ event: "exit" });
    process.exit(Number(process.env.TTY_CLAUDE_EXIT ?? 0));
  }, Number(process.env.TTY_CLAUDE_PRINT_WAIT_MS ?? 0));
} else if (!process.stdin.isTTY) {
  log({ event: "no-tty" });
  process.exit(Number(process.env.TTY_CLAUDE_EXIT ?? 0));
} else {
  ui();
}

function ui() {
  process.stdin.setRawMode(true);
  process.stdout.write("\x1b[?25l\x1b[?2004hTUI-READY\r\n");
  log({ event: "ready" });

  const inputs = [process.env.TTY_CLAUDE_HOOK_INPUT, process.env.TTY_CLAUDE_HOOK_INPUT_2].filter(Boolean).map((x) => JSON.parse(x));
  // A call may carry `__response` (fixture only): when it is allowed, its PostToolUse
  // runs with that tool_response, as Claude Code runs it after the tool.
  const runPost = (hookInput, response, then) => {
    const cmd = settings.hooks.PostToolUse.at(-1).hooks[0].command;
    const h = spawn("/bin/sh", ["-c", cmd], { env: hookEnv, stdio: ["pipe", "pipe", "pipe"] });
    h.stdout.on("data", () => {});
    h.on("exit", (code) => {
      log({ event: "post", code });
      then();
    });
    h.stdin.end(JSON.stringify({ ...hookInput, hook_event_name: "PostToolUse", tool_response: response }));
  };
  const runCall = (full, n) => {
    const { __response: response, ...hookInput } = full;
    // Claude Code writes the call to the transcript while its PreToolUse hook runs.
    fs.mkdirSync(path.dirname(transcript), { recursive: true });
    fs.appendFileSync(transcript, `${JSON.stringify({ type: "assistant", sessionId: "fake-session", message: { role: "assistant", content: [{ type: "tool_use", id: hookInput.tool_use_id, name: hookInput.tool_name, input: hookInput.tool_input }] } })}\n`);
    const cmd = settings.hooks.PreToolUse.at(-1).hooks[0].command;
    const h = spawn("/bin/sh", ["-c", cmd], { env: hookEnv, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    h.stdout.on("data", (d) => (out += d));
    h.on("exit", (code) => {
      let decision = null;
      let reason = null;
      let systemMessage = null;
      try {
        const whole = JSON.parse(out || "null");
        decision = whole?.hookSpecificOutput?.permissionDecision ?? null;
        reason = whole?.hookSpecificOutput?.permissionDecisionReason ?? null;
        systemMessage = whole?.systemMessage ?? null;
      } catch {
        decision = null;
      }
      log({ event: "hook", n, code, decision, reason, systemMessage, raw: out });
      fs.appendFileSync(transcript, `${JSON.stringify({ type: "user", sessionId: "fake-session", message: { role: "user", content: [{ type: "tool_result", tool_use_id: hookInput.tool_use_id, content: "", is_error: decision !== "allow" }] } })}\n`);
      const next = () => {
        process.stdout.write(`HOOK-DONE ${n} ${decision}\r\n`);
        if (inputs[n + 1]) {
          runCall(inputs[n + 1], n + 1);
        }
      };
      if (decision === "allow" && response !== undefined) {
        runPost(hookInput, response, next);
      } else {
        next();
      }
    });
    h.stdin.end(JSON.stringify(hookInput));
  };
  if (inputs.length && settings) {
    runCall(inputs[0], 0);
  }

  process.stdin.on("data", (d) => {
    log({ event: "input", hex: d.toString("hex") });
    if (d.includes(0x1d)) {
      // Ctrl-]: leave the full-screen UI as Claude Code does, then exit.
      process.stdin.setRawMode(false);
      process.stdout.write("\x1b[?2004l\x1b[?25h");
      log({ event: "exit" });
      process.exit(Number(process.env.TTY_CLAUDE_EXIT ?? 0));
    }
  });
}
