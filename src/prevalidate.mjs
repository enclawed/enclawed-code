// The interactive "did not load" guard (round 5, N13c).
//
// Headless, claude's stderr is read and a "These settings files did not
// load ..." line naming Enclawed Code's generated file stops the session at once
// (round 4, F1). An interactive claude owns the terminal, so its stderr
// cannot be read without changing what the person sees. Instead, before the
// interactive launch, the real claude binary is run once headless on the
// same settings content, and the launch is refused when it reports that the
// file did not load.
//
// The one-shot run must not do anything: its hooks are replaced by `true`
// (same structure, so the same validation), it writes no transcript
// (--no-session-persistence), starts no MCP server (--strict-mcp-config
// without --mcp-config), it makes at most one model call with no
// retries, and that call goes to a local socket this process owns, which
// drops every connection (ANTHROPIC_BASE_URL, pinned in the settings `env`
// as well as in the environment), so no credential leaves the process tree
// and no tokens are spent. Without a login, claude stops at "Not logged in"
// after printing the settings check, which is all that is needed.

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { kit } from "./kit.mjs";

/** Claude Code's header before the settings files it did not load. */
export const DROP_HEADER = /did not load[^\n]*including hooks/;

/**
 * @param {{ claude: string, settingsFile: string, settingsDir: string, env: object, cwd: string, dropWatcher: (dir: string, onDrop: (line: string) => void) => (chunk: string) => void, runMs?: number }} o
 * @returns {Promise<{ ok: true, ran: boolean, note?: string } | { ok: false, line: string }>}
 */
export async function prevalidateSettings(o) {
  let settings;
  try {
    settings = JSON.parse(fs.readFileSync(o.settingsFile, "utf8"));
  } catch (err) {
    return { ok: true, ran: false, note: `cannot read the settings file (${err.message})` };
  }
  const sink = net.createServer((s) => s.destroy());
  await new Promise((r) => sink.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${sink.address().port}`;
  const file = path.join(o.settingsDir, "prevalidate.json");
  try {
    const copy = { ...settings, hooks: kit.neutralizeHookCommands(settings.hooks, "true"), env: { ...(settings.env && typeof settings.env === "object" ? settings.env : {}), ANTHROPIC_BASE_URL: base, CLAUDE_CODE_MAX_RETRIES: "0" } };
    fs.writeFileSync(file, `${JSON.stringify(copy, null, 2)}\n`, { mode: 0o600 });
    // Whether the settings were dropped is the kit's decision (settings-drop.ts);
    // starting claude on the copy, with no model behind it, is Enclawed Code's.
    return await kit.prevalidateSettings({
      settingsDir: o.settingsDir,
      header: DROP_HEADER,
      run: ({ onStderr, deadlineMs }) =>
        new Promise((resolve) => {
          let child;
          try {
            child = spawn(o.claude, ["-p", "--settings", file, "--no-session-persistence", "--strict-mcp-config", "--max-turns", "1", "--", "Reply with OK."], {
              cwd: o.cwd,
              env: { ...o.env, ANTHROPIC_BASE_URL: base, CLAUDE_CODE_MAX_RETRIES: "0", ECWCODE_PREVALIDATE_RUN: "1" },
              stdio: ["ignore", "ignore", "pipe"],
            });
          } catch {
            resolve(false);
            return;
          }
          const t = setTimeout(() => child.kill("SIGKILL"), o.runMs ?? deadlineMs);
          child.stderr.on("data", (d) => {
            if (onStderr(d.toString("utf8"))) {
              child.kill("SIGKILL");
            }
          });
          child.on("error", () => {
            clearTimeout(t);
            resolve(false);
          });
          child.on("exit", () => {
            clearTimeout(t);
            resolve(true);
          });
        }),
    });
  } finally {
    fs.rmSync(file, { force: true });
    sink.close();
  }
}
