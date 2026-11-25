// N11: the round-3 secret-path deny list (src/secrets.mjs) versus read-only
// commands and read tools that reach a secret without naming its exact path:
// globs, a parent directory with a recursive search, and Glob/Grep on a parent.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createSession } from "../../../src/session.mjs";
import { hookCommand } from "../../../src/settings.mjs";
import { authDir } from "../../../src/auth.mjs";
import { pre, result, sandbox } from "./lib.mjs";

const sb = sandbox("n11");
const home = path.join(sb.dir, "home");
fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
fs.writeFileSync(path.join(home, ".claude", ".credentials.json"), '{"claudeAiOauth":{"accessToken":"FAKE-TOKEN-FOR-TEST"}}');
sb.env.HOME = home;
sb.ticket(); // the sandbox's throwaway credential (lib.mjs)
const s = createSession({ env: sb.env, cwd: sb.project });
const cmd = hookCommand({ origin: "launcher", session: s.file, digest: s.digest });
const sessRoot = path.dirname(path.dirname(s.file));
const decide = (tool, ti) => {
  const r = spawnSync("/bin/sh", ["-c", cmd], { input: JSON.stringify(pre(sb, tool, ti)), env: { ...sb.env, CLAUDE_PROJECT_DIR: sb.project }, cwd: sb.project, encoding: "utf8" });
  try { return JSON.parse(r.stdout).hookSpecificOutput.permissionDecision; } catch { return `exit ${r.status}`; }
};
const probes = [
  ["cat ~/.claude/.cred*", "Bash", { command: "cat ~/.claude/.cred*" }],
  ["cat ~/.claude/.credentials.jso?", "Bash", { command: "cat ~/.claude/.credentials.jso?" }],
  ["grep -r accessToken ~/.claude", "Bash", { command: "grep -r accessToken ~/.claude" }],
  ["grep -r accessToken <home>", "Bash", { command: `grep -r accessToken ${home}` }],
  ["Grep accessToken in ~/.claude", "Grep", { pattern: "accessToken", path: path.join(home, ".claude"), output_mode: "content" }],
  ["Grep nonce in the session root", "Grep", { pattern: "nonce", path: sessRoot, output_mode: "content" }],
  ["grep -r nonce <session root>", "Bash", { command: `grep -r nonce ${sessRoot}` }],
  ["cat <session root>/s-*/session.json", "Bash", { command: `cat ${sessRoot}/s-*/session.json` }],
  ["Grep hash in the state dir", "Grep", { pattern: "hash", path: sb.state, output_mode: "content" }],
  ["cat <state>/claude-code/a*.json", "Bash", { command: `cat ${sb.state}/claude-code/a*.json` }],
];
let open = 0;
for (const [label, tool, ti] of probes) {
  const d = decide(tool, ti);
  console.log(`  ${label}: ${d}`);
  if (d === "allow") open++;
}
result("N11", open > 0, `${open}/${probes.length} indirect reads of the login, the session secrets or the auth hash are allowed`);
sb.cleanup();
