#!/usr/bin/env node
// Round-2 red-team driver: runs the REAL hook through the REAL session
// mechanism (createSession + --session/--digest), in a throwaway HOME/state,
// never touching real Enclawed state. Prints the permissionDecision.
//
//   node drive.mjs <projectDir> <<<'<PreToolUse JSON>'
//
// Env expected: HOME and ENCLAWED_STATE_DIR already pointed at throwaway dirs.
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createSession } from "../../../src/session.mjs";

const APP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const HOOK = path.join(APP, "bin", "ecwcode-hook.mjs");

const projectDir = process.argv[2];
let raw = "";
process.stdin.setEncoding("utf8");
for await (const c of process.stdin) raw += c;

const s = createSession({ env: process.env, cwd: projectDir });
const r = spawnSync(process.execPath, [HOOK, "--origin", "launcher", "--session", s.file, "--digest", s.digest], {
  input: raw,
  encoding: "utf8",
  env: { ...process.env, CLAUDE_PROJECT_DIR: s.session.projectDir },
  timeout: 30000,
});
let decision = "ERR";
try {
  decision = JSON.parse(r.stdout).hookSpecificOutput.permissionDecision;
} catch {
  /* leave ERR */
}
process.stdout.write(`${decision}\t${(r.stdout || r.stderr || "").replace(/\s+/g, " ").slice(0, 200)}\n`);
