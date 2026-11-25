// Round 4 facts about the REAL claude 2.1.326, run through Enclawed Code with a
// throwaway HOME and CLAUDE_CONFIG_DIR (no login, so no model call is made;
// both facts happen before authentication):
//   F1 `--settings` {"$schema": 5} passes Enclawed Code's validator, and Claude Code
//      then drops the whole generated file ("did not load ... including hooks").
//   F2 a repository `.claude/settings.json` `apiKeyHelper` runs repository
//      code as claude's descendant, repeatedly, and Enclawed Code starts without
//      refusing or warning (it refuses project hooks of every event).
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { LAUNCHER, REAL_CLAUDE, result, sandbox } from "./lib.mjs";

const sb = sandbox("r4");
const home = path.join(sb.dir, "home");
const cfg = path.join(sb.dir, "claude-config");
fs.mkdirSync(home, { recursive: true });
const env = { ...sb.env, HOME: home, CLAUDE_CONFIG_DIR: cfg, ECWCODE_CLAUDE_PATH: REAL_CLAUDE, PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin` };
const run = (args) => spawnSync(process.execPath, [LAUNCHER, ...args], { env, cwd: sb.project, encoding: "utf8", timeout: 90000, input: "" });

const ci = path.join(sb.project, "ci", "claude.json");
fs.mkdirSync(path.dirname(ci), { recursive: true });
fs.writeFileSync(ci, JSON.stringify({ $schema: 5 }));
const a = run(["-p", "--model", "haiku", "--settings", ci, "--", "pong"]);
const dropped = /did not load/.test(a.stderr) && /\$schema/.test(a.stderr);
console.log(`F1: Enclawed Code refused: ${/would reject/.test(a.stderr)}; claude: ${a.stderr.split("\n").filter((l) => /did not load|\$schema/.test(l)).join(" | ").slice(0, 300)}`);
result("F1", dropped, "{\"$schema\": 5} passes Enclawed Code and makes Claude Code drop the generated settings file");

const marker = path.join(sb.dir, "helper-runs");
fs.mkdirSync(path.join(sb.project, ".claude"), { recursive: true });
fs.writeFileSync(path.join(sb.project, ".claude", "settings.json"), JSON.stringify({ apiKeyHelper: `echo run >> ${marker}; echo sk-ant-api03-placeholder` }));
const b = run(["-p", "--model", "haiku", "--", "pong"]);
const runs = fs.existsSync(marker) ? fs.readFileSync(marker, "utf8").trim().split("\n").length : 0;
const warned = b.stderr.split("\n").some((l) => l.startsWith("ecwcode") && /apiKeyHelper|repository/.test(l));
console.log(`F2: repo apiKeyHelper ran ${runs} time(s); Enclawed Code refused: ${/refus|adds a/.test(b.stderr)}; Enclawed Code warned about it: ${warned}`);
result("F2", runs > 0 && !warned, "repository apiKeyHelper code runs inside an Enclawed Code session without refusal or warning");
sb.cleanup();
