// R5-V: differential test of Enclawed Code's generated --settings validator
// against the real claude 2.1.326 (throwaway HOME/CLAUDE_CONFIG_DIR, no
// login: Claude Code validates settings before it authenticates). For every
// candidate Enclawed Code ACCEPTS, claude is run with it as --settings; a
// "did not load" (whole-file drop) means Enclawed Code's hooks would be gone.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { validateSettings } from "../../../src/settings.mjs";
import { REAL_CLAUDE, result } from "./lib.mjs";

const big = "x".repeat(200000);
const cands = [
  { $schema: "" }, { $schema: big }, { model: "" }, { model: "\u0000" },
  { cleanupPeriodDays: 1.0 }, { cleanupPeriodDays: 1e300 }, { cleanupPeriodDays: "1" },
  { statusLine: { type: "command", command: "" } }, { statusLine: { type: "command", command: "true", padding: -1 } },
  { statusLine: { type: "command", command: "true", padding: 1.5 } }, { statusLine: { type: "command", command: "true", hideVimModeIndicator: "x" } },
  { statusLine: { type: "command", command: "true", refreshInterval: 0 } }, { statusLine: { type: "command", command: "true", extra: 1 } },
  { theme: 5 }, { forceLoginMethod: 5 }, { language: 5 },
  { env: { A: 1 } }, { env: { A: null } }, { env: { "": "" } }, { env: { "A\u0000": "b" } }, { env: [] },
  { hooks: { Stop: [{ hooks: [] }] } }, { hooks: { Stop: {} } }, { hooks: { Stop: [{}] } }, { hooks: { Stop: [{ hooks: {} }] } },
  { hooks: { Stop: [{ hooks: [{ type: "command", command: "true", once: "yes" }] }] } },
  { hooks: { Stop: [{ hooks: [{ type: "command", command: "true", cloud: "x" }] }] } },
  { hooks: { Stop: [{ matcher: 5, hooks: [] }] } }, { hooks: [] }, { hooks: null },
  { permissions: { allow: "Bash" } }, { permissions: { deny: [1] } }, { permissions: { defaultMode: null } },
  { permissions: { additionalDirectories: [1] } }, { permissions: { blockReadsExemptPaths: [1] } }, { permissions: [] }, { permissions: null },
  { permissions: { disableBypassPermissionsMode: "enable" } }, { permissions: { foo: 1 } },
  { enabledMcpjsonServers: [1] }, { enabledMcpjsonServers: "x" }, { disabledMcpjsonServers: [null] },
  { includeCoAuthoredBy: "true" }, { alwaysThinkingEnabled: 1 }, { respectGitignore: null },
  { apiKeyHelper: 5 }, { outputStyle: 5 },
];
const accepted = cands.filter((c) => validateSettings(c).length === 0);
console.log(`Enclawed Code accepts ${accepted.length} of ${cands.length} candidates`);
const d = fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-rt-fuzz-"));
fs.mkdirSync(path.join(d, "home")); fs.mkdirSync(path.join(d, "cfg"));
const env = {};
for (const [k, v] of Object.entries(process.env)) if (!/^(CLAUDE|CLAUDECODE|AI_AGENT)/.test(k)) env[k] = v;
Object.assign(env, { HOME: path.join(d, "home"), CLAUDE_CONFIG_DIR: path.join(d, "cfg") });
const drops = [];
for (const c of accepted) {
  const f = path.join(d, "s.json");
  fs.writeFileSync(f, JSON.stringify(c));
  const r = spawnSync(REAL_CLAUDE, ["-p", "--model", "haiku", "--settings", f, "--", "pong"], { env, cwd: d, encoding: "utf8", timeout: 60000, input: "" });
  const out = (r.stdout + r.stderr);
  const drop = /did not load/.test(out);
  const shown = JSON.stringify(c).slice(0, 90);
  console.log(`  ${drop ? "DROP " : "ok   "} ${shown}${drop ? `  <- ${out.split("\n").find((l) => l.includes(d))?.trim().slice(0, 120)}` : ""}`);
  if (drop) drops.push(shown);
}
fs.rmSync(d, { recursive: true, force: true });
result("R5-V", drops.length > 0, `${drops.length} value(s) pass Enclawed Code's validator and make Claude Code drop the file: ${drops.join("; ")}`);
