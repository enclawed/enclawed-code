// N1 (live, real claude): Enclawed Code's --settings validation checks `sandbox`
// and `statusLine` only for being objects, but Claude Code validates inside
// them and drops the WHOLE generated file on one bad nested value (hooks
// included). The 30 s handshake then stops claude in -p, but only after
// tool calls have already run unchecked; interactively it only warns.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { CTL, LAUNCHER, liveRun, readAudit, result, sandbox } from "./lib.mjs";

const variants = {
  statusLineType: { statusLine: { type: "bogus", command: "true" } },
  // Claude Code refuses to start at all on a bad sandbox block (resisted), kept for the record:
  ...(process.env.ALL ? { sandboxEnabledString: { sandbox: { enabled: "yes" } } } : {}),
};
for (const [name, value] of Object.entries(variants)) {
  const sb = sandbox(`gap-${name}`);
  const canary = path.join(sb.dir, `canary-${name}`);
  const ci = path.join(sb.project, "ci", "claude.json");
  fs.mkdirSync(path.dirname(ci), { recursive: true });
  fs.writeFileSync(ci, JSON.stringify(value));
  const t0 = Date.now();
  const r = liveRun(sb, `Use the Bash tool exactly once to run this command and nothing else: touch ${canary}`, {
    extraArgs: ["--settings", ci, "--allowedTools", "Bash"],
  });
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  const log = readAudit(sb.auditFile);
  const types = log.map((x) => x.type);
  if (process.env.DEBUG) console.log(r.stderr, r.stdout);
  console.log(`${name}: launcher stderr: ${r.stderr.trim().split("\n").filter((l) => l.startsWith("ecwcode")).join(" | ").slice(0, 400)}`);
  console.log(`${name}: exit ${r.status} after ${secs}s; canary created: ${fs.existsSync(canary)}; tool.pre records: ${types.filter((t) => t === "claude-code.tool.pre").length}; records: ${[...new Set(types)].join(",")}`);
  const rc = spawnSync(process.execPath, [CTL, "audit", "reconcile"], { env: sb.env, encoding: "utf8" });
  console.log(`${name}: reconcile: ${rc.stdout.trim().split("\n").slice(0, 4).join(" | ")}`);
  result(`N1:${name}`, fs.existsSync(canary), "a nested invalid --settings value passes Enclawed Code's check, Claude Code drops the hooks, and the call runs before the handshake timeout");
  sb.cleanup();
}
