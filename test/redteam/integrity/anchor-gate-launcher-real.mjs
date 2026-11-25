// Round 5 fix proof (R5-A) through the REAL launcher on the REAL Enclaweder
// (run with ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND; throwaway HOME, state, latch and log; a
// fake claude): the launch is refused (exit 6) before claude starts when the
// log does not match the device, and a session runs once a person accepted.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { LAUNCHER, ROOT, readAudit, result, sandbox } from "./lib.mjs";
import { authDir } from "../../../src/auth.mjs";
import { anchorFile, anchorHistoryFile, boundDevice } from "../../../src/device.mjs";
import { acceptAnchorBaseline, launchAnchorGate } from "../../../src/anchor-gate.mjs";

if (process.env.ENCLAWEDER_LIVE_DEVICE_TEST !== "I_UNDERSTAND") {
  console.error("run with ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND (this proof needs the real device)");
  process.exit(2);
}
const sb = sandbox("gate-launch");
const home = path.join(sb.dir, "home");
fs.mkdirSync(home, { recursive: true });
// "optional" is an administrator's grant now (refused from a shell): granted in the stand-in admin dir.
Object.assign(sb.env, { HOME: home, CLAUDE_CONFIG_DIR: path.join(sb.dir, "cfg") });
sb.grant({ hardwareRoot: "optional" });
// Two-factor is mandatory: the sandbox's throwaway credential (lib.mjs);
// rt-launcher.mjs signs a fresh ticket before each launch.
const launch = (label) => {
  const r = spawnSync(process.execPath, [LAUNCHER, "-p", "--", "hello"], { env: sb.env, cwd: sb.project, encoding: "utf8", timeout: 120000 });
  console.log(`  ${label}: exit ${r.status}; ${r.stderr.split("\n").filter((l) => l.startsWith("ecwcode")).map((l) => l.slice(0, 220)).join(" | ")}`);
  return r;
};
const log = sb.auditFile;
const r0 = launch("0 fresh log on a device with anchors");
// A person's accept (what `ecwctl audit accept` does after its terminal, auth and serial gates).
for (const [k, v] of Object.entries(sb.env)) process.env[k] = v;
const fw = await import(path.join(ROOT, ".enclawed-dev", "framework", "framework.js"));
const accept = async () => {
  const o = console.error; console.error = () => {};
  try { await fw.bootHardwareRoot(); } finally { console.error = o; }
  const device = await boundDevice(fw);
  const g = await launchAnchorGate(fw, device, log);
  if (!g.ok) {
    const L = new fw.AuditLogger({ filePath: log });
    await acceptAnchorBaseline(fw, device, log, { found: g, append: (x) => L.append(x) });
    await L.close();
  }
  try { fw.closeHardwareRootSession(); } catch { /* none */ }
  return g;
};
await accept();
const r1 = launch("1 after accept");
const r2 = launch("2 next session");
for (const f of [log, `${log}.head`, anchorFile(log), anchorHistoryFile(log)]) fs.rmSync(f, { force: true });
const L = new fw.AuditLogger({ filePath: log });
await L.append({ type: "claude-code.session.start", actor: "claude-code:s", level: null, payload: { sessionId: "A" } });
await L.close();
const r3 = launch("3 laundered between sessions");
const refused = readAudit(log).filter((x) => x.type === "claude-code.launch.refused").map((x) => `${x.payload.reason}/${x.payload.code}`);
console.log(`  refusal records in the (fabricated) log: ${refused.join(", ")}`);
result("R5-A launcher", !(r0.status === 6 && r1.status === 0 && r2.status === 0 && r3.status === 6), "the launcher starts claude on a log that does not match the device");
sb.cleanup();
setTimeout(() => process.exit(0), 300);
