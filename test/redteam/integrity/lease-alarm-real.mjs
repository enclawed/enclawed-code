// Firmware 0.2 on the REAL Enclaweder (ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND; throwaway log):
// Enclawed Code's BUSY alarm while another holder (a raw anchor session, renewing
// its lease) has the channel shows the time left. lease-real.mjs covers the
// keepalive, the BUSY waitMs and the lapse; within one process the
// framework's head-anchor sinks share one session, so the holder here is a
// separate AnchorSession.
import fs from "node:fs";
import path from "node:path";
import { ROOT, result, sandbox } from "./lib.mjs";
import { boundDevice, startAnchoring } from "../../../src/device.mjs";
import { anchorAlarmAdvice } from "../../../src/launcher.mjs";

if (process.env.ENCLAWEDER_LIVE_DEVICE_TEST !== "I_UNDERSTAND") {
  console.error("run with ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND (this proof needs the real device)");
  process.exit(2);
}
const sb = sandbox("lease-alarm");
const home = path.join(sb.dir, "home");
fs.mkdirSync(home, { recursive: true });
// "optional" is an administrator's grant now (refused from a shell): granted in
// the stand-in admin dir for the launcher; the framework, used in this
// process directly, reads it from process.env below.
Object.assign(sb.env, { HOME: home });
sb.grant({ hardwareRoot: "optional" });
sb.useAuthorityInProcess();
for (const [k, v] of Object.entries(sb.env)) process.env[k] = v;
process.env.ENCLAWEDER_ROOT = "optional";
const fw = await import(path.join(ROOT, ".enclawed-dev", "framework", "framework.js"));
const o = console.error; console.error = () => {};
try { await fw.bootHardwareRoot(); } finally { console.error = o; }
const device = await boundDevice(fw);
const holder = await fw.AnchorSession.open(device.dev, Buffer.from(device.pub, "hex"));
holder.startKeepalive();
console.log(`  holder sid ${holder.sid} renewing`);
const log = path.join(sb.state, "a.jsonl");
const alarms = [];
const a = startAnchoring(fw, device, log, { intervalMs: 3_600_000, onAlarm: (e) => alarms.push(e), onError: (e) => alarms.push(e) });
const L = new fw.AuditLogger({ filePath: log });
await L.append({ type: "x", actor: "a", level: null, payload: {} });
await L.close();
await a.flush();
await a.close().catch(() => {});
const e = alarms[0];
const advice = e ? anchorAlarmAdvice(e) : "";
console.log(`  Enclawed Code alarm: ${e?.code} waitMs=${e?.waitMs}\n  advice: ${advice}`);
await holder.close();
const after = await device.dev.anchorGet();
console.log(`  holder closed; device counter ${after.counter} sess ${after.sess} opens ${after.opens}`);
try { fw.closeHardwareRootSession(); } catch { /* none */ }
result("fw0.2 BUSY alarm", !(e?.code === "ANCHOR_SESSION_BUSY" && typeof e.waitMs === "number" && /lease ends in \d+ s/.test(advice)), "Enclawed Code's BUSY alarm does not show the lease time left");
sb.cleanup();
setTimeout(() => process.exit(0), 300);
