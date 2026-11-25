// Firmware 0.2 lease paths on the REAL Enclaweder (run with ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND;
// throwaway logs in a sandbox; no operator takeover: that needs operator
// private keys, which stay off the host, and is tested in the simulator only).
//   1 Enclawed Code's anchoring (framework sink + startKeepalive) holds its session past the 120 s lease
//   2 a second opener gets BUSY with waitMs
//   3 Enclawed Code's BUSY alarm shows the time left: lease-alarm-real.mjs (a separate holder)
//   4 a holder that stops (no keepalive, no close) lapses; the next open is sid+1 with no alarm
import fs from "node:fs";
import path from "node:path";
import { ROOT, result, sandbox } from "./lib.mjs";
import { boundDevice, startAnchoring } from "../../../src/device.mjs";
import { anchorAlarmAdvice } from "../../../src/launcher.mjs";

if (process.env.ENCLAWEDER_LIVE_DEVICE_TEST !== "I_UNDERSTAND") {
  console.error("run with ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND (this proof needs the real device)");
  process.exit(2);
}
const sb = sandbox("lease-real");
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const logOf = (n) => path.join(sb.state, `${n}.jsonl`);
const append = async (log, n = 1) => {
  const l = new fw.AuditLogger({ filePath: log });
  for (let k = 0; k < n; k++) await l.append({ type: "x", actor: "a", level: null, payload: { k, t: Date.now() } });
  await l.close();
};
const quiet = async (fn) => { const o = console.error; console.error = () => {}; try { return await fn(); } finally { console.error = o; } };
await quiet(() => fw.bootHardwareRoot());
const device = await boundDevice(fw);
const pub = Buffer.from(device.pub, "hex");
const g = async () => { const a = await device.dev.anchorGet(); return `counter ${a.counter} sess ${a.sess} opens ${a.opens}`; };
console.log(`  device ${device.serial}: ${await g()}; lease ${fw.ANCHOR_LEASE_MS} ms, keepalive every ${fw.ANCHOR_KEEPALIVE_INTERVAL_MS} ms`);
const ok = {};

// 1+2+3
const alarms1 = [];
const a1 = startAnchoring(fw, device, logOf("one"), { intervalMs: 3_600_000, onAlarm: (e) => alarms1.push(e), onError: (e) => alarms1.push(e) });
console.log(`  a1 keepalive=${a1.keepalive} mode=${a1.mode}`);
await append(logOf("one"));
console.log(`  1 a1 anchored=${(await a1.flush()).anchored}; ${await g()}`);
const s1 = (await device.dev.anchorGet()).sess;
let busy = null;
try { const x = await fw.AnchorSession.open(device.dev, pub); await x.close(); } catch (e) { busy = e; }
console.log(`  2 second opener: ${busy ? `${busy.code} waitMs=${busy.waitMs}` : "OPENED (unexpected)"}`);
ok.busy = busy?.code === "busy" && typeof busy.waitMs === "number" && busy.waitMs > 0 && busy.waitMs <= fw.ANCHOR_LEASE_MS;
// 3 (Enclawed Code's BUSY alarm) is in lease-alarm-real.mjs: within one process the
// framework's head-anchor sinks share one device session, so a second sink
// here would reuse a1's session instead of meeting BUSY.
console.log("  ... holding a1 for 135 s on keepalives only");
await sleep(135_000);
await append(logOf("one"));
const f1 = await a1.flush();
const s1b = (await device.dev.anchorGet()).sess;
console.log(`  1 after 135 s: anchored=${f1.anchored}, sess ${s1} -> ${s1b}, alarms ${alarms1.map(String).join("; ") || "none"}; ${await g()}`);
ok.held = f1.anchored && s1b === s1 && alarms1.length === 0;
await a1.close();

// 4: a holder that just stops
const c = await fw.AnchorSession.open(device.dev, pub);
const cs = c.sid;
console.log(`  4 holder C opened sid ${cs}; it now stops (no keepalive, no close)`);
let early = null;
try { const x = await fw.AnchorSession.open(device.dev, pub); await x.close(); } catch (e) { early = e; }
console.log(`    open right after: ${early ? `${early.code} waitMs=${early.waitMs}` : "opened (unexpected)"}`);
console.log("  ... waiting 128 s for C's lease to lapse");
await sleep(128_000);
const alarms4 = [];
const a4 = startAnchoring(fw, device, logOf("four"), { intervalMs: 3_600_000, onAlarm: (e) => alarms4.push(e), onError: (e) => alarms4.push(e) });
await append(logOf("four"));
const f4 = await a4.flush();
const after = await device.dev.anchorGet();
console.log(`  4 next open: anchored=${f4.anchored}, sess ${after.sess} (C was ${cs}), alarms ${alarms4.map(String).join("; ") || "none"}`);
ok.lapse = f4.anchored && after.sess === cs + 1n && alarms4.length === 0 && early?.code === "busy";
await a4.close();
try { fw.closeHardwareRootSession(); } catch { /* none */ }
console.log(`  summary ${JSON.stringify(ok)}; ${await g().catch(() => "")}`);
result("fw0.2 lease", !Object.values(ok).every(Boolean), "a 0.2 lease path did not behave as specified");
process.on("exit", () => sb.cleanup());
setTimeout(() => process.exit(0), 300);
