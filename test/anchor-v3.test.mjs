// Command set 0.5 (Enclaweder firmware 0.3.3): the anchor history holds record
// v3 lines, written, read and compared by the kit (hardware-root
// anchor-history.ts). Before, Enclawed Code wrote every v3 anchor without its
// version, session, open count and binding, so every line failed as v1 and a
// held session on a 0.5 device could neither verify, nor launch again on the
// continuing log, nor be accepted.
//
// Evidence: (1) six records a real Enclaweder Pro on firmware 0.3.3 signed in
// the compromised-host benchmark (run a0.C2.-.1, its device key from that
// run's approvals.json), as the fixed writer records them and as the old one
// did; (2) the host-protocol-level simulated device at command set 0.5
// (fixtures/anchor-sim.mjs) under the real framework.
import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

let dir;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "cn-anchor-v3-"));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

// ------------------------------------------------------------ (1) the real device's records

const REAL = {
  pub: "a4c036f9930f8d0512d5ee18ac031af43475a6eafc920128a4dc22420548adb7",
  uid: "0035001c4543501120383447",
  sess: "2",
  opens: "2",
  bind: "010004001c3b9103090000000000000004000000000000000000000000000000",
  // head, counter, sig of each anchor of that session (all record v3).
  rows: [
    ["5301de8501c6ba1f53a73fc60d51092433aa030f2ac41ad914b8e4a861dc1fe1", "1", "yMZdKx0OLn8YDYz+EqLlKHEsy0RIYawRmkHvTT5Zo54vtjK1jReL/1zG/5XXqilkyghI3JWdYFaJZBm2QzKSBw=="],
    ["740286157f211461c05fe543e80c548a9e3eddf4944bb630fed126de2f93a93a", "2", "HnkWv9vCio2vzl9eKdFmKgq0dAPoKf5rFzMRs6eigAo1mpFr/oEOpBUUfWhgx8tDRwD0Oez0UC22svpSezV6Ag=="],
    ["dd7a3a8bbc4d04585be0cf386b66488d56f481009bd25cd129d461511509a851", "3", "6z6LVWK6UhnqYVMi2CdR6WBdBPJOVA0pAnB4OYHfZ0WjCNZetodygIOY26iir3qO7KL5988nqHV4xca2rui3BA=="],
    ["2f11bd2b0950b5364d274774070f15e303aa6af79ea25f9da6b9b3ee53a185c9", "4", "KMy5zQrMMRbkSLhi4zeXrwBhORflia7lmJ67e+1FA3vuNVJAFFygyVEMak/LmQOt1uUMv8mONv7URbcDFaD3BQ=="],
    ["57205ec63d0654f1e9236ec924128908f99736a93ec87c2fe460d8c612f1e82b", "5", "i1ujYehnVljuSIkv4/Ij6QFd4AMbON8BPl0/BGqQV9tLuj3dwAgocYGDI+XeVT8pmQXcwD9T0Z5qPKPPgJD6Bg=="],
    ["b52843e326c94c143ea907763f08f8f2f41e8e69d11d8c576dbfb37b2a35632b", "6", "eL2UeAI+YD+eged+AI3Er6zBGoF/e5R7zy5amIMk+YCDJoU8J6qPZi8FxqG6Qju6yh2XoPaWLY7+F6VX/7GBAw=="],
  ],
  // The launch's own record in that run's log (claude-code.auth.device-factor).
  launch: { type: "claude-code.auth.device-factor", payload: { purpose: "session-start", outcome: "verified", via: "device-unlock", gid: "9", useIndex: 4, boot: "4" } },
};

test("v3 history: a real 0.3.3 device's records verify as the kit writes them, and the old writer's lines are refused", async () => {
  const { loadFramework } = await import("../src/framework.mjs");
  const { readAnchorHistory, anchorHistoryFile, anchorFile } = await import("../src/device.mjs");
  const { fw } = await loadFramework();
  const log = path.join(dir, "audit.jsonl");
  // Enclawed Code's file names are the kit's.
  assert.equal(anchorFile(log), fw.anchorFilePath(log));
  assert.equal(anchorHistoryFile(log), fw.anchorHistoryPath(log));
  // The kit's writer, fed the run's anchor file (counter 6), writes the line that verifies.
  const [head6, , sig6] = REAL.rows[5];
  fs.writeFileSync(anchorFile(log), JSON.stringify({ version: 3, head: head6, counter: "6", uid: REAL.uid, sig: sig6, sess: REAL.sess, opens: REAL.opens, sessions: ["2"], bind: REAL.bind, serial: "ECPRO-X" }));
  const w = fw.appendAnchorHistory({ anchorPath: anchorFile(log), historyPath: anchorHistoryFile(log), devicePublicKey: Buffer.from(REAL.pub, "hex") });
  assert.equal(w.version, 3);
  const line = JSON.parse(fs.readFileSync(anchorHistoryFile(log), "utf8"));
  assert.deepEqual(Object.keys(line).sort(), ["bind", "counter", "head", "opens", "sess", "sig", "ts", "uid", "version"]);
  // All six as the fixed writer records them.
  const lines = REAL.rows.map(([head, counter, sig]) => JSON.stringify({ version: 3, head, counter, uid: REAL.uid, sig, sess: REAL.sess, opens: REAL.opens, bind: REAL.bind, ts: 1 }));
  fs.writeFileSync(anchorHistoryFile(log), `${lines.join("\n")}\n`);
  const h = readAnchorHistory(fw, log, REAL.pub);
  assert.equal(h.bad, 0);
  assert.deepEqual(h.entries.map((e) => [e.version, e.counter]), REAL.rows.map((r) => [3, BigInt(r[1])]));
  // Every line names the run's own launch.
  const acts = fw.deviceFactorActivations([REAL.launch]);
  for (const e of h.entries) assert.equal(fw.unboundHistoryRecord(e, acts), null);
  assert.match(fw.unboundHistoryRecord(h.entries[0], fw.deviceFactorActivations([{ ...REAL.launch, payload: { ...REAL.launch.payload, useIndex: 5 } }])), /none of this log's own auth\.device-factor records/);
  // The lines as bfa80d5 wrote them (v3 records without version, sess, opens, bind): none verifies, as anything.
  const old = REAL.rows.map(([head, counter, sig]) => JSON.stringify({ head, counter, uid: REAL.uid, sig, ts: 1 }));
  fs.writeFileSync(anchorHistoryFile(log), `${old.join("\n")}\n`);
  assert.deepEqual(readAnchorHistory(fw, log, REAL.pub), { entries: [], bad: 6 });
  // Nor with only the binding dropped, or read as record v2.
  const noBind = REAL.rows.map(([head, counter, sig]) => JSON.stringify({ version: 2, head, counter, uid: REAL.uid, sig, sess: REAL.sess, opens: REAL.opens }));
  fs.writeFileSync(anchorHistoryFile(log), `${noBind.join("\n")}\n`);
  assert.equal(readAnchorHistory(fw, log, REAL.pub).bad, 6);
});

// ------------------------------------------------------------ (2) the simulated 0.5 device

/**
 * A command set 0.5 Enclaweder at the host-protocol level behind the real
 * framework. `process()` gives the device as a fresh launcher process sees it
 * (its own anchor-session slot), through the kit's session-anchor decision.
 */
async function softDevice05() {
  const { loadFramework } = await import("../src/framework.mjs");
  const { withSessionAnchor } = await import("../src/device.mjs");
  const { kitSessionAnchor } = await import("./fixtures/kit-anchor.mjs");
  const { SimulatedAnchorFirmware } = await import("./fixtures/anchor-sim.mjs");
  const { fw: real } = await loadFramework();
  const sim = new SimulatedAnchorFirmware(real, { commandSet: "0.5" });
  const process_ = () => {
    sim.dev = null; // a new process: a new device handle, so a new anchor-session slot
    const dev = sim.device();
    const fw = new Proxy(real, {
      get(t, k) {
        if (k === "bootHardwareRoot") return async () => ({});
        if (k === "hardwareRootSigningDevice") return () => dev;
        if (k === "closeHardwareRootSession") return () => {};
        if (k === "requireHardwareRootSessionAnchor") return kitSessionAnchor(real, dev, sim.publicKey);
        return t[k];
      },
    });
    return { fw, device: withSessionAnchor(fw, { dev, pub: sim.publicKey.toString("hex"), uid: sim.uid.toString("hex"), serial: "SIM" }) };
  };
  return { real, sim, process: process_ };
}

const unlockRecord = (a) => ({ type: "claude-code.auth.device-factor", payload: { purpose: "session-start", outcome: "verified", via: "device-unlock", gid: String(a.gid), useIndex: a.useIndex, boot: String(a.boot) } });

/** One launch: the gate on the log as found, the activation, a held session that anchors its records. */
async function launch(d, log, recs) {
  const { startAnchoring } = await import("../src/device.mjs");
  const { launchAnchorGate } = await import("../src/anchor-gate.mjs");
  const { fw, device } = d.process();
  const gate = await launchAnchorGate(fw, device, log, { rootRequired: true });
  if (!gate.ok) return { gate };
  const act = await d.sim.activate();
  const a = startAnchoring(fw, device, log, { intervalMs: 60_000 });
  const L = new fw.AuditLogger({ filePath: log });
  await L.append({ type: "claude-code.launch", actor: "enclawed-code", level: null, payload: { hardware: "held", rootRequired: true } });
  await L.append({ actor: "enclawed-code", level: null, ...unlockRecord(act) });
  for (const r of recs) await L.append({ actor: "a", level: null, ...r });
  await L.flush?.();
  await a.flush();
  await L.close();
  await a.flush();
  await a.close();
  return { gate, act };
}

/** `audit verify`'s device part and verdict, as admin.mjs runs them, in a new process. */
async function verify(d, log) {
  const { checkDeviceAnchor } = await import("../src/device.mjs");
  const { logRecordHashes } = await import("../src/anchor-gate.mjs");
  const { fw } = d.process();
  const dev = await checkDeviceAnchor(fw, log, logRecordHashes(log));
  const records = fs.readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const verdict = fw.decideAuditAnchorVerdict({ claims: fw.launchRootClaims(records), device: dev.status, chainAnchor: null, attestation: dev.attestation ?? null, activations: fw.deviceFactorActivations(records) });
  return { dev, verdict };
}

test("v3 history (guarantee): a held session on a 0.5 device verifies matched, and the next launch on the continuing log passes the anchor gate and verifies too", async () => {
  const { anchorHistoryFile } = await import("../src/device.mjs");
  const d = await softDevice05();
  const log = path.join(dir, "audit.jsonl");
  const s1 = await launch(d, log, [{ type: "claude-code.tool.pre", payload: { tool: "Bash", decision: "ask" } }]);
  assert.equal(s1.gate.ok, true, JSON.stringify(s1.gate));
  const lines = fs.readFileSync(anchorHistoryFile(log), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.ok(lines.length > 0 && lines.every((l) => l.version === 3 && l.bind && l.sess && l.opens), JSON.stringify(lines));
  const v1 = await verify(d, log);
  assert.equal(v1.dev.status, "matched", JSON.stringify(v1.dev));
  assert.equal(v1.dev.attestation?.fresh, true);
  assert.equal(v1.dev.attestation?.version, 3);
  assert.deepEqual(v1.verdict, { ok: true, rootClaimed: true });
  const s2 = await launch(d, log, [{ type: "claude-code.tool.pre", payload: { tool: "Read", decision: "allow" } }]);
  assert.equal(s2.gate.ok, true, JSON.stringify(s2.gate));
  const v2 = await verify(d, log);
  assert.equal(v2.dev.status, "matched", JSON.stringify(v2.dev));
  assert.deepEqual(v2.verdict, { ok: true, rootClaimed: true });
});

test("v3 history (attack): the old writer's history, and a log anchored under a use the log does not record, refuse the launch; audit accept re-baselines and the next launch passes", async () => {
  const { anchorHistoryFile, anchorFile } = await import("../src/device.mjs");
  const { acceptAnchorBaseline, launchAnchorGate } = await import("../src/anchor-gate.mjs");
  const d = await softDevice05();
  const log = path.join(dir, "audit.jsonl");
  await launch(d, log, []);
  // The history stripped to what bfa80d5 wrote: refused, never matched.
  const hist = fs.readFileSync(anchorHistoryFile(log), "utf8");
  fs.writeFileSync(anchorHistoryFile(log), hist.trim().split("\n").map((l) => { const { head, counter, uid, sig, ts } = JSON.parse(l); return JSON.stringify({ head, counter, uid, sig, ts }); }).join("\n") + "\n");
  let p = d.process();
  let g = await launchAnchorGate(p.fw, p.device, log, { rootRequired: true });
  assert.equal(g.ok, false);
  assert.equal(g.code, "history-invalid");
  fs.writeFileSync(anchorHistoryFile(log), hist);
  // A same-user forger between sessions: a fabricated log, anchored under a session bound to a use
  // it spent itself; its log does not (cannot honestly) record the launch that use stands for.
  for (const f of [log, `${log}.head`, anchorFile(log), anchorHistoryFile(log)]) fs.rmSync(f, { force: true });
  {
    const { startAnchoring } = await import("../src/device.mjs");
    const f = d.process();
    await d.sim.activate();
    const a = startAnchoring(f.fw, f.device, log, { intervalMs: 60_000 });
    const L = new f.fw.AuditLogger({ filePath: log });
    await L.append({ type: "claude-code.launch", actor: "enclawed-code", level: null, payload: { hardware: "held" } });
    await L.close();
    await a.flush();
    await a.close();
  }
  p = d.process();
  g = await launchAnchorGate(p.fw, p.device, log, { rootRequired: true });
  assert.equal(g.ok, false, JSON.stringify(g));
  assert.equal(g.code, "history-unbound");
  // A person accepts the log as found: the accept record is anchored under a fresh session, the next launch passes.
  p = d.process();
  const appendRec = async (r) => {
    const A = new p.fw.AuditLogger({ filePath: log });
    await A.append(r);
    await A.close();
  };
  const acc = await acceptAnchorBaseline(p.fw, p.device, log, { found: g, append: appendRec });
  assert.ok(acc.head);
  const after = await launch(d, log, []);
  assert.equal(after.gate.ok, true, JSON.stringify(after.gate));
  const v = await verify(d, log);
  assert.equal(v.dev.status, "matched", JSON.stringify(v.dev));
  assert.deepEqual(v.verdict, { ok: true, rootClaimed: true });
});

test("v3 history: audit accept anchors under a session bound to its own device-verified activation, so the log verifies at once; reads never open the anchor channel", async () => {
  const { anchorHistoryFile, anchorFile } = await import("../src/device.mjs");
  const { acceptAnchorBaseline, launchAnchorGate } = await import("../src/anchor-gate.mjs");
  const d = await softDevice05();
  const log = path.join(dir, "audit.jsonl");
  await launch(d, log, []);
  // Laundering between sessions: anchor files deleted, a fabricated log written.
  for (const f of [log, `${log}.head`, anchorFile(log), anchorHistoryFile(log)]) fs.rmSync(f, { force: true });
  let p = d.process();
  const L = new p.fw.AuditLogger({ filePath: log });
  await L.append({ type: "claude-code.launch", actor: "enclawed-code", level: null, payload: { hardware: "held" } });
  await L.close();
  // The gate and verify read only: the device's open count does not move.
  const opens = d.sim.opens;
  const g = await launchAnchorGate(p.fw, p.device, log, { rootRequired: true });
  assert.equal(g.ok, false, JSON.stringify(g));
  await verify(d, log);
  assert.equal(d.sim.opens, opens, "a read or a comparison opened the anchor channel");
  // The person's activation (as `audit accept` runs it: two factors and a device-verified use or code), recorded in the log.
  p = d.process();
  const act = await d.sim.activate();
  const appendRec = async (r) => {
    const A = new p.fw.AuditLogger({ filePath: log });
    await A.append(r);
    await A.close();
  };
  await appendRec({ actor: "enclawed-code", level: null, ...unlockRecord(act) });
  const acc = await acceptAnchorBaseline(p.fw, p.device, log, { found: g, append: appendRec });
  assert.ok(acc.head);
  const lines = fs.readFileSync(anchorHistoryFile(log), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.ok(lines.every((l) => l.version === 3), JSON.stringify(lines));
  const v = await verify(d, log);
  assert.equal(v.dev.status, "matched", JSON.stringify(v.dev));
  assert.deepEqual(v.verdict, { ok: true, rootClaimed: true });
  const next = await launch(d, log, []);
  assert.equal(next.gate.ok, true, JSON.stringify(next.gate));
});

test("launch order: the anchor gate (a read that spends nothing) runs before the launch's activation, which spends a device-unlock use", () => {
  const src = fs.readFileSync(new URL("../src/launcher.mjs", import.meta.url), "utf8");
  const body = src.slice(src.indexOf("export async function launchSession("));
  const gate = body.indexOf("await launchAnchorGate(");
  const device = body.indexOf("device = await sessionDevice(fw)");
  const activation = body.indexOf("await activateLaunch(");
  const anchoring = body.indexOf("startAnchoring(");
  assert.ok(device > 0 && gate > device && activation > gate, "the session device and the anchor gate must come before the activation");
  assert.ok(anchoring > activation, "anchoring (a bound open on the activation) comes after it");
  assert.equal(body.split("await launchAnchorGate(").length, 2, "one anchor gate per launch");
});
