// The launcher holds the hardware root for the session and serves an
// authenticated health relay; hooks accept only answers that prove the
// session secret and, with a device bound, the device's own signature over a
// fresh nonce. No real device: npm test hides any attached Enclaweder (see
// scripts/test.mjs); every device here is simulated.
import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { checkAttestation } from "../src/device.mjs";
import { loadFramework } from "../src/framework.mjs";
import { checkViaRelay, holdSessionRoot, startHardwareRelay } from "../src/hardware.mjs";
import { setTestAuthority } from "../src/authority.mjs";
import { sessionContainment } from "../src/containment.mjs";
import { EXIT_HARDWARE_HALT, launchSession, prepareLaunch } from "../src/launcher.mjs";
import { hookCommand } from "../src/settings.mjs";
import { auditRecords, issueTestTicket, pre, runHookAsync as runHook, runLauncher, sandbox } from "./helpers.mjs";
import { kitSessionAnchor } from "./fixtures/kit-anchor.mjs";
import { claudeLoginDir } from "../src/claude-login.mjs";
import { readsUnder } from "../src/conformance-login.mjs";

const PERSON_LOGIN = '{"claudeAiOauth":{"accessToken":"sk-ant-oat01-the-persons-own"}}';
const SESSION_LOGIN = '{"claudeAiOauth":{"accessToken":"sk-ant-oat01-test-only-session"}}';
/** Where Claude Code keeps the session's own login under Enclawed Code with a device (claude-login.mjs). */
const sessionLoginFile = () => path.join(claudeLoginDir(sb.env), ".credentials.json");

let sb;
let relays;
beforeEach(() => {
  sb = sandbox();
  relays = [];
});
afterEach(async () => {
  setTestAuthority(null);
  for (const r of relays) {
    await r.close();
  }
  sb.cleanup();
});

const decision = (r) => r.out?.hookSpecificOutput?.permissionDecision;
const lastPre = () => auditRecords(sb).filter((r) => r.type === "claude-code.tool.pre").at(-1);

async function relay(health, secret) {
  const r = await startHardwareRelay({ socketPath: path.join(sb.dir, `relay-${relays.length}.sock`), health, ...(secret ? { secret } : {}) });
  relays.push(r);
  return r;
}

const hw = (r, extra = {}) => ({ mode: "relay", relay: { path: r.path, secret: r.secret }, ...extra });

test("hooks read the launcher's relay: CLEAN without a device attestation, DIRTY or UNAVAILABLE deny", async () => {
  // A relay that says CLEAN for a session that bound no attestable device is refused (red-team
  // H15: held mode used to skip attestation when the device was null, so the owner's word was enough).
  const clean = await relay(async () => ({ allowed: true }));
  assert.equal(decision(await runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { hardware: hw(clean) })), "deny");
  assert.deepEqual(lastPre().payload.codes, ["device-attestation-failed"]);
  for (const [code, reason] of [
    ["hardware-dirty", "hardware root DIRTY: device removed"],
    ["hardware-unavailable", "hardware root UNAVAILABLE: no answer"],
  ]) {
    const r = await relay(async () => ({ allowed: false, code, reason }));
    assert.equal(decision(await runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { hardware: hw(r) })), "deny", code);
    assert.deepEqual(lastPre().payload.codes, [code]);
  }
});

test("I8: the environment cannot name a broker; a relay that cannot prove the session secret is refused", async () => {
  // A fake owner reporting CLEAN at the session's relay path, without the session secret.
  const fake = await relay(async () => ({ allowed: true }), "00".repeat(32));
  const r = await runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { hardware: hw({ path: fake.path, secret: "11".repeat(32) }) });
  assert.equal(decision(r), "deny");
  assert.deepEqual(lastPre().payload.codes, ["owner-unauthenticated"]);
  // The launcher's environment says ENCLAWEDER_ROOT=required (no device); Claude Code's
  // environment offers a fake CLEAN broker and ENCLAWEDER_ROOT=optional. Neither reaches the hook.
  const env = await runHook(sb, pre(sb, "Read", { file_path: "a" }), { ENCLAWEDER_ROOT: "required" }, { claudeEnv: { ECWCODE_HW_BROKER: fake.path, ENCLAWEDER_ROOT: "optional" } });
  assert.equal(decision(env), "deny");
  assert.deepEqual(lastPre().payload.codes, ["hardware-boot-refused"]);
});

test("a relay that is gone, or never answers, denies within the hook timeout", async () => {
  const r = await relay(async () => ({ allowed: true }));
  const session = hw(r);
  await relays.pop().close();
  assert.equal(decision(await runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { hardware: session })), "deny");
  assert.deepEqual(lastPre().payload.codes, ["owner-unavailable"]);
  const silent = await relay(() => new Promise(() => {}));
  const t0 = Date.now();
  assert.equal(decision(await runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { hardware: hw(silent) })), "deny");
  assert.ok(Date.now() - t0 < 8000);
});

/** A simulated device: an Ed25519 key that signs the device's challenge message. */
function simulatedDevice() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const uid = Buffer.alloc(12, 7);
  return {
    pub: pub.toString("hex"),
    uid: uid.toString("hex"),
    signNonce: (nonceHex) => sign(null, Buffer.concat([Buffer.from("ECW-CHALLENGE-01"), Buffer.from(nonceHex, "hex"), uid]), privateKey).toString("base64"),
  };
}

test("attestation: a simulated device with no manufacturer certificate is refused although it says CLEAN and signs", async () => {
  const dev = simulatedDevice();
  const r = await relay(async (_tool, nonce) => ({ allowed: true, attestation: { pub: dev.pub, uid: dev.uid, sig: dev.signNonce(nonce), cert: Buffer.alloc(119, 1).toString("base64") } }));
  const out = await runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { hardware: hw(r, { device: { pub: dev.pub, uid: dev.uid } }) });
  assert.equal(decision(out), "deny");
  assert.deepEqual(lastPre().payload.codes, ["device-attestation-failed"]);
  assert.match(out.out.hookSpecificOutput.permissionDecisionReason, /manufacturer certificate/);
});

test("attestation: the framework's challenge check refuses a replayed nonce, another key and a forged signature", async () => {
  const { fw } = await loadFramework();
  const dev = simulatedDevice();
  const nonce = "ab".repeat(32);
  const answer = { pub: dev.pub, uid: dev.uid, sig: dev.signNonce(nonce), cert: "AA==" };
  // No simulated device has a manufacturer certificate, so only that check is injected.
  const verifyCert = () => ({ ok: true });
  assert.equal(checkAttestation(fw, { nonce, answer, pinnedPub: dev.pub, verifyCert }), null);
  assert.match(checkAttestation(fw, { nonce: "cd".repeat(32), answer, pinnedPub: dev.pub, verifyCert }), /fresh challenge/);
  assert.match(checkAttestation(fw, { nonce, answer, pinnedPub: simulatedDevice().pub, verifyCert }), /not the one bound/);
  assert.match(checkAttestation(fw, { nonce, answer: { ...answer, sig: Buffer.alloc(64).toString("base64") }, pinnedPub: dev.pub, verifyCert }), /fresh challenge/);
  assert.match(checkAttestation(fw, { nonce, answer, pinnedPub: dev.pub }), /manufacturer certificate/);
});

test("each relay request carries a fresh nonce", async () => {
  const seen = [];
  const r = await relay(async (_t, nonce) => {
    seen.push(nonce);
    return { allowed: true, attestation: null };
  });
  const attestation = { check: () => "refused for the test" };
  assert.equal((await checkViaRelay({ path: r.path, secret: r.secret }, "Read", { attestation })).allowed, false);
  await checkViaRelay({ path: r.path, secret: r.secret }, "Read", { attestation });
  assert.equal(seen.length, 2);
  assert.notEqual(seen[0], seen[1]);
  assert.match(seen[0], /^[0-9a-f]{64}$/);
});

test("managed mode takes nothing from the environment (NODE_OPTIONS, ENCLAWED_STATE_DIR, a broker)", () => {
  const res = spawnSync("/bin/sh", ["-c", hookCommand({ origin: "managed" })], {
    input: "not json",
    env: { ...sb.env, ECWCODE_HW_BROKER: path.join(sb.dir, "none.sock"), ENCLAWED_STATE_DIR: path.join(sb.dir, "evil"), NODE_OPTIONS: "--require /nonexistent/preload.js" },
    cwd: sb.project,
    encoding: "utf8",
  });
  // NODE_OPTIONS never reached node (the preload would have crashed it before any output).
  assert.match(res.stdout, /hookSpecificOutput/, res.stderr);
  assert.equal(res.status, 2);
  assert.equal(fs.existsSync(path.join(sb.dir, "evil")), false, "nothing written where the environment pointed");
});

test("no device: the launcher holds nothing and hooks keep software-only behavior", () => {
  const out = path.join(sb.dir, "claude.json");
  const input = pre(sb, "Read", { file_path: "a" });
  const r = runLauncher(sb, ["-p", "x"], { FAKE_CLAUDE_OUT: out, FAKE_CLAUDE_HOOK_INPUT: JSON.stringify(input) });
  assert.equal(r.status, 0, r.stderr);
  const rec = JSON.parse(fs.readFileSync(out, "utf8"));
  assert.equal(JSON.parse(rec.hookOutput).hookSpecificOutput.permissionDecision, "allow");
});

test("ENCLAWEDER_ROOT=required with no device: the launcher refuses to start claude", () => {
  const out = path.join(sb.dir, "claude.json");
  const r = runLauncher(sb, ["-p", "x"], { ENCLAWEDER_ROOT: "required", FAKE_CLAUDE_OUT: out });
  assert.equal(r.status, 4, r.stderr);
  assert.match(r.stderr, /hardware root refused to start/);
  assert.equal(fs.existsSync(out), false);
  assert.ok(auditRecords(sb).some((x) => x.type === "claude-code.launch.refused"));
});

function fakeFw(real, { boot }) {
  const calls = { boot: 0, close: 0 };
  return {
    calls,
    fw: {
      ...real,
      brokerDisabled: () => false,
      bootHardwareRoot: async () => {
        calls.boot++;
        return boot();
      },
      closeHardwareRootSession: () => {
        calls.close++;
      },
    },
  };
}

test("holdSessionRoot: held once and released once; software-only, halted and broker-off hold nothing", async () => {
  const { fw: real } = await loadFramework();
  const { fw, calls } = fakeFw(real, { boot: () => ({ bound: true }) });
  const exitHandlers = [];
  const root = await holdSessionRoot(fw, { onExit: (h) => exitHandlers.push(h) });
  assert.equal(root.mode, "held");
  root.release();
  exitHandlers[0]();
  assert.deepEqual(calls, { boot: 1, close: 1 });
  assert.equal((await holdSessionRoot(fakeFw(real, { boot: () => null }).fw, { onExit: () => {} })).mode, "software-only");
  const halted = await holdSessionRoot(
    fakeFw(real, {
      boot: () => {
        throw new Error("latched DIRTY");
      },
    }).fw,
    { onExit: () => {} },
  );
  assert.equal(halted.mode, "halted");
  const off = fakeFw(real, { boot: () => ({}) });
  off.fw.brokerDisabled = () => true;
  assert.equal((await holdSessionRoot(off.fw, { onExit: () => {} })).mode, "broker-off");
  assert.equal(off.calls.boot, 0);
});

/** The simulated Enclaweder of each sandbox (one device per test, as on a real host). */
const anchorSims = new WeakMap();

/** A launch with a simulated held root whose health turns DIRTY after `afterMs`. */
/** A framework surface without device-verified TOTP (device-activation.mjs deviceTotpSeam). */
const NO_DEVICE_TOTP = Object.freeze({ hardwareRootTotpDevice: undefined, deviceTotpEnrolled: undefined, deviceTotpVerdict: undefined, verifyVerdictRecord: undefined });

async function haltedLaunch({ policyDoc = null, afterMs = 1500, extraEnv = {}, fwExtra: fwGiven = {}, ticket = true, containmentFor = undefined, deviceTotp = true } = {}) {
  const { fw: real } = await loadFramework();
  // With the Enclaweder held, the device's code is the one factor (device-activation.mjs): a held
  // launch here has a simulated device-verified TOTP unless the test brings its own (or none).
  let totpDev = null;
  let fwExtra = fwGiven;
  if (deviceTotp && typeof fwGiven.deviceTotpVerdict !== "function") {
    const { SimTotpDevice, totpFramework } = await import("./fixtures/totp-sim.mjs");
    totpDev = new SimTotpDevice();
    fwExtra = { ...totpFramework(totpDev), ...fwGiven };
  }
  let health = { allowed: true };
  // A held root always has an attestable device (red-team H15: held with none
  // is refused), and a bound session anchors its audit log with an
  // authenticated anchor session or does not start (the kit's
  // requireHardwareRootSessionAnchor). The stand-in is one simulated
  // Enclaweder at the host-protocol level (test/fixtures/anchor-sim.mjs: record
  // v2 ANCHOR_OPEN / MAC'd SET under its Ed25519 key, the framework's real
  // AnchorSession on the host side); the same key signs the challenge.
  // One device for the whole test: its counter, sessions and key persist across launches.
  const { SimulatedAnchorFirmware } = await import("./fixtures/anchor-sim.mjs");
  let anchorSim = anchorSims.get(sb);
  if (!anchorSim) {
    anchorSim = new SimulatedAnchorFirmware(real);
    anchorSims.set(sb, anchorSim);
  }
  const anchorDev = anchorSim.device();
  const simDev = {
    getIdentity: async () => ({ uid: anchorSim.uid, pubkeyRaw: anchorSim.publicKey, serial: "ENCLW-SIM" }),
    getCert: async () => Buffer.alloc(119, 1),
    challenge: async (n) => ({ uid: anchorSim.uid, sig: sign(null, Buffer.concat([Buffer.from("ECW-CHALLENGE-01"), Buffer.from(n), anchorSim.uid]), anchorSim.priv) }),
    anchorOpen: anchorDev.anchorOpen,
    anchorGet: anchorDev.anchorGet,
  };
  // No device TOTP unless a test brings its simulator (fwExtra): the framework
  // exports it from enclawed-oss 8b9ebf990 on, and the real calls would look
  // for a real device.
  const fw = {
    ...real,
    ...NO_DEVICE_TOTP,
    attestHardwareRoot: undefined,
    hardwareRootSigningDevice: () => simDev,
    // The kit decides the session's anchor on the device this framework holds.
    requireHardwareRootSessionAnchor: kitSessionAnchor(real, simDev, anchorSim.publicKey),
    checkHardwareRootForToolCall: () => health,
    hardwareRootInfo: () => ({ status: health.allowed ? "CLEAN" : "DIRTY" }),
    closeHardwareRootSession: () => {},
    ...fwExtra,
  };
  // A throwaway Claude Code config dir holding a login: never the real ~/.claude.
  const claudeDir = path.join(sb.dir, "claude-config");
  fs.mkdirSync(claudeDir, { recursive: true });
  // The person's own plain Claude Code login: never Enclawed Code's, never touched.
  fs.writeFileSync(path.join(claudeDir, ".credentials.json"), PERSON_LOGIN);
  // The session's Claude Code login, as Claude Code's own /login inside an earlier session left it
  // in Enclawed Code's login directory (claude-login.mjs): Enclawed Code never reads it.
  fs.mkdirSync(claudeLoginDir(sb.env), { recursive: true, mode: 0o700 });
  fs.writeFileSync(sessionLoginFile(), SESSION_LOGIN, { mode: 0o600 });
  if (policyDoc) {
    fs.mkdirSync(path.join(sb.home, ".enclawed", "claude-code"), { recursive: true });
    fs.writeFileSync(path.join(sb.home, ".enclawed", "claude-code", "enclawed.json"), JSON.stringify(policyDoc));
  }
  const env = { ...sb.env, CLAUDE_CONFIG_DIR: claudeDir, FAKE_CLAUDE_SLEEP_MS: "20000", ...extraEnv };
  // A headless launch with the device: the device unlock `auth unlock` issues after the device's code (one factor).
  if (ticket && totpDev) {
    const { deviceOnlyUnlock, deviceTotpSeam } = await import("../src/device-activation.mjs");
    await deviceOnlyUnlock({ seam: deviceTotpSeam(fwExtra), readCode: async () => totpDev.code(), uses: 1, minutes: 10, env: sb.env });
  } else if (ticket) {
    issueTestTicket(sb);
  }
  const plan = prepareLaunch(["-p", "x"], { env, cwd: sb.project });
  assert.equal(plan.ok, true, plan.message);
  const lines = [];
  if (afterMs !== null) {
    setTimeout(() => {
      health = { allowed: false, code: "hardware-dirty", reason: "hardware root DIRTY: device removed" };
    }, afterMs);
  }
  const t0 = Date.now();
  const code = await launchSession(plan, {
    env,
    cwd: sb.project,
    stderr: { write: (t) => lines.push(t) },
    load: async () => ({ fw }),
    hold: async () => ({ mode: "held", reason: null, notes: [], release: () => {} }),
    interactive: false,
    ...(containmentFor ? { containmentFor } : {}),
  });
  return { code, ms: Date.now() - t0, claudeDir, sealedFile: sessionLoginFile(), stderr: lines.join("") };
}

test("hardware halt mid-session: claude stopped first, the session's Claude Code login storage erased without Enclawed Code ever reading it, verified gone, audited without the secret, exit 4", async () => {
  // Every read of the session's login directory by the launcher (this process) is recorded.
  const { result: r, reads } = await readsUnder([claudeLoginDir(sb.env)], () => haltedLaunch());
  assert.equal(r.code, 4, r.stderr);
  assert.ok(r.ms < 15000, "claude was stopped, not waited for");
  assert.deepEqual(reads, [], "Enclawed Code read the session's Claude Code login");
  // The person's own plain login is untouched; the halt erases the session's own login storage.
  assert.equal(fs.readFileSync(path.join(r.claudeDir, ".credentials.json"), "utf8"), PERSON_LOGIN);
  assert.equal(fs.existsSync(r.sealedFile), false, "the session's Claude Code login was erased on the halt");
  assert.deepEqual(fs.existsSync(claudeLoginDir(sb.env)) ? fs.readdirSync(claudeLoginDir(sb.env)) : [], []);
  const rec = auditRecords(sb).find((x) => x.type === "hardware.halt.credentials-erased");
  assert.ok(rec);
  assert.deepEqual(rec.payload.remaining, []);
  assert.ok(rec.payload.erased.includes(`file ${r.sealedFile}`), JSON.stringify(rec.payload.erased));
  assert.match(r.stderr, /your own Claude Code login \(outside Enclawed Code\) was not touched/);
  assert.ok(!JSON.stringify(auditRecords(sb)).includes("sk-ant-oat01-test-only"), "the secret is never recorded");
  assert.match(r.stderr, /recover-root/);
  assert.ok(auditRecords(sb).some((x) => x.type === "claude-code.auth.attempt" && x.payload.outcome === "verified"));
});

test("command set (attack): with the root required, a held Enclaweder that does not prove command set 0.5 (firmware 0.3.1, or an owner claiming it, or no proof) refuses the launch before activation, naming the reflash runbook; claude never starts", async () => {
  for (const [what, proof, code] of [
    ["firmware 0.3.1 / an owner saying so", { status: "older", reason: "the device answered ANCHOR_READ as unsupported (firmware before command set 0.5)" }, "firmware-too-old"],
    ["no proof", { status: "unproven", reason: "the ANCHOR_READ answer is not signed over this process's nonce" }, "firmware-unproven"],
  ]) {
    let asked = 0;
    const r = await haltedLaunch({
      afterMs: null,
      ticket: false,
      fwExtra: { hardwareRootCommandSet: async () => (asked++, proof) },
      extraEnv: { ENCLAWEDER_ROOT: "required", FAKE_CLAUDE_SLEEP_MS: "0" },
    });
    assert.equal(r.code, 4, `${what}: ${r.stderr}`);
    assert.equal(asked, 1, what);
    assert.match(r.stderr, /firmware 0\.3\.3/, what);
    const recs = auditRecords(sb);
    const refused = recs.filter((x) => x.type === "claude-code.launch.refused").at(-1);
    assert.deepEqual(refused.payload, { reason: "command-set", code, proof: proof.status }, what);
    // Refused before activation: no second factor was asked, nothing was spent, claude never ran.
    assert.ok(!recs.some((x) => x.type === "claude-code.launch"), what);
  }
});

test("command set: without the root required, an older device runs and the launch record names what it leaves open", async () => {
  const r = await haltedLaunch({
    afterMs: null,
    fwExtra: { hardwareRootCommandSet: async () => ({ status: "older", reason: "unsupported" }) },
    extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" },
  });
  const launch = auditRecords(sb).filter((x) => x.type === "claude-code.launch").at(-1);
  assert.ok(launch, r.stderr);
  const { framework: real } = await import("../src/kit.mjs");
  assert.ok(launch.payload.residuals.includes(real.KEY_DERIVE_RESIDUAL), JSON.stringify(launch.payload.residuals));
  // The simulated device predates KEY_DERIVE: the login key is the CHALLENGE one, said so.
  assert.equal(launch.payload.keyDerivation, "challenge");
});

test("anchor (attack): a held device that the kit finds cannot anchor with authentication refuses the launch; claude never starts", async () => {
  const { fw: real } = await loadFramework();
  const bare = { anchorSet: async () => null, anchorGet: async () => null };
  for (const [what, decide, code] of [
    // Only the bare ANCHOR_SET (any process of the user could anchor a log of its choosing).
    ["bare set", kitSessionAnchor(real, bare, Buffer.alloc(32, 1)), "anchor-unauthenticated"],
    // Nothing to anchor with (the device is not CLEAN, or nothing relays it).
    ["no anchor", kitSessionAnchor(real, {}, Buffer.alloc(32, 1)), "anchor-unavailable"],
  ]) {
    const r = await haltedLaunch({ afterMs: null, fwExtra: { requireHardwareRootSessionAnchor: decide }, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
    assert.equal(r.code, 6, `${what}: ${r.stderr}`);
    assert.match(r.stderr, /cannot anchor this log with an authenticated anchor session/, what);
    const refused = auditRecords(sb).filter((x) => x.type === "claude-code.launch.refused").at(-1);
    assert.equal(refused.payload.code, "anchor-unauthenticated", what);
    assert.equal(refused.payload.anchorRefused.code, code, what);
  }
  assert.ok(!auditRecords(sb).some((x) => x.type === "claude-code.session.start"), "claude ran");
});

// ------------------------------------------------------------------ N7b
// A helper started by the session double-forks with setsid, clears its
// environment (so it carries no session marker) and waits for the erase to
// write Claude Code's login back. With the device bound, the session's login
// is in Enclawed Code's login directory, and the halt erases it; so the helper
// keeps a copy of it (any process of the user can read the file) and writes it
// back once it is gone. No systemd scope here (the suite runs without a user
// bus), and the launcher's re-checks and detached watcher are turned off, so
// the only thing that can stop it is the halt's kill.
const n7bHelper = (sealed, wait = "") =>
  `( setsid env -i PATH=/usr/bin:/bin F='${sealed}' C="$(cat '${sealed}')" ` +
  `sh -c 'while [ -e "$F" ]; do sleep 0.1; done; sleep 0.5; printf %s "$C" > "$F"; touch "$F.restored"' & ${wait}); sleep 30`;

test("N7b (attack): a double-forked, setsid, env-cleared helper is killed before the erase, and nothing writes the login back", async () => {
  setTestAuthority({ eraseRechecks: 0, eraseWatchS: 0 });
  const sealed = sessionLoginFile();
  const r = await haltedLaunch({ extraEnv: { FAKE_CLAUDE_HELPER_SH: n7bHelper(sealed) } });
  assert.equal(r.code, 4, r.stderr);
  assert.equal(r.sealedFile, sealed);
  await new Promise((res) => setTimeout(res, 3000));
  assert.equal(fs.existsSync(`${sealed}.restored`), false, "the escaped helper ran after the erase");
  assert.equal(fs.existsSync(sealed), false, "the sealed login was written back");
  assert.equal(fs.readFileSync(path.join(r.claudeDir, ".credentials.json"), "utf8"), PERSON_LOGIN, "the person's own login is untouched");
  const rec = auditRecords(sb).find((x) => x.type === "hardware.halt.credentials-erased");
  assert.equal(rec.payload.contained.verified, true, JSON.stringify(rec.payload.contained));
  assert.ok(rec.payload.contained.killed >= 1, "the helper was among the killed");
  assert.match(r.stderr, /every process of the session was stopped before the erase/);
});

test("N7b (FP): a process of the same user outside the session survives the halt", async () => {
  setTestAuthority({ eraseRechecks: 0, eraseWatchS: 0 });
  const { spawn } = await import("node:child_process");
  const outsider = spawn("sleep", ["30"], { detached: true, stdio: "ignore", env: { PATH: process.env.PATH } });
  outsider.unref();
  try {
    const r = await haltedLaunch();
    assert.equal(r.code, 4, r.stderr);
    assert.doesNotThrow(() => process.kill(outsider.pid, 0), "an unrelated process of the user was killed");
  } finally {
    try {
      process.kill(outsider.pid, "SIGKILL");
    } catch {
      /* gone */
    }
  }
});

test("N7b (FP): the subreaper wrapper is transparent: same pid, argv, exit code and signal; a double-forked child stays in claude's tree", async () => {
  const { sessionContainment } = await import("../src/containment.mjs");
  const c = sessionContainment(process.env, { scope: false });
  assert.equal(c.reaper, true, "python3 or perl is available on the test machine");
  const { spawn } = await import("node:child_process");
  const run = (script, ...args) =>
    new Promise((res) => {
      const [cmd, a] = c.command("sh", ["-c", script, "sh", ...args]);
      const ch = spawn(cmd, a, { stdio: ["ignore", "pipe", "inherit"] });
      let out = "";
      ch.stdout.on("data", (d) => (out += d));
      ch.on("exit", (code, signal) => res({ code, signal, out, pid: ch.pid }));
    });
  const a = await run('echo "$$ $1 $2"; exit 7', "one", "two words");
  assert.equal(a.code, 7);
  assert.equal(a.out.trim(), `${a.pid} one two words`);
  const b = await run("kill -TERM $$");
  assert.equal(b.signal, "SIGTERM");
  // The grandchild of a double fork is re-parented to the wrapped process, not to init.
  const d = await run("(setsid sleep 3 &); sleep 0.3; ps -o ppid= -C sleep | tr -d ' ' | grep -x $$ >/dev/null && echo adopted; pkill -P $$ sleep");
  assert.equal(d.out.trim(), "adopted");
});

test("N7b (attack): a sibling of claude made with clone(CLONE_PARENT) and a cleared environment is killed by the launcher's own-children sweep", { skip: process.arch !== "x64" || process.platform !== "linux" }, async () => {
  const { killSession, sessionContainment, procStartTime } = await import("../src/containment.mjs");
  const { spawn } = await import("node:child_process");
  const c = sessionContainment(process.env, { scope: false });
  const canary = path.join(sb.dir, "clone-parent-canary");
  // "claude": clones a child whose parent is claude's parent (this process), which then
  // execs with an empty environment and writes the canary later.
  const py = `import ctypes,os,time
l=ctypes.CDLL(None,use_errno=True)
pid=l.syscall(56, 0x8000|17, 0, 0, 0, 0)
if pid==0:
    os.execve("/bin/sh", ["sh","-c","sleep 2; touch ${canary}"], {})
time.sleep(30)`;
  const [cmd, a] = c.command("python3", ["-I", "-S", "-c", py]);
  const claude = spawn(cmd, a, { stdio: "ignore", env: { ...process.env, ...c.env } });
  c.startedAfter = procStartTime(claude.pid);
  await new Promise((res) => setTimeout(res, 600));
  const r = await killSession(claude.pid, c, { launcherChildren: true });
  assert.equal(r.verified, true, JSON.stringify(r));
  await new Promise((res) => setTimeout(res, 2500));
  assert.equal(fs.existsSync(canary), false, "the CLONE_PARENT sibling survived");
});

// ------------------------------------------------------------------ attack 7 (device-verified activation)
// The attacker (a process of this user, outside the agent) rewrote the factor
// store with its own credential and signed its own unlock ticket
// (issueTestTicket is exactly that: a ticket from a key on this host). With an
// Enclaweder held, the launch also needs the device's signed verdict.

const codeOf = (c) => (typeof c === "object" && c !== null ? c.code : c);

/**
 * A person's unlock for these tests: one ticket (signed by the enrolled test
 * key) and the job a device unlock of more than one launch is bound to (this
 * install's measured code, the effective policy, the test project, -p).
 */
async function personUnlock({ uses }) {
  const { fw } = await loadFramework();
  const { currentEffectivePolicy, launchJob, measureLaunch } = await import("../src/commitments.mjs");
  const body = await deviceTicket({ uses });
  const job = launchJob({ name: "ci", measurementDigest: measureLaunch().digest, policyDigest: currentEffectivePolicy(fw, sb.env).digest, projectDir: sb.project, kind: "headless:print" });
  return { ticket: { body }, job };
}

/** A ticket in the device-code factor store, signed by this installation's ticket signer (as `auth unlock` signs it with a device). */
async function deviceTicket({ uses = 1, body = null } = {}) {
  const { deviceTicketSigner } = await import("../src/device-activation.mjs");
  const { signDemoTicket } = await import("../src/demo-credential.mjs");
  return signDemoTicket(await deviceTicketSigner(sb.env), { uses, ...(body ? { body } : {}) });
}

async function totpDevice() {
  const { SimTotpDevice, totpFramework } = await import("./fixtures/totp-sim.mjs");
  const dev = new SimTotpDevice();
  return { dev, fwExtra: totpFramework(dev) };
}

test("attack 7 (attack): with an Enclaweder, a relaunch with the attacker's own credential and ticket but no device-verified unlock is refused, and claude never starts", async () => {
  const { fwExtra } = await totpDevice();
  // The attacker's own ticket on the host (a key of its own) does not start it ...
  const host = await haltedLaunch({ afterMs: null, fwExtra, ticket: false, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
  assert.equal(host.code, 5, host.stderr);
  // ... nor one signed with this installation's ticket signer (any process of the user can read it): no device grant.
  await deviceTicket();
  const r = await haltedLaunch({ afterMs: null, fwExtra, ticket: false, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
  assert.equal(r.code, 5, r.stderr);
  assert.match(r.stderr, /needs a device unlock/);
  assert.ok(auditRecords(sb).some((x) => x.type === "claude-code.auth.device-factor" && x.payload.outcome === "refused" && x.payload.code === "no-grant"));
  assert.ok(!auditRecords(sb).some((x) => x.type === "claude-code.session.start"), "claude ran");
});

test("attack 7 (attack): a forged, edited or re-purposed device unlock does not start a headless launch", async () => {
  const { deviceTotpSeam, grantFile, issueGrant } = await import("../src/device-activation.mjs");
  const { dev, fwExtra } = await totpDevice();
  const env = sb.env;
  const seam = deviceTotpSeam(fwExtra);
  const unlock = await personUnlock({ uses: 2 });
  await issueGrant({ seam, readCode: async () => dev.code(), minutes: 30, uses: 2, env, ...unlock });
  const genuine = JSON.parse(fs.readFileSync(grantFile(env), "utf8"));
  const tries = [];
  // Edited to name another grant on the device, or another program's scope.
  tries.push(["other grant id", { ...genuine, gid: String(BigInt(genuine.gid) + 1n) }, /holds another unlock/]);
  // The stored `scope` only records the binding: the device holds it, and the scope of a spend is
  // computed from the PRESENTED ticket and the launch's own job (kit spendDeviceUnlock). A grant
  // edited to lend another job's name names another scope, which the device refuses.
  tries.push(["other job", { ...genuine, job: { ...genuine.job, name: "other-job" } }, /holds another unlock/]);
  // Forged: made with the attacker's own key, as if from another device.
  const fake = generateKeyPairSync("ed25519");
  tries.push(["forged", { ...genuine, devicePub: Buffer.from(fake.publicKey.export({ format: "jwk" }).x, "base64url").toString("hex") }, /another Enclaweder/]);
  // Re-purposed: a genuine interactive session-start verdict is no device unlock.
  const nonce = Buffer.alloc(32, 7);
  dev.lastStep = 0;
  const sv = await fwExtra.deviceTotpVerdict(dev.access(), { code: dev.code(Date.now() / 1000 + 30), purpose: "session-start", nonce });
  tries.push(["session-start verdict", sv.record, /needs a device unlock/]);
  for (const [what, g, re] of tries) {
    fs.writeFileSync(grantFile(env), JSON.stringify(g));
    await deviceTicket({ uses: 2, body: unlock.ticket.body });
    const r = await haltedLaunch({ afterMs: null, fwExtra, ticket: false, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
    assert.equal(r.code, 5, `${what}: ${r.stderr}`);
    assert.match(r.stderr, re, what);
  }
});

test("attack 7 (FP): after one interactive device-verified unlock, headless (CI-like) launches run until the uses run out", async () => {
  const { deviceTotpSeam, issueGrant } = await import("../src/device-activation.mjs");
  const { dev, fwExtra } = await totpDevice();
  const unlock = await personUnlock({ uses: 3 });
  await issueGrant({ seam: deviceTotpSeam(fwExtra), readCode: async () => dev.code(), minutes: 30, uses: 2, env: sb.env, ...unlock });
  for (let i = 0; i < 2; i++) {
    const r = await haltedLaunch({ afterMs: null, fwExtra, ticket: false, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
    assert.equal(codeOf(r.code), 0, `launch ${i + 1}: ${r.stderr}`);
  }
  const third = await haltedLaunch({ afterMs: null, fwExtra, ticket: false, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
  assert.equal(third.code, 5, third.stderr);
  assert.match(third.stderr, /holds no live unlock \(its uses ran out/);
  assert.equal(auditRecords(sb).filter((x) => x.type === "claude-code.auth.device-factor" && x.payload.via === "device-unlock" && x.payload.outcome === "verified").length, 2);
});

test("attack 7 (attack): a large unlock does not start a launch outside its job, nor with the attacker's own ticket", async () => {
  const { deviceTotpSeam, issueGrant } = await import("../src/device-activation.mjs");
  const { dev, fwExtra } = await totpDevice();
  const unlock = await personUnlock({ uses: 10 });
  await issueGrant({ seam: deviceTotpSeam(fwExtra), readCode: async () => dev.code(), minutes: 30, uses: 10, env: sb.env, ticket: unlock.ticket, job: { ...unlock.job, kind: "headless" } });
  // The job is a non-print headless run: this -p launch is outside it.
  const r = await haltedLaunch({ afterMs: null, fwExtra, ticket: false, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
  assert.equal(r.code, 5, r.stderr);
  // The attacker's own ticket (another nonce, as signed by a key on this host): refused too.
  await deviceTicket({ uses: 10 });
  const own = await haltedLaunch({ afterMs: null, fwExtra, ticket: false, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
  assert.equal(own.code, 5, own.stderr);
  assert.ok(!auditRecords(sb).some((x) => x.type === "claude-code.session.start"), "claude ran");
});

test("one factor: with the Enclaweder held but a framework build that cannot ask it for a code, the launch is refused, saying so; the passkey or key is never asked instead", async () => {
  const r = await haltedLaunch({ afterMs: null, deviceTotp: false, extraEnv: { FAKE_CLAUDE_SLEEP_MS: "0" } });
  assert.equal(r.code, 5, r.stderr);
  assert.match(r.stderr, /cannot ask the Enclaweder to check an authenticator code\. With an Enclaweder attached its authenticator code is the only factor, so your passkey or security key is not asked instead/);
  assert.ok(!auditRecords(sb).some((x) => x.type === "claude-code.session.start"), "claude ran");
});

test("the credential erase can be turned off in Enclawed Code's own policy block", async () => {
  const r = await haltedLaunch({ policyDoc: { enclawed: { policy: {} }, enclawedCode: { onHardwareHalt: { eraseClaudeCredentials: false } } } });
  assert.equal(r.code, 4, r.stderr);
  // The session's Claude Code login is kept; the person's own login is untouched either way.
  assert.equal(fs.existsSync(r.sealedFile), true, "the session's login was kept");
  assert.equal(fs.readFileSync(path.join(r.claudeDir, ".credentials.json"), "utf8"), PERSON_LOGIN);
  assert.match(r.stderr, /the session's Claude Code login was kept \(onHardwareHalt\.eraseClaudeCredentials is false\)/);
});

test("held root with no attestable device: the launcher refuses to start (red-team H15)", async () => {
  const { fw: real } = await loadFramework();
  const fw = { ...real, ...NO_DEVICE_TOTP, attestHardwareRoot: undefined, hardwareRootSigningDevice: () => null, checkHardwareRootForToolCall: () => ({ allowed: true }), hardwareRootInfo: () => ({ status: "CLEAN" }), closeHardwareRootSession: () => {} };
  const claudeDir = path.join(sb.dir, "claude-config-h15");
  fs.mkdirSync(claudeDir);
  const env = { ...sb.env, CLAUDE_CONFIG_DIR: claudeDir };
  issueTestTicket(sb);
  const plan = prepareLaunch(["-p", "x"], { env, cwd: sb.project });
  assert.equal(plan.ok, true, plan.message);
  const lines = [];
  const code = await launchSession(plan, {
    env,
    cwd: sb.project,
    stderr: { write: (t) => lines.push(t) },
    load: async () => ({ fw }),
    hold: async () => ({ mode: "held", reason: null, notes: [], release: () => {} }),
    interactive: false,
  });
  assert.equal(code, 4, lines.join(""));
  assert.match(lines.join(""), /could not be attested/);
});

test("member attestation: every member is checked, and the set must be the one bound at launch (red-team H15)", async () => {
  const { fw } = await loadFramework();
  if (typeof fw.verifyRootMembers !== "function") {
    return; // an older framework: only single-device attestation exists
  }
  const { checkMemberAttestation } = await import("../src/device.mjs");
  // No simulated member has a pinned manufacturer certificate: refused before anything else.
  const att = { nonces: ["ab".repeat(32)], members: [{ uid: "07".repeat(12), pubkey: "11".repeat(32), cert: "00".repeat(119), latch: "00" }] };
  assert.match(checkMemberAttestation(fw, { nonce: "ab".repeat(32), attestation: att, pinnedPubs: ["11".repeat(32)] }), /manufacturer certificate/);
  assert.match(checkMemberAttestation(fw, { nonce: "ab".repeat(32), attestation: { members: [] }, pinnedPubs: null }), /no attestation/);
});

// Settings audit, Table 2 rows 5-6: no containment under a hardware root is
// refused, not warned on, unless the administrator accepted it.
const noContainment = (env) => sessionContainment(env, { scope: false, reaper: null });

test("containment (attack): a hardware-root session where neither the subreaper nor a scope is available is refused", async () => {
  const r = await haltedLaunch({ afterMs: null, containmentFor: noContainment });
  assert.equal(r.code, EXIT_HARDWARE_HALT, r.stderr);
  assert.match(r.stderr, /not starting: neither a cgroup scope nor a subreaper nor process tracking is available.*systemd user scope.*the subreaper wrapper/);
  assert.match(r.stderr, /"reducedContainment": true/);
  assert.ok(auditRecords(sb).some((x) => x.type === "claude-code.launch.refused" && x.payload.reason === "no-containment"));
});

test("containment (FP, macOS): process tracking counts as containment: a hardware-root session without subreaper or scope starts without a grant, and the halt kills an escaped helper", async () => {
  const { processTracker, psTable } = await import("../src/containment.mjs");
  setTestAuthority({ ...sb.authority, eraseRechecks: 0, eraseWatchS: 0 });
  const tracked = (env) => sessionContainment(env, { scope: false, reaper: null, tracker: processTracker({ table: psTable, intervalMs: 50 }) });
  // The helper keeps its parent alive 0.5 s (the tracker sees it), then escapes like N7b.
  const sealed = sessionLoginFile();
  const r = await haltedLaunch({ containmentFor: tracked, extraEnv: { FAKE_CLAUDE_HELPER_SH: n7bHelper(sealed, "sleep 0.5 ") } });
  assert.equal(r.code, 4, r.stderr);
  assert.doesNotMatch(r.stderr, /not starting: neither/);
  await new Promise((res) => setTimeout(res, 2500));
  assert.equal(fs.existsSync(`${sealed}.restored`), false, "the escaped helper was killed before the erase");
  assert.equal(fs.existsSync(sealed), false, "the sealed login was written back");
  const rec = auditRecords(sb).filter((x) => x.type === "hardware.halt.credentials-erased").at(-1);
  assert.equal(rec.payload.contained.mode, "tracked+marker");
  assert.equal(rec.payload.contained.verified, true);
});

test("containment (FP): with reducedContainment granted by the root-owned file it starts, with a warning; with containment it starts without one", async () => {
  sb.grant({ reducedContainment: true });
  setTestAuthority({ ...sb.authority, eraseRechecks: 0, eraseWatchS: 0 });
  let r = await haltedLaunch({ afterMs: 800, containmentFor: noContainment });
  assert.equal(r.code, 4, r.stderr);
  assert.match(r.stderr, /started anyway because .* sets reducedContainment/);
  sb.grant(null);
  r = await haltedLaunch({ afterMs: 800 });
  assert.equal(r.code, 4, r.stderr);
  assert.doesNotMatch(r.stderr, /neither a cgroup scope/);
});
