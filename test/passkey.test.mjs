import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// Device-bound passkeys as Enclawed Code's second factor (Windows Hello on a
// TPM, Apple's or Android's secure hardware), beside FIDO2 security keys.
// Every check is the kit's (enrollPasskey, assertSecondFactor,
// unlockForHeadlessStart, activateSession); Enclawed Code only hands the kit
// its state dir, RP id and audit log, and the kit opens its own page. Here
// the page is the passkey test double (test/fixtures/passkey-double.mjs),
// which answers in the browser's wire format with a software key, so the
// kit's policy runs end to end: attestation at enrollment, UP and UV on every
// use, synced (backup-eligible) passkeys refused, the counter rule and the
// TPM counter exemption only with its proof.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { AuthError, ENROLL_STEPS, METHODS, launchAuthContext, readAuthState, verifyUser } from "../src/auth.mjs";
import { authCommand } from "../src/auth-cli.mjs";
import { UsageError } from "../src/cli-util.mjs";
import { activationOptions } from "../src/device-activation.mjs";
import { framework, kit } from "../src/kit.mjs";
import { FLAGS, PasskeyDouble, TPM_SURFACE_PRO_4_ATTESTATION_OBJECT } from "./fixtures/passkey-double.mjs";
import { sandbox } from "./helpers.mjs";

let sb;
let records;
let pk;
const audit = async (r) => {
  records.push(r);
};
const factorsFile = () => path.join(sb.home, ".enclawed", "claude-code", "auth", "factors.json");
const lastRefusal = () => records.findLast((r) => r.payload?.outcome === "refused")?.payload?.code;
const sink = () => {
  let text = "";
  return { write: (s) => ((text += s), true), get text() { return text; } };
};
/** `ecwctl auth ...` at a terminal, with the passkey double as the page. */
async function auth(args, { passkey = pk, interactive = true, securityKeys = () => ({ tools: false, keys: 0 }), choose = null } = {}) {
  const out = sink();
  const err = sink();
  const code = await authCommand(args, { out, err, env: sb.env, audit, interactive, passkey: passkey.ceremony, securityKeys, choose });
  return { code, out: out.text, err: err.text };
}
const check = (purpose, extra = {}) => verifyUser({ purpose, env: sb.env, interactive: true, audit, allowTicket: false, passkey: pk.ceremony, say: () => {}, ...extra });

before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());
beforeEach(() => {
  // Passkey only: no security key enrolled, so the kit asks the passkey.
  fs.rmSync(path.dirname(factorsFile()), { recursive: true, force: true });
  records = [];
  pk = new PasskeyDouble();
});

test("passkeys are an accepted method, and the enrollment steps name them", () => {
  assert.deepEqual(METHODS, ["fido2", "passkey"]);
  assert.match(ENROLL_STEPS, /This computer's passkey .*\n  ecwctl auth enroll\n/);
  assert.match(ENROLL_STEPS, /Or a FIDO2 security key/);
  assert.match(ENROLL_STEPS, /synced passkey is refused/);
});

test("auth enroll --passkey enrolls this device's passkey through the kit, and it passes every second-factor check", async () => {
  const r = await auth(["enroll", "--passkey", "--label", "laptop"]);
  assert.equal(r.code, 0);
  assert.match(r.out, /enrolled laptop .*device-bound passkey, packed attestation/);
  assert.match(r.out, /Enroll a backup, since a passkey dies with this device: this account's passkey on another device you sign in from \(ecwctl auth enroll there\), or a FIDO2 security key here/);
  assert.deepEqual(pk.requests.map((q) => q.kind), ["create"]);
  const store = JSON.parse(fs.readFileSync(factorsFile(), "utf8"));
  assert.equal(store.credentials.length, 1);
  assert.equal(store.credentials[0].kind, "passkey");
  assert.deepEqual(readAuthState(sb.env), { method: "passkey", keys: 1, securityKeys: 0, passkeys: 1, failures: 0, lockedUntil: null });
  assert.ok(records.some((x) => x.type === "claude-code.auth.enroll" && x.payload.outcome === "enrolled" && x.payload.fmt === "packed"));

  // Sensitive commands (each purpose Enclawed Code gates) accept the passkey.
  for (const purpose of ["history-restore", "audit-accept", "recover-root", "policy-change", "policy-erase-off", "test"]) {
    assert.deepEqual(await check(purpose), { method: "passkey", via: "passkey" });
  }
  assert.equal(JSON.parse(fs.readFileSync(factorsFile(), "utf8")).credentials[0].signCount, 6);
  // `auth test` and `auth status`.
  assert.equal((await auth(["test"])).out, "verified\n");
  const st = await auth(["status"]);
  assert.match(st.out, /0 security key\(s\) and 1 device-bound passkey\(s\) enrolled/);
  assert.match(st.out, /laptop {2}passkey \(packed\) {2}counter 7/);
});

test("a launch at a terminal activates with the passkey, through the launcher's composition (launchAuthContext + kit.activateSession)", async () => {
  await auth(["enroll", "--passkey"]);
  const ctx = await launchAuthContext({ env: sb.env, interactive: true, audit, passkey: pk.ceremony });
  const a = await kit.activateSession({ ...ctx, say: () => {} }, activationOptions({ fw: framework, env: sb.env, held: false, interactive: true }));
  assert.equal(a.via, "passkey");
  assert.equal(a.device, null);
  assert.ok(records.some((x) => x.type === "claude-code.auth.attempt" && x.payload.outcome === "verified" && x.payload.via === "passkey" && x.payload.purpose === "session-start"));
});

test("auth unlock: the passkey signs the ticket a headless launch spends (and a sensitive command never takes it)", async (t) => {
  if (!fs.existsSync("/proc/sys/kernel/random/boot_id")) {
    t.skip("no boot id on this platform");
    return;
  }
  await auth(["enroll", "--passkey"]);
  const u = await auth(["unlock", "--minutes", "5", "--uses", "1"]);
  assert.equal(u.code, 0);
  assert.match(u.out, /ticket signed by your passkey or security key/);
  assert.equal(pk.requests.at(-1).kind, "get");
  const ctx = await launchAuthContext({ env: sb.env, interactive: false, audit });
  const a = await kit.activateSession(ctx, activationOptions({ fw: framework, env: sb.env, held: false, interactive: false }));
  assert.equal(a.via, "ticket");
  await assert.rejects(kit.activateSession(ctx, activationOptions({ fw: framework, env: sb.env, held: false, interactive: false })), (e) => e.code === "no-ticket");
  await assert.rejects(verifyUser({ purpose: "recover-root", env: sb.env, interactive: false, audit, allowTicket: false }), (e) => e instanceof AuthError && e.code === "headless");
});

test("a synced (backup-eligible) passkey is refused at enrollment and at every use", async () => {
  pk.flags = FLAGS.UP | FLAGS.UV | FLAGS.BE;
  await assert.rejects(auth(["enroll", "--passkey"]), (e) => e instanceof AuthError && e.code === "verification-failed");
  assert.equal(lastRefusal(), "backup-eligible");
  assert.equal(readAuthState(sb.env), null);
  // Enrolled device-bound, later answering as synced: refused, and the genuine answer still passes.
  pk.flags = FLAGS.UP | FLAGS.UV;
  await auth(["enroll", "--passkey"]);
  pk.flags = FLAGS.UP | FLAGS.UV | FLAGS.BE;
  await assert.rejects(check("policy-change"), (e) => e.code === "verification-failed");
  assert.equal(lastRefusal(), "backup-eligible");
  pk.flags = FLAGS.UP | FLAGS.UV;
  assert.equal((await check("policy-change")).via, "passkey");
});

test("user presence and user verification are required on every use", async () => {
  pk.flags = FLAGS.UP;
  await assert.rejects(auth(["enroll", "--passkey"]), (e) => e.code === "verification-failed");
  assert.equal(lastRefusal(), "no-user-verification");
  pk.flags = FLAGS.UP | FLAGS.UV;
  await auth(["enroll", "--passkey"]);
  for (const [flags, code] of [
    [FLAGS.UP, "no-user-verification"],
    [FLAGS.UV, "no-user-presence"],
  ]) {
    pk.flags = flags;
    await assert.rejects(check("history-restore"), (e) => e.code === "verification-failed");
    assert.equal(lastRefusal(), code);
  }
  pk.flags = FLAGS.UP | FLAGS.UV;
  assert.equal((await check("history-restore")).via, "passkey");
});

test("the counter is strict, and a stored TPM counter exemption counts only with its verified proof", async () => {
  await auth(["enroll", "--passkey"]);
  pk.counterStep = 0;
  await assert.rejects(check("policy-change"), (e) => e.code === "verification-failed");
  assert.equal(lastRefusal(), "counter-unsupported");
  // A store claiming the exemption, with nothing or with a genuine Windows Hello TPM
  // statement of another credential: tampering, refused.
  for (const extra of [
    { counterPolicy: "tpm-non-exportable" },
    {
      counterPolicy: "tpm-non-exportable",
      tpmCounterEvidence: { attestationObject: Buffer.from(TPM_SURFACE_PRO_4_ATTESTATION_OBJECT, "base64").toString("base64url"), clientDataHash: Buffer.alloc(32).toString("base64url") },
    },
  ]) {
    const st = JSON.parse(fs.readFileSync(factorsFile(), "utf8"));
    st.credentials[0] = { ...st.credentials[0], ...extra };
    fs.writeFileSync(factorsFile(), JSON.stringify(st));
    await assert.rejects(check("policy-change"), (e) => e.code === "verification-failed");
    assert.equal(lastRefusal(), "attestation-invalid");
  }
});

test("auth enroll: --passkey takes no --alg, needs a terminal, and the retired windows-hello method points to it", async () => {
  await assert.rejects(auth(["enroll", "--passkey", "--alg", "es256"]), (e) => e instanceof UsageError && /--alg applies to security keys/.test(e.message));
  await assert.rejects(auth(["enroll", "--passkey", "--method", "fido2"]), (e) => e instanceof UsageError);
  await assert.rejects(auth(["enroll", "--method", "windows-hello"]), (e) => e instanceof UsageError && /auth enroll --passkey/.test(e.message));
  await assert.rejects(auth(["enroll", "--method", "macos"]), (e) => e instanceof UsageError && /device-bound passkey/.test(e.message));
  await assert.rejects(auth(["enroll", "--passkey"], { interactive: false }), (e) => e instanceof AuthError && e.code === "headless");
  assert.equal(pk.requests.length, 0);
  // --method passkey is the same as --passkey.
  assert.equal((await auth(["enroll", "--method", "passkey"])).code, 0);
  assert.equal(readAuthState(sb.env).method, "passkey");
});

test("a second passkey: adding it needs the enrolled factor first, and both count", async () => {
  await auth(["enroll", "--passkey", "--label", "first"]);
  const second = new PasskeyDouble();
  // The enrolled passkey proves the existing factor; the new one answers the create.
  const both = { ceremony: async (req, say) => (req.kind === "create" ? second.ceremony(req, say) : pk.ceremony(req, say)) };
  const r = await auth(["enroll", "--passkey", "--label", "second"], { passkey: both });
  assert.equal(r.code, 0);
  assert.match(r.out, /First confirm with a second factor that is already enrolled/);
  assert.equal(readAuthState(sb.env).passkeys, 2);
  assert.deepEqual(pk.requests.map((q) => q.kind), ["create", "get"]);
});

test("auth enroll with no method enrolls this computer's passkey at once (no question); --security-key / --fido2 are the alternative; with no terminal it names both; a launch and a headless unlock then use the passkey", async (t) => {
  const r = await auth(["enroll"]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /^Enrolling this computer's passkey \(for a FIDO2 security key instead: ecwctl auth enroll --security-key\)\./);
  assert.match(r.out, /enrolled passkey .*device-bound passkey, packed attestation/);
  assert.equal(readAuthState(sb.env).method, "passkey");
  const ctx = await launchAuthContext({ env: sb.env, interactive: true, audit, passkey: pk.ceremony });
  assert.equal((await kit.activateSession({ ...ctx, say: () => {} }, activationOptions({ fw: framework, env: sb.env, held: false, interactive: true }))).via, "passkey");
  await assert.rejects(auth(["enroll"], { interactive: false }), (e) => e instanceof AuthError && e.code === "headless" && /ecwctl auth enroll \(this computer's device-bound passkey.*\), or ecwctl auth enroll --security-key/.test(e.message));
  await assert.rejects(auth(["enroll", "--passkey", "--security-key"]), (e) => e instanceof UsageError);
  await assert.rejects(auth(["enroll", "--passkey", "--fido2"]), (e) => e instanceof UsageError);
  if (!fs.existsSync("/proc/sys/kernel/random/boot_id")) {
    t.skip("no boot id on this platform");
    return;
  }
  assert.equal((await auth(["unlock", "--minutes", "5", "--uses", "1"])).code, 0);
  const h = await launchAuthContext({ env: sb.env, interactive: false, audit });
  assert.equal((await kit.activateSession(h, activationOptions({ fw: framework, env: sb.env, held: false, interactive: false }))).via, "ticket");
});

test("without an Enclaweder the passkey is asked first even when a security key is enrolled too (the key is shown to the framework only when no passkey is enrolled)", async () => {
  const { frameworkAuthContext } = await import("../src/auth.mjs");
  await auth(["enroll"]);
  const store = JSON.parse(fs.readFileSync(factorsFile(), "utf8"));
  store.credentials.push({ ...store.credentials[0], id: "k0000001", kind: undefined, label: "key", credentialId: "a2V5" });
  fs.writeFileSync(factorsFile(), JSON.stringify(store));
  const verifying = frameworkAuthContext({ env: sb.env, audit, interactive: true, preferPasskey: true });
  assert.deepEqual(verifying.transport.listDevices(), []);
  assert.equal(frameworkAuthContext({ env: sb.env, audit, interactive: true }).transport, undefined, "enrolling a key still sees the keys");
});

test("one factor with an Enclaweder attached: only the code the device checks is asked (never the passkey too), for a sensitive command and a launch; an attached device that cannot check a code refuses, saying so", async () => {
  const { SimTotpDevice, totpFramework } = await import("./fixtures/totp-sim.mjs");
  const { activateLaunch, deviceTotpSeam } = await import("../src/device-activation.mjs");
  await auth(["enroll"]);
  const before = pk.requests.length;
  const dev = new SimTotpDevice();
  const fwT = { ...framework, ...totpFramework(dev) };
  const seam = deviceTotpSeam(fwT);
  const asked = [];
  const readCode = async (q) => (asked.push(q), dev.code());
  // A sensitive command.
  const r = await verifyUser({ purpose: "policy-change", env: sb.env, interactive: true, audit, allowTicket: false, passkey: pk.ceremony, device: seam, readCode, say: () => {} });
  assert.deepEqual(r, { method: "device", via: "device-totp" });
  assert.equal(pk.requests.length, before, "the passkey was not asked");
  assert.equal(asked.length, 1);
  // An interactive launch (held): the device's code alone.
  dev.lastStep = 0;
  const ctx = await launchAuthContext({ env: sb.env, interactive: true, audit, passkey: pk.ceremony, readCode });
  const a = await activateLaunch({ ...ctx, say: () => {} }, { fw: fwT, env: sb.env, held: true, interactive: true });
  assert.equal(a.via, "device-totp");
  assert.equal(pk.requests.length, before, "the passkey was not asked at launch either");
  assert.equal(asked.length, 2);
  assert.match(asked[1], /: $/);
  // Fail closed: attached but unable to check a code.
  dev.enrolled = false;
  await assert.rejects(verifyUser({ purpose: "policy-change", env: sb.env, interactive: true, audit, allowTicket: false, passkey: pk.ceremony, device: seam, readCode }), (e) => e.code === "device-factor-unavailable" && /no authenticator enrolled.*your passkey or security key is not asked instead/.test(e.message));
  await assert.rejects(activateLaunch(ctx, { fw: { ...framework, hardwareRootTotpDevice: undefined }, env: sb.env, held: true, interactive: true }), (e) => /cannot ask the Enclaweder to check an authenticator code\. With an Enclaweder attached its authenticator code is the only factor/.test(e.message));
  assert.equal(pk.requests.length, before);
  // No Enclaweder: the passkey alone.
  assert.deepEqual(await verifyUser({ purpose: "policy-change", env: sb.env, interactive: true, audit, allowTicket: false, passkey: pk.ceremony, device: false, say: () => {} }), { method: "passkey", via: "passkey" });
  assert.equal(pk.requests.length, before + 1);
});

test("the Enclaweder's clock and this computer's disagree (firmware 0.3.4, ERR_TIME): the person is told, never to unplug while the prompt holds the device", async () => {
  const { CLOCK_DISAGREES_TEXT, deviceCodeText, issueGrant } = await import("../src/device-activation.mjs");
  assert.equal(deviceCodeText("clock-disagrees"), "the Enclaweder's clock and this computer's disagree: check this computer's time, or cancel this prompt (Ctrl-C), unplug and replug the Enclaweder, then try again with a new code");
  assert.equal(deviceCodeText("clock-disagrees"), CLOCK_DISAGREES_TEXT);
  assert.match(deviceCodeText("wrong-code"), /did not verify an authenticator code \(wrong-code\)/);
  // A device unlock the device refuses with ERR_TIME (enclawed 2.0.1 maps status 10 to clock-disagrees).
  const seam = { access: () => ({}) };
  const stub = { ...kit, issueDeviceUnlock: async () => ({ ok: false, code: "clock-disagrees", message: "status 10" }) };
  const ticket = { credentialId: "x", nonce: "n", expiresAt: Date.now() + 60_000 };
  await assert.rejects(issueGrant({ seam, readCode: async () => "123456", minutes: 10, uses: 1, env: sb.env, ticket, k: stub }), (e) => e.code === "clock-disagrees" && e.message === CLOCK_DISAGREES_TEXT);
  // Another refusal keeps the framework's words.
  const other = { ...kit, issueDeviceUnlock: async () => ({ ok: false, code: "wrong-code", message: "the device refused the code" }) };
  await assert.rejects(issueGrant({ seam, readCode: async () => "123456", minutes: 10, uses: 1, env: sb.env, ticket, k: other }), (e) => e.message === "the device refused the code");
});
