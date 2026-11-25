// Device-verified activation (compromised-host attack 7, with an Enclaweder):
// src/device-activation.mjs against a simulated device (test/fixtures/totp-sim.mjs).
import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import fs from "node:fs";
import { deviceActivation, deviceTotpSeam, grantFile, issueGrant } from "../src/device-activation.mjs";
import { SimTotpDevice, totpFramework } from "./fixtures/totp-sim.mjs";
import { sandbox } from "./helpers.mjs";

let sb;
beforeEach(() => {
  sb = sandbox();
});
afterEach(() => sb.cleanup());

// The person's unlock ticket (its body) and the job a large unlock delegates.
const TICKET = { body: { v: 2, rpId: "r", scope: "session-start", nonce: "n", uid: 1, hostname: "h", machineId: null, bootId: "b", issuedAt: 1, expiresAt: 2, issuedAtMono: "1", expiresAtMono: "2", uses: 2, credential: "k1", credentialId: "cred-person" } };
const JOB = { name: "ci", measurementDigest: "1".repeat(64), policyDigest: "2".repeat(64), projectDigest: "3".repeat(64), kind: "headless:print" };
const setup = () => {
  const dev = new SimTotpDevice();
  return { dev, seam: deviceTotpSeam(totpFramework(dev)) };
};

test("attack 7 (FP): an interactive launch with the authenticator's current code is verified by the device", async () => {
  const { dev, seam } = setup();
  const r = await deviceActivation({ seam, interactive: true, readCode: async () => dev.code(), env: sb.env });
  assert.deepEqual(r, { mode: "verified", via: "device-totp" });
  assert.equal(dev.calls, 1);
});

test("attack 7 (attack): wrong codes, a replayed code, no device and an un-enrolled device are refused", async () => {
  const { dev, seam } = setup();
  await assert.rejects(() => deviceActivation({ seam, interactive: true, readCode: async () => "000000", env: sb.env }), /did not accept/);
  const code = dev.code();
  await deviceActivation({ seam, interactive: true, readCode: async () => code, env: sb.env });
  // The same code again: the device accepts each step once.
  await assert.rejects(() => deviceActivation({ seam, interactive: true, readCode: async () => code, env: sb.env }), /did not accept/);
  dev.present = false;
  await assert.rejects(() => deviceActivation({ seam, interactive: true, readCode: async () => dev.code(), env: sb.env }), /cannot verify/);
  dev.present = true;
  dev.enrolled = false;
  await assert.rejects(() => deviceActivation({ seam, interactive: true, readCode: async () => dev.code(), env: sb.env }), /no authenticator enrolled/);
  await assert.rejects(() => issueGrant({ seam, readCode: async () => dev.code(), minutes: 10, uses: 5, env: sb.env, ticket: TICKET, job: JOB }), /no authenticator enrolled/);
});

test("attack 7 (attack): a device unlock is counted and ended by the device (lease, uses), an edited record gains nothing, and it does not work with another device", async () => {
  let clock = Date.now();
  const dev = new SimTotpDevice();
  const seam = deviceTotpSeam(totpFramework(dev, { now: () => clock }));
  await issueGrant({ seam, readCode: async () => dev.code(clock / 1000), minutes: 10, uses: 2, env: sb.env, ticket: TICKET, job: JOB });
  assert.equal((await deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: JOB })).via, "device-unlock");
  // The host's record edited to more uses: the device's count decides.
  const f = grantFile(sb.env);
  fs.writeFileSync(f, JSON.stringify({ ...JSON.parse(fs.readFileSync(f, "utf8")), uses: 50, leaseMs: 43_200_000 }));
  assert.equal((await deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: JOB })).via, "device-unlock");
  await assert.rejects(() => deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: JOB }), /holds no live unlock/);
  // The lease ends on the device's clock.
  dev.lastStep = 0;
  await issueGrant({ seam, readCode: async () => dev.code(clock / 1000), minutes: 10, uses: 5, env: sb.env, ticket: TICKET, job: JOB });
  clock += 11 * 60_000;
  await assert.rejects(() => deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: JOB }), /holds no live unlock/);
  // Another device, and a record naming another grant.
  const other = setup();
  await assert.rejects(() => deviceActivation({ seam: other.seam, interactive: false, env: sb.env, ticket: TICKET, job: JOB }), /another Enclaweder/);
  fs.rmSync(f);
  await assert.rejects(() => deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: JOB }), /needs a device unlock/);
});

test("without the framework's device TOTP calls, device activation is unavailable (never faked on the host)", async () => {
  assert.equal(deviceTotpSeam({}), null);
  assert.equal((await deviceActivation({ seam: null, interactive: false, env: sb.env })).mode, "unavailable");
});

test("attack 7 (attack): a device unlock spends only with its own ticket, credential and job", async () => {
  const dev = new SimTotpDevice();
  const seam = deviceTotpSeam(totpFramework(dev));
  // A large unlock must name its job.
  await assert.rejects(() => issueGrant({ seam, readCode: async () => dev.code(), minutes: 60, uses: 500, env: sb.env, ticket: TICKET }), /must name the one job/);
  dev.lastStep = 0;
  await issueGrant({ seam, readCode: async () => dev.code(), minutes: 60, uses: 50, env: sb.env, ticket: TICKET, job: JOB });
  const other = { body: { ...TICKET.body, credentialId: "cred-attacker" } };
  await assert.rejects(() => deviceActivation({ seam, interactive: false, env: sb.env, ticket: other, job: JOB }));
  await assert.rejects(() => deviceActivation({ seam, interactive: false, env: sb.env, ticket: { body: { ...TICKET.body, nonce: "replayed" } }, job: JOB }));
  await assert.rejects(() => deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: { ...JOB, projectDigest: "9".repeat(64) } }));
  await assert.rejects(() => deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: null }));
  await assert.rejects(() => deviceActivation({ seam, interactive: false, env: sb.env, ticket: null, job: JOB }), /no unlock ticket/);
  assert.equal((await deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: JOB })).via, "device-unlock");
});

test("attack 7 (attack): through the device owner, a use outside the job (another launch kind, project or credential) is reported as the device refusing that use, never as a device error; nothing is spent", async () => {
  const { framework } = await import("../src/kit.mjs");
  const dev = new SimTotpDevice();
  const sim = totpFramework(dev);
  // The owner relays the use sealed (kit hardware-root/relayed-factors): the device's refusal of a use
  // that does not match its grant arrives as the kit's FactorError "use-refused" (the same byte as a
  // refused seal), not as a direct "mismatch".
  const relayed = {
    ...sim,
    spendUnlock: async (...a) => {
      const r = await sim.spendUnlock(...a);
      if (!r.ok && r.code === "mismatch") {
        throw new framework.FactorError("UNLOCK_USE", "use-refused");
      }
      return r;
    },
  };
  const seam = deviceTotpSeam(relayed);
  await issueGrant({ seam, readCode: async () => dev.code(), minutes: 60, uses: 50, env: sb.env, ticket: TICKET, job: JOB });
  const cases = [
    ["another launch kind", TICKET, { ...JOB, kind: "headless" }],
    ["another project", TICKET, { ...JOB, projectDigest: "9".repeat(64) }],
    ["another credential", { body: { ...TICKET.body, credentialId: "cred-attacker" } }, JOB],
  ];
  for (const [what, ticket, job] of cases) {
    const records = [];
    await assert.rejects(
      () => deviceActivation({ seam, interactive: false, env: sb.env, ticket, job, audit: async (p) => records.push(p) }),
      (e) => /needs a device unlock, and the Enclaweder refused this use: the launch does not match its live unlock/.test(e.message) && !/did not answer as expected/.test(e.message),
      what,
    );
    assert.deepEqual(records.filter((p) => p.via === "device-unlock").map((p) => [p.outcome, p.code]), [["refused", "use-refused"]], what);
  }
  assert.equal(dev.grant.used, 0);
  assert.equal((await deviceActivation({ seam, interactive: false, env: sb.env, ticket: TICKET, job: JOB })).via, "device-unlock");
  assert.equal(dev.grant.used, 1);
});
