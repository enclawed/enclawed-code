// Per-call device commitments, the measured launch and approved policies
// (compromised-host attacks 2 and 2-smart): src/commitments.mjs over the kit,
// with a stand-in device signature (an HMAC under a key only the test holds).
import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { CommitLedger, approvalRefusalMessage, decisionAgainstCommitment, effectivePolicy, launchJob, measureLaunch, measuredEntries, verifyLogCommitments } from "../src/commitments.mjs";
import { kit } from "../src/kit.mjs";

const KEY = Buffer.alloc(32, 3);
const sign = (c) => ({ sig: createHmac("sha256", KEY).update(c).digest("hex") });
const check = (c, s) => (s?.sig === sign(c).sig ? null : "not signed by the device");

const loaded = { policy: { enforceAllowlists: true, allowedTools: new Set(["read", "bash"]), preApprovedIrreversibleTools: new Set() }, options: null, kind: null, note: null };
const policy = effectivePolicy(loaded);
const NONCE = "ab".repeat(16);
const call = (id, over = {}) => ({ callId: id, tool: "Read", inputDigest: "11".repeat(32), decision: "allow", answered: "allow", codes: [], reversible: true, policyIds: ["read"], approvalRoute: "person", approvedBy: null, ...over });

function ledger(over = {}) {
  return new CommitLedger({ sessionNonce: NONCE, policyDigest: policy.digest, measurementDigest: "cd".repeat(32), stamps: [], attest: async (c) => sign(c), measurementChanged: () => null, ...over });
}

/** A held session's log as the genuine launcher and hook write it. */
async function sessionLog(calls) {
  const l = ledger();
  const recs = [{ type: "claude-code.launch", payload: { nonce: NONCE, commitments: { v: 1, sessionNonce: NONCE, required: true, policyDigest: policy.digest, policy: policy.canonical, measurementDigest: "cd".repeat(32), devices: [] } } }];
  for (const c of calls) {
    const ev = await l.commit(c, policy.digest);
    recs.push({ type: "claude-code.tool.pre", payload: { callId: c.callId, answered: c.answered, launcherNonce: NONCE, commitmentCall: c, commitment: ev } });
  }
  recs.push({ type: "claude-code.launch.end", payload: { nonce: NONCE, commitments: l.end() } });
  return recs;
}

test("2 (FP): a genuine held session's calls verify", async () => {
  const recs = await sessionLog([call("a"), call("b", { tool: "Bash", policyIds: ["bash"] })]);
  const v = verifyLogCommitments(recs, { checkSignature: check });
  assert.equal(v.ok, true, JSON.stringify(v));
  assert.equal(v.sessions[0].committed, 2);
});

test("2-smart (attack): a hook that skips the device writes uncommitted calls; verify fails", async () => {
  const recs = await sessionLog([call("a")]);
  recs.splice(2, 0, { type: "claude-code.tool.pre", payload: { callId: "evil", answered: "allow", origin: "launcher" } });
  const v = verifyLogCommitments(recs, { checkSignature: check });
  assert.equal(v.ok, false);
  assert.ok(v.sessions[0].issues.some((i) => i.code === "uncommitted-call"));
});

test("2-smart (attack): a signed decision the recorded policy does not allow fails verify", async () => {
  const recs = await sessionLog([call("w", { tool: "WebFetch", policyIds: ["webfetch"] })]);
  const v = verifyLogCommitments(recs, { checkSignature: check });
  assert.ok(v.sessions[0].issues.some((i) => i.code === "decision-mismatch"));
});

test("2-smart (attack): a removed call record breaks the chain against the launcher's end record", async () => {
  const recs = await sessionLog([call("a"), call("b"), call("c")]);
  recs.splice(2, 1);
  assert.equal(verifyLogCommitments(recs, { checkSignature: check }).ok, false);
});

test("2 (attack): the launcher refuses to commit a call decided under another policy, or after its measured code changed", async () => {
  await assert.rejects(() => ledger().commit(call("a"), "ee".repeat(32)), /another policy/);
  const l = ledger({ measurementChanged: () => "/x/hook.mjs" });
  await assert.rejects(() => l.commit(call("a"), policy.digest), /measured code changed/);
  await assert.rejects(() => l.commit(call("b"), policy.digest), /measured code changed/);
  await assert.rejects(() => ledger().commit({ ...call("a"), decision: "maybe" }, policy.digest));
});

test("2-smart (attack): a reported decision must be the one the device signed", async () => {
  const l = ledger();
  await l.commit(call("a", { decision: "deny", answered: "deny" }), policy.digest);
  assert.match(decisionAgainstCommitment(l, "a", "allow"), /device signed deny/);
  assert.equal(decisionAgainstCommitment(l, "a", "deny"), null);
  assert.match(decisionAgainstCommitment(l, "never", "allow"), /without a device commitment/);
  // An "ask" is reported before the person's answer, which comes before its commitment.
  assert.equal(decisionAgainstCommitment(l, "later", "ask"), null);
});

test("commitments are chained in order, one at a time", async () => {
  const l = ledger();
  const [a, b] = await Promise.all([l.commit(call("a"), policy.digest), l.commit(call("b"), policy.digest)]);
  assert.equal(a.seq, 0);
  assert.equal(b.seq, 1);
  assert.equal(b.previous, kit.signatureLink(a.signature));
  assert.deepEqual(l.end(), { count: 2, last: kit.signatureLink(b.signature) });
});

test("measured launch: the hook, Enclawed Code's code and the framework bundle", () => {
  const names = measuredEntries().map((e) => e.name);
  assert.ok(names.includes("hook"));
  assert.ok(names.includes("src/hook.mjs"));
  assert.ok(names.includes("src/commitments.mjs"));
  assert.ok(names.some((n) => n.startsWith("framework/")));
  assert.match(measureLaunch().digest, /^[0-9a-f]{64}$/);
});

test("measured launch: a changed file is another measurement", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cn-measure-"));
  try {
    for (const d of ["bin", "src", "fw"]) {
      fs.mkdirSync(path.join(dir, d));
    }
    fs.writeFileSync(path.join(dir, "bin", "hook.mjs"), "a");
    fs.writeFileSync(path.join(dir, "src", "x.mjs"), "b");
    fs.writeFileSync(path.join(dir, "fw", "framework.js"), "c");
    const o = { appRoot: dir, hookBin: path.join(dir, "bin", "hook.mjs"), frameworkEntry: path.join(dir, "fw", "framework.js") };
    const m1 = measureLaunch(o);
    fs.writeFileSync(path.join(dir, "src", "x.mjs"), "evil");
    assert.notEqual(measureLaunch(o).digest, m1.digest);
    assert.equal(kit.measurementChanged(m1.stamps), path.join(dir, "src", "x.mjs"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("policy approval: needed for a user policy file, not for managed or default; the message names the command", () => {
  assert.equal(effectivePolicy({ ...loaded, kind: "user" }).needsApproval, true);
  assert.equal(effectivePolicy({ ...loaded, kind: "managed" }).needsApproval, false);
  assert.equal(effectivePolicy(loaded).needsApproval, false);
  assert.notEqual(effectivePolicy({ ...loaded, policy: { ...loaded.policy, allowedTools: new Set(["read", "bash", "webfetch"]) } }).digest, policy.digest);
  assert.match(approvalRefusalMessage({ code: "policy-not-approved", digest: "a".repeat(64), reason: "x" }), /ecwctl policy approve/);
  assert.match(approvalRefusalMessage({ code: "measurement-not-approved", digest: "a".repeat(64), reason: "x" }), /ecwctl measurement approve/);
});

test("a launch's job: same launch, same job; another project or kind, another job", () => {
  const j = launchJob({ name: "ci", measurementDigest: "1".repeat(64), policyDigest: "2".repeat(64), projectDir: os.tmpdir(), kind: "headless:print" });
  assert.equal(kit.unlockJobDigest(j), kit.unlockJobDigest({ ...j }));
  assert.notEqual(kit.unlockJobDigest(j), kit.unlockJobDigest(launchJob({ ...j, projectDir: "/", measurementDigest: j.measurementDigest, policyDigest: j.policyDigest })));
  assert.notEqual(kit.unlockJobDigest(j), kit.unlockJobDigest({ ...j, kind: "headless" }));
});

test("the relay commits a call for the hook, which checks the device's signature over the commitment", async () => {
  const { commitViaRelay, startHardwareRelay } = await import("../src/hardware.mjs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cn-relay-"));
  const l = ledger();
  const relay = await startHardwareRelay({ socketPath: path.join(dir, "hw.sock"), health: async () => ({ allowed: true }), commit: (c, p) => l.commit(c, p) });
  try {
    const ev = await commitViaRelay(relay, call("a"), policy.digest, { check });
    assert.equal(kit.evidenceCovers(call("a"), ev), null);
    // A relay answer the device did not sign is refused by the hook.
    await assert.rejects(() => commitViaRelay(relay, call("b"), policy.digest, { check: () => "forged" }), /refused: forged/);
    // Another policy than the launch's: refused by the launcher.
    await assert.rejects(() => commitViaRelay(relay, call("c"), "ee".repeat(32), { check }), /another policy/);
    // Someone without the session's secret cannot pass as the launcher.
    await assert.rejects(() => commitViaRelay({ path: relay.path, secret: "00".repeat(32) }, call("d"), policy.digest, { check }), /secret/);
  } finally {
    await relay.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a halted root commits nothing", async () => {
  const { commitViaRelay, startHardwareRelay } = await import("../src/hardware.mjs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cn-relay-"));
  const relay = await startHardwareRelay({ socketPath: path.join(dir, "hw.sock"), health: async () => ({ allowed: false, code: "hardware-dirty", reason: "DIRTY" }), commit: (c, p) => ledger().commit(c, p) });
  try {
    await assert.rejects(() => commitViaRelay(relay, call("a"), policy.digest, { check }), /DIRTY/);
  } finally {
    await relay.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
