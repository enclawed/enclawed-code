// Per-call device commitments, the measured launch and device-approved
// policies (compromised-host attacks 2 and 2-smart). Every decision here is
// the kit's (enclawed-oss adapter/call-commitment.ts, digest-approval.ts);
// this file maps Enclawed Code's own files, state and relay onto them.
//
//   Measured launch   The LAUNCHER (not the hook) measures what decides the
//                     session's calls before claude starts: the hook entry,
//                     Enclawed Code's own code and the framework bundle. With
//                     the hardware root required, that measurement must carry
//                     a device-signed approval (`ecwctl
//                     measurement approve`, an authenticator code the device
//                     checks), else the launch is refused. While the session
//                     runs, every commitment first re-checks the measured
//                     files' stat identity: a file written (or written and
//                     restored) since launch stops the commitments.
//   Approved policy   The effective policy's digest must carry a device-signed
//                     approval (`ecwctl policy approve`) when
//                     a policy file the user can write was read into it; a
//                     root-owned managed policy, or the built-in default, needs
//                     none.
//   Commitments       The hook no longer sends a random nonce: for each call
//                     it sends the decision (the kit's CallCommitmentCall) and
//                     the digest of the policy it decided under; the launcher
//                     checks the policy digest is the approved one, assigns
//                     the session's sequence number and the previous
//                     signature's link, and has the device sign the
//                     commitment. The hook checks the device's signature and
//                     the kit records it in the call's audit record. The
//                     launcher keeps what each call committed and stops claude
//                     when the decision reported on the control socket is not
//                     the one the device signed, or a call is reported decided
//                     without a commitment.
//
// Stated plainly: a launcher replaced on a same-user or root host can lie
// about its own measurement. That is detected afterwards by `audit verify`
// (unsigned or mis-chained calls, a decision the recorded policy does not
// allow), not prevented.

import fs from "node:fs";
import path from "node:path";
import { FRAMEWORK_ENTRY, FRAMEWORK_SOURCE, frameworkImportClosure } from "./framework.mjs";
import { kit } from "./kit.mjs";
import { CLOCK_DISAGREES_TEXT, deviceTotpSeam } from "./device-activation.mjs";
import { shellFlavor } from "./env-authority.mjs";
import { APP_ROOT, HOOK_BIN, appStateDir, realpathNearest } from "./paths.mjs";
import { loadPolicy } from "./policy.mjs";
import { policyCandidates } from "./session.mjs";

/** Where the person's device-signed approvals are kept (tamper-evident, not secret). */
export function approvalsFile(env = process.env) {
  return path.join(appStateDir(env), "approvals.json");
}

/** The files that decide a session's calls, by a stable name (the hook, Enclawed Code's code, the framework bundle). */
export function measuredEntries({ appRoot = APP_ROOT, hookBin = HOOK_BIN, frameworkEntry = FRAMEWORK_ENTRY } = {}) {
  const entries = [{ name: "hook", path: hookBin }];
  for (const sub of ["bin", "src"]) {
    const dir = path.join(appRoot, sub);
    for (const f of fs.readdirSync(dir).filter((n) => n.endsWith(".mjs")).sort()) {
      const p = path.join(dir, f);
      if (p !== hookBin) {
        entries.push({ name: `${sub}/${f}`, path: p });
      }
    }
  }
  const fwDir = path.dirname(frameworkEntry);
  // A development build's directory is the framework; an npm install's dist
  // directory is the whole enclawed product, so there the framework is the
  // entry's import closure (framework.mjs).
  const fwFiles =
    FRAMEWORK_SOURCE === "package" && frameworkEntry === FRAMEWORK_ENTRY
      ? frameworkImportClosure(frameworkEntry)
      : fs.readdirSync(fwDir).filter((n) => n.endsWith(".js")).sort();
  for (const f of fwFiles) {
    entries.push({ name: `framework/${f}`, path: path.join(fwDir, f) });
  }
  return entries;
}

/** Measure the launch (kit.measureFiles). Throws when a file cannot be read. */
export function measureLaunch(opts = {}) {
  return kit.measureFiles(measuredEntries(opts));
}

/** The effective policy, as approved and committed: its canonical form and digest. */
export function effectivePolicy(loaded) {
  const canonical = kit.canonicalPolicy(loaded.policy, loaded.options ?? null);
  return { canonical, digest: kit.policyDigestOf(canonical), needsApproval: kit.policyNeedsApproval(loaded) };
}

/** The devices whose approvals count: the members the launch bound (pub and uid, hex). */
export function approvingDevices(device) {
  if (!device) {
    return [];
  }
  if (device.kind === "members" && Array.isArray(device.members)) {
    return device.members.map((m) => ({ pub: m.pub, uid: m.uid }));
  }
  return [{ pub: device.pub, uid: device.uid }];
}

/** What a refused approval gate tells the person (the command to run once). */
export function approvalRefusalMessage(gate) {
  if (gate.code === "measurement-not-approved") {
    return `Enclawed Code's code (hook, launcher, framework) measures ${gate.digest.slice(0, 16)}…, and no device-signed approval covers it (${gate.reason}). After installing or upgrading Enclawed Code, approve it once with an authenticator code the Enclaweder checks: ecwctl measurement approve. If you did not change Enclawed Code, something else did: do not approve; investigate first`;
  }
  return `the effective policy (digest ${gate.digest.slice(0, 16)}…) has no device-signed approval (${gate.reason}). A policy file you can write changed it; if that was you, approve it with an authenticator code the Enclaweder checks: ecwctl policy approve. If it was not you, something on this machine rewrote your policy: do not approve; investigate first`;
}

/**
 * Launcher side: the session's commitment ledger. `attest(nonceHex)` has the
 * device sign a 32-byte nonce (device.mjs attest); calls are committed one at
 * a time, in order.
 */
export class CommitLedger {
  constructor({ sessionNonce, policyDigest, measurementDigest, stamps, attest, measurementChanged = (s) => kit.measurementChanged(s) }) {
    this.sessionNonce = sessionNonce;
    this.policyDigest = policyDigest;
    this.measurementDigest = measurementDigest;
    this.stamps = stamps;
    this.attest = attest;
    this.measurementChanged = measurementChanged;
    this.seq = 0;
    this.previous = null;
    this.byCall = new Map();
    this.chain = Promise.resolve();
    this.stopped = null;
  }

  /** The session's end, for the launch.end record: how many calls were committed and the last signature's link. */
  end() {
    return { count: this.seq, last: this.previous };
  }

  /** What call `id` committed (decision and answer), or null. */
  committed(id) {
    return this.byCall.get(id) ?? null;
  }

  /** Commit one call (unknown input from the relay). Resolves the evidence, or rejects with why not. */
  commit(rawCall, hookPolicyDigest) {
    const run = async () => {
      if (this.stopped) {
        throw new Error(this.stopped);
      }
      if (hookPolicyDigest !== this.policyDigest) {
        throw new Error("the call was decided under another policy than the one approved for this launch");
      }
      const changed = this.measurementChanged(this.stamps);
      if (changed) {
        this.stopped = `Enclawed Code's measured code changed during the session (${changed})`;
        throw new Error(this.stopped);
      }
      const part = { sessionNonce: this.sessionNonce, seq: this.seq, policyDigest: this.policyDigest, measurementDigest: this.measurementDigest, previous: this.previous };
      // The kit checks every field (unknown input) and computes the commitment.
      const fields = kit.commitmentFields({ ...rawCall, ...part });
      const commitment = kit.callCommitment(fields);
      const signature = await this.attest(commitment);
      this.seq += 1;
      this.previous = kit.signatureLink(signature);
      if (fields.callId && !this.byCall.has(fields.callId)) {
        this.byCall.set(fields.callId, { decision: fields.decision, answered: fields.answered });
      }
      return { v: 1, ...part, commitment, signature };
    };
    const p = this.chain.then(run, run);
    this.chain = p.catch(() => {});
    return p;
  }
}

/**
 * Launcher side: whether a decision reported on the control socket matches
 * what the device signed for that call. null when it does (or when an "ask"
 * is reported before its commitment, which follows the person's answer).
 */
export function decisionAgainstCommitment(ledger, id, reported) {
  const c = ledger.committed(id);
  if (!c) {
    return reported === "ask" ? null : `the hook reported ${reported} for ${id} without a device commitment`;
  }
  return c.decision === reported ? null : `the hook reported ${reported} for ${id}, and the device signed ${c.decision}`;
}

/** Launch-record part (audit verify reads it): the commitments' launch data. */
export function commitmentLaunchRecord({ nonce, required, policy, measurement, device }) {
  return {
    v: 1,
    sessionNonce: nonce,
    required,
    policyDigest: policy.digest,
    policy: policy.canonical,
    measurementDigest: measurement.digest,
    measured: measurement.files.map((f) => ({ name: f.name, sha256: f.sha256 })),
    devices: approvingDevices(device),
  };
}

/** The effective policy for this environment, as a launch here would load it. */
export function currentEffectivePolicy(fw, env = process.env) {
  return effectivePolicy(loadPolicy(fw, { candidates: policyCandidates(env, { fw }), flavor: shellFlavor(env).flavor }));
}

/** The launch kinds a device unlock can name (a headless start only; interactive launches need a code every time). */
export const LAUNCH_KINDS = Object.freeze(["headless:print", "headless"]);

/**
 * The job of a launch (kit UnlockJob): its name, the measurement and policy
 * it runs with, its project and its kind. A device unlock for more than one
 * launch is bound to one job; the launcher recomputes it from what it starts.
 */
export function launchJob({ name, measurementDigest, policyDigest, projectDir, kind }) {
  return { name, measurementDigest, policyDigest, projectDigest: kit.projectDigest(realpathNearest(path.resolve(projectDir))), kind };
}

/**
 * `ecwctl measurement approve` / `policy approve`: the person
 * types an authenticator code; the bound Enclaweder checks it and signs its
 * verdict over the current measurement's (or effective policy's) digest. The
 * approval is stored; launches with the hardware root required need it.
 */
export async function approveCurrent({ kind, fw, env = process.env, readCode, out = process.stdout, ifBound = false }) {
  const digest = kind === "measurement" ? measureLaunch().digest : currentEffectivePolicy(fw, env).digest;
  const seam = deviceTotpSeam(fw);
  if (!seam && ifBound) {
    return { digest, skipped: true };
  }
  if (!seam) {
    throw new Error("this framework build exposes no device-verified authenticator codes");
  }
  try {
    await fw.bootHardwareRoot();
  } catch {
    /* reported below as no device */
  }
  try {
    if (!seam.access()) {
      if (ifBound) {
        return { digest, skipped: true };
      }
      throw new Error("no bound, CLEAN Enclaweder can verify the code");
    }
    out.write(`${kind === "measurement" ? "Enclawed Code's code (hook, launcher, framework)" : "the effective policy"}: ${digest}\n`);
    const code = String(await readCode("Authenticator code (checked by the Enclaweder): ")).trim();
    const r = await kit.approveDigest({ kind, digest, code, device: seam, note: kind === "measurement" ? `Enclawed Code ${APP_ROOT}` : "effective policy" });
    if (!r.ok) {
      throw new Error(r.code === "clock-disagrees" ? CLOCK_DISAGREES_TEXT : r.message);
    }
    kit.storeApproval(approvalsFile(env), r.approval);
    return { digest };
  } finally {
    try {
      fw.closeHardwareRootSession();
    } catch {
      /* nothing to close */
    }
  }
}

/**
 * `audit verify`: the committed calls of every launch that held the hardware
 * root, checked by the kit (verifyCallChain) against the launch's record.
 * `records` are the log's records in order; `checkSignature(nonce, answer,
 * devices)` is the device check (device.mjs checkAttestation). A call record
 * that names no launch while exactly one held launch is open belongs to it; with
 * several open, it cannot be attributed and every open held launch fails.
 */
export function verifyLogCommitments(records, { checkSignature }) {
  const launches = new Map();
  const open = new Set();
  const issues = [];
  for (const rec of records) {
    const p = rec?.payload ?? {};
    if (rec?.type === "claude-code.launch" && p.commitments?.v === 1) {
      launches.set(p.commitments.sessionNonce, { launch: p.commitments, calls: [], end: null, unattributable: 0 });
      open.add(p.commitments.sessionNonce);
    } else if (rec?.type === "claude-code.launch.end" && launches.has(p.nonce)) {
      launches.get(p.nonce).end = p.commitments ?? null;
      open.delete(p.nonce);
    } else if (rec?.type === "claude-code.tool.pre") {
      const nonce = p.commitment?.sessionNonce ?? p.launcherNonce ?? null;
      if (nonce && launches.has(nonce)) {
        launches.get(nonce).calls.push(p);
      } else if (!nonce && open.size === 1) {
        launches.get([...open][0]).calls.push(p);
      } else if (!nonce && open.size > 1) {
        for (const n of open) {
          launches.get(n).unattributable += 1;
        }
      }
    }
  }
  const sessions = [];
  for (const [nonce, s] of launches) {
    const devices = s.launch.devices ?? [];
    const v = kit.verifyCallChain({
      launch: { sessionNonce: nonce, required: s.launch.required === true, policyDigest: s.launch.policyDigest, measurementDigest: s.launch.measurementDigest, policy: s.launch.policy ?? null },
      records: s.calls,
      checkSignature: (commitment, signature) => checkSignature(commitment, signature, devices),
      end: s.end,
    });
    const extra = [];
    if (s.unattributable) {
      extra.push({ index: -1, callId: null, code: "unattributable-call", detail: `${s.unattributable} call record(s) name no launch while several held launches were open` });
    }
    // No end record: still running, or the launcher was killed; the anchored
    // log head (not this check) is what proves the log was not cut.
    const notes = s.end ? [] : ["the launch has no end record yet (running, or its launcher was stopped)"];
    const all = [...v.issues, ...extra];
    sessions.push({ nonce, committed: v.committed, ok: all.length === 0, issues: all.slice(0, 20), notes });
    issues.push(...all.map((i) => ({ nonce, ...i })));
  }
  return { ok: issues.length === 0, sessions, held: sessions.length > 0 };
}
