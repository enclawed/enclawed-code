// The hardware root (Enclaweder) for a Claude Code session.
//
// Launcher mode: `ecwcode` boots the hardware root once, before claude
// starts, and keeps it for the whole session (with a device bound it is the
// machine's owner, or a client of an owner that already serves the devices).
// It then serves an authenticated health relay on a socket in its private
// session directory: each hook sends a fresh random challenge and accepts the
// answer only with a valid HMAC under the per-session secret, which only the
// launcher and the hook (through the protected session file) know. The relay
// path and secret come from the session file, never from the environment, so
// a settings file cannot point hooks at a socket of its choosing (red-team I8).
// If the relay cannot be reached or does not authenticate, the call is denied.
//
// The launcher also watches the root's health. On a halt (DIRTY, device
// gone) it stops claude and, unless the policy opts out, erases Claude Code's
// login (see credentials.mjs and launcher.mjs).
//
// Without a device, or when the boot refuses, the launcher holds nothing; each
// hook then checks per call (boot, check, close) with the environment the
// launcher recorded, which keeps software-only behavior and still denies a
// required-but-absent device. Managed mode (no launcher) always checks per call.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import net from "node:net";

const CONNECT_TIMEOUT_MS = 3000;

async function quietly(fn, notes) {
  const orig = console.error;
  console.error = (...args) => notes.push(args.map(String).join(" "));
  try {
    return await fn();
  } finally {
    console.error = orig;
  }
}

/**
 * Launcher side: boot and hold the hardware root for the session.
 *
 * @returns {Promise<{ mode: "held"|"software-only"|"halted"|"broker-off", reason: string|null, notes: string[], release: () => void }>}
 */
export async function holdSessionRoot(fw, { onExit = (h) => process.on("exit", h) } = {}) {
  const notes = [];
  const none = { notes, release: () => {} };
  if (fw.brokerDisabled()) {
    // No sharing: each process must bind the device itself, so the launcher
    // must not hold it.
    return { ...none, mode: "broker-off", reason: null };
  }
  let root;
  try {
    root = await quietly(() => fw.bootHardwareRoot(), notes);
  } catch (err) {
    return { ...none, mode: "halted", reason: err?.message ?? String(err) };
  }
  if (!root) {
    return { ...none, mode: "software-only", reason: null };
  }
  let released = false;
  const release = () => {
    if (released) {
      return;
    }
    released = true;
    try {
      // A deliberate stop: closes the accredited session and stops serving.
      fw.closeHardwareRootSession();
    } catch {
      /* nothing to close */
    }
  };
  onExit(release);
  return { mode: "held", reason: null, notes, release };
}

/** The launcher's own view of the held root, for the relay and the halt monitor. */
export function launcherHealth(fw, tool = "relay") {
  let status = null;
  try {
    status = fw.hardwareRootInfo()?.status ?? null;
  } catch {
    /* reported below */
  }
  try {
    const d = fw.checkHardwareRootForToolCall(tool);
    return d.allowed ? { allowed: true, status } : { allowed: false, code: d.code, reason: d.reason, status };
  } catch (err) {
    return { allowed: false, code: "hardware-unavailable", reason: err?.message ?? String(err), status };
  }
}

/**
 * The relay's health answer in held mode: the launcher's own view, plus the
 * device's answer to the hook's fresh nonce. `device` is never null here (the
 * launcher refuses to start without one, red-team H15); `attestFn(device,
 * nonce)` answers for EVERY member of the root.
 */
export function heldRelayHealth(fw, device, attestFn) {
  return async (tool, nonce, { liveness = true } = {}) => {
    const h = launcherHealth(fw, tool);
    if (!h.allowed || !liveness) {
      return h;
    }
    if (!device || !nonce) {
      return { allowed: false, code: "device-attestation-failed", reason: "no device attestation was asked for or possible" };
    }
    try {
      h.attestation = await attestFn(device, nonce);
    } catch (err) {
      return { allowed: false, code: "device-attestation-failed", reason: `the Enclaweder did not answer a challenge: ${err.message}` };
    }
    return h;
  };
}

function mac(secret, challenge, health) {
  return createHmac("sha256", Buffer.from(secret, "hex")).update(`${challenge}|${JSON.stringify(health)}`).digest("hex");
}

/**
 * Serve health to this session's hooks. `health` is called per request.
 * @returns {Promise<{ path: string, secret: string, close: () => Promise<void> }>}
 */
export function startHardwareRelay({ socketPath, health, commit = null, secret = randomBytes(32).toString("hex") }) {
  fs.rmSync(socketPath, { force: true });
  const server = net.createServer((c) => {
    let buf = "";
    c.setTimeout(CONNECT_TIMEOUT_MS, () => c.destroy());
    c.on("error", () => {});
    c.on("data", async (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) {
        if (buf.length > 4096) {
          c.destroy();
        }
        return;
      }
      let req;
      try {
        req = JSON.parse(buf.slice(0, nl));
      } catch {
        c.destroy();
        return;
      }
      if (typeof req?.challenge !== "string" || !/^[0-9a-f]{64}$/.test(req.challenge)) {
        c.destroy();
        return;
      }
      let h;
      try {
        if (req.commit !== undefined) {
          // A per-call commitment (commitments.mjs): the launcher checks the
          // call, assigns its place in the session's chain and has the device
          // sign it. Health first: a halted root signs nothing.
          h = await health(typeof req.tool === "string" ? req.tool : "relay", null, { liveness: false });
          if (h.allowed) {
            if (!commit) {
              h = { allowed: false, code: "device-commit-failed", reason: "this launcher commits no calls" };
            } else {
              const evidence = await commit(req.commit?.call, req.commit?.policyDigest);
              h = { allowed: true, evidence };
            }
          }
        } else {
          const nonce = typeof req.attest === "string" && /^[0-9a-f]{64}$/.test(req.attest) ? req.attest : null;
          h = await health(typeof req.tool === "string" ? req.tool : "relay", nonce);
        }
      } catch (err) {
        h = { allowed: false, code: req.commit !== undefined ? "device-commit-failed" : "hardware-unavailable", reason: err?.message ?? String(err) };
      }
      c.end(`${JSON.stringify({ health: h, mac: mac(secret, req.challenge, h) })}\n`);
    });
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      try {
        fs.chmodSync(socketPath, 0o600);
      } catch {
        /* the directory is 0700 anyway */
      }
      resolve({ path: socketPath, secret, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

/**
 * Hook side, launcher mode: ask the launcher's relay, and accept only an
 * answer authenticated with the session secret.
 *
 * @returns {Promise<{ allowed: true } | { allowed: false, code: string, reason: string }>}
 */
export function checkViaRelay({ path: socketPath, secret }, tool, { timeoutMs = CONNECT_TIMEOUT_MS, attestation = null } = {}) {
  const unavailable = (code, why) => ({
    allowed: false,
    code,
    reason: `the Enclawed Code launcher holding the Enclaweder for this session ${why}`,
  });
  return new Promise((resolve) => {
    const challenge = randomBytes(32).toString("hex");
    let buf = "";
    let done = false;
    const finish = (v) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        sock.destroy();
        resolve(v);
      }
    };
    const timer = setTimeout(() => finish(unavailable("owner-unavailable", "cannot be reached (no answer)")), timeoutMs);
    const sock = net.connect(socketPath);
    sock.on("error", (err) => finish(unavailable("owner-unavailable", `cannot be reached (${err.code ?? err.message})`)));
    // With a device bound, also send a fresh nonce for the device to sign.
    const attestNonce = attestation ? randomBytes(32).toString("hex") : null;
    sock.on("connect", () => sock.write(`${JSON.stringify({ challenge, tool, ...(attestNonce ? { attest: attestNonce } : {}) })}\n`));
    sock.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) {
        return;
      }
      let res;
      try {
        res = JSON.parse(buf.slice(0, nl));
      } catch {
        finish(unavailable("owner-unauthenticated", "sent an unreadable answer"));
        return;
      }
      const expected = Buffer.from(mac(secret, challenge, res?.health ?? null), "hex");
      const got = Buffer.from(typeof res?.mac === "string" ? res.mac : "", "hex");
      if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
        finish(unavailable("owner-unauthenticated", "did not prove it holds this session's secret"));
        return;
      }
      const h = res.health;
      if (h?.allowed !== true) {
        finish({ allowed: false, code: h?.code ?? "hardware-unavailable", reason: h?.reason ?? "hardware root not CLEAN" });
        return;
      }
      if (attestation) {
        // The relay's own MAC proves only who answered; the device's
        // signature over this nonce proves the device itself is there.
        const why = attestation.check(attestNonce, h.attestation);
        if (why) {
          finish({ allowed: false, code: "device-attestation-failed", reason: `the Enclaweder's answer was refused: ${why}` });
          return;
        }
      }
      finish({ allowed: true });
    });
    sock.on("end", () => finish(unavailable("owner-unavailable", "closed the connection without answering")));
  });
}

/**
 * Hook side, launcher mode: have the launcher commit this call's decision
 * (commitments.mjs) and check the device's signature over the commitment
 * with `check(commitmentHex, signature)` (null when genuine). Resolves the
 * evidence for the kit's engine; rejects with why not (the call is denied).
 */
export function commitViaRelay({ path: socketPath, secret }, call, policyDigest, { check, timeoutMs = 10_000 }) {
  return new Promise((resolve, reject) => {
    const challenge = randomBytes(32).toString("hex");
    let buf = "";
    let done = false;
    const finish = (err, v) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        sock.destroy();
        if (err) {
          reject(err);
        } else {
          resolve(v);
        }
      }
    };
    const timer = setTimeout(() => finish(new Error("the Enclawed Code launcher holding the Enclaweder did not answer the commitment")), timeoutMs);
    const sock = net.connect(socketPath);
    sock.on("error", (err) => finish(new Error(`the Enclawed Code launcher holding the Enclaweder cannot be reached (${err.code ?? err.message})`)));
    sock.on("connect", () => sock.write(`${JSON.stringify({ challenge, tool: call?.tool ?? "relay", commit: { call, policyDigest } })}\n`));
    sock.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) {
        if (buf.length > 1024 * 1024) {
          finish(new Error("the launcher's answer is too long"));
        }
        return;
      }
      let res;
      try {
        res = JSON.parse(buf.slice(0, nl));
      } catch {
        finish(new Error("the launcher sent an unreadable answer"));
        return;
      }
      const expected = Buffer.from(mac(secret, challenge, res?.health ?? null), "hex");
      const got = Buffer.from(typeof res?.mac === "string" ? res.mac : "", "hex");
      if (got.length !== expected.length || !timingSafeEqual(got, expected)) {
        finish(new Error("the launcher did not prove it holds this session's secret"));
        return;
      }
      const h = res.health;
      if (h?.allowed !== true || !h.evidence) {
        finish(new Error(h?.reason ?? "the launcher committed nothing"));
        return;
      }
      const why = check(String(h.evidence.commitment ?? ""), h.evidence.signature);
      if (why) {
        finish(new Error(`the Enclaweder's signature over the commitment was refused: ${why}`));
        return;
      }
      finish(null, h.evidence);
    });
    sock.on("end", () => finish(new Error("the launcher closed the connection without answering")));
  });
}

/**
 * Watch the held root; call `onHalt` once, with the health, when it stops
 * being CLEAN. @returns a stop function.
 */
export function watchForHalt(health, onHalt, { intervalMs = 1000 } = {}) {
  let fired = false;
  const timer = setInterval(async () => {
    if (fired) {
      return;
    }
    let h;
    try {
      h = await health("monitor");
    } catch (err) {
      h = { allowed: false, code: "hardware-unavailable", reason: String(err) };
    }
    if (!h.allowed) {
      fired = true;
      clearInterval(timer);
      onHalt(h);
    }
  }, intervalMs);
  timer.unref?.();
  return () => clearInterval(timer);
}
