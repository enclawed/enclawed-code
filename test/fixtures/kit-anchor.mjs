// The kit's session-anchor decision over a simulated device, for tests.
//
// The launcher never decides how a session anchors its audit log: the
// framework's requireHardwareRootSessionAnchor (hardware-root
// session-anchor.ts) does, from the device the framework holds. A test's
// framework holds no real device, so this stands in for that ONE input (which
// device and certified key are bound) and lets the kit's own decision
// (decideSessionAnchor) run on it: a stand-in with the authenticated anchor
// session (anchorOpen + anchorGet, as the frame-level simulators in
// anchor-sim.mjs and anchor-sim-v2.mjs provide) is accepted; one with only a
// bare ANCHOR_SET, or none, is refused exactly as on a real host.

/** A framework's requireHardwareRootSessionAnchor for `device` (null: nothing bound). */
export function kitSessionAnchor(fw, device, devicePublicKey, { relayed = false } = {}) {
  return () => {
    const d = fw.decideSessionAnchor({ bound: device !== null, device, devicePublicKey: devicePublicKey ? Buffer.from(devicePublicKey) : null, relayed });
    if (!d.ok) {
      throw new fw.SessionAnchorRefused(d.code, d.reason);
    }
    return d;
  };
}
