// The command-set pin at launch (the kit's commandSetPin): with the hardware
// root required, a launch starts only on the Enclaweder's own signed proof of
// command set 0.5 (a fresh ANCHOR_READ over a nonce of this process), never on
// a version something in between asserts. Enclawed Code only maps its launch
// onto the kit: whether the root is required, whether a device is held, and
// the framework's proof.

import { kit } from "./kit.mjs";

/**
 * The kit's decision for this launch. `fw` is the framework (its
 * hardwareRootCommandSet asks the held device); `rootRequired` and `held`
 * are the launch's.
 * @returns {Promise<{ ok: true, proof: object | null, residual: string | null } | { ok: false, code: string, message: string, proof: object }>}
 */
export function launchCommandSetPin({ fw, rootRequired, held, k = kit }) {
  return k.commandSetPin({
    rootRequired,
    deviceBound: held,
    prove:
      typeof fw?.hardwareRootCommandSet === "function"
        ? () => fw.hardwareRootCommandSet()
        : async () => ({ status: "unproven", reason: "this framework build cannot ask the device for its command set" }),
  });
}
