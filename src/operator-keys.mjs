// Operator private keys must not be on the agent's host (red-team round 5, R5-L).
//
// An operator-quorum takeover (recover-anchor) or an operator-quorum latch
// clear (recover-root --operator-*) is authorized by the DEVICE, which checks
// the operators' signatures. Enclawed Code's own gates on these commands (an
// interactive terminal, activation auth, the serial typed in) are a
// convenience: a process of this user can call the framework directly. So the
// quorum is only as strong as the place the operator private keys live. If a
// key is on this host, any process the agent starts can read it and sign its
// own takeover.
//
// The rule (the kit's: findHostOperatorKeys, decideOperatorAuthorization),
// for Enclawed Code's own commands only:
//   - a key FILE is never accepted (`--operator-key FILE` is refused): an
//     operator signs the exact message on another machine (an offline
//     station, a hardware token) and pastes the 64-byte signature in
//     (`--operator-offline N`);
//   - the operation is refused outright while an operator private key is
//     found on this host: a file a policy document names, or one in the known
//     locations below. Remove it from the host (or move it to offline media
//     that is not mounted) and run the command again.
//
// What counts as an operator key: an Ed25519 private key (PEM, PKCS#8, or
// DER) in a known operator location or named like one, or any file a policy
// document names that holds an Ed25519 private key. SSH keys (OpenSSH format,
// ~/.ssh), other tools' signing keys outside these locations, and provisioning
// tools that are not Enclawed Code are not looked at and not affected: on a
// machine that is also a provisioning station, those tools keep working, and
// Enclawed Code's operator commands refuse to run there, which is the point.

import path from "node:path";
import { kit } from "./kit.mjs";
import { homeDir, stateDir } from "./paths.mjs";
import { program } from "./program.mjs";

/** Is the file at `p` an Ed25519 private key? (kit) Never returns or logs the key. */
export function isEd25519PrivateKeyFile(p) {
  return kit.isEd25519PrivateKeyFile(p);
}

/** Enclawed Code's state and config directories: where an operator key directory or file counts (data for the kit). */
export function operatorKeyBases(env = process.env) {
  const home = homeDir(env);
  const xdg = env.XDG_CONFIG_HOME && path.isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : path.join(home, ".config");
  return [...new Set([stateDir(env), path.join(home, ".enclawed"), path.join(xdg, "enclawed"), path.join(xdg, "enclawed-code"), path.join(home, ".enclawed-code"), path.join(xdg, "codenclawed"), path.join(home, ".codenclawed")])];
}

/**
 * Operator private keys present on this host (kit.findHostOperatorKeys):
 * { found: [{ path, why }] }. `policyFiles` are the policy documents
 * Enclawed Code reads; every path a document names is checked.
 */
export function findHostOperatorKeys({ env = process.env, cwd = process.cwd(), policyFiles = [], extra = [] } = {}) {
  return { found: kit.findHostOperatorKeys({ home: homeDir(env), cwd, bases: operatorKeyBases(env), policyFiles, extra }) };
}

/**
 * May an operator-quorum command run from this host? (kit.decideOperatorAuthorization)
 * `keyFiles`: the --operator-key files it was given.
 * @returns {{ ok: true } | { ok: false, code: "operator-key-file"|"operator-key-on-host", message: string }}
 */
export function operatorAuthorization(command, { env = process.env, cwd = process.cwd(), policyFiles = [], keyFiles = [] } = {}) {
  const { found } = findHostOperatorKeys({ env, cwd, policyFiles, extra: keyFiles });
  const d = kit.decideOperatorAuthorization({ command, keyFiles, found });
  return d.ok ? d : { ...d, found, message: `${program()}: ${d.message.trimEnd()}\n${CLI_HINT}` };
}

const CLI_HINT = "With Enclawed Code: run the command with --operator-offline N; each operator signs the printed message on their own device and pastes the signature.\n";

/**
 * Signers for an offline quorum: each prints the exact message the device
 * will check, then reads the 64-byte Ed25519 signature made on another
 * machine (kit.parseOfflineSignature: a malformed paste is an empty
 * signature, which the device refuses). The prompt is Enclawed Code's.
 */
export function offlineSigners(count, { out, readLine }) {
  const n = kit.offlineSignerCount(count);
  return Array.from({ length: n }, (_v, i) => async (msg) => {
    out.write(`\nOperator ${i + 1} of ${n}: sign this message (hex) with your operator key, on your own device (never on this machine):\n${Buffer.from(msg).toString("hex")}\n`);
    return kit.parseOfflineSignature(String(await readLine("Paste the 64-byte Ed25519 signature (hex): ")));
  });
}
