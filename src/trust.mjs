// Who may attest a skill bundle or an MCP server for this installation.
//
// The trust model and every check are the Enclawed adapter kit's
// (enclawed-oss src/enclawed/adapter/trust.ts: trustPaths, addSigner,
// ensureLocalSigner, signRecord, verifyRecord). Enclawed Code only says where
// the trust directory is: <state>/claude-code/trust, inside Enclawed Code's own
// state directory, which no agent tool may write (session.mjs
// protectedPaths); the local signer's private key there is a secret path
// (hook.mjs secretPathsFor). Every change to the list is made by a
// Enclawed Code command after two-factor authentication and is recorded in the
// audit log (admission-cli.mjs).

import { createHash } from "node:crypto";
import path from "node:path";
import { framework, kit } from "./kit.mjs";
import { appStateDir } from "./paths.mjs";

export function trustDir(env = process.env) {
  return path.join(appStateDir(env), "trust");
}
export function signersFile(env = process.env) {
  return kit.trustPaths(trustDir(env)).signers;
}
export function localKeyFile(env = process.env) {
  return kit.trustPaths(trustDir(env)).localKey;
}

/** Sorted-key JSON without whitespace (the framework's; skill bundles and MCP records sign it). */
export const canonicalJson = framework.canonicalJson;

export const sha256Hex = (s) => createHash("sha256").update(s).digest("hex");

export const keyIdOf = (publicKeyPem) => kit.keyIdOf(publicKeyPem);

export function readSigners(env = process.env) {
  return kit.readSigners(trustDir(env));
}

export function findSigner(env, keyId) {
  return kit.findSigner(trustDir(env), keyId);
}

// The callers of the wrappers below have verified the person already
// (admission-cli.mjs authorize), so the kit's authorizer has nothing left to do.
const verified = async () => {};

/** Add (or replace) a trusted signer. Async. `authorize` verifies the person (default: the caller did). */
export function addSigner(env, signer, authorize = verified) {
  return kit.addSigner(trustDir(env), signer, authorize);
}

/** Remove a signer. Async; resolves to whether it was there. */
export function removeSigner(env, keyId, authorize = verified) {
  return kit.removeSigner(trustDir(env), keyId, authorize);
}

/** The local signer (made with the framework's Ed25519 primitive on first use). Async. */
export function ensureLocalSigner(_fw, env = process.env, authorize = verified) {
  return kit.ensureLocalSigner(trustDir(env), authorize);
}

/** Sign a record (every field but `signature`). */
export function signRecord(_fw, record, signer) {
  return kit.signRecord(record, signer);
}

/** Verify a signed record against the trust list. */
export function verifyRecord(_fw, record, env = process.env) {
  return kit.verifyRecord(record, trustDir(env));
}
