#!/usr/bin/env node
// TEST DOUBLE of libfido2's command-line tools (fido2-token, fido2-assert),
// for tests that drive Enclawed Code's interactive two-factor path without a
// security key. It signs with the sandbox's SOFTWARE test credential
// (FAKE_FIDO2_STATE: the private key, the credential id, a counter file).
// It is not a model of an authenticator and proves nothing about one.
// Tests only put it on PATH when no real libfido2 tools are installed in the
// system directories the framework prefers, so a real key is never touched.
import { createHash, createPrivateKey, sign } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const tool = path.basename(process.argv[1]);
const args = process.argv.slice(2);
const state = JSON.parse(fs.readFileSync(process.env.FAKE_FIDO2_STATE, "utf8"));
const DEV = "/dev/fake-fido2";

if (tool === "fido2-token") {
  if (args[0] === "-L") {
    process.stdout.write(`${DEV}: vendor=0x0000, product=0x0000 (Enclawed Code test double)\n`);
  } else if (args[0] === "-I") {
    process.stdout.write(
      ["proto: 0x02", "version strings: U2F_V2, FIDO_2_0, FIDO_2_1", `aaguid: ${state.aaguid.replace(/-/g, "")}`, "options: rk, up, noplat, clientPin, credMgmt", "algorithms: es256 (public-key)", ""].join("\n"),
    );
  }
  process.exit(0);
}
if (tool === "fido2-assert" && args[0] === "-G") {
  const [cdh, rpId, credId] = fs.readFileSync(0, "utf8").split("\n");
  if (Buffer.from(credId, "base64").toString("base64url") !== state.credentialId) {
    process.exit(1);
  }
  const silent = args.includes("up=false");
  const counter = Number(fs.existsSync(state.counterFile) ? fs.readFileSync(state.counterFile, "utf8") : "1") + 1;
  fs.writeFileSync(state.counterFile, String(counter));
  const c = Buffer.alloc(4);
  c.writeUInt32BE(counter);
  const authData = Buffer.concat([createHash("sha256").update(rpId).digest(), Buffer.from([silent ? 0x00 : 0x05]), c]);
  // libfido2 prints authenticator data CBOR-wrapped (a byte string).
  const wrapped = Buffer.concat([Buffer.from([0x58, authData.length]), authData]);
  const key = createPrivateKey({ key: state.privateKeyJwk, format: "jwk" });
  const sig = sign("sha256", Buffer.concat([authData, Buffer.from(cdh, "base64")]), key);
  process.stdout.write([cdh, rpId, wrapped.toString("base64"), sig.toString("base64"), ""].join("\n"));
  process.exit(0);
}
process.exit(1);
