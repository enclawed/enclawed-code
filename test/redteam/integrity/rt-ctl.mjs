#!/usr/bin/env node
// ecwctl as the integrity PoCs run it: `bin/ecwctl.mjs` with the
// PoC sandbox's stand-in authority (src/authority.mjs setTestAuthority) and a
// fresh unlock ticket signed by the sandbox's throwaway software credential
// (two-factor is mandatory; src/demo-credential.mjs), exactly like
// test/fixtures/launcher-entry.mjs does for the unit suite. The sandbox's
// rt-authority.json names the authority and the credential; it is read only
// from under the OS temp directory, and the published package ships no
// test/ directory.
import { createPrivateKey } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { setTestAuthority } from "../../../src/authority.mjs";
import { signDemoTicket } from "../../../src/demo-credential.mjs";

// The sandbox directory: TMPDIR (lib.mjs sets it to the sandbox), else the
// parent of ENCLAWED_STATE_DIR or HOME, else the project's parent (cwd).
const e = process.env;
const candidates = [e.TMPDIR, e.ENCLAWED_STATE_DIR && path.dirname(path.resolve(e.ENCLAWED_STATE_DIR)), e.HOME && path.dirname(path.resolve(e.HOME)), path.dirname(process.cwd())]
  .filter(Boolean)
  .map((d) => path.join(d, "rt-authority.json"));
const tmp = fs.realpathSync(os.tmpdir());
const file = candidates.find((f) => fs.existsSync(f) && fs.realpathSync(f).startsWith(`${tmp}${path.sep}`));
if (!file) {
  process.stderr.write("rt-ctl: no PoC sandbox (rt-authority.json in TMPDIR, beside ENCLAWED_STATE_DIR or HOME, or above the project, under the temp directory)\n");
  process.exit(2);
}
const cfg = JSON.parse(fs.readFileSync(file, "utf8"));
setTestAuthority(cfg.authority);
if (cfg.credential && cfg.ticket !== false) {
  signDemoTicket({ authDir: cfg.credential.authDir, credential: cfg.credential.credential, privateKey: createPrivateKey(cfg.credential.privateKeyPem) });
}
const { main } = await import("../../../src/ctl.mjs");
await main(process.argv.slice(2));
