import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// Enclawed Code keeps working on state written before the rename (enclawde).
// test/fixtures/legacy-state/dot-enclawed is a real ~/.enclawed written by the
// pre-rename build 542a937 (bin/enclawde-hook.mjs through its own test
// helpers, see origin.json): an audit log whose records name `enclawde`
// (code enclawde-protected-path) with its head anchor, a history snapshot, a
// FIDO2 enrollment for RP id enclawde.local, and a policy file with the
// pre-rename `enclawde` options block. Nothing here reads a real user's state.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { RP_ID } from "../src/auth.mjs";
import { locateClaude } from "../src/claude.mjs";
import { loadFramework } from "../src/framework.mjs";
import { ADMISSION_KINDS, pinRecord, readPins, writePin } from "../src/mcp.mjs";
import { fixtureServer } from "./mcp-fixture.mjs";
import { setTestAuthority } from "../src/authority.mjs";
import { LEGACY_OPT_OUT_FILENAME, resolveGrants } from "../src/opt-outs.mjs";
import { loadPolicy, migrateOptionsBlock, parseOptions } from "../src/policy.mjs";
import { ensureLocalSigner } from "../src/trust.mjs";
import { CTL, sandbox } from "./helpers.mjs";

const FIXTURE = new URL("./fixtures/legacy-state/dot-enclawed/", import.meta.url).pathname;
let sb;
let fw;
before(async () => {
  sb = sandbox();
  ({ fw } = await loadFramework());
  // The old state replaces the sandbox's own.
  fs.rmSync(path.join(sb.home, ".enclawed"), { recursive: true, force: true });
  fs.cpSync(FIXTURE, path.join(sb.home, ".enclawed"), { recursive: true });
});
after(() => sb.cleanup());

const cli = (args) => spawnSync(process.execPath, [CTL, ...args], { env: sb.env, cwd: sb.project, encoding: "utf8" });

test("the fixture really is pre-rename state (old names in the records)", () => {
  const log = fs.readFileSync(path.join(sb.home, ".enclawed", "claude-code", "audit.jsonl"), "utf8");
  assert.match(log, /enclawde-protected-path/);
  assert.match(log, /enclawde-hook\.mjs/);
  assert.doesNotMatch(log, /Enclawed Code/);
});

test("ecwctl audit verify accepts an audit log written by enclawde", () => {
  const r = cli(["audit", "verify", "--no-device"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /audit log verifies: 4 records/);
  assert.match(r.stdout, /head anchor matched/);
  const j = JSON.parse(cli(["audit", "verify", "--no-device", "--json"]).stdout);
  assert.equal(j.ok, true);
  assert.equal(j.count, 4);
});

test("an edited old log still fails (the compatibility is not a bypass)", () => {
  const file = path.join(sb.home, ".enclawed", "claude-code", "audit.jsonl");
  const keep = fs.readFileSync(file, "utf8");
  try {
    fs.writeFileSync(file, keep.replace('"enclawde-protected-path"', '"history:snapshot"'));
    assert.notEqual(cli(["audit", "verify", "--no-device"]).status, 0);
  } finally {
    fs.writeFileSync(file, keep);
  }
  assert.equal(cli(["audit", "verify", "--no-device"]).status, 0);
});

test("ecwctl history list shows the snapshot enclawde kept", () => {
  const r = cli(["history", "list", "--json", "--all"]);
  assert.equal(r.status, 0, r.stderr);
  const entries = JSON.parse(r.stdout);
  assert.ok(entries.some((e) => e.hash === "2d27fbdf4e8ca207afbfa388ca9172fbcc6c70e534af2476b3b704f87debadcf"), r.stdout);
});

test("the security key enrolled under the old name is still the enrolled factor (RP id unchanged)", async () => {
  assert.equal(RP_ID, "enclawde.local");
  const st = await fw.secondFactorStatus({ stateDir: path.join(sb.home, ".enclawed", "claude-code"), rpId: RP_ID, audit: async () => {} });
  assert.equal(st.credentials.length, 1);
});

test("the pre-rename options block is read; a file with both blocks is refused; writers migrate it", () => {
  const loaded = loadPolicy(fw, { candidates: [{ kind: "enclawed-code-user", path: path.join(sb.home, ".enclawed", "claude-code", "enclawed.json") }], flavor: "open" });
  assert.equal(loaded.options.inputCleaner, "audit");
  assert.equal(loaded.options.onHardwareHalt.eraseClaudeCredentials, false);
  assert.throws(() => parseOptions({ enclawedCode: {}, enclawde: {} }), /more than one options block \(enclawedCode, enclawde\)/);
  assert.throws(() => parseOptions({ enclawedCode: {}, codenclawed: {} }), /more than one options block \(enclawedCode, codenclawed\)/);
  assert.throws(() => parseOptions({ codenclawed: {}, enclawde: {} }), /more than one options block/);
  assert.equal(parseOptions({ enclawedCode: { inputCleaner: "off" } }).inputCleaner, "off");
  // The block an earlier codenclawed build wrote is read as it was.
  assert.equal(parseOptions({ codenclawed: { inputCleaner: "audit" } }).inputCleaner, "audit");
  assert.deepEqual(migrateOptionsBlock({ enclawed: { policy: {} }, enclawde: { inputCleaner: "off" } }), { enclawed: { policy: {} }, enclawedCode: { inputCleaner: "off" } });
  assert.deepEqual(migrateOptionsBlock({ enclawed: { policy: {} }, codenclawed: { inputCleaner: "off" } }), { enclawed: { policy: {} }, enclawedCode: { inputCleaner: "off" } });
});

test("an MCP pin of the pre-rename kind still verifies; another kind does not", async () => {
  const env = { ...sb.env, HOME: sb.home };
  const signer = await ensureLocalSigner(fw, env);
  // An existing script in a directory of its own: the kit pins it by its package's tree.
  const def = { type: "stdio", command: process.execPath, args: [fixtureServer(sb)] };
  const probe = { serverInfo: { name: "notes", version: "1" }, tools: [{ name: "note_lookup", description: "Look up a note.", inputSchema: { type: "object" } }] };
  assert.deepEqual(ADMISSION_KINDS, ["codenclawed-mcp-admission", "enclawde-mcp-admission"]);
  writePin(fw, { ...pinRecord({ name: "old", def, scope: "user", source: "t", probe, env }), kind: "enclawde-mcp-admission" }, signer, env);
  writePin(fw, { ...pinRecord({ name: "other", def, scope: "user", source: "t", probe, env }), kind: "something-else" }, signer, env);
  const pins = readPins(fw, env);
  assert.equal(pins.find((p) => p.record?.name === "old").ok, true);
  assert.equal(pins.find((p) => p.record?.name === "other").ok, false);
});

test("an opt-out file under the old name is still read (v2 grants); its retired v1 knobs (ENCLAWDE_*) grant nothing", () => {
  const dir = fs.mkdtempSync(path.join(sb.dir, "etc-"));
  const file = path.join(dir, LEGACY_OPT_OUT_FILENAME);
  setTestAuthority({ optOutDirs: [dir], trustedUids: [0, process.getuid(), 65534], ignoreUserNamespace: true });
  try {
    fs.writeFileSync(file, JSON.stringify({ v: 2, reducedContainment: true }), { mode: 0o644 });
    assert.equal(resolveGrants({ PATH: "/usr/bin" }).grants.reducedContainment, true);
    fs.writeFileSync(file, JSON.stringify({ v: 1, optOuts: { ENCLAWDE_ALLOW_PROJECT_HOOKS: "1", ENCLAWDE_SCOPE: "off" } }), { mode: 0o644 });
    const r = resolveGrants({ PATH: "/usr/bin", ENCLAWDE_ALLOW_PROJECT_HOOKS: "1" });
    assert.deepEqual(r.grants.projectHooks, []);
    assert.equal(r.grants.reducedContainment, false);
    assert.match(r.notes.join("\n"), /version 1 .*are retired/);
  } finally {
    setTestAuthority(null);
  }
});

test("an older install (marker @enclawde-launcher) is never run as claude", () => {
  const dir = fs.mkdtempSync(path.join(sb.dir, "oldbin-"));
  const old = path.join(dir, "claude");
  fs.writeFileSync(old, "#!/usr/bin/env node\n// @enclawde-launcher: runs the user's own Claude Code with Enclawed's checks.\n", { mode: 0o755 });
  assert.equal(locateClaude({ PATH: dir }), null);
});
