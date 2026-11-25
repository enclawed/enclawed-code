import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// The rename codenclawed -> Enclawed Code (ecwcode / ecwctl): what an install
// of an earlier build left behind keeps working or is taken out, never mistaken
// for the current one; and ecwctl's own command surface.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { after, afterEach, before, test } from "node:test";
import { setTestAuthority } from "../src/authority.mjs";
import { locateClaude } from "../src/claude.mjs";
import { kit } from "../src/kit.mjs";
import { legacyManagedHookFiles } from "../src/managed.mjs";
import { resolveGrants } from "../src/opt-outs.mjs";
import { CTL, runCtl, runLauncher, sandbox } from "./helpers.mjs";

const sink = () => {
  const o = { text: "", write: (s) => ((o.text += s), true) };
  return o;
};
let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());
afterEach(() => setTestAuthority(null));

test("ecwctl: help lists Enclawed Code's commands, version prints the version, an unknown word is an error; claude is never started", () => {
  const out = path.join(sb.dir, "ctl-claude.json");
  for (const a of [[], ["help"], ["--help"], ["-h"]]) {
    const r = runCtl(sb, a, { FAKE_CLAUDE_OUT: out });
    assert.equal(r.status, 0, `${a}: ${r.stderr}`);
    assert.match(r.stdout, /^Enclawed Code \d+\.\d+\.\d+: Claude Code, with every tool call checked by Enclawed\./);
    for (const c of ["history list", "audit verify", "managed print", "doctor", "demo", "policy init", "auth enroll", "recover-root", "review", "probe", "mcp list"]) {
      assert.ok(r.stdout.includes(`ecwctl ${c}`), `${c} in help`);
    }
    assert.doesNotMatch(r.stdout, /codenclawed|reserved/);
  }
  for (const a of [["version"], ["--version"], ["-v"]]) {
    const r = runCtl(sb, a, { FAKE_CLAUDE_OUT: out });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /^\d+\.\d+\.\d+\n$/);
  }
  const bad = runCtl(sb, ["frobnicate"], { FAKE_CLAUDE_OUT: out });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /^ecwctl: unknown command "frobnicate"/);
  assert.equal(fs.existsSync(out), false, "ecwctl never started claude");
});

test("package.json: the package is enclawed-code; its programs are ecwcode, ecwctl, ecwcode-hook, ecwcode-mcp-proxy, and each exists", () => {
  const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.name, "enclawed-code");
  assert.deepEqual(Object.keys(pkg.bin).sort(), ["ecwcode", "ecwcode-hook", "ecwcode-mcp-proxy", "ecwctl"]);
  for (const f of Object.values(pkg.bin)) {
    assert.ok(fs.statSync(new URL(`../${f}`, import.meta.url)).mode & 0o111, `${f} is executable`);
  }
  assert.equal(spawnSync(process.execPath, [CTL, "--version"], { encoding: "utf8" }).stdout.trim(), pkg.version);
});

test("an install of an earlier build on PATH (its launcher marker) is never run as claude", () => {
  const bin = path.join(sb.dir, "old-bin");
  fs.mkdirSync(bin);
  for (const marker of ["@codenclawed-launcher", "@enclawde-launcher", "@enclawed-code-launcher"]) {
    const f = path.join(bin, "claude");
    fs.writeFileSync(f, `#!/usr/bin/env node\n// ${marker}: an earlier build\n`, { mode: 0o755 });
    assert.equal(locateClaude({ PATH: bin }), null, marker);
  }
});

test("the variables of earlier builds (CODENCLAWED_*) are ignored with a warning; ECWCODE_CLAUDE_PATH is read", () => {
  const r = runLauncher(sb, ["-p", "x"], { CODENCLAWED_CLAUDE_PATH: "/nonexistent/claude" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /ignoring CODENCLAWED_CLAUDE_PATH from your shell: Enclawed Code reads ECWCODE_\* \(renamed from CODENCLAWED_\* and ENCLAWDE_\*\)/);
  const n = runLauncher(sb, ["-p", "x"], { ECWCODE_CLAUDE_PATH: "/nonexistent/claude" });
  assert.equal(n.status, 127);
  assert.match(n.stderr, /cannot find your Claude Code installation/);
});

test("an administrator's grant file under the earlier name codenclawed-opt-outs.json is still read", () => {
  const dir = fs.mkdtempSync(path.join(sb.dir, "etc-"));
  setTestAuthority({ optOutDirs: [dir], trustedUids: [0, process.getuid(), 65534], ignoreUserNamespace: true });
  fs.writeFileSync(path.join(dir, "codenclawed-opt-outs.json"), JSON.stringify({ v: 2, reducedContainment: true }), { mode: 0o644 });
  assert.equal(resolveGrants({ PATH: "/usr/bin" }).grants.reducedContainment, true);
});

test("a managed settings file that still runs an earlier build's hook program is named (it blocks every tool call)", () => {
  const dir = fs.mkdtempSync(path.join(sb.dir, "managed-"));
  fs.mkdirSync(path.join(dir, "managed-settings.d"));
  const hooks = (cmd) => JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: cmd }] }] } });
  fs.writeFileSync(path.join(dir, "managed-settings.d", "50-codenclawed.json"), hooks("'/usr/bin/node' '/opt/x/bin/codenclawed-hook.mjs' --origin managed"));
  fs.writeFileSync(path.join(dir, "managed-settings.d", "40-enclawde.json"), hooks("/opt/y/bin/enclawde-hook --origin managed"));
  fs.writeFileSync(path.join(dir, "managed-settings.d", "50-enclawed-code.json"), hooks("'/usr/bin/node' '/opt/x/bin/ecwcode-hook.mjs' --origin managed"));
  fs.writeFileSync(path.join(dir, "managed-settings.d", "60-other.json"), hooks("/opt/z/my-codenclawed-hook-wrapper --x"));
  assert.deepEqual(legacyManagedHookFiles(dir).map((f) => path.basename(f)), ["40-enclawde.json", "50-codenclawed.json"]);
});

test("the retired login commands and the managed login policy refuse and say what to use instead; an earlier build's drop-in is named for the administrator", async () => {
  for (const sub of ["new", "seal", "resolve", "watch"]) {
    const r = runCtl(sb, ["login", sub]);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /never collects, stores or relays a Claude subscription login\. Sign in with \/login inside an Enclawed Code session/);
  }
  for (const sub of ["install", "status", "print", "remove"]) {
    const r = runCtl(sb, ["managed", "login-policy", sub]);
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stderr, /managed login-policy is retired: Enclawed Code never removes, disables or restricts a way of signing in to Claude Code/);
    assert.match(r.stderr, /forceLoginMethod, forceLoginOrgUUID and allowedProviders \(https:\/\/code\.claude\.com\/docs\/en\/authentication#restrict-login-to-your-organization\)/);
  }
  const { retiredLoginPolicyPaths } = await import("../src/admin.mjs");
  assert.deepEqual(retiredLoginPolicyPaths("/etc/claude-code").map((p) => path.relative("/etc/claude-code", p)), ["managed-settings.d/90-enclawed-code-login.json", "enclawed-code-no-login", "managed-settings.d/90-codenclawed-login.json", "codenclawed-no-login"]);
});

test("shared messages carry the running program's name: ecwctl's say ecwctl:, ecwcode's say ecwcode:", async () => {
  const c = runCtl(sb, ["files", "accept"]);
  assert.match(c.stderr, /^ecwctl: name the files to accept, or --all/m, c.stderr);
  assert.doesNotMatch(c.stderr, /^ecwcode:/m);
  // (A routine launch says nothing; a launch with something to say.)
  const l = runLauncher(sb, ["-p", "x"], { CODENCLAWED_SOMETHING: "1" });
  assert.equal(l.status, 0, l.stderr);
  assert.match(l.stderr, /^ecwcode: ignoring CODENCLAWED_SOMETHING/m);
  assert.doesNotMatch(l.stderr, /^ecwctl:/m);
  // The two-factor context's `say` (the kit's "Open this page in your browser ..." line goes through it).
  const { program, setProgram } = await import("../src/program.mjs");
  const { frameworkAuthContext } = await import("../src/auth.mjs");
  const write = process.stderr.write;
  for (const name of ["ecwctl", "ecwcode"]) {
    setProgram(name);
    const said = [];
    process.stderr.write = (x) => (said.push(String(x)), true);
    try {
      frameworkAuthContext({ env: sb.env, audit: async () => {} }).say("Open this page in your browser to use your passkey: http://localhost:1/x");
    } finally {
      process.stderr.write = write;
    }
    assert.equal(program(), name);
    assert.deepEqual(said, [`${name}: confirm with your passkey: open http://localhost:1/x in your browser\n`]);
  }
  setProgram(null);
});
