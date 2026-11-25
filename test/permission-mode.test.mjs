import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// The permission mode ecwcode starts Claude Code in (src/permission-mode.mjs):
// bypassPermissions by default; the person's own flag wins; the administrator's
// managed settings and a root user turn the default off. The real binary's
// behavior in bypass mode is proven in test/bypass-real.test.mjs.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { MANAGED_NO_BYPASS_TEXT, effectivePermissionMode, modeDoctorLine } from "../src/permission-mode.mjs";
import { runCtl, runLauncher, sandbox } from "./helpers.mjs";

const user = { env: {}, uid: 1000 };

test("the default is bypassPermissions; the person's mode flag wins; managed settings and root turn the default off", () => {
  assert.deepEqual(effectivePermissionMode([], user), { mode: "bypassPermissions", source: "enclawed-default", add: ["--permission-mode", "bypassPermissions"], acceptBypass: true });
  for (const args of [["--permission-mode", "default"], ["--permission-mode=plan"], ["--permission-mode", "auto", "-p", "x"], ["--dangerously-skip-permissions"]]) {
    const m = effectivePermissionMode(args, user);
    assert.equal(m.source, "person", args.join(" "));
    assert.deepEqual(m.add, []);
    assert.equal(m.acceptBypass, false);
  }
  // A mode word after `--` is the prompt, not a flag.
  assert.equal(effectivePermissionMode(["--", "--permission-mode", "plan"], user).source, "enclawed-default");
  const managed = [{ file: "m", doc: { permissions: { disableBypassPermissionsMode: "disable" } } }];
  assert.deepEqual(effectivePermissionMode([], { ...user, managedDocs: managed }), { mode: null, source: "managed", add: [], acceptBypass: false });
  assert.equal(effectivePermissionMode([], { env: {}, uid: 0 }).source, "root");
  assert.equal(effectivePermissionMode([], { env: { IS_SANDBOX: "1" }, uid: 0 }).source, "enclawed-default");
  assert.match(modeDoctorLine(effectivePermissionMode([], user)), /^permission mode: bypassPermissions unless you pass --permission-mode/);
  assert.match(modeDoctorLine(effectivePermissionMode([], { ...user, managedDocs: managed })), /administrator's managed settings turn bypass mode off/);
});

let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());

function launch(args, authority = {}) {
  const out = path.join(sb.dir, `rec-${Math.random().toString(36).slice(2)}.json`);
  const r = runLauncher(sb, args, { FAKE_CLAUDE_OUT: out }, authority);
  return { r, rec: fs.existsSync(out) ? JSON.parse(fs.readFileSync(out, "utf8")) : null };
}

test("a launch passes --permission-mode bypassPermissions and pre-accepts its confirmation in the session's own settings file only; the person's own mode is passed unchanged", () => {
  const { r, rec } = launch(["-p", "x"]);
  assert.equal(r.status, 0, r.stderr);
  const at = rec.argv.indexOf("--permission-mode");
  assert.equal(rec.argv[at + 1], "bypassPermissions", JSON.stringify(rec.argv));
  assert.ok(at < rec.argv.indexOf("-p"), "before the person's own arguments");
  assert.equal(rec.settings.skipDangerousModePermissionPrompt, true);
  assert.ok(!fs.existsSync(path.join(sb.home, ".claude", "settings.json")) || !/skipDangerousModePermissionPrompt/.test(fs.readFileSync(path.join(sb.home, ".claude", "settings.json"), "utf8")));
  const own = launch(["--permission-mode", "plan", "-p", "x"]);
  assert.equal(own.r.status, 0, own.r.stderr);
  assert.deepEqual(own.rec.argv.filter((a) => a === "--permission-mode"), ["--permission-mode"], "only the person's flag");
  assert.equal(own.rec.argv[own.rec.argv.indexOf("--permission-mode") + 1], "plan");
  assert.equal(own.rec.settings.skipDangerousModePermissionPrompt, undefined);
});

test("managed settings that turn bypass mode off: Claude Code starts in its default mode, said once in plain words, and by ecwctl doctor", () => {
  const dir = fs.mkdtempSync(path.join(sb.dir, "managed-"));
  fs.writeFileSync(path.join(dir, "managed-settings.json"), JSON.stringify({ permissions: { disableBypassPermissionsMode: "disable" } }));
  const authority = { managedSettingsDir: dir };
  const first = launch(["-p", "x"], authority);
  assert.equal(first.r.status, 0, first.r.stderr);
  assert.ok(!first.rec.argv.includes("--permission-mode"), JSON.stringify(first.rec.argv));
  assert.equal(first.rec.settings.skipDangerousModePermissionPrompt, undefined);
  assert.ok(first.r.stderr.replace(/\n  /g, " ").includes(`ecwcode: ${MANAGED_NO_BYPASS_TEXT}`), first.r.stderr);
  const again = launch(["-p", "x"], authority);
  assert.ok(!again.r.stderr.includes("turn bypass mode off"), "said once");
  const d = runCtl(sb, ["doctor"], {}, authority);
  assert.match(d.stdout, /permission mode: Claude Code's default\. .*turn bypass mode off/);
  assert.match(runCtl(sb, ["doctor"]).stdout, /permission mode: bypassPermissions unless you pass --permission-mode/);
});
