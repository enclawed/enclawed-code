import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// A launch refused for a local reason spends nothing on the Enclaweder: the login seal's and the
// sealed session state's refusals are decided before the launch's activation (which spends a
// device-counted unlock use), like the anchor gate.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { loginLaunchPrecheck, sealedLoginFile } from "../src/login-seal.mjs";
import { contextStoreDir, sessionStatePrecheck } from "../src/session-state.mjs";
import { auditLogPath } from "../src/paths.mjs";
import { kit } from "../src/kit.mjs";

test("launch order: the login and session-state prechecks run after the anchor gate and before the launch's activation", () => {
  const src = fs.readFileSync(new URL("../src/launcher.mjs", import.meta.url), "utf8");
  const body = src.slice(src.indexOf("export async function launchSession("));
  const gate = body.indexOf("await launchAnchorGate(");
  const login = body.indexOf("loginLaunchPrecheck({");
  const state = body.indexOf("await sessionStatePrecheck({");
  const activation = body.indexOf("await activateLaunch(");
  assert.ok(gate > 0 && login > gate && state > login && activation > state, "the prechecks must come between the anchor gate and the activation");
});

function world() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cn-precheck-"));
  const home = path.join(root, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  return { root, env: { HOME: home, ENCLAWED_STATE_DIR: path.join(root, "state") } };
}

test("the login precheck: no login of Enclawed Code's own refuses (sign in inside Enclawed Code); memory others can read refuses; the person's own login beside the sealed one refuses only under the managed login policy", async () => {
  const w = world();
  const { setTestAuthority } = await import("../src/authority.mjs");
  const { managedLoginPolicyAuthority, sandbox } = await import("./helpers.mjs");
  const sb = sandbox();
  try {
    setTestAuthority({ managedSettingsDir: fs.mkdtempSync(path.join(w.root, "no-managed-")) });
    const shielded = { ...kit, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) };
    const none = loginLaunchPrecheck({ env: w.env, deviceBound: true, platform: "linux", k: shielded });
    assert.equal(none.code, "no-login");
    assert.match(none.message, /ecwctl login new/);
    fs.mkdirSync(path.dirname(sealedLoginFile(w.env)), { recursive: true });
    fs.writeFileSync(sealedLoginFile(w.env), JSON.stringify({ v: 2, kind: "enclawed.adapter.login-seal.v1", label: "claude-code.login", key: "device:u:box:login:0000000000000000", epk: "", iv: "", tag: "", data: "" }));
    assert.deepEqual(loginLaunchPrecheck({ env: w.env, deviceBound: true, platform: "linux", k: shielded }), { ok: true });
    const open = loginLaunchPrecheck({ env: w.env, deviceBound: true, platform: "linux", k: { ...kit, processMemoryShielded: () => ({ shielded: false, reason: "kernel.yama.ptrace_scope=0" }) } });
    assert.equal(open.code, "memory-not-shielded");
    // The person's own plain login beside the sealed one: theirs, not a reason to refuse ...
    fs.writeFileSync(path.join(w.env.HOME, ".claude", ".credentials.json"), "{}");
    assert.deepEqual(loginLaunchPrecheck({ env: w.env, deviceBound: true, platform: "linux", k: shielded }), { ok: true });
    // ... unless the administrator's managed login policy is in force.
    setTestAuthority(await managedLoginPolicyAuthority(sb));
    const beside = loginLaunchPrecheck({ env: w.env, deviceBound: true, platform: "linux", k: shielded });
    assert.equal(beside.ok, false);
    assert.equal(beside.code, "plaintext-beside-seal");
    assert.equal(fs.readFileSync(path.join(w.env.HOME, ".claude", ".credentials.json"), "utf8"), "{}");
  } finally {
    setTestAuthority(null);
    sb.cleanup();
    fs.rmSync(w.root, { recursive: true, force: true });
  }
});

test("the session-state precheck refuses a sealed store the audit log never recorded; an empty one passes", async () => {
  const w = world();
  try {
    assert.deepEqual(await sessionStatePrecheck({ env: w.env }), { ok: true });
    fs.mkdirSync(contextStoreDir(w.env), { recursive: true });
    fs.writeFileSync(path.join(contextStoreDir(w.env), `${"a".repeat(32)}.ctx`), "{}");
    fs.mkdirSync(path.dirname(auditLogPath(w.env)), { recursive: true });
    const r = await sessionStatePrecheck({ env: w.env });
    assert.equal(r.ok, false);
    assert.equal(r.code, "context-unrecorded");
  } finally {
    fs.rmSync(w.root, { recursive: true, force: true });
  }
});
