import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// A launch refused for a local reason spends nothing on the Enclaweder: the login step's and the
// sealed session state's refusals are decided before the launch's activation (which spends a
// device-counted unlock use), like the anchor gate.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { loginLaunchPrecheck } from "../src/claude-login.mjs";
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

test("the login precheck: with a device, memory others can read refuses; no login of Enclawed Code's own is needed (Claude Code keeps the session's login); the person's own login never matters", () => {
  const w = world();
  try {
    const shielded = { ...kit, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) };
    assert.deepEqual(loginLaunchPrecheck({ deviceBound: true, platform: "linux", k: shielded }), { ok: true });
    const open = loginLaunchPrecheck({ deviceBound: true, platform: "linux", k: { ...kit, processMemoryShielded: () => ({ shielded: false, reason: "kernel.yama.ptrace_scope=0" }) } });
    assert.equal(open.code, "memory-not-shielded");
    // The person's own plain login: theirs, never a reason to refuse, never touched.
    fs.writeFileSync(path.join(w.env.HOME, ".claude", ".credentials.json"), "{}");
    assert.deepEqual(loginLaunchPrecheck({ deviceBound: true, platform: "linux", k: shielded }), { ok: true });
    assert.equal(fs.readFileSync(path.join(w.env.HOME, ".claude", ".credentials.json"), "utf8"), "{}");
    // No device: nothing to decide.
    assert.deepEqual(loginLaunchPrecheck({ deviceBound: false, platform: "linux", k: { ...kit, processMemoryShielded: () => ({ shielded: false, reason: "x" }) } }), { ok: true });
  } finally {
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
