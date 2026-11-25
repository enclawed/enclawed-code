// Who decides what (settings audit, Table 2 rows 12-21): the framework sees
// only allowlisted variables; a forensic webhook only from the administrator;
// the flavor only from the managed policy (the shell can only raise it);
// user policies layer tighten-only over the managed one, which must be
// root-owned; ENCLAWEDER_ROOT has one strict parser; helpers come from system
// directories, never PATH. Attack and false-positive tests for each.
import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { setTestAuthority } from "../src/authority.mjs";
import { sessionContainment, subreaperWrapper } from "../src/containment.mjs";
import { frameworkEnv, parseHardwareRootMode, resolveHardwareRootMode, shellFlavor } from "../src/env-authority.mjs";
import { loadFramework } from "../src/framework.mjs";
import { gitTracking } from "../src/gate.mjs";
import { launchAuthority } from "../src/launcher.mjs";
import { loadPolicy } from "../src/policy.mjs";
import { createSession, hookEnvironment } from "../src/session.mjs";
import { clearTrustedBinaryCache, trustedBinary } from "../src/trusted-bin.mjs";
import { inUserNamespace } from "../src/userns.mjs";
import { auditRecords, hookSession, pre, runCtl, runHook, runLauncher, sandbox } from "./helpers.mjs";

const SELF = [0, process.getuid?.() ?? 0, ...(inUserNamespace() ? [65534] : [])];
const { fw } = await loadFramework();

let sb;
beforeEach(() => {
  sb = sandbox();
});
afterEach(() => {
  setTestAuthority(null);
  clearTrustedBinaryCache();
  sb.cleanup();
});

// ---- item 5: the hook's environment is an allowlist; the webhook is the administrator's ----

const HOSTILE = {
  ENCLAWEDER_FORENSIC_WEBHOOK: "https://attacker.example/collect",
  ENCLAWEDER_FORENSIC_LOG: "/dev/null",
  ENCLAWEDER_AUDIT_PATH: "/dev/null",
  ENCLAWEDER_QUEUE_LOG: "/dev/null",
  ENCLAWED_AUDIT_PATH: "/dev/null",
  ENCLAWED_CLASSIFICATION_SCHEME: "/tmp/x.json",
  ENCLAWED_NIX_MODE: "1",
  ENCLAWED_SOMETHING_NEW: "1",
  ENCLAWEDER_SOMETHING_NEW: "1",
};

test("attack: framework variables outside the allowlist never reach the hook's session environment or the launcher's framework", () => {
  const s = createSession({ env: { ...sb.env, ...HOSTILE }, cwd: sb.project });
  for (const k of Object.keys(HOSTILE)) {
    assert.equal(s.session.env[k], undefined, k);
  }
  const auth = launchAuthority({ ...sb.env, ...HOSTILE });
  assert.equal(auth.ok, true);
  for (const k of Object.keys(HOSTILE)) {
    assert.equal(auth.env[k], undefined, k);
  }
  assert.ok(auth.warnings.some((w) => /ignoring .*ENCLAWEDER_FORENSIC_WEBHOOK/.test(w)));
  // End to end: the launch's audit record names what was dropped (names only).
  const r = runLauncher(sb, ["-p", "x"], HOSTILE);
  assert.equal(r.status, 0, r.stderr);
  const rec = auditRecords(sb).find((x) => x.type === "claude-code.launch.opt-outs");
  assert.ok(rec.payload.droppedFrameworkEnv.includes("ENCLAWEDER_FORENSIC_WEBHOOK"));
  assert.doesNotMatch(JSON.stringify(rec), /attacker\.example/);
});

test("FP: the allowlisted, user-specific variables still pass (state dir, device path, latch, broker path, FIPS)", () => {
  const keep = { ENCLAWED_STATE_DIR: path.join(sb.home, ".enclawed"), ENCLAWEDER_HIDRAW: "/dev/hidraw7", ENCLAWEDER_STATE: path.join(sb.dir, "l.state"), ENCLAWEDER_BROKER: path.join(sb.dir, "b.sock"), ENCLAWED_FIPS_REQUIRED: "1", ENCLAWEDER_DEVICE: "deny" };
  const env = hookEnvironment({ ...sb.env, ...keep }, { projectDir: sb.project, sessionDir: sb.dir });
  for (const [k, v] of Object.entries(keep)) {
    assert.equal(env[k], v, k);
  }
});

test("FP: a forensic webhook comes from the administrator's grant file, into the hook's environment", () => {
  sb.grant({ forensicWebhook: "https://forensics.example.com/enclaweder" });
  setTestAuthority(sb.authority);
  const env = hookEnvironment({ ...sb.env, ENCLAWEDER_FORENSIC_WEBHOOK: "https://attacker.example/x" }, { projectDir: sb.project, sessionDir: sb.dir });
  assert.equal(env.ENCLAWEDER_FORENSIC_WEBHOOK, "https://forensics.example.com/enclaweder");
  assert.equal(launchAuthority({ ...sb.env, ENCLAWEDER_FORENSIC_WEBHOOK: "https://attacker.example/x" }).env.ENCLAWEDER_FORENSIC_WEBHOOK, "https://forensics.example.com/enclaweder");
});

// ---- item 6: the flavor, layering and the managed file's ownership ----

test("attack: the shell cannot lower the flavor, and an unknown value is the strictest, never open", () => {
  for (const v of ["permissive", "Enclaved", "OPEN", " open", "default", "enclawed-compat", "1"]) {
    assert.equal(shellFlavor({ ENCLAWED_FLAVOR: v }).flavor, "enclaved", v);
  }
  const managed = path.join(sb.admin, "managed-policy.json");
  fs.writeFileSync(managed, JSON.stringify({ enclawed: { policy: { enforceAllowlists: true, allowedTools: ["read"] } }, enclawedCode: { flavor: "enclaved" } }), { mode: 0o644 });
  setTestAuthority(sb.authority);
  const loaded = loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }], flavor: "open" });
  assert.equal(loaded.flavor, "enclaved");
});

test("FP: the shell can raise open to enclaved; unset keeps the managed flavor; open stays open without a managed policy", () => {
  assert.deepEqual(shellFlavor({}), { flavor: null, unknown: false });
  assert.equal(loadPolicy(fw, { candidates: [], flavor: "enclaved" }).flavor, "enclaved");
  assert.equal(loadPolicy(fw, { candidates: [], flavor: null }).flavor, "open");
  assert.equal(loadPolicy(fw, { candidates: [], flavor: "open" }).flavor, "open");
});

test("attack: a user policy file cannot widen the managed policy (tighten-only, not first-found-wins)", () => {
  const managed = path.join(sb.admin, "managed-policy.json");
  fs.writeFileSync(
    managed,
    JSON.stringify({
      enclawed: { policy: { enforceAllowlists: true, allowedTools: ["read", "write"], allowedHosts: ["docs.example.com"], history: { maxAgeDays: 30 } } },
      enclawedCode: { inputCleaner: "on", onHardwareHalt: { eraseClaudeCredentials: true } },
    }),
    { mode: 0o644 },
  );
  const user = path.join(sb.home, "user-policy.json");
  fs.writeFileSync(
    user,
    JSON.stringify({
      enclawed: { policy: { enforceAllowlists: false, allowedTools: ["read", "bash"], allowedHosts: ["evil.example"], history: { maxAgeDays: 7 } } },
      enclawedCode: { inputCleaner: "off", onHardwareHalt: { eraseClaudeCredentials: false } },
    }),
  );
  setTestAuthority(sb.authority);
  const loaded = loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }, { kind: "launcher-env", path: user }], flavor: null });
  assert.equal(loaded.policy.enforceAllowlists, true);
  assert.deepEqual([...loaded.policy.allowedTools], ["read"]);
  assert.deepEqual([...loaded.policy.allowedHosts], []);
  assert.equal(loaded.policy.history.maxAgeDays, 30, "a smaller age would prune restore points sooner");
  assert.equal(loaded.options.inputCleaner, "on");
  assert.equal(loaded.options.onHardwareHalt.eraseClaudeCredentials, true);
  for (const r of [/enforceAllowlists=false/, /allowedTools \+= "bash"/, /allowedHosts \+= "evil.example"/, /maxAgeDays=7/, /inputCleaner=off/, /onHardwareHalt/]) {
    assert.ok(loaded.refused.some((x) => r.test(x)), `${r} in ${loaded.refused}`);
  }
  // A user file may not name the flavor at all.
  fs.writeFileSync(user, JSON.stringify({ enclawedCode: { flavor: "open" } }));
  assert.throws(() => loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }, { kind: "launcher-env", path: user }] }), /flavor is set only by the organization's managed policy/);
});

test("FP: a user policy that only narrows the managed one is applied in full", () => {
  const managed = path.join(sb.admin, "managed-policy.json");
  fs.writeFileSync(managed, JSON.stringify({ enclawed: { policy: { enforceAllowlists: true, allowedTools: ["read", "write"] } } }), { mode: 0o644 });
  const user = path.join(sb.home, "user-policy.json");
  fs.writeFileSync(user, JSON.stringify({ enclawed: { policy: { allowedTools: ["read"], history: { maxAgeDays: 90 } } }, enclawedCode: { claudeAiConnectors: [] } }));
  setTestAuthority(sb.authority);
  const loaded = loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }, { kind: "launcher-env", path: user }] });
  assert.deepEqual([...loaded.policy.allowedTools], ["read"]);
  // Only the managed policy sets maxAgeDays (the framework's tightenPolicy): a user value is refused, larger or smaller.
  assert.equal(loaded.policy.history.maxAgeDays, 30);
  assert.deepEqual(loaded.refused, ["enclawed.policy.history.maxAgeDays=90 (only the admin policy may change 30)"]);
  // Without a managed policy, in the open flavor, the user's file is the policy (unchanged behavior).
  fs.writeFileSync(user, JSON.stringify({ enclawed: { policy: { enforceAllowlists: false, allowedTools: ["bash"] } }, enclawedCode: { inputCleaner: "audit" } }));
  const open = loadPolicy(fw, { candidates: [{ kind: "managed", path: path.join(sb.admin, "absent.json") }, { kind: "launcher-env", path: user }] });
  assert.equal(open.flavor, "open");
  assert.equal(open.options.inputCleaner, "audit");
});

test("attack: a managed policy that is not root-owned refuses the start (it is never silently skipped or trusted)", () => {
  const managed = path.join(sb.admin, "managed-policy.json");
  fs.writeFileSync(managed, JSON.stringify({ enclawed: { policy: { enforceAllowlists: false } }, enclawedCode: { flavor: "open" } }), { mode: 0o644 });
  // Production trust (root only) and, separately, a user namespace.
  setTestAuthority({ ...sb.authority, trustedUids: [4242] });
  assert.throws(() => loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }] }), /cannot be trusted/);
  fs.chmodSync(managed, 0o666);
  setTestAuthority(sb.authority);
  assert.throws(() => loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }] }), /wider than 0644/);
  if (inUserNamespace()) {
    setTestAuthority({ trustedUids: SELF });
    fs.chmodSync(managed, 0o644);
    assert.throws(() => loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }] }), /user namespace/);
  }
  // End to end: the launcher refuses.
  fs.chmodSync(managed, 0o666);
  const r = runLauncher(sb, ["-p", "x"]);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /managed policy .* cannot be trusted/);
});

test("FP: a root-owned managed policy is used, with its flavor", () => {
  const managed = path.join(sb.admin, "managed-policy.json");
  fs.writeFileSync(managed, JSON.stringify({ enclawed: { policy: { enforceAllowlists: false } }, enclawedCode: { flavor: "open" } }), { mode: 0o644 });
  setTestAuthority(sb.authority);
  const loaded = loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }] });
  assert.equal(loaded.kind, "managed");
  assert.equal(loaded.flavor, "open");
  assert.equal(runLauncher(sb, ["-p", "x"]).status, 0);
  // An unknown managed flavor is an invalid policy: the start is refused, never open.
  fs.writeFileSync(managed, JSON.stringify({ enclawedCode: { flavor: "secure" } }), { mode: 0o644 });
  assert.throws(() => loadPolicy(fw, { candidates: [{ kind: "managed", path: managed }] }), /flavor must be exactly one of open, enclaved/);
});

test("history bounds: maxAgeDays outside 7..365 (or not a whole number) is refused in every policy file", () => {
  const user = path.join(sb.home, "user-policy.json");
  for (const v of [1e-6, 0.5, 1, 6, 366, 1e9]) {
    fs.writeFileSync(user, JSON.stringify({ enclawed: { policy: { history: { maxAgeDays: v } } } }));
    assert.throws(() => loadPolicy(fw, { candidates: [{ kind: "launcher-env", path: user }] }), /maxAgeDays must be a (whole )?number (of days )?from 7 to 365/, String(v));
  }
  for (const v of [7, 30, 365]) {
    fs.writeFileSync(user, JSON.stringify({ enclawed: { policy: { history: { maxAgeDays: v } } } }));
    assert.equal(loadPolicy(fw, { candidates: [{ kind: "launcher-env", path: user }] }).policy.history.maxAgeDays, v);
  }
});

// ---- item 7: one strict ENCLAWEDER_ROOT parser ----

test("attack: ENCLAWEDER_ROOT other than exactly unset or required refuses the start; optional is refused from the shell", () => {
  for (const v of ["1", "true", "Required", " required", "required ", "REQUIRED", "optional", "Optional", "0", "false", "off", "yes"]) {
    const a = launchAuthority({ ...sb.env, ENCLAWEDER_ROOT: v });
    assert.equal(a.ok, false, v);
  }
  let r = runLauncher(sb, ["-p", "x"], { ENCLAWEDER_ROOT: "Required" });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /ENCLAWEDER_ROOT="Required" is not (valid|accepted)/);
  r = runLauncher(sb, ["-p", "x"], { ENCLAWEDER_ROOT: "optional" });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /ENCLAWEDER_ROOT=optional is an administrator's decision/);
  // Enclawed Code's own commands too.
  r = runCtl(sb, ["status"], { ENCLAWEDER_ROOT: "1" });
  assert.equal(r.status, 2, r.stderr);
});

test("attack: the hook refuses a session file or managed --hardware-root that is not exactly unset, required or optional", () => {
  const s = hookSession(sb, { ENCLAWEDER_ROOT: "1" });
  const out = runHook(sb, pre(sb, "Read", { file_path: "a" }), {}, { session: s });
  assert.equal(out.out?.hookSpecificOutput?.permissionDecision, "deny");
  assert.match(out.stdout, /ENCLAWEDER_ROOT is not unset, required or optional/);
  const hook = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "bin", "ecwcode-hook.mjs");
  const m = spawnSync(process.execPath, [hook, "--origin", "managed", "--hardware-root", "Required"], { input: JSON.stringify(pre(sb, "Read", { file_path: "a" })), env: { PATH: "/usr/bin:/bin", HOME: sb.home }, encoding: "utf8" });
  assert.match(m.stdout, /--hardware-root must be required or optional/);
});

test("FP: unset and required are accepted; an administrator's optional grant is honored", () => {
  assert.deepEqual(resolveHardwareRootMode({}), { ok: true, mode: "auto" });
  assert.deepEqual(resolveHardwareRootMode({ ENCLAWEDER_ROOT: "required" }), { ok: true, mode: "required" });
  assert.deepEqual(resolveHardwareRootMode({}, { granted: "optional" }), { ok: true, mode: "optional" });
  assert.deepEqual(resolveHardwareRootMode({ ENCLAWEDER_ROOT: "required" }, { granted: "optional" }), { ok: true, mode: "required" }, "required (stricter) wins");
  assert.equal(frameworkEnv({ ENCLAWEDER_ROOT: "required" }, { hardwareRoot: "optional" }).env.ENCLAWEDER_ROOT, "optional");
  assert.equal(parseHardwareRootMode("optional").ok, true);
  sb.grant({ hardwareRoot: "optional" });
  const r = runLauncher(sb, ["-p", "x"]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /hardwareRoot=optional granted by/);
});

// ---- item 3: helpers from system directories, never the user's PATH ----

function shim(name, marker) {
  const p = path.join(sb.bin, name);
  fs.writeFileSync(p, `#!/bin/sh\necho "$0 $*" >> ${JSON.stringify(marker)}\nexit 0\n`, { mode: 0o755 });
}

test("attack: PATH shims for python3, perl, systemd-run, systemctl and git are never run", () => {
  const marker = path.join(sb.dir, "shim-ran.txt");
  for (const n of ["python3", "perl", "systemd-run", "systemctl", "git", "ps", "ss"]) {
    shim(n, marker);
  }
  const env = { ...sb.env };
  const w = subreaperWrapper(env);
  const c = sessionContainment(env);
  c.command("claude", []);
  const f = path.join(sb.project, "f.txt");
  fs.writeFileSync(f, "x");
  gitTracking(f);
  assert.equal(fs.existsSync(marker), false, fs.existsSync(marker) ? fs.readFileSync(marker, "utf8") : "");
  if (w) {
    assert.ok(path.isAbsolute(w.argv[0]) && !w.argv[0].startsWith(sb.bin));
  }
  const r = runLauncher(sb, ["-p", "x"]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(fs.existsSync(marker), false, fs.existsSync(marker) ? fs.readFileSync(marker, "utf8") : "");
});

test("attack: a helper in a user-writable or non-system directory is not trusted", () => {
  const dir = fs.mkdtempSync(path.join(sb.dir, "bin-"));
  shim("python3", path.join(sb.dir, "m"));
  fs.copyFileSync(path.join(sb.bin, "python3"), path.join(dir, "python3"));
  fs.chmodSync(path.join(dir, "python3"), 0o755);
  setTestAuthority({ trustedUids: [4242] });
  assert.equal(trustedBinary("python3", { dirs: [dir] }), null);
});

test("FP: on this machine the system python3 (or perl) and git are found, so containment and git checks work", () => {
  if (process.platform !== "linux") {
    return;
  }
  const py = trustedBinary("python3");
  const pl = trustedBinary("perl");
  assert.ok(py || pl, "python3 or perl in /usr/bin or /bin");
  assert.ok(subreaperWrapper(sb.env), "the subreaper wrapper runs");
  if (trustedBinary("git")) {
    const f = path.join(sb.project, "f.txt");
    fs.writeFileSync(f, "x");
    assert.equal(gitTracking(f), "no-repo");
  }
});

test("attack: a planted syscall.ph on PERL5LIB cannot turn the perl wrapper's prctl into a no-op; FP: PERL5LIB is restored for claude", () => {
  const pl = trustedBinary("perl");
  const py = trustedBinary("python3");
  if (process.platform !== "linux" || process.arch !== "x64" || !pl || !py) {
    return;
  }
  const w = subreaperWrapper(sb.env, { binary: (n) => (n === "python3" ? null : trustedBinary(n)) });
  assert.ok(w, "perl wrapper");
  const evil = path.join(sb.dir, "evil-lib");
  fs.mkdirSync(evil);
  // SYS_prctl -> sched_yield (24 on x86_64): returns 0 and sets nothing.
  fs.writeFileSync(path.join(evil, "syscall.ph"), "sub SYS_prctl () { 24 } 1;\n");
  // The child (same pid as the wrapper after exec) reports its subreaper bit and PERL5LIB.
  const probe = "import ctypes,os;l=ctypes.CDLL(None);v=ctypes.c_int(0);l.prctl(37,ctypes.byref(v),0,0,0);print(v.value);print(os.environ.get('PERL5LIB',''))";
  const run = (env) => spawnSync(w.argv[0], [...w.argv.slice(1), py, "-I", "-c", probe], { env, encoding: "utf8" });
  const r = run(w.env({ PATH: "/usr/bin:/bin", PERL5LIB: evil }));
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.stdout.trim().split("\n"), ["1", evil]);
  // Control: the same planted library reaching perl unscrubbed does make the prctl a no-op.
  const raw = run({ PATH: "/usr/bin:/bin", PERL5LIB: evil });
  assert.equal(raw.stdout.trim().split("\n")[0], "0", "control: the plant works when not scrubbed");
});
