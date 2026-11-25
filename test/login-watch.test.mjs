import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// A plaintext Claude Code login appearing at rest, with an Enclaweder bound,
// is sealed or quarantined within the watcher's bound and never left readable
// for plain `claude` (src/login-watch.mjs over the kit's
// host-credential-watch.ts), and a person without a working `claude` login
// (a managed install) signs in inside Enclawed Code (kit oauth-code-login.ts).
// Attack side: a login written by plain claude while no session runs is
// quarantined by the watcher process within the bound; one written while a
// session holds the device is sealed under it at once; a launch is refused
// while one is held; a held login sealed under another device is not adopted;
// a pasted code from another sign-in seals nothing; a halt erases what the
// session held.
// False-positive side: no device bound leaves the person's login alone; the
// person adopts the held login (or discards it); `login new` seals a fresh
// login without ever writing it in plaintext; the service file runs the
// watcher; no watcher process is spawned by the suite.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { after, afterEach, before, beforeEach, test } from "node:test";
import { setTestAuthority } from "../src/authority.mjs";
import { claudeCredentialLocations } from "../src/credentials.mjs";
import { containment, kit } from "../src/kit.mjs";
import { loginSealKeys, sealedLoginFile } from "../src/login-seal.mjs";
import {
  closeLoginForSession,
  ensureLoginWatcher,
  loginLaunchPrecheck,
  loginWatchCommand,
  openLoginForSession,
  pendingLogins,
  pendingNotice,
  startLoginWatch,
  sweepLogins,
  unitText,
  CLAUDE_SIGN_IN,
} from "../src/login-watch.mjs";
import { CTL_ENTRY, managedLoginPolicyAuthority, sandbox } from "./helpers.mjs";

const TOKEN = "sk-ant-oat01-login-watch-test-token-0123456789";
const LOGIN = JSON.stringify({ claudeAiOauth: { accessToken: TOKEN, refreshToken: `r-${TOKEN}`, expiresAt: Date.now() + 3600_000, scopes: ["user:inference"] } });
const standIn = (secret = "device-secret-A") => ({ uid: "dev-uid-1", sign: async (m) => createHash("sha512").update(secret).update(m).digest() });
const sink = () => {
  const o = { text: "", write: (s) => ((o.text += s), true) };
  return o;
};
const BOUND = kit.CREDENTIAL_WATCH_BOUND_MS;
const k = { ...kit, createContainerCa: containment.createContainerCa };

let sb;
let n = 0;
// These tests are about the managed login policy, the only case in which Enclawed Code acts on the
// person's own login (login-guard.mjs); test/person-login.test.mjs proves it never does without it.
let policy;
before(async () => {
  sb = sandbox();
});
after(() => sb.cleanup());
beforeEach(async () => {
  policy ??= await managedLoginPolicyAuthority(sb);
  setTestAuthority({ ...policy });
});
afterEach(() => setTestAuthority(null));

function world({ sealed = false } = {}) {
  const root = path.join(sb.dir, `lw${++n}`);
  const home = path.join(root, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  const env = { ...sb.env, HOME: home, ENCLAWED_STATE_DIR: path.join(root, "state"), ENCLAWEDER_DEVICE: "deny" };
  const plain = claudeCredentialLocations(env, "linux").file;
  const sessionDir = path.join(root, "session");
  fs.mkdirSync(sessionDir, { mode: 0o700 });
  return { root, env, plain, sessionDir, sealed };
}

/** Seal LOGIN under the stand-in device as `login seal` would (the device's key). */
async function sealUnder(w, device = standIn()) {
  fs.writeFileSync(w.plain, LOGIN, { mode: 0o600 });
  const keys = await loginSealKeys({ env: w.env, k, device });
  const r = k.sealLoginFile({ plainFile: w.plain, sealedFile: sealedLoginFile(w.env), keys, deviceBound: true, label: "claude-code.login" });
  assert.equal(r.ok, true);
  return keys;
}

const waitGone = async (file, ms = BOUND * 3) => {
  const t0 = Date.now();
  while (fs.existsSync(file) && Date.now() - t0 < ms) {
    await new Promise((r) => setTimeout(r, 10));
  }
  return { gone: !fs.existsSync(file), ms: Date.now() - t0 };
};

const cmd = (w, args, extra = {}) => {
  const out = sink();
  const err = sink();
  return loginWatchCommand(args, { out, err, env: w.env, k, hold: async () => ({ mode: "software-only", release() {} }), device: standIn(), readCode: async () => "", ...extra }).then((code) => ({ code, out: out.text, err: err.text }));
};

test("no device bound: the person's ordinary plaintext login is left alone", async () => {
  const w = world();
  fs.writeFileSync(w.plain, LOGIN, { mode: 0o600 });
  const ev = await sweepLogins({ env: w.env });
  assert.deepEqual(ev.map((e) => e.result.action), ["left"]);
  assert.equal(fs.readFileSync(w.plain, "utf8"), LOGIN);
  assert.equal(pendingNotice(w.env), null);
});

test("attack: plain claude signs in beside a sealed login while no session runs: the watcher process quarantines it within the bound; a launch is refused until the person resolves it", async () => {
  const w = world();
  await sealUnder(w);
  // The watcher process, as the systemd service or a launch starts it.
  const child = spawn(process.execPath, [CTL_ENTRY, JSON.stringify(policy), "login", "watch"], { env: w.env, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  try {
    const t0 = Date.now();
    while (!fs.existsSync(path.join(w.env.ENCLAWED_STATE_DIR, "claude-code", "login-watch.pid")) && Date.now() - t0 < 20_000) {
      await new Promise((r) => setTimeout(r, 50));
    }
    // Claude Code's own write: a temporary file, then the rename.
    const tmp = `${w.plain}.tmp.5c08dced`;
    fs.writeFileSync(tmp, LOGIN, { mode: 0o600 });
    fs.renameSync(tmp, w.plain);
    const g = await waitGone(w.plain);
    assert.equal(g.gone, true, out);
    assert.ok(g.ms <= BOUND, `taken after ${g.ms} ms, bound ${BOUND} ms`);
    // The kit's move goes through a held name beside the file; it is gone once the move completes, and the record follows.
    const auditFile = path.join(w.env.ENCLAWED_STATE_DIR, "claude-code", "audit.jsonl");
    const t1 = Date.now();
    while ((fs.readdirSync(path.dirname(w.plain)).length > 0 || !fs.existsSync(auditFile) || !/login\.watch\.quarantined/.test(fs.readFileSync(auditFile, "utf8"))) && Date.now() - t1 < 5000) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.deepEqual(fs.readdirSync(path.dirname(w.plain)), []);
  } finally {
    child.kill("SIGTERM");
    await new Promise((r) => child.once("exit", r));
  }
  const p = pendingLogins(w.env);
  assert.equal(p.length, 1);
  assert.equal(p[0].sealed, false);
  assert.match(pendingNotice(w.env), /made outside Enclawed Code are held \(quarantined\).*sign out of other Claude Code sessions at claude\.ai/);
  // The launch refuses while it is held.
  const opened = await openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound: true, platform: "linux", k });
  assert.equal(opened.code, "login-pending");
  // The audit names what happened (no secret).
  const log = fs.readFileSync(path.join(w.env.ENCLAWED_STATE_DIR, "claude-code", "audit.jsonl"), "utf8");
  assert.match(log, /claude-code\.login\.watch\.quarantined/);
  assert.ok(!log.includes(TOKEN));
  // The person adopts it (it is theirs): sealed under the device, the quarantine erased.
  const before = fs.readFileSync(sealedLoginFile(w.env), "utf8");
  assert.equal((await cmd(w, ["resolve"])).code, 1); // a sealed login is there: --replace needed
  const r = await cmd(w, ["resolve", "--replace"]);
  assert.equal(r.code, 0, r.err);
  assert.equal(pendingLogins(w.env).length, 0);
  assert.notEqual(fs.readFileSync(sealedLoginFile(w.env), "utf8"), before);
  assert.ok(!fs.readFileSync(sealedLoginFile(w.env), "utf8").includes(TOKEN));
});

test("discard: the held login is erased; a launch sweeps a login that appeared and refuses", async () => {
  const w = world();
  await sealUnder(w);
  fs.writeFileSync(w.plain, LOGIN, { mode: 0o600 });
  const opened = await openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound: true, platform: "linux", k });
  assert.equal(opened.code, "login-pending");
  assert.equal(fs.existsSync(w.plain), false);
  const r = await cmd(w, ["resolve", "--discard"]);
  assert.equal(r.code, 0);
  assert.equal(pendingLogins(w.env).length, 0);
  assert.equal(pendingNotice(w.env), null);
});

// ------------------------------------------------------------ in a session (the relay's stand-ins, as in login-seal.test)
const PROVIDER = "api.anthropic.com";
const TOKEN_HOST = "platform.claude.com";
let standIns = null;
async function startStandIns() {
  if (standIns) {
    return standIns;
  }
  const ca = k.createContainerCa("stand-in provider", [PROVIDER, TOKEN_HOST]);
  const up = https.createServer({ key: ca.leafFor(PROVIDER).keyPem, cert: ca.leafFor(PROVIDER).certPem }, (req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  });
  const tokenCalls = [];
  const tok = https.createServer({ key: ca.leafFor(TOKEN_HOST).keyPem, cert: ca.leafFor(TOKEN_HOST).certPem }, (req, res) => {
    let b = "";
    req.on("data", (d) => (b += d));
    req.on("end", () => {
      const j = JSON.parse(b);
      tokenCalls.push(j);
      const good = j.grant_type === "authorization_code" && j.code === "good-code";
      res.writeHead(good ? 200 : 401, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "sk-ant-oat01-NEW-SIGN-IN", refresh_token: "sk-ant-ort01-NEW", expires_in: 3600, scope: "user:inference user:profile" }));
    });
  });
  const port = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(s.address().port)));
  standIns = { ca, up, tok, tokenCalls, upPort: await port(up), tokPort: await port(tok) };
  return standIns;
}
after(() => {
  for (const s of [standIns?.up, standIns?.tok]) {
    s?.closeAllConnections();
    s?.close();
  }
});

test("attack: plain claude signs in while a session holds the device: the session's watcher seals it under the device at once; a halt erases it", async () => {
  const w = world();
  await sealUnder(w);
  const s = await startStandIns();
  const spawned = [];
  setTestAuthority({ ...policy, loginWatchSpawn: (o) => spawned.push(o) });
  const keys = await loginSealKeys({ env: w.env, k, device: standIn() });
  const opened = await openLoginForSession({
    env: w.env,
    sessionDir: w.sessionDir,
    deviceBound: true,
    platform: "linux",
    k: { ...k, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) },
    keys,
    relayOptionsForTest: { relay: { upstreamTrustForTest: s.ca.certPem, upstreamAddressForTest: { host: "127.0.0.1", port: s.upPort } }, credential: { trustForTest: s.ca.certPem, addressForTest: { host: "127.0.0.1", port: s.tokPort } } },
  });
  assert.equal(opened.ok, true, opened.message);
  assert.equal(opened.action, "relayed");
  // The launch starts the watcher process when none runs (the suite's stand-in records it).
  assert.equal(spawned.length, 1);
  try {
    fs.writeFileSync(w.plain, LOGIN.replace(TOKEN, `${TOKEN}-other`), { mode: 0o600 });
    const g = await waitGone(w.plain);
    assert.equal(g.gone, true);
    assert.ok(g.ms <= BOUND, `taken after ${g.ms} ms, bound ${BOUND} ms`);
    const t0 = Date.now();
    while (pendingLogins(w.env).length === 0 && Date.now() - t0 < 2000) {
      await new Promise((r) => setTimeout(r, 10));
    }
    const p = pendingLogins(w.env);
    assert.equal(p.length, 1);
    assert.equal(p[0].sealed, true);
    assert.ok(!fs.readFileSync(p[0].file, "utf8").includes(TOKEN));
    // It opens with this device's key only.
    assert.equal(k.unsealLoginToMemory({ sealedFile: p[0].file, keys, deviceBound: true, label: "claude-code.login" }).ok, true);
  } finally {
    const end = await closeLoginForSession(opened, { halted: true, k });
    assert.ok(end.erased.some((e) => e.startsWith("held login ")));
  }
  assert.equal(pendingLogins(w.env).length, 0);
});

test("command set 0.5: with the launch's symmetric key forgotten, the session's watcher seals to the launch's login box (which only seals); with no box it quarantines, never leaves it", async (t) => {
  if (typeof k.sealBoxFromSeed !== "function" || typeof k.sealOnlyBox !== "function") {
    t.skip("the kit's login box is not in this framework build");
    return;
  }
  const w = world();
  await sealUnder(w);
  const seed = createHash("sha256").update("box-seed").digest();
  const opener = k.sealBoxFromSeed(Buffer.from(seed), "device:dev-uid-1");
  // What the session holds: the box's public half only, and a forgotten (all-zero) symmetric key.
  const box = k.sealOnlyBox(opener.id, opener.publicKey);
  const forgotten = { write: { key: Buffer.alloc(32), source: "device", id: "device:dev-uid-1:0000" }, read: () => null, keyFile: "/nonexistent" };
  const watch = startLoginWatch({ env: w.env, keys: forgotten, sealOptions: { box } });
  try {
    fs.writeFileSync(w.plain, LOGIN, { mode: 0o600 });
    const g = await waitGone(w.plain);
    assert.equal(g.gone, true);
    assert.ok(g.ms <= BOUND, `taken after ${g.ms} ms`);
    await watch.sweep();
  } finally {
    watch.close();
  }
  const p = pendingLogins(w.env);
  assert.deepEqual(p.map((x) => x.sealed), [true]);
  assert.ok(!fs.readFileSync(p[0].file, "utf8").includes(TOKEN));
  // It opens with the device's box (the next activation), not with the forgotten key.
  const m = k.unsealLoginToMemory({ sealedFile: p[0].file, keys: forgotten, deviceBound: true, label: "claude-code.login", box: opener });
  assert.equal(m.ok, true, m.message);
  assert.equal(JSON.parse(m.plain.toString("utf8")).claudeAiOauth.accessToken, TOKEN);
  k.discardPendingCredential(p[0].file);
  // No box and a forgotten key: the kit cannot seal (key-unavailable); the login is quarantined, never left.
  const w2 = world();
  await sealUnder(w2);
  const watch2 = startLoginWatch({ env: w2.env, keys: forgotten });
  try {
    fs.writeFileSync(w2.plain, LOGIN, { mode: 0o600 });
    assert.equal((await waitGone(w2.plain)).gone, true);
    await watch2.sweep();
  } finally {
    watch2.close();
  }
  assert.deepEqual(pendingLogins(w2.env).map((x) => x.sealed), [false]);
});

test("attack: a held login sealed under another device is not adopted", async () => {
  const w = world();
  await sealUnder(w);
  const other = await loginSealKeys({ env: { ...w.env, ENCLAWED_STATE_DIR: path.join(w.root, "other-state") }, k, device: standIn("device-secret-OTHER") });
  const dir = path.join(w.env.ENCLAWED_STATE_DIR, "claude-code", "credentials", "pending");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const planted = path.join(dir, "claude-code.login.2026-11-23T00-00-00-000Z.abcd1234.sealed.json");
  const tmp = path.join(w.root, "plant.json");
  fs.writeFileSync(tmp, LOGIN);
  assert.equal(k.sealLoginFile({ plainFile: tmp, sealedFile: planted, keys: other, deviceBound: true, label: "claude-code.login" }).ok, true);
  const before = fs.readFileSync(sealedLoginFile(w.env), "utf8");
  const r = await cmd(w, ["resolve", "--replace"]);
  assert.equal(r.code, 1);
  assert.match(r.err, /does not open with this Enclaweder/);
  assert.equal(fs.readFileSync(sealedLoginFile(w.env), "utf8"), before);
});

test("login new: a sign-in inside Enclawed Code is sealed under the device and never written in plaintext; a code from another sign-in seals nothing", async () => {
  const s = await startStandIns();
  const w = world();
  const signInForTest = { trustForTest: s.ca.certPem, addressForTest: { host: "127.0.0.1", port: s.tokPort } };
  let shown = "";
  const out = sink();
  const err = sink();
  const ctx = (paste) => ({
    out,
    err,
    env: w.env,
    k,
    hold: async () => ({ mode: "software-only", release() {} }),
    device: standIn(),
    readCode: async () => paste(new URL(shown.match(/https:\S+/)[0]).searchParams.get("state")),
    signInForTest,
  });
  out.write = (t) => ((shown += t), (out.text += t), true);
  assert.equal(await loginWatchCommand(["new"], ctx((state) => `good-code#not-${state}`)), 1);
  assert.equal(fs.existsSync(sealedLoginFile(w.env)), false);
  s.tokenCalls.length = 0;
  shown = "";
  assert.equal(await loginWatchCommand(["new"], ctx((state) => `good-code#${state}`)), 0, err.text);
  assert.equal(s.tokenCalls.length, 1);
  assert.equal(s.tokenCalls[0].client_id, CLAUDE_SIGN_IN.clientId);
  assert.equal(s.tokenCalls[0].redirect_uri, CLAUDE_SIGN_IN.redirectUri);
  const url = new URL(shown.match(/https:\S+/)[0]);
  assert.equal(`${url.origin}${url.pathname}`, CLAUDE_SIGN_IN.authorizeUrl);
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  const sealed = fs.readFileSync(sealedLoginFile(w.env), "utf8");
  assert.ok(!sealed.includes("NEW-SIGN-IN"));
  const keys = await loginSealKeys({ env: w.env, k, device: standIn() });
  const m = k.unsealLoginToMemory({ sealedFile: sealedLoginFile(w.env), keys, deviceBound: true, label: "claude-code.login" });
  assert.equal(m.ok, true);
  assert.equal(JSON.parse(m.plain.toString("utf8")).claudeAiOauth.accessToken, "sk-ant-oat01-NEW-SIGN-IN");
  // No plaintext login was written anywhere in this world.
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.isFile() ? [fs.readFileSync(path.join(d, e.name), "latin1")] : []));
  assert.ok(!walk(w.root).join("").includes("NEW-SIGN-IN"));
  // A sealed login is not replaced silently.
  assert.equal(await loginWatchCommand(["new"], ctx((state) => `good-code#${state}`)), 1);
});

test("the service: the unit runs the watcher and restarts it after a failure (a watcher that is not needed ends cleanly and stays ended); install writes it and enables it; no watcher is spawned by the suite without its stand-in", async () => {
  const w = world();
  assert.match(unitText(), /ExecStart=.*ecwctl\.mjs" login watch\nRestart=on-failure/);
  const calls = [];
  const r = await cmd(w, ["watch", "install"], { run: (bin, args) => (calls.push(args.join(" ")), { status: 0, stdout: "", stderr: "" }) });
  if (r.code === 1 && /systemctl was not found/.test(r.err)) {
    return; // no systemctl on this machine: the unit file is still written
  }
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(calls, ["--user daemon-reload", "--user enable --now enclawed-code-login-watch.service"]);
  assert.equal(fs.readFileSync(path.join(w.env.HOME, ".config", "systemd", "user", "enclawed-code-login-watch.service"), "utf8"), unitText());
  setTestAuthority({ ...policy });
  assert.deepEqual(ensureLoginWatcher({ env: w.env }), { started: false, running: false });
});

test("launch order: the watcher's sweep and the held-login refusal run inside the launch precheck, before the launch's activation (nothing spent); the launcher takes the precheck from login-watch.mjs", async () => {
  const src = fs.readFileSync(new URL("../src/launcher.mjs", import.meta.url), "utf8");
  assert.match(src, /import \{ loginLaunchPrecheck \} from "\.\/login-watch\.mjs";/);
  const body = src.slice(src.indexOf("export async function launchSession("));
  assert.ok(body.indexOf("loginLaunchPrecheck({") > 0 && body.indexOf("loginLaunchPrecheck({") < body.indexOf("await activateLaunch("));
  const w = world();
  await sealUnder(w);
  fs.writeFileSync(w.plain, LOGIN, { mode: 0o600 });
  const records = [];
  const shielded = { ...k, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) };
  const pre = loginLaunchPrecheck({ env: w.env, deviceBound: true, platform: "linux", k: shielded, audit: async (r) => records.push(r) });
  // Not plaintext-beside-seal: the plaintext was quarantined first, and the held login refuses.
  assert.equal(pre.code, "login-pending");
  assert.equal(fs.existsSync(w.plain), false);
  assert.deepEqual(pendingLogins(w.env).map((p) => p.sealed), [false]);
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(records.map((r) => r.type), ["claude-code.login.watch.quarantined"]);
  // Resolved: the precheck passes again.
  assert.equal((await cmd(w, ["resolve", "--discard"])).code, 0);
  assert.deepEqual(loginLaunchPrecheck({ env: w.env, deviceBound: true, platform: "linux", k: shielded }), { ok: true });
});

test("the watcher process ends when its state directory is removed or another watcher took it over (it never outlives what it watches for)", async () => {
  for (const how of ["state removed", "taken over"]) {
    const w = world();
    const started = Date.now();
    const done = cmd(w, ["watch"]);
    const pid = path.join(w.env.ENCLAWED_STATE_DIR, "claude-code", "login-watch.pid");
    while (!fs.existsSync(pid) && Date.now() - started < 10_000) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(fs.existsSync(pid), how);
    if (how === "state removed") {
      fs.rmSync(w.env.ENCLAWED_STATE_DIR, { recursive: true, force: true });
    } else {
      fs.writeFileSync(pid, JSON.stringify({ pid: process.pid + 1, start: "0" }));
    }
    const t0 = Date.now();
    const ended = await Promise.race([done, new Promise((r) => setTimeout(() => r(null), 8000))]);
    assert.ok(ended, `${how}: the watcher did not end`);
    assert.equal(ended.code, 0, how);
    assert.ok(Date.now() - t0 < 5000, `${how}: ended after ${Date.now() - t0} ms`);
  }
});

test("held copies of the person's own login (left by an earlier build), without the managed login policy: never a reason to refuse a launch, reported with how to erase them, erased by login resolve --discard; no watcher is started or installed, and the old watchers are named by doctor's check", async () => {
  const w = world();
  await sealUnder(w);
  // An earlier build quarantined the person's login (here: the same move, under the policy).
  fs.writeFileSync(w.plain, LOGIN, { mode: 0o600 });
  await sweepLogins({ env: w.env, guarded: true });
  assert.equal(pendingLogins(w.env).length, 1);
  // Now: no managed login policy.
  setTestAuthority({ managedSettingsDir: fs.mkdtempSync(path.join(sb.dir, "no-managed-")), trustedUids: sb.authority.trustedUids, ignoreUserNamespace: true });
  const shielded = { ...k, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) };
  assert.deepEqual(loginLaunchPrecheck({ env: w.env, deviceBound: true, platform: "linux", k: shielded }), { ok: true });
  assert.match(pendingNotice(w.env), /^1 copy of your own Claude Code login, taken by an earlier Enclawed Code build, is held in .*; they are not Enclawed Code's and are never used\. Erase them with: ecwctl login resolve --discard$/);
  // A person's new plain login is left alone, and no watcher is started.
  fs.writeFileSync(w.plain, LOGIN, { mode: 0o600 });
  await sweepLogins({ env: w.env });
  assert.equal(fs.readFileSync(w.plain, "utf8"), LOGIN);
  assert.equal(ensureLoginWatcher({ env: w.env }).notNeeded, true);
  const inst = await cmd(w, ["watch", "install"], { run: () => ({ status: 0, stdout: "", stderr: "" }) });
  assert.equal(inst.code, 1);
  assert.match(inst.err, /only for the managed login policy .*Nothing was installed/);
  const watchNow = await cmd(w, ["watch"]);
  assert.equal(watchNow.code, 0);
  assert.match(watchNow.out, /not needed/);
  // The cleanup.
  const d = await cmd(w, ["resolve", "--discard"]);
  assert.equal(d.code, 0, d.err);
  assert.equal(pendingLogins(w.env).length, 0);
  assert.equal(pendingNotice(w.env), null);
  assert.equal(fs.readFileSync(w.plain, "utf8"), LOGIN, "the person's live login is not among what is erased");
  // doctor's check for watchers of earlier builds (a stand-in /proc).
  const { strayWatchers } = await import("../src/login-watch.mjs");
  const proc = fs.mkdtempSync(path.join(sb.dir, "proc-"));
  const fake = (pid, argv) => {
    fs.mkdirSync(path.join(proc, String(pid)));
    fs.writeFileSync(path.join(proc, String(pid), "cmdline"), `${argv.join("\0")}\0`);
  };
  fake(4242, ["/usr/bin/node", "/home/me/old/bin/codenclawed.mjs", "codenclawed", "login", "watch"]);
  fake(4243, ["/usr/bin/node", path.join(sb.dir, "gone", "bin", "ecwctl.mjs"), "login", "watch"]);
  fake(4244, ["/usr/bin/node", "/usr/bin/other.mjs", "login", "watch"]);
  const found = strayWatchers(w.env, { procDir: proc, uid: null });
  assert.deepEqual(found.map((x) => [x.pid, x.why]), [
    [4242, "started by an earlier build (codenclawed / enclawde)"],
    [4243, "its program no longer exists"],
  ]);
});
