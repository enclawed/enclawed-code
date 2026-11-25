import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// Claude Code's login sealed at rest under the Enclaweder and held only in
// the launcher's memory behind the kit's auth relay (attack 6;
// src/login-seal.mjs over the kit's login-seal.ts and auth-relay.ts). Attack
// side: the copy at rest is ciphertext; no file and no environment variable of
// the session holds the token; claude gets a placeholder and an empty secure
// storage; credentials claude's environment brought are removed; an unlisted
// route never reaches the provider; memory other processes can read refuses;
// a plaintext login next to the sealed one, or two of them, refuse; a sealed
// login without its device refuses; a halt closes the relay and erases the
// sealed login; no device means no seal; a seal is not replaced silently.
// False-positive side: the seal command, a relayed request carries the real
// token, a rejected token is renewed and sealed again before use, the first
// launch with a device seals the one plaintext login, no device and no seal
// change nothing, macOS passes. The provider and its token endpoint are
// local https stand-ins.
//
// The kit's functions are not in the built framework bundle yet:
// LOGIN_SEAL_KIT names them built to JavaScript (esbuild a module exporting
// login-seal.ts, auth-relay.ts and containment/x509.ts createContainerCa);
// without it the test uses the bundle's, when it has them.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { after, before, test } from "node:test";
import { claudeCredentialLocations } from "../src/credentials.mjs";
import { containment, kit } from "../src/kit.mjs";
import { closeLoginForSession, loginCommand, loginSealKeys, openLoginForSession, plainLoginFiles, sealedLoginFile, sessionLoginFile } from "../src/login-seal.mjs";
import { setTestAuthority } from "../src/authority.mjs";
import { managedLoginPolicyAuthority, sandbox } from "./helpers.mjs";

const TOKEN = "sk-ant-oat01-login-seal-test-token-0123456789";
const LOGIN = JSON.stringify({ claudeAiOauth: { accessToken: TOKEN, refreshToken: `r-${TOKEN}`, expiresAt: Date.now() + 3600_000, scopes: ["user:inference"] } });
const standIn = (secret = "device-secret-A") => ({ uid: "dev-uid-1", sign: async (m) => createHash("sha512").update(secret).update(m).digest() });
const sink = () => {
  const o = { text: "", write: (s) => ((o.text += s), true) };
  return o;
};

let sb;
let k;
let n = 0;
before(async () => {
  sb = sandbox();
  let tsKit = null;
  if (process.env.LOGIN_SEAL_KIT) {
    tsKit = await import(path.resolve(process.env.LOGIN_SEAL_KIT));
  }
  // The test's stand-in provider certificate comes from the containment's CA helper.
  k = { ...kit, createContainerCa: containment.createContainerCa, ...(tsKit ?? {}) };
  // These tests seal the person's plaintext login: only under the administrator's managed login
  // policy (login-guard.mjs); test/person-login.test.mjs proves nothing of it happens without it.
  setTestAuthority(await managedLoginPolicyAuthority(sb));
});
after(() => {
  setTestAuthority(null);
  sb.cleanup();
});

/** A fresh HOME and state, with Claude Code's login at ~/.claude/.credentials.json when `login`. */
function world({ login = true, configDir = null } = {}) {
  const root = path.join(sb.dir, `w${++n}`);
  const home = path.join(root, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  const env = { ...sb.env, HOME: home, ENCLAWED_STATE_DIR: path.join(root, "state"), ...(configDir ? { CLAUDE_CONFIG_DIR: path.join(root, configDir) } : {}) };
  const plain = claudeCredentialLocations(env, "linux").file;
  if (login) {
    fs.mkdirSync(path.dirname(plain), { recursive: true });
    fs.writeFileSync(plain, LOGIN, { mode: 0o600 });
  }
  const sessionDir = path.join(root, "session");
  fs.mkdirSync(sessionDir, { mode: 0o700 });
  return { root, env, plain, sessionDir };
}

const seal = async (w, extra = []) => {
  const out = sink();
  const err = sink();
  const code = await loginCommand(["seal", ...extra], { out, err, env: w.env, k, device: standIn(), hold: async () => ({ mode: "software-only", release() {} }) });
  return { code, out: out.text, err: err.text };
};

test("the seal: plaintext erased, the copy at rest is ciphertext under the device key; an existing seal is not replaced silently", async (t) => {
  if (typeof k.sealLoginFile !== "function") {
    t.skip("the kit's login-seal functions are not available (set LOGIN_SEAL_KIT)");
    return;
  }
  const w = world();
  const r = await seal(w);
  assert.equal(r.code, 0, r.err);
  assert.equal(fs.existsSync(w.plain), false);
  const sealed = sealedLoginFile(w.env);
  assert.ok(sealed.startsWith(w.env.ENCLAWED_STATE_DIR));
  const text = fs.readFileSync(sealed, "utf8");
  assert.ok(!text.includes(TOKEN));
  assert.ok(!Buffer.from(JSON.parse(text).data, "base64").toString("latin1").includes(TOKEN));
  assert.match(JSON.parse(text).key, /^device:/);
  // Another login put back at the plain location does not replace the sealed one without --replace.
  fs.writeFileSync(w.plain, LOGIN.replace(TOKEN, "other"), { mode: 0o600 });
  const again = await seal(w);
  assert.equal(again.code, 1);
  assert.match(again.err, /already there.*--replace/);
  assert.equal(fs.readFileSync(sealed, "utf8"), text);
  assert.equal((await seal(w, ["--replace"])).code, 0);
  assert.notEqual(fs.readFileSync(sealed, "utf8"), text);
});

test("attack: no device bound, nothing is sealed and nothing changes", async (t) => {
  if (typeof k.sealLoginFile !== "function") {
    t.skip("kit not available");
    return;
  }
  const w = world();
  const out = sink();
  const err = sink();
  let released = false;
  const code = await loginCommand(["seal"], { out, err, env: w.env, k, hold: async () => ({ mode: "software-only", release: () => (released = true) }) });
  assert.equal(code, 1);
  assert.match(err.text, /no Enclaweder is bound/);
  assert.equal(released, true);
  assert.equal(fs.readFileSync(w.plain, "utf8"), LOGIN);
  assert.equal(fs.existsSync(sealedLoginFile(w.env)), false);
});

// ------------------------------------------------------------------ the relay
// A stand-in provider and token endpoint (https, their own CA), and the
// session's relay pointed at them. Claude's side is played by an https client
// over the socket that trusts only the CA the session gives claude.

const PROVIDER = "api.anthropic.com";
const TOKEN_HOST = "platform.claude.com";
let accepted = TOKEN;
const seenUp = [];
const tokenCalls = [];
/** The token endpoint refuses every refresh (a failed refresh). */
let tokenRefuses = false;
let standIns = null;
/** The relay credential of the last session opened (to check the token is dropped). */
let lastCredential = null;

async function startStandIns() {
  if (standIns) {
    return standIns;
  }
  const ca = k.createContainerCa("stand-in provider", [PROVIDER, TOKEN_HOST]);
  const up = https.createServer({ key: ca.leafFor(PROVIDER).keyPem, cert: ca.leafFor(PROVIDER).certPem }, (req, res) => {
    let b = "";
    req.on("data", (d) => (b += d));
    req.on("end", () => {
      seenUp.push({ url: req.url, authorization: req.headers.authorization ?? null, body: b });
      res.writeHead(req.headers.authorization === `Bearer ${accepted}` ? 200 : 401, { "content-type": "application/json" });
      res.end(req.headers.authorization === `Bearer ${accepted}` ? '{"ok":true}' : "{}");
    });
  });
  const tok = https.createServer({ key: ca.leafFor(TOKEN_HOST).keyPem, cert: ca.leafFor(TOKEN_HOST).certPem }, (req, res) => {
    let b = "";
    req.on("data", (d) => (b += d));
    req.on("end", () => {
      const j = JSON.parse(b);
      tokenCalls.push(j);
      if (tokenRefuses) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end("{}");
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: accepted, refresh_token: `${j.refresh_token}-next`, expires_in: 3600 }));
    });
  });
  const port = (s) => new Promise((r) => s.listen(0, "127.0.0.1", () => r(s.address().port)));
  standIns = { ca, up, tok, upPort: await port(up), tokPort: await port(tok) };
  return standIns;
}
after(async () => {
  if (standIns) {
    standIns.up.closeAllConnections();
    standIns.tok.closeAllConnections();
    standIns.up.close();
    standIns.tok.close();
  }
});

/** Open a session's login with the relay pointed at the stand-ins; `shielded` stands in for the kernel's answer. */
async function openRelayed(w, { shielded = true, device = standIn(), audit = async () => {} } = {}) {
  const s = await startStandIns();
  const keys = await loginSealKeys({ env: w.env, k, device });
  return openLoginForSession({
    audit,
    env: w.env,
    sessionDir: w.sessionDir,
    deviceBound: true,
    platform: "linux",
    k: { ...k, processMemoryShielded: () => ({ shielded, reason: shielded ? "stand-in: shielded" : "stand-in: kernel.yama.ptrace_scope=0" }), oauthRelayCredential: (o) => (lastCredential = k.oauthRelayCredential(o)) },
    keys,
    relayOptionsForTest: {
      relay: { upstreamTrustForTest: s.ca.certPem, upstreamAddressForTest: { host: "127.0.0.1", port: s.upPort } },
      credential: { trustForTest: s.ca.certPem, addressForTest: { host: "127.0.0.1", port: s.tokPort } },
    },
  });
}

/** What claude does: TLS for the provider's name over the socket, trusting the CA file it was given, with the placeholder. */
function asClaude(childEnv, path_ = "/v1/messages?beta=true") {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        socketPath: childEnv.ANTHROPIC_UNIX_SOCKET,
        servername: PROVIDER,
        host: PROVIDER,
        ca: fs.readFileSync(childEnv.NODE_EXTRA_CA_CERTS),
        method: "POST",
        path: path_,
        headers: { authorization: `Bearer ${childEnv.CLAUDE_CODE_OAUTH_TOKEN}`, "content-type": "application/json" },
        agent: false,
      },
      (res) => {
        let b = "";
        res.on("data", (d) => (b += d));
        res.on("end", () => resolve({ status: res.statusCode, body: b }));
      },
    );
    req.on("error", reject);
    req.end('{"model":"m"}');
  });
}

/** Every byte of the files under `dir`: the token must be in none of them. */
function bytesUnder(dir) {
  let out = "";
  const walk = (p) => {
    for (const e of fs.readdirSync(p, { withFileTypes: true })) {
      const q = path.join(p, e.name);
      if (e.isDirectory()) {
        walk(q);
      } else if (e.isFile()) {
        out += fs.readFileSync(q, "latin1");
      }
    }
  };
  walk(dir);
  return out;
}

test("a session: the login lives only in the launcher; claude gets a placeholder, the relay sends the real token; nothing on disk holds it", async (t) => {
  if (typeof k.startAuthRelay !== "function") {
    t.skip("the kit's relay is not available (set LOGIN_SEAL_KIT)");
    return;
  }
  const w = world();
  const login = await openRelayed(w, {});
  assert.equal(login.ok, true, login.message);
  assert.equal(login.action, "relayed");
  // The first launch with the device sealed the plaintext login and erased it.
  assert.equal(login.sealedNow, true);
  assert.equal(fs.existsSync(w.plain), false);
  const childEnv = login.applyEnv({ ...w.env, ANTHROPIC_API_KEY: "sk-other", ANTHROPIC_BASE_URL: "https://elsewhere.test", CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR: "3" });
  assert.equal(childEnv.CLAUDE_CODE_OAUTH_TOKEN, "ssh-placeholder");
  assert.equal(childEnv.ANTHROPIC_API_KEY, undefined);
  assert.equal(childEnv.ANTHROPIC_BASE_URL, undefined);
  assert.equal(childEnv.CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR, undefined);
  assert.equal(fs.statSync(childEnv.ANTHROPIC_UNIX_SOCKET).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(childEnv.ANTHROPIC_UNIX_SOCKET)).mode & 0o777, 0o700);
  // Claude's secure storage is an empty private directory: no login file is read or written.
  assert.equal(claudeCredentialLocations(childEnv, "linux").file, sessionLoginFile(w.sessionDir));
  assert.deepEqual(fs.readdirSync(path.dirname(sessionLoginFile(w.sessionDir))), []);
  // Nothing in the environment, and no file anywhere in this world, holds the token.
  assert.ok(!JSON.stringify(childEnv).includes(TOKEN));
  assert.ok(!bytesUnder(w.root).includes(TOKEN));
  seenUp.length = 0;
  const r = await asClaude(childEnv);
  assert.equal(r.status, 200, r.body);
  assert.deepEqual(seenUp.map((x) => x.authorization), [`Bearer ${TOKEN}`]);
  // A route not listed is refused and never reaches the provider.
  seenUp.length = 0;
  assert.equal((await asClaude(childEnv, "/api/oauth/claude_cli/create_api_key")).status, 403);
  assert.deepEqual(seenUp, []);
  assert.equal(lastCredential.current(), TOKEN);
  const end = await closeLoginForSession(login, { k });
  assert.equal(end.ok, true);
  // The token is dropped from the launcher's memory when the session ends.
  assert.equal(lastCredential.current(), null);
  assert.equal(fs.existsSync(childEnv.ANTHROPIC_UNIX_SOCKET), false);
  assert.equal(fs.existsSync(sealedLoginFile(w.env)), true);
});

test("refresh: a rejected token is renewed by the relay and sealed again before use; claude never sees it", async (t) => {
  if (typeof k.startAuthRelay !== "function") {
    t.skip("kit not available");
    return;
  }
  const w = world();
  const login = await openRelayed(w, {});
  assert.equal(login.ok, true, login.message);
  const childEnv = login.applyEnv(w.env);
  tokenCalls.length = 0;
  seenUp.length = 0;
  accepted = "renewed-access-token-SECRET-2";
  const r = await asClaude(childEnv);
  assert.equal(r.status, 200);
  assert.deepEqual(seenUp.map((x) => x.authorization), [`Bearer ${TOKEN}`, "Bearer renewed-access-token-SECRET-2"]);
  assert.equal(tokenCalls.length, 1);
  assert.equal(tokenCalls[0].client_id, "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
  assert.equal(tokenCalls[0].refresh_token, `r-${TOKEN}`);
  assert.ok(!r.body.includes("renewed"));
  assert.ok(!bytesUnder(w.root).includes("renewed-access-token"));
  await closeLoginForSession(login, { k });
  // The next session opens the renewed login (sealed by the relay).
  const keys = await loginSealKeys({ env: w.env, k, device: standIn() });
  const m = k.unsealLoginToMemory({ sealedFile: sealedLoginFile(w.env), keys, deviceBound: true, label: "claude-code.login" });
  const doc = JSON.parse(m.plain.toString("utf8"));
  assert.equal(doc.claudeAiOauth.accessToken, "renewed-access-token-SECRET-2");
  assert.equal(doc.claudeAiOauth.refreshToken, `r-${TOKEN}-next`);
  accepted = TOKEN;
});

test("halt: the relay is closed and the sealed login erased; memory other processes can read refuses; no login refuses", async (t) => {
  if (typeof k.startAuthRelay !== "function") {
    t.skip("kit not available");
    return;
  }
  const w = world();
  const login = await openRelayed(w, {});
  const childEnv = login.applyEnv(w.env);
  const h = await closeLoginForSession(login, { halted: true, k });
  assert.equal(h.ok, true);
  assert.equal(fs.existsSync(childEnv.ANTHROPIC_UNIX_SOCKET), false);
  assert.equal(fs.existsSync(sealedLoginFile(w.env)), false);
  await assert.rejects(asClaude(childEnv));
  // Yama off: the token would sit in readable memory; refused before anything is opened.
  const open = world();
  const r = await openRelayed(open, { shielded: false });
  assert.equal(r.code, "memory-not-shielded");
  assert.equal(fs.readFileSync(open.plain, "utf8"), LOGIN);
  // No login of its own: refused with how to sign in inside Enclawed Code.
  const none = world({ login: false });
  const n = await openRelayed(none, {});
  assert.equal(n.code, "no-login");
  assert.match(n.message, /Sign in once inside Enclawed Code: ecwctl login new/);
});

test("launch decisions: plaintext next to a device refused wherever this environment keeps it; a seal needs its device; no device and no seal, and macOS, pass", async (t) => {
  if (typeof k.sealLoginFile !== "function") {
    t.skip("kit not available");
    return;
  }
  const open = (w, deviceBound, platform = "linux") => openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound, platform, k, keys: { write: null, read: () => null, keyFile: "/nonexistent" } });
  // No device, no seal: nothing changes.
  const plainOnly = world();
  assert.deepEqual(await open(plainOnly, false), { ok: true, action: "pass" });
  // A device and one plaintext login (where CLAUDE_CONFIG_DIR puts it): sealed at the first launch, then relayed.
  const moved = world({ configDir: "cfg" });
  assert.ok(plainLoginFiles(moved.env).includes(moved.plain));
  const first = await openRelayed(moved, {});
  assert.equal(first.ok, true, first.message);
  assert.equal(first.sealedNow, true);
  assert.equal(fs.existsSync(moved.plain), false);
  assert.ok(!bytesUnder(moved.root).includes(TOKEN));
  await closeLoginForSession(first, { k });
  // Two plaintext logins (this environment's and the default): not guessed.
  const two = world({ configDir: "cfg" });
  fs.writeFileSync(path.join(two.env.HOME, ".claude", ".credentials.json"), LOGIN, { mode: 0o600 });
  assert.equal((await open(two, true)).code, "plaintext-unsealed");
  assert.equal(fs.existsSync(two.plain), true);
  // Sealed, then a copy put back next to it: refused, never adopted.
  const w = world();
  assert.equal((await seal(w)).code, 0);
  fs.writeFileSync(w.plain, LOGIN, { mode: 0o600 });
  const r2 = await open(w, true);
  assert.equal(r2.code, "plaintext-beside-seal");
  assert.equal(fs.existsSync(path.join(w.sessionDir, "claude-secure")), false);
  // A sealed login and no device: refused.
  fs.rmSync(w.plain);
  assert.equal((await open(w, false)).code, "device-required");
  // macOS keeps the login in the Keychain: the seal does not apply.
  assert.deepEqual(await open(w, true, "darwin"), { ok: true, action: "pass" });
});

/** A command set 0.5 stand-in: it proves 0.5 and derives a key per label (as KEY_DERIVE would, once per activation). */
const standIn05 = (secret = "device-secret-A") => {
  const d = standIn(secret);
  let derived = 0;
  return {
    ...d,
    derived: () => derived,
    keyDerivation: {
      pubkey: "ab".repeat(32),
      commandSet: async () => ({ status: "proven", commandSet: "0.5" }),
      derive: async (label) => {
        derived++;
        return { ok: true, key: createHash("sha256").update(`kd:${secret}`).update(label).digest(), binding: Buffer.alloc(32), facts: { kind: "totp", step: 1, counter: 1n } };
      },
    },
  };
};

test("command set 0.5: a login sealed under the CHALLENGE key is moved to the KEY_DERIVE key at launch, once, audited; the launch reports how its key was had", async (t) => {
  if (typeof k.startAuthRelay !== "function" || typeof k.migrateLegacyLoginSeal !== "function") {
    t.skip("kit not available");
    return;
  }
  k.forgetLaunchCredentialKeys();
  const w = world();
  // An earlier version sealed the login under the CHALLENGE-derived key (firmware before 0.5).
  const first = await openRelayed(w, {});
  t.after(() => closeLoginForSession(first, { k }));
  assert.equal(first.ok, true, first.message);
  assert.equal(first.keyDerivation, "challenge");
  assert.equal(first.residual, kit.KEY_DERIVE_RESIDUAL ?? first.residual);
  assert.ok(first.residual);
  await closeLoginForSession(first, { k });
  const before = JSON.parse(fs.readFileSync(sealedLoginFile(w.env), "utf8")).key;
  assert.match(before, /^device:[^:]+:[0-9a-f]{16}$/);
  // The device now proves 0.5: the launch derives the key, moves the login, and records the move.
  const records = [];
  const dev = standIn05();
  // Each launch has a fresh session directory (as the launcher makes one).
  const nextSession = () => {
    w.sessionDir = path.join(w.root, `session-${++n}`);
    fs.mkdirSync(w.sessionDir, { mode: 0o700 });
  };
  nextSession();
  const second = await openRelayed(w, { device: dev, audit: async (r) => records.push(r) });
  t.after(() => closeLoginForSession(second, { k }));
  assert.equal(second.ok, true, second.message);
  assert.equal(second.keyDerivation, "key-derive");
  assert.equal(second.residual, null);
  assert.equal(dev.derived(), 1);
  const after_ = JSON.parse(fs.readFileSync(sealedLoginFile(w.env), "utf8")).key;
  // Moved to the launch's login box (record v2): it opens only at the start of a launch.
  assert.match(after_, /^device:[^:]+:box:login:[0-9a-f]{16}$/);
  const moved = records.filter((r) => r.type === "claude-code.auth.login-seal.migrated");
  assert.equal(moved.length, 1);
  assert.deepEqual([moved[0].payload.from, moved[0].payload.to, moved[0].payload.fromKey, moved[0].payload.toKey], ["device-challenge", "device-key-derive", before, after_]);
  assert.ok(!JSON.stringify(records).includes(TOKEN));
  // The relay serves the moved login.
  seenUp.length = 0;
  assert.equal((await asClaude(second.applyEnv(w.env))).status, 200);
  assert.deepEqual(seenUp.map((x) => x.authorization), [`Bearer ${TOKEN}`]);
  await closeLoginForSession(second, { k });
  // Once only: the next launch (the same launch key) moves nothing.
  nextSession();
  const third = await openRelayed(w, { device: dev, audit: async (r) => records.push(r) });
  t.after(() => closeLoginForSession(third, { k }));
  assert.equal(third.ok, true, third.message);
  await closeLoginForSession(third, { k });
  assert.equal(records.filter((r) => r.type === "claude-code.auth.login-seal.migrated").length, 1);
  k.forgetLaunchCredentialKeys();
});

test("command set 0.5: with the root required, a device that does not prove 0.5 gives no key, and the login is not opened (never the CHALLENGE key)", async () => {
  k.forgetLaunchCredentialKeys();
  const w = world();
  const keys = await loginSealKeys({ env: w.env, k, device: standIn(), rootRequired: true });
  assert.notEqual(keys.write.source, "device");
  assert.match(keys.device.problem, /required/);
  const r = await openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound: true, platform: "linux", k: { ...k, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) }, keys });
  assert.equal(r.ok, false);
  assert.match(r.message, /required/);
  assert.equal(fs.existsSync(w.plain), true, "the plaintext login is left as it was");
});

test("refresh audit: every token refresh and failed refresh of the relay is a record of Enclawed Code's audit log, with no token material", async (t) => {
  if (typeof k.auditedAuthRelayEvents !== "function") {
    t.skip("kit not available");
    return;
  }
  const w = world();
  const records = [];
  const login = await openRelayed(w, { audit: async (r) => records.push(r) });
  assert.equal(login.ok, true, login.message);
  const childEnv = login.applyEnv(w.env);
  // Rejected: renewed (a refresh record).
  accepted = "renewed-access-token-SECRET-3";
  assert.equal((await asClaude(childEnv)).status, 200);
  // Rejected again, and the token endpoint refuses: a failed refresh record.
  accepted = "unreachable-access-token-SECRET-4";
  tokenRefuses = true;
  assert.equal((await asClaude(childEnv)).status, 401);
  tokenRefuses = false;
  accepted = TOKEN;
  const end = await closeLoginForSession(login, { k });
  assert.equal(end.ok, true, end.message);
  const relay = records.filter((r) => /auth\.relay\./.test(r.type));
  assert.deepEqual(relay.map((r) => `${r.type}:${r.payload.reason}:${r.payload.status}`), ["claude-code.auth.relay.token-refreshed:rejected:401", "claude-code.auth.relay.token-refresh-failed:rejected:401"]);
  for (const r of relay) {
    assert.equal(r.actor, "enclawed-code");
    assert.deepEqual(Object.keys(r.payload).sort(), ["method", "path", "reason", "status"]);
  }
  const all = JSON.stringify(records);
  for (const secret of [TOKEN, `r-${TOKEN}`, `r-${TOKEN}-next`, "renewed-access-token", "unreachable-access-token", "ssh-placeholder", "Bearer"]) {
    assert.ok(!all.includes(secret), `the audit holds ${secret}`);
  }
});


/** A command set 0.5 stand-in that answers KEY_DERIVE once per activation the test grants, as the device does. */
const gated05 = (secret = "device-secret-G") => {
  let grants = 0;
  return {
    uid: "dev-uid-g",
    sign: async () => {
      throw new Error("CHALLENGE is never used on command set 0.5");
    },
    activate: () => void grants++,
    keyDerivation: {
      pubkey: "cd".repeat(32),
      commandSet: async () => ({ status: "proven", commandSet: "0.5" }),
      derive: async (label) => {
        if (grants === 0) {
          return { ok: false, code: "no-activation" };
        }
        grants--;
        return { ok: true, key: createHash("sha256").update(`kd:${secret}`).update(label).digest(), binding: Buffer.alloc(32), facts: { kind: "totp", step: 1, counter: 1n } };
      },
    },
  };
};

test("the login box: the login is sealed to the launch's login box (record v2); after the launch forgets its keys nothing opens it; the next activated launch does", async (t) => {
  if (typeof k.boxRefreshVault !== "function") {
    t.skip("kit not available");
    return;
  }
  k.forgetLaunchCredentialKeys();
  const w = world();
  const dev = gated05();
  dev.activate();
  const records = [];
  const s = await startStandIns();
  const open = async (extra = {}) => {
    const keys = await loginSealKeys({ env: w.env, k, device: dev, rootRequired: extra.rootRequired ?? false });
    return openLoginForSession({
      audit: async (r) => records.push(r),
      env: w.env,
      sessionDir: w.sessionDir,
      deviceBound: true,
      platform: "linux",
      rootRequired: extra.rootRequired ?? false,
      reactivate: extra.reactivate ?? null,
      k: { ...k, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }), frameworkCredentialKeyDevice: () => dev },
      keys,
      relayOptionsForTest: {
        relay: { upstreamTrustForTest: s.ca.certPem, upstreamAddressForTest: { host: "127.0.0.1", port: s.upPort } },
        credential: { trustForTest: s.ca.certPem, addressForTest: { host: "127.0.0.1", port: s.tokPort } },
      },
    });
  };
  const first = await open();
  t.after(() => closeLoginForSession(first, { k }));
  assert.equal(first.ok, true, first.message);
  const rec = JSON.parse(fs.readFileSync(sealedLoginFile(w.env), "utf8"));
  assert.equal(rec.v, 2);
  assert.equal(rec.key, first.box.id);
  // The launcher forgets its keys after the start: the sealed login opens for nothing in this process.
  k.forgetLaunchCredentialKeys();
  assert.equal(first.box.canOpen(), false);
  assert.equal(k.unsealLoginToMemory({ sealedFile: sealedLoginFile(w.env), keys: first.keys, deviceBound: true, label: "claude-code.login", box: first.box }).ok, false);
  await closeLoginForSession(first, { k });
  // A launch without an activation: no box, nothing opens.
  w.sessionDir = path.join(w.root, `session-${++n}`);
  fs.mkdirSync(w.sessionDir, { mode: 0o700 });
  const none = await open();
  assert.equal(none.ok, false);
  // The next activated launch opens it.
  dev.activate();
  const second = await open();
  t.after(() => closeLoginForSession(second, { k }));
  assert.equal(second.ok, true, second.message);
  await closeLoginForSession(second, { k });
  k.forgetLaunchCredentialKeys();
});

test("root required: the refresh token is not held in memory; a refresh opens it only after a new device-verified activation, and without one nothing reaches the token endpoint", async (t) => {
  if (typeof k.boxRefreshVault !== "function") {
    t.skip("kit not available");
    return;
  }
  k.forgetLaunchCredentialKeys();
  const w = world();
  const dev = gated05("device-secret-V");
  dev.activate();
  const s = await startStandIns();
  let allow = false;
  let asked = 0;
  const keys = await loginSealKeys({ env: w.env, k, device: dev, rootRequired: true });
  const login = await openLoginForSession({
    env: w.env,
    sessionDir: w.sessionDir,
    deviceBound: true,
    platform: "linux",
    rootRequired: true,
    reactivate: async () => {
      asked++;
      if (allow) {
        dev.activate();
      }
      return allow;
    },
    k: { ...k, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }), frameworkCredentialKeyDevice: () => dev },
    keys,
    relayOptionsForTest: {
      relay: { upstreamTrustForTest: s.ca.certPem, upstreamAddressForTest: { host: "127.0.0.1", port: s.upPort } },
      credential: { trustForTest: s.ca.certPem, addressForTest: { host: "127.0.0.1", port: s.tokPort } },
    },
  });
  t.after(() => closeLoginForSession(login, { k }));
  assert.equal(login.ok, true, login.message);
  assert.equal(login.refreshVaulted, true);
  k.forgetLaunchCredentialKeys();
  const childEnv = login.applyEnv(w.env);
  // The provider rejects the token: without an activation the refresh is not made.
  tokenCalls.length = 0;
  accepted = "rotated-access-token-SECRET-9";
  assert.equal((await asClaude(childEnv)).status, 401);
  assert.equal(tokenCalls.length, 0);
  assert.equal(asked, 1);
  // With one: the refresh token is opened for this refresh and the request succeeds.
  allow = true;
  assert.equal((await asClaude(childEnv)).status, 200);
  assert.equal(tokenCalls.length, 1);
  assert.equal(tokenCalls[0].refresh_token, `r-${TOKEN}`);
  accepted = TOKEN;
  await closeLoginForSession(login, { k });
  k.forgetLaunchCredentialKeys();
});

// ------------------------------------------------------------------ the person's own login (no managed login policy)

test("without the managed login policy the person's own Claude Code login is untouched: at launch, by a /login inside the session (it lands in the session's storage and becomes Enclawed Code's sealed login), by the watcher and the sweep, and at a halt", async (t) => {
  if (typeof k.startAuthRelay !== "function") {
    t.skip("kit not available");
    return;
  }
  const policyAuthority = await managedLoginPolicyAuthority(sb);
  const noPolicy = fs.mkdtempSync(path.join(sb.dir, "no-managed-"));
  setTestAuthority({ managedSettingsDir: noPolicy, trustedUids: sb.authority.trustedUids, ignoreUserNamespace: true });
  try {
    const { personLoginGuarded } = await import("../src/login-guard.mjs");
    assert.equal(personLoginGuarded(), false);
    const w = world(); // the person's own plain login at ~/.claude/.credentials.json
    const mine = fs.readFileSync(w.plain, "utf8");
    const untouched = (when) => assert.equal(fs.existsSync(w.plain) && fs.readFileSync(w.plain, "utf8"), mine, `the person's login was touched ${when}`);
    // No login of Enclawed Code's own yet: refused with how to sign in inside Enclawed Code; the person's login is not adopted.
    const none = await openRelayed(w, {});
    assert.equal(none.code, "no-login");
    assert.match(none.message, /your own Claude Code login is not used or touched\). Sign in once inside Enclawed Code: ecwctl login new/);
    untouched("by a launch with no login of its own");
    assert.equal(fs.existsSync(sealedLoginFile(w.env)), false);
    // Enclawed Code's own login, sealed under the device (as `ecwctl login new` leaves it).
    const ownFile = path.join(w.root, "own-login.json");
    const OWN = LOGIN.replace(TOKEN, `${TOKEN}-own`);
    fs.writeFileSync(ownFile, OWN, { mode: 0o600 });
    const keys = await loginSealKeys({ env: w.env, k, device: standIn() });
    assert.equal(k.sealLoginFile({ plainFile: ownFile, sealedFile: sealedLoginFile(w.env), keys, deviceBound: true, label: "claude-code.login" }).ok, true);
    // The launch: the person's login beside the sealed one is neither refused nor taken.
    const { loginLaunchPrecheck: precheck } = await import("../src/login-watch.mjs");
    assert.equal(precheck({ env: w.env, deviceBound: true, platform: "linux", k: { ...k, processMemoryShielded: () => ({ shielded: true }) } }).ok, true);
    const records = [];
    const s1 = await openRelayed(w, { audit: async (r) => records.push(r) });
    assert.equal(s1.action, "relayed", s1.message);
    untouched("at launch");
    // A /login inside the session: Claude Code writes `.credentials.json` in CLAUDE_SECURESTORAGE_CONFIG_DIR
    // (else CLAUDE_CONFIG_DIR, else ~/.claude), which the session points at its own storage.
    const childEnv = s1.applyEnv(w.env);
    const loginTarget = claudeCredentialLocations(childEnv, "linux").file;
    assert.equal(loginTarget, s1.sessionFile);
    const NEW = LOGIN.replace(TOKEN, `${TOKEN}-session-login`);
    fs.writeFileSync(`${loginTarget}.tmp.1`, NEW, { mode: 0o600 });
    fs.renameSync(`${loginTarget}.tmp.1`, loginTarget);
    // ... while the person's plain claude refreshes its own token (a rewrite, as Claude Code writes it).
    fs.writeFileSync(`${w.plain}.tmp.2`, mine, { mode: 0o600 });
    fs.renameSync(`${w.plain}.tmp.2`, w.plain);
    const { startLoginWatch, sweepLogins, pendingLogins } = await import("../src/login-watch.mjs");
    const watch = startLoginWatch({ env: w.env, keys });
    await new Promise((r) => setTimeout(r, k.CREDENTIAL_WATCH_BOUND_MS * 2));
    await watch.sweep();
    watch.close();
    await sweepLogins({ env: w.env });
    untouched("by the watcher and the sweep");
    assert.equal(pendingLogins(w.env).length, 0);
    // The session ends: its /login is Enclawed Code's sealed login now; the person's login is untouched.
    const end = await closeLoginForSession(s1, { k, audit: async (r) => records.push(r) });
    assert.equal(end.ok, true, end.message);
    assert.match(end.message, /the login made inside the session is now Enclawed Code's sealed login/);
    assert.equal(fs.existsSync(loginTarget), false);
    const m = k.unsealLoginToMemory({ sealedFile: sealedLoginFile(w.env), keys: await loginSealKeys({ env: w.env, k, device: standIn() }), deviceBound: true, label: "claude-code.login", box: s1.box ?? undefined });
    assert.equal(m.ok, true);
    assert.ok(m.plain.toString("utf8").includes("-session-login"));
    m.plain.fill(0);
    assert.ok(records.some((r) => r.type === "claude-code.login.session-login-sealed" && r.payload.ok === true));
    untouched("at the end of the session");
    // A halt: Enclawed Code's sealed login and the session's storage go; the person's login stays.
    w.sessionDir = path.join(w.root, "session-2");
    fs.mkdirSync(w.sessionDir, { mode: 0o700 });
    const s2 = await openRelayed(w, {});
    assert.equal(s2.action, "relayed", s2.message);
    const h = await closeLoginForSession(s2, { halted: true, k });
    assert.equal(h.ok, true);
    assert.equal(fs.existsSync(sealedLoginFile(w.env)), false);
    untouched("at a halt");
    // The control: under the administrator's managed login policy the same plain login IS taken by the sweep.
    setTestAuthority(policyAuthority);
    fs.writeFileSync(sealedLoginFile(w.env), "{}", { mode: 0o600 });
    await sweepLogins({ env: w.env });
    assert.equal(fs.existsSync(w.plain), false, "under the managed login policy the sweep takes a plaintext login");
    assert.equal(pendingLogins(w.env).length, 1);
  } finally {
    setTestAuthority(await managedLoginPolicyAuthority(sb));
  }
});
