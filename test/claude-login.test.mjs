import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// How Claude Code's sessions authenticate under Enclawed Code (src/claude-login.mjs).
//
// For Claude subscription logins, Enclawed Code follows Anthropic's terms: the
// login stays with Claude Code, signed in through Anthropic's own flow, and
// Enclawed Code never collects, stores, seals, opens, reads, relays or moves it.
// An API key (the customer's own key management) may be sealed under the
// Enclaweder and served through the kit's auth relay.
//
// Attack side: a subscription token is never sealed (`login api-key` refuses
// it before any device step), and never read as a credential or relayed, even
// when placed where the sealed store is (in plaintext, sealed under the API key
// label, or sealed under an earlier build's label): the launch is refused and
// the provider sees nothing; Enclawed Code opens no file of Claude Code's login
// storage; an earlier build's stored login is erased without being opened; the
// relayed key is in no file and no variable of the session.
// False-positive side: a sealed API key is relayed (x-api-key) and dropped at
// the end; without a device nothing changes; with a device and no key, the
// session uses Claude Code's own login in Enclawed Code's login directory.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { after, before, test } from "node:test";
import { claudeCredentialLocations } from "../src/credentials.mjs";
import { containment, kit } from "../src/kit.mjs";
import {
  API_KEY_LABEL,
  claudeLoginDir,
  closeLoginForSession,
  credentialKind,
  legacySubscriptionStores,
  loginCommand,
  loginSealKeys,
  openLoginForSession,
  sealedApiKeyFile,
} from "../src/claude-login.mjs";
import { readsUnder } from "../src/conformance-login.mjs";
import { sandbox } from "./helpers.mjs";

const API_KEY = `sk-ant-api03-${"Kq7".repeat(30)}-AbCdEfAA`;
const OAUTH = "sk-ant-oat01-subscription-token-never-relayed-0123456789";
const SUBSCRIPTION_DOC = JSON.stringify({ claudeAiOauth: { accessToken: OAUTH, refreshToken: "sk-ant-ort01-never", expiresAt: 4102444800000, scopes: ["user:inference"] } });
const standIn = (secret = "device-secret-A") => ({ uid: "dev-uid-1", sign: async (m) => createHash("sha512").update(secret).update(m).digest() });
const sink = () => {
  const o = { text: "", write: (s) => ((o.text += s), true) };
  return o;
};
const shielded = { ...kit, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) };

let sb;
let n = 0;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());

/** A fresh HOME and state; the person's own Claude Code login at ~/.claude/.credentials.json. */
function world() {
  const root = path.join(sb.dir, `w${++n}`);
  const home = path.join(root, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  const env = { ...sb.env, HOME: home, ENCLAWED_STATE_DIR: path.join(root, "state") };
  const person = claudeCredentialLocations(env, "linux").file;
  fs.writeFileSync(person, SUBSCRIPTION_DOC, { mode: 0o600 });
  const sessionDir = path.join(root, "session");
  fs.mkdirSync(sessionDir, { mode: 0o700 });
  return { root, env, person, sessionDir };
}

async function sealKey(w, secret, extra = []) {
  const out = sink();
  const err = sink();
  const code = await loginCommand(["api-key", ...extra], { out, err, env: w.env, k: kit, device: standIn(), platform: "linux", readSecret: async () => secret, hold: async () => ({ mode: "software-only", release() {} }) });
  return { code, out: out.text, err: err.text };
}

// A stand-in provider (https, its own CA); Claude's side is an https client over the relay's socket.
const PROVIDER = "api.anthropic.com";
const seenUp = [];
let standIns = null;
async function provider() {
  if (standIns) {
    return standIns;
  }
  const ca = containment.createContainerCa("stand-in provider", [PROVIDER]);
  const up = https.createServer({ key: ca.leafFor(PROVIDER).keyPem, cert: ca.leafFor(PROVIDER).certPem }, (req, res) => {
    let b = "";
    req.on("data", (d) => (b += d));
    req.on("end", () => {
      seenUp.push({ url: req.url, authorization: req.headers.authorization ?? null, apiKey: req.headers["x-api-key"] ?? null, body: b });
      const ok = req.headers["x-api-key"] === API_KEY && !req.headers.authorization;
      res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
      res.end(ok ? '{"ok":true}' : "{}");
    });
  });
  const port = await new Promise((r) => up.listen(0, "127.0.0.1", () => r(up.address().port)));
  standIns = { ca, up, port };
  return standIns;
}
after(() => {
  if (standIns) {
    standIns.up.closeAllConnections();
    standIns.up.close();
  }
});

async function open(w, { k = shielded } = {}) {
  const s = await provider();
  const keys = await loginSealKeys({ env: w.env, k: kit, device: standIn() });
  return openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound: true, platform: "linux", k, keys, relayOptionsForTest: { relay: { upstreamTrustForTest: s.ca.certPem, upstreamAddressForTest: { host: "127.0.0.1", port: s.port } } } });
}

function asClaude(childEnv, p = "/v1/messages?beta=true") {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        socketPath: childEnv.ANTHROPIC_UNIX_SOCKET,
        servername: PROVIDER,
        host: PROVIDER,
        ca: fs.readFileSync(childEnv.NODE_EXTRA_CA_CERTS),
        method: "POST",
        path: p,
        headers: { authorization: `Bearer ${childEnv.CLAUDE_CODE_OAUTH_TOKEN}`, "anthropic-version": "2023-06-01", "content-type": "application/json" },
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

test("credentialKind: only Anthropic's API key format is an API key; OAuth tokens, a login document and anything else are a subscription credential", () => {
  assert.equal(credentialKind(API_KEY), "api-key");
  for (const x of [OAUTH, "sk-ant-ort01-abcdefghijklmnopqrstuvwxyz", SUBSCRIPTION_DOC, "sk-ant-api03-short", `${API_KEY} `, `x${API_KEY}`, "", null, undefined, 42, { apiKey: API_KEY }]) {
    assert.equal(credentialKind(x), "subscription", String(x));
  }
});

test("login api-key: a subscription token is refused before any device step and nothing is written; an API key is sealed under the device (ciphertext only), --replace and --remove", async () => {
  const w = world();
  let held = false;
  const r = await loginCommand(["api-key"], { out: sink(), err: sink(), env: w.env, platform: "linux", readSecret: async () => OAUTH, hold: async () => ((held = true), { mode: "software-only", release() {} }) });
  assert.equal(r, 1);
  assert.equal(held, false);
  assert.equal(fs.existsSync(sealedApiKeyFile(w.env)), false);
  const bad = await sealKey(w, SUBSCRIPTION_DOC);
  assert.equal(bad.code, 1);
  assert.match(bad.err, /not an Anthropic API key .* Claude subscription logins are never stored by Enclawed Code: sign in with \/login inside a session/);
  const ok = await sealKey(w, API_KEY);
  assert.equal(ok.code, 0, ok.err);
  assert.ok(fs.existsSync(sealedApiKeyFile(w.env)));
  assert.ok(!fs.readFileSync(sealedApiKeyFile(w.env), "latin1").includes(API_KEY), "the key at rest is ciphertext");
  assert.equal((await sealKey(w, API_KEY)).code, 1, "an existing key is not replaced silently");
  assert.equal((await sealKey(w, API_KEY, ["--replace"])).code, 0);
  // No device bound: nothing sealed.
  const w2 = world();
  const none = await loginCommand(["api-key"], { out: sink(), err: sink(), env: w2.env, platform: "linux", readSecret: async () => API_KEY, hold: async () => ({ mode: "software-only", release() {} }) });
  assert.equal(none, 1);
  assert.equal(fs.existsSync(sealedApiKeyFile(w2.env)), false);
  const rm = await loginCommand(["api-key", "--remove"], { out: sink(), err: sink(), env: w.env, platform: "linux" });
  assert.equal(rm, 0);
  assert.equal(fs.existsSync(sealedApiKeyFile(w.env)), false);
  // The person's own Claude Code login was never touched.
  assert.equal(fs.readFileSync(w.person, "utf8"), SUBSCRIPTION_DOC);
});

test("a sealed API key is relayed: claude holds a placeholder, the provider gets x-api-key with the key and no authorization; nothing on disk or in the environment holds it; dropped at the end", async () => {
  const w = world();
  assert.equal((await sealKey(w, API_KEY)).code, 0);
  const login = await open(w);
  assert.equal(login.ok, true, login.message);
  assert.equal(login.action, "relayed");
  const childEnv = login.applyEnv({ ...w.env, ANTHROPIC_API_KEY: "sk-other", ANTHROPIC_BASE_URL: "https://elsewhere.test", CLAUDE_CODE_USE_BEDROCK: "1" });
  assert.equal(childEnv.CLAUDE_CODE_OAUTH_TOKEN, "ssh-placeholder");
  assert.equal(childEnv.ANTHROPIC_API_KEY, undefined);
  assert.equal(childEnv.ANTHROPIC_BASE_URL, undefined);
  assert.equal(childEnv.CLAUDE_CODE_USE_BEDROCK, undefined);
  assert.equal(childEnv.CLAUDE_SECURESTORAGE_CONFIG_DIR, claudeLoginDir(w.env));
  assert.ok(!JSON.stringify(childEnv).includes(API_KEY));
  assert.ok(!bytesUnder(w.root).includes(API_KEY));
  seenUp.length = 0;
  const r = await asClaude(childEnv);
  assert.equal(r.status, 200, r.body);
  assert.deepEqual(seenUp.map((x) => [x.apiKey, x.authorization]), [[API_KEY, null]]);
  // An unlisted route never reaches the provider.
  seenUp.length = 0;
  assert.equal((await asClaude(childEnv, "/api/oauth/claude_cli/create_api_key")).status, 403);
  assert.deepEqual(seenUp, []);
  assert.equal(login.credential.current(), API_KEY);
  const end = await closeLoginForSession(login, { k: kit });
  assert.equal(end.ok, true);
  assert.equal(login.credential.current(), null, "the key is dropped from memory");
  assert.equal(fs.existsSync(childEnv.ANTHROPIC_UNIX_SOCKET), false);
  assert.ok(fs.existsSync(sealedApiKeyFile(w.env)), "the sealed key is kept between sessions");
  // A halt erases the sealed API key too.
  // The next launch (a fresh session directory) halts.
  w.sessionDir = path.join(w.root, "session-2");
  fs.mkdirSync(w.sessionDir, { mode: 0o700 });
  const again = await open(w);
  assert.equal(again.ok, true, again.message);
  const h = await closeLoginForSession(again, { halted: true, k: kit, platform: "linux" });
  assert.equal(h.ok, true, JSON.stringify(h));
  assert.equal(fs.existsSync(sealedApiKeyFile(w.env)), false);
  assert.ok(h.erased.includes(`sealed API key ${sealedApiKeyFile(w.env)}`));
});

test("attack: a subscription token placed where the sealed store is (plaintext, sealed under the API key label, or under an earlier build's label) is never relayed: the launch is refused and the provider sees nothing", async () => {
  const cases = [
    ["plaintext login document", (w) => fs.writeFileSync(sealedApiKeyFile(w.env), SUBSCRIPTION_DOC, { mode: 0o600 })],
    [
      "an OAuth token sealed under the API key label",
      async (w, keys) => {
        const bytes = Buffer.from(JSON.stringify({ kind: "anthropic-api-key", apiKey: OAUTH }), "utf8");
        assert.equal(kit.sealLoginBytes({ plain: bytes, sealedFile: sealedApiKeyFile(w.env), keys, deviceBound: true, label: API_KEY_LABEL }).ok, true);
      },
    ],
    [
      "a login document sealed under an earlier build's login label",
      async (w, keys) => {
        assert.equal(kit.sealLoginBytes({ plain: Buffer.from(SUBSCRIPTION_DOC), sealedFile: sealedApiKeyFile(w.env), keys, deviceBound: true, label: "claude-code.login" }).ok, true);
      },
    ],
  ];
  for (const [what, plant] of cases) {
    const w = world();
    fs.mkdirSync(path.dirname(sealedApiKeyFile(w.env)), { recursive: true, mode: 0o700 });
    await plant(w, await loginSealKeys({ env: w.env, k: kit, device: standIn() }));
    seenUp.length = 0;
    const login = await open(w);
    assert.equal(login.ok, false, what);
    assert.match(login.message, /not hold an Anthropic API key|cannot be opened/, what);
    assert.equal(login.relay, undefined, what);
    assert.deepEqual(seenUp, [], what);
    assert.equal(fs.readFileSync(w.person, "utf8"), SUBSCRIPTION_DOC, what);
  }
});

test("with a device and no API key: the session uses Claude Code's own login in Enclawed Code's login directory; no relay, no credential variable; no file of Claude Code's login storage is opened; without a device nothing changes", async () => {
  const w = world();
  const loginDir = claudeLoginDir(w.env);
  // Claude Code's own /login in an earlier session left its credential there.
  fs.mkdirSync(loginDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(loginDir, ".credentials.json"), SUBSCRIPTION_DOC, { mode: 0o600 });
  const { result: login, reads } = await readsUnder([loginDir, path.dirname(w.person)], () => open(w));
  assert.equal(login.ok, true, login.message);
  assert.equal(login.action, "own-login");
  assert.deepEqual(reads, []);
  const childEnv = login.applyEnv({ ...w.env, ANTHROPIC_API_KEY: "sk-ant-api03-the-persons-own-env-key-xxxxxxxxxxxx" });
  assert.equal(childEnv.CLAUDE_SECURESTORAGE_CONFIG_DIR, loginDir);
  assert.equal(childEnv.ANTHROPIC_UNIX_SOCKET, undefined);
  assert.equal(childEnv.CLAUDE_CODE_OAUTH_TOKEN, undefined);
  // The person's own environment credentials are passed through unchanged (their own key management).
  assert.equal(childEnv.ANTHROPIC_API_KEY, "sk-ant-api03-the-persons-own-env-key-xxxxxxxxxxxx");
  const end = await closeLoginForSession(login, { k: kit });
  assert.equal(end.ok, true);
  assert.equal(fs.readFileSync(path.join(loginDir, ".credentials.json"), "utf8"), SUBSCRIPTION_DOC, "kept between sessions");
  // No device: nothing changes.
  const pass = await openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound: false, platform: "linux" });
  assert.deepEqual(pass, { ok: true, action: "pass" });
  assert.equal(fs.readFileSync(w.person, "utf8"), SUBSCRIPTION_DOC);
});

test("an earlier build's stored subscription login (sealed, or held in pending) is erased without being opened", async () => {
  const w = world();
  const [sealed, pending] = legacySubscriptionStores(w.env);
  fs.mkdirSync(pending, { recursive: true });
  fs.writeFileSync(sealed, '{"v":1,"kind":"enclawed.adapter.login-seal.v1","label":"claude-code.login"}');
  fs.writeFileSync(path.join(pending, "1.quarantined.json"), SUBSCRIPTION_DOC);
  const records = [];
  const { result: login, reads } = await readsUnder([path.dirname(sealed)], () => openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound: true, platform: "linux", k: shielded, keys: { write: null, read: () => null, device: { boxes: null } }, audit: async (r) => records.push(r) }));
  assert.equal(login.ok, true, login.message);
  assert.deepEqual(reads, []);
  assert.equal(fs.existsSync(sealed), false);
  assert.equal(fs.existsSync(pending), false);
  assert.match(login.notice, /erased without being opened/);
  assert.ok(records.some((r) => r.type === "claude-code.login.legacy-erased"));
});
