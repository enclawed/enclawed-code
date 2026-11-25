// Runs inside a private mount and network namespace made by
// test/managed-login.test.mjs (its own /etc overlay, so /etc/claude-code is
// this namespace's; api.anthropic.com and platform.claude.com resolve to
// 127.0.0.1, where a stand-in provider listens). Drives the REAL Claude Code
// binary in an isolated HOME holding a planted plaintext login:
//   1. control: plain `claude -p` with no managed policy uses the planted login;
//   2. ecwctl managed login-policy install (as root of this namespace);
//   3. plain claude, and the ways a user would try around it: refused, the
//      planted login never sent;
//   4. an Enclawed Code session (the launcher's login with the relay, a
//      stand-in Enclaweder) under the same policy: claude answers, the relay
//      adds the login.
// Prints one JSON document with what was observed.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import tls from "node:tls";

const [claude, work] = process.argv.slice(2);
const { setTestAuthority } = await import("../../src/authority.mjs");
// The kernel's ownership is this namespace's (root here is the suite's user): the kit's rules, the suite's stand-in for root.
setTestAuthority({ trustedUids: [0, 65534], ignoreUserNamespace: true });
const { containment, kit } = await import("../../src/kit.mjs");
const { loginPolicyCommand, managedLoginPolicyStatus, loginPolicySpec } = await import("../../src/managed-login.mjs");
const { openLoginForSession, closeLoginForSession } = await import("../../src/login-watch.mjs");
const { loginSealKeys } = await import("../../src/login-seal.mjs");

const REAL = "sk-ant-oat01-PLANTED-REAL-LOGIN-0123456789";
const NAMES = ["api.anthropic.com", "platform.claude.com", "claude.ai", "claude.com", "statsig.anthropic.com", "mcp-proxy.anthropic.com"];
const ca = containment.createContainerCa("stand-in provider", NAMES);
const caFile = path.join(work, "ca.pem");
fs.writeFileSync(caFile, ca.certPem);
const contexts = Object.fromEntries(NAMES.map((n) => [n, tls.createSecureContext({ key: ca.leafFor(n).keyPem, cert: ca.leafFor(n).certPem })]));
const seen = [];
let accept = /PLANTED-REAL-LOGIN/;
const handler = (via) => (req, res) => {
  let b = "";
  req.on("data", (d) => (b += d));
  req.on("end", () => {
    const cred = `${req.headers.authorization ?? ""} ${req.headers["x-api-key"] ?? ""}`;
    seen.push({ via, url: req.url, cred });
    const json = (status, o) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(o));
    };
    if (req.url.startsWith("/v1/oauth/token")) {
      return json(200, { access_token: "sk-ant-oat01-NEW-LOGIN-FROM-PLAIN-CLAUDE", refresh_token: "sk-ant-ort01-NEW", expires_in: 3600, scope: "user:inference user:profile", account: { uuid: "11111111-1111-4111-8111-111111111111", email_address: "person@example.test" }, organization: { uuid: "22222222-2222-4222-8222-222222222222" } });
    }
    if (req.url.startsWith("/api/oauth/profile")) {
      return json(200, { account: { uuid: "11111111-1111-4111-8111-111111111111", email: "person@example.test", display_name: "P" }, organization: { uuid: "22222222-2222-4222-8222-222222222222", organization_type: "claude_max", rate_limit_tier: "default_claude_max_20x" } });
    }
    if (req.url.startsWith("/v1/messages") && !req.url.includes("count_tokens")) {
      if (!accept.test(cred)) {
        return json(401, { type: "error", error: { type: "authentication_error", message: "invalid credential" } });
      }
      res.writeHead(200, { "content-type": "text/event-stream" });
      const ev = (t, d) => res.write(`event: ${t}\ndata: ${JSON.stringify({ type: t, ...d })}\n\n`);
      ev("message_start", { message: { id: "msg_1", type: "message", role: "assistant", model: "claude-sonnet-4-6", content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } });
      ev("content_block_start", { index: 0, content_block: { type: "text", text: "" } });
      ev("content_block_delta", { index: 0, delta: { type: "text_delta", text: "STANDIN-ANSWER" } });
      ev("content_block_stop", { index: 0 });
      ev("message_delta", { delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 2 } });
      ev("message_stop", {});
      return res.end();
    }
    return json(404, {});
  });
};
const opts = { SNICallback: (name, cb) => cb(null, contexts[name] ?? contexts["api.anthropic.com"]), key: ca.leafFor("api.anthropic.com").keyPem, cert: ca.leafFor("api.anthropic.com").certPem };
const server = https.createServer(opts, handler("tcp"));
await new Promise((r) => server.listen(443, "127.0.0.1", r));
// An attacker's own forwarder on a socket (a tunnel claude would use with ANTHROPIC_UNIX_SOCKET).
const sock = path.join(work, "fwd.sock");
const fwd = https.createServer(opts, handler("attacker-socket"));
await new Promise((r) => fwd.listen(sock, r));

function freshHome(name) {
  const home = path.join(work, name, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  fs.writeFileSync(path.join(home, ".claude", ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: REAL, refreshToken: "sk-ant-ort01-PLANTED", expiresAt: 4102444800000, scopes: ["user:inference", "user:profile"], subscriptionType: "max" } }), { mode: 0o600 });
  fs.writeFileSync(path.join(home, ".claude.json"), JSON.stringify({ hasCompletedOnboarding: true, lastOnboardingVersion: "2.1.326" }));
  return home;
}

function runClaude(name, args, { env = {}, home = freshHome(name), paste = false, timeoutMs = 60_000 } = {}) {
  const before = seen.length;
  return new Promise((resolve) => {
    const c = spawn(claude, args, { env: { PATH: "/usr/bin:/bin", HOME: home, TERM: "dumb", NODE_EXTRA_CA_CERTS: caFile, DISABLE_AUTOUPDATER: "1", ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    let pasted = false;
    const onData = () => {
      const m = /[?&]state=([A-Za-z0-9_-]+)/.exec(out + err);
      if (paste && m && !pasted) {
        pasted = true;
        setTimeout(() => c.stdin.write(`fakecode123#${m[1]}\n`), 300);
      }
    };
    c.stdout.on("data", (d) => ((out += d), onData()));
    c.stderr.on("data", (d) => ((err += d), onData()));
    if (!paste) {
      c.stdin.end();
    }
    const t = setTimeout(() => c.kill("SIGKILL"), timeoutMs);
    c.on("exit", (code) => {
      clearTimeout(t);
      const mine = seen.slice(before);
      const credsFile = path.join(home, ".claude", ".credentials.json");
      resolve({
        name,
        code,
        answered: out.includes("STANDIN-ANSWER"),
        out: out.slice(0, 400),
        err: err.slice(0, 400),
        plantedSent: mine.filter((s) => s.cred.includes(REAL)).length,
        requests: mine.length,
        messagesRequests: mine.filter((s) => s.url.startsWith("/v1/messages")).length,
        newLoginStored: [credsFile, path.join(loginPolicySpec("/etc/claude-code").storageDir, ".credentials.json")].some((f) => {
          try {
            return fs.readFileSync(f, "utf8").includes("NEW-LOGIN-FROM-PLAIN-CLAUDE");
          } catch {
            return false;
          }
        }),
        pasted,
      });
    });
  });
}

const sink = () => {
  const o = { text: "", write: (s) => ((o.text += s), true) };
  return o;
};
const result = { runs: {} };
const run = async (name, args, o) => {
  result.runs[name] = await runClaude(name, args, o);
};

// 1. control
await run("control", ["-p", "say hi"]);
// 2. install, as root of this namespace
const out = sink();
const err = sink();
result.install = { code: await loginPolicyCommand(["install"], { out, err, uid: 0 }), out: out.text, err: err.text };
result.reinstall = { code: await loginPolicyCommand(["install"], { out: sink(), err: sink(), uid: 0 }) };
result.status = managedLoginPolicyStatus("/etc/claude-code");
result.notRoot = await loginPolicyCommand(["install"], { out: sink(), err: sink(), uid: 1000 });
// Root of this namespace may write anywhere; a person's account cannot write the empty directory: made read-only here.
const dir = loginPolicySpec("/etc/claude-code").storageDir;
spawnSync("mount", ["--bind", dir, dir]);
spawnSync("mount", ["-o", "remount,bind,ro", dir]);
// 3. plain claude, and the ways around it
await run("plain", ["-p", "say hi"]);
{
  const home = freshHome("storage-override");
  await run("storage-override", ["-p", "say hi"], { home, env: { CLAUDE_SECURESTORAGE_CONFIG_DIR: path.join(home, ".claude") } });
}
{
  const home = freshHome("settings-override");
  await run("settings-override", ["--settings", JSON.stringify({ env: { CLAUDE_SECURESTORAGE_CONFIG_DIR: path.join(home, ".claude") } }), "-p", "say hi"], { home });
}
await run("attacker-tunnel", ["-p", "say hi"], { env: { CLAUDE_CODE_OAUTH_TOKEN: "x", ANTHROPIC_UNIX_SOCKET: sock } });
await run("auth-login", ["auth", "login", "--claudeai"], { paste: true, timeoutMs: 40_000 });
// 4. an Enclawed Code session: the planted login sealed under a stand-in Enclaweder at its first launch, then relayed.
{
  const home = freshHome("session");
  const env = { PATH: "/usr/bin:/bin", HOME: home, TERM: "dumb", NODE_EXTRA_CA_CERTS: caFile, DISABLE_AUTOUPDATER: "1", ENCLAWED_STATE_DIR: path.join(work, "session", "state"), ENCLAWEDER_DEVICE: "deny" };
  const sessionDir = path.join(work, "session", "s");
  fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  const device = { uid: "dev-uid-1", sign: async (m) => createHash("sha512").update("device-secret").update(m).digest() };
  const keys = await loginSealKeys({ env, k: kit, device });
  setTestAuthority({ trustedUids: [0, 65534], ignoreUserNamespace: true, loginWatchSpawn: () => {} });
  accept = /PLANTED-REAL-LOGIN/; // the provider takes only the real login: claude itself holds only the placeholder
  const login = await openLoginForSession({
    env,
    sessionDir,
    deviceBound: true,
    platform: "linux",
    k: { ...kit, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) },
    keys,
    relayOptionsForTest: { relay: { upstreamTrustForTest: ca.certPem, upstreamAddressForTest: { host: "127.0.0.1", port: 443 } }, credential: { trustForTest: ca.certPem, addressForTest: { host: "127.0.0.1", port: 443 } } },
  });
  result.sessionOpen = { ok: login.ok, action: login.action, code: login.code ?? null, message: login.message ?? null, sealedNow: login.sealedNow ?? null };
  if (login.ok && login.applyEnv) {
    const childEnv = login.applyEnv(env);
    result.sessionEnvHasReal = JSON.stringify(childEnv).includes(REAL);
    result.plaintextLeft = fs.existsSync(path.join(home, ".claude", ".credentials.json"));
    const before = seen.length;
    const r = await runClaude("session", ["-p", "say hi"], { home, env: childEnv });
    r.viaRelayWithReal = seen.slice(before).filter((s) => s.url.startsWith("/v1/messages") && s.cred.includes(REAL)).length;
    result.runs.session = r;
    await closeLoginForSession(login, { k: kit });
  }
}
server.close();
fwd.close();
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exit(0);
