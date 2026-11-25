// Runs inside a private mount and network namespace made by
// test/api-key-relay-real.test.mjs (its /etc/hosts sends api.anthropic.com and
// Claude's other hosts to 127.0.0.1, where a stand-in provider listens). Drives
// the REAL Claude Code binary in an isolated HOME:
//   1. an Enclawed Code session with an API key sealed under a stand-in
//      Enclaweder: claude holds only the relay's placeholder, the relay adds
//      the key as x-api-key, the stand-in answers only to that key;
//   2. a subscription token sealed where the API key belongs: the launch is
//      refused and the token never reaches the provider.
// Prints one JSON document with what was observed.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import tls from "node:tls";

const [claude, work] = process.argv.slice(2);
const { setTestAuthority } = await import("../../src/authority.mjs");
setTestAuthority({ trustedUids: [0, 65534], ignoreUserNamespace: true });
const { containment, kit } = await import("../../src/kit.mjs");
const { API_KEY_LABEL, closeLoginForSession, loginCommand, loginSealKeys, openLoginForSession, sealedApiKeyFile } = await import("../../src/claude-login.mjs");

const KEY = `sk-ant-api03-${"R3alKeyStandIn".repeat(6)}-AA`;
const OAUTH = "sk-ant-oat01-SUBSCRIPTION-NEVER-RELAYED-0123456789";
const NAMES = ["api.anthropic.com", "platform.claude.com", "claude.ai", "claude.com", "statsig.anthropic.com", "mcp-proxy.anthropic.com"];
const ca = containment.createContainerCa("stand-in provider", NAMES);
const caFile = path.join(work, "ca.pem");
fs.writeFileSync(caFile, ca.certPem);
const contexts = Object.fromEntries(NAMES.map((n) => [n, tls.createSecureContext({ key: ca.leafFor(n).keyPem, cert: ca.leafFor(n).certPem })]));
const seen = [];
const server = https.createServer({ SNICallback: (name, cb) => cb(null, contexts[name] ?? contexts["api.anthropic.com"]), key: ca.leafFor("api.anthropic.com").keyPem, cert: ca.leafFor("api.anthropic.com").certPem }, (req, res) => {
  let b = "";
  req.on("data", (d) => (b += d));
  req.on("end", () => {
    seen.push({ url: req.url, authorization: req.headers.authorization ?? null, apiKey: req.headers["x-api-key"] ?? null });
    const json = (status, o) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(o));
    };
    if (req.url.startsWith("/v1/messages") && !req.url.includes("count_tokens")) {
      if (req.headers["x-api-key"] !== KEY || req.headers.authorization) {
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
    if (req.url.startsWith("/api/oauth/profile")) {
      return json(200, { account: { uuid: "11111111-1111-4111-8111-111111111111", email: "person@example.test", display_name: "P" }, organization: { uuid: "22222222-2222-4222-8222-222222222222", organization_type: "claude_max", rate_limit_tier: "default_claude_max_20x" } });
    }
    return json(404, {});
  });
});
await new Promise((r) => server.listen(443, "127.0.0.1", r));

const device = { uid: "dev-uid-1", sign: async (m) => createHash("sha512").update("device-secret").update(m).digest() };
const quiet = { write: () => true };
const shielded = { ...kit, processMemoryShielded: () => ({ shielded: true, reason: "stand-in" }) };
const relayOptionsForTest = { relay: { upstreamTrustForTest: ca.certPem, upstreamAddressForTest: { host: "127.0.0.1", port: 443 } } };

function world(name) {
  const home = path.join(work, name, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  fs.writeFileSync(path.join(home, ".claude.json"), JSON.stringify({ hasCompletedOnboarding: true, lastOnboardingVersion: "2.1.331" }));
  const sessionDir = path.join(work, name, "s");
  fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  return { home, sessionDir, env: { PATH: "/usr/bin:/bin", HOME: home, TERM: "dumb", NODE_EXTRA_CA_CERTS: caFile, DISABLE_AUTOUPDATER: "1", ENCLAWED_STATE_DIR: path.join(work, name, "state") } };
}

function runClaude(env) {
  const before = seen.length;
  return new Promise((resolve) => {
    const c = spawn(claude, ["-p", "say hi"], { env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (err += d));
    const t = setTimeout(() => c.kill("SIGKILL"), 90_000);
    c.on("exit", (code) => {
      clearTimeout(t);
      const mine = seen.slice(before);
      resolve({ code, answered: out.includes("STANDIN-ANSWER"), out: out.slice(0, 300), err: err.slice(0, 300), messagesWithKey: mine.filter((s) => s.url.startsWith("/v1/messages") && s.apiKey === KEY && !s.authorization).length, keySeenOutsideMessages: mine.filter((s) => !s.url.startsWith("/v1/messages") && s.apiKey === KEY).length });
    });
  });
}

const result = {};
{
  const w = world("relayed");
  result.seal = await loginCommand(["api-key"], { out: quiet, err: quiet, env: w.env, k: kit, device, platform: "linux", readSecret: async () => KEY });
  const keys = await loginSealKeys({ env: w.env, k: kit, device });
  const login = await openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound: true, platform: "linux", k: shielded, keys, relayOptionsForTest });
  result.open = { ok: login.ok, action: login.action ?? null, message: login.message ?? null };
  if (login.ok && login.applyEnv) {
    const childEnv = login.applyEnv(w.env);
    result.envHasKey = JSON.stringify(childEnv).includes(KEY);
    result.session = await runClaude(childEnv);
    await closeLoginForSession(login, { k: kit });
  }
}
{
  const w = world("planted");
  const keys = await loginSealKeys({ env: w.env, k: kit, device });
  fs.mkdirSync(path.dirname(sealedApiKeyFile(w.env)), { recursive: true, mode: 0o700 });
  kit.sealLoginBytes({ plain: Buffer.from(JSON.stringify({ kind: "anthropic-api-key", apiKey: OAUTH })), sealedFile: sealedApiKeyFile(w.env), keys, deviceBound: true, label: API_KEY_LABEL });
  const before = seen.length;
  const login = await openLoginForSession({ env: w.env, sessionDir: w.sessionDir, deviceBound: true, platform: "linux", k: shielded, keys, relayOptionsForTest });
  result.planted = { ok: login.ok, code: login.code ?? null, tokenSent: seen.slice(before).some((s) => `${s.authorization} ${s.apiKey}`.includes(OAUTH)) };
}
server.close();
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exit(0);
