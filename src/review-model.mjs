// The review judge's model access (review.mjs): only an Anthropic API key, sealed under the
// Enclaweder (`ecwctl login api-key`) and served through the same relay a session uses
// (claude-login.mjs, the kit's auth-relay.ts). The key is opened into this process's memory only
// after the person's two factors and the device-verified activation; the requests carry the
// relay's placeholder, and the relay adds the key. A Claude subscription login is never used:
// it stays with Claude Code, and Enclawed Code never reads or relays it. Without a bound
// Enclaweder or a sealed API key, the access is unavailable and nothing is sent.
//
// Requests go only to the relay's Messages route, over TLS for the provider's
// name with the relay's session CA, and nowhere else. Closed (the key
// dropped, the device released) when the run ends.

import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import tls from "node:tls";
import { launchAuthContext } from "./auth.mjs";
import { activateLaunch } from "./device-activation.mjs";
import { kit } from "./kit.mjs";
import { CLAUDE_RELAY } from "./claude-login.mjs";
import { appStateDir } from "./paths.mjs";

/** The model the judge asks (an internal constant). */
export const REVIEW_MODEL = "claude-sonnet-4-6";
const API_VERSION = "2023-06-01";
const REQUEST_TIMEOUT_MS = 60_000;
const MAX_RESPONSE_BYTES = 256 * 1024;

/** The Messages request body for one prompt. */
export function messagesBody(prompt, { model = REVIEW_MODEL, maxTokens }) {
  return { model, max_tokens: maxTokens, temperature: 0, system: prompt.system, messages: [{ role: "user", content: prompt.user }] };
}

/** The text of a Messages response, or throws. */
export function messagesText(status, body) {
  if (status !== 200) {
    throw new Error(`the model answered HTTP ${status}`);
  }
  const doc = JSON.parse(body);
  const parts = Array.isArray(doc?.content) ? doc.content.filter((c) => c?.type === "text" && typeof c.text === "string") : [];
  if (parts.length !== 1) {
    throw new Error("the model's answer is not one text block");
  }
  return parts[0].text;
}

/** POST one Messages request through the relay's socket. */
export function relayPost({ socketPath, caCertPem, body, placeholder = CLAUDE_RELAY.placeholder, host = CLAUDE_RELAY.upstreamHost }) {
  const data = Buffer.from(JSON.stringify(body), "utf8");
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        method: "POST",
        host,
        path: "/v1/messages",
        headers: {
          [placeholder.header]: placeholder.value,
          "anthropic-version": API_VERSION,
          "content-type": "application/json",
          "content-length": String(data.length),
        },
        agent: false,
        createConnection: () => tls.connect({ path: socketPath, servername: host, ca: [caCertPem] }),
        timeout: REQUEST_TIMEOUT_MS,
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (c) => {
          size += c.length;
          if (size > MAX_RESPONSE_BYTES) {
            req.destroy(new Error("the model's answer is too large"));
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("the model did not answer in time")));
    req.on("error", reject);
    req.end(data);
  });
}

const unavailable = (reason) => ({ ok: false, reason });

/** Why the judge does not run with only a Claude subscription login. */
export const NO_API_KEY =
  "the review judge runs only with an Anthropic API key sealed under the Enclaweder (ecwctl login api-key); a Claude subscription login stays with Claude Code, and Enclawed Code does not use it";

/**
 * Open the model access, or { ok: false, reason } with nothing sent. `deps`
 * replaces the device and login steps (tests): hold, sessionDevice,
 * precheck, activate, openLogin, closeLogin.
 */
export async function openRelayedModel({ env = process.env, audit = async () => {}, deps = {} } = {}) {
  // No sealed API key: said before anything is held or spent (no device use, no activation).
  const hasKey = deps.hasApiKey ?? (async () => fs.existsSync((await import("./claude-login.mjs")).sealedApiKeyFile(env)));
  if (!(await hasKey())) {
    return unavailable(NO_API_KEY);
  }
  const fw = deps.fw ?? (await import("./kit.mjs")).framework;
  const hold = deps.hold ?? (async (f) => (await import("./hardware.mjs")).holdSessionRoot(f));
  const root = await hold(fw).catch((e) => ({ mode: "halted", reason: e?.message ?? String(e), release: () => {} }));
  if (root?.mode !== "held") {
    root?.release?.();
    return unavailable(`no Enclaweder is held${root?.reason ? ` (${root.reason})` : ""}; the review uses only an API key sealed under it`);
  }
  let sessionDir = null;
  let login = null;
  const fail = async (reason) => {
    if (login) {
      await (deps.closeLogin ?? (async (l) => (await import("./claude-login.mjs")).closeLoginForSession(l)))(login).catch(() => {});
    }
    root.release();
    if (sessionDir) {
      fs.rmSync(sessionDir, { recursive: true, force: true });
    }
    return unavailable(reason);
  };
  try {
    const device = await (deps.sessionDevice ?? (async (f) => (await import("./device.mjs")).sessionDevice(f)))(fw).catch(() => null);
    if (!device) {
      return await fail("the held Enclaweder could not be attested");
    }
    const pre = await (deps.precheck ?? (async (o) => (await import("./claude-login.mjs")).loginLaunchPrecheck(o)))({ env, deviceBound: true, audit });
    if (!pre.ok) {
      return await fail(pre.message);
    }
    // The person's two factors and the device-verified code, as for a session start.
    const activate =
      deps.activate ??
      (async () => {
        const { ask } = await import("./cli-util.mjs");
        const ctx = await launchAuthContext({ env, interactive: true, audit, readCode: (q) => ask(q) });
        await activateLaunch(ctx, { fw, env, held: true, interactive: true });
      });
    await activate();
    const base = path.join(appStateDir(env), "review");
    fs.mkdirSync(base, { recursive: true, mode: 0o700 });
    sessionDir = fs.mkdtempSync(path.join(base, "s-"));
    fs.chmodSync(sessionDir, 0o700);
    const open = deps.openLogin ?? (async (o) => (await import("./claude-login.mjs")).openLoginForSession(o));
    login = await open({ env, sessionDir, device, rootRequired: env.ENCLAWEDER_ROOT === "required", audit });
    if (!login?.ok || login.action !== "relayed") {
      // Only an API key: a Claude subscription login stays with Claude Code and is never used here.
      const why = login?.ok ? NO_API_KEY : login?.message;
      login = login?.ok ? login : null;
      return await fail(why ?? "the sealed API key could not be opened");
    }
  } catch (e) {
    return await fail(e?.message ?? String(e));
  }
  const relay = login.relay;
  return {
    ok: true,
    model: REVIEW_MODEL,
    async send(prompt, { maxTokens }) {
      const r = await (deps.post ?? relayPost)({ socketPath: relay.socketPath, caCertPem: relay.caCertPem, body: messagesBody(prompt, { maxTokens }) });
      return messagesText(r.status, r.body);
    },
    async close() {
      await fail("closed");
    },
  };
}
