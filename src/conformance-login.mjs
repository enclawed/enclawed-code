// Login guarantees, through Enclawed Code's own mapping of how Claude Code
// authenticates (claude-login.mjs). These checks run anywhere (temporary
// directories only, a stand-in device key, no network).
//
// For Claude subscription logins, Enclawed Code follows Anthropic's terms: the
// login stays with Claude Code, signed in through Anthropic's own flow, and
// Enclawed Code never reads, stores or relays it. An API key, the customer's
// own key management, may be sealed under the Enclaweder.

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { kit } from "./kit.mjs";
import { claudeCredentialLocations } from "./credentials.mjs";
import { claudeLoginDir, closeLoginForSession, credentialKind, loginCommand, openLoginForSession, sealedApiKeyFile } from "./claude-login.mjs";

const SUBSCRIPTION = JSON.stringify({ claudeAiOauth: { accessToken: "sk-ant-oat01-conformance-stand-in", refreshToken: "sk-ant-ort01-conformance", expiresAt: 4102444800000, scopes: ["user:inference"] } });

function tmp(prefix) {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

const sink = () => {
  const o = { text: "", write: (s) => ((o.text += s), true) };
  return o;
};

/** A stand-in for the launch's device keys (the kit's credential-keys shape, no device). */
function standInKeys() {
  return { write: { key: createHash("sha256").update("conformance-login-key").digest(), source: "device", id: "device:conformance:0" }, read: () => null, keyFile: "/nonexistent", device: { boxes: null } };
}

/**
 * Record every read of a file under `dirs` while `fn` runs (fs read calls and read-mode opens).
 * Write-only opens (an erase overwrites, it does not read) are not reads.
 */
export async function readsUnder(dirs, fn) {
  const roots = dirs.map((d) => path.resolve(d) + path.sep);
  const hit = (p) => (typeof p === "string" || p instanceof URL) && roots.some((r) => path.resolve(String(p)).startsWith(r));
  const reads = [];
  const orig = { readFileSync: fs.readFileSync, openSync: fs.openSync, createReadStream: fs.createReadStream, readFile: fs.promises.readFile, open: fs.promises.open };
  const readFlags = (flags) => flags === undefined || (typeof flags === "string" ? /r/.test(flags) : (flags & 3) !== fs.constants.O_WRONLY);
  fs.readFileSync = (p, ...a) => (hit(p) && reads.push(String(p)), orig.readFileSync(p, ...a));
  fs.openSync = (p, flags, ...a) => (hit(p) && readFlags(flags) && reads.push(String(p)), orig.openSync(p, flags, ...a));
  fs.createReadStream = (p, ...a) => (hit(p) && reads.push(String(p)), orig.createReadStream(p, ...a));
  fs.promises.readFile = (p, ...a) => (hit(p) && reads.push(String(p)), orig.readFile(p, ...a));
  fs.promises.open = (p, flags, ...a) => (hit(p) && readFlags(flags) && reads.push(String(p)), orig.open(p, flags, ...a));
  try {
    return { result: await fn(), reads };
  } finally {
    Object.assign(fs, { readFileSync: orig.readFileSync, openSync: orig.openSync, createReadStream: orig.createReadStream });
    fs.promises.readFile = orig.readFile;
    fs.promises.open = orig.open;
  }
}

export function loginChecks() {
  return [
    {
      id: "adapter:claude-code:subscription-login-never-handled",
      title: "claude-code: a Claude subscription login stays with Claude Code; Enclawed Code never reads, stores or relays it",
      proves:
        "with an Enclaweder bound and no API key sealed, a session's Claude Code keeps its own login in Enclawed Code's login directory (CLAUDE_SECURESTORAGE_CONFIG_DIR), no relay starts and no credential variable is set; Enclawed Code opens no file of that directory or of the person's own Claude Code storage while the session opens, closes and halts; the halt erases the session's login storage (written only, never read) and leaves the person's own login exactly as it was",
      remedy: "claude-login.mjs must only point Claude Code at its login directory, never open its files, and erase them write-only on a halt",
      run: async () => {
        const root = tmp("enclawed-code-conf-login-");
        try {
          const env = { HOME: path.join(root, "home"), ENCLAWED_STATE_DIR: path.join(root, "state") };
          const person = claudeCredentialLocations(env, "linux").file;
          fs.mkdirSync(path.dirname(person), { recursive: true });
          fs.writeFileSync(person, SUBSCRIPTION, { mode: 0o600 });
          const sessionDir = path.join(root, "session");
          fs.mkdirSync(sessionDir, { mode: 0o700 });
          const loginDir = claudeLoginDir(env);
          const k = { ...kit, processMemoryShielded: () => ({ shielded: true, reason: "conformance stand-in" }) };
          const { result: opened, reads: openReads } = await readsUnder([loginDir, path.dirname(person)], async () => {
            const o = await openLoginForSession({ env, sessionDir, deviceBound: true, platform: "linux", k, keys: standInKeys() });
            if (o.ok) {
              // Claude Code signs in with its own /login and writes its credential (stood in here).
              fs.writeFileSync(path.join(loginDir, ".credentials.json"), SUBSCRIPTION, { mode: 0o600 });
            }
            return o;
          });
          if (!opened.ok || opened.action !== "own-login") {
            throw new Error(`the session did not use Claude Code's own login: ${JSON.stringify({ ok: opened.ok, action: opened.action, code: opened.code, message: opened.message })}`);
          }
          const childEnv = opened.applyEnv({ ...env });
          if (childEnv.CLAUDE_SECURESTORAGE_CONFIG_DIR !== loginDir || childEnv.ANTHROPIC_UNIX_SOCKET || childEnv.CLAUDE_CODE_OAUTH_TOKEN || childEnv.ANTHROPIC_API_KEY) {
            throw new Error(`the session's environment is not Claude Code's own login: ${JSON.stringify(childEnv)}`);
          }
          const { result: end, reads: haltReads } = await readsUnder([loginDir, path.dirname(person)], () => closeLoginForSession(opened, { halted: true, k, platform: "linux" }));
          if (openReads.length || haltReads.length) {
            throw new Error(`Enclawed Code read Claude Code's login storage: ${[...openReads, ...haltReads].join(", ")}`);
          }
          if (!end?.ok || fs.existsSync(path.join(loginDir, ".credentials.json"))) {
            throw new Error(`the halt did not erase the session's Claude Code login: ${JSON.stringify(end)}`);
          }
          if (fs.readFileSync(person, "utf8") !== SUBSCRIPTION) {
            throw new Error("the person's own Claude Code login was changed");
          }
        } finally {
          fs.rmSync(root, { recursive: true, force: true });
        }
      },
    },
    {
      id: "adapter:claude-code:only-api-keys-sealed",
      title: "claude-code: only an Anthropic API key is ever sealed; anything else is treated as a subscription login and refused",
      proves:
        "credentialKind is 'api-key' only for Anthropic's API key format and 'subscription' for OAuth access and refresh tokens, a Claude login document, an empty or arbitrary string; `ecwctl login api-key` given a subscription token refuses before any device step and writes nothing",
      remedy: "claude-login.mjs credentialKind must recognize only the API key format, and loginCommand must refuse anything else before sealing",
      run: async () => {
        const key = `sk-ant-api03-${"A".repeat(86)}-${"b".repeat(6)}`;
        const table = [
          [key, "api-key"],
          ["sk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123456789", "subscription"],
          ["sk-ant-ort01-abcdefghijklmnopqrstuvwxyz0123456789", "subscription"],
          [SUBSCRIPTION, "subscription"],
          ["", "subscription"],
          [`${key}\n`, "subscription"],
          [null, "subscription"],
        ];
        for (const [secret, want] of table) {
          if (credentialKind(secret) !== want) {
            throw new Error(`credentialKind(${JSON.stringify(secret).slice(0, 30)}) is not ${want}`);
          }
        }
        const root = tmp("enclawed-code-conf-apikey-");
        try {
          const env = { HOME: path.join(root, "home"), ENCLAWED_STATE_DIR: path.join(root, "state") };
          let held = false;
          const code = await loginCommand(["api-key"], {
            out: sink(),
            err: sink(),
            env,
            platform: "linux",
            readSecret: async () => "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123456789",
            hold: async () => {
              held = true;
              return { mode: "software-only", release() {} };
            },
          });
          if (code !== 1 || held || fs.existsSync(sealedApiKeyFile(env))) {
            throw new Error(`a subscription token was taken for sealing: exit ${code}, device held ${held}, sealed ${fs.existsSync(sealedApiKeyFile(env))}`);
          }
        } finally {
          fs.rmSync(root, { recursive: true, force: true });
        }
      },
    },
  ];
}
