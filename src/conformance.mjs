// Enclawed Code's conformance adapter: Enclawed's adapter invariants
// (enclawed-oss conformance/checks-adapter.ts) run through Enclawed Code's own
// mapping of Claude Code's hook input (gate.mjs, tools.mjs) onto the kit.
//
//   enclawed conformance --adapter <Enclawed Code>/src/conformance.mjs
//   ecwctl conformance [--json]
//
// Each intent becomes the PreToolUse input Claude Code would send; the
// sandbox's state directory is Enclawed Code's protected set, its host secret
// a secret path, and its hardware state the gate's hardware answer. Nothing
// here decides: if the kit's decisions were stubbed to "allow", every attack
// case would fail.

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { RP_ID, verifyUser } from "./auth.mjs";
import { authCommand } from "./auth-cli.mjs";
import { launchCommandSetPin } from "./command-set.mjs";
import { anchorChecks } from "./conformance-anchor.mjs";
import { loginChecks } from "./conformance-login.mjs";
import { reviewChecks } from "./conformance-review.mjs";
import { sessionStateChecks } from "./conformance-session-state.mjs";
import { decidePreToolUse } from "./gate.mjs";
import { framework } from "./kit.mjs";
import { mcpSessionOf } from "./mcp.mjs";
import { shellDefinitionsOf } from "./shell-env.mjs";

/** The Claude Code tool call for one host-neutral intent. */
function claudeCodeCall(intent) {
  switch (intent.action) {
    case "write":
      return ["Write", { file_path: intent.path, content: "x\n" }];
    case "read":
      return ["Read", { file_path: intent.path }];
    case "search":
      return ["Grep", { pattern: intent.pattern, ...(intent.path ? { path: intent.path } : {}) }];
    case "shell":
      return ["Bash", { command: intent.command }];
    case "fetch":
      return ["WebFetch", { url: intent.url, prompt: "summarize" }];
    case "mcp":
      return [`mcp__${intent.server}__${intent.tool}`, intent.arguments ?? {}];
    default:
      throw new Error(`unknown intent ${JSON.stringify(intent.action)}`);
  }
}

export const enclawedConformanceAdapter = {
  host: "claude-code",
  async decide(intent, sandbox) {
    const fw = framework;
    const policy = fw.defaultOpenPolicy();
    const [tool, toolInput] = claudeCodeCall(intent);
    const input = {
      hook_event_name: "PreToolUse",
      session_id: "conformance",
      tool_use_id: `toolu_conformance_${Date.now()}`,
      tool_name: tool,
      tool_input: toolInput,
      cwd: sandbox.projectDir,
      permission_mode: intent.headless ? "bypassPermissions" : "default",
    };
    const d = await decidePreToolUse(input, {
      fw,
      policy,
      hardware: async () => (sandbox.hardware === "halted" ? { allowed: false, code: "hardware-dirty", reason: "the conformance sandbox's hardware root is halted" } : { allowed: true }),
      historyStore: new fw.HistoryStore({ dir: path.join(sandbox.home, ".enclawed-code-history"), limits: policy.history }),
      projectDir: sandbox.projectDir,
      home: sandbox.home,
      protected: { paths: [sandbox.stateDir], prefixes: [] },
      secretPaths: [sandbox.hostSecret],
      // A launcher session that admitted no MCP server.
      mcp: mcpSessionOf({ servers: {} }),
      // The session's verified skills as admission recorded them, as a
      // launcher session hands them to the hook (session.skills).
      skills: sandbox.skills ?? null,
      // The sandbox's login shell has no startup files, so the snapshot Claude Code makes of it
      // defines no alias or function (mapped as the hook maps a snapshot, shell-env.mjs).
      shellDefinitions: shellDefinitionsOf([], {}),
    });
    return { outcome: d.decision, codes: d.codes };
  },
};

/**
 * A stand-in Enclaweder's ANCHOR_READ (the public host protocol): command
 * set 0.5 signs its current anchor over the caller's nonce; firmware before
 * it answers ERR_UNSUPPORTED (8).
 */
function standInAnchorRead(cs05) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = Buffer.from(publicKey.export({ format: "der", type: "spki" }).subarray(12));
  const uid = randomBytes(12);
  const read = async (nonce) => {
    if (!cs05) {
      return Buffer.from([8]);
    }
    const body = Buffer.alloc(112);
    body[0] = 1;
    uid.copy(body, 44);
    return Buffer.concat([Buffer.from([0]), body, sign(null, Buffer.concat([Buffer.from("enclaweder.anchor-read.v1", "latin1"), nonce, body]), privateKey)]);
  };
  return { pub, uid, read };
}

/** Launch guarantees, through Enclawed Code's own launch mapping (command-set.mjs). */
export function launchChecks(fw) {
  return [
    ...anchorChecks(fw),
    {
      id: "adapter:claude-code:launch-firmware-pin",
      title: "claude-code: a 0.4-firmware Enclaweder refuses a root-required launch",
      proves:
        "through Enclawed Code's launch mapping, with the hardware root required, a held Enclaweder that does not prove command set 0.5 by its own signature over the launch's nonce (firmware 0.3.1 answering ANCHOR_READ as unsupported, an owner claiming so, or a read replayed from another nonce) refuses the launch naming the reflash runbook, and one that proves it starts",
      remedy: "Enclawed Code's launcher must ask the kit's commandSetPin with the framework's hardwareRootCommandSet before the launch's activation, and stop on a refusal",
      run: async () => {
        const pinOf = (dev, read = dev.read) =>
          launchCommandSetPin({ fw: { hardwareRootCommandSet: () => fw.proveCommandSet05(read, dev.pub, dev.uid) }, rootRequired: true, held: true });
        const old = await pinOf(standInAnchorRead(false));
        if (old.ok || old.code !== "firmware-too-old" || !old.message.includes(fw.CS05_REFLASH_RUNBOOK)) {
          throw new Error(`a 0.4-firmware device was not refused with the runbook named: ${JSON.stringify(old)}`);
        }
        const dev = standInAnchorRead(true);
        const stale = await dev.read(randomBytes(32));
        const replayed = await pinOf(dev, async () => stale);
        if (replayed.ok) {
          throw new Error("a read replayed from another nonce was taken as proof of command set 0.5");
        }
        const fresh = await pinOf(dev);
        if (!fresh.ok) {
          throw new Error(`a device proving command set 0.5 was refused: ${fresh.message}`);
        }
        // Not required: an older device runs, and the launch records what it leaves open.
        const optional = await launchCommandSetPin({ fw: { hardwareRootCommandSet: () => fw.proveCommandSet05(standInAnchorRead(false).read, dev.pub, dev.uid) }, rootRequired: false, held: true });
        if (!optional.ok || optional.residual !== fw.KEY_DERIVE_RESIDUAL) {
          throw new Error(`without the root required, an older device must run with its residual recorded: ${JSON.stringify(optional)}`);
        }
      },
    },
  ];
}

// ─── Second factor: device-bound passkeys only ───────────────────────────

const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, AT: 0x40 };

/** Minimal CBOR (unsigned and negative ints, text, bytes, maps) for the stand-in's answers. */
function cbor(v) {
  const head = (major, n) => (n < 24 ? Buffer.from([(major << 5) | n]) : n < 0x100 ? Buffer.from([(major << 5) | 24, n]) : Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]));
  if (typeof v === "number") {
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (typeof v === "string") {
    return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  }
  if (v instanceof Uint8Array) {
    return Buffer.concat([head(2, v.length), v]);
  }
  return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
}

/**
 * A stand-in for a platform passkey behind the framework's loopback page: it
 * answers the framework's passkey ceremony in the browser's wire format with
 * a software key and the authenticator flags it is told to report. It is not
 * an authenticator; it only lets the framework's own checks run end to end.
 */
function standInPasskey() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
  const id = randomBytes(32);
  const origin = `http://localhost:${40000 + Math.floor(Math.random() * 20000)}`;
  let counter = 1;
  const authData = (flags, attested) => {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);
    const parts = [createHash("sha256").update("localhost").digest(), Buffer.from([flags]), c];
    if (attested) {
      parts.push(Buffer.alloc(16), Buffer.from([0, id.length]), id, cose);
    }
    return Buffer.concat(parts);
  };
  const self = {
    flags: FLAG.UP | FLAG.UV,
    /** The enrolled record of this passkey (as the framework keeps one), for a throwaway store. */
    record: {
      id: "c0f0a001",
      label: "conformance passkey",
      kind: "passkey",
      credentialId: id.toString("base64url"),
      alg: -7,
      publicKeyCose: cose.toString("base64url"),
      signCount: 1,
      aaguid: "00000000-0000-0000-0000-000000000000",
      attestation: { fmt: "tpm", aaguid: "00000000-0000-0000-0000-000000000000", certSha256: "0".repeat(64), certSubject: "CN=conformance stand-in", certIssuer: "CN=conformance stand-in", allowedAs: null },
      enrolledAt: Date.now(),
      lastUsedAt: null,
    },
    ceremony: async (req) => {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: `webauthn.${req.kind}`, challenge: Buffer.from(req.challenge).toString("base64url"), origin, crossOrigin: false }));
      const cdh = createHash("sha256").update(clientDataJSON).digest();
      counter += 1;
      if (req.kind === "create") {
        // A registration that names no attestation: the flags are judged first.
        const raw = authData(self.flags | FLAG.AT, true);
        return { kind: "create", origin, credentialId: id, clientDataJSON, attestationObject: cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", raw]])) };
      }
      const raw = authData(self.flags, false);
      return { kind: "get", origin, credentialId: id, clientDataJSON, authenticatorData: raw, signature: sign("sha256", Buffer.concat([raw, cdh]), privateKey) };
    },
  };
  return self;
}

/** A throwaway Enclawed Code state dir holding one enrolled device-bound passkey; `run` gets its env and the audited records. */
async function withPasskeySandbox(passkey, run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-conformance-passkey-"));
  try {
    const env = { ...process.env, ENCLAWED_STATE_DIR: dir };
    const authDir = path.join(dir, "claude-code", "auth");
    fs.mkdirSync(authDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(authDir, "factors.json"), JSON.stringify({ v: 1, rpId: RP_ID, credentials: [passkey.record], failures: 0, lockedUntil: null }), { mode: 0o600 });
    const records = [];
    const audit = async (r) => {
      records.push(r);
    };
    return await run({ env, audit, records, authDir });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** The last refusal Enclawed Code audited for a second-factor attempt or enrollment. */
const lastRefusalCode = (records) => records.findLast((r) => r.payload?.outcome === "refused")?.payload?.code ?? null;

/** Enclawed Code's own second-factor check (verifyUser) for a sensitive command, through the stand-in. */
async function sensitiveCheck(passkey, { env, audit }) {
  try {
    const r = await verifyUser({ purpose: "policy-change", env, interactive: true, audit, allowTicket: false, passkey: passkey.ceremony, say: () => {} });
    return { ok: true, via: r.via };
  } catch (err) {
    return { ok: false, code: err?.code };
  }
}

/** Enclawed Code's `auth enroll --passkey`, through the stand-in (a second passkey next to the enrolled one). */
async function enrollThrough(passkey, existing, { env, audit }) {
  const sink = { write: () => true };
  // The enrolled passkey proves the existing factor first; the new one answers the create.
  const ceremony = async (req, say) => (req.kind === "create" ? passkey.ceremony(req, say) : existing.ceremony(req, say));
  try {
    await authCommand(["enroll", "--passkey", "--label", "candidate"], { out: sink, err: sink, env, audit, interactive: true, passkey: ceremony });
    return { ok: true };
  } catch (err) {
    return { ok: false, code: err?.code };
  }
}

/** Second-factor guarantees, through Enclawed Code's own enrollment and verification (auth.mjs, auth-cli.mjs). */
export function authChecks() {
  return [
    {
      id: "adapter:claude-code:passkey-synced-refused",
      title: "claude-code: a synced (backup-eligible) passkey is refused",
      proves:
        "through Enclawed Code's `auth enroll --passkey` and its second-factor check for a sensitive command, a passkey whose authenticator reports it backup-eligible (a synced passkey, its key copied to a vendor cloud) is refused at enrollment and at every use, naming backup-eligible, while the same passkey reporting device-bound passes",
      remedy: "Enclawed Code must enroll and verify passkeys only through the framework's enrollPasskey and assertSecondFactor, and never accept a passkey answer the framework refused",
      run: async () => {
        const enrolled = standInPasskey();
        await withPasskeySandbox(enrolled, async (sb) => {
          const ok = await sensitiveCheck(enrolled, sb);
          if (!ok.ok || ok.via !== "passkey") {
            throw new Error(`a device-bound passkey with user verification was not accepted: ${JSON.stringify(ok)}`);
          }
          const synced = standInPasskey();
          synced.flags = FLAG.UP | FLAG.UV | FLAG.BE;
          const before = fs.readFileSync(path.join(sb.authDir, "factors.json"), "utf8");
          const e = await enrollThrough(synced, enrolled, sb);
          if (e.ok || lastRefusalCode(sb.records) !== "backup-eligible") {
            throw new Error(`a synced passkey was not refused at enrollment as backup-eligible: ${JSON.stringify(e)}, last refusal ${lastRefusalCode(sb.records)}`);
          }
          if (JSON.parse(fs.readFileSync(path.join(sb.authDir, "factors.json"), "utf8")).credentials.length !== JSON.parse(before).credentials.length) {
            throw new Error("a refused synced passkey was written to the factor store");
          }
          enrolled.flags = FLAG.UP | FLAG.UV | FLAG.BE;
          const used = await sensitiveCheck(enrolled, sb);
          if (used.ok || lastRefusalCode(sb.records) !== "backup-eligible") {
            throw new Error(`a passkey answering as backup-eligible was accepted or refused for another reason: ${JSON.stringify(used)}, last refusal ${lastRefusalCode(sb.records)}`);
          }
        });
      },
    },
    {
      id: "adapter:claude-code:passkey-uv-required",
      title: "claude-code: a passkey assertion without user verification is refused",
      proves:
        "through Enclawed Code's second-factor check for a sensitive command and its `auth enroll --passkey`, a device-bound passkey that asserts user presence but not user verification (no PIN, fingerprint or face: UV=0) is refused naming no-user-verification, and the same passkey with UV passes",
      remedy: "Enclawed Code must verify every passkey answer with the framework's assertSecondFactor and enroll with its enrollPasskey, which require UV on every use",
      run: async () => {
        const passkey = standInPasskey();
        await withPasskeySandbox(passkey, async (sb) => {
          passkey.flags = FLAG.UP;
          const noUv = await sensitiveCheck(passkey, sb);
          if (noUv.ok || lastRefusalCode(sb.records) !== "no-user-verification") {
            throw new Error(`an assertion without user verification was accepted or refused for another reason: ${JSON.stringify(noUv)}, last refusal ${lastRefusalCode(sb.records)}`);
          }
          passkey.flags = FLAG.UP | FLAG.UV;
          const ok = await sensitiveCheck(passkey, sb);
          if (!ok.ok || ok.via !== "passkey") {
            throw new Error(`the same passkey with user verification was not accepted: ${JSON.stringify(ok)}`);
          }
          const candidate = standInPasskey();
          candidate.flags = FLAG.UP;
          const e = await enrollThrough(candidate, passkey, sb);
          if (e.ok || lastRefusalCode(sb.records) !== "no-user-verification") {
            throw new Error(`a passkey created without user verification was not refused at enrollment: ${JSON.stringify(e)}, last refusal ${lastRefusalCode(sb.records)}`);
          }
        });
      },
    },
  ];
}

/** Run the framework's checks plus the adapter invariants through Enclawed Code. */
export async function runConformance({ json = false, out = process.stdout } = {}) {
  const fw = framework;
  const report = await fw.runConformanceChecks({ extraChecks: [...fw.adapterChecks(enclawedConformanceAdapter), ...launchChecks(fw), ...authChecks(), ...loginChecks(), ...sessionStateChecks(fw), ...reviewChecks()] });
  out.write(json ? `${JSON.stringify(report, null, 2)}\n` : `${fw.renderConformanceReport(report)}\n`);
  return report.ok ? 0 : 1;
}
