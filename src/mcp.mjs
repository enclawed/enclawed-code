// MCP admission (after enclawed-oss extensions/mcp-attested): which MCP
// servers a session may start, and what their tools may be.
//
// Every decision is the Enclawed adapter kit's (enclawed-oss
// src/enclawed/adapter/mcp.ts, trust.ts, mcp-package-pins.ts, code-pins.ts,
// contained-launch.ts):
//
//   - kit.admitMcpServers: only a server whose identity (definition digest,
//     executable digest, code pinned by content) matches a verified admission
//     record may start; same-named tools on two servers, a tool named like a
//     Claude Code tool, two servers with one `mcp__<server>__` prefix and the
//     claude.ai connectors' prefix are refused.
//   - kit.signedMcpPinStore: records are returned only when their signature
//     verifies against the trust list (trust.mjs).
//   - kit.mcpToolSetProblems / inspectMcpToolDefinition: a flagged tool
//     definition (hidden content, instructions aimed at the model) cannot be
//     pinned.
//   - kit.McpSession: the per-call rule (a pinned, unrevoked tool of an
//     admitted server) and tools/list drift (mcp-proxy.mjs).
//   - kit.launchMcpServer: an admitted server starts only contained, with the
//     containment part of its signed record (mcp-proxy.mjs).
//
// Enclawed Code keeps the Claude Code specifics: where Claude Code reads MCP
// definitions (candidateServers), its built-in tool names, its name
// normalization, probing a server once at pin time, the session's MCP block
// and the --mcp-config document that puts the proxy in front of every
// admitted server, and the claude.ai connector allowlist.

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { LockedAuditLog } from "./audit.mjs";
import { writeFileAtomic } from "./cli-util.mjs";
import { framework, kit } from "./kit.mjs";
import { codeIdentity, localCodePath, measuredLaunch } from "./mcp-code-pins.mjs";
import { authority } from "./authority.mjs";
import { APP_ROOT, appStateDir, auditLogPath, realpathNearest } from "./paths.mjs";
import { sha256Hex, signRecord, trustDir } from "./trust.mjs";

export const MCP_PROXY_BIN = path.join(APP_ROOT, "bin", "ecwcode-mcp-proxy.mjs");
export const PIN_VERSION = 1;

export function mcpStoreDir(env = process.env) {
  return path.join(appStateDir(env), "mcp");
}

/** Claude Code's form of a server or tool name inside `mcp__<server>__<tool>`. */
export const normalizeMcpName = (n) => kit.defaultMcpNormalizer(String(n));

// Claude Code's own tool names: an MCP tool with one of these names shadows it.
export const BUILTIN_TOOL_NAMES = Object.freeze(["Agent", "Task", "Bash", "BashOutput", "Edit", "MultiEdit", "Write", "Read", "Glob", "Grep", "LS", "NotebookEdit", "NotebookRead", "WebFetch", "WebSearch", "TodoWrite", "Skill", "SlashCommand", "ToolSearch", "LSP", "Monitor", "PowerShell", "ExitPlanMode", "EnterPlanMode", "AskUserQuestion", "KillShell", "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "TaskOutput"]);

export const CLAUDE_AI_PREFIX = "mcp__claude_ai_";

/** Record kinds earlier Enclawed Code releases wrote (still accepted; the signature covers the kind). */
export const ADMISSION_KINDS = Object.freeze(["codenclawed-mcp-admission", "enclawde-mcp-admission"]);
/** Every record kind accepted: the kit's (written now) and the earlier ones. */
export const RECORD_KINDS = Object.freeze([kit.MCP_ADMISSION_KIND, ...ADMISSION_KINDS]);

/** The kit's pin store options for this installation. */
export function pinStore(env = process.env) {
  return { dir: mcpStoreDir(env), trustDir: trustDir(env), kinds: RECORD_KINDS, normalize: normalizeMcpName };
}

function readJson(f) {
  try {
    return JSON.parse(fs.readFileSync(f, "utf8"));
  } catch {
    return null;
  }
}

/** Claude Code's per-user state file (user- and local-scope MCP servers). */
export function claudeStateFile(env) {
  return env.CLAUDE_CONFIG_DIR ? path.join(env.CLAUDE_CONFIG_DIR, ".claude.json") : path.join(env.HOME || os.homedir(), ".claude.json");
}

function readConfigValue(v, cwd) {
  const t = String(v).trim();
  if (t.startsWith("{")) {
    return { doc: JSON.parse(t), source: "--mcp-config JSON string" };
  }
  const f = path.resolve(cwd, t);
  return { doc: JSON.parse(fs.readFileSync(f, "utf8")), source: f };
}

/**
 * Every MCP server definition Claude Code would otherwise read for this
 * session, with where it comes from.
 * @returns {Array<{ name: string, scope: string, source: string, def: object }>}
 */
export function candidateServers({ projectDir, env, mcpConfigValues = [], cwd = projectDir }) {
  const out = [];
  const add = (scope, source, servers) => {
    if (servers && typeof servers === "object" && !Array.isArray(servers)) {
      for (const [name, def] of Object.entries(servers)) {
        if (def && typeof def === "object" && !Array.isArray(def)) {
          out.push({ name, scope, source, def });
        }
      }
    }
  };
  const stateFile = claudeStateFile(env);
  const st = readJson(stateFile);
  add("user", stateFile, st?.mcpServers);
  add("local", stateFile, st?.projects?.[projectDir]?.mcpServers);
  add("project", path.join(projectDir, ".mcp.json"), readJson(path.join(projectDir, ".mcp.json"))?.mcpServers);
  for (const v of mcpConfigValues) {
    let r;
    try {
      r = readConfigValue(v, cwd);
    } catch (err) {
      throw new Error(`cannot read --mcp-config ${String(v).slice(0, 80)}: ${err.message}`, { cause: err });
    }
    add("--mcp-config", r.source, r.doc?.mcpServers);
  }
  return out;
}

/** The executable a stdio definition runs (absolute, or looked up on PATH). */
export function resolveCommand(command, env) {
  if (typeof command !== "string" || command === "") {
    return null;
  }
  if (command.includes("/")) {
    return fs.existsSync(command) ? realpathNearest(path.resolve(command)) : null;
  }
  for (const d of String(env.PATH ?? "").split(path.delimiter).filter(Boolean)) {
    const p = path.join(d, command);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      if (fs.statSync(p).isFile()) {
        return fs.realpathSync(p);
      }
    } catch {
      /* next */
    }
  }
  return null;
}

function fileSha(p) {
  try {
    return sha256Hex(fs.readFileSync(p));
  } catch {
    return null;
  }
}

/** Is this a remote (http / sse) server definition? (kit.remoteTransportOf) */
export function isRemoteDefinition(def) {
  return kit.remoteTransportOf({ ...def, type: def?.type ?? (typeof def?.url === "string" ? "http" : "stdio") }) !== null;
}

/**
 * The remote part of an admission record for a definition (kit
 * McpRemoteRecord): its URL and transport, and the https origins on another
 * site the operator names for its authorization server.
 */
export function remotePart(def, authorizationOrigins = [], oauth = null) {
  const transport = kit.remoteTransportOf({ ...def, type: def?.type ?? "http" });
  const rec = {
    url: def?.url,
    transport,
    ...(authorizationOrigins.length ? { authorizationOrigins: [...authorizationOrigins] } : {}),
    ...(oauth && (oauth.clientId || oauth.scope) ? { oauth: { ...(oauth.clientId ? { clientId: oauth.clientId } : {}), ...(oauth.scope ? { scope: oauth.scope } : {}) } } : {}),
  };
  if (!kit.isRemoteRecord(rec)) {
    throw new Error(`the remote definition (url ${JSON.stringify(def?.url ?? null)}, transport ${JSON.stringify(transport)}) cannot be admitted: an http(s) URL, an http or sse transport, and https authorization origins only`);
  }
  return rec;
}

/** Enclawed's credential store for remote servers (Enclawed Code's protected state; kit.remoteCredentialStore). */
export function remoteCredentialDir(env = process.env) {
  return path.join(appStateDir(env), "credentials", "remote-mcp");
}

/** The store's key file, apart from the sealed records (used only without a device or an OS keyring). */
export function remoteCredentialKeyFile(env = process.env) {
  return path.join(appStateDir(env), "credentials", "remote-mcp.key");
}

/**
 * The credential store, sealed with the kit's key (kit.credentialStoreKeys):
 * the bound Enclaweder's when this process holds the hardware root, else the
 * OS keyring's, else the key file's.
 */
export async function remoteCredentialStoreFor(env = process.env, { audit = null } = {}) {
  const keys = await kit.credentialStoreKeys({ keyFile: remoteCredentialKeyFile(env), device: kit.frameworkCredentialKeyDevice(), keyring: kit.osKeyring(env), rootRequired: env.ENCLAWEDER_ROOT === "required" });
  // Every record the store refuses (a record sealed under the Enclaweder's earlier CHALLENGE key among them) is audited.
  const log = audit ?? new LockedAuditLog(framework, auditLogPath(env));
  return kit.remoteCredentialStore(remoteCredentialDir(env), keys, {
    audit: (r) => log.append({ type: `claude-code.${r.type}`, actor: "enclawed-code", level: null, payload: r.payload }),
  });
}

/** The environment a measured launch starts with: an env file's defaults, the definition's, then the launch's own. */
export function launchEnv(defEnv, measured) {
  return { ...(measured?.envDefaults ?? {}), ...defEnv, ...(measured?.env ?? {}) };
}

/**
 * What a connection to a remote server sends (kit.remoteCredentials): the
 * definition's headers, `${VAR}` taken from `env`, and the stored OAuth
 * token, all bound to the server's origin.
 */
export async function remoteCredentialsFor(def, remote, env = process.env) {
  // The store is read lazily during the connection; each refusal is appended to the audit log as it happens.
  return kit.remoteCredentials(def, remote, { store: await remoteCredentialStoreFor(env), env, ...remoteConnectSeam() });
}

/** The remote transport's connect override, set only by the suite (authority.mjs remoteConnect; a function call). */
export function remoteConnectSeam() {
  const c = authority().remoteConnect;
  return c ? { connect: c } : {};
}

/** What the launcher measures of a definition: the kit's digest and the executable's SHA-256. */
export function definitionIdentity(def, env = process.env) {
  const type = def.type ?? (typeof def.url === "string" ? "http" : "stdio");
  const exe = type === "stdio" ? resolveCommand(def.command, { PATH: env.PATH }) : null;
  return { type, definitionDigest: kit.mcpDefinitionDigest(def), executable: exe, executableSha256: exe ? fileSha(exe) : null };
}

/** The pinned hash of one tool definition. */
export const toolHash = (tool) => kit.mcpToolDefinitionDigest(tool);

/** Findings for one tool definition (empty when clean). */
export const inspectTool = (server, tool) => kit.inspectMcpToolDefinition(server, tool);

/** Problems that keep a probed tool set from being pinned (shadowing of Claude Code tools, flagged definitions, duplicates). */
export const toolSetProblems = (server, tools) => kit.mcpToolSetProblems(server, tools, BUILTIN_TOOL_NAMES, normalizeMcpName);

// ------------------------------------------------------------------ starting a server

/**
 * Start a stdio server contained: kit.launchMcpServer with the containment
 * part of its record decides (no record: mcp-server-not-contained; a machine
 * that cannot contain: containment-unavailable). `launch` is the kit's seam,
 * replaceable only in-process (tests).
 * @returns {Promise<{ ok: true, child, containment } | { ok: false, code: string, message: string }>}
 */
export async function startContained({ name, command, args, env, cwd = null, containment, stateDir, launch = kit.launchMcpServer, stdio = ["pipe", "pipe", "pipe"], onEvent }) {
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  // The definition's working directory (Claude Code's `cwd` field), absolute;
  // the containment refuses one outside the record's roots.
  const r = await launch({ name, command, args, env, ...(cwd ? { cwd } : {}) }, containment ?? null, { stateDir, onEvent });
  if (!r.ok) {
    return { ok: false, code: r.code, message: r.message };
  }
  const [cmd, ...rest] = r.containment.argv;
  const child = spawn(cmd, rest, { env: { ...r.containment.env }, stdio });
  child.on("exit", () => void r.containment.close());
  return { ok: true, child, containment: r.containment };
}

/** A definition's `cwd` (Claude Code resolves a relative one against the project), absolute; null without one. */
export function definitionCwd(def, base) {
  return typeof def?.cwd === "string" && def.cwd !== "" ? path.resolve(base, def.cwd) : null;
}

/** The values of the variables a definition sets, as the server receives them (definition first, then `from`). */
export function definitionEnv(def, from = {}) {
  const out = {};
  for (const [k, v] of Object.entries(def?.env && typeof def.env === "object" ? def.env : {})) {
    out[k] = typeof from[k] === "string" ? from[k] : String(v);
  }
  return out;
}

/**
 * Start a stdio server once, outside any session, contained with the
 * containment the operator declares, and read its identity and tools:
 * initialize, notifications/initialized, tools/list (every page).
 */
export async function probeServer(def, { env = process.env, cwd = process.cwd(), timeoutMs = 20_000, name = "probe", containment = null, remote = null, stateDir = path.join(appStateDir(env), "containment"), launch, code: measuredCode = null } = {}) {
  if (isRemoteDefinition(def)) {
    // A remote server is read through Enclawed's own remote transport, with
    // the remote part the operator is about to sign (kit.probeRemoteMcpServer).
    const rec = remote ?? remotePart(def);
    return kit.probeRemoteMcpServer({ ...def, name }, rec, { timeoutMs, ...remoteConnectSeam(), credentials: await remoteCredentialsFor({ ...def, name }, rec, env) });
  }
  const type = def.type ?? "stdio";
  if (type !== "stdio") {
    throw new Error(`${name} has the MCP transport ${JSON.stringify(type)}, which Enclawed Code cannot start`);
  }
  // A pinned package-runner form runs the measured tree, as the proxy will
  // (`code`: the pin-time measurement, so the index is read once).
  const code = measuredCode ?? codeIdentity(def, { env, cwd, pin: true });
  const measured = code.ok ? measuredLaunch(code.launch, def.command) : null;
  const started = await startContained({
    name,
    command: measured ? measured.command : def.command,
    args: measured ? measured.args : Array.isArray(def.args) ? def.args.map(String) : [],
    env: launchEnv(definitionEnv(def), measured),
    cwd: definitionCwd(def, cwd),
    containment,
    stateDir,
    launch,
  });
  if (!started.ok) {
    throw new Error(`${started.message} (${started.code})`);
  }
  return talkToProbe(started.child, def, timeoutMs);
}

function talkToProbe(child, def, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = "";
    let stderr = "";
    const pending = new Map();
    let nextId = 1;
    const timer = setTimeout(() => finish(new Error(`the server did not answer within ${timeoutMs / 1000} s${stderr ? ` (stderr: ${stderr.slice(0, 300)})` : ""}`)), timeoutMs);
    let done = false;
    const finish = (err, value) => {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(timer);
      try {
        child.kill("SIGTERM");
      } catch {
        /* gone */
      }
      if (err) {
        reject(err);
      } else {
        resolve(value);
      }
    };
    child.on("error", (err) => finish(new Error(`cannot start ${def.command}: ${err.message}`)));
    child.on("exit", (code) => finish(new Error(`the server exited (${code}) before it listed its tools${stderr ? ` (stderr: ${stderr.slice(0, 300)})` : ""}`)));
    child.stderr?.on("data", (d) => (stderr = (stderr + d).slice(-4000)));
    const request = (method, params) =>
      new Promise((res, rej) => {
        const id = nextId++;
        pending.set(id, { res, rej });
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      });
    child.stdout.on("data", (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (!line) {
          continue;
        }
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        const p = msg && pending.get(msg.id);
        if (p) {
          pending.delete(msg.id);
          if (msg.error) {
            p.rej(new Error(`${msg.error.message ?? "error"} (${msg.error.code ?? ""})`));
          } else {
            p.res(msg.result);
          }
        }
      }
    });
    (async () => {
      const init = await request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "enclawed-code-mcp-pin", version: "1" } });
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
      const tools = [];
      let cursor;
      for (let page = 0; page < 50; page++) {
        const r = await request("tools/list", cursor ? { cursor } : {});
        tools.push(...(Array.isArray(r?.tools) ? r.tools : []));
        cursor = r?.nextCursor;
        if (!cursor) {
          break;
        }
      }
      finish(null, { serverInfo: { name: init?.serverInfo?.name ?? null, version: init?.serverInfo?.version ?? null }, protocolVersion: init?.protocolVersion ?? null, tools });
    })().catch((err) => finish(err));
  });
}

// ------------------------------------------------------------------ pins

export function pinFile(name, env = process.env) {
  return path.join(mcpStoreDir(env), `${normalizeMcpName(name)}.json`);
}

/**
 * What the launcher measured about a probed server, as the kit's pin input
 * (kit.pinMcpServer / kit.mcpPinRecord). Throws when its code cannot be
 * pinned. `containment` and `roles` are what the operator declared.
 */
export function pinInput({ name, def, scope, source, probe, env = process.env, cwd = process.cwd(), containment = null, roles = null, remote = null, code: measuredCode = null }) {
  const id = definitionIdentity(def, env);
  // Pin time: a Python runner's wheels are downloaded and checked too.
  const code = measuredCode ?? codeIdentity(def, { env, cwd, pin: true });
  if (!code.ok) {
    throw new Error(`${name} cannot be pinned: ${code.problem}; ${code.how}`);
  }
  return { name, scope, source, definitionDigest: id.definitionDigest, executable: id.executable, executableSha256: id.executableSha256, serverInfo: probe.serverInfo, tools: probe.tools, code: code.code, args: roles, containment, remote };
}

/** Build the (unsigned) admission record for a probed server (kit.mcpPinRecord). */
export function pinRecord(o) {
  return kit.mcpPinRecord(pinInput(o));
}

/** Sign a record with `signer` and store it (tests and imports; `mcp pin` goes through kit.pinMcpServer). */
export function writePin(fw, record, signer, env = process.env) {
  const signed = signRecord(fw, record, signer);
  writeFileAtomic(pinFile(record.name, env), `${JSON.stringify(signed, null, 2)}\n`);
  return signed;
}

/** Every stored record (pinned or imported), with the kit's verdict; `record` is the raw file when the kit refused it. */
export function readPins(_fw, env = process.env) {
  return kit.readMcpPins(pinStore(env)).map((p) => ({ ...p, record: p.record ?? readJson(p.file) }));
}

/**
 * Decide which candidate servers start in this session (kit.admitMcpServers).
 * @returns {{ ok: true, admitted: Array<{ name, scope, def, record, normalized, launch }>, skipped: Array<{ name, scope, why }> } | { ok: false, message: string }}
 */
export function admitServers({ env, candidates, cwd = process.cwd() }) {
  const { records, broken } = kit.signedMcpPinStore(pinStore(env)).load();
  const measured = new Map();
  const kc = candidates.map((c) => {
    const ccwd = typeof c.def.cwd === "string" ? path.resolve(cwd, c.def.cwd) : cwd;
    const id = definitionIdentity(c.def, env);
    // The record's pin for this server: a Python release's hashes come from
    // it, and of several cached copies the pinned one is measured.
    const rec = records.find((r) => r?.name === c.name && r?.identity?.definitionDigest === id.definitionDigest) ?? null;
    let m;
    try {
      m = codeIdentity(c.def, { env, cwd: ccwd, pinned: rec?.code ?? null });
    } catch (err) {
      m = { ok: false, problem: err.message };
    }
    measured.set(c, m);
    return { name: c.name, scope: c.scope, source: c.source, definitionDigest: id.definitionDigest, executableSha256: id.executableSha256, definition: c.def, code: m.ok ? m.code : null, cwd: ccwd, pathVar: localCodePath(c.def, env) };
  });
  const adm = kit.admitMcpServers(kc, records, { builtinToolNames: BUILTIN_TOOL_NAMES, normalize: normalizeMcpName, reservedPrefixes: [CLAUDE_AI_PREFIX] }, broken);
  if (!adm.ok) {
    return adm;
  }
  const admitted = adm.admitted.map((a) => {
    const c = candidates.find((x) => x.name === a.name && x.scope === a.scope);
    const m = measured.get(c);
    return { ...a, def: c.def, launch: m?.ok ? (m.launch ?? null) : null };
  });
  return { ok: true, admitted, skipped: adm.skipped };
}

/** The session's MCP block (session.json) and the --mcp-config document for an admission. */
export function sessionMcp(admission, { sessionDir, sessionFileRef = null, node = process.execPath }) {
  const servers = {};
  const config = { mcpServers: {} };
  for (const a of admission.admitted) {
    const env = a.def.env && typeof a.def.env === "object" ? a.def.env : {};
    servers[a.name] = {
      normalized: a.normalized ?? normalizeMcpName(a.name),
      definitionDigest: a.record.identity.definitionDigest,
      command: a.def.command,
      args: Array.isArray(a.def.args) ? a.def.args.map(String) : [],
      // The values reach the proxy through its environment (the generated
      // --mcp-config below), never through the session file.
      envKeys: Object.keys(env),
      cwd: typeof a.def.cwd === "string" ? a.def.cwd : null,
      executableSha256: a.record.identity.executableSha256 ?? null,
      // Pinned code, checked again by the proxy right before it starts the
      // server; `launch` replaces a pinned npx definition (mcp-code-pins.mjs).
      code: a.record.code ?? null,
      launch: a.launch ?? null,
      serverInfo: a.record.identity.serverInfo ?? null,
      tools: a.record.tools,
      roles: a.record.args ?? null,
      // The signed containment (kit.launchMcpServer): none, and it does not start.
      containment: a.record.containment ?? null,
      // A remote server: the definition's URL and transport, and the signed
      // remote part it connects with (kit.connectRemoteMcpServer).
      ...(isRemoteDefinition(a.def) ? { type: a.def.type ?? "http", url: a.def.url, headers: a.def.headers ?? null, remote: a.record.remote ?? null } : {}),
      signer: a.record.signerKeyId ?? null,
    };
    config.mcpServers[a.name] = {
      type: "stdio",
      command: node,
      // The session file reference is filled in by the launcher (it changes
      // as the session file is rewritten): see launcher materializeSession.
      args: [MCP_PROXY_BIN, "--session", sessionFileRef?.file ?? "", "--digest", sessionFileRef?.digest ?? "", "--server", a.name],
      env,
    };
  }
  return {
    session: { servers, events: path.join(sessionDir, "mcp-events"), containment: path.join(sessionDir, "containment"), connectors: admission.connectors ?? { enabled: false, allow: [] } },
    config,
  };
}

// ------------------------------------------------------------------ the per-call rule

const sessions = new WeakMap();

/**
 * The kit's McpSession for a session file's MCP block (cached per block).
 * This is what the gate passes as `deps.mcp` to kit.decidePreAction. Throws
 * when a server's pins are malformed (the session must not run its tools).
 */
export function mcpSessionOf(block) {
  if (!block) {
    return null;
  }
  if (block instanceof kit.McpSession) {
    return block;
  }
  let s = sessions.get(block);
  if (!s) {
    const admitted = Object.entries(block.servers ?? {}).map(([name, x]) => ({
      name,
      scope: "session",
      normalized: x.normalized ?? normalizeMcpName(name),
      record: { name, identity: { definitionDigest: x.definitionDigest ?? "", executableSha256: x.executableSha256 ?? null, serverInfo: x.serverInfo ?? null }, tools: x.tools ?? {}, code: x.code ?? null, args: x.roles ?? null, containment: x.containment ?? null, remote: x.remote ?? null, signerKeyId: x.signer ?? null },
    }));
    // claude.ai account connectors: no server to pin; the kit admits only the
    // tools the operator's policy lists (enclawedCode.claudeAiConnectors).
    const connectors = [];
    for (const pat of block.connectors?.enabled ? (block.connectors.allow ?? []) : []) {
      const ref = typeof pat === "string" ? mcpToolRef(null, pat.endsWith("__*") ? `${pat.slice(0, -1)}*` : pat) : null;
      if (ref) {
        const c = connectors.find((x) => x.server === ref.server);
        c ? c.tools.push(ref.tool) : connectors.push({ server: ref.server, tools: [ref.tool] });
      }
    }
    s = new kit.McpSession(admitted, { connectors, connectorServer: (n) => `mcp__${n}__`.startsWith(CLAUDE_AI_PREFIX) });
    sessions.set(block, s);
  }
  return s;
}

/**
 * The kit event's `mcp` part for a Claude Code tool name `mcp__<server>__<tool>`:
 * the longest admitted server prefix, else the first `__` split.
 * @returns {{ server: string, tool: string } | null}
 */
export function mcpToolRef(session, tool) {
  if (typeof tool !== "string" || !tool.startsWith("mcp__")) {
    return null;
  }
  const rest = tool.slice(5);
  let first = null;
  let best = null;
  for (let i = rest.indexOf("__"); i > 0; i = rest.indexOf("__", i + 1)) {
    const ref = { server: rest.slice(0, i), tool: rest.slice(i + 2) };
    first ??= ref;
    if (session?.server(ref.server)) {
      best = ref;
    }
  }
  return best ?? first;
}

/**
 * The gate's MCP rule (launcher sessions), the kit's McpSession.verdict: an
 * MCP tool must be a pinned, unrevoked tool of an admitted server, and a
 * claude.ai connector tool one the policy lists (enclawedCode.claudeAiConnectors).
 * `mcp` is the session file's MCP block (or a kit McpSession).
 * @returns {null | { code: string, reason: string }}
 */
export function mcpVerdict(mcp, tool) {
  if (!mcp || typeof tool !== "string" || !tool.startsWith("mcp__")) {
    return null;
  }
  let session;
  try {
    session = mcpSessionOf(mcp);
  } catch (err) {
    return { code: "mcp-server-not-admitted", reason: `this session's MCP admission could not be read (${err.message}); no MCP tool may run` };
  }
  const ref = mcpToolRef(session, tool);
  return ref ? session.verdict(ref.server, ref.tool, normalizeMcpName) : session.verdict("", "", normalizeMcpName);
}

// ------------------------------------------------------------------ the proxy's reports

/** Write a violation the launcher acts on (the MCP proxy's report). */
export function reportViolation(eventsDir, event) {
  fs.mkdirSync(eventsDir, { recursive: true, mode: 0o700 });
  const f = path.join(eventsDir, `${Date.now()}-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(f, JSON.stringify({ ...event, at: Date.now(), pid: process.pid }), { mode: 0o600 });
  return f;
}

/** Poll the session's MCP violation reports; `onViolation(event)` once. */
export function watchMcpEvents(eventsDir, onViolation, { intervalMs = 300 } = {}) {
  let fired = false;
  const check = () => {
    if (fired) {
      return;
    }
    let names = [];
    try {
      names = fs.readdirSync(eventsDir).filter((f) => f.endsWith(".json")).sort();
    } catch {
      return;
    }
    if (names.length) {
      fired = true;
      const ev = readJson(path.join(eventsDir, names[0])) ?? { reason: "an unreadable violation report" };
      onViolation(ev);
    }
  };
  const t = setInterval(check, intervalMs);
  t.unref?.();
  return { check, stop: () => clearInterval(t) };
}
