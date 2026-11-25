// `ecwctl skills|mcp|trust ...` (also `ecwctl ...`):
// the signed admission records the launcher checks before a session starts.
//
//   skills list|verify [--json] [--add-dir D]... [--plugin-dir D]...
//   skills sign <name>... | --all     produce and store a skill's signed formal bundle
//   skills unsign <name>              remove a skill's bundle
//   mcp list [--json] [--mcp-config F]...
//   mcp pin <name> --containment F [--roles R] [--mcp-config F]...
//                                     start the server once (contained), pin its
//                                     identity, code, tools, argument roles and
//                                     containment in one signed record
//   mcp pin <remote> [--authorization-origin O]...
//                                     a remote (http / sse) server: read it once
//                                     through Enclawed's remote transport, pin its
//                                     identity, tools and remote part (URL,
//                                     transport, authorization origins)
//   mcp import <file>                 store a record attested by a trusted signer
//   mcp unpin <name> | show <name>
//   trust list | add <key-id> <public-key.pem> [--label L] | remove <key-id>
//
// Every change needs two-factor authentication and is recorded in the audit
// log. The records, their checks and the trust list are the Enclawed adapter
// kit's (kit.pinMcpServer, kit.importMcpRecord, kit.unpinMcpServer,
// kit.addSigner, kit.removeSigner); this file is the command line. Nothing here runs inside a session: the agent cannot reach these
// files (they are in Enclawed Code's protected state directory).

import fs from "node:fs";
import path from "node:path";
import { verifyUser } from "./auth.mjs";
import { UsageError, isInteractive, parseFlags } from "./cli-util.mjs";
import { loadFormal } from "./formal.mjs";
import { kit } from "./kit.mjs";
import { codeIdentity } from "./mcp-code-pins.mjs";
import { BUILTIN_TOOL_NAMES, admitServers, candidateServers, isRemoteDefinition, mcpStoreDir, pinFile, pinInput, pinStore, probeServer, readPins, remoteConnectSeam, remoteCredentialStoreFor, remotePart } from "./mcp.mjs";
import { realpathNearest } from "./paths.mjs";
import { discoverSkills, signSkill, unsignSkill, verifyAll } from "./skills.mjs";
import { addSigner, ensureLocalSigner, readSigners, removeSigner, signersFile } from "./trust.mjs";

export const ADMISSION_HELP = `usage:
  ecwctl skills list|verify [--json] [--add-dir D]... [--plugin-dir D]...
  ecwctl skills sign <name>... | --all [--add-dir D]... [--plugin-dir D]...
  ecwctl skills unsign <name>
  ecwctl mcp list [--json] [--mcp-config F]...
  ecwctl mcp pin <name> --containment <file.json> [--roles git|filesystem|fetch|<file.json>] [--mcp-config F]...
  ecwctl mcp pin <remote name> [--authorization-origin https://...]... [--client-id ID] [--scope S] [--roles <file.json>] [--mcp-config F]...
  ecwctl mcp login <remote name> [--mcp-config F]...
  ecwctl mcp import <file> | unpin <name> | show <name>
  ecwctl trust list | add <key-id> <public-key.pem> [--label L] | remove <key-id>
`;

// Trust decisions are policy changes: two-factor authentication, no ticket.
async function authorize(ctx) {
  await verifyUser({ purpose: "policy-change", env: ctx.env, interactive: isInteractive(), audit: ctx.audit, allowTicket: false });
}

function skillScope(flags, cwd) {
  return {
    projectDir: realpathNearest(path.resolve(cwd)),
    addDirs: (flags["--add-dir"] ?? []).map((d) => realpathNearest(path.resolve(cwd, d))),
    pluginDirs: (flags["--plugin-dir"] ?? []).map((d) => path.resolve(cwd, d)),
  };
}

async function skillsCommand(args, ctx) {
  const { out, err, env, fw, audit } = ctx;
  const sub = args[0];
  const rest = args.slice(1);
  const cwd = process.cwd();
  if (sub === "list" || sub === "verify") {
    const { flags, positionals } = parseFlags(rest, { bool: ["--json"], multi: ["--add-dir", "--plugin-dir"] });
    const formal = await loadFormal();
    const discovered = discoverSkills({ ...skillScope(flags, cwd), env });
    let results = verifyAll({ formal, discovered, env });
    if (positionals.length) {
      results = results.filter((r) => positionals.includes(r.name));
    }
    if (flags["--json"]) {
      out.write(`${JSON.stringify(results, null, 2)}\n`);
    } else if (results.length === 0) {
      out.write("no skills: Claude Code would load none here\n");
    } else {
      for (const r of results) {
        out.write(`${r.status === "verified" ? "ok " : "!! "} ${r.status.padEnd(10)} ${r.name} (${r.scope}) ${r.dir}\n`);
        if (r.status === "verified") {
          out.write(`     capabilities: ${r.caps.join(", ") || "none"}; signed by ${r.signer}\n`);
        }
        for (const why of r.reasons) {
          out.write(`     ${why}\n`);
        }
      }
    }
    return sub === "verify" && results.some((r) => r.status !== "verified") ? 1 : 0;
  }
  if (sub === "sign") {
    const { flags, positionals } = parseFlags(rest, { bool: ["--all"], multi: ["--add-dir", "--plugin-dir"] });
    if (!flags["--all"] && positionals.length === 0) {
      throw new UsageError("skills sign needs skill names (see: ecwctl skills list) or --all");
    }
    const formal = await loadFormal();
    const discovered = discoverSkills({ ...skillScope(flags, cwd), env });
    const chosen = flags["--all"] ? discovered.skills : discovered.skills.filter((s) => positionals.includes(s.name));
    const missing = positionals.filter((n) => !discovered.skills.some((s) => s.name === n));
    if (missing.length) {
      throw new UsageError(`no skill named ${missing.join(", ")} would load here (see: ecwctl skills list)`);
    }
    // Check every chosen skill before asking for the key: a skill that does
    // not satisfy the biconditional is never signed.
    const { biconditional, skillManifest } = await import("./skills.mjs");
    for (const s of chosen) {
      const { manifest, problems } = skillManifest(s);
      const a = formal.static.methodA({ dir: s.dir, declaredCaps: manifest.caps });
      const bi = biconditional(a, manifest.caps);
      out.write(`${s.name} (${s.scope}) ${s.dir}\n  declared: ${manifest.caps.join(", ") || "none"}; implementation: ${a.unionEffects.join(", ") || "none"}; ${Object.keys(manifest.files).length} files, content ${manifest.contentDigest.slice(0, 16)}…\n`);
      if (problems.length || !bi.pass) {
        err.write(`ecwctl: ${s.name} is not signed: ${[...problems, ...bi.reasons].join("; ")}\n`);
        return 1;
      }
    }
    await authorize(ctx);
    const signer = await ensureLocalSigner(fw, env);
    for (const s of chosen) {
      const r = await signSkill({ formal, skill: s, signer, env });
      await audit({ type: "claude-code.skills.sign", actor: "enclawed-code", level: null, payload: { name: s.name, scope: s.scope, dir: s.dir, caps: r.manifest.caps, contentDigest: r.manifest.contentDigest, manifestHash: r.attestation.manifestHash, signer: signer.keyId } });
      out.write(`signed ${s.name}: formal bundle in ${r.bundleDir} (signer ${signer.keyId})\n`);
    }
    return 0;
  }
  if (sub === "unsign") {
    const { flags, positionals } = parseFlags(rest, { multi: ["--add-dir", "--plugin-dir"], maxPositionals: 1 });
    const discovered = discoverSkills({ ...skillScope(flags, cwd), env });
    const s = discovered.skills.find((x) => x.name === positionals[0]);
    if (!s) {
      throw new UsageError(`no skill named ${positionals[0] ?? "(none)"} would load here`);
    }
    await authorize(ctx);
    const had = await unsignSkill(s, env);
    await audit({ type: "claude-code.skills.unsign", actor: "enclawed-code", level: null, payload: { name: s.name, scope: s.scope, dir: s.dir, had } });
    out.write(had ? `removed the bundle of ${s.name}; it is unverified again\n` : `${s.name} had no bundle\n`);
    return 0;
  }
  err.write(ADMISSION_HELP);
  return 2;
}

/** The containment the operator declares for a server (kit.isContainmentRecord checks its shape). */
function readContainment(file) {
  if (!file) {
    throw new UsageError("mcp pin needs --containment <file.json>: the folders, programs, environment, secrets and destinations the server may use (a server whose record declares none does not start)");
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(path.resolve(file), "utf8"));
  } catch (e) {
    throw new UsageError(`cannot read the containment declaration ${file}: ${e.message}`);
  }
  if (!kit.isContainmentRecord(doc)) {
    throw new UsageError(`${file} is not a containment declaration: { "roots": [{ "path": "/abs", "access": "ro"|"rw", "exec"?: bool }], "packageRoot"?, "programs"?, "cwd"?, "env"?, "secrets"?, "destinations"?: [{ "host", "port", "mode": "inspect"|"http"|"opaque" }] }`);
  }
  return doc;
}

/** Argument roles: a reference server's map (kit.REFERENCE_ARGUMENT_ROLES) or a JSON file. */
function readRoles(v) {
  if (!v) {
    return null;
  }
  if (Object.hasOwn(kit.REFERENCE_ARGUMENT_ROLES, v)) {
    return kit.REFERENCE_ARGUMENT_ROLES[v];
  }
  try {
    return JSON.parse(fs.readFileSync(path.resolve(v), "utf8"));
  } catch (e) {
    throw new UsageError(`--roles is ${Object.keys(kit.REFERENCE_ARGUMENT_ROLES).join(", ")} or a JSON file of { tool: { argument: role } }: ${e.message}`);
  }
}

/**
 * `mcp pin` for a remote (http / sse) server: read its identity and tools
 * once through Enclawed's remote transport, then sign the record with its
 * remote part (URL, transport, and the authorization origins on another site
 * the operator names). The session's proxy connects only with that part
 * (kit.connectRemoteMcpServer).
 */
/**
 * Authorize Enclawed Code for a remote server that asks for OAuth
 * (kit.authorizeRemoteMcpServer): the authorization URL is printed for the
 * person to open (never opened here), the answer comes back to a loopback
 * listener, and the tokens go to Enclawed's credential store.
 */
async function authorizeRemote(name, def, remote, ctx) {
  const { out, err, env } = ctx;
  const store = await remoteCredentialStoreFor(env);
  const r = await kit.authorizeRemoteMcpServer({ ...def, name }, remote, {
    store,
    env,
    ...remoteConnectSeam(),
    ...(ctx.oauthRedirect ? { redirect: ctx.oauthRedirect } : {}),
    show: (url) => {
      out.write(`${name} asks for authorization. Open this address in your browser yourself (Enclawed Code does not open it):\n\n  ${url}\n\nwaiting for the answer...\n`);
      ctx.onAuthorizationUrl?.(url);
    },
  });
  await store.settled?.();
  await ctx.audit({ type: "claude-code.mcp.oauth", actor: "enclawed-code", level: null, payload: { name, url: remote.url, ...(r.ok ? { action: r.action, registered: r.registered } : { code: r.code }) } });
  if (!r.ok) {
    err.write(`ecwctl: ${name} is not authorized: ${r.message} (${r.code})\n`);
  } else if (r.action === "authorized") {
    out.write(`${name}: authorized; the tokens are kept in Enclawed's credential store\n`);
  }
  return r.ok;
}

async function pinRemote({ name, c, roles, origins, oauth, containmentFlag, projectDir }, ctx) {
  const { out, err, env, fw, audit } = ctx;
  if (containmentFlag) {
    throw new UsageError(`${name} is a remote server: nothing of it runs on this machine, so it takes no --containment (its calls go through Enclawed's egress checks)`);
  }
  let remote;
  try {
    remote = remotePart(c.def, origins, oauth);
  } catch (e) {
    throw new UsageError(`${name} cannot be pinned: ${e.message}`);
  }
  if (!(await authorizeRemote(name, c.def, remote, ctx))) {
    return 1;
  }
  out.write(`connecting to ${name} once (${remote.transport} ${remote.url}, ${c.scope}) to read its identity and tools...\n`);
  let probe;
  try {
    probe = await probeServer(c.def, { env, cwd: projectDir, name, remote });
  } catch (e) {
    err.write(`ecwctl: ${name} is not pinned: ${e.message}\n`);
    await audit({ type: "claude-code.mcp.pin-refused", actor: "enclawed-code", level: null, payload: { name, problems: [String(e.code ?? "remote-probe-failed"), String(e.message).slice(0, 300)] } });
    return 1;
  }
  out.write(`server: ${probe.serverInfo.name ?? "(no name)"} ${probe.serverInfo.version ?? ""}; ${probe.tools.length} tools: ${probe.tools.map((t) => t.name).join(", ")}\n`);
  const input = pinInput({ name, def: c.def, scope: c.scope, source: c.source, probe, env, cwd: projectDir, roles, remote });
  const r = await kit.pinMcpServer({ ...pinStore(env), builtinToolNames: BUILTIN_TOOL_NAMES, authorize: () => authorize(ctx) }, input);
  if (!r.ok) {
    err.write(`ecwctl: ${name} is not pinned:\n${r.problems.map((p) => `  - ${p}`).join("\n")}\n`);
    await audit({ type: "claude-code.mcp.pin-refused", actor: "enclawed-code", level: null, payload: { name, problems: r.problems.slice(0, 20) } });
    return 1;
  }
  const stored = readPins(fw, env).find((p) => p.file === r.file);
  if (!stored?.ok) {
    fs.rmSync(r.file, { force: true });
    err.write(`ecwctl: ${name} is not pinned: ${stored?.reason ?? "the record could not be read back"}\n`);
    return 1;
  }
  await audit({ type: "claude-code.mcp.pin", actor: "enclawed-code", level: null, payload: { name, scope: c.scope, identity: r.record.identity, tools: r.record.tools, roles: r.record.args ?? null, remote: r.record.remote ?? null, signer: r.record.signerKeyId } });
  out.write(`pinned ${name}: ${Object.keys(r.record.tools).length} tools, remote (${remote.transport} ${remote.url}; ${r.file})\n`);
  return 0;
}

async function mcpCommand(args, ctx) {
  const { out, err, env, fw, audit } = ctx;
  const sub = args[0];
  const rest = args.slice(1);
  const projectDir = realpathNearest(process.cwd());
  if (sub === "list") {
    const { flags } = parseFlags(rest, { bool: ["--json"], multi: ["--mcp-config"], maxPositionals: 0 });
    const candidates = candidateServers({ projectDir, env, mcpConfigValues: flags["--mcp-config"] ?? [] });
    const adm = admitServers({ fw, env, candidates, cwd: projectDir });
    const pins = readPins(fw, env);
    // What keeps a valid record from starting its server is the kit's (mcpRecordProblems).
    const problems = kit.mcpRecordProblems(pins.filter((p) => p.ok && p.record).map((p) => p.record));
    const summary = { pins: pins.map((p) => ({ file: p.file, name: p.record?.name ?? null, ok: p.ok, reason: p.reason, signer: p.signer, tools: Object.keys(p.record?.tools ?? {}), remote: p.record?.remote ?? null, contained: Boolean(p.record?.containment), startProblem: problems.find((x) => p.ok && x.name === p.record?.name)?.why ?? null })), admission: adm.ok ? { admitted: adm.admitted.map((a) => a.name), skipped: adm.skipped } : { refused: adm.message } };
    if (flags["--json"]) {
      out.write(`${JSON.stringify(summary, null, 2)}\n`);
      return 0;
    }
    out.write(`admission records (${mcpStoreDir(env)}):\n`);
    for (const p of summary.pins) {
      out.write(`  ${p.ok && !p.startProblem ? "ok " : "!! "} ${p.name ?? path.basename(p.file)}: ${p.ok ? `${p.tools.length} pinned tools, signed by ${p.signer}${p.remote ? `, remote ${p.remote.transport} ${p.remote.url}` : ""}${p.startProblem ? `; it does not start: ${p.startProblem}` : ""}` : p.reason}\n`);
    }
    if (!summary.pins.length) {
      out.write("  none\n");
    }
    if (adm.ok) {
      out.write(`a session here would start: ${adm.admitted.map((a) => a.name).join(", ") || "no MCP server"}\n`);
      for (const x of adm.skipped) {
        out.write(`  not started: ${x.name} (${x.scope}): ${x.why}\n`);
      }
    } else {
      out.write(`a session here would be refused: ${adm.message}\n`);
    }
    return 0;
  }
  if (sub === "login") {
    // A remote server asks for authorization again (its refresh token expired
    // or was refused): the same flow as at pin time, with the signed remote part.
    const { flags, positionals } = parseFlags(rest, { multi: ["--mcp-config"], maxPositionals: 1 });
    const name = positionals[0];
    const c = candidateServers({ projectDir, env, mcpConfigValues: flags["--mcp-config"] ?? [] }).find((x) => x.name === name);
    if (!c || !isRemoteDefinition(c.def)) {
      throw new UsageError(`mcp login needs the name of a remote (http / sse) server in your Claude Code configuration`);
    }
    const pin = readPins(fw, env).find((p) => p.ok && p.record?.name === name && p.record?.remote);
    if (!pin) {
      throw new UsageError(`${name} is not pinned: pin it first (ecwctl mcp pin ${name})`);
    }
    return (await authorizeRemote(name, c.def, pin.record.remote, ctx)) ? 0 : 1;
  }
  if (sub === "pin") {
    const { flags, positionals } = parseFlags(rest, { value: ["--containment", "--roles", "--client-id", "--scope"], multi: ["--mcp-config", "--authorization-origin"], maxPositionals: 1 });
    const name = positionals[0];
    if (!name) {
      throw new UsageError("mcp pin needs a server name (as in your Claude Code MCP configuration)");
    }
    const candidates = candidateServers({ projectDir, env, mcpConfigValues: flags["--mcp-config"] ?? [] }).filter((c) => c.name === name);
    if (candidates.length === 0) {
      throw new UsageError(`no MCP server named ${JSON.stringify(name)} in your Claude Code configuration, this project's .mcp.json or the given --mcp-config`);
    }
    const c = candidates[0];
    const roles = readRoles(flags["--roles"]);
    if (isRemoteDefinition(c.def)) {
      return pinRemote({ name, c, roles, origins: flags["--authorization-origin"] ?? [], oauth: { clientId: flags["--client-id"], scope: flags["--scope"] }, containmentFlag: flags["--containment"], projectDir }, ctx);
    }
    if (flags["--authorization-origin"] || flags["--client-id"] || flags["--scope"]) {
      throw new UsageError("--authorization-origin, --client-id and --scope are for remote (http / sse) servers only");
    }
    const containment = readContainment(flags["--containment"]);
    // Resolve-at-launch forms are refused BEFORE the server is started once
    // (postmark-mcp 1.0.16: `npx postmark-mcp` would run whatever the
    // registry serves). The probe is contained, so an exact npx version must
    // already be in npx's cache.
    const pre = codeIdentity(c.def, { env, cwd: projectDir, pin: true });
    if (!pre.ok) {
      err.write(`ecwctl: ${name} is not pinned: ${pre.problem}. To pin it, ${pre.how}\n`);
      await audit({ type: "claude-code.mcp.pin-refused", actor: "enclawed-code", level: null, payload: { name, problems: [pre.code, pre.problem.slice(0, 300)] } });
      return 1;
    }
    out.write(`starting ${name} once, contained (${c.scope}, ${c.source}), to read its identity and tools...\n`);
    let probe;
    try {
      probe = await probeServer(c.def, { env, cwd: projectDir, name, containment, code: pre });
    } catch (e) {
      err.write(`ecwctl: ${name} is not pinned: ${e.message}\n`);
      return 1;
    }
    out.write(`server: ${probe.serverInfo.name ?? "(no name)"} ${probe.serverInfo.version ?? ""}; ${probe.tools.length} tools: ${probe.tools.map((t) => t.name).join(", ")}\n`);
    let input;
    try {
      input = pinInput({ name, def: c.def, scope: c.scope, source: c.source, probe, env, cwd: projectDir, containment, roles, code: pre });
    } catch (e) {
      err.write(`ecwctl: ${e.message}\n`);
      return 1;
    }
    // kit.pinMcpServer refuses a flagged or shadowing tool set before asking
    // for the second factor, then signs the record (containment and roles
    // inside the signature) with the local signer.
    const r = await kit.pinMcpServer({ ...pinStore(env), builtinToolNames: BUILTIN_TOOL_NAMES, authorize: () => authorize(ctx) }, input);
    if (!r.ok) {
      err.write(`ecwctl: ${name} is not pinned:\n${r.problems.map((p) => `  - ${p}`).join("\n")}\n`);
      await audit({ type: "claude-code.mcp.pin-refused", actor: "enclawed-code", level: null, payload: { name, problems: r.problems.slice(0, 20) } });
      return 1;
    }
    // The kit's loader must accept what was stored (it checks the shapes of the roles and the containment).
    const stored = readPins(fw, env).find((p) => p.file === r.file);
    if (!stored?.ok) {
      fs.rmSync(r.file, { force: true });
      err.write(`ecwctl: ${name} is not pinned: ${stored?.reason ?? "the record could not be read back"}\n`);
      return 1;
    }
    await audit({ type: "claude-code.mcp.pin", actor: "enclawed-code", level: null, payload: { name, scope: c.scope, identity: r.record.identity, code: r.record.code ?? null, tools: r.record.tools, roles: r.record.args ?? null, containment: r.record.containment ?? null, signer: r.record.signerKeyId } });
    out.write(`pinned ${name}: ${Object.keys(r.record.tools).length} tools, contained (${r.file})\n`);
    return 0;
  }
  if (sub === "import") {
    const { positionals } = parseFlags(rest, { maxPositionals: 1 });
    if (!positionals[0]) {
      throw new UsageError("mcp import needs an attested admission record (a JSON file)");
    }
    const rec = JSON.parse(fs.readFileSync(path.resolve(positionals[0]), "utf8"));
    const r = await kit.importMcpRecord({ ...pinStore(env), authorize: () => authorize(ctx) }, rec);
    if (!r.ok) {
      err.write(`ecwctl: not imported: ${r.problems.join("; ")}\n`);
      return 1;
    }
    await audit({ type: "claude-code.mcp.import", actor: "enclawed-code", level: null, payload: { name: rec.name, identity: rec.identity, tools: rec.tools, containment: rec.containment ?? null, signer: rec.signerKeyId } });
    out.write(`imported the attested record for ${rec.name} (signed by ${rec.signerKeyId})\n`);
    if (!rec.containment) {
      err.write(`ecwctl: ${rec.name} will not start: its record declares no containment (mcp-server-not-contained); ask its signer for a record with one\n`);
    }
    return 0;
  }
  if (sub === "unpin") {
    const { positionals } = parseFlags(rest, { maxPositionals: 1 });
    if (!positionals[0] || !(await kit.unpinMcpServer({ ...pinStore(env), authorize: () => authorize(ctx) }, positionals[0]))) {
      throw new UsageError(`no admission record for ${positionals[0] ?? "(none)"}`);
    }
    await audit({ type: "claude-code.mcp.unpin", actor: "enclawed-code", level: null, payload: { name: positionals[0] } });
    out.write(`removed the admission record for ${positionals[0]}; it no longer starts\n`);
    return 0;
  }
  if (sub === "show") {
    const { positionals } = parseFlags(rest, { maxPositionals: 1 });
    const f = pinFile(positionals[0] ?? "", env);
    if (!positionals[0] || !fs.existsSync(f)) {
      throw new UsageError(`no admission record for ${positionals[0] ?? "(none)"}`);
    }
    out.write(fs.readFileSync(f, "utf8"));
    return 0;
  }
  err.write(ADMISSION_HELP);
  return 2;
}

async function trustCommand(args, ctx) {
  const { out, err, env, audit } = ctx;
  const sub = args[0];
  const rest = args.slice(1);
  if (sub === "list") {
    parseFlags(rest, { maxPositionals: 0 });
    const list = readSigners(env);
    out.write(`trusted signers (${signersFile(env)}):\n`);
    for (const s of list) {
      out.write(`  ${s.keyId} (${s.origin}${s.label ? `, ${s.label}` : ""})\n`);
    }
    if (!list.length) {
      out.write("  none yet (the first `skills sign` or `mcp pin` creates this installation's own signer)\n");
    }
    return 0;
  }
  if (sub === "add") {
    const { flags, positionals } = parseFlags(rest, { value: ["--label"], maxPositionals: 2 });
    if (positionals.length !== 2) {
      throw new UsageError("trust add needs a key id and a public-key PEM file");
    }
    const pem = fs.readFileSync(path.resolve(positionals[1]), "utf8");
    await addSigner(env, { keyId: positionals[0], publicKeyPem: pem, label: flags["--label"] ?? "", origin: "imported" }, () => authorize(ctx));
    await audit({ type: "claude-code.trust.add", actor: "enclawed-code", level: null, payload: { keyId: positionals[0], label: flags["--label"] ?? "" } });
    out.write(`trusted ${positionals[0]}\n`);
    return 0;
  }
  if (sub === "remove") {
    const { positionals } = parseFlags(rest, { maxPositionals: 1 });
    if (!positionals[0]) {
      throw new UsageError("trust remove needs a key id");
    }
    const had = await removeSigner(env, positionals[0], () => authorize(ctx));
    await audit({ type: "claude-code.trust.remove", actor: "enclawed-code", level: null, payload: { keyId: positionals[0], had } });
    out.write(had ? `no longer trusted: ${positionals[0]} (records it signed are refused)\n` : `${positionals[0]} was not trusted\n`);
    return 0;
  }
  err.write(ADMISSION_HELP);
  return 2;
}

/** Dispatch `skills`, `mcp` and `trust`. */
export async function admissionCommand(group, args, ctx) {
  if (group === "skills") {
    return skillsCommand(args, ctx);
  }
  if (group === "mcp") {
    return mcpCommand(args, ctx);
  }
  return trustCommand(args, ctx);
}
