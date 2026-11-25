// ecwcode-mcp-proxy: the stdio MCP server Claude Code starts in place of an
// admitted server (mcp.mjs). The decisions are the Enclawed adapter kit's:
//
//   - The real server starts only through kit.launchMcpServer, with the
//     containment part of its SIGNED admission record (folders, programs,
//     package tree, environment, secrets, destinations). No containment part:
//     it does not start (mcp-server-not-contained); a machine that cannot
//     contain: it does not start (containment-unavailable). The proxy then
//     answers every request with the refusal, so Claude Code shows it.
//   - Its code is checked again right before it starts (mcp-code-pins.mjs:
//     kit.codePinProblem, kit.localCodeProblem, the _npx tree).
//   - Every tools/list answer goes to kit.McpSession.observe: a changed
//     definition (a rug pull), a tool that was not pinned or a withdrawn tool
//     revokes it, and the session is stopped.
//   - A tools/call for a tool that is not a pinned, unrevoked tool
//     (kit.McpSession.verdict) is answered with an error here and never
//     reaches the server. Every other tools/call runs inside
//     kit.bracketMcpCall, one at a time: the containment's relay lets a
//     request out only while that call is in flight.
//   - The `initialize` answer must report the pinned server name and version
//     (kit McpSession.identityProblem).
//   - A remote (http / sse) server is connected, never started: through
//     kit.connectRemoteMcpServer with the signed remote part of its record
//     (the same URL and transport; OAuth endpoints off the server's site
//     refused unless the record names them), every tools/call body through
//     Enclawed's egress pipeline first.
//   - Repository configuration a contained git checks out holds the session
//     at once; the launcher re-admits it (repo-config-relay.mjs).
//
// On a violation the proxy answers the request with an error instead of the
// server's answer, refuses every later call, and reports the violation in
// the session's mcp-events directory; the launcher then stops the session
// (launcher.mjs). A forged report can only stop a session, never admit
// anything.
//
// Its configuration comes from the session file named on its command line,
// checked like the hook's (owner, mode, SHA-256 digest).

import fs from "node:fs";
import path from "node:path";
import { kit } from "./kit.mjs";
import { checkCodePin, measuredLaunch } from "./mcp-code-pins.mjs";
import { definitionCwd, launchEnv, mcpSessionOf, normalizeMcpName, remoteConnectSeam, remoteCredentialsFor, reportViolation, startContained } from "./mcp.mjs";
import { forwardRepoConfigEvent, watchRepoConfigWrites } from "./repo-config-relay.mjs";
import { readSession } from "./session.mjs";

function argOf(argv, name) {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
}

function lineReader(stream, onLine) {
  let buf = "";
  stream.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (line.trim()) {
        onLine(line);
      }
    }
  });
}

/** The definition a session entry stands for (its environment as the proxy received it). */
function definitionOf(server, env) {
  return { type: "stdio", command: server.command, args: server.args ?? [], env: Object.fromEntries((server.envKeys ?? []).filter((k) => typeof env[k] === "string").map((k) => [k, env[k]])) };
}

/** The session entry's code still matches its pin, right before the server starts (kit checks; the _npx tree). */
export function verifyLaunchCode(server, { env = process.env, cwd = process.cwd() } = {}) {
  const v = checkCodePin(definitionOf(server, env), server.code ?? null, { env, cwd: server.cwd ? path.resolve(cwd, server.cwd) : cwd });
  if (!v.ok) {
    return { ok: false, reason: `the server's code changed after admission or cannot be checked: ${v.reason}` };
  }
  const startsAs = (l) => (l ? JSON.stringify([l.kind ?? null, l.script ?? null, l.command ?? null, l.args ?? null]) : null);
  if (startsAs(server.launch) !== startsAs(v.launch)) {
    return { ok: false, reason: "the verified install moved after admission" };
  }
  return { ok: true, launch: v.launch };
}

function recordContainmentEvent(file, server, e) {
  // Repository configuration checked out (or refused) inside this server's
  // containment: the session holds at once (kit.handleRepoConfigEvent), and
  // the event goes to the launcher, which runs its launch admission again
  // over the files (and asks a person about a conflict) and releases the
  // hold when they are admissible (repo-config-relay.mjs).
  if (e?.code === "containment-repo-config-changed" || e?.code === "containment-repo-config-refused") {
    const sessionDir = path.dirname(file);
    void kit
      .handleRepoConfigEvent(e, {
        hold: kit.fileHoldStore(path.join(sessionDir, "repo-config-hold.json")),
        admit: async () => ({ ok: false, refusals: ["waiting for Enclawed Code's launcher to admit it again"] }),
      })
      .catch(() => {})
      .then(() => forwardRepoConfigEvent(sessionDir, `mcp:${server}`, e))
      .catch(() => {});
  }
  try {
    const a = kit.containmentAuditOf(e);
    fs.appendFileSync(file, `${JSON.stringify({ type: `claude-code.mcp.${a.type}`, server, payload: a.payload, at: Date.now() })}\n`, { mode: 0o600 });
  } catch {
    /* the containment's own decision stands; only the record is lost */
  }
}

/**
 * Run the proxy. `launch` is the kit's containment seam (kit.launchMcpServer),
 * replaceable only in-process (tests); `input`/`output` are the client's
 * stdio.
 */
export async function runProxy({ argv = process.argv.slice(2), env = process.env, input = process.stdin, output = process.stdout, errput = process.stderr, launch = kit.launchMcpServer, exit = (c) => process.exit(c) } = {}) {
  const fail = (msg) => {
    errput.write(`ecwcode-mcp-proxy: ${msg}\n`);
    exit(2);
  };
  let session;
  try {
    session = readSession(argOf(argv, "--session"), argOf(argv, "--digest"));
  } catch (err) {
    fail(`the session file could not be verified: ${err.message}`);
    return;
  }
  const name = argOf(argv, "--server");
  const server = session.mcp?.servers?.[name];
  if (!server) {
    fail(`the MCP server ${JSON.stringify(name)} was not admitted for this session`);
    return;
  }
  const normalized = server.normalized ?? normalizeMcpName(name);
  let mcp;
  try {
    mcp = mcpSessionOf({ servers: { [name]: server } });
  } catch (err) {
    fail(`${name}: its admission cannot be read: ${err.message}`);
    return;
  }
  const eventsDir = session.mcp.events;
  let tripped = null;
  const violation = (reason, extra = {}) => {
    if (!tripped) {
      tripped = reason;
      errput.write(`ecwcode-mcp-proxy: ${name}: ${reason}; refusing every further call and stopping the session\n`);
      try {
        reportViolation(eventsDir, { server: name, reason, ...extra });
      } catch {
        /* the refusal below stands either way */
      }
    }
  };
  const toClient = (msg) => output.write(`${JSON.stringify(msg)}\n`);
  const errorTo = (id, message) => toClient({ jsonrpc: "2.0", id, error: { code: -32001, message: `Enclawed: ${message}` } });

  // A remote server: connected through Enclawed's remote transport, never started here.
  if (server.remote !== undefined) {
    return runRemote({ name, server, normalized, mcp, input, violation, errorTo, toClient, tripped: () => tripped, exit, env });
  }
  // The pinned code, checked right before the server starts.
  const code = verifyLaunchCode(server, { env });
  if (!code.ok) {
    violation(code.reason);
    fail(`${name}: ${code.reason}; not starting it`);
    return;
  }
  // A pinned package-runner server: the measured tree, started without its
  // runner (the runner never resolves anything at launch).
  const measured = measuredLaunch(server.launch ?? null, server.command);
  const started = await startContained({
    name,
    command: measured ? measured.command : server.command,
    args: measured ? measured.args : server.args,
    env: launchEnv(definitionOf(server, env).env, measured),
    cwd: definitionCwd(server, process.cwd()),
    containment: server.containment,
    stateDir: session.mcp.containment ?? path.join(path.dirname(eventsDir), "containment"),
    launch,
    // The containment's events (kit.containmentAuditOf: a closed set of
    // types), kept next to the session for the launcher's audit log.
    onEvent: (e) => recordContainmentEvent(path.join(path.dirname(eventsDir), "containment-events.jsonl"), name, e),
    stdio: ["pipe", "pipe", "inherit"],
  });
  if (!started.ok) {
    // Not started. Every request is answered with the refusal (Claude Code shows it).
    const refusal = `${started.message} (${started.code})`;
    errput.write(`ecwcode-mcp-proxy: ${refusal}\n`);
    lineReader(input, (line) => {
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        return;
      }
      if (msg && typeof msg.method === "string" && msg.id !== undefined) {
        errorTo(msg.id, refusal);
      }
    });
    input.on("end", () => exit(2));
    return { refused: started.code };
  }
  const { child, containment } = started;
  // A conflict a person resolved at the launcher's prompt: one write of that
  // path is let through, by this server's containment only.
  const writes = watchRepoConfigWrites(path.dirname(eventsDir), `mcp:${name}`, (p) => containment.approveRepoConfigWrite(p));
  child.on("error", (err) => fail(`cannot start ${server.command}: ${err.message}`));
  child.on("exit", (c, signal) => {
    writes.stop();
    void containment.close();
    exit(c ?? (signal ? 1 : 0));
  });
  const toServer = (line) => child.stdin.write(`${line}\n`);

  // id -> what the answer is checked for.
  const watched = new Map();
  // tools/list pages of the listing in progress (a listing is complete at the page without nextCursor).
  let listing = [];
  // tools/call: each inside kit.bracketMcpCall (the containment's runCall:
  // one call in flight per server, the relay binds every outbound request to it).
  const answers = new Map();
  const runCall = (msg, line) => {
    const call = { callId: `${String(msg.id)}`, tool: msg.params.name, arguments: msg.params?.arguments ?? {} };
    kit
      .bracketMcpCall(containment, call, () => {
        if (tripped) {
          errorTo(msg.id, `this MCP server was stopped: ${tripped}`);
          return Promise.resolve();
        }
        return new Promise((resolve) => {
          answers.set(msg.id, resolve);
          toServer(line);
        });
      })
      .catch((err) => errorTo(msg.id, `the call could not be run contained: ${err?.message ?? err}`));
  };
  const settle = (id) => {
    const r = answers.get(id);
    if (r) {
      answers.delete(id);
      r();
    }
  };

  lineReader(input, (line) => {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      toServer(line);
      return;
    }
    if (msg && typeof msg === "object" && msg.method === "notifications/cancelled") {
      settle(msg.params?.requestId);
    }
    if (msg && typeof msg === "object" && typeof msg.method === "string" && msg.id !== undefined) {
      if (tripped && msg.method !== "initialize") {
        errorTo(msg.id, `this MCP server was stopped: ${tripped}`);
        return;
      }
      if (msg.method === "tools/call") {
        const tool = msg.params?.name;
        const v = typeof tool === "string" ? mcp.verdict(normalized, normalizeMcpName(tool), normalizeMcpName) : { code: "mcp-tool-not-pinned", reason: "the call names no tool" };
        if (v) {
          errorTo(msg.id, `the tool ${JSON.stringify(String(tool)).slice(0, 120)} is not pinned for this server or was revoked (${v.code}): ${v.reason}`);
          return;
        }
        runCall(msg, line);
        return;
      }
      if (msg.method === "initialize" || msg.method === "tools/list") {
        watched.set(msg.id, { method: msg.method, cursor: msg.params?.cursor ?? null });
      }
    }
    toServer(line);
  });
  input.on("end", () => {
    try {
      child.stdin.end();
    } catch {
      /* gone */
    }
  });

  // Pages before the last cannot show a withdrawn tool (a fresh session judges
  // the rest of the page); the complete listing goes to this session's pins.
  const checkListing = (page, last) => {
    if (!last) {
      listing.push(...page);
      return mcpSessionOf({ servers: { [name]: server } })
        .observe(normalized, page)
        .filter((d) => d.code !== "removed");
    }
    const all = [...listing, ...page];
    listing = [];
    return mcp.observe(normalized, all);
  };
  // The kit's sentence for a revoked tool; a tool that was never pinned has none.
  const driftReason = (d) => (d.code !== "not-pinned" && mcp.verdict(normalized, normalizeMcpName(d.tool), normalizeMcpName)?.reason) || `the MCP server ${JSON.stringify(name)} offered the tool ${JSON.stringify(d.tool)}, which was not part of its admission; it is refused`;

  lineReader(child.stdout, (line) => {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      output.write(`${line}\n`);
      return;
    }
    if (msg && msg.id !== undefined && !msg.method) {
      settle(msg.id);
    }
    const w = msg && msg.id !== undefined && !msg.method ? watched.get(msg.id) : undefined;
    if (w) {
      watched.delete(msg.id);
      if (w.method === "initialize" && msg.result) {
        // The server must be the one admitted (kit McpSession.identityProblem).
        const wrong = mcp.identityProblem(normalized, msg.result.serverInfo);
        if (wrong) {
          violation(wrong);
          errorTo(msg.id, `server identity mismatch: ${tripped}`);
          return;
        }
      }
      // An error answer lists nothing; a result without a tools array cannot be checked.
      if (w.method === "tools/list" && msg.result) {
        if (w.cursor === null) {
          listing = [];
        }
        const page = Array.isArray(msg.result.tools) ? msg.result.tools : null;
        const drifts = page ? checkListing(page, !msg.result.nextCursor) : mcp.revokeAll(normalized);
        if (drifts.length) {
          const d = drifts[0];
          violation(page ? driftReason(d) : "its tools/list answer could not be checked", { kind: d.code === "definition-changed" ? "rug-pull" : `tool-${d.code}`, drifts: drifts.slice(0, 20) });
          errorTo(msg.id, tripped);
          return;
        }
      }
    }
    output.write(`${line}\n`);
  });
  return { child, containment };
}

/**
 * The proxy for a remote (http / sse) server: kit.connectRemoteMcpServer with
 * the signed remote part of its record (the definition must name the same URL
 * and transport; endpoints of the server's OAuth metadata off its site are
 * refused unless the record names them), every tools/call body through
 * Enclawed's egress pipeline first, and the same identity and drift checks as
 * a local server. Not connected: every request is answered with the refusal.
 */
async function runRemote({ name, server, normalized, mcp, input, violation, errorTo, toClient, tripped, exit, env = process.env }) {
  // The definition's headers and the stored OAuth token, bound to the
  // server's origin (kit.remoteCredentials); never in the agent's environment.
  const def = { name, type: server.type ?? "http", url: server.url, ...(server.headers ? { headers: server.headers } : {}) };
  let c;
  try {
    c = kit.connectRemoteMcpServer(def, server.remote, { ...remoteConnectSeam(), credentials: server.remote ? await remoteCredentialsFor(def, server.remote, env) : null });
  } catch (err) {
    c = { ok: false, code: err?.code ?? "mcp-remote-header-invalid", message: err?.message ?? String(err) };
  }
  const refusal = c.ok ? null : `${c.message} (${c.code})`;
  const fail = (id, err) =>
    errorTo(id, `${err?.message ?? err}${err?.code ? ` (${err.code})` : ""}${err?.code === "oauth-required" ? `; authorize it in a terminal: ecwctl mcp login ${name}` : ""}`);
  let listing = [];
  const onList = (id, params, result) => {
    const page = Array.isArray(result?.tools) ? result.tools : null;
    if (!params?.cursor) {
      listing = [];
    }
    let drifts;
    if (!page) {
      drifts = mcp.revokeAll(normalized);
    } else if (result.nextCursor) {
      listing.push(...page);
      drifts = mcpSessionOf({ servers: { [name]: server } })
        .observe(normalized, page)
        .filter((d) => d.code !== "removed");
    } else {
      drifts = mcp.observe(normalized, [...listing, ...page]);
      listing = [];
    }
    if (drifts.length) {
      const d = drifts[0];
      const why = (d.code !== "not-pinned" && mcp.verdict(normalized, normalizeMcpName(d.tool), normalizeMcpName)?.reason) || `the MCP server ${JSON.stringify(name)} offered the tool ${JSON.stringify(d.tool)}, which was not part of its admission; it is refused`;
      violation(page ? why : "its tools/list answer could not be checked", { kind: d.code === "definition-changed" ? "rug-pull" : `tool-${d.code}`, drifts: drifts.slice(0, 20) });
      errorTo(id, tripped());
      return;
    }
    toClient({ jsonrpc: "2.0", id, result });
  };
  // One request at a time, in order (the remote session is one conversation).
  let queue = Promise.resolve();
  const handle = async (msg) => {
    if (refusal) {
      errorTo(msg.id, refusal);
      return;
    }
    if (tripped() && msg.method !== "initialize") {
      errorTo(msg.id, `this MCP server was stopped: ${tripped()}`);
      return;
    }
    try {
      if (msg.method === "initialize") {
        const result = await c.client.initialize();
        const wrong = mcp.identityProblem(normalized, result?.serverInfo);
        if (wrong) {
          violation(wrong);
          errorTo(msg.id, `server identity mismatch: ${tripped()}`);
          return;
        }
        toClient({ jsonrpc: "2.0", id: msg.id, result });
      } else if (msg.method === "tools/list") {
        onList(msg.id, msg.params, await c.client.request("tools/list", msg.params ?? {}));
      } else if (msg.method === "tools/call") {
        const tool = msg.params?.name;
        const v = typeof tool === "string" ? mcp.verdict(normalized, normalizeMcpName(tool), normalizeMcpName) : { code: "mcp-tool-not-pinned", reason: "the call names no tool" };
        if (v) {
          errorTo(msg.id, `the tool ${JSON.stringify(String(tool)).slice(0, 120)} is not pinned for this server or was revoked (${v.code}): ${v.reason}`);
          return;
        }
        const result = await c.callTool({ callId: String(msg.id), tool, arguments: msg.params?.arguments ?? {} });
        toClient({ jsonrpc: "2.0", id: msg.id, result });
      } else {
        toClient({ jsonrpc: "2.0", id: msg.id, result: await c.client.request(msg.method, msg.params ?? {}) });
      }
    } catch (err) {
      fail(msg.id, err);
    }
  };
  lineReader(input, (line) => {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    // Notifications from the client (initialized, cancelled) need no answer;
    // the remote client sends its own initialized notification.
    if (msg && typeof msg.method === "string" && msg.id !== undefined) {
      queue = queue.then(() => handle(msg));
    }
  });
  input.on("end", () => {
    void queue.then(() => {
      if (c.ok) {
        c.client.close();
      }
      exit(refusal ? 2 : 0);
    });
  });
  return Promise.resolve(c.ok ? { remote: c } : { refused: c.code });
}

export async function main(argv = process.argv.slice(2)) {
  const r = await runProxy({ argv });
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"]) {
    process.on(sig, () => {
      try {
        r?.child?.kill(sig);
      } catch {
        /* gone */
      }
      if (!r?.child) {
        process.exit(1);
      }
    });
  }
}
