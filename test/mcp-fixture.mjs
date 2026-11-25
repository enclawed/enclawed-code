// Test support for MCP admission and containment: the fixture server in a
// directory of its own (the kit pins a script by its package's tree), its
// containment declaration, and an in-process stand-in for the kit's
// containment seam (kit.launchMcpServer) for hosts where the framework build
// cannot contain (no contain-init next to framework.js). The stand-in keeps
// the kit's contract: no record, no start; only the declared variables reach
// the server; every tools/call is bracketed (recorded in `calls`).
import fs from "node:fs";
import path from "node:path";
import { ROOT } from "./helpers.mjs";

export const FIXTURE_SOURCE = path.join(ROOT, "test", "fixtures", "mcp-server.mjs");
export const FIXTURE_ENV = ["MCP_FIXTURE_DESC_FILE", "MCP_FIXTURE_RUGPULL", "MCP_FIXTURE_LOG", "MCP_FIXTURE_EXTRA_TOOL", "MCP_FIXTURE_VERSION"];

/** Copy the fixture server into <sb.dir>/servers/<name>/ (with a package.json); returns its script. */
export function fixtureServer(sb, name = "notes") {
  const dir = path.join(sb.dir, "servers", name);
  fs.mkdirSync(dir, { recursive: true });
  fs.copyFileSync(FIXTURE_SOURCE, path.join(dir, "server.mjs"));
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: `${name}-fixture`, version: "1.0.0", type: "module" }));
  return path.join(dir, "server.mjs");
}

/** The containment a fixture server needs: its own directory read-only, the fixture's variables. */
export function fixtureContainment(script, extraRoots = []) {
  return { roots: [{ path: path.dirname(script), access: "ro", exec: true }, ...extraRoots], env: FIXTURE_ENV };
}

/** A stand-in for kit.launchMcpServer that runs the command directly (tests only, in-process). */
export function standInLaunch() {
  const calls = [];
  const launches = [];
  let queue = Promise.resolve();
  const launch = async (def, record) => {
    launches.push({ def, record });
    if (!record) {
      return { ok: false, code: "mcp-server-not-contained", message: `Enclawed: MCP server "${def.name}" was not started: its admission record declares no containment` };
    }
    const env = { PATH: process.env.PATH ?? "/usr/bin:/bin" };
    for (const k of record.env ?? []) {
      if (def.env && k in def.env) {
        env[k] = def.env[k];
      }
    }
    return {
      ok: true,
      containment: {
        argv: [def.command, ...def.args],
        env,
        // The kit's contract: one call in flight at a time (runCall queues).
        runCall: (c, run) => {
          const go = queue.then(async () => {
            calls.push({ begin: c.callId, tool: c.tool });
            try {
              return await run();
            } finally {
              calls.push({ end: c.callId });
            }
          });
          queue = go.catch(() => {});
          return go;
        },
        close: async () => {},
      },
    };
  };
  return { launch, calls, launches };
}

/** A line-oriented JSON-RPC client over a pair of streams. */
export function rpcClient(write) {
  const answers = [];
  let buf = "";
  const feed = (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (line.trim()) {
        answers.push(JSON.parse(line));
      }
    }
  };
  const send = (msg) => write(`${JSON.stringify(msg)}\n`);
  const wait = async (pred, tries = 100) => {
    for (let n = 0; n < tries && !answers.some(pred); n++) {
      await new Promise((r) => setTimeout(r, 50));
    }
    return answers.find(pred);
  };
  return { answers, feed, send, wait };
}
