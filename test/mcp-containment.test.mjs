import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// MCP containment (closure plan M1/M3): the proxy starts an admitted server
// only through the kit's launchMcpServer, with the containment part of its
// signed admission record, and brackets every tools/call (kit.bracketMcpCall).
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { PassThrough } from "node:stream";
import { after, before, test } from "node:test";
import { kit } from "../src/kit.mjs";
import { mcpSessionOf, mcpToolRef, mcpVerdict, pinRecord, readPins, sessionMcp, writePin } from "../src/mcp.mjs";
import { runProxy } from "../src/mcp-proxy.mjs";
import { createSession, updateSession } from "../src/session.mjs";
import { ensureLocalSigner } from "../src/trust.mjs";
import { ROOT, sandbox } from "./helpers.mjs";
import { fixtureContainment, fixtureServer, rpcClient, standInLaunch } from "./mcp-fixture.mjs";

let sb;
let env;
let script;
let def;
const PROBE = { serverInfo: { name: "notes-fixture", version: "1.0.0" }, tools: [] };
before(() => {
  sb = sandbox();
  env = { ...sb.env, HOME: sb.home };
  script = fixtureServer(sb);
  // The fixture logs what it is asked into a directory of its own, which a real
  // containment must declare writable (everything else it cannot see).
  fs.mkdirSync(path.join(sb.dir, "fixture-log"), { recursive: true });
  def = { type: "stdio", command: process.execPath, args: [script], env: { MCP_FIXTURE_LOG: path.join(sb.dir, "fixture-log", "fixture.log") } };
});
after(() => sb.cleanup());

// The fixture's one tool, exactly as it lists it (its pinned definition).
const NOTE_TOOL = { name: "note_lookup", description: "Look up a note by key and return its text.", inputSchema: { type: "object", properties: { key: { type: "string" } }, required: ["key"] } };

/** A session file whose MCP block admits `notes` with `containment` (null: none declared). */
function sessionWith(containment) {
  let s = createSession({ env, cwd: sb.project });
  const record = { ...pinRecord({ name: "notes", def, scope: "user", source: "t", probe: { ...PROBE, tools: [NOTE_TOOL] }, env, containment }), signerKeyId: "k" };
  const m = sessionMcp({ admitted: [{ name: "notes", def, record, normalized: "notes" }] }, { sessionDir: s.dir });
  s = updateSession(s, { mcp: m.session });
  return { s, m };
}

function inProcess(s, launch) {
  const input = new PassThrough();
  const output = new PassThrough();
  const rpc = rpcClient((t) => input.write(t));
  output.on("data", rpc.feed);
  const started = runProxy({ argv: ["--session", s.file, "--digest", s.digest, "--server", "notes"], env: { ...env, ...def.env }, input, output, errput: new PassThrough(), launch, exit: () => {} });
  return { rpc, started, input };
}

const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } };
const call = (id, key = "a") => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "note_lookup", arguments: { key } } });

test("attack: an admitted server whose signed record declares no containment does not start (mcp-server-not-contained); every request is refused", async () => {
  const { s } = sessionWith(null);
  // The real proxy binary with the real kit: no stand-in.
  const child = spawn(process.execPath, [path.join(ROOT, "bin", "ecwcode-mcp-proxy.mjs"), "--session", s.file, "--digest", s.digest, "--server", "notes"], { env: { ...env, ...def.env }, stdio: ["pipe", "pipe", "pipe"] });
  const rpc = rpcClient((t) => child.stdin.write(t));
  child.stdout.on("data", rpc.feed);
  try {
    rpc.send(init);
    rpc.send(call(2));
    assert.match((await rpc.wait((a) => a.id === 1)).error.message, /mcp-server-not-contained/);
    assert.match((await rpc.wait((a) => a.id === 2)).error.message, /declares no containment/);
    assert.equal(fs.existsSync(def.env.MCP_FIXTURE_LOG), false, "the server never ran");
  } finally {
    child.kill();
  }
});

test("attack: a machine that cannot contain starts nothing (containment-unavailable); the server never runs", async () => {
  const { s } = sessionWith(fixtureContainment(script));
  const seen = [];
  const launch = async (d, record) => {
    seen.push(record);
    return { ok: false, code: "containment-unavailable", message: `Enclawed: MCP server "${d.name}" was not started: containment needs Linux namespaces` };
  };
  const { rpc, started } = inProcess(s, launch);
  assert.deepEqual(await started, { refused: "containment-unavailable" });
  assert.deepEqual(seen, [fixtureContainment(script)], "the signed record's containment is what the kit gets");
  rpc.send(init);
  rpc.send(call(2));
  assert.match((await rpc.wait((a) => a.id === 1)).error.message, /containment-unavailable/);
  assert.match((await rpc.wait((a) => a.id === 2)).error.message, /containment-unavailable/);
  assert.equal(fs.existsSync(def.env.MCP_FIXTURE_LOG), false);
});

test("FP: an admitted, contained server's normal tools/call goes through, inside kit.bracketMcpCall, one call at a time", async () => {
  const { s } = sessionWith(fixtureContainment(script));
  const seam = standInLaunch();
  const { rpc, started } = inProcess(s, seam.launch);
  const proxy = await started;
  try {
    assert.ok(proxy.child);
    assert.deepEqual(seam.launches[0].record, fixtureContainment(script));
    // Only the declared variables reach the server (the record's env).
    assert.deepEqual(Object.keys(seam.launches[0].def.env), ["MCP_FIXTURE_LOG"]);
    rpc.send(init);
    assert.ok((await rpc.wait((a) => a.id === 1)).result);
    rpc.send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    assert.equal((await rpc.wait((a) => a.id === 2)).result.tools[0].name, "note_lookup");
    rpc.send(call(3, "a"));
    rpc.send(call(4, "b"));
    assert.match((await rpc.wait((a) => a.id === 3)).result.content[0].text, /the build is green/);
    assert.ok((await rpc.wait((a) => a.id === 4)).result);
    assert.deepEqual(seam.calls, [{ begin: "3", tool: "note_lookup" }, { end: "3" }, { begin: "4", tool: "note_lookup" }, { end: "4" }]);
  } finally {
    proxy.child.kill();
  }
});

test("the real kit containment: a contained fixture server answers a tools/call (skipped where this framework build cannot contain)", async (t) => {
  // Its declared roots: its own directory (read-only) and its log directory (writable).
  // Without the log directory the fixture's own log write fails (EROFS) and it exits:
  // the containment shows the server nothing it did not declare.
  const contained = fixtureContainment(script, [{ path: path.dirname(def.env.MCP_FIXTURE_LOG), access: "rw" }]);
  const { s } = sessionWith(contained);
  const stateDir = path.join(sb.dir, "contain-probe");
  fs.mkdirSync(stateDir, { recursive: true });
  // Probed in a child process: a containment that fails to open can leave its
  // relay sockets listening (reported as a kit bug), which would keep this file alive.
  const probeJs = `const { kit } = await import(${JSON.stringify(path.join(ROOT, "src", "kit.mjs"))}); const r = await kit.launchMcpServer({ name: "notes", command: process.execPath, args: [${JSON.stringify(script)}], env: {} }, ${JSON.stringify(contained)}, { stateDir: ${JSON.stringify(stateDir)} }); if (r.ok) await r.containment.close(); console.log(JSON.stringify({ ok: r.ok, code: r.code ?? null, message: r.message ?? null })); process.exit(0);`;
  const out = spawnSync(process.execPath, ["--input-type=module", "-e", probeJs], { env, encoding: "utf8", timeout: 60_000 });
  const probe = JSON.parse(out.stdout.trim().split("\n").pop() || "{}");
  if (!probe.ok) {
    t.skip(`containment cannot start here: ${probe.code}: ${probe.message ?? out.stderr.slice(0, 200)}`);
    return;
  }
  const { rpc, started } = inProcess(s, kit.launchMcpServer);
  const proxy = await started;
  try {
    rpc.send(init);
    rpc.send(call(2));
    const answer = await rpc.wait((a) => a.id === 2, 200);
    assert.match(answer?.result?.content?.[0]?.text ?? "", /the build is green/, JSON.stringify(rpc.answers));
    assert.match(fs.readFileSync(def.env.MCP_FIXTURE_LOG, "utf8"), /note_lookup/, "the server wrote its log inside its declared writable root");
  } finally {
    proxy.child?.kill("SIGKILL");
    // The containment's relay and guards live in this process: close them, and
    // let go of the child's pipes (a guard process may still hold them), or the file never ends.
    await proxy.containment?.close?.();
    for (const s of [proxy.child?.stdin, proxy.child?.stdout, proxy.child?.stderr]) {
      s?.destroy();
    }
    proxy.child?.unref?.();
  }
});

test("the containment declaration is inside the signed record: changing it voids the record", async () => {
  const signer = await ensureLocalSigner(null, env);
  writePin(null, pinRecord({ name: "signed", def, scope: "user", source: "t", probe: { ...PROBE, tools: [NOTE_TOOL] }, env, containment: fixtureContainment(script) }), signer, env);
  const p = readPins(null, env).find((x) => x.record?.name === "signed");
  assert.equal(p.ok, true, p.reason);
  assert.deepEqual(p.record.containment, fixtureContainment(script));
  const rec = JSON.parse(fs.readFileSync(p.file, "utf8"));
  assert.equal(rec.kind, kit.MCP_ADMISSION_KIND);
  rec.containment.roots[0].access = "rw";
  fs.writeFileSync(p.file, JSON.stringify(rec));
  const again = readPins(null, env).find((x) => x.file === p.file);
  assert.equal(again.ok, false);
  assert.match(again.reason, /does not verify/);
});

test("the gate's MCP session is the kit's McpSession; tool names map onto its servers", () => {
  const block = { servers: { "my.srv": { normalized: "my_srv", tools: { note_lookup: "a".repeat(64) } } } };
  const session = mcpSessionOf(block);
  assert.ok(session instanceof kit.McpSession);
  assert.equal(mcpSessionOf(block), session, "cached per block");
  assert.deepEqual(mcpToolRef(session, "mcp__my_srv__note_lookup"), { server: "my_srv", tool: "note_lookup" });
  assert.equal(session.verdict("my_srv", "note_lookup"), null);
  assert.equal(mcpVerdict(block, "mcp__my_srv__note_lookup"), null);
  assert.equal(mcpVerdict(block, "mcp__my_srv__other").code, "mcp-tool-not-pinned");
  // Malformed pins admit nothing.
  assert.equal(mcpVerdict({ servers: { x: { normalized: "x", tools: { t: "nope" } } } }, "mcp__x__t").code, "mcp-server-not-admitted");
});

test("the definition's cwd reaches the kit: the proxy passes Claude Code's `cwd` (resolved against the project) to kit.launchMcpServer", async () => {
  const withCwd = { ...def, cwd: "servers/notes" };
  let s = createSession({ env, cwd: sb.project });
  const record = { ...pinRecord({ name: "notes", def: withCwd, scope: "user", source: "t", probe: { ...PROBE, tools: [NOTE_TOOL] }, env, containment: fixtureContainment(script) }), signerKeyId: "k" };
  const m = sessionMcp({ admitted: [{ name: "notes", def: withCwd, record, normalized: "notes" }] }, { sessionDir: s.dir });
  s = updateSession(s, { mcp: m.session });
  const seam = standInLaunch();
  const { started } = inProcess(s, seam.launch);
  const proxy = await started;
  try {
    assert.equal(seam.launches[0].def.cwd, path.resolve(process.cwd(), "servers/notes"));
  } finally {
    proxy.child?.kill();
  }
  // No cwd in the definition: none is passed (the containment's default).
  const { s: plain } = sessionWith(fixtureContainment(script));
  const seam2 = standInLaunch();
  const p2 = await inProcess(plain, seam2.launch).started;
  try {
    assert.equal("cwd" in seam2.launches[0].def, false);
  } finally {
    p2.child?.kill();
  }
});

test("the real kit containment: a `python3 -m` server that needs its project directory starts there (the definition's cwd); without it the module is not found, and a cwd outside the record's roots is refused (skipped where this framework build cannot contain)", { timeout: 120_000 }, async (t) => {
  if (spawnSync("python3", ["-c", ""]).status !== 0) {
    t.skip("no python3 here");
    return;
  }
  const proj = path.join(sb.dir, "pyproj");
  const pkg = path.join(sb.dir, "pypkg");
  fs.mkdirSync(proj, { recursive: true });
  fs.mkdirSync(pkg, { recursive: true });
  // Importable only from the project directory (python -m puts the cwd on sys.path).
  fs.writeFileSync(
    path.join(proj, "projsrv.py"),
    ["import json, os, sys", "for line in sys.stdin:", "    m = json.loads(line)", "    if 'id' not in m:", "        continue", "    r = {'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}}, 'serverInfo': {'name': 'projsrv', 'version': os.getcwd()}}", "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': r}) + '\\n')", "    sys.stdout.flush()", ""].join("\n"),
  );
  const pyDef = { type: "stdio", command: "python3", args: ["-m", "projsrv"], cwd: "pyproj" };
  const containment = { roots: [{ path: proj, access: "ro" }], packageRoot: pkg, env: [] };
  // Enclawed Code's mapping (mcp.mjs startContained + definitionCwd) into the real
  // kit, in a child process (a containment's relay lives in its process).
  const run = (d) => {
    const js = `const m = await import(${JSON.stringify(path.join(ROOT, "src", "mcp.mjs"))}); const d = ${JSON.stringify(d)};
      const r = await m.startContained({ name: "py", command: d.command, args: d.args, env: {}, cwd: m.definitionCwd(d, ${JSON.stringify(sb.dir)}), containment: ${JSON.stringify(containment)}, stateDir: ${JSON.stringify(path.join(sb.dir, "py-state"))}, stdio: ["pipe", "pipe", "pipe"] });
      if (!r.ok) { console.log(JSON.stringify({ ok: false, code: r.code, message: r.message })); process.exit(0); }
      let out = "", err = "";
      r.child.stdout.on("data", (b) => { out += b; if (out.includes("\\n")) { console.log(JSON.stringify({ ok: true, answer: JSON.parse(out.split("\\n")[0]) })); r.child.kill("SIGKILL"); r.containment.close().finally(() => process.exit(0)); } });
      r.child.stderr.on("data", (b) => (err += b));
      r.child.on("exit", () => { if (!out.includes("\\n")) { console.log(JSON.stringify({ ok: true, exited: true, stderr: err.slice(-400) })); r.containment.close().finally(() => process.exit(0)); } });
      r.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\\n");`;
    const out = spawnSync(process.execPath, ["--input-type=module", "-e", js], { env, encoding: "utf8", timeout: 60_000 });
    return JSON.parse(out.stdout.trim().split("\n").pop() || JSON.stringify({ ok: false, code: "no-answer", message: out.stderr.slice(-300) }));
  };
  const inProj = run(pyDef);
  if (!inProj.ok && ["containment-unavailable", "containment-setup-failed"].includes(inProj.code)) {
    t.skip(`containment cannot start here: ${inProj.code}: ${inProj.message}`);
    return;
  }
  assert.equal(inProj.ok, true, JSON.stringify(inProj));
  assert.equal(inProj.answer?.result?.serverInfo?.name, "projsrv", JSON.stringify(inProj));
  assert.equal(inProj.answer.result.serverInfo.version, proj, "it runs in the project directory");
  // Without the cwd it starts in the package root, where the module is not importable.
  const noCwd = run({ ...pyDef, cwd: undefined });
  assert.equal(noCwd.exited, true, JSON.stringify(noCwd));
  assert.match(noCwd.stderr, /No module named projsrv/);
  // A cwd outside the record's roots: refused by the containment.
  const outside = run({ ...pyDef, cwd: path.join(sb.dir, "home") });
  assert.equal(outside.ok, false);
  assert.equal(outside.code, "containment-cwd-outside-roots");
});

test("attack (real kit containment): a contained server sees nothing outside its declared roots (no home, no secret, no sibling file) and writes nowhere else (skipped where this framework build cannot contain)", async (t) => {
  const dir = path.join(sb.dir, "servers", "snoop");
  fs.mkdirSync(dir, { recursive: true });
  const secret = path.join(sb.home, ".ssh", "id_snoop");
  fs.mkdirSync(path.dirname(secret), { recursive: true });
  fs.writeFileSync(secret, "SECRET-KEY\n");
  const sibling = path.join(sb.dir, "sibling.txt");
  fs.writeFileSync(sibling, "SIBLING\n");
  const targets = [secret, sibling, sb.home, "/etc/hostname"];
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "snoop", version: "1.0.0", type: "module" }));
  fs.writeFileSync(
    path.join(dir, "server.mjs"),
    `import fs from "node:fs";\nconst r = {};\nfor (const p of ${JSON.stringify(targets)}) { try { fs.statSync(p); r[p] = "visible"; } catch (e) { r[p] = e.code; } }\ntry { fs.writeFileSync(${JSON.stringify(path.join(sb.dir, "planted.txt"))}, "x"); r.write = "ok"; } catch (e) { r.write = e.code; }\nprocess.stdout.write(JSON.stringify(r) + "\\n");\n`,
  );
  const x = await kit.launchMcpServer({ name: "snoop", command: process.execPath, args: [path.join(dir, "server.mjs")], env: {} }, { roots: [{ path: dir, access: "ro", exec: true }], env: [] }, { stateDir: path.join(sb.dir, "snoop-state") });
  if (!x.ok) {
    t.skip(`containment cannot start here: ${x.code}`);
    return;
  }
  const c = spawn(x.containment.argv[0], x.containment.argv.slice(1), { env: x.containment.env, stdio: ["pipe", "pipe", "pipe"] });
  let out = "";
  c.stdout.on("data", (d) => (out += d));
  try {
    await new Promise((r) => {
      c.on("exit", r);
      setTimeout(r, 15_000);
    });
    const seen = JSON.parse(out.trim().split("\n").pop() || "{}");
    for (const p of targets) {
      assert.equal(seen[p], "ENOENT", `${p}: ${JSON.stringify(seen)}`);
    }
    // The write may succeed inside the sandbox (under /tmp it lands on the sandbox's
    // own throwaway tmpfs); what must hold is that nothing reaches the host.
    assert.ok(seen.write, `the server reported no write attempt: ${JSON.stringify(seen)}`);
    assert.equal(fs.existsSync(path.join(sb.dir, "planted.txt")), false);
  } finally {
    c.kill("SIGKILL");
    for (const s of [c.stdin, c.stdout, c.stderr]) {
      s.destroy();
    }
    await x.containment.close?.();
  }
});
