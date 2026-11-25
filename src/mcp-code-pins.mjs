// MCP server CODE pinned by content (closure plan M2; postmark-mcp 1.0.16).
//
// The decisions are the Enclawed adapter kit's (enclawed-oss
// src/enclawed/adapter/mcp-package-pins.ts and code-pins.ts):
// kit.codeResolution says whether a definition resolves its code at launch
// (npx without an exact version, uvx, pipx run, docker run IMAGE:TAG, ...:
// refused with how to pin), kit.codePinProblem compares a package runner's
// pinned code with what the launcher measured, and kit.measureLocalCode /
// kit.localCodeProblem pin a script's package or a Python module by its
// tree. Enclawed Code only measures what the kit asks for:
//
//   npx NAME@X.Y.Z   kit.measureNpxPackage: the package npx installed (its
//                    cache entry under <npm cache>/_npx/), by the lockfile's
//                    integrity of NAME, a digest of the whole lockfile and of
//                    every installed file, and its bin. The proxy then starts
//                    that bin with Node itself: npx never resolves anything
//                    at launch.
//   pnpm dlx, bunx, npm exec, yarn dlx, uvx, pipx run, uv tool run
//                    kit.measurePackageRunner over the runners' caches
//                    (kit.runnerCacheDirs): the installed tree, its lockfile
//                    or RECORD hashes; the proxy starts the measured tree, the
//                    runner never runs. For the Python runners Enclawed Code
//                    reads the index page the runner uses (and, at pin time,
//                    downloads the release's wheels for the kit to check).
//                    The Python runners' index (kit.pythonIndexUrls) is read
//                    at pin time only; a launch is checked against the
//                    record's pin. yarn dlx keeps no tree: at pin time the
//                    release is installed through npx (no install scripts;
//                    kit.yarnDlxInstallCommand) and that tree is measured.
//   anything else    kit.measureLocalCode (a script's package, a Python
//                    module, `uv run` in a locked project, deno with a lock,
//                    an installed script), or nothing (a binary); `uv run`
//                    and deno start through kit.localCodeLaunch (uv never
//                    runs; deno runs from its measured cache only).

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { kit } from "./kit.mjs";
import { appStateDir } from "./paths.mjs";

const base = (c) => path.basename(String(c ?? "")).replace(/\.(exe|cmd)$/i, "");

const refuse = (problem, how) => ({ ok: false, code: "mcp-server-unpinned-code", problem, how });

/** The file-hash cache of measured trees (Enclawed Code's protected state; kit.treeHashCache). */
export function treeHashCacheFile(env = process.env) {
  return path.join(appStateDir(env), "tree-hash-cache.json");
}

/**
 * What the launcher measures about a definition's code, for the kit: the
 * measured pin (`code`, null when the executable is all there is) and how
 * the proxy starts it (`launch`: a package runner's measured tree, `uv run`'s
 * project environment, deno with its cache locked). Or why it cannot be
 * measured (`problem` with `how`). `pin`: pin time (the Python index and
 * wheels are read, a yarn dlx release is installed through npx, every file is
 * hashed again); else `pinned`, the record's pin (no network).
 * @returns {{ ok: true, code: object|null, launch?: object } | { ok: false, code: "mcp-server-unpinned-code", problem: string, how: string }}
 */
export function codeIdentity(def, { env = process.env, cwd = process.cwd(), pin = false, pinned = null } = {}) {
  if ((def?.type ?? (typeof def?.url === "string" ? "http" : "stdio")) !== "stdio") {
    return { ok: true, code: null };
  }
  const cache = kit.treeHashCache(treeHashCacheFile(env), { refresh: pin });
  try {
    return measure(def, { env, cwd, pin, pinned, cache });
  } finally {
    try {
      cache.save();
    } catch {
      // An unwritable cache only costs the next launch a full hash.
    }
  }
}

function measure(def, { env, cwd, pin, pinned, cache }) {
  const r = kit.codeResolution(def);
  if (r.kind === "unpinned") {
    return refuse(r.reason, r.howToPin);
  }
  const home = env.HOME || os.homedir();
  const caches = () => kit.runnerCacheDirs({ ...env, ...definitionVars(def) }, home, process.platform, { cwd, def });
  if (r.kind === "pinned-form") {
    const { kind, name, version } = r.expected;
    const how = `name the exact version and run it once with its runner (the launcher measures what the runner installed), or install the server and point the definition at its script`;
    if (kind === "npm" && base(def.command) === "npx") {
      const m = kit.measureNpxPackage(def, caches().npm, { pinned, hashCache: cache });
      if (!m.ok) {
        return refuse(m.reason, m.code === "inconsistent-copies" ? "clear them (`npm cache clean --force` removes npx's cache too) and pin again" : how);
      }
      return { ok: true, code: m.pin, launch: { kind: "npm", ...m.launch } };
    }
    if (kind !== "npm" && kind !== "pypi") {
      return refuse(`the launcher cannot measure the code ${name}@${version} that ${base(def.command)} would fetch`, how);
    }
    let index = null;
    if (kind === "pypi" && pin) {
      index = pythonIndex(def, env, name, version, cwd);
      if (!index.ok) {
        return refuse(index.problem, "make the package index reachable (UV_INDEX_URL / PIP_INDEX_URL or the runner's config may name a file: index)");
      }
    }
    const o = { index: index?.index ?? null, pinned, hashCache: cache };
    let m = kit.measurePackageRunner(def, caches(), o);
    // yarn dlx keeps no tree: at pin time the release is installed through npx (kit.yarnDlxInstallCommand).
    const install = pin && !m.ok && m.code === "not-installed" ? kit.yarnDlxInstallCommand(def) : null;
    if (install) {
      const ran = spawnSync(install.command, install.args, { cwd, env: { ...env, ...definitionVars(def) }, encoding: "utf8", timeout: 300_000 });
      if (ran.status !== 0) {
        return refuse(`${name}@${version} could not be installed through npx for yarn dlx (${(ran.stderr || "").trim().slice(0, 200)})`, how);
      }
      m = kit.measurePackageRunner(def, caches(), o);
    }
    if (!m.ok) {
      return refuse(m.reason, m.code === "inconsistent-copies" ? "clear the runner's cache and pin again" : how);
    }
    return { ok: true, code: m.pin, launch: { kind: "runner", ...m.launch } };
  }
  try {
    const o = { cwd, pathVar: env.PATH ?? "" };
    const code = kit.measureLocalCode(def, { ...o, denoDir: caches().deno, ...(env.JSR_URL ? { jsrUrl: env.JSR_URL } : {}), hashCache: cache });
    const local = code ? kit.localCodeLaunch(def, o) : null;
    return { ok: true, code, ...(local ? { launch: { kind: "local", ...local } } : {}) };
  } catch (err) {
    return refuse(`its code could not be measured: ${err.message}`, "install the server into a directory of its own and point the definition at its script");
  }
}

/**
 * The PATH the kit's local-code lookup sees for a definition. Workaround for
 * a kit bug: kit.localCodeOf resolves a package runner (`npx` is a Node
 * script) and asks for a tree pin of npm itself, so the kit would refuse
 * every pinned npx server. A pinned-form runner's code is its package, which
 * kit.codePinProblem checks; its runner never runs (the proxy starts the
 * verified tree with Node).
 */
export function localCodePath(def, env = process.env) {
  return kit.codeResolution(def).kind === "pinned-form" ? "" : (env.PATH ?? "");
}

/**
 * Does the definition's code still match the record's pin? (the proxy, right
 * before it starts the server; admission runs the same kit checks in
 * kit.admitMcpServers)
 * @returns {{ ok: true, launch: object|null } | { ok: false, reason: string }}
 */
export function checkCodePin(def, pinned, { env = process.env, cwd = process.cwd() } = {}) {
  const now = codeIdentity(def, { env, cwd, pinned: pinned ?? null });
  if (!now.ok) {
    return { ok: false, reason: `${now.problem}; ${now.how}` };
  }
  let problem;
  try {
    problem =
      kit.codePinProblem(def, pinned ?? null, now.code) ??
      kit.localCodeProblem(kit.localCodeOf(def, { cwd, pathVar: localCodePath(def, env) }), pinned ?? null, now.code);
  } catch (err) {
    problem = `its local code could not be located (${err.message})`;
  }
  return problem ? { ok: false, reason: problem } : { ok: true, launch: now.launch ?? null };
}

/** The string variables a definition sets (they configure its runner's caches and index). */
function definitionVars(def) {
  return Object.fromEntries(Object.entries(def?.env && typeof def.env === "object" ? def.env : {}).filter(([, v]) => typeof v === "string"));
}

const FETCH = `
const [url, out] = process.argv.slice(1);
const r = await fetch(url, { redirect: "error", headers: { accept: "text/html" }, signal: AbortSignal.timeout(20000) });
if (!r.ok) { console.error("HTTP " + r.status); process.exit(2); }
const b = Buffer.from(await r.arrayBuffer());
if (b.length > 64 * 1024 * 1024) process.exit(3);
if (out) { (await import("node:fs")).writeFileSync(out, b); } else { process.stdout.write(b); }
`;

/** Read `url` (file: or https:) synchronously; `out`: save it there. */
function readUrl(url, out = null) {
  const u = new URL(url);
  if (u.protocol === "file:") {
    const b = fs.readFileSync(fileURLToPath(u));
    if (out) {
      fs.writeFileSync(out, b);
    }
    return b.toString("utf8");
  }
  if (u.protocol !== "https:") {
    throw new Error(`the index ${u.origin} is not https or file:`);
  }
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", FETCH, u.href, out ?? ""], { encoding: "utf8", timeout: 30_000, maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) {
    throw new Error(`could not read ${u.origin}${u.pathname} (${(r.stderr || "").trim().slice(0, 200)})`);
  }
  return r.stdout;
}

/**
 * At pin time, the index page a Python runner would read for name==version
 * (the first of kit.pythonIndexUrls, the runner's options, environment and
 * config, that lists the release), and the release's wheels downloaded next
 * to it, for the kit to check against the installed environment. A launch
 * reads no index (the record's pin carries the hashes).
 */
function pythonIndex(def, env, name, version, cwd) {
  const v = { ...env, ...definitionVars(def) };
  const norm = name.toLowerCase().replace(/[-_.]+/g, "-");
  const problems = [];
  for (const base of kit.pythonIndexUrls(def, v, env.HOME || os.homedir(), process.platform, { cwd })) {
    const pageUrl = new URL(`${norm}/`, base);
    const at = pageUrl.protocol === "file:" ? new URL("index.html", pageUrl) : pageUrl;
    let page;
    try {
      page = readUrl(at.href);
    } catch (err) {
      problems.push(`${pageUrl.origin}: ${err.message}`);
      continue;
    }
    if (kit.simpleIndexHashes(page, name, version).length === 0) {
      problems.push(`${pageUrl.origin}${pageUrl.pathname} lists no hashed file of ${name}==${version}`);
      continue;
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-wheels-"));
    const files = [];
    try {
      for (const m of page.matchAll(/href="([^"]+\.whl)(?:#[^"]*)?"/g)) {
        const href = m[1].replaceAll("&amp;", "&");
        const file = decodeURIComponent(href.split("/").pop());
        const w = /^([A-Za-z0-9_.]+?)-([^-]+)-/.exec(file);
        if (!w || w[1].toLowerCase().replace(/[-_.]+/g, "-") !== norm || w[2] !== version) {
          continue;
        }
        const target = path.join(dir, file.replace(/[^A-Za-z0-9_.+-]/g, "_"));
        readUrl(new URL(href, at).href, target);
        files.push(target);
      }
    } catch (err) {
      return { ok: false, problem: `the wheels of ${name}==${version} could not be downloaded: ${err.message}` };
    }
    return { ok: true, index: { page, wheels: files } };
  }
  return { ok: false, problem: `the index page of ${name} could not be read or lists no ${version}: ${problems.join("; ").slice(0, 400)}` };
}

/**
 * The command and arguments that start a measured tree instead of its runner
 * (npx and the other package runners), or null when the definition runs as
 * written.
 */
export function measuredLaunch(launch, command) {
  if (launch?.kind === "local") {
    // uv run's project environment started directly, or deno with its cache locked (kit.localCodeLaunch).
    return { command: launch.command, args: [...launch.args], env: launch.env ?? {}, envDefaults: launch.envDefaults ?? {} };
  }
  if (!launch || (launch.kind !== "npm" && launch.kind !== "runner")) {
    return null;
  }
  const runtime = launch.runtime ?? "node";
  if (runtime === "python") {
    return { command: launch.interpreter, args: [launch.script, ...launch.args] };
  }
  if (runtime === "bun") {
    // bunx is bun itself: the definition's own (admitted) executable.
    const exe = kit.resolveCommand(String(command ?? ""), process.cwd(), process.env.PATH ?? "");
    return exe ? { command: fs.realpathSync(exe), args: [launch.script, ...launch.args] } : null;
  }
  return { command: process.execPath, args: [launch.script, ...launch.args] };
}
