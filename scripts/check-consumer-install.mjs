#!/usr/bin/env node
// The consumer gate: enclawed-code installs as a person installs it, by name
// from a registry, with every npm given (npm 9 by default, and each
// NPM_CLI=<path to npm-cli.js>, comma-separated, e.g. npm 11):
//   - the registry metadata for the version equals the package.json inside the
//     tarball the registry serves (global installs resolve from the metadata);
//   - `npm install -g enclawed-code@<version>` into an empty prefix succeeds,
//     prints no `npm WARN deprecated` line, and `ecwctl --version` prints it;
//   - `npm install enclawed-code@<version>` into a project, and `npm audit`
//     over it reports 0 vulnerabilities.
// By default the package is packed and published, with each npm, to a stand-in
// registry (enclawed-oss scripts/ci/stand-in-registry.mjs) that stores what npm
// uploads and passes everything else through to the real registry; with
// --enclawed-tarball the enclawed tarball an unreleased pin needs is published
// there first. With --live <version> the real registry is checked instead.
// Everything happens in a throwaway directory (TMPDIR).
//   node scripts/check-consumer-install.mjs [--enclawed-tarball <tgz>] [--npm-cli /path/to/npm-cli.js ...]
//   node scripts/check-consumer-install.mjs --live <version> [--npm-cli ...]
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const oss = path.join(root, "vendor", "enclawed-oss", "scripts", "ci");
const { metadataMismatches } = await import(pathToFileURL(path.join(oss, "consumer-install-check.mjs")).href);
const NAME = "enclawed-code";

const clis = [null];
let live = null;
let enclawedTarball = null;
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === "--npm-cli" && process.argv[i + 1]) {
    clis.push(path.resolve(process.argv[++i]));
  } else if (process.argv[i] === "--live" && process.argv[i + 1]) {
    live = process.argv[++i];
  } else if (process.argv[i] === "--enclawed-tarball" && process.argv[i + 1]) {
    enclawedTarball = path.resolve(process.argv[++i]);
  }
}
for (const c of (process.env.NPM_CLI ?? "").split(",").filter(Boolean)) {
  clis.push(path.resolve(c));
}
const npm = (cli, args, opts = {}) =>
  cli
    ? spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", maxBuffer: 64 << 20, ...opts })
    : spawnSync("npm", args, { encoding: "utf8", maxBuffer: 64 << 20, ...opts });

/** The stand-in runs as its own process: the npm runs below block this one. */
function startStandIn(own) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(oss, "stand-in-registry.mjs"), ...own.flatMap((n) => ["--own", n])], {
      stdio: ["ignore", "pipe", "inherit"],
    });
    let out = "";
    child.stdout.on("data", (d) => {
      out += d;
      if (out.includes("\n")) {
        resolve({ url: out.split("\n")[0].trim(), stop: () => child.kill("SIGKILL") });
      }
    });
    child.on("exit", (code) => reject(new Error(`stand-in registry exited (${code})`)));
  });
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-consumer-"));
const problems = [];
const standIns = [];
try {
  let tarball = null;
  let version = live;
  if (!live) {
    const packed = npm(null, ["pack", "--pack-destination", work], { cwd: root });
    if (packed.status !== 0) {
      throw new Error(`npm pack failed: ${packed.stderr}`);
    }
    tarball = path.join(work, packed.stdout.trim().split("\n").pop());
    version = JSON.parse(spawnSync("tar", ["xzf", tarball, "-O", "package/package.json"], { encoding: "utf8" }).stdout).version;
  }
  const spec = `${NAME}@${version}`;
  for (const cli of clis) {
    const v = npm(cli, ["--version"]).stdout.trim();
    const cache = path.join(work, `cache-${v}`);
    // npm settings inherited from the caller could change the install; only the registry is set here.
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^npm_config_/i.test(k)));
    const base = ["--cache", cache, "--no-fund", "--loglevel", "warn"];
    if (!live) {
      const reg = await startStandIn(enclawedTarball ? [NAME, "enclawed"] : [NAME]);
      standIns.push(reg);
      env.npm_config_registry = reg.url;
      const auth = `--${reg.url.replace(/^https?:/, "")}:_authToken=stand-in`;
      for (const t of [enclawedTarball, tarball].filter(Boolean)) {
        const p = npm(cli, ["publish", t, "--tag", "latest", auth, "--cache", cache], { cwd: work, env });
        if (p.status !== 0) {
          problems.push(`npm ${v}: publishing ${path.basename(t)} to the stand-in registry failed: ${p.stderr.trim().slice(-500)}`);
        }
      }
    }
    // The registry metadata against the package.json in the tarball it serves.
    const view = npm(cli, ["view", spec, "--json", "--cache", cache], { cwd: work, env });
    const packDir = fs.mkdtempSync(path.join(work, `served-${v}-`));
    const served = npm(cli, ["pack", spec, "--pack-destination", packDir, "--cache", cache], { cwd: packDir, env });
    if (view.status !== 0 || served.status !== 0) {
      problems.push(`npm ${v}: the registry does not serve ${spec}: ${(view.stderr || served.stderr).trim().slice(0, 300)}`);
    } else {
      const tgz = fs.readdirSync(packDir).find((f) => f.endsWith(".tgz"));
      const manifest = JSON.parse(spawnSync("tar", ["xzf", path.join(packDir, tgz), "-O", "package/package.json"], { encoding: "utf8" }).stdout);
      const mismatches = metadataMismatches(JSON.parse(view.stdout), manifest);
      if (mismatches.length) {
        problems.push(`npm ${v}: the registry metadata differs from the package.json in the tarball: ${mismatches.join("; ")}`);
      }
    }
    // A global install by name, as a person installs it.
    const prefix = fs.mkdtempSync(path.join(work, `prefix-${v}-`));
    const g = npm(cli, ["install", "-g", spec, "--prefix", prefix, ...base], { cwd: work, env });
    const out = `${g.stdout}\n${g.stderr}`;
    const deprecated = out.split("\n").filter((l) => /npm warn deprecated/i.test(l));
    if (g.status !== 0) {
      problems.push(`npm ${v}: npm install -g ${spec} failed: ${g.stderr.trim().slice(-800)}`);
    } else {
      const bin = path.join(prefix, process.platform === "win32" ? "" : "bin", "ecwctl");
      const ver = spawnSync(bin, ["--version"], { encoding: "utf8", env });
      if (!`${ver.stdout}`.includes(version)) {
        problems.push(`npm ${v}: the installed ecwctl --version printed ${JSON.stringify(`${ver.stdout}${ver.stderr}`.trim())}, expected ${version}`);
      }
    }
    if (deprecated.length) {
      problems.push(`npm ${v}: ${deprecated.join("; ")}`);
    }
    if (/Invalid comparator/.test(out)) {
      problems.push(`npm ${v}: "Invalid comparator" (an npm: alias npm cannot read)`);
    }
    // The audit over the same dependency tree (npm audit needs a project).
    const proj = fs.mkdtempSync(path.join(work, `audit-${v}-`));
    fs.writeFileSync(path.join(proj, "package.json"), JSON.stringify({ name: "consumer", version: "0.0.0", private: true }));
    const l = npm(cli, ["install", spec, ...base], { cwd: proj, env });
    if (l.status !== 0) {
      problems.push(`npm ${v}: npm install ${spec} failed: ${l.stderr.trim().slice(-500)}`);
    }
    const a = npm(cli, ["audit", "--json", "--omit=dev", "--cache", cache], { cwd: proj, env });
    let total = null;
    try {
      total = JSON.parse(a.stdout).metadata?.vulnerabilities?.total ?? null;
    } catch {
      total = null;
    }
    if (total !== 0) {
      problems.push(`npm ${v}: npm audit reports ${total ?? "an unreadable result"} vulnerabilities`);
    }
    console.log(`consumer-install: npm ${v}: ${spec} ${g.status === 0 ? "installed globally" : "global install FAILED"}, ${deprecated.length} deprecation warning(s), audit ${total}`);
  }
} finally {
  for (const reg of standIns) {
    reg.stop();
  }
  fs.rmSync(work, { recursive: true, force: true });
}
if (problems.length) {
  console.error(`consumer-install: FAILED\n${problems.map((p) => `  - ${p}`).join("\n")}`);
  process.exit(1);
}
console.log("consumer-install: ok");
