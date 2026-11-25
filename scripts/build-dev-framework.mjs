#!/usr/bin/env node
// Development only: build `enclawed/framework` from a local enclawed-oss
// checkout into ./.enclawed-dev/, without touching that checkout's tracked
// dist/. The app's framework seam (src/framework.mjs) prefers this build when
// it exists, so the app can be developed against framework exports that have
// not been released yet. Published packages never contain .enclawed-dev/.
//
// NOTE (2026-11-22, hardware-root red-team fixes H1-H15): enclawed-oss now
// refuses Enclaweder firmware before 0.3 ("device latch unsupported"), and a
// broker client refuses an owner from an older build (no device attestation).
// Rebuild only AFTER the attached Enclaweder is reflashed to firmware 0.3, and
// rebuild every Enclawed Code copy and benchmark snapshot at once, so no
// old-framework process (which can open the device and write the real latch)
// is left running beside a new one.
//
// Usage: node scripts/build-dev-framework.mjs [path-to-enclawed-oss]
//        (default: ENCLAWED_OSS_DIR, else the vendor/enclawed-oss git
//        submodule, else a sibling ../enclawed-oss checkout)

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// enclawed-oss is tracked from GitHub as a submodule: its npm package follows a
// slower stable-release path than the repository this app builds against.
const submoduleDir = path.join(appRoot, "vendor", "enclawed-oss");
// An empty argument or ENCLAWED_OSS_DIR="" means "not set" (path.resolve("")
// would silently be the current directory).
const nonEmpty = (v) => (typeof v === "string" && v.trim() !== "" ? v : undefined);
const ossDir = path.resolve(
  nonEmpty(process.argv[2]) ??
    nonEmpty(process.env.ENCLAWED_OSS_DIR) ??
    (fs.existsSync(path.join(submoduleDir, "src", "framework.ts")) ? submoduleDir : path.join(appRoot, "..", "enclawed-oss")),
);
const tsdownBin = path.join(ossDir, "node_modules", "tsdown", "dist", "run.mjs");

/** Which enclawed-oss commit `dir` holds: { commit, dirty }, or { commit: null } when unknown. */
function sourceOf(dir) {
  try {
    const sha = fs.readFileSync(path.join(dir, ".sha"), "utf8").trim();
    if (/^[0-9a-f]{40}$/.test(sha)) {
      return { commit: sha, dirty: false, from: "export" };
    }
  } catch {
    /* not an export */
  }
  const git = (args) => spawnSync("git", ["-C", dir, ...args], { encoding: "utf8" });
  const head = git(["rev-parse", "HEAD"]);
  if (head.status !== 0) {
    return { commit: null, dirty: true, from: "unknown" };
  }
  const st = git(["status", "--porcelain", "--untracked-files=no"]);
  return { commit: head.stdout.trim(), dirty: st.status !== 0 || st.stdout.trim() !== "", from: "checkout" };
}
if (!fs.existsSync(path.join(ossDir, "src", "framework.ts")) || !fs.existsSync(tsdownBin)) {
  console.error(`build-dev-framework: ${ossDir} is not an installed enclawed-oss checkout`);
  process.exit(1);
}

const outRoot = path.join(appRoot, ".enclawed-dev");
const outDir = path.join(outRoot, "framework");
fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outRoot, { recursive: true });

// The bundle keeps enclawed-oss's runtime dependencies external, so they must
// resolve from the bundle: point .enclawed-dev/node_modules at the checkout's.
const link = path.join(outRoot, "node_modules");
fs.rmSync(link, { force: true, recursive: false });
fs.symlinkSync(path.join(ossDir, "node_modules"), link, "dir");

// Workspace packages (packages/<name>) resolve to their declared source entry:
// a tsconfig in the checkout may map them to a dist/ that was never built.
const alias = {};
try {
  for (const d of fs.readdirSync(path.join(ossDir, "packages"))) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(ossDir, "packages", d, "package.json"), "utf8"));
      const entry = typeof pkg.exports === "string" ? pkg.exports : pkg.exports?.["."];
      if (pkg.name && typeof entry === "string") {
        alias[pkg.name] = path.join(ossDir, "packages", d, entry);
      }
    } catch {
      /* not a package */
    }
  }
} catch {
  /* no packages/ */
}

// One tsconfig for the whole build, the checkout's root one: a nested
// tsconfig (extensions/) may map workspace packages to an unbuilt dist/.
const tsconfigPath = path.join(outRoot, "tsconfig.json");
fs.writeFileSync(tsconfigPath, `${JSON.stringify({ extends: path.join(ossDir, "tsconfig.json") }, null, 2)}\n`);

// A config with no imports, so it loads from outside the checkout.
const configPath = path.join(outRoot, "tsdown.config.mjs");
fs.writeFileSync(
  configPath,
  `export default {
  // contain-init runs inside every containment (the framework looks for it beside framework.js).
  entry: {
    framework: ${JSON.stringify(path.join(ossDir, "src", "framework.ts"))},
    "contain-init": ${JSON.stringify(path.join(ossDir, "src", "enclawed", "containment", "contain-init.ts"))},
  },
  outDir: ${JSON.stringify(outDir)},
  format: "esm",
  platform: "node",
  fixedExtension: false,
  dts: false,
  clean: true,
  env: { NODE_ENV: "production" },
  alias: ${JSON.stringify(alias)},
  tsconfig: ${JSON.stringify(tsconfigPath)},
};
`,
);

const res = spawnSync(process.execPath, [tsdownBin, "--config", configPath], {
  cwd: ossDir,
  stdio: "inherit",
});
if (res.status !== 0) {
  process.exit(res.status ?? 1);
}
fs.writeFileSync(path.join(outDir, "package.json"), '{ "type": "module" }\n');
// The enclawed-oss commit this build is made from (scripts/check-vendor-pin.mjs
// compares it with the vendor/enclawed-oss gitlink): a clean export records
// its commit in .sha (refactor builds use `git archive`); a checkout records
// HEAD, marked dirty when its tracked files differ from HEAD.
fs.writeFileSync(path.join(outDir, "source.json"), `${JSON.stringify(sourceOf(ossDir))}\n`);
// The containment's name guard: the prebuilt static binaries (verified by the
// digest bundled in framework.js) and its source (the runtime-build fallback),
// where the bundle looks for them.
const guardSrc = path.join(ossDir, "src", "enclawed", "containment", "name-guard.c");
if (fs.existsSync(guardSrc)) {
  fs.copyFileSync(guardSrc, path.join(outDir, "name-guard.c"));
}
const prebuilt = path.join(ossDir, "prebuilt", "name-guard");
if (fs.existsSync(prebuilt)) {
  fs.cpSync(prebuilt, path.join(outDir, "prebuilt", "name-guard"), { recursive: true });
}
console.log(`build-dev-framework: built ${path.join(outDir, "framework.js")}`);
