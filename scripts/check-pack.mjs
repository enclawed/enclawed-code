#!/usr/bin/env node
// prepack: refuse to pack Enclawed Code for npm unless the package is complete
// and consistent.
//
// An npm install of Enclawed Code loads the framework from its `enclawed`
// dependency (src/framework.mjs) and the skill analyzer from the vendored
// enclawed-oss sources the package ships (src/formal.mjs reads
// vendor/enclawed-oss/enclawed/src). Both must be the same enclawed release:
//   - package.json pins `enclawed` to an exact version;
//   - the vendored checkout is the commit vendor/enclawed-oss pins, unmodified,
//     and its package.json carries that same version;
//   - the skill analyzer is present (the submodule is checked out);
//   - the version is a release version (0.0.0 is the placeholder of the source tree).

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const problems = [];
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));

if (pkg.private === true) {
  problems.push('package.json is "private": true');
}
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(pkg.version ?? "") || pkg.version === "0.0.0") {
  problems.push(`package.json version ${JSON.stringify(pkg.version)} is not a release version`);
}
const fw = pkg.dependencies?.enclawed;
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(fw ?? "")) {
  problems.push(`dependencies.enclawed must be an exact version (found ${JSON.stringify(fw)})`);
}

const vendor = path.join(root, "vendor", "enclawed-oss");
const git = (args, cwd = root) => spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8" });
const link = /^160000 ([0-9a-f]{40}) 0\tvendor\/enclawed-oss$/m.exec(git(["ls-files", "-s", "--", "vendor/enclawed-oss"]).stdout ?? "");
if (!link) {
  problems.push("vendor/enclawed-oss is not a gitlink");
} else {
  const head = git(["rev-parse", "HEAD"], vendor);
  if (head.status !== 0 || head.stdout.trim() !== link[1]) {
    problems.push(`vendor/enclawed-oss is not checked out at the pinned ${link[1].slice(0, 12)} (git submodule update --init vendor/enclawed-oss)`);
  } else if (git(["status", "--porcelain", "--untracked-files=no"], vendor).stdout.trim() !== "") {
    problems.push("vendor/enclawed-oss has local changes");
  }
}
if (!fs.existsSync(path.join(vendor, "enclawed", "src", "skill-formal-static.mjs"))) {
  problems.push("the vendored skill analyzer (vendor/enclawed-oss/enclawed/src) is missing");
}
try {
  const vendored = JSON.parse(fs.readFileSync(path.join(vendor, "package.json"), "utf8")).version;
  if (fw && vendored !== fw) {
    problems.push(`dependencies.enclawed is ${fw} but the vendored enclawed-oss is ${vendored}`);
  }
} catch {
  problems.push("vendor/enclawed-oss/package.json is unreadable");
}

// node-domexception (deprecated upstream, reached through enclawed -> @google/genai ->
// google-auth-library -> gaxios -> node-fetch -> fetch-blob) is Enclawed's own replacement, by
// alias, so an install of enclawed-code (global, project or nested) prints no deprecation warning.
if (pkg.dependencies?.["node-domexception"] !== "npm:@enclawed/node-domexception@1.0.0" || pkg.bundleDependencies || pkg.bundledDependencies) {
  problems.push('package.json must depend on "node-domexception": "npm:@enclawed/node-domexception@1.0.0" (and bundle nothing)');
}

if (problems.length > 0) {
  console.error(`check-pack: refusing to pack Enclawed Code:\n${problems.map((p) => `  - ${p}`).join("\n")}`);
  process.exit(1);
}
console.log(`check-pack: ${pkg.name} ${pkg.version} with enclawed ${fw} (vendored ${link[1].slice(0, 12)})`);
