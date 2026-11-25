#!/usr/bin/env node
// The framework Enclawed Code runs must be the enclawed-oss commit its
// vendor/enclawed-oss gitlink pins. The development build
// (.enclawed-dev/framework, scripts/build-dev-framework.mjs) records the
// commit it was built from in source.json; this check fails when that record
// is missing, was built from a dirty tree, or names another commit than the
// gitlink in the index (what the next commit records).
//
// usage: node scripts/check-vendor-pin.mjs [app-root]

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** The vendor/enclawed-oss gitlink in `root`'s index, or null. */
export function vendorGitlink(root) {
  const r = spawnSync("git", ["-C", root, "ls-files", "-s", "--", "vendor/enclawed-oss"], { encoding: "utf8" });
  const m = r.status === 0 ? /^160000 ([0-9a-f]{40}) 0\tvendor\/enclawed-oss$/m.exec(r.stdout) : null;
  return m ? m[1] : null;
}

/** null when the built framework is the pinned commit, else why not. */
export function vendorPinProblem({ gitlink, source }) {
  if (!gitlink) {
    return "vendor/enclawed-oss is not a gitlink in the index";
  }
  if (!source || typeof source.commit !== "string") {
    return "the built framework records no source commit (rebuild it with scripts/build-dev-framework.mjs)";
  }
  if (source.dirty) {
    return `the built framework was made from a tree with uncommitted changes on top of ${source.commit}`;
  }
  if (source.commit !== gitlink) {
    return `the built framework is enclawed-oss ${source.commit.slice(0, 12)}, but vendor/enclawed-oss pins ${gitlink.slice(0, 12)}`;
  }
  return null;
}

export function checkVendorPin(root) {
  let source = null;
  try {
    source = JSON.parse(fs.readFileSync(path.join(root, ".enclawed-dev", "framework", "source.json"), "utf8"));
  } catch {
    /* missing or unreadable: no record */
  }
  return vendorPinProblem({ gitlink: vendorGitlink(root), source });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), ".."));
  const problem = checkVendorPin(root);
  if (problem) {
    console.error(`check-vendor-pin: ${problem}`);
    process.exit(1);
  }
  console.log(`check-vendor-pin: the built framework is the pinned enclawed-oss ${vendorGitlink(root)}`);
}
