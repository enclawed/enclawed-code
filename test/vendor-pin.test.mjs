import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// The built framework must be the enclawed-oss commit vendor/enclawed-oss pins
// (scripts/check-vendor-pin.mjs over .enclawed-dev/framework/source.json).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkVendorPin, vendorPinProblem } from "../scripts/check-vendor-pin.mjs";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const A = "a".repeat(40);
const B = "b".repeat(40);

test("vendor pin: the same clean commit passes; another, a dirty build or no record fails", () => {
  assert.equal(vendorPinProblem({ gitlink: A, source: { commit: A, dirty: false } }), null);
  assert.match(vendorPinProblem({ gitlink: A, source: { commit: B, dirty: false } }), /pins aaaaaaaaaaaa/);
  assert.match(vendorPinProblem({ gitlink: A, source: { commit: A, dirty: true } }), /uncommitted changes/);
  assert.match(vendorPinProblem({ gitlink: A, source: null }), /no source commit/);
  assert.match(vendorPinProblem({ gitlink: null, source: { commit: A, dirty: false } }), /not a gitlink/);
});

test("vendor pin: read from a repository's index gitlink and its built framework's record", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cn-vendor-pin-"));
  try {
    const git = (...a) => assert.equal(spawnSync("git", ["-C", dir, ...a], { encoding: "utf8" }).status, 0);
    git("init", "-q");
    git("update-index", "--add", "--cacheinfo", `160000,${A},vendor/enclawed-oss`);
    const rec = path.join(dir, ".enclawed-dev", "framework");
    fs.mkdirSync(rec, { recursive: true });
    assert.match(checkVendorPin(dir), /no source commit/);
    fs.writeFileSync(path.join(rec, "source.json"), JSON.stringify({ commit: B, dirty: false }));
    assert.match(checkVendorPin(dir), /is enclawed-oss bbbbbbbbbbbb, but vendor\/enclawed-oss pins aaaaaaaaaaaa/);
    fs.writeFileSync(path.join(rec, "source.json"), JSON.stringify({ commit: A, dirty: false }));
    assert.equal(checkVendorPin(dir), null);
    // The gitlink bumped without a rebuild: the old build no longer passes.
    git("update-index", "--cacheinfo", `160000,${B},vendor/enclawed-oss`);
    assert.match(checkVendorPin(dir), /pins bbbbbbbbbbbb/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("vendor pin: this checkout's built framework is the commit its gitlink pins", () => {
  assert.equal(checkVendorPin(appRoot), null);
});
