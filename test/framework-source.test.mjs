// The framework of an npm install is the enclawed package's framework entry and
// the modules it imports (framework.mjs frameworkImportClosure); that closure is
// what a launch measures (commitments.mjs measuredEntries).
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { frameworkImportClosure } from "../src/framework.mjs";

function distTree() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fw-closure-"));
  const w = (n, s) => fs.writeFileSync(path.join(dir, n), s);
  w("framework.js", 'import { a } from "./chunk-a.js";\nexport { a };\nconst later = () => import("./chunk-lazy.js");\n');
  w("chunk-a.js", 'import "./chunk-b.js";\nexport const a = 1;\nconst doc = "see import \\"./not-a-file.js\\" in the guide";\n');
  w("chunk-b.js", "export const b = 2;\n");
  w("chunk-lazy.js", 'export * from "./sub/deep.js";\n');
  fs.mkdirSync(path.join(dir, "sub"));
  w("sub/deep.js", "export const d = 4;\n");
  w("unrelated-product-chunk.js", "export const gateway = true;\n");
  return dir;
}

test("the closure is the entry and what it imports, statically or by literal dynamic import, sorted", () => {
  const dir = distTree();
  try {
    assert.deepEqual(frameworkImportClosure(path.join(dir, "framework.js")), [
      "chunk-a.js",
      "chunk-b.js",
      "chunk-lazy.js",
      "framework.js",
      "sub/deep.js",
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a module the framework adds to its imports joins the closure (and so the measurement)", () => {
  const dir = distTree();
  try {
    fs.appendFileSync(path.join(dir, "chunk-b.js"), 'import "./unrelated-product-chunk.js";\n');
    assert.ok(frameworkImportClosure(path.join(dir, "framework.js")).includes("unrelated-product-chunk.js"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
