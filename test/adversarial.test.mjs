// The offline adversarial layer, the mutation check, and `ecwctl demo`.
// No model calls: every verdict is ecwcode-hook's actual answer to the
// PreToolUse input a planted instruction produces.
import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { nativeLine, runScenarios } from "../src/demo.mjs";
import { FEATURES, SCENARIOS } from "../src/demo-scenarios.mjs";
import { mutationCheck } from "./adversarial/run.mjs";
import { CTL } from "./helpers.mjs";

test("every offline adversarial scenario passes against this install", async () => {
  const results = await runScenarios();
  assert.equal(results.length, SCENARIOS.length);
  for (const r of results) {
    const failed = r.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`);
    assert.ok(r.ok, `${r.id}: ${failed.join("; ")}`);
  }
});

test("every enclawed-derived feature maps to at least one scenario", () => {
  for (const f of Object.keys(FEATURES)) {
    assert.ok(SCENARIOS.some((s) => s.features.includes(f)), f);
  }
  for (const s of SCENARIOS) {
    for (const f of s.features) {
      assert.ok(Object.hasOwn(FEATURES, f), `${s.id}: unknown feature ${f}`);
    }
  }
});

test("mutation check: every deliberately broken gate makes the offline layer fail", async () => {
  const { rows, ok } = await mutationCheck({ log: () => {} });
  const survivors = rows.filter((r) => !r.killed).map((r) => r.id);
  assert.ok(ok, `mutants survived: ${survivors.join(", ")}`);
  assert.ok(rows.length >= 10);
});

function demo(args, env) {
  return spawnSync(process.execPath, [CTL, "demo", ...args], { env, encoding: "utf8", timeout: 120_000 });
}

function isolatedEnv() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-demo-test-")));
  const home = path.join(dir, "home");
  const tmp = path.join(dir, "tmp");
  fs.mkdirSync(home);
  fs.mkdirSync(tmp);
  return { dir, home, tmp, env: { PATH: process.env.PATH, HOME: home, TMPDIR: tmp } };
}

test("ecwctl demo: one plain-language block per scenario, a summary, and pointers", () => {
  const iso = isolatedEnv();
  try {
    const r = demo([], iso.env);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    for (const s of SCENARIOS) {
      assert.match(r.stdout, new RegExp(`ok  ${s.id}\\n    attack:   .+\\n    native:   .+\\n    ecwcode:  .+`), s.id);
    }
    assert.match(r.stdout, /blocked: deleting files needs your approval/);
    assert.match(r.stdout, /blocked: overwriting a file git does not keep needs your approval \(refused when nobody can approve\); a copy is kept either way/);
    assert.match(r.stdout, /audit log edit detected/);
    // Never a simulated device: with none attached the device halt is reported as not run.
    assert.doesNotMatch(r.stdout, /simulated: the Enclaweder/);
    assert.match(r.stdout, /not run: .*(no Enclaweder attached|real device event)/);
    assert.match(r.stdout, new RegExp(`${SCENARIOS.length}/${SCENARIOS.length} scenarios behaved as described`));
    assert.match(r.stdout, /ecwctl audit verify/);
    assert.match(r.stdout, /ecwctl history list/);
    // It touched neither HOME nor left sandboxes behind.
    assert.deepEqual(fs.readdirSync(iso.home), []);
    assert.deepEqual(fs.readdirSync(iso.tmp).filter((f) => f.startsWith("enclawed-code-demo-")), []);
  } finally {
    fs.rmSync(iso.dir, { recursive: true, force: true });
  }
});

test("ecwctl demo --json --scenario: machine-readable, filtered", () => {
  const iso = isolatedEnv();
  try {
    const r = demo(["--json", "--scenario", "delete-untracked-file,hardware-halt"], iso.env);
    assert.equal(r.status, 0, r.stderr);
    const j = JSON.parse(r.stdout);
    assert.equal(j.total, 2);
    assert.equal(j.passed, 2);
    assert.deepEqual(j.scenarios.map((s) => s.id), ["delete-untracked-file", "hardware-halt"]);
    assert.ok(j.scenarios[1].checks.some((c) => c.skipped), "the attached-device halt is reported as not run");
    assert.ok(j.scenarios[0].checks.every((c) => c.ok));
    const bad = demo(["--scenario", "nope"], iso.env);
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /unknown demo scenario nope/);
  } finally {
    fs.rmSync(iso.dir, { recursive: true, force: true });
  }
});

test("native column cites recorded live results, or says not measured", () => {
  assert.equal(nativeLine(null, "x"), "native Claude Code: not measured");
  const s = { scenarios: { x: { native: [{ mode: "acceptEdits", model: "m", date: "2026-11-21", text: "the file was deleted in 1/1 run" }] } } };
  assert.equal(nativeLine(s, "x"), "native Claude Code in acceptEdits (live, m, 2026-11-21): the file was deleted in 1/1 run");
});
