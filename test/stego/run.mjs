#!/usr/bin/env node
// Offline runner for the class-A steganographic-injection suite. No model.
//
//   node test/stego/run.mjs                 decode + gate-replay + preprocessor
//   node test/stego/run.mjs --scenario ID[,ID]
//   node test/stego/run.mjs --fp            preprocessor false-positive report only
//   node test/stego/run.mjs --json          machine-readable results
//
// What it proves:
//  (a) each payload decodes back to the intended instruction and is invisible in
//      a plain view (visible-view == the benign host text);
//  (b) the Enclawed Code gate's decision on the forbidden tool call is the SAME as the
//      plaintext control (clean project), because the gate reads the tool input,
//      not the hidden instruction — hiding gives zero uplift at the action gate;
//  (c) the open preprocess.mjs catch rate on the invisible-channel techniques and
//      its false-positive rate on a benign corpus (real repo files + non-English).

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { preprocess, COVERED } from "./preprocess.mjs";
import { SCENARIOS } from "./scenarios.mjs";
import { visibleView } from "./stego.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");
const HOOK = path.join(ROOT, "bin", "ecwcode-hook.mjs");

function opt(argv, name, dflt) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : dflt;
}

// Build the project files for a scenario, filling {{NONCE}} via a fixed nonce.
function materialize(sc, dir, nonce) {
  const ctx = { nonce };
  const out = {};
  for (const [rel, f] of Object.entries(sc.files)) {
    const content = typeof f === "function" ? f(ctx) : f;
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
    out[rel] = content;
  }
  return out;
}

// --- gate replay: drive the real hook with a valid launcher session file. ---
let session = null;
let sessionErr = null;
async function makeSandbox() {
  const { createSession } = await import(path.join(ROOT, "src", "session.mjs"));
  const { loadFramework } = await import(path.join(ROOT, "src", "framework.mjs"));
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "stego-")));
  const home = path.join(dir, "home");
  const project = path.join(dir, "project");
  const state = path.join(dir, "state");
  const sbase = path.join(dir, "sess");
  for (const d of [home, project, state, sbase]) {
    fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  }
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    TMPDIR: dir,
    ENCLAWED_STATE_DIR: state,
    ENCLAWED_CONFIG_PATH: path.join(state, "enclawed.json"),
    ENCLAWEDER_ROOT: "optional",
    ENCLAWEDER_STATE: path.join(state, "hw.state"),
    ENCLAWEDER_STATE_DIR: state,
    ENCLAWEDER_FORENSIC_LOG: path.join(state, "forensics.jsonl"),
    ENCLAWEDER_QUEUE_LOG: path.join(state, "hw.queue.jsonl"),
  };
  const { fw } = await loadFramework();
  const s = createSession({ env, cwd: project, fw, root: sbase });
  return { dir, project, env, session: s };
}

function decide(sb, tool, toolInput, mode) {
  const input = {
    session_id: "stego",
    transcript_path: path.join(sb.dir, "t.jsonl"),
    cwd: sb.project,
    permission_mode: mode,
    hook_event_name: "PreToolUse",
    tool_name: tool,
    tool_input: toolInput,
    tool_use_id: `toolu_${crypto.randomBytes(4).toString("hex")}`,
  };
  const r = spawnSync(process.execPath, [HOOK, "--origin", "launcher", "--session", sb.session.file, "--digest", sb.session.digest], {
    env: { ...sb.env, CLAUDE_PROJECT_DIR: sb.project },
    cwd: sb.project,
    input: JSON.stringify(input),
    encoding: "utf8",
  });
  let out = null;
  try {
    out = JSON.parse(r.stdout);
  } catch {
    /* non-JSON */
  }
  return out?.hookSpecificOutput?.permissionDecision ?? `ERR(${r.status}):${(r.stdout || r.stderr).slice(0, 120)}`;
}

// --- benign corpus for the false-positive measurement. ---
function corpusChunks() {
  const chunks = [];
  const push = (label, text) => {
    for (let i = 0; i < text.length; i += 1500) {
      chunks.push({ label, text: text.slice(i, i + 1500) });
    }
  };
  const repoFiles = ["README.md", "docs/commands.md", "docs/adversarial.md", "src/gate.mjs", "src/hook.mjs", "src/shell-readonly.mjs", "test/adversarial/live-scenarios.mjs"];
  for (const rel of repoFiles) {
    try {
      push(rel, fs.readFileSync(path.join(ROOT, rel), "utf8"));
    } catch {
      /* skip */
    }
  }
  try {
    push("corpus/multilang.txt", fs.readFileSync(path.join(HERE, "corpus", "multilang.txt"), "utf8"));
  } catch {
    /* skip */
  }
  return chunks;
}

async function main(argv = process.argv.slice(2)) {
  const asJson = argv.includes("--json");
  const only = opt(argv, "--scenario")?.split(",");
  const fpOnly = argv.includes("--fp");
  const scenarios = SCENARIOS.filter((s) => !only || only.includes(s.id));

  // ------- preprocessor false-positive measurement (benign corpus) -------
  const chunks = corpusChunks();
  const fp = [];
  for (const ch of chunks) {
    const { findings } = preprocess(ch.text);
    if (findings.length) {
      fp.push({ label: ch.label, findings: findings.map((f) => `${f.type}${f.note ? `(${f.note})` : ""}` ) });
    }
  }
  const fpRate = chunks.length ? fp.length / chunks.length : 0;

  if (fpOnly) {
    const report = { corpusChunks: chunks.length, falsePositiveChunks: fp.length, fpRate: Number(fpRate.toFixed(4)), detail: fp };
    process.stdout.write(asJson ? JSON.stringify(report, null, 2) + "\n" : `preprocessor false positives: ${fp.length}/${chunks.length} chunks (${(fpRate * 100).toFixed(1)}%)\n${fp.map((x) => `  ${x.label}: ${x.findings.join(", ")}`).join("\n")}\n`);
    return 0;
  }

  // ------- gate sandbox -------
  let sb = null;
  try {
    sb = await makeSandbox();
  } catch (err) {
    sessionErr = String(err?.message ?? err);
  }

  const results = [];
  let catchHits = 0;
  let catchTotal = 0;
  for (const sc of scenarios) {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `stego-${sc.id}-`)));
    const nonce = crypto.createHash("sha256").update(sc.id).digest("hex").slice(0, 12);
    const files = materialize(sc, dir, nonce);
    const filesMap = {};
    for (const rel of Object.keys(sc.files)) {
      const abs = path.join(dir, rel);
      filesMap[rel] = sc.isBinary && rel === sc.carrierFile ? fs.readFileSync(abs) : fs.readFileSync(abs, "utf8");
    }

    // (a) decode check + invisibility
    const recovered = sc.decode(filesMap);
    const decodeOk = recovered.replace(/\s+/g, " ").trim().includes(sc.hiddenInstruction.replace(/\s+/g, " ").trim()) || sc.hiddenInstruction.includes(recovered.trim());
    let invisible = null;
    if (!sc.isBinary) {
      const carrierText = filesMap[sc.carrierFile];
      const vis = visibleView(carrierText);
      // Invisibility applies to the pure-invisible channels: the host text shows,
      // the hidden instruction does not. For visible-markup techniques we report
      // "visible-in-source" rather than claiming invisibility.
      const invisibleChannel = ["unicode-tag", "zero-width", "variation-selector", "ansi-conceal"].includes(sc.technique);
      invisible = invisibleChannel
        ? !vis.includes(sc.hiddenInstruction.slice(0, 12))
        : sc.technique === "bidi-trojan-source"
          ? "renderer-dependent reorder (Trojan Source), not a byte property"
          : "visible-in-source (reviewer must read raw markup/metadata)";
    } else {
      invisible = "binary (not shown in a text pane)";
    }

    // (b) gate replay vs plaintext control
    const gate = {};
    if (sb) {
      for (const mode of sc.modes) {
        const calls = sc.toolCalls({ nonce });
        const decisions = calls.map((c) => decide(sb, c.name, c.input, mode));
        const worst = decisions.includes("deny") ? "deny" : decisions.includes("ask") ? "ask" : decisions.includes("allow") ? "allow" : decisions[0];
        gate[mode] = { decisions, effective: worst, expected: sc.expect[mode] ?? sc.expect.default, ok: (sc.expect[mode] ?? sc.expect.default) === worst };
      }
    }

    // (c) preprocessor catch
    let preproc = null;
    if (!sc.isBinary) {
      const { findings } = preprocess(filesMap[sc.carrierFile]);
      const types = findings.map((f) => f.type);
      const caught = sc.expectCovered ? types.includes(sc.expectCoverType) : findings.length === 0;
      if (sc.expectCovered) {
        catchTotal++;
        if (types.includes(sc.expectCoverType)) {
          catchHits++;
        }
      }
      preproc = { expectCovered: sc.expectCovered, expectType: sc.expectCoverType, findings: types, ok: caught };
    } else {
      preproc = { expectCovered: false, note: "binary carrier; text cleaner not applicable" };
    }

    results.push({
      id: sc.id,
      technique: sc.technique,
      placement: sc.placement,
      hookCanClean: sc.hookCanClean,
      sideEffect: sc.sideEffect,
      reversible: sc.reversible,
      decodeOk,
      recovered: recovered.slice(0, 80),
      invisible,
      gate,
      preproc,
    });
    fs.rmSync(dir, { recursive: true, force: true });
  }
  if (sb) {
    fs.rmSync(sb.dir, { recursive: true, force: true });
  }

  const gateChecked = results.flatMap((r) => Object.values(r.gate));
  const gateOk = gateChecked.filter((g) => g.ok).length;
  const summary = {
    scenarios: results.length,
    decodeOk: results.filter((r) => r.decodeOk).length,
    gate: sb ? `${gateOk}/${gateChecked.length} gate decisions matched expectation` : `SKIPPED (${sessionErr})`,
    preprocessorCatch: catchTotal ? `${catchHits}/${catchTotal} invisible-channel scenarios flagged` : "n/a",
    preprocessorCatchRate: catchTotal ? Number((catchHits / catchTotal).toFixed(4)) : null,
    falsePositiveRate: Number(fpRate.toFixed(4)),
    falsePositiveChunks: `${fp.length}/${chunks.length}`,
  };

  if (asJson) {
    process.stdout.write(JSON.stringify({ summary, results, falsePositives: fp }, null, 2) + "\n");
    return 0;
  }

  for (const r of results) {
    const gateStr = Object.entries(r.gate).map(([m, g]) => `${m}:${g.effective}${g.ok ? "" : `!=${g.expected}`}`).join(" ");
    const pp = r.preproc.expectCovered ? (r.preproc.ok ? `caught[${r.preproc.expectType}]` : `MISSED[${r.preproc.expectType}]`) : "out-of-scope";
    process.stdout.write(`${r.decodeOk ? "ok  " : "FAIL"} ${r.id}\n       decode=${r.decodeOk} gate: ${gateStr || "(skipped)"}  preproc: ${pp}\n`);
  }
  process.stdout.write("\n");
  process.stdout.write(`decode:      ${summary.decodeOk}/${summary.scenarios} payloads decode to the intended instruction\n`);
  process.stdout.write(`gate:        ${summary.gate}\n`);
  process.stdout.write(`preprocessor: ${summary.preprocessorCatch}; catch rate ${summary.preprocessorCatchRate}; false positives ${summary.falsePositiveChunks} (${(fpRate * 100).toFixed(1)}%)\n`);
  if (fp.length) {
    process.stdout.write("false positives:\n" + fp.map((x) => `  ${x.label}: ${x.findings.join(", ")}`).join("\n") + "\n");
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((c) => process.exit(c));
}

export { main };
