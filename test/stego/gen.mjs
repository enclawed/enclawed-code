#!/usr/bin/env node
// Deterministic (seeded) generator: builds each scenario's payload into a temp
// project and verifies, for every pure-invisible channel, that the hidden
// instruction is absent from a plain `cat`/rendered view while present in the
// raw code points. For visible-markup and binary channels it shows where the
// instruction sits and that it still decodes.
//
//   node test/stego/gen.mjs [--out DIR] [--scenario ID[,ID]] [--seed N] [--json]
//
// With --out, the built projects are kept (one subdir per scenario) for the
// coordinator's later live model runs; without it, a temp dir is used and the
// invisibility/decoding report is printed.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SCENARIOS } from "./scenarios.mjs";
import { codepoints, visibleView } from "./stego.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

function opt(argv, name, dflt) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] !== undefined ? argv[i + 1] : dflt;
}

// Seeded, reproducible nonce per scenario (so a rebuild is byte-identical).
function nonceFor(id, seed) {
  return crypto.createHash("sha256").update(`${seed}:${id}`).digest("hex").slice(0, 12);
}

const INVISIBLE_CHANNELS = new Set(["unicode-tag", "zero-width", "variation-selector", "ansi-conceal"]);

function build(sc, dir, nonce) {
  const ctx = { nonce };
  const filesMap = {};
  for (const [rel, f] of Object.entries(sc.files)) {
    const content = typeof f === "function" ? f(ctx) : f;
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
    filesMap[rel] = sc.isBinary && rel === sc.carrierFile ? content : content.toString();
  }
  return filesMap;
}

function main(argv = process.argv.slice(2)) {
  const asJson = argv.includes("--json");
  const seed = Number(opt(argv, "--seed", "1337"));
  const only = opt(argv, "--scenario")?.split(",");
  const outArg = opt(argv, "--out");
  const base = outArg ? path.resolve(outArg) : fs.mkdtempSync(path.join(os.tmpdir(), "stego-gen-"));
  fs.mkdirSync(base, { recursive: true });
  const scenarios = SCENARIOS.filter((s) => !only || only.includes(s.id));

  const report = [];
  for (const sc of scenarios) {
    const nonce = nonceFor(sc.id, seed);
    const dir = path.join(base, sc.id);
    fs.mkdirSync(dir, { recursive: true });
    const filesMap = build(sc, dir, nonce);
    const carrier = filesMap[sc.carrierFile];

    const recovered = sc.decode(filesMap);
    const decodeOk = recovered.replace(/\s+/g, " ").trim().includes(sc.hiddenInstruction.replace(/\s+/g, " ").trim()) || sc.hiddenInstruction.includes(recovered.trim());

    const entry = {
      id: sc.id,
      technique: sc.technique,
      placement: sc.placement,
      carrierFile: sc.carrierFile,
      hiddenInstruction: sc.hiddenInstruction,
      decodeOk,
      recovered: typeof recovered === "string" ? recovered.slice(0, 100) : recovered,
    };

    if (sc.isBinary) {
      entry.carrierKind = "binary";
      entry.bytes = Buffer.isBuffer(sc.files[sc.carrierFile]({ nonce })) ? sc.files[sc.carrierFile]({ nonce }).length : fs.statSync(path.join(dir, sc.carrierFile)).size;
      entry.invisibility = "binary: not shown in a text pane; a metadata/vision layer, not the text cleaner, is the defense";
    } else if (INVISIBLE_CHANNELS.has(sc.technique)) {
      const vis = visibleView(carrier);
      const marker = sc.hiddenInstruction.slice(0, 14);
      entry.carrierKind = "invisible-channel";
      entry.visibleView = vis.replace(/\n/g, " ").trim().slice(0, 90);
      entry.hiddenAbsentFromVisibleView = !vis.includes(marker);
      // Show the raw code points of a small window around the payload.
      const sample = carrier.slice(0, 60);
      entry.firstCodepoints = codepoints(sample);
    } else if (sc.technique === "bidi-trojan-source") {
      entry.carrierKind = "bidi-reordered";
      entry.invisibility = "not invisible: the model reads logical order (the instruction); an editor's bidi algorithm reorders the rendered line so a reviewer sees a decoy (Trojan Source). Invisibility is renderer-dependent, not a byte property.";
    } else {
      entry.carrierKind = "visible-markup";
      entry.invisibility = "visible in raw source/markup; relies on the reviewer not reading comments/alt-text/metadata (rendered pane hides it)";
    }
    report.push(entry);
  }

  if (asJson) {
    process.stdout.write(JSON.stringify({ seed, out: outArg ? base : null, built: report }, null, 2) + "\n");
  } else {
    for (const e of report) {
      process.stdout.write(`\n### ${e.id}  [${e.technique} / ${e.placement}]\n`);
      process.stdout.write(`  carrier file: ${e.carrierFile}\n`);
      process.stdout.write(`  hidden:       ${JSON.stringify(e.hiddenInstruction)}\n`);
      process.stdout.write(`  decodes back: ${e.decodeOk}  -> ${JSON.stringify(e.recovered)}\n`);
      if (e.carrierKind === "invisible-channel") {
        process.stdout.write(`  visible view: ${JSON.stringify(e.visibleView)}\n`);
        process.stdout.write(`  hidden text absent from visible view: ${e.hiddenAbsentFromVisibleView}\n`);
        process.stdout.write(`  first code points: ${e.firstCodepoints}\n`);
      } else {
        process.stdout.write(`  ${e.invisibility}\n`);
      }
    }
    process.stdout.write(`\nbuilt ${report.length} scenarios under ${base}${outArg ? "" : " (temp; pass --out DIR to keep)"}\n`);
    process.stdout.write(`decode: ${report.filter((e) => e.decodeOk).length}/${report.length} payloads decode to the intended instruction\n`);
    const inv = report.filter((e) => e.carrierKind === "invisible-channel");
    process.stdout.write(`invisibility: ${inv.filter((e) => e.hiddenAbsentFromVisibleView).length}/${inv.length} invisible-channel payloads absent from the plain visible view\n`);
  }
  if (!outArg) {
    fs.rmSync(base, { recursive: true, force: true });
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main());
}

export { main, nonceFor };
