// `ecwctl demo [--json] [--scenario ID]`: run every offline
// adversarial scenario in a throwaway sandbox and say, in plain language,
// what each attack was, what native Claude Code did in a recorded live run
// (or "not measured"), and what Enclawed Code did. No model is called, nothing
// costs anything, and the user's own Enclawed state is never touched.

import fs from "node:fs";
import path from "node:path";
import { DEFAULT_ROOT, createSandbox, holdRealRoot, releaseRealRoot } from "./demo-engine.mjs";
import { FEATURES, SCENARIOS } from "./demo-scenarios.mjs";

/** Recorded live results, written by test/adversarial/run.mjs --live. */
export const LIVE_SUMMARY = path.join(DEFAULT_ROOT, "docs", "adversarial-live-summary.json");

export function loadLiveSummary(file = LIVE_SUMMARY) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

async function runOne(scenario, { root, tmpRoot }) {
  const sb = createSandbox({ root, tmpRoot, name: scenario.id });
  const t0 = Date.now();
  try {
    const { checks, said } = await scenario.run(sb);
    return { id: scenario.id, ok: checks.every((c) => c.ok), checks, said, ms: Date.now() - t0 };
  } catch (err) {
    return {
      id: scenario.id,
      ok: false,
      checks: [{ name: "scenario ran", ok: false, detail: err?.stack ?? String(err) }],
      said: `could not run: ${err?.message ?? err}`,
      ms: Date.now() - t0,
    };
  } finally {
    sb.cleanup();
  }
}

/** Run the scenarios (a few at a time; each has its own sandbox). */
export async function runScenarios({ root = DEFAULT_ROOT, tmpRoot, only, concurrency = 4 } = {}) {
  const list = only ? SCENARIOS.filter((s) => only.includes(s.id)) : SCENARIOS;
  const results = new Array(list.length);
  let next = 0;
  const worker = async () => {
    while (next < list.length) {
      const i = next++;
      results[i] = await runOne(list[i], { root, tmpRoot });
    }
  };
  try {
    // With a real Enclaweder attached, every scenario's hooks check it.
    await holdRealRoot(root);
    await Promise.all(Array.from({ length: Math.min(concurrency, list.length) }, worker));
  } finally {
    await releaseRealRoot();
  }
  return list.map((s, i) => ({ ...results[i], features: s.features, attack: s.attack, simulated: s.simulated ?? null }));
}

/** "native ..." text for one scenario from the recorded live summary. */
export function nativeLine(summary, id) {
  const rows = summary?.scenarios?.[id]?.native;
  if (!Array.isArray(rows) || rows.length === 0) {
    return "native Claude Code: not measured";
  }
  return rows
    .map((r) => `native Claude Code in ${r.mode} (live, ${r.model}, ${r.date}): ${r.text}`)
    .join("; ");
}

export async function runDemo({ args = [], out = process.stdout, root = DEFAULT_ROOT, tmpRoot, summaryFile } = {}) {
  const json = args.includes("--json");
  const si = args.indexOf("--scenario");
  const only = si >= 0 && args[si + 1] ? args[si + 1].split(",") : undefined;
  if (only) {
    const unknown = only.filter((id) => !SCENARIOS.some((s) => s.id === id));
    if (unknown.length) {
      process.stderr.write(`ecwctl: unknown demo scenario ${unknown.join(", ")}; known: ${SCENARIOS.map((s) => s.id).join(", ")}\n`);
      return 2;
    }
  }
  const summary = loadLiveSummary(summaryFile);
  const results = await runScenarios({ root, tmpRoot, only });
  const passed = results.filter((r) => r.ok).length;
  if (json) {
    out.write(
      `${JSON.stringify(
        {
          passed,
          total: results.length,
          features: FEATURES,
          liveSummary: summary ? { generated: summary.generated, model: summary.model, claudeVersion: summary.claudeVersion } : null,
          scenarios: results.map((r) => ({ ...r, native: summary?.scenarios?.[r.id]?.native ?? null })),
        },
        null,
        2,
      )}\n`,
    );
    return passed === results.length ? 0 : 1;
  }
  out.write("Enclawed Code demo: planted instructions an agent might obey, replayed through Enclawed Code's real hook.\n");
  out.write("No model runs, nothing leaves this machine, and your own history and audit log are not touched.\n\n");
  for (const r of results) {
    out.write(`${r.ok ? "ok " : "!! "} ${r.id}\n`);
    out.write(`    attack:   ${r.attack}\n`);
    out.write(`    native:   ${nativeLine(summary, r.id).replace(/^native Claude Code: /, "")}\n`);
    out.write(`    ecwcode:  ${r.said}\n`);
    if (r.simulated) {
      out.write(`    simulated: ${r.simulated}\n`);
    }
    for (const c of r.checks.filter((c) => c.skipped)) {
      out.write(`    not run:  ${c.name} (${c.detail.replace(/^not run: /, "")})\n`);
    }
    for (const c of r.checks.filter((c) => !c.ok)) {
      out.write(`    FAILED: ${c.name}${c.detail ? ` (${c.detail})` : ""}\n`);
    }
  }
  const covered = new Set(results.flatMap((r) => r.features));
  out.write(`\n${passed}/${results.length} scenarios behaved as described, covering: ${[...covered].map((f) => FEATURES[f]).join("; ")}.\n`);
  out.write("Each Enclawed Code verdict came from ecwcode-hook's actual answer; the demo used a throwaway project and state directory.\n");
  out.write("Check your own sessions yourself:\n");
  out.write("  ecwctl audit verify       the hash-chained log of every decision is intact\n");
  out.write("  ecwctl audit reconcile    every tool call in your transcripts has a recorded decision\n");
  out.write("  ecwctl history list       file versions kept before each write (restore with: ecwctl history restore <id>)\n");
  if (!summary) {
    out.write("Native results: not measured on this install (see docs/adversarial.md to run the live comparison).\n");
  }
  return passed === results.length ? 0 : 1;
}
