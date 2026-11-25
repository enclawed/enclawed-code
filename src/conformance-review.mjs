// The review judge cannot influence a decision, through Enclawed Code's own
// modules (review.mjs, review-model.mjs). The kit's side (the decision engine
// never imports the judge) is the kit's conformance check
// review-judge-no-influence; this one covers the adapter:
//
//   - the hook's static import graph (bin/ecwcode-hook.mjs: every module
//     loaded before a decision) excludes review.mjs and review-model.mjs;
//   - only the CLI dispatcher (admin.mjs, itself outside that graph) and the
//     review modules load them, and only by a dynamic import in the
//     dispatcher's "review" command;
//   - no module of the hook's graph, static or dynamic, names a kit review
//     function, so no decision code can call the judge;
//   - the review modules write nothing but their own state and the audit
//     log: no policy, grant, approval, pin or trust file is named in them.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STATIC = /(?:^|[;\n])\s*(?:import|export)\s+(?:[^"';]*?\s+from\s+)?["'](\.{1,2}\/[^"']+)["']/g;
const ANY = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}\/[^"']+)["']/g;
const REVIEW_MODULES = ["src/review.mjs", "src/review-model.mjs"];
const KIT_REVIEW_FUNCTIONS = /\b(?:prepareReviewText|reviewOf|reviewPrompt|runReview|parseReviewAnswer|correctOutcomes)\b/;
/** What the review modules must not name: the files that decide or authorize. */
const AUTHORITY_NAMES = /\b(?:userPolicyPath|writePolicy|approvalsFile|grantFile|pinStore|trustPaths|addSigner|signRecord|policyCommand|project-grants|opt-outs)\b/;

/** Repo-relative modules reachable from `entry` (repo-relative); `dynamic` also follows literal import(). */
export function importGraph(entry, { dynamic = false, root = ROOT } = {}) {
  const seen = new Set();
  const queue = [path.resolve(root, entry)];
  while (queue.length) {
    const f = queue.pop();
    if (seen.has(f)) {
      continue;
    }
    seen.add(f);
    const text = fs.readFileSync(f, "utf8");
    for (const m of text.matchAll(dynamic ? ANY : STATIC)) {
      const t = path.resolve(path.dirname(f), m[1]);
      if (fs.existsSync(t) && fs.statSync(t).isFile()) {
        queue.push(t);
      }
    }
  }
  return new Set([...seen].map((f) => path.relative(root, f).split(path.sep).join("/")));
}

/** Problems with the guarantee, empty when it holds. */
export function reviewInfluenceProblems(root = ROOT) {
  const problems = [];
  const hookStatic = importGraph("bin/ecwcode-hook.mjs", { root });
  for (const m of [...REVIEW_MODULES, "src/admin.mjs"]) {
    if (hookStatic.has(m)) {
      problems.push(`the hook loads ${m} before it decides`);
    }
  }
  const src = fs.readdirSync(path.join(root, "src")).filter((f) => f.endsWith(".mjs")).map((f) => `src/${f}`);
  for (const f of src) {
    if (REVIEW_MODULES.includes(f) || f === "src/admin.mjs") {
      continue;
    }
    const text = fs.readFileSync(path.join(root, f), "utf8");
    for (const m of text.matchAll(ANY)) {
      const t = path.relative(root, path.resolve(root, path.dirname(f), m[1])).split(path.sep).join("/");
      if (REVIEW_MODULES.includes(t)) {
        problems.push(`${f} imports ${t} (only the CLI dispatcher may)`);
      }
    }
  }
  const adminText = fs.readFileSync(path.join(root, "src/admin.mjs"), "utf8");
  if (/^\s*import\s[^(]*["']\.\/review(?:-model)?\.mjs["']/m.test(adminText)) {
    problems.push("admin.mjs imports the review modules statically (only its review command may, dynamically)");
  }
  const hookAll = importGraph("bin/ecwcode-hook.mjs", { dynamic: true, root });
  for (const f of hookAll) {
    // This check names them in its own pattern.
    if (REVIEW_MODULES.includes(f) || f === "src/admin.mjs" || f === "src/conformance-review.mjs" || !f.endsWith(".mjs")) {
      continue;
    }
    if (KIT_REVIEW_FUNCTIONS.test(fs.readFileSync(path.join(root, f), "utf8"))) {
      problems.push(`${f} names a kit review function`);
    }
  }
  for (const m of REVIEW_MODULES) {
    const text = fs.readFileSync(path.join(root, m), "utf8").replace(/^\s*\/\/.*$/gm, "");
    const hit = AUTHORITY_NAMES.exec(text);
    if (hit) {
      problems.push(`${m} names ${hit[0]}, a file or call that decides or authorizes`);
    }
  }
  return problems;
}

export function reviewChecks() {
  return [
    {
      id: "adapter:claude-code:review-cannot-influence",
      title: "claude-code: the review judge cannot influence a decision",
      proves:
        "Enclawed Code's evaluation-only review judge (ecwctl review) is outside the decision path: the hook's static import graph excludes the review modules and the CLI dispatcher, only the dispatcher's review command loads them, no module the hook can load names a kit review function, and the review modules name no policy, grant, approval, pin or trust file",
      remedy: "do not enable the review judge; report the failure to your Enclawed contact",
      run: async () => {
        const problems = reviewInfluenceProblems();
        if (problems.length) {
          throw new Error(problems.join("; "));
        }
      },
    },
  ];
}
