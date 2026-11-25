// Skill admission: before a session starts, every skill Claude Code would
// load is verified against its signed formal bundle by the biconditional
// criterion (Metere, "A Trust Schema and a Biconditional Correctness
// Criterion for Agent Skills"; the open implementation is enclawed-oss
// enclawed/src/skill-formal-bundle.mjs, loaded through formal.mjs).
//
// A skill's declared specification is its capability set M.caps, given in
// its SKILL.md frontmatter (`enclawed-capabilities: [fs.read, spawn.proc]`;
// none declared means none). Its implementation is every file in its
// directory. The skill is admissible only when the effects its scripts can
// produce (Method A, the framework's sound static effect analysis, unionEffects)
// EQUAL M.caps, in both directions:
//
//   (=>) every effect the implementation can produce is declared
//        (containment: no undeclared side effect, no reflective construct
//        that lifts the analysis to TOP, no file the analysis cannot read);
//   (<=) every declared capability is produced by the implementation
//        (no declared behavior the implementation does not have).
//
// The skill's bundle (static.json, types.proof.json, smt.unsat.json and the
// Ed25519-signed manifest.attest.json, produced by produceFormalBundle) is a
// cache, not a trust source: at every launch the launcher recomputes the
// skill's manifest from disk (its content digest pins every file, SKILL.md
// included), checks the attestation's manifest hash and signature against
// the trust list (trust.mjs), re-runs Methods A, B and C (verifyFormalBundle)
// and the biconditional. A skill whose files changed after signing is
// "tampered"; one that no longer reproduces its evidence is "drifted"; one
// with no bundle is "unverified". None of them is admitted.
//
// Bundles live in Enclawed Code's own state (<state>/claude-code/skills/), which
// the agent may not write; `ecwctl skills sign` writes them after
// two-factor authentication.
//
// Every decision above is the kit's (enclawed-oss adapter/skills.ts:
// verifySkill, signSkill, admitSkills, skillDrift, and the engine's skill
// rule over the session's SkillSet). This file keeps Claude Code's skill
// roots (project, nested, user, --add-dir, enabled plugins, --plugin-dir),
// how a plugin's skills are named, and how a skill is switched off
// (skillOverrides "off").

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { kit } from "./kit.mjs";
import { comparablePath } from "./paths.mjs";
import { appStateDir } from "./paths.mjs";
import { trustDir } from "./trust.mjs";
import { claudeCodeEvent } from "./workflow.mjs";

export const SKILL_CAPS = kit.SKILL_CAPS;

export function skillStoreDir(env = process.env) {
  return path.join(appStateDir(env), "skills");
}

// The frontmatter, manifest and biconditional are the kit's.
export const parseFrontmatter = (text) => kit.parseFrontmatter(text);
export const declaredCaps = (front) => kit.declaredCaps(front);
export const contentDigest = (dir) => kit.contentDigest(dir);
export const skillManifest = (skill) => kit.skillManifest(skill);
export const biconditional = (methodA, declared) => kit.biconditional(methodA, declared);

// ------------------------------------------------------------------ Claude Code's skill roots

function isDir(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function readJsonFile(f) {
  try {
    return JSON.parse(fs.readFileSync(f, "utf8"));
  } catch {
    return null;
  }
}

/** The install directories of the plugins Claude Code would enable (installed_plugins.json v1 or v2). */
export function enabledPluginRoots({ configDir, projectDir, settingSources = null, extraSettings = [] }) {
  const sources = settingSources ?? ["user", "project", "local"];
  const docs = [];
  if (sources.includes("user")) {
    docs.push(readJsonFile(path.join(configDir, "settings.json")));
  }
  if (sources.includes("project")) {
    docs.push(readJsonFile(path.join(projectDir, ".claude", "settings.json")));
  }
  if (sources.includes("local")) {
    docs.push(readJsonFile(path.join(projectDir, ".claude", "settings.local.json")));
  }
  docs.push(...extraSettings);
  const enabled = new Map();
  for (const d of docs) {
    const e = d?.enabledPlugins;
    if (e && typeof e === "object" && !Array.isArray(e)) {
      for (const [k, v] of Object.entries(e)) {
        enabled.set(k, v === true || (Array.isArray(v) && v.length > 0));
      }
    }
  }
  const installed = readJsonFile(path.join(configDir, "plugins", "installed_plugins.json"))?.plugins ?? {};
  const out = [];
  for (const [key, on] of enabled) {
    if (!on) {
      continue;
    }
    const entries = Array.isArray(installed[key]) ? installed[key] : installed[key] ? [installed[key]] : [];
    for (const e of entries) {
      if (typeof e?.installPath === "string") {
        out.push(e.installPath);
      }
    }
  }
  return out;
}

function pluginName(skillsDir) {
  const pluginRoot = path.dirname(skillsDir);
  try {
    const m = JSON.parse(fs.readFileSync(path.join(pluginRoot, ".claude-plugin", "plugin.json"), "utf8"));
    if (typeof m?.name === "string" && m.name) {
      return m.name;
    }
  } catch {
    /* no manifest */
  }
  return path.basename(pluginRoot);
}

/**
 * The skill roots Claude Code would load for this session (the kit's
 * SkillRoot list): the project's `.claude/skills` (and nested ones below it),
 * the user's `<config dir>/skills`, `--add-dir` directories' `.claude/skills`,
 * and the skills of plugins (installed under `<config dir>/plugins` and
 * enabled, and `--plugin-dir` directories), named `<plugin>:<skill>`.
 */
export function claudeSkillRoots({ projectDir, env = process.env, addDirs = [], pluginDirs = [], settingSources = null, extraSettings = [] }) {
  const configDir = env.CLAUDE_CONFIG_DIR || path.join(env.HOME || os.homedir(), ".claude");
  const own = path.join(projectDir, ".claude", "skills");
  const roots = [{ dir: own, scope: "project" }];
  for (const nested of kit.findNestedDirs(projectDir, [".claude", "skills"], 4)) {
    if (comparablePath(nested) !== comparablePath(own)) {
      roots.push({ dir: nested, scope: "project-nested" });
    }
  }
  roots.push({ dir: path.join(configDir, "skills"), scope: "user" });
  for (const d of addDirs) {
    roots.push({ dir: path.join(d, ".claude", "skills"), scope: "add-dir" });
  }
  // Installed plugins load only when enabled (enabledPlugins in a settings
  // source Claude Code reads: --setting-sources, and --settings).
  const pluginSkillDirs = enabledPluginRoots({ configDir, projectDir, settingSources, extraSettings }).filter((d) => isDir(path.join(d, "skills"))).map((d) => path.join(d, "skills"));
  for (const d of pluginDirs) {
    if (isDir(path.join(d, "skills"))) {
      pluginSkillDirs.push(path.join(d, "skills"));
    } else {
      // A folder of plugins loads each child.
      pluginSkillDirs.push(...kit.findNestedDirs(d, ["skills"], 1));
    }
  }
  for (const sd of pluginSkillDirs) {
    roots.push({ dir: sd, scope: "plugin", prefix: `${pluginName(sd)}:` });
  }
  return roots;
}

/**
 * Every skill Claude Code would load for this session (kit.discoverSkills over
 * claudeSkillRoots).
 * @returns {{ skills: Array<{ name, scope, dir, root, skillFile, linkedDir }>, roots: string[] }}
 */
export function discoverSkills(o) {
  return kit.discoverSkills(claudeSkillRoots(o));
}

// ------------------------------------------------------------------ bundles (the kit's)

/** The kit's skill store: bundles in Enclawed Code's state, signers on its trust list. */
function storeOf(env, formal) {
  const f = formal && typeof formal.verifyFormalBundle === "function" ? formal : kit.frameworkFormal;
  return { storeDir: skillStoreDir(env), trustDir: trustDir(env), formal: f };
}

/** Where a skill's bundle is kept: one directory per (scope, real directory, name). */
export function bundleDirFor(skill, env = process.env) {
  return kit.bundleDirFor(skill, skillStoreDir(env));
}

/**
 * Verify one discovered skill against its bundle (kit.verifySkill).
 * @returns {{ name, scope, dir, status: "verified"|"unverified"|"tampered"|"drifted"|"failed", reasons: string[], caps?: string[], contentDigest?: string, signer?: string }}
 */
export function verifySkill({ formal, skill, env = process.env }) {
  return kit.verifySkill(storeOf(env, formal), skill);
}

/** Verify every discovered skill. */
export function verifyAll({ formal, discovered, env = process.env }) {
  return discovered.skills.map((skill) => verifySkill({ formal, skill, env }));
}

/**
 * Produce, verify and store a skill's signed formal bundle (kit.signSkill:
 * a skill that does not satisfy the biconditional is refused before
 * `authorize` runs). `authorize(detail)` verifies the person; without one the
 * caller must have done so already.
 * @returns {Promise<{ manifest, bundleDir, attestation, effects }>}
 */
export async function signSkill({ formal, skill, signer, env = process.env, authorize = async () => {} }) {
  const store = storeOf(env, formal);
  const r = await kit.signSkill(store, skill, signer, authorize);
  return { ...r, attestation: store.formal.readFormalBundle(r.bundleDir).attestation };
}

/** Remove a skill's bundle (it is unverified again): kit.unsignSkill. */
export async function unsignSkill(skill, env = process.env, authorize = async () => {}) {
  return kit.unsignSkill(storeOf(env, null), skill, authorize);
}

// ------------------------------------------------------------------ session

// Kept in the session's skill set so the drift watcher re-reads the same roots.
const scopeOf = (o) => ({ addDirs: o.addDirs ?? [], pluginDirs: o.pluginDirs ?? [], settingSources: o.settingSources ?? null, extraSettings: (o.extraSettings ?? []).map((d) => ({ enabledPlugins: d?.enabledPlugins ?? {} })) });

/**
 * The launcher's skill decision for a session (kit.admitSkills). `session`
 * is the kit's SkillSet (verified, excluded, roots), plus the roots' inputs
 * for the drift watcher: what the session file carries and the engine's
 * `skills` option takes. `overrides` switches the excluded skills off in
 * Claude Code's settings (skillOverrides, schema 2.1.326).
 * @returns {{ ok: true, session: object, overrides: Record<string,string>, results: object[], warnings: string[] } | { ok: false, message: string, results: object[] }}
 */
export function admitSkills({ formal, projectDir, env, addDirs = [], pluginDirs = [], settingSources = null, extraSettings = [], mode = "refuse" }) {
  const discovered = discoverSkills({ projectDir, env, addDirs, pluginDirs, settingSources, extraSettings });
  const a = kit.admitSkills(storeOf(env, formal), discovered, mode === "exclude" ? "exclude" : "refuse");
  if (!a.ok) {
    return { ...a, message: `${a.message}. List them with \`ecwctl skills list\`; after review, sign one with \`ecwctl skills sign <name>\`, or remove it` };
  }
  const overrides = Object.fromEntries(a.session.excluded.map((s) => [s.name, "off"]));
  return { ...a, overrides, session: { ...a.session, ...scopeOf({ addDirs, pluginDirs, settingSources, extraSettings }) } };
}

/**
 * Watch the skills of a running session (kit.watchSkills, polled): a verified
 * skill whose files change, or a skill that appears or reappears, calls
 * `onDrift`.
 */
export function watchSkills(sessionSkills, { projectDir, env, onDrift, intervalMs = 1000 }) {
  const rediscover = () => discoverSkills({ projectDir, env, ...scopeOf(sessionSkills) });
  return kit.watchSkills(sessionSkills, rediscover, onDrift, intervalMs);
}

// ------------------------------------------------------------------ gate

// A profile that admits nothing: the kit's rules after the skill rule never
// run in skillVerdict (the workflow rule refuses first), so its answer is the
// skill rule's alone.
const STOP = kit.parseProfile("skill-rule-only", { tools: [], paths: { read: [], write: [] } });

/**
 * The skill rule at the gate (launcher sessions), decided by the kit's
 * engine over the session's SkillSet: the Skill tool may load only a
 * verified skill, and no shell command may run, or run from, a file under a
 * skill directory that is not in the verified set.
 * @returns {Promise<null | { code: string, reason: string }>}
 */
export async function skillVerdict(skills, tool, ti, { cwd, home = null }) {
  if (!skills) {
    return null;
  }
  const at = typeof cwd === "string" && path.isAbsolute(cwd) ? cwd : "/";
  const d = await kit.decidePreAction(claudeCodeEvent(tool, ti, { cwd: at }), {
    host: "claude-code",
    historyRestoreCommand: "ecwctl history restore",
    policy: null,
    projectDir: at,
    home,
    history: null,
    hardware: () => ({ allowed: true }),
    skills,
    workflow: STOP,
  });
  // The gate adds its own "Enclawed: " prefix.
  const reason = d.reason.startsWith(kit.REASON_PREFIX) ? d.reason.slice(kit.REASON_PREFIX.length) : d.reason;
  return d.codes.includes("skill-not-verified") ? { code: "skill-not-verified", reason } : null;
}
