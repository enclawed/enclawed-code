// Hooks with no administrator's grant from the person's own sources (their
// settings, a plugin, their skills and subagents, --settings): asked about at
// an interactive launch instead of refusing it.
//
// The question is put on the controlling terminal (/dev/tty), never read from
// standard input: nothing piped in, and nothing the session can write, answers
// it (the session does not exist yet). The default is No, which refuses the
// launch exactly as without the question. Yes starts this one session with
// those sources switched off; nothing is stored, and it is never a grant:
//   - a plugin: disabled for the session (enabledPlugins false in the
//     session's settings; a --plugin-dir plugin: that --plugin-dir is not
//     passed), since its hooks cannot be removed one by one;
//   - a hook in --settings: dropped from the merged session settings;
//   - a hook in the user's settings file: the session reads a copy of that
//     file without it (inside the session's own settings) instead of the file
//     itself (--setting-sources without "user"); the file is not touched;
//   - a skill's or subagent's frontmatter hook: the skill is switched off
//     (skillOverrides "off"), the subagent denied (permissions.deny), so the
//     hook's owner never runs.
// A granted hook runs as before, without a question.

import fs from "node:fs";
import path from "node:path";
import { askLine } from "./tty-question.mjs";
import { sanitizeText } from "./untrusted.mjs";

/** What switches one source off: its key in the question and in the audit record. */
export function sourceOf(h) {
  if (h.scope === "plugin") {
    return { kind: "plugin", key: `plugin ${h.pluginRoot}`, root: h.pluginRoot, pluginDir: Boolean(h.pluginDir) };
  }
  if (h.declaredBy) {
    return { kind: h.declaredBy.kind, key: `${h.declaredBy.kind} ${h.declaredBy.name} (${h.file})`, name: h.declaredBy.name, file: h.file };
  }
  if (h.scope === "--settings") {
    return { kind: "settings-flag", key: h.file, file: h.file };
  }
  return { kind: "user-settings", key: h.file, file: h.file };
}

/** The installed plugin ids whose install directory is `root` (installed_plugins.json v1 or v2). */
export function pluginIdsAt(root, configDir) {
  let installed = {};
  try {
    installed = JSON.parse(fs.readFileSync(path.join(configDir, "plugins", "installed_plugins.json"), "utf8"))?.plugins ?? {};
  } catch {
    installed = {};
  }
  const real = (p) => {
    try {
      return fs.realpathSync(p);
    } catch {
      return path.resolve(p);
    }
  };
  const r = real(root);
  const ids = [];
  for (const [id, v] of Object.entries(installed)) {
    for (const e of Array.isArray(v) ? v : [v]) {
      if (typeof e?.installPath === "string" && real(e.installPath) === r) {
        ids.push(id);
      }
    }
  }
  return [...new Set(ids)].sort();
}

/** The unapproved hooks grouped by source, in a stable order. */
export function groupBySource(hooks, { configDir = null } = {}) {
  const groups = new Map();
  for (const h of hooks) {
    const src = sourceOf(h);
    if (src.kind === "plugin" && configDir) {
      src.ids = pluginIdsAt(src.root, configDir);
    }
    if (!groups.has(src.key)) {
      groups.set(src.key, { source: src, hooks: [] });
    }
    groups.get(src.key).hooks.push(h);
  }
  return [...groups.values()].sort((a, b) => a.source.key.localeCompare(b.source.key));
}

/** The question's text (also what a refusal lists). */
export function questionText(groups, grantFile) {
  const lines = ["ecwcode: these hooks have no administrator's grant; a hook runs code inside the session, outside Enclawed's checks:"];
  for (const g of groups) {
    const what = { plugin: "plugin", skill: "skill", agent: "subagent", "settings-flag": "--settings", "user-settings": "settings file" }[g.source.kind];
    const label = g.source.kind === "plugin" ? (g.source.ids?.length ? `${g.source.ids.join(", ")} (${g.source.root})` : g.source.root) : g.source.kind === "skill" || g.source.kind === "agent" ? `${g.source.name} (${g.source.file})` : g.source.file;
    lines.push(`  ${what} ${sanitizeText(label, { max: 300 })}:`);
    for (const h of g.hooks) {
      lines.push(`    ${sanitizeText(h.event, { max: 60 })}: ${sanitizeText(h.command, { max: 160 })}`);
    }
  }
  lines.push(`Start this session without them (${groups.some((g) => g.source.kind === "plugin") ? "a plugin is switched off whole; " : ""}nothing is changed on disk or remembered; an administrator can grant them in ${grantFile})? [y/N] `);
  return lines.join("\n");
}

/**
 * Ask on the controlling terminal. Resolves true only for "y" or "yes"
 * (any case) followed by Enter; anything else, no terminal, Ctrl-C, Ctrl-D
 * or the timeout is No. Keys queued before the question are discarded.
 */
export async function askOnTerminal(text, { ttyPath = "/dev/tty", timeoutMs = 120_000 } = {}) {
  const answer = await askLine(text, { ttyPath, timeoutMs });
  return answer !== null && /^(y|yes)$/i.test(answer.trim());
}

/** A settings document without the given hook entries (compared by value), and without the matchers left empty. */
export function withoutHooks(doc, hooks) {
  if (!doc || typeof doc !== "object" || !doc.hooks || typeof doc.hooks !== "object") {
    return doc;
  }
  const drop = hooks.map((h) => JSON.stringify(h.raw));
  const out = { ...doc, hooks: {} };
  for (const [event, list] of Object.entries(doc.hooks)) {
    const kept = [];
    for (const m of Array.isArray(list) ? list : []) {
      const inner = (Array.isArray(m?.hooks) ? m.hooks : []).filter((x) => !hooks.some((h, i) => h.event === event && drop[i] === JSON.stringify(x ?? null)));
      if (inner.length > 0) {
        kept.push({ ...m, hooks: inner });
      }
    }
    if (kept.length > 0) {
      out.hooks[event] = kept;
    }
  }
  if (Object.keys(out.hooks).length === 0) {
    delete out.hooks;
  }
  return out;
}

/**
 * The plan for a session with these hooks' sources switched off.
 * @returns {{ ok: true, plan: object, record: object } | { ok: false, message: string }}
 */
export function excludeHooks(plan, hooks, { cwd = process.cwd(), configDir }) {
  const groups = groupBySource(hooks);
  const exclusion = { disabledPlugins: [], dropPluginDirs: [], userSettingsCopy: null, skillsOff: [], agentsDenied: [] };
  let userSettings = plan.userSettings;
  for (const g of groups) {
    const s = g.source;
    if (s.kind === "plugin") {
      if (s.pluginDir) {
        exclusion.dropPluginDirs.push(s.root);
      }
      exclusion.disabledPlugins.push(...pluginIdsAt(s.root, configDir));
    } else if (s.kind === "skill") {
      exclusion.skillsOff.push(s.name);
    } else if (s.kind === "agent") {
      exclusion.agentsDenied.push(s.name);
    } else if (s.kind === "settings-flag") {
      const i = Number(/(\d+)$/.exec(s.file)?.[1]) - 1;
      userSettings = userSettings.map((d, j) => (j === i ? withoutHooks(d, g.hooks) : d));
    } else {
      // The user's settings file: read once now, without these hooks; the session reads this copy.
      let doc;
      try {
        doc = JSON.parse(fs.readFileSync(s.file, "utf8"));
      } catch (err) {
        return { ok: false, message: `${s.file} cannot be read to start without its hooks (${err.message})` };
      }
      exclusion.userSettingsCopy = withoutHooks(doc, g.hooks);
      exclusion.userSettingsFile = s.file;
    }
  }
  exclusion.disabledPlugins = [...new Set(exclusion.disabledPlugins)].sort();
  const dropDirs = new Set(exclusion.dropPluginDirs);
  const args = dropDirs.size ? withoutPluginDirs(plan.args, dropDirs, cwd) : plan.args;
  const record = {
    sources: groups.map((g) => ({
      kind: g.source.kind,
      source: g.source.kind === "plugin" ? g.source.root : g.source.file,
      ...(g.source.name ? { name: g.source.name } : {}),
      ...(g.source.kind === "plugin" ? { ids: pluginIdsAt(g.source.root, configDir) } : {}),
      hooks: g.hooks.map((h) => ({ event: h.event, digest: h.wouldGrant?.digest ?? null })),
    })),
    disabledPlugins: exclusion.disabledPlugins,
    droppedPluginDirs: [...dropDirs],
    skillsOff: exclusion.skillsOff,
    agentsDenied: exclusion.agentsDenied,
    userSettingsCopy: exclusion.userSettingsFile ?? null,
  };
  return { ok: true, plan: { ...plan, args, userSettings, pluginDirs: (plan.pluginDirs ?? []).filter((d) => !dropDirs.has(d)), hookExclusion: exclusion }, record };
}

function withoutPluginDirs(args, dirs, cwd) {
  const end = args.indexOf("--") < 0 ? args.length : args.indexOf("--");
  const out = [];
  const resolve = (d) => path.resolve(cwd, d);
  for (let i = 0; i < args.length; i++) {
    if (i < end && args[i] === "--plugin-dir" && i + 1 < end && dirs.has(resolve(args[i + 1]))) {
      i++;
      continue;
    }
    if (i < end && args[i].startsWith("--plugin-dir=") && dirs.has(resolve(args[i].slice("--plugin-dir=".length)))) {
      continue;
    }
    out.push(args[i]);
  }
  return out;
}

/** The exclusion's effect on the session's settings (after Enclawed Code's own are merged). */
export function applyToSettings(settings, exclusion) {
  if (!exclusion) {
    return settings;
  }
  const s = { ...settings };
  if (exclusion.disabledPlugins.length) {
    s.enabledPlugins = { ...(s.enabledPlugins ?? {}), ...Object.fromEntries(exclusion.disabledPlugins.map((id) => [id, false])) };
  }
  if (exclusion.skillsOff.length) {
    s.skillOverrides = { ...(s.skillOverrides ?? {}), ...Object.fromEntries(exclusion.skillsOff.map((n) => [n, "off"])) };
  }
  if (exclusion.agentsDenied.length) {
    const deny = new Set([...(s.permissions?.deny ?? []), ...exclusion.agentsDenied.flatMap((n) => [`Agent(${n})`, `Task(${n})`])]);
    s.permissions = { ...(s.permissions ?? {}), deny: [...deny] };
  }
  return s;
}

/** The one stderr line said at the start of a session that runs without them. */
export function exclusionLine(record) {
  const parts = record.sources.map((x) => `${{ plugin: "plugin", skill: "skill", agent: "subagent", "settings-flag": "--settings", "user-settings": "settings file" }[x.kind]} ${x.name ?? (x.ids?.length ? x.ids.join(", ") : x.source)} (${x.hooks.map((h) => h.event).join(", ")})`);
  return `started without the hooks you declined, for this session only (a hook runs code outside Enclawed's checks; to keep one, an administrator grants it in /etc/enclawed/enclawed-code-opt-outs.json): ${parts.join("; ")}`;
}
