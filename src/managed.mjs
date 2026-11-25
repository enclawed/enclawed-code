// The organization-wide settings template: Enclawed's hooks for every Claude
// Code session on a machine, whether started as `claude` or `ecwcode`,
// with the settings locks that keep a user from switching them off.
// `ecwctl managed print` fills in this installation's absolute paths; an
// administrator copies the result into Claude Code's managed-settings
// directory (see docs/enterprise.md). Enclawed Code never writes there itself.

import { kit } from "./kit.mjs";
import fs from "node:fs";
import path from "node:path";
import { authority } from "./authority.mjs";
import { enclawedHooks, hookCommand } from "./settings.mjs";

export const TEMPLATE_URL = new URL("../managed/enclawed-code.json", import.meta.url);
export const COMMAND_PLACEHOLDER = "__ECWCODE_HOOK_COMMAND__";

export function managedTemplate({ command, flavor = null, hardwareRoot = null } = {}) {
  const template = JSON.parse(fs.readFileSync(TEMPLATE_URL, "utf8"));
  const cmd = command ?? hookCommand({ origin: "managed", flavor, hardwareRoot });
  const text = JSON.stringify(template).replaceAll(
    JSON.stringify(COMMAND_PLACEHOLDER).slice(1, -1),
    JSON.stringify(cmd).slice(1, -1),
  );
  return JSON.parse(text);
}

// The hook programs of earlier releases: a managed file that still runs one
// blocks every tool call (the program is gone and the hooks fail closed).
const LEGACY_HOOK_NAMES = Object.freeze(["codenclawed-hook", "enclawde-hook"]);

/**
 * Managed settings files whose hook command runs an earlier release's hook
 * program: they must be regenerated with `ecwctl managed print`.
 * @returns {string[]} the files
 */
export function legacyManagedHookFiles(dir = authority().managedSettingsDir) {
  const out = [];
  for (const { file, doc } of readManagedSettings(dir)) {
    const commands = Object.values(doc?.hooks ?? {})
      .flatMap((entries) => (Array.isArray(entries) ? entries : []))
      .flatMap((e) => (Array.isArray(e?.hooks) ? e.hooks : []))
      .map((h) => (typeof h?.command === "string" ? h.command : ""));
    if (commands.some((c) => LEGACY_HOOK_NAMES.some((n) => new RegExp(`(^|[/\\s'"])${n}(\\.mjs)?(['"\\s]|$)`).test(c)))) {
      out.push(file);
    }
  }
  return out;
}

/** The template's hooks must stay identical to what the launcher injects. */
export function expectedManagedHooks() {
  return enclawedHooks(COMMAND_PLACEHOLDER);
}

/** The managed settings Claude Code would read: managed-settings.json, then drop-ins alphabetically. */
export function readManagedSettings(dir = authority().managedSettingsDir) {
  const files = [path.join(dir, "managed-settings.json")];
  try {
    for (const f of fs.readdirSync(path.join(dir, "managed-settings.d")).sort()) {
      if (f.endsWith(".json") && !f.startsWith(".")) {
        files.push(path.join(dir, "managed-settings.d", f));
      }
    }
  } catch {
    /* no drop-in directory */
  }
  const docs = [];
  for (const f of files) {
    let text;
    try {
      text = fs.readFileSync(f, "utf8");
    } catch {
      continue;
    }
    try {
      docs.push({ file: f, doc: JSON.parse(text) });
    } catch {
      docs.push({ file: f, doc: null, invalid: true });
    }
  }
  return docs;
}

/**
 * Do the managed settings really run Enclawed Code's hooks on every event, with
 * the same structure the launcher would inject (red-team I10)? Merges
 * managed-settings.json and its drop-ins the way Claude Code does (hook lists
 * concatenate), then requires, per event, an entry structurally equal to
 * expectedManagedHooks() whose command runs an existing ecwcode-hook in
 * managed mode, plus allowManagedHooksOnly.
 *
 * @returns {{ installed: boolean, reason: string, files: string[] }}
 */
export function managedHooksStatus(dir = authority().managedSettingsDir) {
  // Whether they are installed, unmodified and locked is the kit's decision
  // (managed-hooks.ts); the template, the script names and the lock key are Claude Code's.
  return kit.managedHooksStatus(readManagedSettings(dir), {
    expected: expectedManagedHooks(),
    placeholder: COMMAND_PLACEHOLDER,
    hookScriptNames: ["ecwcode-hook", "ecwcode-hook.mjs"],
    managedArgs: ["--origin", "managed"],
    lockKey: "allowManagedHooksOnly",
  });
}
