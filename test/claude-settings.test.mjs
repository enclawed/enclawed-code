// Round 3, N9 (a): the --settings validator against Claude Code's own schema
// and the real binary.
//
// Claude Code drops a whole --settings file when one value fails its schema,
// Enclawed Code's hooks included, so every key Enclawed Code accepts in a user's
// --settings must be one Claude Code really loads. Three checks:
//   1. the validator refuses the values 2.1.326's zod schema rejects
//      (cleanupPeriodDays 0 and 1.5, an unknown permission mode, a shell
//      other than bash/powershell);
//   2. the zod definitions read from the installed binary
//      (scripts/claude-settings-schema.mjs) equal the pinned copy the
//      validator was derived from (test/fixtures/claude-settings-schema-*.json);
//   3. a settings file holding every accepted key, with every accepted
//      nested key, every hook event and every permission mode, really loads
//      in the real binary: its SessionStart hook runs. A file with
//      cleanupPeriodDays 0 does not (the oracle's negative control).
// 2 and 3 need the real `claude` (ECWCODE_REAL_CLAUDE, else
// ~/.local/bin/claude) and run it in a throwaway HOME and CLAUDE_CONFIG_DIR:
// SessionStart hooks run before the login check, so no account is used.
import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { claudeVersion, extractSchema } from "../scripts/claude-settings-schema.mjs";
import { KNOWN_HOOK_EVENTS, MERGEABLE_KEYS, PERMISSION_MODES, validateSettings } from "../src/settings.mjs";
import { ROOT } from "./helpers.mjs";

const REAL = process.env.ECWCODE_REAL_CLAUDE ?? path.join(process.env.ECWCODE_REAL_HOME ?? os.homedir(), ".local", "bin", "claude");
const haveReal = (() => {
  try {
    fs.accessSync(fs.realpathSync(REAL), fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
})();

test("N9a: the validator refuses what Claude Code 2.1.326's schema rejects", () => {
  const bad = [
    [{ cleanupPeriodDays: 0 }, /cleanupPeriodDays must be a number above 0/],
    [{ cleanupPeriodDays: 1.5 }, /cleanupPeriodDays/],
    [{ cleanupPeriodDays: -3 }, /cleanupPeriodDays/],
    [{ permissions: { defaultMode: "manual" } }, /defaultMode/],
    [{ hooks: { Stop: [{ hooks: [{ type: "command", command: "true", shell: "zsh" }] }] } }, /shell/],
  ];
  for (const [doc, re] of bad) {
    assert.match(validateSettings(doc).join("; "), re, JSON.stringify(doc));
  }
  assert.deepEqual(validateSettings({ cleanupPeriodDays: 1 }), []);
  assert.deepEqual(validateSettings({ cleanupPeriodDays: 3650 }), []);
});

// Every accepted key, with a value for every nested key Enclawed Code accepts.
function everyKeyDoc(canary) {
  const hooks = {};
  for (const event of KNOWN_HOOK_EVENTS) {
    hooks[event] = [{ ...(event === "PreToolUse" ? { matcher: "Bash" } : {}), hooks: [{ type: "command", command: "true", timeout: 5 }] }];
  }
  hooks.SessionStart = [
    {
      hooks: [
        { type: "command", command: "touch", args: [canary], timeout: 10, shell: "bash", async: false, statusMessage: "canary" },
        { type: "command", command: "true", onFailure: "block", if: "Bash(git *)" },
      ],
    },
  ];
  hooks.Stop = [{ hooks: [{ type: "command", command: "true", shell: "powershell" }] }];
  const doc = {
    $schema: "https://json.schemastore.org/claude-code-settings.json",
    model: "sonnet",
    outputStyle: "default",
    forceLoginMethod: "claudeai",
    theme: "dark",
    language: "english",
    cleanupPeriodDays: 1,
    includeCoAuthoredBy: true,
    disableAllHooks: false,
    enableAllProjectMcpServers: false,
    alwaysThinkingEnabled: false,
    spinnerTipsEnabled: true,
    respectGitignore: true,
    enabledMcpjsonServers: ["a"],
    disabledMcpjsonServers: ["b"],
    env: { ECWCODE_SCHEMA_TEST: "1" },
    statusLine: { type: "command", command: "true", padding: 0 },
    sandbox: {
      enabled: false,
      failIfUnavailable: false,
      allowUnsandboxedCommands: true,
      autoAllowBashIfSandboxed: false,
      excludedCommands: ["git status"],
      filesystem: { disabled: false, allowWrite: ["/tmp/x"], denyWrite: ["/tmp/y"], allowRead: ["/tmp/z"], denyRead: ["/tmp/w"] },
      network: { allowedDomains: ["example.com"], deniedDomains: ["example.org"], strictAllowlist: false },
    },
    permissions: { allow: ["Read"], deny: ["Bash(rm:*)"], ask: ["Write"], additionalDirectories: ["/tmp"], defaultMode: "default", disableBypassPermissionsMode: "disable", disableAutoMode: "disable" },
    hooks,
  };
  return doc;
}

const ACCEPTED_EXTRA = new Set(["apiKeyHelper"]); // run by its own file below: it changes authentication

function loads(dir, doc) {
  const canary = path.join(dir, "canary");
  fs.rmSync(canary, { force: true });
  const file = path.join(dir, "settings.json");
  fs.writeFileSync(file, JSON.stringify(doc));
  const env = { PATH: "/usr/bin:/bin", HOME: path.join(dir, "home"), CLAUDE_CONFIG_DIR: path.join(dir, "cfg"), TMPDIR: dir };
  spawnSync(REAL, ["-p", "hi", "--settings", file], { cwd: path.join(dir, "proj"), env, encoding: "utf8", timeout: 90_000 });
  return fs.existsSync(canary);
}

function scratch() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "enclawed-code-schema-")));
  for (const d of ["home", "cfg", "proj"]) {
    fs.mkdirSync(path.join(dir, d));
  }
  return dir;
}

test("N9a: the zod schema in the installed Claude Code equals the pinned copy the validator was derived from", { skip: !haveReal && "no real claude" }, () => {
  const bin = fs.realpathSync(REAL);
  const version = claudeVersion(bin);
  const fixture = path.join(ROOT, "test", "fixtures", `claude-settings-schema-${version}.json`);
  if (!fs.existsSync(fixture)) {
    assert.fail(`Claude Code ${version} has no pinned settings schema: run node scripts/claude-settings-schema.mjs --write, re-derive settings.mjs from the diff, and re-run this test`);
  }
  const pinned = JSON.parse(fs.readFileSync(fixture, "utf8"));
  // `zod` and `aliases` are the reviewed name maps (src/settings-schema.mjs), not extracted.
  const { zod: _zod, aliases: _aliases, ...extracted } = pinned;
  assert.deepEqual({ claudeCode: version, ...extractSchema(bin) }, extracted);
  // The runtime copy the validator is generated from is the pinned one.
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(ROOT, "src", "claude-settings-schema.json"), "utf8")), pinned);
  for (const k of MERGEABLE_KEYS) {
    assert.ok(pinned.keys[k], `${k} is in Claude Code's settings schema`);
  }
  assert.deepEqual(JSON.parse(pinned.nested.permissionModes).sort(), [...PERMISSION_MODES].sort());
  assert.deepEqual(new Set(JSON.parse(pinned.nested.hookEvents)), KNOWN_HOOK_EVENTS);
});

test("N9a: a --settings file with every accepted key, nested key, hook event and permission mode loads in the real binary", { skip: !haveReal && "no real claude", timeout: 600_000 }, () => {
  const dir = scratch();
  try {
    const canary = path.join(dir, "canary");
    // Negative control: the oracle sees a dropped file.
    assert.equal(loads(dir, { cleanupPeriodDays: 0, hooks: { SessionStart: [{ hooks: [{ type: "command", command: `touch ${canary}` }] }] } }), false, "cleanupPeriodDays 0 drops the file");
    const doc = everyKeyDoc(canary);
    assert.deepEqual(validateSettings(doc), [], "Enclawed Code accepts the whole document");
    const covered = new Set(Object.keys(doc));
    for (const k of MERGEABLE_KEYS) {
      assert.ok(covered.has(k) || ACCEPTED_EXTRA.has(k), `${k} is exercised`);
    }
    assert.equal(loads(dir, doc), true, "every accepted key loads");
    for (const mode of PERMISSION_MODES) {
      const d = { ...doc, permissions: { ...doc.permissions, defaultMode: mode } };
      assert.deepEqual(validateSettings(d), []);
      assert.equal(loads(dir, d), true, `defaultMode ${mode} loads`);
    }
    const helper = { apiKeyHelper: "/bin/false", hooks: doc.hooks };
    assert.deepEqual(validateSettings(helper), []);
    assert.equal(loads(dir, helper), true, "apiKeyHelper loads");
    // Boundaries of the numeric constraints Enclawed Code accepts.
    for (const d of [{ ...doc, cleanupPeriodDays: 3650 }, { ...doc, statusLine: { type: "command", command: "true", padding: 7 } }]) {
      assert.deepEqual(validateSettings(d), []);
      assert.equal(loads(dir, d), true, JSON.stringify(d).slice(0, 80));
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
