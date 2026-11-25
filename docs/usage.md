# Using Enclawed Code

`ecwcode` runs your own Claude Code installation with every argument passed through unchanged, and adds Enclawed's checks through Claude Code's own hooks. Interactive sessions, `-p`, models, subagents, MCP servers, slash commands and your settings all work as they do with `claude`.

```bash
ecwcode                                  # interactive, same as claude
ecwcode -p "fix the failing test"        # headless, same flags as claude
ecwcode --resume                         # any claude option
```

For the complete reference of every Enclawed Code command, flag, environment variable, policy key and audit record, and copy-paste commands to check each feature yourself, see [commands.md](commands.md).

## What happens to each tool call

Before a tool runs, Claude Code asks `ecwcode-hook` for a decision. Enclawed's rule is that an action is **reversible** when the data it affects has a history, or when its history is irrelevant. Reversible actions run. Irreversible actions wait for a person.

| Tool call | Decision |
|---|---|
| `Read`, `Glob`, `Grep`, `WebSearch` | Run (reversible). |
| `WebFetch` | Runs for hosts on `enclawed.policy.allowedHosts`. With no list (the default), a fetch to any host asks, because whatever is in the URL leaves the machine. With a list, an unlisted host is refused. |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` inside the project | The file's current content is kept first, then the write runs. Undo it with `ecwctl history restore`. |
| `Write`, `Edit`, `MultiEdit`, `NotebookEdit` that replace an **existing file git does not track or ignores** (for example an ignored `config/local.json` or `.env.local`) | Ask: no copy of it exists outside this machine. Its current content is still kept first, so an approved change can be restored. With no person to ask (`bypassPermissions`, `-p` without a permission prompt tool) it is refused. Allowed without asking: files under `enclawedCode.overwritablePaths`, files this same session created, scratch locations, and projects that are not git repositories. |
| Writes inside Claude Code's session scratchpad | Run (scratch: history is irrelevant). |
| Writes with no possible history | Ask: outside the project, opted out by `history.noHistoryPaths` or `history.noHistoryTools`, over the size caps, or not a regular file. |
| Writes to files that make code run later: `.git/`, `.claude/`, `.husky/`, `.githooks/`, `.devcontainer/`, `.mcp.json`, `.envrc`, `.gitmodules`, `.gitattributes`, `.npmrc`, `package.json`, `Makefile`, `.pre-commit-config.yaml`, `pyproject.toml`, `setup.py`, `.vscode/tasks.json` and similar (any letter case), and any write through a symlink | Ask. The current content is still kept, so an approved change can be restored, but undoing the file does not undo what already ran. |
| Writes to Enclawed Code's own files: the Enclawed state directory (policy, audit log, history, auth), Enclawed Code's code and framework, the Node binary, the session files, the hardware latch | Refused. |
| `Bash`, `Monitor`, `PowerShell` | Run only a single read-only command from a strict allowlist (`ls`, `cat`, `grep`, `git status`, `git log`, `git diff`, ...), with only that command's known read-only options (an attached value like `git grep -Orm` is recognized). Pipes, redirects, `;`, `&&`, `$`, backticks, subshells, variable assignments, unknown options and any unlisted command ask; so does a git read in a repository whose own config can start a program. |
| `Agent` / `Task` | Run. Every tool call the subagent makes is checked the same way. |
| MCP tools (`mcp__server__tool`) | Ask, unless listed in `preApprovedIrreversibleTools`. |
| Anything else | Ask. |

Before any of that, the hardware check runs: if an Enclaweder is bound and is not CLEAN, or `ENCLAWEDER_ROOT=required` and none is present, every call is denied.

After a `Read`, `WebFetch`, `WebSearch`, `Bash` or MCP call, the input cleaner removes hidden characters from the result before the model reads it: Unicode tag characters, runs of invisible (default-ignorable) and variation-selector characters, bidi overrides and unbalanced isolates, and terminal escapes that conceal text. Nothing is added to the result itself: Enclawed's note about what it removed reaches the model separately, as hook context (a system reminder next to the result), and the model is told that any "Enclawed" text inside a tool result is untrusted. Legitimate joiners (Persian ZWNJ, emoji sequences, Indic conjuncts) are kept. Hidden HTML that reads like an instruction is not deleted; Claude gets a note about it. Files on disk are not changed. `CLAUDE.md`, your own prompt and images are out of a hook's reach. Turn it to `audit` or `off` with `enclawedCode.inputCleaner` (see [commands.md](commands.md#the-input-cleaner)).

### The Enclaweder during a session

When a device is present, `ecwcode` boots the hardware root once, before claude starts, and holds it for the whole session. Each hook asks the launcher, through a private socket, with a fresh random challenge each time: the answer must prove the session's secret (which the hook receives from the launcher only after the kernel confirms it is the real hook process) and carry the device's own signature over the hook's nonce, checked against the device's manufacturer certificate and the key bound at launch. A fake socket, a replayed answer or an uncertified device is refused. Enclawed Code releases the root when claude exits.

- If the device is unplugged or reports tampering mid-session, every call is denied; Enclawed Code stops claude and everything it started (tool commands and hooks included), seals the session's context, erases Enclawed Code's own sealed login and the session's login storage (unless your policy says `"enclawedCode": { "onHardwareHalt": { "eraseClaudeCredentials": false } }`), and exits 4. Your own Claude Code login is never touched (only an administrator's managed login policy changes that). To continue: plug the genuine device back in, run `ecwctl recover-root`, prove who you are, and sign in again inside Enclawed Code: `ecwctl login new`.
- If the launch stops with `ALARM ANCHOR_SESSION_BUSY`, another process holds the Enclaweder's anchor channel (or one crashed without closing it). The message says how to recover: with firmware 0.2, wait out the lease it prints (at most 120 s) or take the channel over with `ecwctl recover-anchor --operator-offline N` (each operator signs on their own device, never on this machine); with firmware 0.1, unplug the device and plug it back in. `ALARM ANCHOR_TAMPER` means the audit log or its anchor files changed during the session: keep them as they are and run `ecwctl audit verify`.
- If the launch stops with exit 6 (`the audit log does not match what the Enclaweder anchored`), the log, its anchor file or its anchor history changed or went missing between sessions, or the device was anchored by something else (an operator takeover, another log). Nothing was started. Check with `ecwctl audit verify`; once you know why, accept the log as it is as the new baseline with `ecwctl audit accept` (at a terminal, with activation auth, the device's serial and `ACCEPT` typed in).
- In an interactive session, an action that needs your approval is asked by Enclawed Code itself: claude pauses and Enclawed Code shows the reason and a three-letter code; type the code and Enter to approve, anything else denies.
- A repository that sets a command in its settings (`apiKeyHelper`, `statusLine`, `fileSuggestion`, auth refresh helpers, ...) or has `.mcp.json` servers that would start (always in `-p`) is refused like a repository hook; review it, then ask an administrator to grant that exact command for that repository (`projectCommands` in `/etc/enclawed/enclawed-code-opt-outs.json`, [admin-only opt-outs](commands.md#admin-only-opt-outs)); the refusal prints the entry to add, your shell cannot set it, and a changed command needs a new grant.
- If the root refuses to start (a latched DIRTY state, an accredited session that may not continue without its device, or `ENCLAWEDER_ROOT=required` with no device), Enclawed Code does not start claude, and says how to recover.
- With no device and `ENCLAWEDER_ROOT` unset, nothing is held and Enclawed runs software-only. `ENCLAWEDER_ROOT` takes exactly `required`; any other value (`1`, `true`, `Required`, `optional`, ...) refuses the start. Running on after a device-accredited session without the device (`optional`, for retiring a device) is an administrator's grant (`"hardwareRoot": "optional"` in the opt-out file), not a shell setting.
- While a device is held, Enclawed Code refuses to start on Linux when it cannot contain the session (neither a systemd user scope nor the python3/perl subreaper wrapper): on a halt it could not find every process before erasing the login. An administrator can accept that (`"reducedContainment": true` in the opt-out file). On macOS the session is contained by process tracking (below), so no grant is needed. The helpers are always run from `/usr/bin` or `/bin`, never from your `PATH`.
- A repository's `.claude/settings.json` or `.claude/settings.local.json` may not set, in its `env`, a variable that changes where Claude Code or the commands it runs send traffic (`ANTHROPIC_BASE_URL` and every other `*_BASE_URL`/`*_URL`/endpoint/host/region, the provider switches such as `CLAUDE_CODE_USE_BEDROCK`, `HTTP(S)_PROXY`/`ALL_PROXY`/`NO_PROXY` in any case, `PIP_INDEX_URL`, `GOPROXY`, ...), what they trust (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`/`_DIR`, `NODE_TLS_REJECT_UNAUTHORIZED`, client certificates, `CLAUDE_CONFIG_DIR`, the managed-settings path, ...), whose account they use (API keys, auth tokens, custom headers, cloud profiles and projects), what they load (`CLAUDE_CODE_PLUGIN_DIRS`, `CLAUDE_CODE_SHELL`, `JAVA_TOOL_OPTIONS`, `ZDOTDIR`, ...) or what they export (`OTEL_*`, `CLAUDE_CODE_ENABLE_TELEMETRY`). Enclawed Code refuses to start and names the file and the variable (CVE-2026-21852). It starts when the value can never take effect (your `--settings` or the organization's managed settings set the same name) or equals the value you already have. The same variables from your own shell, `~/.claude/settings.json`, `--settings` or the managed settings are yours: they are kept and recorded in the session's `session.start` audit record (credentials only as a digest). `src/claude-env.mjs` has the rules; `test/fixtures/claude-env-names-2.1.326.json` the class of every variable Claude Code 2.1.326 reads.
- Reading your own credentials or the environment needs a person: `env` and `printenv` (whole environment, or a credential-shaped name), `export -p`, `declare -x`, `set`, `ps e`, `/proc/*/environ`, `~/.aws/credentials` and the AWS caches, SSH private keys (not `*.pub`, `known_hosts` or `config`), `~/.netrc`, `~/.docker/config.json`, `~/.kube/config`, `~/.config/gcloud`, `~/.azure`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, the GitHub CLI token, GnuPG and the password store, and, anywhere including the project, `.env` files (not `.env.example`/`.sample`/`.template`), private keys and keystores (`*.key`, `*.p12`, `*.pfx`, `*.jks`, `id_*`), PEM files not named as certificates (`cert`, `chain`, `ca`, `public`, ... stay allowed) and credential JSON (`credentials.json`, `client_secret*.json`, `service-account*.json`). Listing names (`ls`, `stat`, Glob) reads no content and stays allowed, except a Glob inside a credential directory.
- Glob and Grep arguments shaped like options are denied: a path, glob, type or Glob pattern that starts with `-`, holds a control character, or names a ripgrep or fd flag that runs programs (`--pre`, `--pre-glob`, `-z`, `-X`, `--exec`). A Grep pattern that starts with `-` is fine (Claude Code passes it with `-e`). Read, Grep and shell commands that reach one ask (denied where nobody can be asked), and no pre-approval covers them. `env FOO=1 cmd` still runs `cmd` (it is not a dump), and `printenv PATH` or `cat README.md` are unaffected.
- When a project script or an MCP server runs `git checkout`, `git merge` or `git pull` and git changes the repository's configuration (`.claude/settings.json`, `.mcp.json`, `.vscode/settings.json`, CI workflows, ...), every tool call is held at once until Enclawed Code has checked the changed files with the same rules as at launch. Admissible changes go on without a restart; a change that would add an ungranted hook or command keeps the session held and the file is moved out of the project. A merge conflict in such a file waits for you: Enclawed Code asks for one approved write that resolves it (its own prompt, with a code), then checks the result. Sessions without the Enclawed Code launcher (managed hooks) are re-checked the same way; there, a conflict is resolved through Claude Code's own permission prompt: the one edit of the conflicted file is asked (every other call stays held), and once Claude Code has run it the file is checked again before the session goes on.
- Remote MCP servers (`http`, `sse`) are pinned with `ecwctl mcp pin NAME` and connected through Enclawed's own transport, with their calls checked before they leave; servers that need an OAuth sign-in are refused in this version.
- After an upgrade, `ecwctl doctor` lists every MCP record to pin again and every hook to grant again, with the command or entry for each.
- MCP servers are admitted by their code, not their launcher: `npx NAME@X.Y.Z` (exact version only) is pinned by the package's integrity, its lockfile and every installed file, and the session starts that verified tree with Node, never through npx; a container must be named by digest (`IMAGE@sha256:...`); a `node`/`python` script by every file of its package. `pnpm dlx`, `bunx`, `npm exec` and `yarn dlx` with an exact version are pinned the same way from what the runner installed (yarn keeps no installed copy, so run the package once with `npx -y`); `uvx`, `pipx run` and `uv tool run` with `NAME==X.Y.Z` by the wheel hashes the package index lists, every installed file against its record, and the runner's environment, started with that environment's Python; `uv run` in a project with a `uv.lock`, by the project and its environment; deno with a lock file, including the npm packages deno cached; `python -m` by the module's files checked against its distribution's record. Forms without an exact version (`npx NAME`, `uvx NAME`, `uv run --with ...`, deno without a lock) and `docker run IMAGE:TAG` resolve whatever the registry serves at launch and are refused, with how to pin (a silently published backdoor, such as postmark-mcp 1.0.16, never runs). Records pinned before this need `ecwctl mcp pin` again for those forms.
- A hook from your own settings, a plugin, one of your skills or subagents, or a `--settings` value needs an administrator's grant by digest (`"hooks"` in the opt-out file), like a repository's hook; the refusal prints the entry. Changing the hook, or a file it runs, needs a new grant.
- `LD_PRELOAD`, `LD_AUDIT` and `DYLD_INSERT_LIBRARIES` from your shell are removed from claude's environment (a library preloaded into claude could change what it runs and what it reports), with a warning and an audit record, unless an administrator lists them in `"loaderEnv"` in the opt-out file. `LD_LIBRARY_PATH` and the `DYLD_*_PATH` search paths stay yours (module systems, conda and CUDA set them) and are recorded.
- With `ENCLAWEDER_BROKER=off`, Enclawed Code holds nothing and each hook checks the device itself. Background sessions (`--bg`, `agents`) cannot hold the device and have no halt monitor, so Enclawed Code refuses them while a hardware root is in use.
- While the session runs, Enclawed Code anchors the audit log's head in the device (on firmware that supports it, such as a current Enclaweder Pro), so a rewritten or fabricated log is detected by `ecwctl audit verify` (`device anchor: MISMATCH`) even if every file on the machine was changed.
- Other Claude Code processes on the machine share the login, and could write it back after the erase; Enclawed Code lists them when it starts with a device and when it erases.

In an interactive `ecwcode` session, "ask" is Enclawed Code's own prompt in your terminal, in every permission mode. A call that Enclawed denies cannot run, whatever the permission mode.

### Permission mode

`ecwcode` starts Claude Code in `bypassPermissions` mode unless you choose a mode yourself (`--permission-mode ...` or `--dangerously-skip-permissions` on the command line; your choice is passed unchanged, and Shift+Tab in the session stays yours). Claude Code's own permission gates are not deterministic (Claude Code 2.1.331 starts in `auto`, where a model classifier decides), so in bypass mode they decide nothing and Enclawed Code's hooks decide every call: a reversible call runs, an irreversible one is asked at Enclawed Code's own prompt in your terminal (never Claude Code's dialog), and a denied one does not run. With nobody to ask (`-p`, a background session) an irreversible call is denied. Proven with the real Claude Code 2.1.331 binary in `test/bypass-real.test.mjs`: a PreToolUse deny is enforced (the file it would delete is intact), an ask goes to Enclawed Code's prompt and its answer is enforced both ways, SessionStart and PostToolUse still run, an administrator's managed hooks still run (even with `disableAllHooks` in your settings), and an allowed call shows no Claude Code dialog. Claude Code's one-time bypass-mode confirmation is pre-accepted in the session's own settings file (`skipDangerousModePermissionPrompt`), never in your `~/.claude`.

Two cases start Claude Code in its own default mode instead, so its own prompts appear in addition to Enclawed Code's: managed settings with `permissions.disableBypassPermissionsMode: "disable"` (said once at launch; an administrator changes it in the managed settings), and running as root (Claude Code refuses bypass mode for root outside a deliberate sandbox, `IS_SANDBOX=1`; run `ecwcode` as your own user). `ecwctl doctor` shows the effective mode.

Without Enclawed Code's prompt (the managed hooks alone, with plain `claude`), "ask" is Claude Code's own prompt, and in `bypassPermissions` Enclawed denies irreversible calls (Claude Code would not ask). `dontAsk`: Claude Code turns every prompt into a denial.

### Headless runs (`-p`)

In a `-p` run there is nobody to answer a prompt, so Enclawed denies every irreversible call itself (in the default bypass mode; in a mode you choose, Claude Code turns the ask into a denial: verified with Claude Code 2.1.326 and 2.1.331, the call does not run, and Claude reports that it was blocked). Reversible calls run normally.

Enclawed Code also checks that its hooks really run. At session start its hook proves itself to the launcher over a private socket (on Linux the kernel tells the launcher which process is connecting, and it must be Enclawed Code's hook started by this claude), and every tool call waits until that has happened. If a tool call shows up in Claude Code's transcript without a decision from Enclawed Code's hook (for example because Claude Code dropped the settings that carry it), Enclawed Code stops claude at once and exits 3; without the handshake within 30 s (fixed) it stops claude too. A run whose output is not a terminal (CI, `| tee`) counts as headless even without `-p`. `--no-session-persistence` is refused, since without a transcript this check is blind. A `-p` run needs an unlock ticket signed by your security key or passkey (`ecwctl auth unlock`: one launch within 10 minutes by default, this boot only). With an Enclaweder bound, every launch also needs a code from your authenticator app that the **device** checks: typed at an interactive launch, or once at `auth unlock` for headless runs, which then work without you until that device unlock expires or its launches are used up (see [Activation auth](commands.md#activation-auth)).

For unattended runs that must perform irreversible actions, pre-approve exactly those tools in your policy:

```json
{
  "enclawed": {
    "policy": {
      "preApprovedIrreversibleTools": ["bash", "mcp__github__create_pull_request"]
    }
  }
}
```

Tool ids are matched case-insensitively against the Claude Code tool name (`bash`, `write`, `mcp__server__tool`); the Enclawed gateway's ids (`exec`, `write`, `edit`, `web_fetch`) also work. Pre-approved calls are still recorded, and file writes still keep their history first.

## Policy

Set up Enclawed Code's own policy once, at install time or later:

```bash
ecwctl policy init                       # asks: tool allowlist, WebFetch hosts, pre-approvals, scratch dirs, halt behavior, auth method
ecwctl policy init --tool Read --tool Bash --host docs.python.org --yes   # no questions (install scripts)
ecwctl policy show                       # what is in effect, and where it comes from
ecwctl policy add-host pypi.org          # later changes: add-tool, remove-tool, add-host, remove-host, edit
```

It is written to `~/.enclawed/claude-code/enclawed.json` (mode 0600), so it never changes the Enclawed gateway's config. Your policy is the first of these that exists: `ENCLAWED_CONFIG_PATH` set in the shell you start `ecwcode` from; a file chosen with `ecwctl policy use <path>`; Enclawed Code's own file; the gateway's `~/.enclawed/enclawed.json`. When your organization has a managed policy (root-owned, [policy](commands.md#where-it-is-read-from)), that is the base and your policy can only tighten it: anything that would widen it is ignored, shown by `ecwctl policy show` and recorded. A managed policy that is not root-owned refuses the start. A repository cannot change any of this: a settings file's `env` never reaches the hook.

The format is the Enclawed gateway's `enclawed.policy` block, loaded by the same code. Without a file, the open flavor applies: allowlists are not enforced, and the reversibility rules above still apply. The flavor is the managed policy's; `ENCLAWED_FLAVOR=enclaved` in your shell can raise it to deny-by-default (never lower it; a value other than exactly `open` or `enclaved` counts as `enclaved`), and then your own file can only narrow the enclaved defaults. With an enclaved managed policy, the organization lists the tools to allow:

```json
{
  "enclawed": {
    "policy": {
      "enforceAllowlists": true,
      "allowedTools": ["read", "glob", "grep", "write", "edit", "bash", "agent"],
      "allowedHosts": ["docs.python.org"],
      "scratchPaths": ["/srv/agent-scratch"],
      "history": { "noHistoryPaths": ["/data/datasets/**"], "maxFileBytes": 16777216 }
    }
  },
  "enclawedCode": { "onHardwareHalt": { "eraseClaudeCredentials": true }, "auth": { "method": "auto" }, "inputCleaner": "on" }
}
```

An organization can install a policy that replaces the user's (see [enterprise.md](enterprise.md)).

## Proving who you are (activation auth)

Two-factor authentication is mandatory: before Enclawed Code starts a session and before its sensitive commands (`recover-root`, policy changes, `history restore`, `audit accept`), you touch your FIDO2 security key and enter its PIN, or confirm this computer's device-bound passkey (Windows Hello on a TPM, or Apple's or Android's secure hardware) with its PIN, fingerprint or face on a page that opens in your browser. Enroll a key with `ecwctl auth enroll` (and a backup key the same way), or the passkey with `ecwctl auth enroll --passkey`; keep a security key enrolled as a backup, since a passkey dies with its device. The passkey's attestation is verified at enrollment against the vendor's pinned root; a synced passkey (one that copies its key to a cloud account) and a passkey that does not verify you are refused, at enrollment and on every use. Touch ID or the macOS password unlocking a key on this computer, `sudo`, passphrases and authenticator-app codes are not accepted: their secret would live on this computer. It protects an unattended or stolen machine; it does not stop someone from running plain `claude` with valid credentials (see [enterprise.md](enterprise.md)).

## Enclawed Code's own commands

They are a separate program, `ecwctl`, so `ecwcode` takes no word or option from claude: `ecwcode doctor` is Claude Code's doctor and `ecwcode history of this module` is a prompt.

```
ecwctl history list [--path P] [--limit N] [--json]   versions kept before writes (with ids)
ecwctl history restore <id> [--to P]                  put a kept version back
ecwctl history prune                                  drop versions past retention
ecwctl audit verify [--json]                          check the audit log (chain, gaps, device anchor, measurements)
ecwctl audit accept                                   accept the log as found as the new device-anchor baseline (after an exit-6 refusal)
ecwctl audit reconcile [--json] [--no-transcripts]    find calls without a recorded decision
ecwctl audit path                                     where the audit log is
ecwctl managed print [--hook-command CMD]             organization-wide settings
ecwctl doctor                                         check this installation
ecwctl policy init|show|edit|...                      set up or change Enclawed Code's policy
ecwctl auth enroll|status|test|unlock|lock|remove     two-factor (enroll: this computer's passkey; --security-key: a FIDO2 key)
ecwctl recover-root                                   clear a DIRTY hardware latch with the genuine device
ecwctl recover-anchor [--operator-offline N]          free a BUSY anchor channel (operator takeover signed off this host, or the steps to recover)
ecwctl probe <Tool> '<input JSON>'                    ask the hook for one decision (runs nothing)
ecwctl version | --version
ecwctl help | --help                                  every command
```

Kept versions are listed from the audit log, not from the history store's own index, so a planted index entry is never offered or restored. A restore takes the entry's id, goes back to the file it was recorded for (with its original mode), is itself recorded, and keeps the content it replaces, so a restore can be undone.

Every option, output format, exit code and refusal of these commands is in [commands.md](commands.md).

## The audit log

Every decision, every tool result, and every session start and end is appended to a hash-chained log at `~/.enclawed/claude-code/audit.jsonl` (under `ENCLAWED_STATE_DIR` if set), where any edit is detected by `ecwctl audit verify`. Truncating or deleting the log is detected too: the next append writes a gap record, and verify fails. Someone who can write both the log and its head anchor can still fabricate a consistent history; with an Enclaweder that supports it, the device-signed anchor detects that as well. Commands, URLs and errors pass through Enclawed's DLP redaction and are truncated; file content is recorded only as its SHA-256 and size.

`ecwctl audit reconcile` compares the log with itself and with Claude Code's own session transcripts. It reports tool calls that ran without a recorded decision, calls that ran despite a denial, calls whose input another hook rewrote after Enclawed decided, launches whose hooks never reported in, and tool calls in a transcript (subagent transcripts included) that Enclawed never saw, which is what a session with its hooks switched off looks like.

## How the hooks are attached

Enclawed Code writes a private session directory outside the project (0700; files 0600; removed when claude exits) with two files: `session.json`, everything the hook needs, resolved from your shell's environment, and `settings.json`, passed to claude as `--settings`. Hooks from `--settings` run in addition to your own; nothing of yours is replaced.

- The hook command starts node with an empty environment (`env -i`) and names the session file and its SHA-256. Claude Code exports every settings file's `env` to hooks, so this is what keeps a repository's `.claude/settings.json` from moving your policy or audit log, or preloading code into the hook with `NODE_OPTIONS`. When a user, project or local settings file sets such variables (`ENCLAWED_*`, `NODE_OPTIONS`, `PATH`, `LD_PRELOAD`, `GIT_*`, ...), Enclawed Code warns and pins them to your shell's values in its settings.
- If you pass your own `--settings` (a file or a JSON string, once or more), Enclawed Code checks it and merges it into the generated file, because claude reads only one `--settings` value. Claude Code drops a whole settings file when one value is invalid, hooks included, so a value of the wrong type, or a key Enclawed Code cannot check (also nested ones, such as `statusLine.type` or an unknown `sandbox` key, and hook handlers other than `command`), is refused before launch; put such keys in `.claude/settings.local.json` instead.
- The generated file sets `disableAllHooks: false`, which outranks a `true` in your user or project settings (verified with Claude Code 2.1.326). A `disableAllHooks: true` inside your own `--settings` is ignored, with a warning.
- `--bare` and `--safe-mode` turn off settings hooks, so Enclawed Code refuses them. Run plain `claude` if you mean to work without Enclawed.
- A repository whose `.claude/settings.json`, skills or subagents add their own PreToolUse hook could rewrite a call after Enclawed approved it, so Enclawed Code does not start there until you review it and an administrator grants that hook for that repository (`projectHooks` in the [opt-out file](commands.md#admin-only-opt-outs); the refusal prints the entry, and a changed hook or a changed script it runs needs a new one). Hooks in `.claude/settings.local.json` count as the repository's. A rewrite is reported to you when it happens and by `audit reconcile`. Repository hooks for other events (SessionStart, UserPromptSubmit, Stop, ...) are refused the same way, and once granted get a warning; hooks from your own settings and plugins get a warning.
- Enclawed Code does not start in a directory that contains its own installation or the Enclawed state directory (for example your home directory); there is no override, and the agent can never write those files either way.
- The PreToolUse hook has a 10 s timeout and `"onFailure": "block"`: if it crashes, times out or exits oddly, the call is blocked. Enclawed Code requires Claude Code 2.1.295 or later for that reason.
- claude commands that start no session here (`mcp`, `plugin`, `auth`, `doctor`, `update`, `attach`, ...) and `--version`/`--help` pass through without hooks. `agents` gets Enclawed Code's settings, since the agent view dispatches sessions.
- When your organization's managed settings really run `ecwcode-hook` on every event (checked structurally, not by a text search), Enclawed Code does not add its own copy.

## Limits

- Hooks run on the same machine as Claude Code, under your account. Someone with control of that account (or root) can stop them; `ecwctl audit reconcile` then shows the session's tool calls without decisions. For a setup users cannot switch off, see [enterprise.md](enterprise.md).
- A read-only command can still read anything your account can, except Enclawed Code's own secrets and Claude Code's login file, which every read tool and shell command is refused. Keep your other secrets out of reach with Claude Code's `permissions.deny` rules and its Bash sandbox.
- A hard link in the project to one of Enclawed Code's files is refused like the file itself, and a write to any file with several hard links asks first. When Enclawed Code's own files are too many to rule out that a hard-linked target is one of them (its code tree usually shares a filesystem with your projects), the write asks you, says so, is never pre-approved, and is refused where no person may be asked. The check runs before the write: a process you approved earlier could still swap the file in between.
- git reads ask in a repository whose own config can start a program (pager, fsmonitor, drivers, includes); your user-level git config is trusted as yours.
- Background sessions (`--bg`) keep their settings file until you remove it, because the session outlives Enclawed Code. Whether `claude respawn` keeps the `--settings` of the original launch is not documented; use managed settings for background sessions you need covered.
- On Windows the hook command line is quoted for `cmd` and cannot be started with an empty environment (there is no `env -i`), so a settings file's `NODE_OPTIONS` can still reach the hook there; this has not been tested yet.
- Erasing a login on a hardware halt is best effort. An overwrite is not guaranteed to reach the old blocks on SSDs and journaling filesystems. A copy of the token taken earlier keeps working, and a process that waits out the one-minute watcher can write the login back. API keys in the environment are not touched. Revoking the session at claude.ai is the real control: do that after a halt.
- On a hardware halt, every process the session started is killed before the login is erased, and the launcher then verifies that none is left (red-team N7b). On Linux claude is its own child subreaper (started through a one-line python3 or perl wrapper), so a double-forked or `setsid` helper, with or without its environment, stays in claude's process tree and is frozen and killed with it; the systemd user scope (when `systemd-run --user --scope` works), the session marker in the environment or cgroup, and the launcher's own late children are swept too. If anything survives, the halt message lists it. It does not reach work handed to something that runs outside the session: `at` or `batch` jobs, cron entries, systemd user timers or a new `systemd-run --user` unit, an already running tmux or screen server, a container daemon, or another host over ssh; all of these need a command a person approved first. Without python3 or perl and without a scope on Linux, a helper that clears its environment is not found, and the launcher refuses such a hardware-root session unless an administrator granted `reducedContainment`.
- On macOS (no subreaper, no cgroups) the launcher tracks the session instead: while claude runs it reads the process table every 100 ms and keeps every process it saw below claude (by pid and start time, so a process re-parented to launchd by a double fork stays tracked and a recycled pid is never taken), plus every process group a tracked process leads (a `setsid` helper's later children are in it even if they were never seen); the session marker is read with `ps -E`. On a halt claude is frozen, and every tracked process, every process of a session-led group and every marker carrier is frozen and killed, swept again until none is left, and verified (`contained.mode: "tracked+marker"` in the halt record). The terminal's own job group (which can hold your `| tee`) and processes started outside the session are never touched. What tracking cannot see: a process that, within one 100 ms read, both leaves claude's tree (its parent exits before the next read) and leaves every session-led group (its own `setsid`) and clears its environment. What must be verified on a real Mac (the logic and the kill path are tested on Linux with the same `ps` columns): `ps -axo pid=,ppid=,pgid=,stat=,lstart=` with `LC_ALL=C TZ=UTC` parses on macOS 13-15; `ps -E -ww -axo pid=,command=` prints the initial environment of the user's own processes (and so the marker) for processes started by claude, including after they clear their environment (they must then NOT show it); orphans are re-parented to launchd (pid 1) and keep their pgid; `kill(-pgid)` reaches a group whose leader exited; the 100 ms poll's CPU cost under a busy session; an interactive Claude Code still restores the terminal after the halt; and the N7b helper of `test/hardware.test.mjs` (with `sleep 0.5` before its parent exits) is killed and the login stays erased in the Keychain.
- The device head anchor needs an Enclaweder with record v2 firmware (authenticated anchor sessions); with older firmware the log is anchored on the host only.
