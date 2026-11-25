# Organization-wide deployment

`ecwcode` adds Enclawed's hooks to sessions it launches. To apply the same checks to every Claude Code session on a machine, including plain `claude`, install them as Claude Code managed settings. Managed settings rank above every user and project setting, and the template also locks the settings a user could otherwise use to switch the checks off.

## 1. Install Node and Enclawed Code where only administrators can write

The managed hook runs `node` and `ecwcode-hook` by absolute path. If either, or anything they load (Enclawed Code's `src/`, the framework build and its dependencies), or any directory above them is writable by a user, that user can replace it, so install everything in system locations (for example a system Node and Enclawed Code under `/opt` or `/usr/local/lib`). `ecwctl managed print` lists every user-writable path the hook would run from.

## 2. Generate the settings

```bash
ecwctl managed print > enclawed-code.json
```

This fills the template in `managed/enclawed-code.json` with this installation's absolute paths. The hook command is `/usr/bin/env -i CLAUDE_PROJECT_DIR="$CLAUDE_PROJECT_DIR" '<node>' '<ecwcode-hook.mjs>' --origin managed`: Claude Code exports every settings file's `env`, a repository's included, to hooks, and `allowManagedHooksOnly` does not restrict `env`, so the hook starts with an empty environment and reads no configuration from it. In managed mode its home directory is the OS account's, and the flavor and hardware mode are options on its command line: `ecwctl managed print --flavor enclaved --hardware-root required`. To use other paths, pass the full command line with `--hook-command`, keeping the `env -i` prefix.

What the template sets:

| Key | Why |
|---|---|
| `hooks.PreToolUse` (`matcher: "*"`, `timeout: 10`, `onFailure: "block"`) | Every tool call is checked; a hook that crashes or times out blocks the call. |
| `hooks.PostToolUse`, `PostToolUseFailure` | What each tool actually did, for reconciliation. |
| `hooks.SessionStart`, `SessionEnd`, `SubagentStop`, `ConfigChange` | Session boundaries, subagent transcripts and settings changes, so missing records are detectable. |
| `allowManagedHooksOnly: true` | Only hooks your organization deploys run. |
| `disableAllHooks: false` | Managed settings outrank any `true` set elsewhere. |
| `permissions.disableBypassPermissionsMode: "disable"` | Nobody can enter `bypassPermissions`. |
| `permissions.disableAutoMode: "disable"` | Removes auto mode, so every irreversible call goes to a person. |
| `sandbox` (`enabled`, `failIfUnavailable`, `allowUnsandboxedCommands: false`) | Claude Code's OS sandbox for `Bash`: hooks see each command, the sandbox confines what its child processes can do. On native Windows there is no sandbox, and `failIfUnavailable` makes commands fail; remove the `sandbox` block there, or keep it to refuse unsandboxed commands. |

Review and adjust before deploying, for example to add `permissions.deny` rules, `allowManagedPermissionRulesOnly`, `allowManagedMcpServersOnly` and a `managed-mcp.json` (see Claude Code's managed-settings and managed-MCP documentation).

## 3. Copy it into Claude Code's managed-settings directory

Enclawed Code never writes to system directories itself. An administrator copies the file:

| OS | Command |
|---|---|
| Linux, WSL | `sudo install -D -m 0644 enclawed-code.json /etc/claude-code/managed-settings.d/50-enclawed-code.json` |
| macOS | `sudo install -d "/Library/Application Support/ClaudeCode/managed-settings.d" && sudo install -m 0644 enclawed-code.json "/Library/Application Support/ClaudeCode/managed-settings.d/50-enclawed-code.json"` |
| Windows (admin PowerShell) | `New-Item -ItemType Directory -Force "C:\Program Files\ClaudeCode\managed-settings.d"; Copy-Item enclawed-code.json "C:\Program Files\ClaudeCode\managed-settings.d\50-enclawed-code.json"` |

Drop-in files merge after `managed-settings.json` in alphabetical order. Claude Code refuses to start if a managed file is not valid JSON, so validate before copying (`node -e 'JSON.parse(require("fs").readFileSync(process.argv[1]))' enclawed-code.json`). MDM (macOS profile domain `com.anthropic.claudecode`, Windows `HKLM\SOFTWARE\Policies\ClaudeCode` value `Settings`) can deliver the same JSON.

On WSL, `/etc/claude-code` is writable by users; deliver the settings through the Windows chain instead (`wslInheritsWindowsSettings`).

Check the result with `/status` inside Claude Code and `claude doctor`. `ecwctl doctor` reports `managed hooks: installed` only when the merged managed settings run `ecwcode-hook --origin managed` on every event with the template's exact structure and set `allowManagedHooksOnly`; then `ecwcode` stops adding its own copy of the hooks so calls are not checked twice. A file that only mentions `ecwcode-hook` (a deny rule, a hook for one tool) does not count.

## 4. Optional: an organization-wide Enclawed policy

When this file exists, it is the base every user policy (`ENCLAWED_CONFIG_PATH`, `policy use`, `~/.enclawed/claude-code/enclawed.json`, `~/.enclawed/enclawed.json`) is layered over **tighten-only**: a user value that would widen it (an allowlist entry it lacks, `enforceAllowlists: false`, a smaller `history.maxAgeDays`, a weaker input cleaner, the credential erase off, ...) is ignored and recorded, so users cannot loosen it but can narrow it. It is also the only place the flavor is set (`"enclawedCode": { "flavor": "enclaved" }`; a user's shell can raise it, never lower it). It has the same shape as the Enclawed config (`{ "enclawed": { "policy": { ... } } }`, see [usage.md](usage.md)). It must be owned by root, mode no wider than 0644, not a symlink, in root-owned directories no group or other user can write (`sudo install -d -m 0755 /etc/enclawed/claude-code && sudo install -m 0644 policy.json /etc/enclawed/claude-code/`); if it fails that check, or cannot be read or parsed, Enclawed Code refuses to start and, in managed mode, every call is denied.

| OS | Path |
|---|---|
| Linux | `/etc/enclawed/claude-code/policy.json` |
| macOS | `/Library/Application Support/Enclawed/claude-code/policy.json` |
| Windows | `C:\ProgramData\Enclawed\claude-code\policy.json` |

## Logins, API keys and login restrictions

For Claude subscription logins, Enclawed Code follows Anthropic's terms: the login stays with Claude Code, signed in through Anthropic's own flow, and Enclawed Code never stores or relays it. Such a login is kept where Claude Code keeps it, readable by programs running as you. With an API key, Enclawed Code can seal the credential under the Enclaweder, so even a compromised computer cannot use it without the device. Organizations that need that protection use an API key.

- **Claude subscription logins** (Free, Pro, Max, Ultra, Team, Enterprise) are signed in with Claude Code's own `/login`. Without an Enclaweder, `ecwcode` uses the login plain `claude` uses. With an Enclaweder, each session's Claude Code keeps its login in `~/.enclawed/claude-code/claude-login` (on macOS, the login Keychain item Claude Code keys to that directory); Enclawed Code never reads it, and erases it on a hardware halt.
- **API keys** are sealed under the Enclaweder with `ecwctl login api-key` (Linux); sessions reach Claude through Enclawed Code's relay, which adds the key, and claude holds only a placeholder. Only a string in Anthropic's API key format is accepted; anything else is treated as a subscription login and refused.
- **Amazon Bedrock, Google Cloud's Agent Platform, Microsoft Foundry** credentials are configured as Claude Code documents and passed through unchanged.

### Restricting how people sign in

Enclawed Code never removes, disables or restricts a way of signing in to Claude Code. To restrict login methods on managed machines, use Claude Code's own managed settings, documented in [Authentication: restrict login to your organization](https://code.claude.com/docs/en/authentication#restrict-login-to-your-organization) and the [settings reference](https://code.claude.com/docs/en/settings-reference):

| Managed setting (Claude Code's) | What it does, per Claude Code's documentation |
|---|---|
| `forceLoginMethod` | Restricts login to claude.ai (`"claudeai"`), Claude Console (`"console"`) or a cloud gateway (`"gateway"`). |
| `forceLoginOrgUUID` | Pins claude.ai logins to your organization (a list of organization ids); only managed settings enforce it. |
| `allowedProviders` | Limits which API providers a machine may use (for example `["anthropic", "bedrock"]`; Claude Code 2.1.285 or later). It refuses a session over `ANTHROPIC_UNIX_SOCKET`, so with an API key sealed under the Enclaweder (which reaches Claude through that socket) leave it unset. |

For example, to require that developers sign in with your claude.ai organization (Claude Code's own example):

```json
{
  "forceLoginMethod": "claudeai",
  "forceLoginOrgUUID": ["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"]
}
```

Claude Code's documentation says to deploy these keys through device management, since server-managed settings reach a developer only after they authenticate into your organization. To keep every machine on a reviewed Claude Code version as well, its managed `requiredMinimumVersion` and `requiredMaximumVersion` make Claude Code refuse to start outside a range, and `DISABLE_UPDATES` in the managed `env` stops its own updates ([setup: disable auto-updates](https://code.claude.com/docs/en/setup#disable-auto-updates)).

### Upgrading from an earlier build: leftover login files

On a machine where an earlier build's `sudo ecwctl managed login-policy install` was run, an administrator removes its drop-in and directory (`ecwctl doctor` names any that are left):

| OS | Remove |
|---|---|
| Linux, WSL | `sudo rm /etc/claude-code/managed-settings.d/90-enclawed-code-login.json && sudo rmdir /etc/claude-code/enclawed-code-no-login` (and the `90-codenclawed-login.json` and `codenclawed-no-login` of the builds before the rename, if present) |

A leftover `ecwctl login watch` process is named by `ecwctl doctor` with the `kill` command to stop it, and its systemd user unit (`enclawed-code-login-watch.service`) is removed with `systemctl --user disable --now enclawed-code-login-watch.service` and deleting the unit file. Leftover files at `~/.enclawed/claude-code/credentials/claude-login.sealed.json` and `credentials/pending/` are erased without being opened at the next launch with an Enclaweder or by `ecwctl login status`.

## The Enclaweder under managed settings

Plain `claude` has no launcher to hold the hardware root for the session, so the managed hook checks it on every call: it boots the root, checks it and closes its session again. When another process already owns the device (an `ecwcode` session, the Enclawed gateway), that per-call check becomes a client of the owner and only reads its health. The launcher-only features (the authenticated relay with per-call device attestation, the device head anchor, the credential erase on a halt, the handshake) need `ecwcode`; the managed hook also refuses every call when the Claude Code that runs it is not a [reviewed version](../README.md#reviewed-claude-code-versions); under plain `claude` with managed hooks they do not run.

## Approvals at Claude Code's prompt

Under managed settings there is no Enclawed Code prompt, so a call Enclawed wants a person to approve is asked at Claude Code's own permission prompt. Claude Code 2.1.326 re-checks a pending call by itself whenever its permission context changes while the prompt is open (for example shift+tab into `acceptEdits`), and runs it with no answer when its own permission check now allows it. So Enclawed asks there only what Claude Code's check cannot allow by itself, or an overwrite it can put back:

- A call Claude Code's check can allow by itself (file edits in `acceptEdits`, the file commands `acceptEdits` allows such as `rm` and `mv`, its read-only commands, reads in the working folders, its preapproved documentation hosts, a tool a managed allow rule names) that cannot be put back is refused up front. Approve it under `ecwcode`, whose own prompt is answered only by the person, or do it yourself.
- An overwrite of a file git does not track (its prior content is kept as a snapshot) is asked in `default` mode only (shift+tab reaches `plan` through `acceptEdits`). If Claude Code then runs it in another mode, or with another input, no person's answer is on record: the written file is quarantined under `~/.enclawed/claude-code/host-prompt/`, the file is put back from the snapshot, `approval-not-from-person` is recorded, and every further tool call of that Claude Code session is refused.
- Every other ask (for example `git push`, a package install, an MCP tool) is asked at Claude Code's prompt as usual; its re-check cannot allow those.
- The template sets `allowManagedHooksOnly` (no `PermissionRequest` hook outside the managed settings can answer the prompt) and pins `sandbox.autoAllowBashIfSandboxed` to `false`. If the managed settings miss either, add a `PermissionRequest` hook, or enable plugins (whose hooks still run under the lock), every ask is refused.

## Audit and reconciliation

Each user's decisions are recorded in `~/.enclawed/claude-code/audit.jsonl`, a hash-chained log where any edit is detected. Collect it with your log pipeline and run `ecwctl audit verify` and `ecwctl audit reconcile` against it. Reconciliation flags tool calls that ran without a decision and transcript entries Enclawed never saw.

## Limits

- Hooks run on the user's machine. A local administrator can change managed settings or stop the hook; the `ConfigChange` hook records changes to settings files, and reconciliation shows sessions without decisions, but neither can prevent an administrator's change.
- `allowManagedHooksOnly` and `disableAllHooks` interact in ways Claude Code's docs do not fully spell out (which non-managed hooks still run; whether a non-managed `disableAllHooks: true` affects managed hooks). The template sets both defensively; confirm with `claude doctor` on your Claude Code version.
- Hooks see each tool call, not what a `Bash` child process does afterwards. Use the sandbox block for that.
- On native Windows there is no `env -i`: the managed hook is started with Claude Code's environment, so a settings file's `NODE_OPTIONS` could reach it. Lock `env` with managed settings there, and keep repositories untrusted.
- Activation auth gates `ecwcode`, not a plain `claude` run with valid credentials; managed settings are what cover plain `claude` (its hooks, and with Claude Code's own `forceLoginMethod` and `forceLoginOrgUUID`, its sign-in).

## Compromised-host threat model

What Enclawed Code assumes, and what it can and cannot do when something malicious already runs on the machine as the same user (malware, a prompt-injected agent that escaped its gate earlier, a hostile repository's code you ran yourself).

**What such an attacker can do, regardless of Enclawed Code.** Run any program as you, read and write every file you can (Enclawed Code's state directory, policy, audit log and its head anchor, the history store, a Claude subscription login wherever Claude Code keeps it), replace Enclawed Code or Node before you start them, start plain `claude`, and open the Enclaweder's HID device if your account can (on Linux, membership in the device's group). Enclawed Code does not prevent any of this. Nothing that runs as you can.

**What Enclawed Code adds against it, with an Enclaweder attached:**

| Protection | What it gives | Limit |
|---|---|---|
| Device attestation on every tool call | The hook sends a fresh random nonce through the launcher to the device and checks the device's signature itself, with the manufacturer certificate (pinned roots), the uid/key binding and the key bound at launch. A fake socket or broker claiming CLEAN, a replayed answer, or a cloned or uncertified device is refused. | The device must be attached and held by the `ecwcode` launcher; managed-mode hooks under plain `claude` check health per call without this relay. |
| Device head anchor | The launcher anchors the audit log's head in the device (signed, with a monotonic counter the host has no command to set) every 2 s, whenever the hook asks, and at the end of the session, and prints the counter. With record v2 firmware the device advances the anchor only under its one authenticated anchor session, which the launcher holds (the key only in its memory); a bare `ANCHOR_SET` is refused, and a second opener gets BUSY, which the launcher treats as an alarm (it stops claude). `ecwctl audit verify` reports `matched`, or fails with `MISMATCH` (including `foreign-session`, `downgrade`, `foreign-open`) or `superseded`. Truncating, rewriting or fabricating the log on the host, even with its head anchor file and a re-anchor under another session, fails verification (red-team round 3, N10, N10b; docs/anchor-auth-design.md). | One device holds one anchor session at a time: a second log anchored on the same device is foreign to the first, whose `verify` then fails (use `--no-device` and compare counters out of band when that is expected). A launcher that crashed without closing its session leaves the device BUSY until it is unplugged and plugged back in. A process that opens the channel before Enclawed Code starts makes every launch stop with an alarm (loud, a denial of service, not a silent forgery). Firmware before record v2 reports `unavailable` for the anchor (an earlier Base unit answers `ST_UNSUPPORTED`). Verified on the reflashed Enclaweder Pro: `matched` after a session; `ERR_AUTH` for a bare set; BUSY for a second open; `foreign-session` for a forged or truncated log anchored by another session. |
| Measured launch | Each session-start record carries SHA-256 measurements of the hook, Enclawed Code's code, the framework, the effective policy and the settings; `audit verify` re-measures and lists what changed. Covered by the device anchor. | Detects a replaced hook or policy after the fact; does not stop it from running. A replaced Enclawed Code could also lie about its own measurements, which the anchor then preserves as evidence of that session. |
| Credential erase on a halt | Unplugging the device mid-session stops claude, then erases the session's Claude Code login storage (written over and removed, never read) and the API key sealed under the device; coming back needs the genuine device, activation auth and a fresh `/login` (or the API key sealed again). | Does not revoke a credential at Anthropic; a copy taken earlier keeps working until revoked (sign out of the session at claude.ai, or revoke the API key in the Claude Console). Between sessions a subscription login is a file readable by programs running as you; an API key is sealed under the device. Not guaranteed to reach old blocks on SSDs or journaling filesystems. |
| API key sealed under the device | With `ecwctl login api-key`, the key is opened only in the launcher's memory at the start of a session and reaches Claude through the relay; claude holds a placeholder, and no file holds the key in plaintext. | Only an Anthropic API key; a Claude subscription login is never sealed or relayed. |
| Two-factor auth (mandatory) | Starting Enclawed Code and its sensitive commands need a FIDO2 security key (touch + PIN) or a device-bound passkey (Windows Hello on a TPM, Apple's or Android's secure hardware; never a synced passkey) with user verification on every use, strict counters (a proven non-exportable TPM key excepted), attestation verified at enrollment; headless launches need an unlock ticket the key or passkey itself signs. | Gates Enclawed Code, not plain `claude`. In a software-only install a same-user process able to rewrite the protected state dir could replace the enrolled public key (audited). |

**Without an Enclaweder,** the audit log is self-consistent but not tamper-evident against someone who can write `~/.enclawed`: they can fabricate a complete history that verifies (red-team I7). Enclawed Code detects truncation and deletion by its own appends (gap records), and prevents the agent itself from writing these files, but not another process running as you.

In one line: against a compromised host, the device makes host-level tampering **detectable** and keeps evidence the attacker cannot forge; it does not **prevent** what a process running as you can already do.
