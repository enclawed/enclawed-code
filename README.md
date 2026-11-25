# Enclawed Code

Use Claude Code exactly as you do today, with every action it takes checked by [Enclawed](https://enclawed.com) before it runs.

> **Release 0.666.1.** Install with `npm install -g enclawed-code` (Node.js 22 or later, and a [reviewed Claude Code version](#reviewed-claude-code-versions), 2.1.326 or 2.1.331, on your PATH); see [Install](#install).

## What Enclawed Code does for you

Type `ecwcode` wherever you type `claude`: it launches your own Claude Code installation with every argument passed through, so the interface, slash commands, models, subagents, MCP servers and resumed sessions stay the same ([what differs](#how-ecwcode-differs-from-plain-claude)). Enclawed Code's own commands are a separate program, `ecwctl`. Enclawed's open core ([enclawed-oss](https://github.com/enclawed/enclawed-oss)) checks each tool call against a fixed policy outside the model:

- **Every action is checked before it runs**, in the main session and in every subagent, however the model was prompted. See it: reasons starting with `Enclawed:` in Claude Code's prompts.
- **File changes are reversible by default:** before a file is changed, its previous content is kept locally. See it: `ecwctl history list`; undo with `ecwctl history restore <id>`.
- **You approve only what cannot be undone:** shell commands off a strict read-only allowlist, MCP tools and unknown tools wait for you at Enclawed Code's own prompt (a code you type, so nothing inside the session can approve for you), unless your policy pre-approves them.
- **Files that start programs later are protected:** writes to `.git/`, `.claude/`, `.mcp.json`, `.envrc`, `package.json`, `Makefile`, editor task files and similar always ask, whatever their letter case and even through a symlink; Enclawed Code's own policy, audit log, history and code are never the agent's to write.
- **Egress and tool allowlists:** `WebFetch` runs without asking only for hosts you list, and an enforced allowlist denies every unlisted tool. See it: `ecwctl policy show`.
- **Hardware root:** with an Enclaweder bound, every tool call is checked against the device's own signature, an unhealthy device halts every call, and unplugging it mid-session stops claude and erases the session's own Claude Code login storage and any API key sealed under the device until the genuine device and you are back (your own Claude Code login is never touched). See it: `ecwctl doctor | grep 'hardware root'`.
- **You, verified (two-factor, mandatory, one factor at a time):** this computer's device-bound passkey (Windows Hello on a TPM, Apple or Android; never a synced one) or a FIDO2 security key; with an Enclaweder attached, only the authenticator code the device checks; before Enclawed Code starts and before its sensitive commands. See it: `ecwctl auth status`.
- **A tamper-evident record:** every decision goes to a hash-chained log where an edit, a truncation or a deletion is detected (and, with an Enclaweder that supports it, a wholesale forgery too), and reconciliation against Claude Code's own transcripts shows calls Enclawed never saw. Check it: `ecwctl audit verify` and `ecwctl audit reconcile`.
- **Organization-wide:** a managed-settings template applies the same checks to every Claude Code session on a machine. See it: `ecwctl managed print`.

After installing, run **`ecwctl demo`** first: it replays attack scenarios offline, at no cost, and shows what Enclawed Code did with each one (see [docs/adversarial.md](docs/adversarial.md)). To check each feature yourself with copy-paste commands, see [What Enclawed Code does for you](docs/commands.md#what-enclawed-code-does-for-you).

## Install

You need [Claude Code](https://docs.anthropic.com/en/docs/claude-code) at a [reviewed version](#reviewed-claude-code-versions) (2.1.326 or 2.1.331) and Node.js 22 or later.

From npm (the framework is the `enclawed` package at the exact version Enclawed Code pins):

```bash
npm install -g enclawed-code
ecwctl policy init   # your policy: asks a few questions (or pass --tool/--host/... --yes)
ecwctl auth enroll   # required: this computer's passkey (Windows Hello, Apple, Android); a security key instead: --security-key
ecwctl doctor        # checks claude, the framework, your policy, auth and the hardware root
```

From source, you also need [pnpm](https://pnpm.io) and git. Enclawed Code builds against [enclawed-oss](https://github.com/enclawed/enclawed-oss) from GitHub, included as a git submodule:

```bash
git clone --recurse-submodules https://github.com/enclawed/enclawed-code.git
cd enclawed-code
(cd vendor/enclawed-oss && pnpm install)
npm run build:framework
npm link                       # puts ecwcode, ecwctl and ecwcode-hook on your PATH
ecwctl policy init  # your policy: asks a few questions (or pass --tool/--host/... --yes)
ecwctl auth enroll  # required: this computer's passkey (Windows Hello, Apple, Android); a security key instead: --security-key
ecwctl doctor       # checks claude, the framework, your policy, auth and the hardware root
ecwctl demo         # see what Enclawed Code does, offline and at no cost
```

To update:

```bash
git pull --recurse-submodules
git submodule update --remote vendor/enclawed-oss
(cd vendor/enclawed-oss && pnpm install)
npm run build:framework
```

If `ecwctl doctor` reports missing framework exports, the enclawed-oss submodule is older than ecwcode: run the update steps above.

Upgrading from the earlier `codenclawed` builds (or the older `enclawde` ones): the commands are now `ecwcode` (Claude Code itself; it reserves no word, so `codenclawed history list` is now `ecwctl history list` and `codenclawed codenclawed doctor` is `ecwctl doctor`), `ecwctl`, `ecwcode-hook` and `ecwcode-mcp-proxy`; there is no `codenclawed` or `enclawde` alias. Environment variables are `ECWCODE_*`: a `CODENCLAWED_*` or `ENCLAWDE_*` variable in your shell is ignored, with a warning. Your existing state keeps working without a migration step: `~/.enclawed/claude-code` (policy, audit log and its anchors, history, MCP pins, auth state) is unchanged; an audit log written by an earlier build verifies with `ecwctl audit verify` (record types are unchanged; records written by `codenclawed` name it as their actor, new ones `enclawed-code`); an enrolled security key stays enrolled (the FIDO2 relying-party id is still `enclawde.local`); a policy file's `codenclawed` (or `enclawde`) options block is read as the `enclawedCode` block; an administrator's grant file is still read under its earlier names `codenclawed-opt-outs.json` and `enclawde-opt-outs.json` (a version 1 file grants nothing, see [admin-only opt-outs](docs/commands.md#admin-only-opt-outs)); MCP admission records signed by an earlier build still verify. `ecwctl doctor` names any login files an earlier build left behind, and [docs/enterprise.md](docs/enterprise.md#upgrading-from-an-earlier-build-leftover-login-files) says how to remove them. If your organization installed the managed hooks, replace `50-codenclawed.json` with the output of `ecwctl managed print` (the old file runs `codenclawed-hook`, which no longer exists, so Claude Code blocks every tool call until it is replaced; `ecwctl doctor` names such a file). Then `npm uninstall -g codenclawed` and install `enclawed-code`, or re-run `npm link` from source.

For organization-wide enforcement through Claude Code's managed settings, see [docs/enterprise.md](docs/enterprise.md).

## Usage

Wherever you would type `claude`, type `ecwcode`. Every argument goes to claude unchanged; `ecwcode` reserves no word of its own:

```bash
ecwcode                                 # interactive, same as claude
ecwcode -p "fix the failing test"       # headless, same flags as claude
ecwcode --continue                      # resume, choose a model, run agents, Claude Code's own subcommands:
ecwcode --resume <id> --model opus      #   all exactly as with claude (resume with ecwcode, not claude: Claude Code's
                                        #   own exit line says `claude --resume <id>`; ecwcode adds its own line after it)
ecwcode mcp list
ecwcode doctor                          # Claude Code's doctor
```

Enclawed Code's own commands are `ecwctl` (`ecwctl --help` lists them all):

```bash
ecwctl history list                # file versions kept before each write
ecwctl history restore <id>        # put one back
ecwctl audit verify                # check the hash-chained log
ecwctl audit reconcile             # find tool calls with no recorded decision
ecwctl managed print               # organization-wide settings for Claude Code
ecwctl doctor                      # check this installation
ecwctl policy show                 # the policy in effect and where it comes from
```

### How `ecwcode` differs from plain `claude`

`ecwcode` starts your own claude with your arguments, your terminal and your environment, so the screen, slash commands, models, subagents, MCP servers you admitted and resumed sessions are Claude Code's own; `test/interactive-parity.test.mjs` drives it in a real terminal to prove it (every argument, every key byte including arrows, Escape and bracketed paste, the terminal size and resizes, Ctrl-C, the exit code). What is different, all of it on purpose:

- **One second factor before a session starts:** this computer's passkey (or a security key), or, with an Enclaweder attached, only the authenticator code the device checks (never both). Claude Code's own commands that start no session (`ecwcode mcp list`, `ecwcode doctor`, `ecwcode update`, `ecwcode --version`, `ecwcode --help` ...) go straight to claude without it.
- **Three arguments are refused:** `--bare` and `--safe-mode` (they turn hooks off) and `--no-session-persistence` (no transcript to reconcile). `--settings` is merged into Enclawed Code's settings and `--mcp-config` servers are admitted first; `--workflow` and `--passphrase-fd` are Enclawed Code's own. Everything else is passed unchanged.
- **Every tool call is checked.** Reversible calls run; a call Enclawed decides to ask about is asked at Enclawed Code's own prompt instead of Claude Code's permission dialog: claude is paused, the prompt appears on a screen of its own, you type the word and code it shows, and Claude Code's screen comes back as it was. In `-p` runs (and whenever standard output is not a terminal) nobody is asked, so those calls are refused. Denied and asked calls carry reasons starting with `Enclawed:`.
- **What runs code is admitted before the session starts:** a repository's hooks and command settings need an administrator's grant by digest; a hook from your own settings, a plugin, your skills or subagents or `--settings` without a grant is asked about at the start (`[y/N]` on the terminal: start this session without it, its plugin switched off whole; nothing is stored), and refused when nobody can be asked (`-p`, no terminal); MCP servers start only when pinned (`ecwctl mcp pin`); claude.ai connectors are off unless your policy lists them; a skill that is not verified refuses the launch (or is switched off, by policy). A launch can also be refused for other reasons, each with an exit code and the fix ([exit codes](docs/commands.md#exit-codes)).
- **Repository settings are read once, at launch** (`--setting-sources=user` plus the admitted copy); a change to them mid-session is checked before it takes effect.
- **A few lines on stderr** at the start of a session (warnings, a note about files changed outside the agent).
- **The environment claude gets** differs only by the variables listed in [set by Enclawed Code](docs/commands.md#set-by-enclawed-code-for-claude-and-its-hooks) (`ECWCODE_SESSION`, a session marker, the flavor, one empty directory at the end of `PATH`; loader-injection variables are removed).
- **With an Enclaweder:** each session's Claude Code keeps its login in a directory Enclawed Code sets aside for its sessions (sign in once with Claude Code's own `/login` inside a session; Enclawed Code never reads it), or reaches Claude with an API key sealed under the device ([logins and API keys](#claude-logins-and-api-keys)); your own Claude Code login for plain `claude` is never used, moved or erased. Unplugging the device stops claude and erases the session's login storage.
- **Claude Code's automatic updates are off inside the session** (Claude Code's own `DISABLE_AUTOUPDATER` and `DISABLE_UPDATES`, in the session's environment and settings only), and a session starts only with a [reviewed Claude Code version](#reviewed-claude-code-versions). The session context is sealed under the device between sessions, so `--continue` and `--resume` offer the sessions made under Enclawed Code, not those made with plain `claude` (and plain `claude` does not see these).

### Review the gate's decisions with a model (optional, experimental feature)

`ecwctl review` is an experimental feature: an opt-in, evaluation-only judge: after the fact, a model reviews the calls the gate already decided, and you see only the calls where the model and the gate disagree, to label as candidates for refining the rules. It is off until you turn it on with your second factor (`review enable`), it never changes a decision, it runs only when you run it (`review run`, which prints its cap and asks first), it runs only with an Anthropic API key sealed under the Enclaweder (with only a Claude subscription login it says so and sends nothing), and it sends only each call's normalized text, never file content and never a call holding a credential. See [the review reference](docs/commands.md#review-experimental-feature).

### Claude logins and API keys

For Claude subscription logins, Enclawed Code follows Anthropic's terms: the login stays with Claude Code, signed in through Anthropic's own flow, and Enclawed Code never stores or relays it. Such a login is kept where Claude Code keeps it, readable by programs running as you. With an API key, Enclawed Code can seal the credential under the Enclaweder, so even a compromised computer cannot use it without the device. Organizations that need that protection use an API key.

- **Claude subscription login (Free, Pro, Max, Ultra, Team, Enterprise):** sign in with Claude Code's own `/login` inside an `ecwcode` session. Without an Enclaweder, sessions use the login plain `claude` uses. With an Enclaweder, Claude Code keeps the sessions' login in `~/.enclawed/claude-code/claude-login` (Claude Code writes and reads it; on macOS, the login Keychain item Claude Code keys to that directory), and a hardware halt erases it without Enclawed Code reading it. Enclawed Code never collects, stores, seals, opens, relays or moves a subscription login.
- **API key (Claude Console):** `ecwctl login api-key` reads the key from standard input and seals it under the Enclaweder (Linux). Sessions then reach Claude through Enclawed Code's relay, which adds the key; claude holds only a placeholder, and usage is billed to the key's owner. Only a string in Anthropic's API key format (`sk-ant-api...`) is accepted; anything else is treated as a subscription login and refused. Without an Enclaweder, configure the key as Claude Code documents (`ANTHROPIC_API_KEY` or `apiKeyHelper`).
- **Amazon Bedrock, Google Cloud, Microsoft Foundry:** configured as Claude Code documents; Enclawed Code passes them through unchanged.

### Reviewed Claude Code versions

Enclawed Code runs Claude Code under Anthropic's terms, reviewed clause by clause in [docs/legal-review.md](docs/legal-review.md). A newer Claude Code may come with new terms that Enclawed Code has not reviewed, so `ecwcode` (and, in managed mode, the hook) starts a session only with a Claude Code version listed in `legal/reviewed-terms.json` (now 2.1.326 and 2.1.331). Any other version, or one whose version cannot be read, is refused with the reviewed versions and the command that installs one (for a native installation, `curl -fsSL https://claude.ai/install.sh | bash -s 2.1.331`; for npm, `npm install -g @anthropic-ai/claude-code@2.1.331`). This is a compliance control: no variable, setting or opt-out changes it. Inside its sessions Enclawed Code turns off Claude Code's automatic updates, so a session stays on the reviewed version it started with; your own settings for plain `claude` are not changed.

See [docs/usage.md](docs/usage.md) for what each tool call does under Enclawed, headless (`-p`) runs and the policy file, and [docs/enterprise.md](docs/enterprise.md) for deploying it to every Claude Code user in an organization.

## Documentation

- [docs/usage.md](docs/usage.md): using Enclawed Code day to day: what happens to each tool call, the permission mode (`ecwcode` starts Claude Code in bypass mode, so only Enclawed Code's deterministic checks decide), headless runs, the policy file and the audit log.
- [docs/commands.md](docs/commands.md): the complete reference for every Enclawed Code command, flag, environment variable, policy key, decision and audit record, with copy-paste checks for each feature.
- [docs/enterprise.md](docs/enterprise.md): deploying Enclawed Code to every Claude Code user in an organization through managed settings.
- [docs/legal-review.md](docs/legal-review.md): the clause-by-clause review of the terms under which Enclawed Code runs Claude Code.

## Requirements

- Your own installation of [Claude Code](https://docs.anthropic.com/en/docs/claude-code). This project does not include, modify or redistribute Claude Code.
- A reviewed Claude Code version, 2.1.326 or 2.1.331 ([why](#reviewed-claude-code-versions)); every reviewed version blocks a tool call when its hook fails (2.1.295 and later do).
- Node.js 22 or later.
- The open core, [enclawed-oss](https://github.com/enclawed/enclawed-oss), as the `vendor/enclawed-oss` git submodule built by `npm run build:framework` (there is no npm dependency on `enclawed`).

## Development

```bash
npm run build:framework   # build enclawed/framework into .enclawed-dev/ (vendor/enclawed-oss, or ENCLAWED_OSS_DIR, or ../enclawed-oss)
npm test                  # an attached Enclaweder is hidden from the unit tests (unshare), never touched
```

## Not affiliated with Anthropic

Claude and Claude Code are trademarks of Anthropic, PBC. This is an independent project by Enclawed, Inc. It is not affiliated with, endorsed by or sponsored by Anthropic.

## Legal

Enclawed Code's review of the terms under which it runs Claude Code (Anthropic's Claude Code legal and compliance page, Commercial Terms of Service, Service Specific Terms, Supported Regions Policy, Consumer Terms of Service, Usage Policy and trademark guidelines), clause by clause, with how Enclawed Code complies and the tests that prove it: [docs/legal-review.md](docs/legal-review.md). Every publish is refused until the review is redone if any of those pages changed.

## License

MIT. See [LICENSE](LICENSE).
