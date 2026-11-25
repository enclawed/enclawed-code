# Legal review: the terms under which Enclawed Code runs Claude Code

Reviewed by Enclawed, Inc. on 2026-11-25. This document records how Enclawed Code relates to each obligation or restriction in Anthropic's published terms that could apply to it, stated as facts about the code that anyone can check. It is not legal advice. Anthropic's documents are quoted only where this review relies on them; the documents themselves are Anthropic's, at the addresses below.

Enclawed Code (`ecwcode`, `ecwctl`) is a launcher and a set of Claude Code hooks. A person installs Claude Code from Anthropic, signs in with their own account or credentials, and types `ecwcode` where they would type `claude`. Enclawed Code starts that person's own, unmodified Claude Code with Claude Code's documented settings and hooks, and checks each tool call against the person's or organization's policy before it runs. Enclawed Code does not offer Claude, host Claude Code for others, or bill for model usage.

## Documents reviewed

| Document | Address | Reviewed version |
|---|---|---|
| Claude Code: Legal and compliance | https://code.claude.com/docs/en/legal-and-compliance.md (Markdown form of https://code.claude.com/docs/en/legal-and-compliance) | Fetched 2026-11-25T07:13:30Z |
| Commercial Terms of Service | https://www.anthropic.com/legal/commercial-terms | "Commercial Terms of Service", "Effective—Jun 17, 2025", 12 pages (snapshot PDF SHA-256 `af5032c44336929c06722809e2a29a421175837d91be0de149d3462f1fd3e270`) |
| Service Specific Terms | https://www.anthropic.com/legal/service-specific-terms | As published on 2026-11-25 |
| Supported Regions Policy | https://www.anthropic.com/legal/supported-regions | As published on 2026-11-25 |
| Consumer Terms of Service | https://www.anthropic.com/legal/consumer-terms | As published on 2026-11-25 |
| Usage Policy | https://www.anthropic.com/legal/aup | As published on 2026-11-25 |
| Trademark Guidelines | https://www.anthropic.com/legal/trademark-guidelines | As published on 2026-11-25 |

Commercial Terms section D.2 incorporates three of these by reference: "Customer and its Users may only use the Services in compliance with these Terms, including (a) the Usage Policy (“Usage Policy”, which was previously referred to as the Acceptable Use Policy), (b) our policy on the countries and regions Anthropic currently supports (“Supported Regions Policy”) and (c) our Service Specific Terms, each of which is incorporated by reference into these Terms."

## Clause by clause

Each entry gives the page, its section and the clause verbatim, then how Enclawed Code complies (with the files and the tests that prove it), or why the clause does not apply.

### 1. The Claude Code binary is not modified

**Claude Code: Legal and compliance, "Can customers offer Claude Code in their products?":** "**The Claude Code binary must not be modified.** Claude Code must be installed and run as published by Anthropic, and customers may not remove, disable, or restrict any authentication method built into it (including methods that permit signing in with a Claude account or the user's own API key)."

How Enclawed Code complies:

- Enclawed Code does not include, bundle, patch or redistribute Claude Code. `src/claude.mjs` (`locateClaude`) finds the `claude` the person installed on their `PATH` and runs it; no code path writes to the Claude Code executable or its installation directory.
- Enclawed Code changes Claude Code's behavior only through Claude Code's documented interfaces: a `--settings` file (hooks, permission settings, `env`), command-line flags, and environment variables (`src/settings.mjs`, `src/launcher.mjs`).
- Claude Code's automatic updates are turned off inside Enclawed Code's sessions with Claude Code's documented variables `DISABLE_AUTOUPDATER` and `DISABLE_UPDATES` (https://code.claude.com/docs/en/setup#disable-auto-updates), in the session's environment and generated settings only (`src/claude-terms.mjs` `SESSION_UPDATE_ENV`, `src/settings.mjs` `buildSettings`); the binary is not touched. Test: `test/claude-terms.test.mjs` ("the generated session settings always carry Claude Code's update switches", and the launcher test that reads the session's environment and settings).

### 2. No authentication method is removed, disabled or restricted

**Same clause as entry 1:** "customers may not remove, disable, or restrict any authentication method built into it (including methods that permit signing in with a Claude account or the user's own API key)."

How Enclawed Code complies:

- Every sign-in method of Claude Code stays available inside an Enclawed Code session: `/login` with a Claude account or a Claude Console account, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `apiKeyHelper`, and Amazon Bedrock, Google Cloud's Agent Platform and Microsoft Foundry configuration. Without an Enclaweder the session's environment is the person's own (`openLoginForSession` returns `pass`). With an Enclaweder and no API key sealed, the only change is `CLAUDE_SECURESTORAGE_CONFIG_DIR`, the directory where Claude Code keeps its own login for these sessions; the person's environment credentials pass through unchanged (`src/claude-login.mjs`; test: `test/claude-login.test.mjs`, "with a device and no API key").
- Enclawed Code ships no setting that restricts sign-in. `ecwctl managed login-policy install` explains this and points administrators to Claude Code's own managed settings `forceLoginMethod`, `forceLoginOrgUUID` and `allowedProviders` (https://code.claude.com/docs/en/authentication#restrict-login-to-your-organization), which are Anthropic's mechanism for an organization's own choice (`src/admin.mjs`; test: `test/rename-migration.test.mjs`).
- When a customer chooses to seal their own API key under the Enclaweder (`ecwctl login api-key`), sessions authenticate with that key, as Claude Code does when a person sets `ANTHROPIC_API_KEY`; the customer removes it with `ecwctl login api-key --remove` to use a Claude account again. This is the customer's own key management (entry 6).
- Enclawed Code refuses three Claude Code flags because they turn off the hooks or the transcript Enclawed Code checks (`--bare`, `--safe-mode`, `--no-session-persistence`); none of them is a sign-in method, and plain `claude` keeps them (`src/launcher.mjs`).
- Persistence of a Console-created key: on an Enclaweder with command set 0.5, each session runs with a private `CLAUDE_CONFIG_DIR` whose `.claude.json` is a per-session copy (`src/session-state.mjs`). A Claude Console sign-in that creates an API key keeps that key in `.claude.json` on Linux, so such a key lasts for the session in which it was created; sealing the key with `ecwctl login api-key`, or `ANTHROPIC_API_KEY` or `apiKeyHelper`, keeps it across sessions. The sign-in method itself is available in every session.

### 3. Claude.ai credentials and session tokens are never collected, stored or intermediated

**Claude Code: Legal and compliance, "Authentication and credential use":** "Anthropic does not permit third-party developers to offer Claude.ai login into their own applications, or to route requests through Free, Pro, Max, or Ultra plan credentials on behalf of their users. Moreover, developers may not collect, store, or intermediate Claude.ai credentials or session tokens — sign-in to a Claude account must complete through Anthropic's own flow."

How Enclawed Code complies:

- A Claude subscription login stays with Claude Code. Enclawed Code has no sign-in of its own for Claude accounts: `ecwctl login new`, `login seal`, `login resolve` and `login watch` only point to Claude Code's own `/login` (`src/admin.mjs`; test: `test/rename-migration.test.mjs`).
- With an Enclaweder bound, each session's Claude Code keeps its login in a directory Enclawed Code sets aside for its sessions (`<state>/claude-code/claude-login`, passed as `CLAUDE_SECURESTORAGE_CONFIG_DIR`). Claude Code writes and reads the credential there itself. Enclawed Code opens no file in that directory and none of the person's own Claude Code storage (`src/claude-login.mjs` `openLoginForSession`, `closeLoginForSession`). Tests: `test/claude-login.test.mjs` records every read of those directories while a session opens and closes and requires none; conformance check `adapter:claude-code:subscription-login-never-handled` (`src/conformance-login.mjs`, run by `ecwctl conformance` and `test/conformance.test.mjs`) does the same through a session's open, close and hardware halt.
- The relay that serves a sealed API key forwards a request only when it carries the relay's fixed, non-secret placeholder; any other credential header is dropped and the request is refused, never forwarded or recorded (the kit's `auth-relay.ts`; `CLAUDE_RELAY` in `src/claude-login.mjs`).
- What counts as an API key is decided deterministically: only a string in Anthropic's API key format (`sk-ant-api` followed by two digits, `-` and the key body) is an API key; anything else, including Claude OAuth access and refresh tokens, is treated as a subscription credential and is never sealed or relayed (`credentialKind` in `src/claude-login.mjs`). Tests: `test/claude-login.test.mjs` ("credentialKind", "login api-key: a subscription token is refused before any device step", and "a subscription token placed where the sealed store is ... is never relayed"); conformance check `adapter:claude-code:only-api-keys-sealed`.
- Any file at the paths `credentials/claude-login.sealed.json` or `credentials/pending/` is erased without being opened (`eraseLegacySubscriptionStores`; test: `test/claude-login.test.mjs`).
- The optional review judge (`ecwctl review`) runs only with a sealed API key; with only a subscription login it says so before holding the device or asking for a factor, and sends nothing (`src/review-model.mjs`; test: `test/review.test.mjs`, "no model access (no device, or only a Claude subscription login)").

### 4. Sign-in goes only through Anthropic's own flow

**Same clause as entry 3:** "sign-in to a Claude account must complete through Anthropic's own flow." And: "Nor does it prevent an end user from signing in to the unmodified Claude Code binary with their own Claude subscription".

How Enclawed Code complies: the person signs in with Claude Code's own `/login` (or `claude auth login`) inside the unmodified Claude Code. Enclawed Code shows no sign-in page, handles no authorization code and calls no token endpoint for a Claude account (`src/claude-login.mjs` has no authorize or token address).

### 5. No paying for, reselling or intermediating usage; each user brings their own credentials

**Claude Code: Legal and compliance, "Can customers offer Claude Code in their products?":** "**Customers may not pay for, resell, or intermediate Claude usage on their end users' behalf.** Each end user must authenticate with their own Anthropic API key, Claude subscription plan credentials, or 3P inference provider credential (Amazon Bedrock, Google Cloud's Agent Platform, Microsoft Foundry). That usage is billed directly to the end user under their own agreement with Anthropic or, for third-party inference providers, with the applicable provider."

**Commercial Terms, D.4 Use Restrictions (part a):** "Customer may not and must not attempt to (a) access the Services to build a competing product or service, including to train competing AI models or resell the Services except as expressly approved by Anthropic".

How Enclawed Code complies: Enclawed Code supplies no credential and holds no account of its own. Each person authenticates with their own subscription, API key or provider credential, and their usage is billed to that account by Anthropic or the provider. A sealed API key is the key its owner sealed, sent only to `api.anthropic.com` for that owner's own sessions on that owner's computer. Enclawed Code does not charge for, meter or resell model usage.

### 6. API keys and provider credentials are the customer's own key management

**Claude Code: Legal and compliance, "Authentication and credential use":** "This does not restrict how customers provision and manage their own API keys or third-party inference provider credentials — for example, configuring an API key in a development environment, secrets manager, or machine image for use by the customer's own authorized users — provided the resulting usage is billed to the key owner under their agreement with Anthropic (or the applicable provider) and is not resold or intermediated as described above."

How Enclawed Code complies: `ecwctl login api-key` seals the customer's own Anthropic API key under the customer's Enclaweder, as a secrets manager would hold it (Linux). At the start of a session it is opened into the launcher's memory only, and claude reaches `api.anthropic.com` through a relay on a private unix socket that adds the key as `x-api-key`; the key is in no file and no variable of the session, is dropped when the session ends, and is erased on a hardware halt (`src/claude-login.mjs`; test: `test/claude-login.test.mjs`, "a sealed API key is relayed"). Usage is billed to the key's owner. Amazon Bedrock, Google Cloud's Agent Platform and Microsoft Foundry credentials are configured as Claude Code documents and passed through unchanged.

### 7. Names and logos

**Claude Code: Legal and compliance, "Using the Claude Code name and logo":** "You can accurately say, in plain text, that your product has Claude Code preinstalled or that it runs Claude Code. But you can't use the Claude Code or Anthropic names or logos as part of your own product, feature, or company name, in your own logo, or in a way that suggests Anthropic built, endorses, or is partnered with your product. Any other use of Anthropic's names or logos is governed by our Trademark Guidelines and requires our written permission."

**Trademark Guidelines:** "You may only use our trademarks as specifically permitted by us and only in materials we approve beforehand." "You may not use our trademarks in a manner that implies Anthropic’s sponsorship or endorsement, or a relationship or affiliation with Anthropic, except as we expressly authorize."

How Enclawed Code complies: the product is named Enclawed Code, its programs `ecwcode` and `ecwctl`; none contains "Claude" or "Anthropic". Its materials say in plain text that it runs Claude Code (`README.md`: "it launches your own Claude Code installation"), use no Anthropic or Claude Code logo, and state: "Claude and Claude Code are trademarks of Anthropic, PBC. This is an independent project by Enclawed, Inc. It is not affiliated with, endorsed by or sponsored by Anthropic." (`README.md`, "Not affiliated with Anthropic").

### 8. Usage Policy

**Claude Code: Legal and compliance, "Acceptable use":** "Claude Code usage is subject to the Anthropic Usage Policy. Advertised usage limits for Pro, Max, and Ultra plans assume ordinary, individual usage of Claude Code and the Agent SDK."

**Usage Policy, Additional Use Case Guidelines:** "Agentic use cases must comply with the Usage Policy. Users are responsible for ensuring that agents they build or deploy, including actions those agents take through tools, browsers, or connected systems, comply with this Usage Policy."

**Usage Policy, Universal Usage Standards (among prohibited uses):** "Engage in actions or behaviors that circumvent the guardrails or terms of other platforms or services".

How Enclawed Code relates: each person's use of Claude Code under Enclawed Code remains that person's use under the Usage Policy. Enclawed Code adds checks on the agent's tool calls (a deterministic policy, approval for irreversible actions, egress allowlists, an audit log); it supports the agentic-use guideline above and works around none of Anthropic's safeguards. It starts Claude Code in Claude Code's documented `bypassPermissions` permission mode so that Enclawed Code's hooks, which run on every tool call, make each decision; an organization's managed `permissions.disableBypassPermissionsMode` turns that off, and Enclawed Code honors it (`src/permission-mode.mjs`; test: `test/permission-mode.test.mjs`). Enclawed Code adds no usage beyond the person's own sessions, except the optional review judge, which runs only when the person runs it, at most 40 requests per run, with the person's own API key (entry 3).

### 9. Competing products, reverse engineering and duplication

**Commercial Terms, D.4 Use Restrictions:** "Customer may not and must not attempt to (a) access the Services to build a competing product or service, including to train competing AI models or resell the Services except as expressly approved by Anthropic; (b) reverse engineer or duplicate the Services; or (c) support any third party’s attempt at any of the conduct restricted in this sentence."

**Consumer Terms, 3. Use of our Services:** "To develop any products or services that compete with our Services, including to develop or train any artificial intelligence or machine learning algorithms or models or resell the Services." "To decompile, reverse engineer, disassemble, or otherwise reduce our Services to human-readable form, except when these restrictions are prohibited by applicable law."

How Enclawed Code relates: Enclawed Code is a security control for Claude Code sessions; it is not a model, an assistant or a coding agent, offers no model access, trains no model and resells nothing. It does not duplicate Claude Code: it runs the person's own installation. Enclawed Code integrates with Claude Code through its documented hooks, settings, flags and environment variables, and its tests run the published binary as a black box. Where the code refers to how Claude Code behaves (for example where it keeps its credential file, which `src/credentials.mjs` uses only to erase the session's storage or to keep the agent from reading it), that behavior is also described in Claude Code's documentation (https://code.claude.com/docs/en/authentication#credential-management).

### 10. Automated or non-human access (Consumer Terms)

**Consumer Terms, 3. Use of our Services:** "Except when you are accessing our Services via an Anthropic API Key or where we otherwise explicitly permit it, to access the Services through automated or non-human means, whether through a bot, script, or otherwise."

What Enclawed Code does, precisely: `ecwcode` starts the person's own Claude Code, in the person's terminal, with the person's arguments, as the person would run `claude`: an interactive session the person drives, or a `claude -p` run the person starts (Claude Code's documented non-interactive mode). Enclawed Code itself sends no prompts and makes no requests to Claude on its own: its hooks only decide whether each tool call Claude Code proposes may run, and its approval prompt asks the person. A headless run (`-p`) needs the person's second factor first, or an unlock the person issued for a bounded number of runs (`ecwctl auth unlock`). The one feature that sends requests by itself, the review judge, runs only with an Anthropic API key (entry 3), which the clause above excepts.

### 11. Account sharing

**Consumer Terms, 2. Account creation and access:** "You may not share your Account login information, Anthropic API key, or Account credentials with anyone else. You also may not make your Account available to anyone else."

**Commercial Terms, D.5 Service Account:** "Customer is responsible for all activity under its account. Customer will promptly notify Anthropic if Customer believes the account it uses to access the Services has been compromised, or is subject to a denial of service or similar malicious attack that may negatively impact the Services."

How Enclawed Code complies: Enclawed Code keeps no credential for anyone else and offers no way to share one. A subscription login stays in Claude Code's storage on the person's computer; a sealed API key opens only on its owner's computer with its owner's Enclaweder and second factor, for that owner's sessions. The agent cannot read Claude Code's login or Enclawed Code's login directory (every read tool and shell command is refused, reason `secret-path`; `src/hook.mjs` `secretPathsFor`). The tamper-evident audit log and the hardware halt help an account holder notice and contain a compromised computer.

### 12. Hardware-halt erase of the session's own Claude Code login storage

**Related clauses:** entry 3 ("developers may not collect, store, or intermediate Claude.ai credentials or session tokens") and Consumer Terms 2 ("you agree to notify us immediately if you become aware of any unauthorized access to your Account").

What Enclawed Code does: with an Enclaweder bound, when the device is unplugged or reports tampering during a session, the launcher stops every process of the session, then erases the session's own Claude Code login storage: every file in the directory Claude Code was given for these sessions is overwritten through a write-only open and removed (on macOS, the login Keychain item Claude Code keys to that directory is deleted), and the API key sealed under the device is erased (`src/launcher.mjs`; `eraseSessionClaudeLogin` in `src/claude-login.mjs`). Enclawed Code never reads the credential, before or during the erase: deleting a file is neither collecting, storing nor intermediating it. The person's own Claude Code login, the one plain `claude` uses, is never touched. Coming back needs the genuine device, the person's second factor and a fresh sign-in through Claude Code's own `/login`. Tests: `test/hardware.test.mjs` ("hardware halt mid-session: ... the session's Claude Code login storage erased without Enclawed Code ever reading it") records every read of that directory by the launcher across a halted session and requires none; conformance check `adapter:claude-code:subscription-login-never-handled`.

### 13. Notice to Users about Outputs

**Commercial Terms, D.3 Limitations of Outputs; Notice to Users:** "It is Customer’s responsibility to evaluate whether Outputs are appropriate for Customer’s use case, including where human review is appropriate, before using or sharing Outputs. Customer acknowledges, and must notify its Users, that factual assertions in Outputs should not be relied upon without independently checking their accuracy, as they may be false, incomplete, misleading or not reflective of recent events or information."

**Commercial Terms, A.1 Overview:** "Subject to these Terms, Anthropic gives Customer permission to use the Services, including to power products and services Customer makes available to its own customers and end users (“Users”)."

Not applicable to Enclawed Code as a provider: Enclawed Code does not make the Services available to Users. Each person uses their own Claude Code under their own agreement with Anthropic, and the D.3 duties sit with that person or their organization as the Customer. The review judge's model answers are shown to the person who ran it, as candidates for that person's own label, and never change a decision (`src/review.mjs`).

### 14. Service Specific Terms

**Service Specific Terms, A. Claude for Work (Team Plan; Enterprise Plan):** "Customer must inform its Users that (i) they are accessing an administered service offering that enables Customer’s access to and control over data submitted to the Services by Customer and its Users, and (ii) use of the Services is subject to Anthropic’s policies, including the Privacy Policy and Usage Policy."

Not applicable to Enclawed Code: this duty belongs to the organization that holds a Team or Enterprise plan. Enclawed Code is not a party to that plan and administers no one's Claude account. Sections B (Beta Services), C (Fine-Tuning Services), E (Development Partner Program), F (Covered Models) and G (Trusted Access and Verification Programs) concern Anthropic offerings Enclawed Code does not provide or configure. Section D (Marketplace Services): "Customer may only use the Services in compliance with applicable Marketplace Provider policies and agreements it has with the applicable Marketplace Provider." Bedrock and Vertex configurations pass through Enclawed Code unchanged, under the customer's own agreements with those providers.

### 15. Supported regions and export

**Supported Regions Policy:** "Anthropic's products and services — including our apps (such as Claude.ai, Claude Code, and Cowork), our API and developer platform, and Claude models offered through cloud platforms and authorized resellers — are available only in the countries and regions listed below."

**Commercial Terms, M.8 Export and Sanctions:** "Customer may not export or provide access to the Services to persons or entities or into countries or for uses where it is prohibited under U.S. or other applicable international law."

How Enclawed Code relates: Enclawed Code provides no access to Anthropic's services; each person reaches them with their own account, under Anthropic's own regional rules. Enclawed Code adds no proxy that would change where a request comes from: requests go from the person's computer to `api.anthropic.com` (the relay that serves a sealed API key is a local unix socket on that same computer). The Usage Policy entry "Access, facilitate, or provide others (including end users) with access to our products or services in violation of our Supported Regions Policy" is addressed the same way.

### 16. Third-party features, compliance with laws, and incorporated policies

**Commercial Terms, A.2 Third Party Features:** "Customer may elect (in its sole discretion) to use features, services or other content made available by third parties to Customer through the Services (“Third Party Features”)." Not applicable: Enclawed Code is not offered through Anthropic's Services.

**Commercial Terms, D.1 Compliance:** "Each party will comply with all laws applicable to the provision (for Anthropic) and use (for Customer) of the Services, including any applicable data privacy laws." Enclawed Code sends no customer content to Enclawed, Inc.: its state (policy, audit log, history) stays on the person's computer, and the review judge's requests go only to `api.anthropic.com` with the person's own key, with credential-shaped text skipped (`src/review.mjs`).

**Commercial Terms, D.2 Policies and Service Terms:** quoted under "Documents reviewed"; the Usage Policy, Supported Regions Policy and Service Specific Terms are covered in entries 8, 14 and 15.

## How a future review is triggered and recorded

Two controls keep Enclawed Code on the terms reviewed here:

- **Release gate.** `legal/reviewed-terms.json` records a SHA-256 fingerprint of each page above. `scripts/check-legal-terms.mjs` fetches every page and fails, naming each page, if any fingerprint differs or a page cannot be fetched. It runs from `scripts/check-pack.mjs` (npm's `prepack`, so every `npm pack` and `npm publish`) and from `scripts/publish-public.sh`, so a publish is refused until this review is redone. The installed program never fetches these pages. Test: `test/claude-terms.test.mjs` ("the release gate").
- **Claude Code version gate.** A session starts only with a Claude Code version listed under `claudeCode.versions` in `legal/reviewed-terms.json`; a newer Claude Code may come with new terms not reviewed here. Any other version, or one that cannot be read, is refused with the reviewed versions and the command that installs one, in the launcher and in a managed hook (`src/claude-terms.mjs`; tests: `test/claude-terms.test.mjs`). No variable, setting or opt-out changes it. Inside its sessions Enclawed Code turns off Claude Code's updates (entry 1), so a session stays on the version it started with.

To record a new review: read each changed page, update the entries above (clauses quoted verbatim, how Enclawed Code complies, the tests), run `node scripts/check-legal-terms.mjs --print`, put the new fingerprints, the review date and any newly reviewed Claude Code versions in `legal/reviewed-terms.json`, and commit the document and the record together.

### Fingerprints

Two forms, named by `form` in `legal/reviewed-terms.json`:

- `raw`: SHA-256 of the bytes the address serves. Claude Code's documentation serves each page in a stable Markdown form at the page's address plus `.md`; that form is used. Two fetches gave identical bytes.
- `html-text-v1`: anthropic.com/legal serves HTML only (no Markdown or plain-text form), so the fingerprint is of the page's normalized text: the `<main>` element (else `<body>`); HTML comments and every `script`, `style`, `noscript`, `template`, `svg`, `iframe`, `head`, `nav`, `header` and `footer` element removed with their content; every remaining tag replaced by a space; character references decoded; Unicode NFC; every run of whitespace collapsed to one space and the ends trimmed; SHA-256 of the UTF-8 bytes. The scripts carry the pages' volatile content (build identifiers and nonces) and are removed; the text that remains carries no date or nonce. Two fetches about an hour apart gave identical fingerprints.

| Document | Form | SHA-256 |
|---|---|---|
| https://code.claude.com/docs/en/legal-and-compliance.md | raw | `1a7c59468a71304f19e6ce74c8d23b7d71382b81daa5d1c7afe524cc644d6e16` |
| https://www.anthropic.com/legal/commercial-terms | html-text-v1 | `afcb35fb41752e0b778fb646d3eed7b4817bd734257ea11adf4a827e0c5becad` (the live page; the reviewed version is the snapshot effective Jun 17, 2025, PDF SHA-256 `af5032c44336929c06722809e2a29a421175837d91be0de149d3462f1fd3e270`) |
| https://www.anthropic.com/legal/service-specific-terms | html-text-v1 | `a244ca342e540ad49d5b38c2b44b2342f9ded1a12bd7b4da247716e894ce4ac7` |
| https://www.anthropic.com/legal/supported-regions | html-text-v1 | `f00f6819b19c007896b3bae5af7d054c061a6a7e096b4ef57c260bb350345419` |
| https://www.anthropic.com/legal/consumer-terms | html-text-v1 | `316cbc2f2728dda3d48e81be51d7c0a6d15ea44a6588b4ed139c0239df823bf1` |
| https://www.anthropic.com/legal/aup | html-text-v1 | `74003daee1d6cc46dd542f4ad6970fc8c66f0e0b706e47cb1a0bfaf6909119f4` |
| https://www.anthropic.com/legal/trademark-guidelines | html-text-v1 | `afa3b78d910459cdf4b5f7b82139d880d094cff16f2235514cd0935d7be0991d` |

### Reviewed Claude Code versions

2.1.326 and 2.1.331 (2.1.331 is the version this release was tested with; 2.1.326 is the version its benchmarks and recorded fixtures pin).
