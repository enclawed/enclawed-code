// How `ecwcode` reads its command line without taking anything from claude's.
//
// Scheme:
//   - `ecwcode` reserves no word and no flag: every argument goes to claude,
//     in order, exactly as `claude` would get it (`ecwcode doctor` is Claude
//     Code's doctor, `ecwcode history` is a prompt). Enclawed Code's own
//     commands are a separate program, `ecwctl` (src/ctl.mjs).
//   - Arguments that would switch Enclawed off are refused, never dropped
//     (HOOK_DISABLING_FLAGS, --no-session-persistence: launcher.mjs).
//   - The arguments Enclawed Code rewrites keep their meaning for claude:
//     `--settings`, merged into the settings file it generates (settings.mjs),
//     because claude reads a single `--settings` value, and `--mcp-config`,
//     whose servers are admitted first (mcp.mjs). `--workflow` and
//     `--passphrase-fd` are Enclawed Code's own launch options (claude has
//     neither) and are taken out.

// claude subcommands that do not start a session in this process, so there
// are no tool calls to gate (from `claude --help`, Claude Code 2.1.326).
//
// `agents` is NOT here: it opens the agent view, which dispatches sessions and
// accepts --settings for them (`claude agents --help`), so Enclawed Code treats it
// as session-starting and injects its hooks (red-team I11). `attach` opens an
// existing background session (started with its own settings) and `respawn`
// restarts one with the settings it was started with.
export const CLAUDE_NON_SESSION_COMMANDS = Object.freeze([
  "attach",
  "auth",
  "auto-mode",
  "doctor",
  "gateway",
  "import",
  "install",
  "logs",
  "mcp",
  "plugin",
  "plugins",
  "purge",
  "respawn",
  "rm",
  "setup-token",
  "stop",
  "kill",
  "ultrareview",
  "update",
  "upgrade",
]);

// Informational flags: claude prints and exits, no session starts.
export const CLAUDE_INFO_FLAGS = Object.freeze(["-v", "--version", "-h", "--help"]);

/** Enclawed Code's own launch options, taken out of claude's arguments (claude has neither). */
export const ECWCODE_LAUNCH_OPTIONS = Object.freeze(["--workflow", "--passphrase-fd"]);

// Flags that turn off settings-defined hooks, which would switch Enclawed
// off for the session; Enclawed Code refuses to pass them.
export const HOOK_DISABLING_FLAGS = Object.freeze(["--bare", "--safe-mode"]);

/**
 * Every argument is claude's; `session` says whether claude starts a session
 * in this process (and so has tool calls to check).
 * @returns {{ kind: "passthrough", args: string[], session: boolean }}
 */
export function routeArgs(argv) {
  const first = argv[0];
  const session = !(
    first !== undefined &&
    (CLAUDE_NON_SESSION_COMMANDS.includes(first) || (argv.length === 1 && CLAUDE_INFO_FLAGS.includes(first)))
  );
  return { kind: "passthrough", args: [...argv], session };
}

/** Index of a standalone `--`, after which nothing is an option. */
function optionsEnd(args) {
  const i = args.indexOf("--");
  return i < 0 ? args.length : i;
}

/**
 * Take every `--settings` value out of the argument list (both
 * `--settings X` and `--settings=X`), in order, leaving all else untouched.
 *
 * @returns {{ rest: string[], values: string[] }}
 */
export function extractSettingsArgs(args) {
  const end = optionsEnd(args);
  const rest = [];
  const values = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (i < end && a === "--settings") {
      if (i + 1 >= end) {
        throw new Error("--settings needs a value (a settings file or a JSON string)");
      }
      values.push(args[i + 1]);
      i++;
      continue;
    }
    if (i < end && a.startsWith("--settings=")) {
      values.push(a.slice("--settings=".length));
      continue;
    }
    rest.push(a);
  }
  return { rest, values };
}

export function hasBackgroundFlag(args) {
  const end = optionsEnd(args);
  return args[0] === "agents" || args.slice(0, end).some((a) => a === "--bg" || a === "--background");
}

/** A headless run: `-p` / `--print` among the options. */
export function isPrintMode(args) {
  const end = optionsEnd(args);
  return args.slice(0, end).some((a) => a === "-p" || a === "--print");
}

/**
 * Take Enclawed Code's own `--passphrase-fd N` (or `--passphrase-fd=N`) out of a
 * claude argument list. claude has no such option.
 * @returns {{ rest: string[], fd: string|null }}
 */
export function extractPassphraseFd(args) {
  const end = optionsEnd(args);
  const rest = [];
  let fd = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (i < end && a === "--passphrase-fd") {
      if (i + 1 >= end) {
        throw new Error("--passphrase-fd needs a file descriptor number");
      }
      fd = args[++i];
      continue;
    }
    if (i < end && a.startsWith("--passphrase-fd=")) {
      fd = a.slice("--passphrase-fd=".length);
      continue;
    }
    rest.push(a);
  }
  return { rest, fd };
}

/**
 * Take Enclawed Code's own `--workflow NAME` (or `--workflow=NAME`) out of a
 * claude argument list (workflow.mjs). claude has no such option.
 * @returns {{ rest: string[], workflow: string|null }}
 */
export function extractWorkflow(args) {
  const end = optionsEnd(args);
  const rest = [];
  let workflow = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (i < end && a === "--workflow") {
      if (i + 1 >= end) {
        throw new Error("--workflow needs a profile name (see: ecwctl policy workflow list)");
      }
      if (workflow !== null) {
        throw new Error("--workflow is given twice");
      }
      workflow = args[++i];
      continue;
    }
    if (i < end && a.startsWith("--workflow=")) {
      if (workflow !== null) {
        throw new Error("--workflow is given twice");
      }
      workflow = a.slice("--workflow=".length);
      continue;
    }
    rest.push(a);
  }
  return { rest, workflow };
}

/**
 * Take the user's `--mcp-config` values (variadic: every following argument
 * up to the next option) and `--strict-mcp-config` out of the argument list:
 * Enclawed Code passes its own (mcp.mjs), and the user's servers are admission
 * candidates.
 * @returns {{ rest: string[], values: string[], strict: boolean }}
 */
export function extractMcpConfig(args) {
  const end = optionsEnd(args);
  const rest = [];
  const values = [];
  let strict = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (i < end && a === "--strict-mcp-config") {
      strict = true;
      continue;
    }
    if (i < end && a.startsWith("--mcp-config=")) {
      values.push(a.slice("--mcp-config=".length));
      continue;
    }
    if (i < end && a === "--mcp-config") {
      let n = 0;
      while (i + 1 < end && !args[i + 1].startsWith("-")) {
        values.push(args[++i]);
        n++;
      }
      if (n === 0) {
        throw new Error("--mcp-config needs a file or a JSON string");
      }
      continue;
    }
    rest.push(a);
  }
  return { rest, values, strict };
}

/** The values of a variadic claude option (`--add-dir a b`, `--add-dir=a`), left in place. */
export function optionValues(args, name) {
  const end = optionsEnd(args);
  const out = [];
  for (let i = 0; i < end; i++) {
    if (args[i] === name) {
      while (i + 1 < end && !args[i + 1].startsWith("-")) {
        out.push(args[++i]);
      }
    } else if (args[i].startsWith(`${name}=`)) {
      out.push(args[i].slice(name.length + 1));
    }
  }
  return out;
}

/** `args` without an option and its values (before `--`): `--name a b`, `--name=a`. */
export function withoutOption(args, name) {
  const end = optionsEnd(args);
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (i < end && args[i] === name) {
      while (i + 1 < end && !args[i + 1].startsWith("-")) {
        i++;
      }
      continue;
    }
    if (i < end && args[i].startsWith(`${name}=`)) {
      continue;
    }
    out.push(args[i]);
  }
  return out;
}
