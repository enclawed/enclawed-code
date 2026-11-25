// The environment Claude Code's Bash tool runs a command with, for the kit's
// EngineOptions.environment (the complete environment of the agent's shell
// commands, or null when it is not known exactly).
//
// Read from Claude Code 2.1.326's own code (the Bash tool's spawn environment
// $Oo, its command line buildExecCommand, its shell snapshot DZn/Gws, its
// session environment Djs) on Linux, for a command of the Bash tool:
//
//   - the process is spawned with Claude Code's own environment (what
//     Enclawed Code launched it with, plus what Claude Code itself sets at
//     start), every settings file's `env` over it (user, --settings, managed;
//     later sources win), and per command CLAUDECODE, CLAUDE_CODE_SESSION_ID,
//     CLAUDE_CODE_CHILD_SESSION, GIT_EDITOR=true, SHELL, CLAUDE_PID, AI_AGENT,
//     CLAUDE_CODE_SESSION_ATTENDED, CLAUDE_CODE_EXECPATH and a few optional
//     names of Claude Code's own (never a credential);
//   - the shell then sources the session's shell snapshot,
//     <config dir>/shell-snapshots/snapshot-bash-<ms>-<random>.sh, written
//     once at start by a login shell that sourced ~/.bashrc. The snapshot
//     carries the login shell's functions, shell options and aliases and one
//     `export PATH=...` (the PATH Claude Code computed: settings PATH, else its
//     own, plus plugin bin directories). The login shell's other exports are
//     NOT in it: Claude Code takes them (hM().reportShellExports) only when it
//     was started by Claude Desktop (CLAUDE_CODE_ENTRYPOINT claude-desktop or
//     claude-desktop-3p, not a child session);
//   - when the snapshot file is missing, the command runs in a login shell
//     instead (every startup file's exports apply);
//   - CLAUDE_ENV_FILE, and the files hooks write to
//     <config dir>/session-env/<session id>/, are sourced before the command;
//   - with sandboxing, a remote session, the subprocess credential scrub or a
//     shell prefix the command line differs again;
//   - bash itself sources /etc/bash.bashrc and ~/.bashrc for `bash -c` when
//     its stdin is a socket and its shell level is 1 (SHLVL unset or 0).
//
// So the environment is given to the kit only when all of this is known: a
// launcher session on Linux, exactly one bash snapshot of this session in the
// config directory that parses as Claude Code writes it, no
// session-environment script, a CLI entrypoint, no sandbox, remote, scrub,
// shell prefix, BASH_ENV or ENV, and a SHLVL of 1 to 998. The snapshot is
// told apart from other sessions' (the person's own config directory holds
// every session's) by the launcher's marker: an empty directory of the
// session, the last entry of the PATH claude starts with, which Claude Code
// writes into the snapshot's PATH. For one call, a
// function or alias of the person's login shell that the command may invoke
// (it can set any variable) withholds it too. Anything else: null, and the
// kit asks where it would have needed the environment. Values Claude Code
// makes per command (CLAUDE_PID, SHELL, AI_AGENT ...) are left out, so the
// kit treats them as unknown, never as empty; none is a credential.
//
// The same snapshot gives the kit the shell's aliases and functions
// (EngineOptions.shellDefinitions; shellDefinitionsOf): the person's, from the
// snapshot, the functions the environment exports as BASH_FUNC_NAME%%, and
// Claude Code's own rg/find/grep/pkill/pgrep/pidwait shadows when a person's
// name could run inside them (an alias or function named after a builtin or
// reserved word: their bodies call command, local, printf, exec ...). The kit
// then never decides a command word the shell defines as the program of its
// name. They are known once this session's snapshot is read (independent of
// the command); in managed mode (no launcher) from every bash snapshot in the
// config directory, claude's environment and command line (/proc) and every
// settings scope (managedShellDefinitions). Otherwise "unknown", and the kit
// decides no command word as the program of its name.
//
// This module reads files only (node:fs, node:path): the replay of the
// ground-truth benchmark imports it to decide exactly as a session does.

import fs from "node:fs";
import path from "node:path";

/** The record of claude's environment, in the session directory. */
export const CLAUDE_ENV_RECORD = "claude-env.json";
const RECORD_VERSION = 1;

/** The Claude Code version this map was read from. */
export const SHELL_ENV_CLAUDE_VERSION = "2.1.326";

// Claude Code's own shadows in the snapshot (rg, the embedded bfs/ugrep, pkill, pgrep, pidwait; git on macOS).
const CLAUDE_FUNCTIONS = new Set(["rg", "find", "grep", "pkill", "pgrep", "pidwait", "git"]);
// `set -o` options that export what a command assigns.
const EXPORTING_OPTIONS = new Set(["allexport", "keyword"]);
// Entrypoints whose shell takes no login-shell exports (unset: Claude Code sets cli or sdk-cli itself).
const CLI_ENTRYPOINTS = new Set(["cli", "sdk-cli"]);
// Names Claude Code sets per command or at start with values the hook cannot know: left out (unknown).
const PER_COMMAND_UNKNOWN = Object.freeze([
  "SHELL",
  "CLAUDE_PID",
  "AI_AGENT",
  "CLAUDE_CODE_SESSION_ATTENDED",
  "CLAUDE_CODE_EXECPATH",
  "CLAUDE_EFFORT",
  "CLAUDE_CODE_CHILD_NOTES_DIR",
  "TRACEPARENT",
  "BUN_OPTIONS",
  "CLAUDE_CODE_ENTRYPOINT",
  "DEBUG",
  "__CLAUDE_CC_BUN_OPTIONS",
  "__CLAUDE_CC_COMMAND_TEXT",
  // bash's own
  "PWD",
  "OLDPWD",
  "SHLVL",
  "_",
]);
// Claude Code's own namespaces: names it sets, changes or removes at start or per command, in ways
// that depend on how it runs (its relaunch, desktop, bridge, proxy, model and login paths). A
// credential-shaped one stays (present: never treated as absent); any other is left out (unknown).
const CLAUDE_MANAGED = /^(?:CLAUDE_|ANTHROPIC_|CCR_|AGENT_PROXY_|SELF_HOSTED_RUNNER_|OTEL_)|^(?:BROWSER)$/;
const CREDENTIAL_SHAPED = /TOKEN|KEY|SECRET|PASSW|AUTH|CREDENTIAL|COOKIE|HEADER/;
// Names Claude Code sets with fixed values (CLAUDE_CODE_SESSION_ID is the hook input's session_id).
const FIXED = Object.freeze({
  CLAUDECODE: "1",
  CLAUDE_CODE_CHILD_SESSION: "1",
  GIT_EDITOR: "true",
  COREPACK_ENABLE_AUTO_PIN: "0",
  NoDefaultCurrentDirectoryInExePath: "1",
});
// Words that run text the lexer cannot see as words (a function named only inside them).
const INDIRECT = new Set(["eval", "source", ".", "trap"]);

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const nonEmpty = (v) => typeof v === "string" && v !== "";

/**
 * Launcher side, right before claude starts: the environment claude is spawned
 * with, the generated settings file and the setting sources it was given, and
 * the session's PATH marker (null when there is none).
 */
export function recordClaudeEnvironment({ sessionDir, nonce, env, settingsFile, settingSources, pathMarker }) {
  const file = path.join(sessionDir, CLAUDE_ENV_RECORD);
  const clean = {};
  for (const [k, v] of Object.entries(env ?? {})) {
    if (typeof v === "string") {
      clean[k] = v;
    }
  }
  const doc = {
    v: RECORD_VERSION,
    nonce,
    platform: process.platform,
    env: clean,
    settingsFile: settingsFile ?? null,
    settingSources: Array.isArray(settingSources) ? settingSources : null,
    pathMarker: pathMarker ?? null,
  };
  fs.writeFileSync(file, JSON.stringify(doc), { mode: 0o600, flag: "wx" });
  return file;
}

/** The setting sources an argument list gives Claude Code (--setting-sources), or null when it gives none. */
export function settingSourcesOf(args) {
  const vals = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      break;
    }
    if (a === "--setting-sources" && i + 1 < args.length) {
      vals.push(args[++i]);
    } else if (typeof a === "string" && a.startsWith("--setting-sources=")) {
      vals.push(a.slice("--setting-sources=".length));
    }
  }
  return vals.length ? vals.join(",").split(",").map((x) => x.trim()).filter(Boolean) : null;
}

/** Hook side: the record, only as the launcher wrote it for this session (own regular file, 0600, the session's nonce). */
export function readClaudeEnvironment(session) {
  if (!session?.sessionDir || !nonEmpty(session.nonce)) {
    return null;
  }
  let fd;
  try {
    fd = fs.openSync(path.join(session.sessionDir, CLAUDE_ENV_RECORD), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  } catch {
    return null;
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || (process.getuid && st.uid !== process.getuid()) || (st.mode & 0o077) !== 0) {
      return null;
    }
    const doc = JSON.parse(fs.readFileSync(fd, "utf8"));
    if (doc?.v !== RECORD_VERSION || doc.nonce !== session.nonce || !isPlainObject(doc.env) || Object.values(doc.env).some((v) => typeof v !== "string")) {
      return null;
    }
    return doc;
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

// ------------------------------------------------------------------ bash words

const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;

/** Decode bash's $'...' body (ANSI-C quoting). Null on an escape bash would not read the same way here. */
function ansiC(body) {
  let out = "";
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c !== "\\") {
      out += c;
      continue;
    }
    const n = body[++i];
    const simple = { a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" };
    if (n === undefined) {
      return null;
    }
    if (Object.hasOwn(simple, n)) {
      out += simple[n];
    } else if (/[0-7]/.test(n)) {
      const m = /^[0-7]{1,3}/.exec(body.slice(i));
      out += String.fromCharCode(parseInt(m[0], 8) & 0xff);
      i += m[0].length - 1;
    } else if (n === "x") {
      const m = /^[0-9A-Fa-f]{1,2}/.exec(body.slice(i + 1));
      if (!m) {
        return null;
      }
      out += String.fromCharCode(parseInt(m[0], 16));
      i += m[0].length;
    } else {
      // \u, \U, \c and others: not in what bash's %q writes for a function or a path.
      return null;
    }
  }
  return out;
}

/**
 * One shell word as bash reads it with no expansion: '...', $'...', "..."
 * (no $ or ` inside), backslash escapes and plain characters. Null for
 * anything else (an expansion, several words).
 */
export function unquoteWord(w) {
  let out = "";
  let i = 0;
  while (i < w.length) {
    const c = w[i];
    if (c === "'") {
      const j = w.indexOf("'", i + 1);
      if (j < 0) {
        return null;
      }
      out += w.slice(i + 1, j);
      i = j + 1;
    } else if (c === "$" && w[i + 1] === "'") {
      let j = i + 2;
      while (j < w.length && w[j] !== "'") {
        j += w[j] === "\\" ? 2 : 1;
      }
      if (j >= w.length) {
        return null;
      }
      const d = ansiC(w.slice(i + 2, j));
      if (d === null) {
        return null;
      }
      out += d;
      i = j + 1;
    } else if (c === '"') {
      let j = i + 1;
      let s = "";
      while (j < w.length && w[j] !== '"') {
        if (w[j] === "$" || w[j] === "`") {
          return null;
        }
        if (w[j] === "\\" && /["\\$`]/.test(w[j + 1] ?? "")) {
          s += w[j + 1];
          j += 2;
        } else {
          s += w[j++];
        }
      }
      if (j >= w.length) {
        return null;
      }
      out += s;
      i = j + 1;
    } else if (c === "\\") {
      if (i + 1 >= w.length || w[i + 1] === "\n") {
        return null;
      }
      out += w[i + 1];
      i += 2;
    } else if (SAFE_WORD.test(c)) {
      out += c;
      i++;
    } else {
      return null;
    }
  }
  return out;
}

/**
 * Do the braces of a function's text close exactly at its end (bash words `{`
 * and `}` outside quotes, substitutions and comments)? Here-documents are not
 * read (null: not known).
 */
function bracesCloseAtEnd(text, start) {
  let depth = 0;
  const stack = ["top"];
  let wordStart = true;
  let closedAt = -1;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    const ctx = stack.at(-1);
    if (ctx === "sq") {
      if (c === "'") {
        stack.pop();
      }
      continue;
    }
    if (c === "\\") {
      i++;
      wordStart = false;
      continue;
    }
    if (ctx === "dq") {
      if (c === '"') {
        stack.pop();
      } else if (c === "$" && text[i + 1] === "(") {
        stack.push("sub");
        i++;
      } else if (c === "`") {
        stack.push("bq");
      }
      continue;
    }
    if (ctx === "bq" && c === "`") {
      stack.pop();
      wordStart = false;
      continue;
    }
    if (c === "<" && text[i + 1] === "<" && text[i + 2] !== "<") {
      return false;
    }
    if (c === "#" && wordStart) {
      const nl = text.indexOf("\n", i);
      i = nl < 0 ? text.length : nl - 1;
      continue;
    }
    if (c === "'") {
      if (text[i - 1] === "$") {
        // $'...': backslash escapes inside.
        let j = i + 1;
        while (j < text.length && text[j] !== "'") {
          j += text[j] === "\\" ? 2 : 1;
        }
        i = j;
      } else {
        stack.push("sq");
      }
      wordStart = false;
      continue;
    }
    if (c === '"') {
      stack.push("dq");
      wordStart = false;
      continue;
    }
    if (c === "`") {
      stack.push("bq");
      wordStart = false;
      continue;
    }
    if (c === "$" && text[i + 1] === "(") {
      stack.push("sub");
      i++;
      wordStart = true;
      continue;
    }
    if (ctx === "sub" && c === "(") {
      stack.push("sub");
      wordStart = true;
      continue;
    }
    if (ctx === "sub" && c === ")") {
      stack.pop();
      wordStart = false;
      continue;
    }
    const boundary = (ch) => ch === undefined || /[\s;&|()]/.test(ch);
    if (ctx === "top" && (c === "{" || c === "}") && wordStart && boundary(text[i + 1])) {
      if (closedAt >= 0) {
        return false;
      }
      depth += c === "{" ? 1 : -1;
      if (depth < 0) {
        return false;
      }
      if (depth === 0) {
        closedAt = i;
      }
      wordStart = false;
      continue;
    }
    if (closedAt >= 0 && !/\s/.test(c)) {
      return false;
    }
    wordStart = /[\s;&|()]/.test(c);
  }
  return stack.length === 1 && closedAt >= 0;
}

/** A function's text as `declare -f` prints it (`NAME () \n{ \n...\n}`): its name, or null. */
function declaredFunctionName(text) {
  const m = /^([^\s'"\\$`(){}<>|&;]+) \(\) \n\{ \n/.exec(text);
  if (!m || !text.endsWith("\n}")) {
    return null;
  }
  return bracesCloseAtEnd(text, m[0].length - 3) ? m[1] : null;
}

// What a Claude Code shadow function's body may not hold: anything that sets or exports a variable for later commands.
const SHADOW_BODY_REFUSED = /(?:^|[\s;&|(`])(?:export|declare|typeset|readonly|eval|source|\.|enable|set\s+-[A-Za-z]*[ak]|set\s+-o\s+(?:allexport|keyword))(?=\s|$)/m;

/**
 * Parse a Claude Code 2.1.326 bash shell snapshot. `userNames`: the functions
 * and aliases of the person's login shell it defines (any of them may set
 * variables when invoked); `path`: its PATH. Null fields and `ok: false` for
 * a line Claude Code does not write.
 * `expandsNext`: an alias's value ends in a blank (the word after it is
 * read as an alias too). `aliases` (name -> text) and `functions`: the
 * person's, apart (Claude Code's own shadows are in neither).
 * @returns {{ ok: true, path: string, userNames: string[], expandsNext: boolean, aliases: Record<string, string>, functions: string[] } | { ok: false, why: string }}
 */
export function parseShellSnapshot(text) {
  if (typeof text !== "string") {
    return { ok: false, why: "no snapshot" };
  }
  const lines = text.split("\n");
  const userNames = new Set();
  const aliases = Object.create(null);
  const functions = new Set();
  let pathValue = null;
  let expandsNext = false;
  const bad = (i, why) => ({ ok: false, why: `line ${i + 1}: ${why}` });
  // A `function NAME {` block of Claude Code's own: its lines up to `}` at `indent`.
  const shadow = (i, name, indent) => {
    if (!CLAUDE_FUNCTIONS.has(name)) {
      return { err: bad(i, `a function ${name} Claude Code does not write`) };
    }
    const end = lines.findIndex((l, k) => k > i && l === `${indent}}`);
    if (end < 0) {
      return { err: bad(i, `the function ${name} does not end`) };
    }
    const body = lines.slice(i, end + 1).join("\n");
    const open = body.indexOf("{");
    if (!bracesCloseAtEnd(body, open) || SHADOW_BODY_REFUSED.test(lines.slice(i + 1, end).join("\n"))) {
      return { err: bad(i, `the function ${name} is not Claude Code's shadow`) };
    }
    return { next: end + 1 };
  };
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    let m;
    if (line === "" || /^\s*#/.test(line) || line === "unalias -a 2>/dev/null || true" || /^shopt -[su] [A-Za-z0-9_]+$/.test(line)) {
      i++;
    } else if ((m = /^unalias (\S+) 2>\/dev\/null \|\| true$/.exec(line)) && CLAUDE_FUNCTIONS.has(m[1])) {
      i++;
    } else if ((m = /^set -o ([a-z-]+)$/.exec(line))) {
      if (EXPORTING_OPTIONS.has(m[1])) {
        return bad(i, `set -o ${m[1]} exports what a command assigns`);
      }
      i++;
    } else if ((m = /^eval (?:-- )?(.+) > \/dev\/null 2>&1$/.exec(line))) {
      const textOf = unquoteWord(m[1]);
      const name = textOf === null ? null : declaredFunctionName(textOf);
      if (!name) {
        return bad(i, "an eval that is not one function definition");
      }
      userNames.add(name);
      functions.add(name);
      i++;
    } else if ((m = /^alias -- ([^=\s'"\\$`]+)=(.*)$/.exec(line))) {
      // The value: one quoted word, maybe over several lines (a multi-line alias).
      let value = m[2];
      let k = i;
      while (unquoteWord(value) === null && k + 1 < lines.length && (value.split("'").length - 1) % 2 === 1) {
        value += `\n${lines[++k]}`;
      }
      const unq = unquoteWord(value);
      if (unq === null) {
        return bad(i, "an alias whose value is not one quoted word");
      }
      userNames.add(m[1]);
      aliases[m[1]] = unq;
      expandsNext ||= /[ \t]$/.test(unq);
      i = k + 1;
    } else if (line === "if ! hash rg 2>/dev/null && ! typeset -f rg >/dev/null 2>&1; then") {
      const a = /^ {2}alias rg=(.*)$/.exec(lines[i + 1] ?? "");
      let next;
      if (a && unquoteWord(a[1]) !== null) {
        next = i + 2;
      } else if (lines[i + 1] === "  function rg {") {
        const r = shadow(i + 1, "rg", "");
        if (r.err) {
          return r.err;
        }
        next = r.next;
      } else {
        return bad(i + 1, "Claude Code's rg check holds something else");
      }
      if (lines[next] !== "fi") {
        return bad(next, "Claude Code's rg check does not end");
      }
      i = next + 1;
    } else if ((m = /^if command -v (pgrep|pidwait) >\/dev\/null 2>&1; then$/.exec(line))) {
      if (lines[i + 1] !== `  function ${m[1]} {`) {
        return bad(i + 1, `Claude Code's ${m[1]} shadow holds something else`);
      }
      const r = shadow(i + 1, m[1], "  ");
      if (r.err) {
        return r.err;
      }
      if (lines[r.next] !== "fi") {
        return bad(r.next, `Claude Code's ${m[1]} shadow does not end`);
      }
      i = r.next + 1;
    } else if ((m = /^function (\S+) \{$/.exec(line))) {
      const r = shadow(i, m[1], "");
      if (r.err) {
        return r.err;
      }
      i = r.next;
    } else if ((m = /^export PATH=(.+)$/.exec(line))) {
      const v = unquoteWord(m[1]);
      if (v === null || pathValue !== null) {
        return bad(i, pathValue !== null ? "PATH is exported twice" : "a PATH that is not one word");
      }
      pathValue = v;
      i++;
    } else {
      return bad(i, "a line Claude Code does not write");
    }
  }
  if (pathValue === null) {
    return { ok: false, why: "the snapshot exports no PATH" };
  }
  return { ok: true, path: pathValue, userNames: [...userNames].sort(), expandsNext, aliases: { ...aliases }, functions: [...functions].sort() };
}

// Bash's builtins and reserved words (bash 5: compgen -b, compgen -k). Claude
// Code's own shadows (rg, find, grep, pkill, pgrep, pidwait) call command,
// local, printf, exec, case, [[ ...: a person's alias or function of one of
// them runs inside those shadows, which are then the person's code too.
const BASH_BUILTINS = new Set(
  ". : [ alias bg bind break builtin caller cd command compgen complete compopt continue declare dirs disown echo enable eval exec exit export false fc fg getopts hash help history jobs kill let local logout mapfile popd printf pushd pwd read readarray readonly return set shift shopt source suspend test times trap true type typeset ulimit umask unalias unset wait if then else elif fi case esac for select while until do done in function time { } ! [[ ]] coproc".split(" "),
);

/**
 * The aliases and functions of the shell a Bash command runs in, for the
 * kit's EngineOptions.shellDefinitions: the person's from the parsed
 * snapshot(s), the functions `env` exports (BASH_FUNC_NAME%%), and Claude
 * Code's own shadows when a person's name could run inside them. An alias
 * two snapshots give different texts keeps both (so no shape the kit accepts).
 */
export function shellDefinitionsOf(snaps, env) {
  const aliases = Object.create(null);
  const functions = new Set();
  for (const snap of snaps) {
    for (const [k, v] of Object.entries(snap.aliases)) {
      aliases[k] = k in aliases && aliases[k] !== v ? `${aliases[k]}\n${v}` : v;
    }
    for (const f of snap.functions) {
      functions.add(f);
    }
  }
  for (const k of Object.keys(env ?? {})) {
    const m = /^BASH_FUNC_(.+?)(?:%%|\(\))$/.exec(k);
    if (m) {
      functions.add(m[1]);
    }
  }
  if ([...Object.keys(aliases), ...functions].some((n) => BASH_BUILTINS.has(n))) {
    for (const f of CLAUDE_FUNCTIONS) {
      functions.add(f);
    }
  }
  return { aliases: { ...aliases }, functions: [...functions].sort() };
}

// ------------------------------------------------------------------ one call

// Reserved words after which bash reads a command again.
const RESERVED = new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "select", "case", "esac", "in", "function", "time", "!", "{", "}", "coproc"]);

/** The text up to the `close` that ends what starts at `i` (nested parentheses, quotes); -1 when it does not end. */
function closingParen(text, i) {
  let depth = 1;
  for (let j = i; j < text.length; j++) {
    const c = text[j];
    if (c === "\\") {
      j++;
    } else if (c === "'") {
      const k = text.indexOf("'", j + 1);
      if (k < 0) {
        return -1;
      }
      j = k;
    } else if (c === '"') {
      let k = j + 1;
      while (k < text.length && text[k] !== '"') {
        k += text[k] === "\\" ? 2 : 1;
      }
      j = k;
    } else if (c === "(") {
      depth++;
    } else if (c === ")" && --depth === 0) {
      return j;
    }
  }
  return -1;
}

/**
 * The words bash may run as a command in `command` (the first word of each
 * simple command, after assignments, redirections and reserved words, and in
 * every command substitution), and whether such a word is made by an
 * expansion (parameter, substitution, brace, glob), which could be any name.
 * @returns {{ words: Set<string>, unsafe: boolean }}
 */
export function commandWords(command, depth = 0) {
  const words = new Set();
  let unsafe = depth > 8;
  let cmdPos = true;
  let redirectTarget = false;
  const sub = (inner) => {
    const r = commandWords(inner, depth + 1);
    r.words.forEach((w) => words.add(w));
    unsafe ||= r.unsafe;
  };
  const n = command.length;
  let i = 0;
  while (i < n && !unsafe) {
    const c = command[i];
    if (c === " " || c === "\t") {
      i++;
      continue;
    }
    if (c === "#") {
      const nl = command.indexOf("\n", i);
      i = nl < 0 ? n : nl;
      continue;
    }
    if (c === "\n" || c === ";" || c === "|" || c === "(" || c === ")" || (c === "&" && command[i + 1] !== ">")) {
      cmdPos = true;
      redirectTarget = false;
      i++;
      continue;
    }
    if (c === "<" || c === ">" || (c === "&" && command[i + 1] === ">")) {
      if ((c === "<" || c === ">") && command[i + 1] === "(") {
        // Process substitution: its commands run.
        const end = closingParen(command, i + 2);
        if (end < 0) {
          unsafe = true;
          break;
        }
        sub(command.slice(i + 2, end));
        i = end + 1;
        continue;
      }
      if (c === "<" && command[i + 1] === "<" && command[i + 2] !== "<") {
        // A here-document: its body is text, but with an unquoted delimiter its substitutions run.
        let j = i + 2 + (command[i + 2] === "-" ? 1 : 0);
        while (command[j] === " " || command[j] === "\t") {
          j++;
        }
        let k = j;
        while (k < n && !/[\s;&|()<>]/.test(command[k])) {
          k++;
        }
        const raw = command.slice(j, k);
        const delim = raw.replace(/['"\\]/g, "");
        const quoted = delim !== raw;
        const nl = command.indexOf("\n", k);
        if (!delim || nl < 0) {
          // The rest of the line: the body follows on later lines; none here.
          i = k;
          continue;
        }
        const lines = command.slice(nl + 1).split("\n");
        const endLine = lines.findIndex((l) => l.replace(/^\t+/, "") === delim);
        const body = (endLine < 0 ? lines : lines.slice(0, endLine)).join("\n");
        if (!quoted && /\$\(|`/.test(body)) {
          unsafe = true;
          break;
        }
        // Continue after the delimiter word on its own line; the body lines are skipped.
        const rest = command.slice(k, nl);
        sub(rest);
        i = endLine < 0 ? n : nl + 1 + lines.slice(0, endLine + 1).join("\n").length;
        continue;
      }
      while (i < n && /[<>&|-]/.test(command[i])) {
        i++;
      }
      // `2>&1`: the descriptor is part of the operator.
      while (i < n && /[0-9]/.test(command[i]) && (command[i + 1] === undefined || /[\s;&|()]/.test(command[i + 1]))) {
        i++;
      }
      redirectTarget = true;
      continue;
    }
    // A word.
    let text = "";
    let dynamic = false;
    const start = i;
    while (i < n && !/[\s;&|()<>]/.test(command[i])) {
      const d = command[i];
      if (d === "'") {
        const k = command.indexOf("'", i + 1);
        if (k < 0) {
          unsafe = true;
          break;
        }
        text += command.slice(i + 1, k);
        i = k + 1;
      } else if (d === "$" && command[i + 1] === "'") {
        let k = i + 2;
        while (k < n && command[k] !== "'") {
          k += command[k] === "\\" ? 2 : 1;
        }
        const dec = ansiC(command.slice(i + 2, k));
        if (dec === null) {
          dynamic = true;
        }
        text += dec ?? "";
        i = k + 1;
      } else if (d === '"' || (d === "$" && command[i + 1] === '"')) {
        let k = i + (d === "$" ? 2 : 1);
        while (k < n && command[k] !== '"') {
          if (command[k] === "\\") {
            text += command[k + 1] ?? "";
            k += 2;
          } else if (command[k] === "$" && command[k + 1] === "(") {
            const end = closingParen(command, k + 2);
            if (end < 0) {
              unsafe = true;
              break;
            }
            sub(command.slice(k + 2, end));
            dynamic = true;
            k = end + 1;
          } else if (command[k] === "`") {
            const end = command.indexOf("`", k + 1);
            if (end < 0) {
              unsafe = true;
              break;
            }
            sub(command.slice(k + 1, end));
            dynamic = true;
            k = end + 1;
          } else {
            if (command[k] === "$") {
              dynamic = true;
            }
            text += command[k++];
          }
        }
        i = k + 1;
      } else if (d === "\\") {
        if (command[i + 1] !== "\n") {
          text += command[i + 1] ?? "";
        }
        i += 2;
      } else if (d === "$" && command[i + 1] === "(") {
        const end = closingParen(command, i + 2);
        if (end < 0) {
          unsafe = true;
          break;
        }
        sub(command.slice(i + 2, end));
        dynamic = true;
        i = end + 1;
      } else if (d === "`") {
        const end = command.indexOf("`", i + 1);
        if (end < 0) {
          unsafe = true;
          break;
        }
        sub(command.slice(i + 1, end));
        dynamic = true;
        i = end + 1;
      } else {
        // `[` globs only with a `]` after it in the word (`[ "$x" = 1 ]` runs the test program).
        const bracket = d === "[" && /^[^\s;&|()<>]*\]/.test(command.slice(i + 1));
        if (d === "$" || d === "*" || d === "?" || bracket || ((d === "{" || d === "}") && i > start) || (d === "{" && i + 1 < n && !/[\s]/.test(command[i + 1]))) {
          dynamic = true;
        }
        text += d;
        i++;
      }
    }
    if (redirectTarget) {
      redirectTarget = false;
      continue;
    }
    if (!cmdPos) {
      continue;
    }
    // A descriptor number right before a redirection (`2>x cmd`).
    if (/^[0-9]+$/.test(text) && (command[i] === "<" || command[i] === ">")) {
      continue;
    }
    const raw = command.slice(start, i);
    if (/^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=/.test(raw)) {
      // An assignment: the command word comes after it.
      continue;
    }
    words.add(text);
    if (dynamic) {
      unsafe = true;
    }
    cmdPos = RESERVED.has(text) && raw === text;
  }
  return { words, unsafe };
}

/**
 * May this Bash command invoke one of `names` (functions and aliases of the
 * snapshot)? `everyWord`: an alias whose value ends in a blank makes the next
 * word an alias too: then every word counts.
 */
export function mayInvoke(command, names, { everyWord = false } = {}) {
  if (names.length === 0) {
    return false;
  }
  if (names.includes("command_not_found_handle") || names.some((x) => x.includes("/"))) {
    return true;
  }
  const text = typeof command === "string" ? command : "";
  const { words, unsafe } = commandWords(text);
  if (unsafe || [...INDIRECT].some((w) => words.has(w)) || names.some((x) => words.has(x))) {
    return true;
  }
  if (everyWord) {
    // Any word anywhere (quotes and escapes removed) naming one of them.
    const loose = new Set(text.replace(/['"\\]/g, "").split(/[\s;&|()<>=]+/));
    return names.some((x) => loose.has(x)) || /[$`{*?[]/.test(text);
  }
  return false;
}

function readJsonFile(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (err) {
    return err.code === "ENOENT" ? { absent: true } : { error: `${file}: ${err.code ?? err.message}` };
  }
  try {
    return { doc: JSON.parse(text) };
  } catch {
    return { error: `${file} is not JSON` };
  }
}

/** A settings document's `env`, or an error when Claude Code could read it otherwise. */
function settingsEnvOf(doc, where) {
  if (!isPlainObject(doc)) {
    return { error: `${where} is not a settings object` };
  }
  if (doc.env === undefined) {
    return { env: {} };
  }
  if (!isPlainObject(doc.env) || Object.values(doc.env).some((v) => typeof v !== "string")) {
    return { error: `${where} has an env that is not names to strings` };
  }
  return { env: doc.env };
}

/**
 * The complete environment Claude Code's Bash tool runs `input`'s command
 * with in this session, or null and why it is not known exactly.
 *
 * `record`: claude-env.json (readClaudeEnvironment); `managedDocs`: the managed
 * settings documents (managed.mjs readManagedSettings), read now.
 * `definitions`: the shell's aliases and functions (EngineOptions.shellDefinitions),
 * known once this session's snapshot is read, else "unknown".
 * @returns {{ environment: Record<string, string> | null, definitions: { aliases: Record<string, string>, functions: string[] } | "unknown", why: string | null }}
 */
export function shellEnvironment({ record, input, managedDocs = [], platform = process.platform }) {
  // definitions: the shell's aliases and functions (shellDefinitionsOf), "unknown" until the snapshot is read.
  let definitions = "unknown";
  const no = (why) => ({ environment: null, definitions, why });
  if (!record) {
    return no("the launcher's record of claude's environment is not there");
  }
  if (platform !== "linux" || record.platform !== "linux") {
    return no("only Claude Code's Linux shell is mapped");
  }
  const tool = input?.tool_name;
  if (tool !== undefined && tool !== "Bash" && typeof input?.tool_input?.command === "string") {
    return no(`the ${tool} tool's shell is not mapped`);
  }
  const sessionId = input?.session_id;
  if (!nonEmpty(sessionId) || !/^[A-Za-z0-9_-]{1,128}$/.test(sessionId)) {
    return no("no session id");
  }
  const base = record.env;
  // Claude Code's config directory: CLAUDE_CONFIG_DIR, else ~/.claude.
  const configDir = nonEmpty(base.CLAUDE_CONFIG_DIR) ? base.CLAUDE_CONFIG_DIR : nonEmpty(base.HOME) ? path.join(base.HOME, ".claude") : null;
  const marker = record.pathMarker;
  // Enclawed Code always passes --setting-sources: the project's and the local settings are admitted copies inside its own settings file.
  if (!Array.isArray(record.settingSources) || record.settingSources.some((x) => x !== "user")) {
    return no("the setting sources Claude Code loads live are not known");
  }
  if (!configDir || !path.isAbsolute(configDir)) {
    return no("claude's config directory is not known");
  }
  if (!nonEmpty(marker) || !path.isAbsolute(marker) || !(base.PATH ?? "").split(":").includes(marker)) {
    return no("claude's PATH carries no session marker: this session's shell snapshot cannot be told apart");
  }
  // Settings `env`, in Claude Code's order (later wins): user (when loaded), --settings, managed.
  const layers = [];
  if (record.settingSources.includes("user")) {
    const u = readJsonFile(path.join(configDir, "settings.json"));
    if (u.error) {
      return no(u.error);
    }
    if (!u.absent) {
      layers.push({ where: "the user settings", doc: u.doc });
    }
  }
  if (nonEmpty(record.settingsFile)) {
    const f = readJsonFile(record.settingsFile);
    if (f.error || f.absent) {
      return no(f.error ?? "Enclawed Code's settings file is gone");
    }
    layers.push({ where: "Enclawed Code's settings", doc: f.doc });
  }
  const managedSeen = new Map();
  for (const m of managedDocs) {
    if (m.invalid || !isPlainObject(m.doc)) {
      return no(`the managed settings ${m.file} cannot be read as Claude Code reads them`);
    }
    for (const [k, v] of Object.entries(isPlainObject(m.doc.env) ? m.doc.env : {})) {
      if (managedSeen.has(k) && managedSeen.get(k) !== v) {
        return no(`two managed settings files set ${k}`);
      }
      managedSeen.set(k, v);
    }
    layers.push({ where: `the managed settings ${m.file}`, doc: m.doc });
  }
  if (fs.existsSync(path.join(configDir, "remote-settings.json"))) {
    return no("server-managed settings apply");
  }
  const env = { ...base };
  for (const l of layers) {
    const e = settingsEnvOf(l.doc, l.where);
    if (e.error) {
      return no(e.error);
    }
    if (l.doc.sandbox?.enabled === true) {
      return no(`${l.where} turns the sandbox on`);
    }
    Object.assign(env, e.env);
  }
  const entry = env.CLAUDE_CODE_ENTRYPOINT;
  if (entry !== undefined && !CLI_ENTRYPOINTS.has(entry)) {
    return no(`CLAUDE_CODE_ENTRYPOINT=${entry}: the shell may take the login shell's exports`);
  }
  for (const name of ["CLAUDE_CODE_REMOTE", "CLAUDE_ENV_FILE", "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB", "CLAUDE_CODE_SHELL_PREFIX", "BASH_ENV", "ENV"]) {
    if (nonEmpty(env[name])) {
      return no(`${name} is set`);
    }
  }
  // bash started with a socket for stdin (isnetconn: it reads as "run by rshd") and at shell level 1
  // (SHLVL unset, 0 or not a number; 1000 or more resets to 1) sources /etc/bash.bashrc and ~/.bashrc
  // first, with every export in them: only a SHLVL of 1 to 998 keeps it from doing that.
  if (!/^[0-9]{1,3}$/.test(env.SHLVL ?? "") || Number(env.SHLVL) < 1 || Number(env.SHLVL) > 998) {
    return no("SHLVL is not 1 to 998: bash may source the startup files for every command");
  }
  // Hooks' session environment files: sourced before every command.
  const sessionEnvDir = path.join(configDir, "session-env", sessionId);
  try {
    for (const f of fs.readdirSync(sessionEnvDir)) {
      if (fs.readFileSync(path.join(sessionEnvDir, f), "utf8").trim() !== "") {
        return no(`a hook wrote the session environment file ${f}`);
      }
    }
  } catch (err) {
    if (err.code !== "ENOENT") {
      return no(`the session environment directory cannot be read (${err.code ?? err.message})`);
    }
  }
  // This session's snapshot: the one whose PATH holds the marker; exactly one, bash's, as Claude Code writes it.
  const snapDir = path.join(configDir, "shell-snapshots");
  let names;
  try {
    names = fs.readdirSync(snapDir).filter((n) => n.startsWith("snapshot-"));
  } catch {
    names = [];
  }
  const ours = [];
  for (const n of names) {
    let text;
    try {
      text = fs.readFileSync(path.join(snapDir, n), "utf8");
    } catch {
      continue;
    }
    if (text.includes(marker)) {
      ours.push({ n, text });
    }
  }
  if (ours.length !== 1) {
    return no(ours.length === 0 ? "no shell snapshot of this session (a command would run in a login shell)" : "more than one shell snapshot names this session");
  }
  if (!/^snapshot-bash-\d+-[a-z0-9]{1,8}\.sh$/.test(ours[0].n)) {
    return no("this session's shell snapshot is not bash's");
  }
  const snap = parseShellSnapshot(ours[0].text);
  if (!snap.ok) {
    return no(`the shell snapshot is not as Claude Code writes it (${snap.why})`);
  }
  if (!snap.path.split(":").includes(marker)) {
    return no("this session's shell snapshot does not export its marked PATH");
  }
  definitions = shellDefinitionsOf([snap], env);
  // Functions the environment exports (BASH_FUNC_name%%) are the shell's too.
  const fnNames = [...snap.userNames];
  for (const k of Object.keys(env)) {
    const m = /^BASH_FUNC_(.+)(?:%%|\(\))$/.exec(k);
    if (m) {
      fnNames.push(m[1]);
    }
  }
  if (typeof input?.tool_input?.command === "string" && mayInvoke(input.tool_input.command, fnNames, { everyWord: snap.expandsNext })) {
    return no("the command may invoke a function or alias of the login shell");
  }
  for (const k of PER_COMMAND_UNKNOWN) {
    delete env[k];
  }
  for (const k of Object.keys(env)) {
    if (CLAUDE_MANAGED.test(k) && !CREDENTIAL_SHAPED.test(k)) {
      delete env[k];
    }
  }
  Object.assign(env, FIXED, { CLAUDE_CODE_SESSION_ID: sessionId, PATH: snap.path });
  return { environment: env, definitions, why: null };
}

/**
 * Managed mode (no launcher, so no record of claude's environment and no
 * marker in its PATH): the aliases and functions of the shell Claude Code's
 * Bash tool runs commands in, from what the hook reads itself. `claudeEnv`:
 * the environment claude started with (/proc/<pid>/environ), `claudeArgs` its
 * command line. Every bash snapshot in the config directory counts (this
 * session's is one of them; the union is a superset), each must parse as
 * Claude Code writes it, and settings `env` of every scope is read
 * (user, project, local, managed). "unknown" unless all of that is known, as
 * for shellEnvironment: Linux, a CLI entrypoint, no --settings, sandbox,
 * remote, session-environment script, shell prefix, BASH_ENV or ENV, a
 * SHLVL of 1 to 998, and at least one snapshot.
 * @returns {{ definitions: { aliases: Record<string, string>, functions: string[] } | "unknown", why: string | null }}
 */
export function managedShellDefinitions({ claudeEnv, claudeArgs = [], projectDir, sessionId, managedDocs = [], platform = process.platform }) {
  const unknown = (why) => ({ definitions: "unknown", why });
  if (platform !== "linux") {
    return unknown("only Claude Code's Linux shell is mapped");
  }
  if (!isPlainObject(claudeEnv)) {
    return unknown("claude's environment cannot be read");
  }
  if (!Array.isArray(claudeArgs) || claudeArgs.some((a) => typeof a !== "string" || /^--settings?(?:=|$)|^--setting-sources/.test(a))) {
    return unknown("claude was started with settings the hook does not see");
  }
  if (!nonEmpty(sessionId) || !/^[A-Za-z0-9_-]{1,128}$/.test(sessionId)) {
    return unknown("no session id");
  }
  const configDir = nonEmpty(claudeEnv.CLAUDE_CONFIG_DIR) ? claudeEnv.CLAUDE_CONFIG_DIR : nonEmpty(claudeEnv.HOME) ? path.join(claudeEnv.HOME, ".claude") : null;
  if (!configDir || !path.isAbsolute(configDir) || typeof projectDir !== "string" || !path.isAbsolute(projectDir)) {
    return unknown("claude's config directory or the project is not known");
  }
  const env = { ...claudeEnv };
  const docs = [];
  for (const f of [path.join(configDir, "settings.json"), path.join(projectDir, ".claude", "settings.json"), path.join(projectDir, ".claude", "settings.local.json")]) {
    const r = readJsonFile(f);
    if (r.error) {
      return unknown(r.error);
    }
    if (!r.absent) {
      docs.push({ where: f, doc: r.doc });
    }
  }
  for (const m of managedDocs) {
    if (m.invalid || !isPlainObject(m.doc)) {
      return unknown(`the managed settings ${m.file} cannot be read as Claude Code reads them`);
    }
    docs.push({ where: `the managed settings ${m.file}`, doc: m.doc });
  }
  if (fs.existsSync(path.join(configDir, "remote-settings.json"))) {
    return unknown("server-managed settings apply");
  }
  for (const d of docs) {
    const e = settingsEnvOf(d.doc, d.where);
    if (e.error) {
      return unknown(e.error);
    }
    if (d.doc.sandbox?.enabled === true) {
      return unknown(`${d.where} turns the sandbox on`);
    }
    Object.assign(env, e.env);
  }
  const entry = env.CLAUDE_CODE_ENTRYPOINT;
  if (entry !== undefined && !CLI_ENTRYPOINTS.has(entry)) {
    return unknown(`CLAUDE_CODE_ENTRYPOINT=${entry}: the shell may take the login shell's exports`);
  }
  for (const name of ["CLAUDE_CODE_REMOTE", "CLAUDE_ENV_FILE", "CLAUDE_CODE_SHELL_PREFIX", "BASH_ENV", "ENV"]) {
    if (nonEmpty(env[name])) {
      return unknown(`${name} is set`);
    }
  }
  if (!/^[0-9]{1,3}$/.test(env.SHLVL ?? "") || Number(env.SHLVL) < 1 || Number(env.SHLVL) > 998) {
    return unknown("SHLVL is not 1 to 998: bash may source the startup files for every command");
  }
  const sessionEnvDir = path.join(configDir, "session-env", sessionId);
  try {
    for (const f of fs.readdirSync(sessionEnvDir)) {
      if (fs.readFileSync(path.join(sessionEnvDir, f), "utf8").trim() !== "") {
        return unknown(`a hook wrote the session environment file ${f}`);
      }
    }
  } catch (err) {
    if (err.code !== "ENOENT") {
      return unknown(`the session environment directory cannot be read (${err.code ?? err.message})`);
    }
  }
  const snapDir = path.join(configDir, "shell-snapshots");
  let names;
  try {
    names = fs.readdirSync(snapDir).filter((n) => n.startsWith("snapshot-"));
  } catch {
    names = [];
  }
  if (names.length === 0) {
    return unknown("no shell snapshot (a command would run in a login shell)");
  }
  const snaps = [];
  for (const n of names) {
    if (!/^snapshot-bash-\d+-[a-z0-9]{1,8}\.sh$/.test(n)) {
      return unknown(`the shell snapshot ${n} is not bash's`);
    }
    let text;
    try {
      text = fs.readFileSync(path.join(snapDir, n), "utf8");
    } catch {
      return unknown(`the shell snapshot ${n} cannot be read`);
    }
    const snap = parseShellSnapshot(text);
    if (!snap.ok) {
      return unknown(`the shell snapshot ${n} is not as Claude Code writes it (${snap.why})`);
    }
    snaps.push(snap);
  }
  return { definitions: shellDefinitionsOf(snaps, env), why: null };
}
