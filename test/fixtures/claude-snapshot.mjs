// Claude Code 2.1.326's shell snapshot, made the way it makes it (its DZn,
// Gws, $ws, Wws, mvt, Mws, Ows and Iws, transcribed): a login bash
// (`bash -c -l`) sources ~/.bashrc and writes the functions, shell options
// and aliases it then has, Claude Code's own shadows (rg, the embedded
// bfs/ugrep, pkill, pgrep, pidwait) and the PATH Claude Code computed, to
// <config dir>/shell-snapshots/snapshot-bash-<ms>-<random>.sh. Used by the
// tests and by the ground-truth replay to stand for the real file.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// shell-quote's quote() (Claude Code's Jr) for one word.
function jr(s) {
  if (s === "") {
    return "''";
  }
  if (/["\s]/.test(s) && !/'/.test(s)) {
    return `'${s.replace(/(['\\])/g, "\\$1")}'`;
  }
  if (/["'\s]/.test(s)) {
    return `"${s.replace(/(["\\$`!])/g, "\\$1")}"`;
  }
  return s.replace(/([A-Za-z]:)?([#!"$&'()*,:;<=>?@[\\\]^`{|}])/g, "$1\\$2");
}

const pvt = (e, n, r) => [
  "  if [[ -n ${ZSH_VERSION:-} ]]; then",
  `    ARGV0=${n} ${e} ${r}`,
  '  elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then',
  `    ARGV0=${n} ${e} ${r}`,
  "  else",
  `    (exec -a ${n} ${e} ${r})`,
  "  fi",
];

function mvt(e, n, { claudePath, execPath, flagRws }, r = [], a = []) {
  const h = r.length > 0 ? `${r.join(" ")} \${1+"$@"}` : '${1+"$@"}';
  const N = a.length > 0 ? ["  local _cc_a", '  for _cc_a in ${1+"$@"}; do', `    case "$_cc_a" in ${a.join("|")}) command ${e} \${1+"$@"}; return ;; esac`, "  done"] : [];
  const V = jr(claudePath);
  const oe = jr(execPath);
  return [
    `function ${e} {`,
    ...N,
    ...(flagRws
      ? [`  if [[ -x ${oe} ]]; then`, ...pvt(oe, n, h), `  elif [[ -x ${V} ]]; then`, ...pvt(V, n, h), `  else command ${e} \${1+"$@"}; fi`]
      : ['  local _cc_bin="${CLAUDE_CODE_EXECPATH:-}"', `  [[ -x $_cc_bin ]] || _cc_bin=${V}`, `  if [[ ! -x $_cc_bin ]]; then command ${e} \${1+"$@"}; return; fi`, ...pvt('"$_cc_bin"', n, h)]),
    "}",
  ].join("\n");
}

const AZn = (e, n) => [`${n}case "$(command ${e} --help 2>&1)" in`, `${n}  *--ignore-ancestors*) set -- --ignore-ancestors \${1+"$@"} ;;`, `${n}esac`];

function ows() {
  return [
    "unalias pkill 2>/dev/null || true",
    "function pkill {",
    '  if [ -n "${CLAUDE_PID:-}" ] && [ -r "/proc/${CLAUDE_PID}/comm" ]; then',
    '    local _cc_skip="" _cc_a',
    "    local -a _cc_probe=()",
    '    for _cc_a in ${1+"$@"}; do',
    '      if [ -n "$_cc_skip" ]; then _cc_skip=""; continue; fi',
    '      case "$_cc_a" in',
    "        --signal) _cc_skip=1 ;;",
    "        --signal=*|-e|--echo) ;;",
    "        -[0-9]*) ;;",
    '        -[PUGOF]?*) _cc_probe+=("$_cc_a") ;;',
    "        -[ABCDEFGHIJKLMNOPQRSTUVWXYZ][ABCDEFGHIJKLMNOPQRSTUVWXYZ0-9]*) ;;",
    '        *) _cc_probe+=("$_cc_a") ;;',
    "      esac",
    "    done",
    '    if command pgrep ${_cc_probe[@]+"${_cc_probe[@]}"} 2>/dev/null | command grep -qx "${CLAUDE_PID}"; then',
    "      printf 'pkill: refusing to run \u2014 this pattern matches the Claude CLI process (PID %s). Narrow the pattern, or target your own children with `pkill -P $$ ...`.\\n' \"${CLAUDE_PID}\" >&2",
    "      return 1",
    "    fi",
    ...AZn("pkill", "    "),
    "  fi",
    '  command pkill ${1+"$@"}',
    "}",
  ].join("\n");
}

const iws = () =>
  ["pgrep", "pidwait"]
    .flatMap((e) => [`unalias ${e} 2>/dev/null || true`, `if command -v ${e} >/dev/null 2>&1; then`, `  function ${e} {`, ...AZn(e, "    "), `    command ${e} \${1+"$@"}`, "  }", "fi"])
    .join("\n");

const IZn = `declare -F | while read func; do
        func=\${func##* } # the name: the last word of each declare -F line
        # declare reads a name starting with - or + as an option, and eval one starting with -; other names need no "--"
        if [[ "$func" == [-+]* ]]; then
          printf 'eval -- %q > /dev/null 2>&1\\n' "$(declare -f -- "$func")" >> "$SNAPSHOT_FILE"
        else
          [[ "$func" == _[!_]* ]] ||
            printf 'eval %q > /dev/null 2>&1\\n' "$(declare -f "$func")" >> "$SNAPSHOT_FILE"
        fi
      done`;
const Fws = `declare -F | (
        trap - DEBUG
        ((BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 501)) &&
        __cc_all=$(
          __cc_count=0
          while [[ "$__cc_count" != none ]] && builtin read func; do
            func=\${func##* }
            if [[ -z "$func" || "$func" == [-+]* ]]; then
              __cc_count=none
            elif [[ "$func" != _[!_]* ]]; then
              declare -f "$func"
              builtin printf '\\037'
              __cc_count=$((__cc_count + 1))
            fi
          done
          builtin printf %s "$__cc_count"
        ) &&
        set -f &&
        IFS=$'\\037' &&
        set -- $__cc_all &&
        [[ "\${!#}" == "$(($# - 1))" ]] &&
        set -- "\${@:1:$# - 1}" &&
        (($#)) &&
        printf 'eval %q > /dev/null 2>&1\\n' "\${@%$'\\n'}" >> "$SNAPSHOT_FILE"
      ) || ${IZn}`;

const bashSections = `
      echo "# Shopt" >> "$SNAPSHOT_FILE"
      shopt -p >> "$SNAPSHOT_FILE"
      echo "# Functions" >> "$SNAPSHOT_FILE"
      declare -f > /dev/null 2>&1
      ${Fws}
      echo "# Shell Options" >> "$SNAPSHOT_FILE"
      set -o | awk '$2 == "on" || $1 == "monitor" {print "set -o " $1}' >> "$SNAPSHOT_FILE"
      echo "shopt -s expand_aliases" >> "$SNAPSHOT_FILE"
      echo "# Aliases" >> "$SNAPSHOT_FILE"
      \\alias -p | sed -e '1001,$d' -e 's/^alias -- /alias /' -e 's/^alias /alias -- /' >> "$SNAPSHOT_FILE"
`;

/**
 * Write a snapshot as Claude Code 2.1.326 would for a session whose HOME is
 * `home` and whose PATH is `pathValue`, into `<configDir>/shell-snapshots`.
 * `env`: the environment of the login shell (Claude Code's own). Returns its path.
 */
export function makeClaudeSnapshot({ configDir, home, pathValue, env = {}, claudePath = "/opt/claude/claude", execPath = "/opt/claude/versions/2.1.326", flagRws = false, embeddedSearch = true, now = Date.now() }) {
  const dir = path.join(configDir, "shell-snapshots");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `snapshot-bash-${now}-${Math.random().toString(36).substring(2, 8)}.sh`);
  const rc = path.join(home, ".bashrc");
  const hasRc = fs.existsSync(rc);
  const o = { claudePath, execPath, flagRws };
  const heredoc = [
    "# Check for rg availability",
    "if ! hash rg 2>/dev/null && ! typeset -f rg >/dev/null 2>&1; then",
    `  ${mvt("rg", "rg", o)}`,
    "fi",
    ...(embeddedSearch
      ? [
          "# Shadow find/grep with embedded bfs/ugrep",
          [
            "unalias find 2>/dev/null || true",
            "unalias grep 2>/dev/null || true",
            mvt("find", "bfs", o, ["-S", "dfs", "-regextype", "findutils-default"]),
            mvt("grep", "ugrep", o, ["-G", "--ignore-files", "--hidden", "-I", "--encoding=UTF-8", ...[".git", ".svn", ".hg", ".bzr", ".jj", ".sl"].map((e) => `--exclude-dir=${e}`)], ["-*-filter*", "-*-pager*", "-*-view*", "-*-format-open*", "-*-config*", "---*", "-@*", "-*-save-config*", "-[Zz]*", "-[!-]*[Zz]*", "--null", "--null-data"]),
          ].join("\n"),
        ]
      : []),
    "# Shadow pkill to refuse patterns matching the CLI process",
    ows(),
    "# Shadow pgrep and pidwait to leave their own ancestors out of the results",
    iws(),
    `export PATH=${jr(pathValue)}`,
  ];
  const end = `CLAUDE_CODE_END_${Math.random().toString(36).substring(2, 18)}`;
  const script = `SNAPSHOT_FILE=${jr(file)}
      ${hasRc ? `source "${rc}" < /dev/null` : "# No user config file to source"}

      echo "# Snapshot file" >| "$SNAPSHOT_FILE"
      echo "# Unset all aliases to avoid conflicts with functions" >> "$SNAPSHOT_FILE"
      echo "unalias -a 2>/dev/null || true" >> "$SNAPSHOT_FILE"

      ${hasRc ? bashSections : 'echo "shopt -s expand_aliases" >> "$SNAPSHOT_FILE"'}

      cat >> "$SNAPSHOT_FILE" << '${end}'
${heredoc.join("\n")}
${end}

      if [ ! -f "$SNAPSHOT_FILE" ]; then
        echo "Error: Snapshot file was not created at $SNAPSHOT_FILE" >&2
        exit 1
      fi
    `;
  const r = spawnSync("/bin/bash", ["-c", "-l", script], { env: { ...env, HOME: home, SHELL: "/bin/bash", GIT_EDITOR: "true", CLAUDECODE: "1" }, encoding: "utf8", timeout: 10000 });
  if (r.status !== 0) {
    throw new Error(`snapshot: ${r.stderr}`);
  }
  return file;
}
