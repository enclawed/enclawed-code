// What Claude Code's own permission prompt guarantees, as data for the kit's
// host-prompt guard (kit.askAtHostPrompt / completeHostPromptAsk, engine
// option `hostPrompt`). Only managed (launcher-less) sessions use it: there an
// Enclawed "ask" goes to Claude Code's prompt. In a launcher session the ask is
// answered at Enclawed Code's own prompt (approval.mjs) and never reaches
// Claude Code's; a launcher session without a terminal runs claude without its
// interactive prompt (-p, background), which has no re-check to exploit.
//
// Checked against Claude Code 2.1.326 (its bundled JavaScript, read only):
//
//   - The open permission dialog subscribes to the permission-context signal
//     (emitted on a mode change with shift+tab, a saved rule, any change of
//     the permission context) and re-runs the permission check for the
//     pending call, WITHOUT the PreToolUse hook. When that check now allows
//     the call, the dialog closes and the call runs, logged as
//     {decision:"accept", source:"config", modeAtRecheck}. A hook's "ask" is
//     not exempt: only asks marked forcedByCaller or personOnly, tools that
//     require user interaction, or bypass-immune safety checks are.
//   - acceptEdits allows Edit/Write/MultiEdit/NotebookEdit inside the working
//     folders, and Bash commands made of mkdir, touch, rm, rmdir, mv, cp and
//     sed (PowerShell likewise). Every mode allows its read-only commands,
//     reads inside the working folders, WebFetch to its preapproved hosts, and
//     whatever an allow rule names.
//   - PostToolUse's input carries permission_mode as the session's mode when
//     the call ran.
//   - allowManagedHooksOnly (managed settings only) runs only managed hooks
//     and the hooks of plugins the managed settings enable, so no other
//     PermissionRequest hook can answer the prompt; sandbox.autoAllowBashIfSandboxed
//     (default false) would let its check allow every sandboxed command.

import { createHash } from "node:crypto";
import path from "node:path";

/**
 * The modes in which a pending ask waits for the person (bypassPermissions
 * and auto are off in managed settings). Only default: shift+tab cycles
 * default -> acceptEdits -> plan, so a call that ran in plan may have been
 * approved by Claude Code itself on the way through acceptEdits.
 */
export const PERSON_MODES = Object.freeze(["default"]);

/**
 * How permissive Claude Code 2.1.326's permission modes are (kit
 * HostModeOrder), read from its bundled JavaScript:
 *
 *   - its own rank table {plan:0, default:1, dontAsk:1, acceptEdits:2,
 *     auto:3, bypassPermissions:4}, with acceptEdits not within auto (its
 *     "is this mode within that one" check excludes acceptEdits under auto:
 *     acceptEdits allows edits that auto puts to its classifier), and dontAsk
 *     narrower than default (dontAsk denies what default asks);
 *   - plan runs as bypassPermissions when bypass is available (its check
 *     allows every call in plan when isBypassPermissionsModeAvailable);
 *   - when auto is unavailable (the model, e.g. claude-haiku-4-5 on a
 *     first-party subscription; the plan; settings disableAutoMode; fast
 *     mode), a session launched with --permission-mode auto falls back to
 *     default (trigger "auto_gate_denied"), and its hooks then report
 *     permission_mode "default".
 *
 * The same data decides the headless mode binding (a stricter mode than
 * launched is a downgrade, accepted and audited; a wider one, or any mode
 * where a person answers asks under a launched bypassPermissions, stops claude),
 * the no-person approval route (gate.mjs)
 * and which PERSON_MODES count at the prompt guard.
 */
export const MODE_ORDER = Object.freeze({
  rank: Object.freeze({ plan: 0, default: 1, dontAsk: 1, acceptEdits: 2, auto: 3, bypassPermissions: 4 }),
  notWithin: Object.freeze([Object.freeze(["acceptEdits", "auto"])]),
  narrowestOfRank: Object.freeze(["dontAsk"]),
  planMode: "plan",
  bypassMode: "bypassPermissions",
  planIsBypassWhenAvailable: true,
  // Nobody answers an ask in bypassPermissions: Enclawed denies it there
  // (gate.mjs, approvalRoute "no-person"), so a session launched in bypass
  // that reports a person-answered mode is a mismatch, not a downgrade.
  noPersonModes: Object.freeze(["bypassPermissions"]),
});

// Bash commands Claude Code 2.1.326 may allow by itself (acceptEdits file
// commands, and the commands and prefixes of its read-only check), as word
// prefixes. Generous on purpose: a command left out here would be asked at a
// prompt that can approve it by itself.
const SHELL_PREFIXES = Object.freeze([
  // acceptEdits
  "mkdir", "touch", "rm", "rmdir", "mv", "cp", "sed",
  // read-only commands
  "cal", "uptime", "cat", "head", "tail", "wc", "stat", "strings", "hexdump", "od", "nl", "id", "uname", "free", "df", "du",
  "locale", "groups", "nproc", "basename", "dirname", "realpath", "cut", "paste", "tr", "column", "tac", "rev", "fold",
  "expand", "unexpand", "fmt", "comm", "cmp", "numfmt", "readlink", "diff", "true", "false", "sleep", "type", "expr", "seq",
  "tsort", "pr", "xargs", "file", "sort", "man", "help", "netstat", "ps", "base64", "grep", "egrep", "fgrep", "rg", "ag", "ack",
  "sha256sum", "sha1sum", "md5sum", "tree", "date", "hostname", "which", "whereis", "locate", "lsof", "pgrep", "tput", "ss",
  "fd", "fdfind", "test", "[", "ls", "find", "echo", "printf", "cd", "pwd", "whoami", "alias", "jq", "awk", "uniq", "less", "more", ":",
  "docker ps", "docker images", "docker logs", "docker inspect",
  "git diff", "git log", "git show", "git shortlog", "git reflog", "git stash list", "git ls-remote", "git status", "git blame",
  "git ls-files", "git config --get", "git remote show", "git remote", "git merge-base", "git rev-parse", "git rev-list",
  "git describe", "git cat-file", "git for-each-ref", "git grep", "git stash show", "git worktree list", "git tag", "git branch",
  "gh pr view", "gh pr list", "gh pr diff", "gh pr checks", "gh issue view", "gh issue list", "gh repo view", "gh run list",
  "gh run view", "gh auth status", "gh pr status", "gh issue status", "gh release list", "gh release view", "gh workflow list",
  "gh workflow view", "gh label list", "gh search repos", "gh search issues", "gh search prs", "gh search commits", "gh search code",
]);

// WebFetch's preapproved hosts (host or host/path), fetched without a prompt in every mode.
const FETCH_HOSTS = Object.freeze([
  "platform.claude.com", "code.claude.com", "claude.dev", "www.claude.dev", "claude.com/docs", "modelcontextprotocol.io",
  "github.com/anthropics", "github.com/anthropic-experimental", "raw.githubusercontent.com/anthropics",
  "raw.githubusercontent.com/anthropic-experimental", "agentskills.io", "docs.python.org", "en.cppreference.com",
  "docs.oracle.com", "learn.microsoft.com", "developer.mozilla.org", "go.dev/doc", "go.dev/ref", "www.php.net",
  "docs.swift.org", "kotlinlang.org", "ruby-doc.org", "doc.rust-lang.org", "www.typescriptlang.org", "react.dev",
  "angular.io", "vuejs.org", "nextjs.org", "expressjs.com", "nodejs.org", "bun.sh", "jquery.com", "getbootstrap.com",
  "tailwindcss.com", "d3js.org", "threejs.org", "redux.js.org", "webpack.js.org", "jestjs.io", "reactrouter.com",
  "docs.djangoproject.com", "flask.palletsprojects.com", "fastapi.tiangolo.com", "pandas.pydata.org", "numpy.org",
  "www.tensorflow.org", "pytorch.org", "scikit-learn.org", "matplotlib.org", "requests.readthedocs.io", "jupyter.org",
  "laravel.com", "symfony.com", "wordpress.org/documentation", "docs.spring.io", "hibernate.org", "tomcat.apache.org",
  "gradle.org", "maven.apache.org", "asp.net", "dotnet.microsoft.com", "blazor.net", "reactnative.dev", "docs.flutter.dev",
  "developer.apple.com", "developer.android.com", "keras.io", "spark.apache.org", "huggingface.co/docs",
  "www.kaggle.com/docs", "www.mongodb.com", "redis.io", "www.postgresql.org", "dev.mysql.com", "www.sqlite.org",
  "graphql.org", "prisma.io", "docs.getdbt.com", "docs.aws.amazon.com", "cloud.google.com", "kubernetes.io",
  "www.docker.com", "www.terraform.io", "www.ansible.com", "vercel.com/docs", "docs.stripe.com", "docs.netlify.com",
  "devcenter.heroku.com", "dev.wix.com/docs", "cypress.io", "selenium.dev", "docs.unity.com", "docs.unrealengine.com",
  "git-scm.com", "nginx.org", "httpd.apache.org",
]);

/** What must hold in the managed settings for Claude Code's prompt to be the person's (kit.hostPromptAnswerer). */
export const PROMPT_ANSWERER_SPEC = Object.freeze({
  lockKey: "allowManagedHooksOnly",
  answerEvents: ["PermissionRequest"],
  pluginsKey: "enabledPlugins",
  pinned: [{ path: ["sandbox", "autoAllowBashIfSandboxed"], value: false }],
});

/**
 * The tools Claude Code's allow rules can name: with allowManagedPermissionRulesOnly
 * only the managed rules count, and their tool names are read here; without
 * it any settings file may add a rule for any tool ("*").
 */
function ruleToolsOf(docs) {
  const locked = docs.some((d) => d.doc?.allowManagedPermissionRulesOnly === true);
  if (!locked) {
    return { tools: ["*"], prefixes: [] };
  }
  const tools = new Set();
  const prefixes = new Set();
  for (const { doc } of docs) {
    const allow = doc?.permissions?.allow;
    for (const r of Array.isArray(allow) ? allow : []) {
      if (typeof r !== "string") {
        continue;
      }
      const name = r.replace(/\(.*$/s, "").trim();
      if (name === "" || name.includes("*")) {
        tools.add("*");
      } else if (name.startsWith("mcp__") && name.split("__").length === 2) {
        // A rule for a whole MCP server names every tool of it.
        tools.add(name);
        prefixes.add(`${name}__`);
      } else {
        tools.add(name);
      }
    }
  }
  return { tools: [...tools], prefixes: [...prefixes] };
}

/** Claude Code's self-approval data (kit HostSelfApproval) under these managed settings. */
export function claudeSelfApproval(docs) {
  const rules = ruleToolsOf(docs);
  return {
    personModes: [...PERSON_MODES],
    modeOrder: MODE_ORDER,
    // Reads in the working folders (every mode); skills, searches, subagents
    // and tools Enclawed Code does not know: assumed allowable in every mode.
    kinds: ["read", "search", "skill", "session", "agent", "unknown"],
    // File edits: allowed by Claude Code itself only in acceptEdits.
    otherModeKinds: ["fs-write"],
    shellPrefixes: [...SHELL_PREFIXES],
    shellDialects: ["powershell"],
    fetchHosts: [...FETCH_HOSTS],
    ruleTools: rules.tools,
    ruleToolPrefixes: rules.prefixes,
  };
}

/**
 * The kit's host-prompt guard for one Claude Code session of a managed
 * (launcher-less) install: grants and the hold in a directory of its own
 * under `stateRoot`, named by the session id.
 */
export function claudePromptGuard({ stateRoot, sessionId, docs, answerer }) {
  const dir = path.join(stateRoot, "host-prompt", createHash("sha256").update(String(sessionId ?? "")).digest("hex"));
  return {
    dir,
    quarantineDir: path.join(dir, "quarantine"),
    host: claudeSelfApproval(docs),
    promptAnswerer: answerer,
  };
}
