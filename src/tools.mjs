// Claude Code's tool table: each tool name mapped onto the kit's action kind
// (enclawed-oss adapter/types.ts ActionKind), the input fields that name its
// targets, and its policy ids. This table is Claude Code data; what each kind
// of action needs (history, a person, an allowlist) is decided by Enclawed's
// adapter kit (kit.decidePreAction), never here.

import { kit } from "./kit.mjs";

/** Whether a file configures what runs later (the kit's list: git, agent CLI, editor, package and build settings). */
export const isExecConfigPath = (absPath) => kit.isExecConfigPath(absPath);

/** @typedef {"read"|"fetch"|"search"|"session"|"agent"|"fs-write"|"shell"|"mcp"|"skill"|"unknown"} ActionKind */

const READ_TOOLS = new Set(["Read", "Glob", "Grep", "LS", "NotebookRead", "ToolSearch", "BashOutput", "LSP"]);

const SESSION_TOOLS = new Set([
  "TodoWrite",
  "TaskCreate",
  "TaskGet",
  "TaskList",
  "TaskUpdate",
  "TaskOutput",
  "AskUserQuestion",
  "ExitPlanMode",
  "EnterPlanMode",
  "SubagentHandback",
]);

const AGENT_TOOLS = new Set(["Agent", "Task"]);

const FS_WRITE_TOOLS = {
  Write: { op: "write", fields: ["file_path"] },
  Edit: { op: "edit", fields: ["file_path"] },
  MultiEdit: { op: "edit", fields: ["file_path"] },
  NotebookEdit: { op: "edit", fields: ["notebook_path", "file_path"] },
};

/** The kit's action kind for a Claude Code tool. */
export function toolKind(name) {
  if (typeof name !== "string" || name.length === 0) {
    return "unknown";
  }
  if (name.startsWith("mcp__")) {
    return "mcp";
  }
  if (name === "WebFetch") {
    return "fetch";
  }
  if (name === "WebSearch") {
    return "search";
  }
  if (name === "Skill") {
    return "skill";
  }
  if (READ_TOOLS.has(name)) {
    return "read";
  }
  if (SESSION_TOOLS.has(name)) {
    return "session";
  }
  if (AGENT_TOOLS.has(name)) {
    return "agent";
  }
  if (Object.hasOwn(FS_WRITE_TOOLS, name)) {
    return "fs-write";
  }
  if (name === "Bash" || name === "Monitor" || name === "PowerShell") {
    return "shell";
  }
  return "unknown";
}

/** The shell dialect of a shell tool. */
export function shellDialect(name) {
  return name === "PowerShell" ? "powershell" : "posix";
}

export function fsWriteSpec(name) {
  return Object.hasOwn(FS_WRITE_TOOLS, name) ? FS_WRITE_TOOLS[name] : null;
}

const GATEWAY_ALIASES = {
  Read: ["read"],
  Write: ["write"],
  Edit: ["edit"],
  MultiEdit: ["edit"],
  NotebookEdit: ["edit"],
  Bash: ["exec"],
  Monitor: ["exec"],
  PowerShell: ["exec"],
  WebFetch: ["web_fetch"],
  WebSearch: ["web_search"],
  Agent: ["subagents"],
  Task: ["subagents"],
};

/**
 * The ids a policy list may use for this tool: the Claude Code name,
 * lowercased (the policy loader lowercases every id), plus the matching
 * gateway tool id when there is one.
 */
export function policyIds(name) {
  const own = String(name).trim().toLowerCase();
  return [own, ...(GATEWAY_ALIASES[name] ?? [])];
}

/**
 * Claude Code's MCP tool name, mcp__<server>__<tool>, split into the
 * server and tool in Claude Code's normalized spelling (the kit's McpSession
 * compares in that spelling). Null when the name does not have that form.
 */
export function mcpNameOf(name) {
  const m = /^mcp__(.+?)__(.+)$/.exec(typeof name === "string" ? name : "");
  return m ? { server: m[1], tool: m[2] } : null;
}

/**
 * The files a Claude Code read or search tool reads, as the kit's read
 * targets (`recursive` for a search below a directory), and the arguments
 * Claude Code passes to its search program as data (Grep's pattern goes
 * after -e, so it may begin with "-").
 */
export function readTargetsOf(tool, ti, cwd) {
  const reads = [];
  // Glob lists names that match; it reads no content (listOnly).
  const listOnly = tool === "Glob";
  const add = (p, recursive = false) => {
    if (typeof p === "string" && p !== "") {
      reads.push({ path: p, ...(recursive ? { recursive: true } : {}), ...(listOnly ? { listOnly: true } : {}) });
    }
  };
  switch (tool) {
    case "Read":
      add(ti.file_path);
      break;
    case "NotebookRead":
      add(ti.notebook_path ?? ti.file_path);
      break;
    case "LS":
      add(ti.path);
      break;
    case "Grep":
      // No path: Claude Code searches the working directory.
      add(typeof ti.path === "string" && ti.path !== "" ? ti.path : cwd, true);
      break;
    case "Glob": {
      const base = typeof ti.path === "string" && ti.path !== "" ? ti.path : cwd;
      add(base, true);
      // The pattern itself, resolved under the base (the kit matches a glob
      // against the secret and credential paths: ~/.claude/.cred* names the login).
      if (typeof ti.pattern === "string" && ti.pattern !== "") {
        add(/^(\/|~|\$HOME|\$\{HOME\})/.test(ti.pattern) ? ti.pattern : `${base.replace(/\/+$/, "")}/${ti.pattern}`, true);
      }
      break;
    }
    default:
      break;
  }
  return { reads, literalParams: tool === "Grep" ? ["pattern"] : [] };
}
