// What the audit log records about a tool call's input and result: enough to
// reconcile what ran against what was decided, without storing file content
// or secrets. Which fields of each Claude Code tool are recorded is
// Enclawed Code's (presentation); how a value is recorded is Enclawed's: free
// text capped and DLP-redacted, or omitted when it cannot be redacted
// (kit.auditText), content only as its SHA-256 and size (kit.auditDigest).

import { createHash } from "node:crypto";
import { kit } from "./kit.mjs";

/** SHA-256 of a string or Buffer (hex). */
export function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

// `_fw` is kept in the signatures for callers that pass the framework.
const text = (_fw, value, max) => kit.auditText(value, max);
const digest = (value) => kit.auditDigest(value);

export function summarizeInput(fw, tool, ti = {}) {
  switch (tool) {
    case "Bash":
    case "Monitor":
    case "PowerShell":
      return {
        command: text(fw, ti.command),
        description: text(fw, ti.description, 200),
        runInBackground: ti.run_in_background === true,
      };
    case "Write":
      return { filePath: ti.file_path ?? null, content: digest(ti.content ?? "") };
    case "Edit":
    case "MultiEdit":
      return {
        filePath: ti.file_path ?? null,
        oldString: digest(ti.old_string ?? ""),
        newString: digest(ti.new_string ?? ""),
        replaceAll: ti.replace_all === true,
        ...(Array.isArray(ti.edits) ? { edits: ti.edits.length } : {}),
      };
    case "NotebookEdit":
      return { filePath: ti.notebook_path ?? ti.file_path ?? null, input: digest(ti) };
    case "Read":
      return { filePath: ti.file_path ?? null, offset: ti.offset ?? null, limit: ti.limit ?? null };
    case "Glob":
    case "Grep":
      return { pattern: text(fw, ti.pattern, 500), path: ti.path ?? null };
    case "WebFetch":
      return { url: text(fw, ti.url, 1000) };
    case "WebSearch":
      return { query: text(fw, ti.query, 500) };
    case "Agent":
    case "Task":
      return {
        subagentType: ti.subagent_type ?? null,
        description: text(fw, ti.description, 200),
        prompt: digest(ti.prompt ?? ""),
      };
    default:
      return { keys: Object.keys(ti).sort(), input: digest(ti) };
  }
}

export function summarizeResponse(fw, tool, response) {
  const out = { ...digest(response) };
  if (response && typeof response === "object" && !Array.isArray(response)) {
    if (typeof response.stdout === "string") {
      out.stdout = text(fw, response.stdout, 500);
    }
    if (typeof response.stderr === "string") {
      out.stderr = text(fw, response.stderr, 500);
    }
    if (typeof response.interrupted === "boolean") {
      out.interrupted = response.interrupted;
    }
    if (typeof response.filePath === "string") {
      out.filePath = response.filePath;
    }
  } else if (typeof response === "string") {
    out.text = text(fw, response, 500);
  }
  return out;
}
