#!/usr/bin/env node
// The environment variables a Claude Code binary reads, each with its class
// (src/claude-env.mjs), pinned in test/fixtures/claude-env-names-<version>.json.
//
// Claude Code is a Bun single-file executable whose JavaScript is embedded as
// text. The names are every `process.env.NAME` / `process.env["NAME"]` read,
// every quoted all-caps name with a prefix Claude Code or its SDKs read
// (ANTHROPIC_, CLAUDE_, AWS_, GOOGLE_, OTEL_, NODE_, ...), and every name in
// Claude Code's own lists of sensitive variables (the provider, proxy,
// certificate, credential and settings-source lists it strips from remote
// settings, and its loader-injection list). test/claude-env.test.mjs checks
// that each pinned name still classifies the same way, and that every name of
// Claude Code's own sensitive lists is refused from a repository.
//
//   node scripts/claude-env-names.mjs [path-to-claude]          print JSON
//   node scripts/claude-env-names.mjs [path] --write            write the fixture
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { classifyEnv } from "../src/claude-env.mjs";
import { claudeVersion } from "./claude-settings-schema.mjs";

const PREFIXES =
  /^(ANTHROPIC_|_?CLAUDE_|CLAUDECODE|AWS_|AZURE_|GOOGLE_|GCLOUD_|GCE_|CLOUDSDK_|CLOUD_ML_|VERTEX_|OTEL_|NODE_|BUN_|HTTPS?_PROXY$|ALL_PROXY$|NO_PROXY$|SSL_CERT|LD_|DYLD_|GIT_|GH_|MCP_|DISABLE_|ENABLE_|BASH_|MAX_|SANDBOX_|USE_)/;
// Quoted constants with an env-like prefix that are not variables.
const NOT_ENV = /^(SSL_OP_|HTTP_PARSER|NODE_API_MODULE|NODE_[A-Z0-9_]+_CONFIG_OPTIONS$|MCP_REQUIRED|CLAUDE_AI_PROJECTS_)/;
// Where Claude Code keeps its own sensitive-variable lists (see the header).
const SENSITIVE_ANCHORS = ['var yc=new Set([...Hao', 'var ye=["LD_PRELOAD"', 'var he=["CLAUDE_CODE_MANAGED_SETTINGS_PATH"'];
const SENSITIVE_LISTS = /(?:^|[,\s;(])(?:Hao|TR|O4|iZt|aZt|QLt|BU|l|o|Dao|Drs|SFe|Oao|ye|he)=\[([^\]]*)\]/g;

export function extractEnvNames(binaryPath) {
  const js = fs.readFileSync(binaryPath).toString("latin1");
  const names = new Set();
  for (const m of js.matchAll(/process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[["']([A-Za-z_][A-Za-z0-9_]*)["']\])/g)) {
    names.add(m[1] ?? m[2]);
  }
  for (const m of js.matchAll(/["'`](_?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)["'`]/g)) {
    if (PREFIXES.test(m[1]) && !NOT_ENV.test(m[1])) {
      names.add(m[1]);
    }
  }
  const sensitive = new Set();
  for (const a of SENSITIVE_ANCHORS) {
    const at = js.indexOf(a);
    if (at < 0) {
      throw new Error(`Claude Code's sensitive-variable list ${a} was not found in this binary`);
    }
  }
  // The lists are defined near the anchors; read every definition in the binary.
  for (const m of js.matchAll(SENSITIVE_LISTS)) {
    const body = m[1];
    if (!/"[A-Z_]+_(URL|PROXY|KEY|TOKEN|CERTS?|PATH|DIR|REGION|PROJECT|PROFILE|FILE|ID|HOST|SOCKET|PRELOAD|OPTIONS|ENV|BEDROCK|VERTEX|FOUNDRY|MANTLE|GATEWAY)"/.test(body)) {
      continue;
    }
    for (const n of body.matchAll(/"(_?[A-Z][A-Z0-9_]{2,})"/g)) {
      sensitive.add(n[1]);
      names.add(n[1]);
    }
  }
  const table = {};
  for (const n of [...names].sort()) {
    table[n] = classifyEnv(n).class;
  }
  return { names: table, claudeSensitive: [...sensitive].sort() };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const bin = fs.realpathSync(process.argv.slice(2).find((a) => !a.startsWith("--")) ?? path.join(os.homedir(), ".local", "bin", "claude"));
  const version = claudeVersion(bin);
  const doc = { claudeCode: version, ...extractEnvNames(bin) };
  const text = `${JSON.stringify(doc, null, 2)}\n`;
  if (process.argv.includes("--write")) {
    fs.writeFileSync(new URL(`../test/fixtures/claude-env-names-${version}.json`, import.meta.url), text);
  } else {
    process.stdout.write(text);
  }
}
