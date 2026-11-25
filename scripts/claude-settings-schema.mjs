#!/usr/bin/env node
// Reads Claude Code's own settings schema out of its binary (round 3, N9).
//
// Claude Code is a Bun single-file executable; its JavaScript, including the
// zod schema it validates settings files with, is embedded as text. This
// prints, for every settings key Enclawed Code accepts in a user's --settings
// (settings.mjs MERGEABLE_KEYS), the zod definition the binary carries, plus
// the nested schemas Enclawed Code checks (hook events, the command hook handler,
// the permission modes, sandbox network/filesystem), with the human-readable
// .describe(...) text removed. Enclawed Code's validator (settings.mjs) is derived
// from this output, and test/claude-settings.test.mjs compares it with the
// pinned copy in test/fixtures/claude-settings-schema-<version>.json, so a
// Claude Code release that changes one of these schemas is noticed.
//
//   node scripts/claude-settings-schema.mjs [path-to-claude]          print JSON
//   node scripts/claude-settings-schema.mjs [path] --write            write the fixture
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { MERGEABLE_KEYS } from "../src/settings.mjs";

/** Remove `.describe(<expr>)` calls, skipping string and template literals. */
export function stripDescribe(js) {
  let out = "";
  let i = 0;
  while (i < js.length) {
    const at = js.indexOf(".describe(", i);
    if (at < 0) {
      out += js.slice(i);
      break;
    }
    out += js.slice(i, at);
    let p = at + ".describe(".length;
    let depth = 1;
    while (p < js.length && depth > 0) {
      const c = js[p];
      if (c === '"' || c === "'" || c === "`") {
        p++;
        while (p < js.length && js[p] !== c) {
          p += js[p] === "\\" ? 2 : 1;
        }
      } else if (c === "(") {
        depth++;
      } else if (c === ")") {
        depth--;
      }
      p++;
    }
    i = p;
  }
  return out;
}

// The end of one `key:()=>…` thunk: the next top-level `,name:()=>`, or the
// close of the object, tracking brackets and string literals.
function thunkEnd(js, from) {
  let depth = 0;
  for (let p = from; p < js.length; p++) {
    const c = js[p];
    if (c === '"' || c === "'" || c === "`") {
      p++;
      while (p < js.length && js[p] !== c) {
        p += js[p] === "\\" ? 2 : 1;
      }
    } else if (c === "(" || c === "[" || c === "{") {
      depth++;
    } else if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) {
        return p;
      }
      depth--;
    } else if (c === "," && depth === 0) {
      return p;
    }
  }
  return js.length;
}

function slice(js, start, maxLen = 4000) {
  const end = thunkEnd(js, start);
  return stripDescribe(js.slice(start, Math.min(end, start + maxLen * 4))).slice(0, maxLen);
}

// Minified names change with every Claude Code release, so none is written
// here: each nested schema is found by following the references from the
// settings object's own keys (hooks, permissions, sandbox), and the found
// names are returned (`names`) for the hand-reviewed alias map.
const ID = "[$\\w]+";
const esc = (n) => n.replace(/\$/g, "\\$");

export function extractSchema(binaryPath) {
  const buf = fs.readFileSync(binaryPath);
  const m0 = /\$schema:\(\)=>([$\w]+)\(\)\.optional\(\)\.describe\("JSON Schema reference for Claude Code settings"\)/.exec(buf.toString("latin1", 0, buf.length));
  if (!m0) {
    throw new Error("the settings schema was not found in this binary");
  }
  const anchor = m0.index;
  // The settings schema and the helpers it names sit within this window.
  const from = Math.max(0, anchor - 600_000);
  const js = buf.subarray(from, anchor + 400_000).toString("latin1");
  const base = anchor - from; // the settings object's first key
  // Each key's definition: the first `key:()=>` at or after the object start.
  const keys = {};
  for (const k of [...MERGEABLE_KEYS].sort()) {
    const at = js.indexOf(`${k}:()=>`, base);
    keys[k] = at < 0 ? null : slice(js, at + k.length + 1);
  }
  // A lazily built definition `NAME=wrap(()=>...)`, or `function NAME(e){return ...` / `function NAME(){let e=...`.
  const lazy = (name, len = 2500) => {
    if (!name) {
      return null;
    }
    const m = new RegExp(`[ ,;]${esc(name)}=${ID}\\(\\(\\)=>`).exec(js);
    return m ? slice(js, m.index + m[0].length, len) : null;
  };
  const fn = (name, head, len) => {
    if (!name) {
      return null;
    }
    const m = new RegExp(`function ${esc(name)}\\(${head}`).exec(js);
    return m ? slice(js, m.index + m[0].length, len) : null;
  };
  const array = (name) => (name ? (new RegExp(`[ ,;]${esc(name)}=(\\[[^\\]]*\\])`).exec(js)?.[1] ?? null) : null);
  const ref = (text, re) => (text ? (re.exec(text)?.[1] ?? null) : null);
  // hooks: lazy(() => H()); H = record(enum(EVENTS), array(MATCHER())); MATCHER has hooks: array(HANDLERS());
  // HANDLERS destructures the command handler function's result.
  const hooksName = ref(keys.hooks, new RegExp(`^\\(\\)=>${ID}\\(\\(\\)=>(${ID})\\(\\)\\)$`));
  const hooksDef = lazy(hooksName);
  const eventsName = ref(hooksDef, new RegExp(`^${ID}\\(${ID}\\((${ID})\\),`));
  const matcherName = ref(hooksDef, new RegExp(`,${ID}\\((${ID})\\(\\)\\)\\)$`));
  const hookMatcher = lazy(matcherName);
  const handlersName = ref(hookMatcher, new RegExp(`hooks:${ID}\\((${ID})\\(\\)\\)`));
  const handlers = lazy(handlersName, 600);
  const commandName = ref(handlers, new RegExp(`\\}=(${ID})\\(\\);`));
  const commandHandler = fn(commandName, "\\)\\{let e=", 1500);
  const shellsName = ref(commandHandler, new RegExp(`shell:${ID}\\((${ID})\\)`));
  // permissions: lazy(() => P(e)); function P(e){return object({... defaultMode: ...enum([...MODES, ...
  const permName = ref(keys.permissions, new RegExp(`^\\(\\)=>${ID}\\(\\(\\)=>(${ID})\\(e\\)\\)$`));
  const permissions = fn(permName, "e\\)\\{return ", 2500);
  const modesName = ref(permissions, new RegExp(`\\[\\.\\.\\.(${ID}),`));
  // sandbox: lazy(() => S()); S has network: N(...) and filesystem: F(...).
  const sandboxName = ref(keys.sandbox, new RegExp(`^\\(\\)=>${ID}\\(\\(\\)=>(${ID})\\(\\)\\)$`));
  const sandbox = lazy(sandboxName, 3000);
  const networkName = ref(sandbox, new RegExp(`network:(${ID})\\(`));
  const filesystemName = ref(sandbox, new RegExp(`filesystem:(${ID})\\(`));
  const nested = {
    hookEvents: array(eventsName),
    permissionModes: array(modesName),
    hookShells: array(shellsName),
    hookMatcher,
    commandHandler,
    permissions,
    sandbox,
    sandboxNetwork: lazy(networkName, 1500),
    sandboxFilesystem: lazy(filesystemName, 1500),
  };
  const names = { string: m0[1], hooks: hooksName, hookEvents: eventsName, hookMatcher: matcherName, hookHandlers: handlersName, commandHandler: commandName, hookShells: shellsName, permissions: permName, permissionModes: modesName, sandbox: sandboxName, sandboxNetwork: networkName, sandboxFilesystem: filesystemName };
  return { keys, nested, all: allKeys(js, base), names };
}

/**
 * Every top-level key of the settings object (round 4, F2): the source of
 * the list of command-valued settings (settings-schema.mjs commandPaths).
 * Keys inside a conditional spread (`...flag&&{k:()=>...}`) are included.
 */
export function allKeys(js, base) {
  const out = {};
  const put = (seg) => {
    const m = /^([$\w]+):\(\)=>/.exec(seg);
    if (m) {
      out[m[1]] = stripDescribe(seg.slice(m[0].length - 4)).slice(0, 4000);
      return;
    }
    // A spread: its inner `name:()=>` entries.
    for (const inner of seg.matchAll(/[{,]([$\w]+):\(\)=>/g)) {
      const at = seg.indexOf(inner[0]) + 1;
      out[inner[1]] ??= slice(seg, at + inner[1].length + 1);
    }
  };
  let depth = 0;
  let start = base;
  for (let p = base; p < js.length; p++) {
    const c = js[p];
    if (c === '"' || c === "'" || c === "`") {
      p++;
      while (p < js.length && js[p] !== c) {
        p += js[p] === "\\" ? 2 : 1;
      }
    } else if (c === "(" || c === "[" || c === "{") {
      depth++;
    } else if (c === ")" || c === "]" || c === "}") {
      if (depth === 0) {
        put(js.slice(start, p));
        break;
      }
      depth--;
    } else if (c === "," && depth === 0) {
      put(js.slice(start, p));
      start = p + 1;
    }
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

export function claudeVersion(binaryPath) {
  const r = spawnSync(binaryPath, ["--version"], { encoding: "utf8", timeout: 30_000, env: { PATH: "/usr/bin:/bin", HOME: os.tmpdir() } });
  return /(\d+\.\d+\.\d+)/.exec(r.stdout ?? "")?.[1] ?? null;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const bin = fs.realpathSync(process.argv.slice(2).find((a) => !a.startsWith("--")) ?? path.join(os.homedir(), ".local", "bin", "claude"));
  const version = claudeVersion(bin);
  // The name maps (minified zod constructors and helper aliases) are kept
  // from the pinned copy: they are reviewed by hand for each release, and
  // test/claude-settings.test.mjs checks the result against the real binary.
  const prev = (() => {
    try {
      return JSON.parse(fs.readFileSync(new URL(`../test/fixtures/claude-settings-schema-${version}.json`, import.meta.url), "utf8"));
    } catch {
      return {};
    }
  })();
  const doc = { claudeCode: version, ...extractSchema(bin), ...(prev.zod ? { zod: prev.zod } : {}), ...(prev.aliases ? { aliases: prev.aliases } : {}) };
  const text = `${JSON.stringify(doc, null, 2)}\n`;
  if (process.argv.includes("--write")) {
    const out = new URL(`../test/fixtures/claude-settings-schema-${version}.json`, import.meta.url);
    fs.writeFileSync(out, text);
    // The runtime copy the validator is generated from (src/settings-schema.mjs).
    const runtime = new URL("../src/claude-settings-schema.json", import.meta.url);
    fs.writeFileSync(runtime, text);
    console.log(`wrote ${out.pathname} and ${runtime.pathname}`);
  } else {
    process.stdout.write(text);
  }
}
