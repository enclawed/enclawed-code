// The --settings validator, generated from Claude Code's own zod settings
// schema (red-team round 4, F1).
//
// Claude Code drops a whole settings file when one value in it fails its
// schema, Enclawed's hooks included. Round 3 checked a hand-written list of
// keys and types; round 4 found one it did not type-check (`$schema: 5`). So
// the validator is no longer written by hand: src/claude-settings-schema.json
// (the same document as test/fixtures/claude-settings-schema-<version>.json,
// read out of the claude binary by scripts/claude-settings-schema.mjs) holds
// the minified zod definition of every key Enclawed Code merges, and this module
// parses those definitions and checks values against them.
//
// The definitions are minified JavaScript (`o().optional()`, `C(o())`,
// `u({type:T("command"),command:o()})`). Two small maps in the same document
// give them meaning for this Claude Code release, reviewed by hand per
// release and checked against the real binary by test/claude-settings.test.mjs:
//   zod      the minified zod constructors (o = string, C = array, ...);
//   aliases  helper names used inside definitions, written in the same
//            minified syntax, where "@name" refers to a `nested` definition.
// Anything the parser does not recognize (an unknown helper, `.refine`, a
// method it does not know) becomes an UNCHECKABLE node, and a value for it is
// refused, unless a `.catch(...)` around it makes Claude Code replace a bad
// value instead of dropping the file. Objects are checked strictly: a key the
// schema does not define is refused (Claude Code would ignore it, but
// Enclawed Code only merges what it can vouch for).

import fs from "node:fs";

const SCHEMA_URL = new URL("./claude-settings-schema.json", import.meta.url);

/** The pinned schema document. */
export const SCHEMA = JSON.parse(fs.readFileSync(SCHEMA_URL, "utf8"));

// ---------------------------------------------------------------- parser

class ParseError extends Error {}

/**
 * Parse a minified zod expression into a node tree.
 * Nodes: { t: "string"|"boolean"|"number"|"array"|"object"|"literal"|"enum"|
 *   "union"|"record"|"fn"|"value"|"unchecked", ... } plus `optional` and
 *   `caught` flags and `checks` (method calls that constrain the value).
 */
export function parseSchema(text, doc = SCHEMA, depth = 0) {
  if (depth > 20) {
    throw new ParseError("alias nesting too deep");
  }
  const p = new Parser(text, doc, depth);
  const node = p.expr();
  p.ws();
  if (p.i < p.s.length) {
    throw new ParseError(`unexpected ${JSON.stringify(p.s.slice(p.i, p.i + 20))}`);
  }
  return node;
}

class Parser {
  constructor(s, doc, depth) {
    this.s = s;
    this.i = 0;
    this.doc = doc;
    this.depth = depth;
  }
  ws() {
    while (this.i < this.s.length && /\s/.test(this.s[this.i])) {
      this.i++;
    }
  }
  peek(t) {
    this.ws();
    return this.s.startsWith(t, this.i);
  }
  eat(t) {
    if (!this.peek(t)) {
      throw new ParseError(`expected ${t} at ${JSON.stringify(this.s.slice(this.i, this.i + 20))}`);
    }
    this.i += t.length;
  }
  ident() {
    this.ws();
    const m = /^[$@\w]+/.exec(this.s.slice(this.i, this.i + 200));
    if (!m) {
      throw new ParseError(`expected a name at ${JSON.stringify(this.s.slice(this.i, this.i + 20))}`);
    }
    this.i += m[0].length;
    return m[0];
  }
  // Skip one opaque JavaScript expression (an arrow function body): to the
  // next , ) ] } at depth 0, over strings, template literals and brackets.
  skipExpr() {
    let d = 0;
    for (; this.i < this.s.length; this.i++) {
      const c = this.s[this.i];
      if (c === '"' || c === "'" || c === "`") {
        this.i++;
        while (this.i < this.s.length && this.s[this.i] !== c) {
          this.i += this.s[this.i] === "\\" ? 2 : 1;
        }
      } else if (c === "(" || c === "[" || c === "{") {
        d++;
      } else if (c === ")" || c === "]" || c === "}") {
        if (d === 0) {
          return;
        }
        d--;
      } else if (c === "," && d === 0) {
        return;
      }
    }
  }
  string() {
    this.ws();
    const q = this.s[this.i];
    let j = this.i + 1;
    let out = "";
    while (j < this.s.length && this.s[j] !== q) {
      if (this.s[j] === "\\") {
        out += JSON.parse(`"${this.s.slice(j, j + 2)}"`);
        j += 2;
      } else {
        out += this.s[j++];
      }
    }
    this.i = j + 1;
    return out;
  }
  // An arrow function `(a,b)=>body` or `x=>body`, if one starts here.
  arrowAhead() {
    this.ws();
    const m = /^(\([\w,\s]*\)|[a-zA-Z_$][\w$]*)\s*=>/.exec(this.s.slice(this.i, this.i + 100));
    return m ? m[0].length : 0;
  }
  primary() {
    this.ws();
    const c = this.s[this.i];
    const arrow = this.arrowAhead();
    if (arrow) {
      const head = this.s.slice(this.i, this.i + arrow);
      this.i += arrow;
      // A thunk `()=>expr` whose body is a schema: parse it. Anything else is
      // an opaque function (a transform or preprocess step).
      if (/^\(\s*\)/.test(head) && !this.peek("{")) {
        const save = this.i;
        try {
          return { t: "thunk", body: this.expr() };
        } catch {
          this.i = save;
        }
      }
      this.skipExpr();
      return { t: "fn" };
    }
    if (c === '"' || c === "'") {
      return { t: "value", v: this.string() };
    }
    if (c === "[") {
      this.i++;
      const items = [];
      while (!this.peek("]")) {
        if (this.peek("...")) {
          this.i += 3;
          items.push({ spread: this.postfix(this.primary()) });
        } else {
          items.push(this.expr());
        }
        if (this.peek(",")) {
          this.i++;
        }
      }
      this.eat("]");
      return { t: "list", items };
    }
    if (c === "{") {
      this.i++;
      const props = {};
      while (!this.peek("}")) {
        let key;
        if (this.peek('"') || this.peek("'")) {
          key = this.string();
        } else {
          key = this.ident();
        }
        this.eat(":");
        props[key] = this.expr();
        if (this.peek(",")) {
          this.i++;
        }
      }
      this.eat("}");
      return { t: "props", props };
    }
    if (/[0-9-]/.test(c)) {
      const m = /^-?[0-9.e+]+/.exec(this.s.slice(this.i, this.i + 40));
      this.i += m[0].length;
      return { t: "value", v: Number(m[0]) };
    }
    if (this.s.startsWith("void 0", this.i)) {
      this.i += 6;
      return { t: "value", v: undefined };
    }
    if (this.s.startsWith("!0", this.i) || this.s.startsWith("!1", this.i)) {
      const v = this.s[this.i + 1] === "0";
      this.i += 2;
      return { t: "value", v };
    }
    const name = this.ident();
    if (name.startsWith("@")) {
      return this.nested(name.slice(1));
    }
    let args = null;
    if (this.peek("(")) {
      this.i++;
      args = [];
      while (!this.peek(")")) {
        args.push(this.expr());
        if (this.peek(",")) {
          this.i++;
        }
      }
      this.eat(")");
    }
    return this.call(name, args);
  }
  nested(name) {
    const text = this.doc.nested?.[name];
    if (typeof text !== "string") {
      return { t: "unchecked", why: `no nested definition ${name}` };
    }
    return parseSchema(text, this.doc, this.depth + 1);
  }
  call(name, args) {
    const zod = this.doc.zod?.[name];
    // A minified name is per module: the same name can be a zod constructor in one
    // definition and a helper in another (Claude Code 2.1.331: `ue` is z.lazy in
    // `env`, and the onFailure helper in the command hook). A constructor that
    // needs an argument, called with none, is the helper.
    const helper = zod && (args ?? []).length === 0 && ARG_KINDS.has(zod) && typeof this.doc.aliases?.[name] === "string";
    if (zod && !helper) {
      return zodNode(zod, args ?? []);
    }
    const alias = this.doc.aliases?.[name];
    if (typeof alias === "string") {
      // The alias stands for the helper's result; its arguments are scope
      // values (a plugin mode list, say) the alias already accounts for.
      return parseSchema(alias, this.doc, this.depth + 1);
    }
    return { t: "unchecked", why: `unknown helper ${name}` };
  }
  postfix(node) {
    for (;;) {
      this.ws();
      if (this.s[this.i] !== "." || this.s.startsWith("...", this.i)) {
        return node;
      }
      this.i++;
      const m = this.ident();
      const args = [];
      if (this.peek("(")) {
        this.i++;
        while (!this.peek(")")) {
          args.push(this.expr());
          if (this.peek(",")) {
            this.i++;
          }
        }
        this.eat(")");
      }
      node = method(node, m, args);
    }
  }
  expr() {
    return this.postfix(this.primary());
  }
}

// Zod constructors that are never called without an argument.
const ARG_KINDS = new Set(["array", "object", "literal", "enum", "union", "record", "lazy", "preprocess"]);

const lazyBody = (n) => (n?.t === "thunk" ? n.body : n);

function listValues(n) {
  if (n?.t !== "list") {
    return null;
  }
  const out = [];
  for (const it of n.items) {
    if (it.spread) {
      const inner = listValues(it.spread);
      if (inner === null) {
        return null;
      }
      out.push(...inner);
    } else if (it.t === "value") {
      out.push(it.v);
    } else {
      return null;
    }
  }
  return out;
}

function zodNode(kind, args) {
  switch (kind) {
    case "string":
    case "boolean":
    case "number":
      return { t: kind, checks: [] };
    case "array":
      return { t: "array", of: schemaArg(args[0]) };
    case "object": {
      if (args[0]?.t !== "props") {
        return { t: "unchecked", why: "object without a shape" };
      }
      const shape = {};
      for (const [k, v] of Object.entries(args[0].props)) {
        shape[k] = schemaArg(v);
      }
      return { t: "object", shape };
    }
    case "literal":
      return args[0]?.t === "value" ? { t: "literal", v: args[0].v } : { t: "unchecked", why: "literal of an expression" };
    case "enum": {
      const values = listValues(args[0]);
      return values ? { t: "enum", values } : { t: "unchecked", why: "enum of unknown values" };
    }
    case "union": {
      const branches = args[0]?.t === "list" ? args[0].items.map(schemaArg) : null;
      return branches ? { t: "union", of: branches } : { t: "unchecked", why: "union of an expression" };
    }
    case "record":
      return { t: "record", key: schemaArg(args[0]), value: schemaArg(args[1]) };
    case "lazy":
      return schemaArg(lazyBody(args[0]));
    case "preprocess":
      // z.preprocess(fn, schema): Enclawed Code checks the schema without the
      // function, which can only make it stricter.
      return schemaArg(args[1]);
    default:
      return { t: "unchecked", why: `zod ${kind}` };
  }
}

// A schema argument: a thunk's body, or the node itself.
function schemaArg(n) {
  const b = lazyBody(n);
  if (!b || b.t === "value" || b.t === "list" || b.t === "props" || b.t === "fn") {
    return { t: "unchecked", why: "not a schema" };
  }
  return b;
}

const NUMBER_CHECKS = new Set(["int", "positive", "nonnegative", "min", "max", "gt", "gte", "lt", "lte"]);
const STRING_CHECKS = new Set(["min", "max", "startsWith"]);

function method(node, m, args) {
  const n = { ...node, checks: node.checks ? [...node.checks] : undefined };
  switch (m) {
    case "optional":
      n.optional = true;
      return n;
    case "catch":
      // A failing value is replaced, the file still loads.
      n.caught = true;
      return n;
    case "passthrough":
    case "describe":
    case "meta":
    case "transform":
      return n;
    case "or":
      return { t: "union", of: [node, schemaArg(args[0])] };
    default:
      break;
  }
  const arg = args[0]?.t === "value" ? args[0].v : undefined;
  if (node.t === "number" && NUMBER_CHECKS.has(m)) {
    n.checks.push([m, arg]);
    return n;
  }
  if (node.t === "string" && STRING_CHECKS.has(m) && (arg !== undefined || m === "startsWith")) {
    n.checks.push([m, arg]);
    return n;
  }
  // .refine, .superRefine, .url, .regex, ...: a rule Enclawed Code cannot run.
  return { t: "unchecked", why: `.${m}()`, optional: node.optional, caught: node.caught };
}

// ---------------------------------------------------------------- validator

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const show = (v) => (JSON.stringify(v) ?? String(v)).slice(0, 40);

function numberOk(v, checks) {
  if (typeof v !== "number" || !Number.isFinite(v)) {
    return checks.some(([m]) => m === "int") ? "an integer" : "a finite number";
  }
  for (const [m, a] of checks) {
    const ok =
      m === "int" ? Number.isSafeInteger(v) : m === "positive" ? v > 0 : m === "nonnegative" ? v >= 0 : m === "min" || m === "gte" ? v >= a : m === "max" || m === "lte" ? v <= a : m === "gt" ? v > a : m === "lt" ? v < a : false;
    if (!ok) {
      return { int: "an integer", positive: "a number above 0", nonnegative: "a number of at least 0" }[m] ?? `a number with ${m}(${a})`;
    }
  }
  return null;
}

function stringOk(v, checks) {
  if (typeof v !== "string") {
    return "a string";
  }
  for (const [m, a] of checks) {
    const ok = m === "min" ? v.length >= a : m === "max" ? v.length <= a : m === "startsWith" ? v.startsWith(a) : false;
    if (!ok) {
      return `a string with ${m}(${JSON.stringify(a)})`;
    }
  }
  return null;
}

/** Problems with `value` at `at` (an empty list: Claude Code loads it). */
export function check(node, value, at, problems = []) {
  if (node.caught) {
    return problems; // Claude Code replaces a failing value; the file loads
  }
  const bad = (want) => problems.push(`${at} must be ${want} (Claude Code ${SCHEMA.claudeCode} drops the whole file otherwise), not ${show(value)}`);
  switch (node.t) {
    case "string": {
      const w = stringOk(value, node.checks);
      if (w) {
        bad(w);
      }
      break;
    }
    case "number": {
      const w = numberOk(value, node.checks);
      if (w) {
        bad(w);
      }
      break;
    }
    case "boolean":
      if (typeof value !== "boolean") {
        bad("true or false");
      }
      break;
    case "literal":
      if (value !== node.v) {
        bad(JSON.stringify(node.v));
      }
      break;
    case "enum":
      if (!node.values.includes(value)) {
        bad(`one of ${node.values.map((x) => JSON.stringify(x)).join(", ")}`);
      }
      break;
    case "array":
      if (!Array.isArray(value)) {
        bad("an array");
      } else {
        value.forEach((x, i) => check(node.of, x, `${at}[${i}]`, problems));
      }
      break;
    case "object":
      if (!isObj(value)) {
        bad("an object");
        break;
      }
      for (const [k, x] of Object.entries(value)) {
        const sub = Object.hasOwn(node.shape, k) ? node.shape[k] : null;
        if (!sub) {
          problems.push(`${at}.${k} is not a key Claude Code ${SCHEMA.claudeCode} defines here, so Enclawed Code cannot check it before merging`);
        } else {
          check(sub, x, `${at}.${k}`, problems);
        }
      }
      for (const [k, sub] of Object.entries(node.shape)) {
        if (value[k] === undefined && !sub.optional && !sub.caught && sub.t !== "unchecked") {
          problems.push(`${at}.${k} is required`);
        }
      }
      break;
    case "record":
      if (!isObj(value)) {
        bad("an object");
        break;
      }
      for (const [k, x] of Object.entries(value)) {
        check(node.key, k, `${at} key ${JSON.stringify(k)}`, problems);
        check(node.value, x, `${at}.${k}`, problems);
      }
      break;
    case "union": {
      const ok = node.of.some((b) => check(b, value, at, []).length === 0);
      if (!ok) {
        bad("a value of one of the accepted forms");
      }
      break;
    }
    default:
      problems.push(`${at}: Enclawed Code cannot check this value against Claude Code's schema (${node.why ?? node.t}); put it in .claude/settings.local.json or ~/.claude/settings.json instead`);
  }
  return problems;
}

let compiled = null;
/** The parsed top-level key schemas: key -> node. */
export function keySchemas() {
  if (!compiled) {
    compiled = new Map();
    for (const [k, text] of Object.entries(SCHEMA.keys)) {
      let node;
      try {
        node = schemaArg(parseSchema(text));
      } catch (err) {
        node = { t: "unchecked", why: `unparsed (${err.message})` };
      }
      compiled.set(k, node);
    }
  }
  return compiled;
}

/** Every key Enclawed Code merges from a user's --settings: the pinned schema's keys. */
export const SCHEMA_KEYS = new Set(Object.keys(SCHEMA.keys));

/** Check a whole --settings document; an empty list means Claude Code loads it. */
export function validateAgainstSchema(doc) {
  const problems = [];
  const schemas = keySchemas();
  for (const [k, v] of Object.entries(doc)) {
    const node = schemas.get(k);
    if (!node) {
      problems.push(`${k} is not a key Enclawed Code can check before merging (put it in .claude/settings.local.json or ~/.claude/settings.json)`);
      continue;
    }
    check(node, v, k, problems);
  }
  return problems;
}

// ---------------------------------------------------------------- command-valued settings (F2)

// A string setting named like a program to run (apiKeyHelper, awsAuthRefresh,
// awsCredentialExport, gcpAuthRefresh, otelHeadersHelper, proxyAuthHelper,
// processWrapper, policyHelper(s), sshHostCommands, ...).
const COMMAND_NAME = /(Helpers?|Refresh|Export|Wrapper|Commands?)$/;

/**
 * Every settings path whose value makes Claude Code run a command, derived
 * from the pinned schema (`all`, every top-level key, and `nested`): keys
 * named like a helper program, and every object in a key's definition that
 * has a `command` field (statusLine, subagentStatusLine, fileSuggestion,
 * sandbox.ripgrep, ...). `hooks` is handled on its own (session.mjs).
 * @returns {string[]} dotted paths, sorted
 */
export function commandPaths(doc = SCHEMA) {
  const out = new Set();
  const walk = (node, at) => {
    if (!node || typeof node !== "object") {
      return;
    }
    if (node.t === "object") {
      if (Object.hasOwn(node.shape, "command")) {
        out.add(at);
      }
      for (const [k, sub] of Object.entries(node.shape)) {
        walk(sub, `${at}.${k}`);
      }
    } else if (node.t === "union") {
      node.of.forEach((b) => walk(b, at));
    } else if (node.t === "array") {
      walk(node.of, at);
    }
  };
  for (const [k, text] of Object.entries(doc.all ?? doc.keys)) {
    if (k === "hooks") {
      continue;
    }
    let node = null;
    try {
      node = schemaArg(parseSchema(text, doc));
    } catch {
      // Not parseable here: fall back to the text.
      if (COMMAND_NAME.test(k) || /[{,]command:/.test(text)) {
        out.add(k);
      }
      continue;
    }
    // A helper-named key counts unless its value cannot hold a command line
    // (a boolean such as respondToBashCommands, a number, a fixed enum).
    if (COMMAND_NAME.test(k) && !["boolean", "number", "enum", "literal"].includes(node.t)) {
      out.add(k);
    }
    walk(node, k);
  }
  return [...out].sort();
}
