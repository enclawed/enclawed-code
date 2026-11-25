// Small helpers shared by Enclawed Code's own commands.

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline/promises";

export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = "UsageError";
  }
}

/**
 * Parse `args` strictly: every option must be listed; options may come
 * before, between or after positionals; a value option needs a value that is
 * not itself an option.
 *
 * @param {string[]} args
 * @param {{ bool?: string[], value?: string[], multi?: string[], maxPositionals?: number }} spec
 * @returns {{ positionals: string[], flags: Record<string, any> }}
 */
export function parseFlags(args, { bool = [], value = [], multi = [], maxPositionals = Infinity } = {}) {
  const flags = {};
  const positionals = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (!a.startsWith("--")) {
      positionals.push(a);
      continue;
    }
    const eq = a.indexOf("=");
    const name = eq < 0 ? a : a.slice(0, eq);
    const inline = eq < 0 ? undefined : a.slice(eq + 1);
    if (bool.includes(name)) {
      if (inline !== undefined) {
        throw new UsageError(`${name} takes no value`);
      }
      flags[name] = true;
    } else if (value.includes(name) || multi.includes(name)) {
      let v = inline;
      if (v === undefined) {
        v = args[i + 1];
        if (v === undefined || v.startsWith("--")) {
          throw new UsageError(`${name} needs a value`);
        }
        i++;
      }
      if (v === "") {
        throw new UsageError(`${name} needs a non-empty value`);
      }
      if (multi.includes(name)) {
        (flags[name] ??= []).push(v);
      } else {
        flags[name] = v;
      }
    } else {
      throw new UsageError(`unknown option ${name}`);
    }
  }
  if (positionals.length > maxPositionals) {
    throw new UsageError(`unexpected argument ${positionals[maxPositionals]}`);
  }
  return { positionals, flags };
}

export function positiveInt(v, name) {
  if (!/^\d+$/.test(String(v)) || Number(v) <= 0) {
    throw new UsageError(`${name} must be a positive whole number, not ${v}`);
  }
  return Number(v);
}

/** Write a file atomically with mode 0600 (its directory 0700). */
export function writeFileAtomic(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(tmp, text, { mode: 0o600, flag: "wx" });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}

export const isInteractive = () => Boolean(process.stdin.isTTY && process.stdout.isTTY);

/** Ask a question on the terminal. */
export async function ask(question, { def = "" } = {}) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const a = (await rl.question(def ? `${question} [${def}] ` : `${question} `)).trim();
    return a === "" ? def : a;
  } finally {
    rl.close();
  }
}

export async function askYesNo(question, def = false) {
  const a = (await ask(`${question} (y/n)`, { def: def ? "y" : "n" })).toLowerCase();
  return a === "y" || a === "yes";
}
