// The single place this app loads Enclawed: the public `enclawed/framework`
// entry point of the open core (https://github.com/enclawed/enclawed-oss).
// Nothing else in the app imports Enclawed, and nothing here reaches past the
// public entry point.
//
// `npm run build:framework` builds the framework entry of the enclawed-oss
// submodule (or ENCLAWED_OSS_DIR, or ../enclawed-oss) into ./.enclawed-dev/.
// That directory lives inside the app's own install, so it is exactly as
// trusted as the app's code; Enclawed Code protects it from the agent like the
// app's own code (see session.mjs protectedPaths).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REQUIRED = [
  "AuditLogger",
  "adapterKit",
  "containment",
  "assertSecondFactor",
  "enrollPasskey",
  "enrollSecurityKey",
  "removeSecurityKey",
  "revokeUnlockTicket",
  "secondFactorStatus",
  "unlockForHeadlessStart",
  "CAPABILITY",
  "HistoryStore",
  "RootHaltError",
  "bootHardwareRoot",
  "brokerDisabled",
  "brokerSocketPath",
  "connectRoot",
  "checkHardwareRootForToolCall",
  "closeHardwareRootSession",
  "createPolicy",
  "defaultEnclavedPolicy",
  "defaultOpenPolicy",
  "dlpRedact",
  "getFlavor",
  "hardwareRootInfo",
  "loadPolicyFromJson",
  "prepareFsWriteHistory",
  "recoverHardwareRootStandalone",
  "resolveDefaultConfigPath",
  "resolveHistoryDir",
  "restoreSnapshot",
  "setRuntime",
  "verifyHistory",
];

// Where the framework comes from, in this order:
//   1. a development build of the enclawed-oss git submodule (vendor/enclawed-oss),
//      made by `npm run build:framework` into ./.enclawed-dev/ (a git checkout);
//   2. the `enclawed` npm package this package depends on, at the exact version
//      package.json pins (an npm install): its public `enclawed/framework` entry.
// Either way the entry's directory is measured with Enclawed Code's own code
// (commitments.mjs) and the package is protected from the agent (session.mjs).
const devEntry = new URL("../.enclawed-dev/framework/framework.js", import.meta.url);

/** The npm package's framework entry, or null when `enclawed` is not installed. */
function packageEntry() {
  try {
    return fileURLToPath(import.meta.resolve("enclawed/framework"));
  } catch {
    return null;
  }
}

const devPath = fileURLToPath(devEntry);
const pkgPath = fs.existsSync(devPath) ? null : packageEntry();

export const FRAMEWORK_ENTRY = pkgPath ?? devPath;
/** "dev" (.enclawed-dev) or "package" (the enclawed npm dependency). */
export const FRAMEWORK_SOURCE = pkgPath ? "package" : "dev";
/**
 * The installed enclawed package's root and the node_modules directory that
 * holds it and its dependencies (null for a development build).
 */
export const FRAMEWORK_PACKAGE = pkgPath ? frameworkPackageDirs(pkgPath) : null;

function frameworkPackageDirs(entry) {
  for (let d = path.dirname(entry); d !== path.dirname(d); d = path.dirname(d)) {
    try {
      if (JSON.parse(fs.readFileSync(path.join(d, "package.json"), "utf8")).name === "enclawed") {
        const root = fs.realpathSync(d);
        const parent = path.dirname(root);
        return { root, nodeModules: path.basename(parent) === "node_modules" ? parent : null };
      }
    } catch {
      /* keep looking */
    }
  }
  return null;
}

/**
 * The framework files an npm install loads: the entry and every module it
 * reaches through a relative static or literal dynamic import, sorted. The
 * package's dist directory holds the whole product (thousands of chunks); the
 * framework is this closure, the same set a development build writes into
 * .enclawed-dev/framework. A specifier that names no file (text in a bundled
 * string that only looks like an import) is skipped: such a module could not
 * be loaded at all, so nothing unmeasured runs from it.
 */
export function frameworkImportClosure(entry = FRAMEWORK_ENTRY) {
  const base = path.dirname(entry);
  const seen = new Set();
  const queue = [path.resolve(entry)];
  const spec = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}\/[^"']+)["']/g;
  while (queue.length > 0) {
    const file = queue.pop();
    if (seen.has(file)) {
      continue;
    }
    seen.add(file);
    for (const m of fs.readFileSync(file, "utf8").matchAll(spec)) {
      const target = path.resolve(path.dirname(file), m[1]);
      if (fs.existsSync(target) && fs.statSync(target).isFile()) {
        queue.push(target);
      }
    }
  }
  return [...seen].map((f) => path.relative(base, f).split(path.sep).join("/")).sort();
}

export const BUILD_HINT =
  "install Enclawed Code from npm (its enclawed dependency is the framework), or in a git checkout build it with: git submodule update --init vendor/enclawed-oss && (cd vendor/enclawed-oss && pnpm install) && npm run build:framework";

let loaded = null;

/** Load the framework once. Throws, naming what is missing, if it is absent or too old. */
export async function loadFramework() {
  if (loaded) {
    return loaded;
  }
  if (!fs.existsSync(FRAMEWORK_ENTRY)) {
    throw new Error(`the Enclawed framework is not built (${FRAMEWORK_ENTRY} is missing); ${BUILD_HINT}`);
  }
  const mod = await import(pathToFileURL(FRAMEWORK_ENTRY).href);
  const missing = REQUIRED.filter((name) => !(name in mod));
  if (missing.length > 0) {
    throw new Error(
      `the built enclawed framework does not export ${missing.join(", ")}; the enclawed-oss submodule is older than Enclawed Code: ` +
        "git submodule update --remote vendor/enclawed-oss, then rebuild (npm run build:framework)",
    );
  }
  loaded = { fw: mod, source: FRAMEWORK_ENTRY };
  return loaded;
}
