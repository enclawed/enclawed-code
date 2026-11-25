// The skill formal-verification pipeline (the framework's proof-carrying
// skill bundle, Methods A/B/C, paper section 8). The verifier the kit's skill
// admission uses is the framework's own (kit.frameworkFormal, from the built
// framework this app loads through kit.mjs). Method A alone (`static`) is
// loaded from the enclawed-oss submodule inside this app's install, which
// Enclawed Code protects from the agent like its own code (session.mjs
// protectedPaths), only to show a skill's effects before signing; whether a
// skill is signed or admitted is decided by the kit (skills.mjs).

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { kit } from "./kit.mjs";
import { APP_ROOT } from "./paths.mjs";

export const FORMAL_DIR = path.join(APP_ROOT, "vendor", "enclawed-oss", "enclawed", "src");

let loaded = null;

/** The kit's FormalVerifier (produce/read/verify/write a bundle), plus `static.methodA` for previews. */
export async function loadFormal() {
  if (loaded) {
    return loaded;
  }
  const file = path.join(FORMAL_DIR, "skill-formal-static.mjs");
  if (!fs.existsSync(file)) {
    throw new Error(`the Enclawed skill analyzer is missing (${file}); git submodule update --init vendor/enclawed-oss`);
  }
  const stat = await import(pathToFileURL(file).href);
  if (typeof stat.methodA !== "function") {
    throw new Error(`the Enclawed skill analyzer in ${FORMAL_DIR} does not export methodA; update the enclawed-oss submodule`);
  }
  loaded = { ...kit.frameworkFormal, static: stat };
  return loaded;
}
