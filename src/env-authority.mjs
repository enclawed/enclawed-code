// The framework's environment, decided once per process by Enclawed (adapter
// kit: `frameworkEnv`, `FRAMEWORK_ENV_ALLOW`, `resolveHardwareRootMode`,
// `shellFlavor`, `stricterFlavor`): which ENCLAWED_* and ENCLAWEDER_*
// variables reach the framework (in the launcher and the hook), the one strict
// ENCLAWEDER_ROOT parser, and the flavor the shell may only raise. This
// module keeps the names the rest of Enclawed Code imports.
//
// ENCLAWEDER_ROOT: unset, or exactly "required". "optional" is an admin-only
// device-retirement decision (opt-outs.mjs `hardwareRoot`), refused from the
// environment. A forensic webhook comes only from the root-owned opt-out file
// (opt-outs.mjs `forensicWebhook`).

import { kit } from "./kit.mjs";

export const HARDWARE_ROOT_MODES = Object.freeze(["required", "optional"]);

/**
 * The strict ENCLAWEDER_ROOT parser (the framework's), as a result.
 * @returns {{ ok: true, mode: "auto"|"required"|"optional" } | { ok: false, reason: string }}
 */
export function parseHardwareRootMode(value, { source = "ENCLAWEDER_ROOT" } = {}) {
  const v = value === undefined || value === null ? undefined : String(value);
  const r = kit.resolveHardwareRootMode({ ENCLAWEDER_ROOT: v });
  if (r.ok) {
    return r;
  }
  // "optional" parses; the kit refuses it from a shell because of where it
  // comes from. A session file or a managed --hardware-root may carry it.
  if (v === "optional") {
    return { ok: true, mode: "optional" };
  }
  return { ok: false, reason: `${source}=${JSON.stringify(v)} is not valid: it takes exactly "required" (or is unset)` };
}

/**
 * The hardware-root mode for this process: the shell's ENCLAWEDER_ROOT, the
 * admin grant (`hardwareRoot: "optional"`), strictest wins (kit).
 * @returns {{ ok: true, mode: "auto"|"required"|"optional" } | { ok: false, reason: string }}
 */
export function resolveHardwareRootMode(env, { granted = null } = {}) {
  return kit.resolveHardwareRootMode(env, { adminGrantedOptional: granted === "optional" });
}

export const FLAVORS = Object.freeze(["open", "enclaved"]);

/** The flavor the user's shell asks for: null when unset; every unknown value reads as "enclaved". */
export function shellFlavor(env) {
  return kit.shellFlavor(env);
}

/** The stricter of two flavors (null counts as open). */
export function stricterFlavor(a, b) {
  return kit.stricterFlavor(a, b);
}

/** The ENCLAWED_* / ENCLAWEDER_* variables that may reach the framework (kit). */
export const FRAMEWORK_ENV_ALLOW = kit.FRAMEWORK_ENV_ALLOW;

/**
 * A copy of `env` whose framework variables are only the allowlisted ones,
 * with the resolved hardware-root mode, flavor and forensic webhook (kit).
 *
 * `loaderGranted`: the administrator's loaderEnv grant; the kit removes every
 * other loader-injection variable. A caller that does not pass it (the
 * launcher today) scrubs them itself right after (launcher.mjs
 * scrubLoaderEnv, which reports what it removed), so they are passed through
 * here unchanged for that caller.
 * @returns {{ env: object, dropped: string[], loaderRemoved: string[] }}
 */
export function frameworkEnv(env, { hardwareRoot, flavor = null, forensicWebhook = null, loaderGranted = undefined }) {
  const granted = loaderGranted ?? Object.keys(env).filter((k) => kit.LOADER_INJECTION_ENV.includes(k));
  return kit.frameworkEnv(env, { hardwareRoot, flavor, forensicWebhook, loaderGranted: granted });
}

/** Replace process.env in place (the framework reads it directly). */
export function replaceEnvInPlace(target, next) {
  kit.replaceProcessEnv(next, target);
}
