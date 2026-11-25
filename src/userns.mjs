// N16 (round 5, found by the coordinator on the real device): inside an
// unprivileged user namespace (`unshare -r`, rootless containers) the uid is
// a mapped one, often 0. The framework's hardware-root broker socket is
// `<XDG_RUNTIME_DIR or tmp>/enclawed-<uid>/enclaweder.sock` with the uid of
// the process, so a process in such a namespace looks for a different broker
// than the host's, misses the real owner, opens /dev/hidraw* itself and
// becomes a second owner of the Enclaweder: the two owners' frames collide
// ("no response") and the latch goes DIRTY.
//
// Enclawed Code therefore refuses to touch the hardware root from a non-initial
// user namespace while an Enclaweder could be reached there: the launcher does
// not start, the hook denies, and the device commands stop. When that is the
// case is the kit's decision (userNamespaceDeviceRisk): "reached" is not
// "listed in sysfs" (red-team H11), and with every node masked (npm test
// binds /dev/null over /dev/hidraw*) nothing changes.

import fs from "node:fs";
import { kit } from "./kit.mjs";

/** The uid_map of this process, or null when it cannot be read (not Linux). */
function uidMap() {
  try {
    return fs.readFileSync("/proc/self/uid_map", "utf8").trim().split("\n").map((l) => l.trim().split(/\s+/).map(Number));
  } catch {
    return null;
  }
}

/** Is this process in a user namespace other than the initial one? */
export function inUserNamespace() {
  const m = uidMap();
  // The initial namespace maps every uid to itself: "0 0 4294967295".
  return m !== null && !(m.length === 1 && m[0][0] === 0 && m[0][1] === 0 && m[0][2] === 4294967295);
}

/** The host uid this process runs as, from its uid_map (null when unknown). */
export function hostUid() {
  const m = uidMap();
  const uid = process.getuid?.();
  if (m === null || typeof uid !== "number") {
    return typeof uid === "number" ? uid : null;
  }
  for (const [inside, outside, count] of m) {
    if (uid >= inside && uid < inside + count) {
      return outside + (uid - inside);
    }
  }
  return null;
}

/**
 * Why the hardware root must not be touched from here, or null: the kit's
 * decision (userNamespaceDeviceRisk: inside a non-initial user namespace,
 * refused whenever a device could be reached, by a reachable hidraw node, a
 * pinned ENCLAWEDER_HIDRAW or a listed device; nodes are stat'ed, never
 * opened). Enclawed Code adds how to run it instead.
 */
export function userNamespaceDeviceRisk() {
  const risk = kit.userNamespaceDeviceRisk({ pinnedHidraw: process.env.ENCLAWEDER_HIDRAW ?? null });
  return risk ? `${risk} (red-team round 5 N16, H11); run Enclawed Code outside the namespace` : null;
}
