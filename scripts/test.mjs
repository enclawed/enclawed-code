#!/usr/bin/env node
// `npm test`: run the unit suite where no Enclaweder can be reached.
//
// Unit tests use simulated devices only; a real Enclaweder attached to this
// machine must never be bound, challenged or latched by a test, and the
// machine's real broker socket and session bus must not be reachable either.
// On Linux the suite therefore always runs in a private user and mount
// namespace (`unshare -r -m`) in which /sys/class/hidraw is an empty tmpfs,
// every /dev/hidraw* node is bind-mounted over by /dev/null (so nothing can
// open the device even by path, round 5 N16), and /run/user is an empty tmpfs.
//
// "Already isolated" is read from the kernel, never from the environment
// (red-team H14 T1: a caller-exported ECWCODE_TEST_NO_DEVICE=1 used to turn
// the hiding off): a non-initial user namespace (/proc/self/uid_map), an empty
// /sys/class/hidraw, and every hidraw node masked by /dev/null. If the
// namespace cannot be made while a device could be reached, the suite refuses.
// The framework itself also refuses a real device under node --test unless
// ENCLAWEDER_LIVE_DEVICE_TEST=I_UNDERSTAND, which is stripped here.
import { spawnSync } from "node:child_process";
import fs from "node:fs";

const files = fs.readdirSync(new URL("../test/", import.meta.url)).filter((f) => f.endsWith(".test.mjs")).map((f) => `test/${f}`).sort();
const testArgs = ["--test", "--test-concurrency=1", ...process.argv.slice(2), ...(process.argv.slice(2).some((a) => a.endsWith(".mjs")) ? [] : files)];

function hidrawNodes() {
  try {
    return fs.readdirSync("/dev").filter((n) => /^hidraw\d+$/.test(n)).map((n) => `/dev/${n}`);
  } catch {
    return [];
  }
}

function sysfsListed() {
  try {
    return fs.readdirSync("/sys/class/hidraw");
  } catch {
    return [];
  }
}

/** Every hidraw node here is the /dev/null mask (or not a character device at all). */
function nodesMasked() {
  const nul = fs.statSync("/dev/null").rdev;
  return hidrawNodes().every((p) => {
    try {
      const st = fs.statSync(p);
      return !st.isCharacterDevice() || st.rdev === nul;
    } catch {
      return true;
    }
  });
}

function inUserNamespace() {
  try {
    return !/^0\s+0\s+4294967295$/.test(fs.readFileSync("/proc/self/uid_map", "utf8").trim());
  } catch {
    return false;
  }
}

/** The child's environment: no host runtime dir or session bus, and no live-device opt-in. */
function childEnv() {
  const env = { ...process.env };
  delete env.XDG_RUNTIME_DIR;
  delete env.DBUS_SESSION_BUS_ADDRESS;
  delete env.ENCLAWEDER_LIVE_DEVICE_TEST;
  return env;
}

if (process.platform !== "linux" || (inUserNamespace() && sysfsListed().length === 0 && nodesMasked())) {
  const r = spawnSync(process.execPath, testArgs, { stdio: "inherit", env: childEnv() });
  process.exit(r.status ?? 1);
}

const quoted = [process.execPath, ...testArgs].map((a) => `'${a.replaceAll("'", `'\\''`)}'`).join(" ");
const script =
  "mount -t tmpfs none /sys/class/hidraw" +
  ' && for d in /dev/hidraw*; do if [ -e "$d" ]; then mount --bind /dev/null "$d" || exit 32; fi; done' +
  " && { [ ! -d /run/user ] || mount -t tmpfs none /run/user; }" +
  ` && exec ${quoted}`;
const r = spawnSync("unshare", ["-r", "-m", "sh", "-c", script], { stdio: "inherit", env: childEnv() });
if (r.error || r.status === 32 || r.status === null) {
  if (sysfsListed().length > 0 || !nodesMasked()) {
    console.error("test: an Enclaweder could be reached and could not be hidden from the tests (unshare -r -m failed); detach it or run in a container");
    process.exit(1);
  }
  console.error("test: warning: no private namespace (unshare -r -m failed); no Enclaweder is reachable here, running anyway");
  const d = spawnSync(process.execPath, testArgs, { stdio: "inherit", env: childEnv() });
  process.exit(d.status ?? 1);
}
process.exit(r.status ?? 1);
