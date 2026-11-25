// Every test file imports this first. A test run outside scripts/test.mjs's
// isolation namespace (for example `node --test test/adversarial.test.mjs` run
// directly) once held a real Enclaweder attached to the host. So each test file refuses
// to run unless the KERNEL says no Enclaweder can be reached: a non-initial
// user namespace (/proc/self/uid_map), an empty /sys/class/hidraw, and every
// /dev/hidraw* node masked by /dev/null. Never read from the environment: an
// exported variable cannot turn this off. Run the suite with `npm test`.
import fs from "node:fs";

function isolationProblem() {
  if (process.platform !== "linux") {
    return null; // no hidraw nodes; the framework's own test-runner guard applies
  }
  try {
    if (/^0\s+0\s+4294967295$/.test(fs.readFileSync("/proc/self/uid_map", "utf8").trim())) {
      return "this process is in the initial user namespace";
    }
  } catch {
    return "/proc/self/uid_map is unreadable";
  }
  let listed = [];
  try {
    listed = fs.readdirSync("/sys/class/hidraw");
  } catch {
    listed = [];
  }
  if (listed.length > 0) {
    return `/sys/class/hidraw lists ${listed.join(", ")}`;
  }
  const nul = fs.statSync("/dev/null").rdev;
  let nodes = [];
  try {
    nodes = fs.readdirSync("/dev").filter((n) => /^hidraw\d+$/.test(n));
  } catch {
    nodes = [];
  }
  for (const n of nodes) {
    try {
      const st = fs.statSync(`/dev/${n}`);
      if (st.isCharacterDevice() && st.rdev !== nul) {
        return `/dev/${n} is a reachable device node`;
      }
    } catch {
      /* gone */
    }
  }
  return null;
}

const problem = isolationProblem();
if (problem) {
  process.stderr.write(`refusing to run tests outside the isolation namespace (${problem}): run them with \`npm test\` (scripts/test.mjs)\n`);
  process.exit(3);
}
