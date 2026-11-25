import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// On a managed install plain `claude` cannot sign in or use a stored login,
// while an Enclawed Code session still reaches Claude through its relay
// (src/managed-login.mjs over the kit's managed-login-policy.ts).
// Attack side: another managed document that admits an organization or
// re-points the login directory, a login directory a user can write, a policy
// file that is not root's: not in force; install without root changes
// nothing; with the REAL Claude Code 2.1.326 in a private namespace (its own
// /etc, an isolated HOME holding a planted plaintext login, a stand-in
// provider) plain claude, a user's environment or --settings pointing it back
// at the stored login, an attacker's own tunnel, and a completed `claude auth
// login` never send or store a login, and no session answers.
// False-positive side: the control (no policy) uses the planted login, proving
// the stand-in sees what claude sends; install is idempotent and reversible;
// an Enclawed Code session under the policy answers through the relay.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, afterEach, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { setTestAuthority } from "../src/authority.mjs";
import { kit } from "../src/kit.mjs";
import { loginPolicyCommand, loginPolicyFile, loginPolicySpec, managedLoginPolicyStatus } from "../src/managed-login.mjs";
import { sandbox } from "./helpers.mjs";

const sink = () => {
  const o = { text: "", write: (s) => ((o.text += s), true) };
  return o;
};
let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());
afterEach(() => setTestAuthority(null));

function managedWorld() {
  const dir = fs.mkdtempSync(path.join(sb.dir, "managed-"));
  fs.chmodSync(dir, 0o755);
  setTestAuthority({ managedSettingsDir: dir, trustedUids: sb.authority.trustedUids, ignoreUserNamespace: true });
  return dir;
}
const cmd = async (args, uid = 0) => {
  const out = sink();
  const err = sink();
  const code = await loginPolicyCommand(args, { out, err, uid, platform: "linux" });
  return { code, out: out.text, err: err.text };
};

test("install (root): prints what it writes, puts the policy in force, is idempotent and reversible; without root nothing changes", async () => {
  const dir = managedWorld();
  const spec = loginPolicySpec(dir);
  const p = await cmd(["print"]);
  assert.equal(p.code, 0);
  assert.match(p.out, /create directory .*enclawed-code-no-login \(owner root, mode 0555, stays empty\)/);
  assert.match(p.out, /"forceLoginOrgUUID": \[\]/);
  assert.match(p.out, /"CLAUDE_SECURESTORAGE_CONFIG_DIR": ".*enclawed-code-no-login"/);
  assert.match(p.out, /"DISABLE_LOGIN_COMMAND": "1"/);
  assert.equal(fs.existsSync(loginPolicyFile(dir)), false);
  const user = await cmd(["install"], 1000);
  assert.equal(user.code, 1);
  assert.match(user.err, /only root can: run it with sudo/);
  assert.equal(fs.existsSync(loginPolicyFile(dir)), false);
  assert.equal(managedLoginPolicyStatus(dir).installed, false);
  const i = await cmd(["install"]);
  assert.equal(i.code, 0, i.err);
  assert.equal(i.out.split("installed\n")[0], p.out);
  assert.deepEqual(JSON.parse(fs.readFileSync(loginPolicyFile(dir), "utf8")), { forceLoginOrgUUID: [], env: { CLAUDE_SECURESTORAGE_CONFIG_DIR: spec.storageDir, DISABLE_LOGIN_COMMAND: "1" } });
  assert.equal(fs.statSync(loginPolicyFile(dir)).mode & 0o777, 0o644);
  assert.equal(fs.statSync(spec.storageDir).mode & 0o777, 0o555);
  assert.equal(managedLoginPolicyStatus(dir).installed, true);
  assert.equal((await cmd(["status"])).code, 0);
  const again = await cmd(["install"]);
  assert.equal(again.code, 0);
  assert.match(again.out, /already installed; nothing changed/);
  const r = await cmd(["remove"]);
  assert.equal(r.code, 0);
  assert.equal(fs.existsSync(loginPolicyFile(dir)), false);
  assert.equal(fs.existsSync(spec.storageDir), false);
  assert.equal((await cmd(["status"])).code, 1);
});

test("attack: what would make the policy not hold is reported as not in force", async () => {
  const dir = managedWorld();
  assert.equal((await cmd(["install"])).code, 0);
  const spec = loginPolicySpec(dir);
  const main = path.join(dir, "managed-settings.json");
  fs.writeFileSync(main, JSON.stringify({ forceLoginOrgUUID: ["22222222-2222-4222-8222-222222222222"] }));
  assert.equal(managedLoginPolicyStatus(dir).code, "org-pin-widened");
  fs.writeFileSync(main, JSON.stringify({ env: { CLAUDE_SECURESTORAGE_CONFIG_DIR: "/home/someone/.claude" } }));
  assert.equal(managedLoginPolicyStatus(dir).code, "env-pin-overridden");
  fs.writeFileSync(main, "{ not json");
  assert.equal(managedLoginPolicyStatus(dir).code, "invalid-document");
  fs.rmSync(main);
  assert.equal(managedLoginPolicyStatus(dir).installed, true);
  fs.chmodSync(spec.storageDir, 0o777);
  assert.equal(managedLoginPolicyStatus(dir).code, "storage-dir-unsafe");
  fs.chmodSync(spec.storageDir, 0o555);
  fs.chmodSync(loginPolicyFile(dir), 0o666);
  assert.equal(managedLoginPolicyStatus(dir).code, "policy-file-untrusted");
  fs.chmodSync(loginPolicyFile(dir), 0o644);
  // A changed file is not removed by `remove` (only what install wrote).
  fs.writeFileSync(loginPolicyFile(dir), "{}");
  assert.equal((await cmd(["remove"])).code, 1);
  assert.equal(fs.existsSync(loginPolicyFile(dir)), true);
  // Outside the suite's stand-in for root, a file owned by this user is not root's.
  setTestAuthority({ managedSettingsDir: dir, trustedUids: [4242], ignoreUserNamespace: true });
  assert.equal(kit.adminOnlyEmptyDirProblem(spec.storageDir, [4242]) !== null, true);
});

// ------------------------------------------------------------ the real Claude Code
// The benchmark pin, from the account that runs the suite (read and run only; never its ~/.claude).
const CLAUDE = path.join(process.env.HOME ?? os.homedir(), ".local", "share", "claude", "versions", "2.1.326");
const DRIVER = fileURLToPath(new URL("./fixtures/managed-login-driver.mjs", import.meta.url));

test("the real Claude Code 2.1.326 under the managed policy: plain claude cannot authenticate, an Enclawed Code session can", { timeout: 600_000 }, (t) => {
  if (!fs.existsSync(CLAUDE)) {
    t.skip(`Claude Code 2.1.326 is not installed at ${CLAUDE}`);
    return;
  }
  const work = fs.mkdtempSync(path.join(sb.dir, "real-"));
  for (const d of ["up", "work", "run"]) {
    fs.mkdirSync(path.join(work, d));
  }
  const hosts = path.join(work, "hosts");
  fs.writeFileSync(hosts, `${fs.readFileSync("/etc/hosts", "utf8")}\n127.0.0.1 api.anthropic.com platform.claude.com claude.ai claude.com statsig.anthropic.com mcp-proxy.anthropic.com\n`);
  // A private mount and network namespace inside the suite's: this namespace's own /etc (an overlay), loopback only.
  const script = [
    "ip link set lo up",
    `mount -t overlay overlay -o lowerdir=/etc,upperdir=${work}/up,workdir=${work}/work /etc`,
    `mount --bind ${hosts} /etc/hosts`,
    "mkdir -p /etc/claude-code",
    `exec '${process.execPath}' '${DRIVER}' '${CLAUDE}' '${work}/run'`,
  ].join(" && ");
  const r = spawnSync("unshare", ["-m", "-n", "sh", "-c", script], { encoding: "utf8", timeout: 590_000, env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", HOME: path.join(work, "nohome") } });
  if (r.status !== 0 && /unshare|overlay|Operation not permitted/.test(r.stderr)) {
    t.skip(`no private namespace with an /etc overlay here: ${r.stderr.trim().split("\n")[0]}`);
    return;
  }
  assert.equal(r.status, 0, r.stderr);
  const res = JSON.parse(r.stdout.trim().split("\n").pop());
  const runs = res.runs;
  // Control: the stand-in sees the planted login and claude answers (the test can see what claude sends).
  assert.equal(runs.control.answered, true, JSON.stringify(runs.control));
  assert.ok(runs.control.plantedSent > 0);
  // The admin command, run for real against this namespace's /etc/claude-code.
  assert.equal(res.install.code, 0, res.install.err);
  assert.equal(res.reinstall.code, 0);
  assert.equal(res.status.installed, true, res.status.reason);
  assert.equal(res.notRoot, 1);
  // Plain claude and the ways around it: never answered, the planted login never sent, no new login stored.
  for (const name of ["plain", "storage-override", "settings-override", "attacker-tunnel", "auth-login"]) {
    const x = runs[name];
    assert.equal(x.answered, false, `${name}: ${JSON.stringify(x)}`);
    assert.equal(x.plantedSent, 0, `${name}: the planted login was sent: ${JSON.stringify(x)}`);
    assert.equal(x.newLoginStored, false, `${name}: a new login was stored`);
    assert.notEqual(x.code, 0, `${name}: exited 0`);
  }
  assert.match(runs.plain.err, /forceLoginOrgUUID in managed settings is set to an empty array/);
  assert.equal(runs["auth-login"].pasted, true, "the sign-in was completed (code pasted)");
  // An Enclawed Code session under the same policy: the first launch sealed the planted login, claude holds only the placeholder, the relay adds the login.
  assert.equal(res.sessionOpen.ok, true, res.sessionOpen.message);
  assert.equal(res.sessionOpen.action, "relayed");
  assert.equal(res.sessionOpen.sealedNow, true);
  assert.equal(res.plaintextLeft, false);
  assert.equal(res.sessionEnvHasReal, false);
  assert.equal(runs.session.answered, true, JSON.stringify(runs.session));
  assert.ok(runs.session.viaRelayWithReal > 0);
});
