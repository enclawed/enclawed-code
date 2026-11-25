import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// The REAL Claude Code (the reviewed release version, 2.1.331) with an Anthropic
// API key sealed under a stand-in Enclaweder (src/claude-login.mjs): claude
// holds only the relay's placeholder and answers through the relay, which adds
// the key as x-api-key; a subscription token sealed where the key belongs is
// never relayed. Runs in a private mount and network namespace inside the
// suite's, with a stand-in provider on 127.0.0.1 and an isolated HOME (never
// the account's ~/.claude).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { sandbox } from "./helpers.mjs";

let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());

// The release's Claude Code, from the account that runs the suite (read and run only).
const CLAUDE = path.join(process.env.HOME ?? os.homedir(), ".local", "share", "claude", "versions", "2.1.331");
const DRIVER = fileURLToPath(new URL("./fixtures/api-key-relay-driver.mjs", import.meta.url));

test("the real Claude Code 2.1.331 with a sealed API key answers through the relay (x-api-key, placeholder only in claude); a subscription token sealed in its place is never relayed", { timeout: 600_000 }, (t) => {
  if (!fs.existsSync(CLAUDE)) {
    t.skip(`Claude Code 2.1.331 is not installed at ${CLAUDE}`);
    return;
  }
  const work = fs.mkdtempSync(path.join(sb.dir, "real-"));
  fs.mkdirSync(path.join(work, "run"));
  const hosts = path.join(work, "hosts");
  fs.writeFileSync(hosts, `${fs.readFileSync("/etc/hosts", "utf8")}\n127.0.0.1 api.anthropic.com platform.claude.com claude.ai claude.com statsig.anthropic.com mcp-proxy.anthropic.com\n`);
  const script = ["ip link set lo up", `mount --bind ${hosts} /etc/hosts`, `exec '${process.execPath}' '${DRIVER}' '${CLAUDE}' '${work}/run'`].join(" && ");
  const r = spawnSync("unshare", ["-m", "-n", "sh", "-c", script], { encoding: "utf8", timeout: 590_000, env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", HOME: path.join(work, "nohome"), TMPDIR: process.env.TMPDIR ?? "/var/tmp" } });
  if (r.status !== 0 && /unshare|Operation not permitted/.test(r.stderr)) {
    t.skip(`no private namespace here: ${r.stderr.trim().split("\n")[0]}`);
    return;
  }
  assert.equal(r.status, 0, r.stderr);
  const res = JSON.parse(r.stdout.trim().split("\n").pop());
  assert.equal(res.seal, 0);
  assert.deepEqual(res.open, { ok: true, action: "relayed", message: null });
  assert.equal(res.envHasKey, false, "claude's environment holds the key");
  assert.equal(res.session.answered, true, JSON.stringify(res.session));
  assert.ok(res.session.messagesWithKey > 0, JSON.stringify(res.session));
  assert.equal(res.session.keySeenOutsideMessages, 0, "the key went to a route other than Messages");
  assert.equal(res.planted.ok, false);
  assert.equal(res.planted.code, "not-an-api-key");
  assert.equal(res.planted.tokenSent, false);
});
