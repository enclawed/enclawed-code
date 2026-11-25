// Conformance guarantees of the root takeover (session-state.mjs, login-seal.mjs): run through
// Enclawed Code's own mapping of Claude Code's state onto the kit, in a throwaway home with stand-in
// boxes (the boxes a launch derives with KEY_DERIVE; the device itself is not needed to seal, and
// the stand-in only takes its place for opening).

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { auditLogPath } from "./paths.mjs";
import { openSessionState } from "./session-state.mjs";

const box = (fw, purpose, open = true) => {
  const b = fw.adapterKit.sealBoxFromSeed(createHash("sha256").update(`conformance-${purpose}`).digest(), `device:conformance:box:${purpose}`);
  if (!open) {
    b.close();
  }
  return b;
};

/** Every byte of every regular file under `dir`, never following a link. */
function bytesUnder(dir) {
  let out = "";
  const walk = (p) => {
    let st;
    try {
      st = fs.lstatSync(p);
    } catch {
      return;
    }
    if (st.isDirectory()) {
      for (const n of fs.readdirSync(p)) {
        walk(path.join(p, n));
      }
    } else if (st.isFile()) {
      out += fs.readFileSync(p, "latin1");
    }
  };
  walk(dir);
  return out;
}

async function withHome(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cn-conf-state-"));
  const home = path.join(root, "home");
  const runtime = path.join(root, "run");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  fs.mkdirSync(runtime, { mode: 0o700 });
  fs.writeFileSync(path.join(home, ".claude", "settings.json"), "{}\n");
  fs.writeFileSync(path.join(home, ".gitconfig"), "[credential]\n\thelper = store\n");
  const env = { HOME: home, ENCLAWED_STATE_DIR: path.join(home, ".enclawed"), XDG_RUNTIME_DIR: runtime, PATH: process.env.PATH };
  fs.mkdirSync(path.dirname(auditLogPath(env)), { recursive: true });
  const audit = async (r) => fs.appendFileSync(auditLogPath(env), `${JSON.stringify(r)}\n`);
  try {
    return await run({ home, env, audit, root });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

const boxesOf = (fw, open = true) => ({ context: box(fw, "context", open), tools: box(fw, "tools", open) });

/** One governed session: the transcript, a memory file and tool logins made inside it. */
async function session(fw, { env, audit }, secret) {
  const s = await openSessionState({ env, cwd: env.HOME, boxes: boxesOf(fw), audit });
  if (!s.ok || s.action !== "sealed") {
    throw new Error(`the session's state did not open: ${JSON.stringify(s)}`);
  }
  const e = s.applyEnv({ ...env, DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/bus" });
  const cfg = e.CLAUDE_CONFIG_DIR;
  fs.mkdirSync(path.join(cfg, "projects", "-proj", "memory"), { recursive: true });
  fs.writeFileSync(path.join(cfg, "projects", "-proj", "s.jsonl"), `{"text":"${secret}-transcript"}\n`);
  fs.writeFileSync(path.join(cfg, "projects", "-proj", "memory", "MEMORY.md"), `${secret}-memory\n`);
  fs.mkdirSync(e.GH_CONFIG_DIR, { recursive: true });
  fs.writeFileSync(path.join(e.GH_CONFIG_DIR, "hosts.yml"), `github.com:\n  oauth_token: gho_${secret}\n`);
  const git = spawnSync("git", ["credential", "approve"], { env: e, input: `protocol=https\nhost=example.com\nusername=a\npassword=git-${secret}\n\n`, encoding: "utf8" });
  if (git.status !== 0) {
    throw new Error(`git credential approve failed: ${git.stderr}`);
  }
  // A tool that ignores its variable and writes the person's own file anyway.
  fs.appendFileSync(path.join(env.HOME, ".npmrc"), `//registry.npmjs.org/:_authToken=npm_${secret}\n`);
  if (e.DBUS_SESSION_BUS_ADDRESS !== undefined) {
    throw new Error("the keyring's bus is in the session's environment");
  }
  const end = await s.close();
  if (!end.ok) {
    throw new Error(`the session's state was not sealed and erased: ${JSON.stringify(end)}`);
  }
  return { cfg, toolDir: s.toolDir };
}

export function sessionStateChecks(fw) {
  return [
    {
      id: "adapter:claude-code:no-plaintext-at-rest-between-sessions",
      title: "claude-code: between sessions, no plaintext session context of the person exists at rest",
      proves:
        "through Enclawed Code's session-state mapping, the transcript and memory a governed session wrote are sealed at its end: nothing of them is plaintext under the home directory, Enclawed's state or the runtime directory, Claude Code's own directory (what plain `claude`, `claude -c` or `--resume` reads) holds no context, a launch without the device's opening key opens nothing, a store changed outside the audit record is refused, and the next activated launch gets the context back",
      remedy: "Enclawed Code's launcher must point claude at the session's private config directory opened by openSessionState, seal it with close() at the end and at a halt, and forget the launch's keys after the start",
      run: () =>
        withHome(async (h) => {
          const secret = randomBytes(8).toString("hex");
          await session(fw, h, secret);
          const rest = bytesUnder(h.root);
          if (rest.includes(`${secret}-transcript`) || rest.includes(`${secret}-memory`)) {
            throw new Error("the session's context is plaintext at rest after the session");
          }
          if (fs.existsSync(path.join(h.home, ".claude", "projects"))) {
            throw new Error("plain claude finds session context in its own directory");
          }
          // No opening key (the launcher after its start, or root without an activation): nothing opens.
          const closed = await openSessionState({ env: h.env, cwd: h.home, boxes: boxesOf(fw, false), audit: h.audit });
          if (closed.ok) {
            throw new Error("the sealed context opened without the device's opening key");
          }
          // The next activated launch resumes it.
          const next = await openSessionState({ env: h.env, cwd: h.home, boxes: boxesOf(fw), audit: h.audit });
          const cfg = next.ok && next.applyEnv(h.env).CLAUDE_CONFIG_DIR;
          if (!cfg || !fs.readFileSync(path.join(cfg, "projects", "-proj", "s.jsonl"), "utf8").includes(secret)) {
            throw new Error("the next activated launch did not get the session's context back");
          }
          await next.close();
          // A record removed outside the audit record: refused, not resumed.
          const store = path.join(h.env.ENCLAWED_STATE_DIR, "claude-code", "context", "sealed");
          const blob = fs.readdirSync(store).find((n) => n.endsWith(".ctx"));
          fs.rmSync(path.join(store, blob));
          const tampered = await openSessionState({ env: h.env, cwd: h.home, boxes: boxesOf(fw), audit: h.audit });
          if (tampered.ok) {
            throw new Error("a sealed context changed outside the audit record was opened");
          }
        }),
    },
    {
      id: "adapter:claude-code:session-credentials-stay-in-session",
      title: "claude-code: a credential created inside an Enclawed Code session is not usable by any process outside one",
      proves:
        "through Enclawed Code's session-state mapping, a gh login, a git credential and an npm token made inside a governed session (one of them written into the person's own ~/.npmrc by a tool that ignores its variable) are nowhere in plaintext once the session ends: not in the person's tool configuration, not in Enclawed's state, not in the runtime directory; the person's own configuration is untouched; the next activated launch gets them back",
      remedy: "Enclawed Code's launcher must apply the kit's tool redirection (toolCredentialEnv) to claude's environment and run the floor sweep and the seal at the end of every session",
      run: () =>
        withHome(async (h) => {
          fs.writeFileSync(path.join(h.home, ".npmrc"), "registry=https://registry.npmjs.org/\n");
          const secret = randomBytes(8).toString("hex");
          await session(fw, h, secret);
          const rest = bytesUnder(h.root);
          for (const v of [`gho_${secret}`, `git-${secret}`, `npm_${secret}`]) {
            if (rest.includes(v)) {
              throw new Error(`a credential made in the session (${v.split("_")[0].split("-")[0]}) is usable outside it`);
            }
          }
          if (fs.readFileSync(path.join(h.home, ".npmrc"), "utf8") !== "registry=https://registry.npmjs.org/\n") {
            throw new Error("the person's own ~/.npmrc was not restored");
          }
          const next = await openSessionState({ env: h.env, cwd: h.home, boxes: boxesOf(fw), audit: h.audit });
          const e = next.ok && next.applyEnv(h.env);
          if (!e || !fs.readFileSync(path.join(e.GH_CONFIG_DIR, "hosts.yml"), "utf8").includes(secret)) {
            throw new Error("the next activated launch did not get the session's gh login back");
          }
          await next.close();
        }),
    },
  ];
}
