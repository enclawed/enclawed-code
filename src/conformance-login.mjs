// Login guarantees, through Enclawed Code's own mapping of Claude Code's login
// (managed-login.mjs, login-watch.mjs). The real Claude Code binary run under
// the managed policy is test/managed-login.test.mjs; these checks run anywhere
// (temporary directories only, no device, no network).

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { kit } from "./kit.mjs";
import { claudeCredentialLocations } from "./credentials.mjs";
import { LOGIN_LABEL, sealedLoginFile } from "./login-seal.mjs";
import { claudeCredentialSpec, pendingLogins, startLoginWatch, sweepLogins } from "./login-watch.mjs";
import { LOGIN_POLICY_FILE, loginPolicySpec } from "./managed-login.mjs";

const LOGIN = JSON.stringify({ claudeAiOauth: { accessToken: "sk-ant-oat01-conformance-stand-in", refreshToken: "r", expiresAt: 4102444800000, scopes: ["user:inference"] } });

function tmp(prefix) {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

export function loginChecks() {
  return [
    {
      id: "adapter:claude-code:managed-login-policy",
      title: "claude-code: on a managed install plain claude cannot authenticate",
      proves:
        "the managed settings Enclawed Code installs pin Claude Code's organization list to none (every session or sign-in with a login of its own is refused; a session over Enclawed Code's relay socket is not judged by it) and its login storage to an empty directory only root can write (a stored login is never read or written), never set allowedProviders (which would refuse the relay), and are reported in force only when no other managed document widens or re-points them and the directory is root's and empty; the real Claude Code 2.1.326 under it is run in test/managed-login.test.mjs",
      remedy: "Enclawed Code's managed login-policy must write forceLoginOrgUUID [] and env.CLAUDE_SECURESTORAGE_CONFIG_DIR to its empty root-only directory, and report it in force only on the kit's managedLoginPolicyStatus",
      run: async () => {
        const dir = tmp("enclawed-code-conf-managed-");
        try {
          fs.chmodSync(dir, 0o755);
          const spec = loginPolicySpec(dir);
          const doc = kit.managedLoginPolicyDocument(spec);
          if (!Array.isArray(doc.forceLoginOrgUUID) || doc.forceLoginOrgUUID.length !== 0) {
            throw new Error(`the policy does not admit no organization: ${JSON.stringify(doc.forceLoginOrgUUID)}`);
          }
          if (doc.env?.CLAUDE_SECURESTORAGE_CONFIG_DIR !== spec.storageDir || "allowedProviders" in doc || "apiKeyHelper" in doc) {
            throw new Error(`the policy does not pin the login storage, or sets a key that would refuse the relay: ${JSON.stringify(doc)}`);
          }
          fs.mkdirSync(path.join(dir, "managed-settings.d"), { mode: 0o755 });
          fs.mkdirSync(spec.storageDir, { mode: 0o555 });
          const policyFile = path.join(dir, "managed-settings.d", LOGIN_POLICY_FILE);
          fs.writeFileSync(policyFile, kit.managedLoginPolicyText(spec), { mode: 0o644 });
          // This check is about the directory itself: the owners of its (temporary) ancestors stand in for root.
          const owners = [process.getuid?.() ?? 0];
          for (let d = path.dirname(dir); d !== path.dirname(d); d = path.dirname(d)) {
            owners.push(fs.statSync(d).uid);
          }
          const status = (extra) =>
            kit.managedLoginPolicyStatus([...extra, { file: policyFile, doc: JSON.parse(fs.readFileSync(policyFile, "utf8")) }], spec, {
              policyFile,
              fileCheck: () => ({ ok: true }),
              dirProblem: (d) => kit.adminOnlyEmptyDirProblem(d, owners),
            });
          if (!status([]).installed) {
            throw new Error(`the installed policy is not in force: ${status([]).reason}`);
          }
          const main = path.join(dir, "managed-settings.json");
          for (const [doc2, code] of [
            [{ forceLoginOrgUUID: ["22222222-2222-4222-8222-222222222222"] }, "org-pin-widened"],
            [{ env: { CLAUDE_SECURESTORAGE_CONFIG_DIR: path.join(dir, "home", ".claude") } }, "env-pin-overridden"],
          ]) {
            const s = status([{ file: main, doc: doc2 }]);
            if (s.installed || s.code !== code) {
              throw new Error(`a managed document that undoes the policy was not caught (${code}): ${JSON.stringify(s)}`);
            }
          }
          fs.chmodSync(spec.storageDir, 0o777);
          if (status([]).code !== "storage-dir-unsafe") {
            throw new Error("a login directory other users can write was taken as safe");
          }
        } finally {
          fs.chmodSync(path.join(dir), 0o755);
          fs.rmSync(dir, { recursive: true, force: true });
        }
      },
    },
    {
      id: "adapter:claude-code:plaintext-login-sealed-or-quarantined",
      title: "claude-code: under the managed login policy, a plaintext login is sealed or quarantined within the watcher's bound",
      proves:
        "under the administrator's managed login policy (its only use), with a login sealed under the Enclaweder, a plaintext Claude Code login written to its credentials file (as plain claude writes it: a temporary file, then a rename) is out of Claude Code's reach within the kit's CREDENTIAL_WATCH_BOUND_MS: sealed to the launch's login box when a session holds one, quarantined otherwise; nothing is left in Claude Code's directory",
      remedy: "Enclawed Code must run the kit's watchHostCredentials on Claude Code's credential locations, with the session's login box while one is held",
      run: async () => {
        const root = tmp("enclawed-code-conf-watch-");
        try {
          const env = { HOME: path.join(root, "home"), ENCLAWED_STATE_DIR: path.join(root, "state") };
          const plain = claudeCredentialLocations(env, "linux").file;
          fs.mkdirSync(path.dirname(plain), { recursive: true });
          fs.mkdirSync(path.dirname(sealedLoginFile(env)), { recursive: true, mode: 0o700 });
          fs.writeFileSync(sealedLoginFile(env), "{}", { mode: 0o600 }); // a login is sealed: the device is bound
          const box = typeof kit.sealBoxFromSeed === "function" ? kit.sealBoxFromSeed(createHash("sha256").update("conformance-box").digest(), "device:conformance") : null;
          const forgotten = { write: { key: Buffer.alloc(32), source: "device", id: "device:conformance:0" }, read: () => null, keyFile: path.join(root, "none") };
          for (const [name, opts, sealed] of [
            ["no session", {}, false],
            ...(box ? [["a session's login box", { keys: forgotten, sealOptions: { box } }, true]] : []),
          ]) {
            const w = startLoginWatch({ env, guarded: true, ...opts });
            try {
              const t0 = Date.now();
              fs.writeFileSync(`${plain}.tmp.conformance`, LOGIN, { mode: 0o600 });
              fs.renameSync(`${plain}.tmp.conformance`, plain);
              while (fs.existsSync(plain) && Date.now() - t0 < kit.CREDENTIAL_WATCH_BOUND_MS * 3) {
                await new Promise((r) => setTimeout(r, 10));
              }
              const ms = Date.now() - t0;
              if (fs.existsSync(plain) || ms > kit.CREDENTIAL_WATCH_BOUND_MS) {
                throw new Error(`${name}: the plaintext login was still readable after ${ms} ms (bound ${kit.CREDENTIAL_WATCH_BOUND_MS} ms)`);
              }
              await w.sweep();
            } finally {
              w.close();
            }
            const left = fs.readdirSync(path.dirname(plain));
            const held = pendingLogins(env);
            if (left.length || held.length !== 1 || held[0].sealed !== sealed || fs.readFileSync(held[0].file, "utf8").includes("conformance-stand-in") === sealed) {
              throw new Error(`${name}: expected the login ${sealed ? "sealed" : "quarantined"} and nothing left beside Claude Code's file: left ${JSON.stringify(left)}, held ${JSON.stringify(held)}`);
            }
            if (sealed && !kit.unsealLoginToMemory({ sealedFile: held[0].file, keys: forgotten, deviceBound: true, label: LOGIN_LABEL, box }).ok) {
              throw new Error(`${name}: the sealed login does not open with the device's box`);
            }
            kit.discardPendingCredential(held[0].file);
          }
        } finally {
          fs.rmSync(root, { recursive: true, force: true });
        }
      },
    },
    {
      id: "adapter:claude-code:person-login-untouched",
      title: "claude-code: without the managed login policy, the person's own Claude Code login is never touched",
      proves:
        "with a login of Enclawed Code's own sealed under the Enclaweder and no managed login policy, the person's plaintext login in their own storage (written as plain claude writes it, and rewritten as a token refresh does) stays exactly where and as it is through the watcher, the launch sweep and the launch's login decision; nothing is held, sealed, quarantined or erased",
      remedy: "Enclawed Code must act on the person's login storage only when the managed login policy is in force (login-guard.mjs)",
      run: async () => {
        const root = tmp("enclawed-code-conf-person-");
        try {
          const env = { HOME: path.join(root, "home"), ENCLAWED_STATE_DIR: path.join(root, "state") };
          const plain = claudeCredentialLocations(env, "linux").file;
          fs.mkdirSync(path.dirname(plain), { recursive: true });
          fs.mkdirSync(path.dirname(sealedLoginFile(env)), { recursive: true, mode: 0o700 });
          fs.writeFileSync(sealedLoginFile(env), "{}", { mode: 0o600 });
          const w = startLoginWatch({ env, guarded: false });
          try {
            for (const n of [1, 2]) {
              fs.writeFileSync(`${plain}.tmp.${n}`, LOGIN, { mode: 0o600 });
              fs.renameSync(`${plain}.tmp.${n}`, plain);
              await new Promise((r) => setTimeout(r, kit.CREDENTIAL_WATCH_BOUND_MS * 3));
            }
            await w.sweep();
          } finally {
            w.close();
          }
          await sweepLogins({ env, guarded: false });
          if (!fs.existsSync(plain) || fs.readFileSync(plain, "utf8") !== LOGIN || pendingLogins(env).length !== 0) {
            throw new Error(`the person's login was acted on: present ${fs.existsSync(plain)}, held ${pendingLogins(env).length}`);
          }
          const s = kit.loginSealStatus({ sealedFile: sealedLoginFile(env), plainFiles: claudeCredentialSpec(env, { guarded: false }).files });
          const d = kit.loginLaunchDecision({ deviceBound: true, status: s });
          if (d.action !== "unseal") {
            throw new Error(`the launch's login decision looked at the person's login: ${JSON.stringify(d)}`);
          }
        } finally {
          fs.rmSync(root, { recursive: true, force: true });
        }
      },
    },
  ];
}
