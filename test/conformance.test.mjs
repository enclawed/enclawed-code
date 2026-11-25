import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// Enclawed's adapter invariants, run through Enclawed Code's own mapping of
// Claude Code's hook input onto the kit (src/conformance.mjs). The kit-stub
// counterpart (the same run fails with the kit's decision stubbed to allow)
// is the adversarial mutant kit-force-allow.
import assert from "node:assert/strict";
import { test } from "node:test";
import { authChecks, enclawedConformanceAdapter, launchChecks } from "../src/conformance.mjs";
import { framework } from "../src/kit.mjs";

test("conformance: every adapter invariant holds through Enclawed Code", async () => {
  const checks = framework.adapterChecks(enclawedConformanceAdapter);
  const r = await framework.runConformanceChecks({ only: checks.map((c) => c.id), extraChecks: checks });
  assert.equal(r.results.length, framework.ADAPTER_CASE_IDS.length);
  assert.deepEqual(r.results.filter((x) => x.status !== "pass").map((x) => `${x.id}: ${x.detail}`), []);
});

test("conformance: a 0.4-firmware Enclaweder refuses a root-required launch, through Enclawed Code's launch mapping", async () => {
  const checks = launchChecks(framework);
  const r = await framework.runConformanceChecks({ only: checks.map((c) => c.id), extraChecks: checks });
  assert.deepEqual(
    r.results.map((x) => `${x.id}: ${x.status}${x.detail ? ` ${x.detail}` : ""}`),
    ["adapter:claude-code:anchor-v3-continuing-log: pass", "adapter:claude-code:launch-firmware-pin: pass"],
  );
});

test("conformance: a synced passkey and a passkey assertion without UV are refused, through Enclawed Code's enrollment and second-factor check", async () => {
  const checks = authChecks();
  const r = await framework.runConformanceChecks({ only: checks.map((c) => c.id), extraChecks: checks });
  assert.deepEqual(
    r.results.map((x) => `${x.id}: ${x.status}${x.detail ? ` ${x.detail}` : ""}`),
    ["adapter:claude-code:passkey-synced-refused: pass", "adapter:claude-code:passkey-uv-required: pass"],
  );
});

test("conformance: between sessions no plaintext context exists, and a credential made in a session is not usable outside one, through Enclawed Code's session-state mapping", async () => {
  const { sessionStateChecks } = await import("../src/conformance-session-state.mjs");
  const checks = sessionStateChecks(framework);
  const r = await framework.runConformanceChecks({ only: checks.map((c) => c.id), extraChecks: checks });
  assert.deepEqual(
    r.results.map((x) => `${x.id}: ${x.status}${x.detail ? ` ${x.detail}` : ""}`),
    ["adapter:claude-code:no-plaintext-at-rest-between-sessions: pass", "adapter:claude-code:session-credentials-stay-in-session: pass"],
  );
});

test("conformance: a Claude subscription login stays with Claude Code (never read, stored or relayed; the halt erases the session's storage write-only), and only an API key is ever sealed, through Enclawed Code's login mapping", async () => {
  const { loginChecks } = await import("../src/conformance-login.mjs");
  const checks = loginChecks();
  const r = await framework.runConformanceChecks({ only: checks.map((c) => c.id), extraChecks: checks });
  assert.deepEqual(
    r.results.map((x) => `${x.id}: ${x.status}${x.detail ? ` ${x.detail}` : ""}`),
    ["adapter:claude-code:subscription-login-never-handled: pass", "adapter:claude-code:only-api-keys-sealed: pass"],
  );
});
