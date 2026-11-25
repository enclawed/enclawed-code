import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// Two compliance controls (docs/legal-review.md):
//   - a session starts only with a Claude Code version whose terms Enclawed Code
//     reviewed (legal/reviewed-terms.json; src/claude-terms.mjs), in the launcher
//     and in a managed hook; a newer, an older unreviewed, or an unreadable
//     version refuses with what to install; nothing bypasses it;
//   - Claude Code's automatic updates are off inside Enclawed Code's sessions
//     (its documented DISABLE_AUTOUPDATER and DISABLE_UPDATES), in the session's
//     environment and its generated settings;
//   - the release gate (scripts/check-legal-terms.mjs) fails when a reviewed
//     page's fingerprint differs, or a page cannot be fetched.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { REVIEWED_TERMS_FILE, SESSION_UPDATE_ENV, claudeVersionGate, installReviewedCommand, reviewedClaudeVersions } from "../src/claude-terms.mjs";
import { buildSettings } from "../src/settings.mjs";
import { checkTerms, fingerprint, FORMS, normalizeTermsText, NORMALIZATION, pageFingerprint, readReviewedTerms } from "../scripts/check-legal-terms.mjs";
import { pre, runLauncher, sandbox } from "./helpers.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());

test("the reviewed versions: the shipped record lists 2.1.331 (the release's) and every fingerprint; the file ships in the package", () => {
  const v = reviewedClaudeVersions();
  assert.ok(v.includes("2.1.331"), JSON.stringify(v));
  const terms = readReviewedTerms();
  assert.equal(terms.normalization, NORMALIZATION);
  assert.deepEqual(
    terms.pages.map((p) => p.url),
    [
      "https://code.claude.com/docs/en/legal-and-compliance.md",
      "https://www.anthropic.com/legal/commercial-terms",
      "https://www.anthropic.com/legal/service-specific-terms",
      "https://www.anthropic.com/legal/supported-regions",
      "https://www.anthropic.com/legal/consumer-terms",
      "https://www.anthropic.com/legal/aup",
      "https://www.anthropic.com/legal/trademark-guidelines",
    ],
  );
  for (const p of terms.pages) {
    assert.match(p.sha256, /^[0-9a-f]{64}$/, p.url);
    assert.ok(FORMS.includes(p.form), p.url);
  }
  // Claude Code's page is fingerprinted in its Markdown form (raw bytes); the reviewed Commercial Terms are the snapshot effective Jun 17, 2025.
  assert.equal(terms.pages[0].form, "raw");
  assert.deepEqual(terms.pages[1].reviewedVersion, { title: "Commercial Terms of Service", effective: "Jun 17, 2025", snapshotPdfSha256: "af5032c44336929c06722809e2a29a421175837d91be0de149d3462f1fd3e270", pages: 12 });
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.ok(pkg.files.includes("legal/") && pkg.files.includes("docs/"), "legal/reviewed-terms.json and docs/legal-review.md ship");
  assert.ok(fs.existsSync(path.join(ROOT, "docs", "legal-review.md")));
});

test("the gate: a reviewed version starts; a newer, an older unreviewed or an unreadable version refuses, naming the reviewed versions and how to install one; an unreadable record refuses", () => {
  const native = path.join(sb.home, ".local", "share", "claude", "versions", "2.1.332");
  assert.deepEqual(claudeVersionGate("2.1.331", native), { ok: true, version: "2.1.331" });
  for (const [v, code] of [
    ["2.1.332", "claude-version-unreviewed"],
    ["2.2.0", "claude-version-unreviewed"],
    ["2.1.330", "claude-version-unreviewed"],
    ["2.1.295", "claude-version-unreviewed"],
    [null, "claude-version-unreadable"],
    ["", "claude-version-unreadable"],
    ["2.1.331-beta", "claude-version-unreadable"],
  ]) {
    const r = claudeVersionGate(v, native);
    assert.equal(r.ok, false, String(v));
    assert.equal(r.code, code, String(v));
    assert.match(r.message, /reviewed with Claude Code 2\.1\.326, 2\.1\.331|reviewed: 2\.1\.326, 2\.1\.331/, String(v));
    assert.match(r.message, /curl -fsSL https:\/\/claude\.ai\/install\.sh \| bash -s 2\.1\.331/, String(v));
  }
  assert.match(claudeVersionGate("2.1.332", native).message, /A newer Claude Code may come with new terms that Enclawed Code has not reviewed yet/);
  const missing = path.join(sb.dir, "no-terms.json");
  assert.equal(claudeVersionGate("2.1.331", native, { file: missing }).code, "reviewed-terms-unreadable");
  fs.writeFileSync(missing, JSON.stringify({ claudeCode: { versions: ["latest"] } }));
  assert.equal(claudeVersionGate("2.1.331", native, { file: missing }).code, "reviewed-terms-unreadable");
});

test("how to install a reviewed version matches the installation: native, npm, or both commands when it cannot tell", () => {
  const nativeDir = path.join(sb.home, ".local", "share", "claude", "versions");
  fs.mkdirSync(nativeDir, { recursive: true });
  fs.writeFileSync(path.join(nativeDir, "2.1.400"), "");
  assert.equal(installReviewedCommand(path.join(nativeDir, "2.1.400"), "2.1.331"), "this is a native installation: curl -fsSL https://claude.ai/install.sh | bash -s 2.1.331");
  const npmBin = path.join(sb.dir, "npm", "lib", "node_modules", "@anthropic-ai", "claude-code", "bin", "claude");
  fs.mkdirSync(path.dirname(npmBin), { recursive: true });
  fs.writeFileSync(npmBin, "");
  assert.equal(installReviewedCommand(npmBin, "2.1.331"), "this is an npm installation: npm install -g @anthropic-ai/claude-code@2.1.331");
  assert.match(installReviewedCommand("/usr/bin/claude", "2.1.331"), /native installer: curl -fsSL https:\/\/claude\.ai\/install\.sh \| bash -s 2\.1\.331 \(or, for an npm installation: npm install -g @anthropic-ai\/claude-code@2\.1\.331\)/);
});

test("ecwcode: an unreviewed (newer or older) or unreadable Claude Code refuses before anything starts; a reviewed one starts; no variable bypasses it", () => {
  for (const [v, re] of [
    ["2.1.332", /Claude Code 2\.1\.332 .* is not a version Enclawed Code has reviewed; reviewed: 2\.1\.326, 2\.1\.331\. A newer Claude Code may come with new terms/],
    ["2.1.330", /Claude Code 2\.1\.330 .* is not a version Enclawed Code has reviewed/],
    ["not-a-version", /the version of Claude Code at .* could not be read/],
  ]) {
    const out = path.join(sb.dir, `claude-${v}.json`);
    // Variables a person might try: none of them is read by the gate.
    const r = runLauncher(sb, ["-p", "x"], { FAKE_CLAUDE_VERSION: v, FAKE_CLAUDE_OUT: out, ECWCODE_SKIP_VERSION_CHECK: "1", ENCLAWED_CLAUDE_VERSION: "2.1.331", DISABLE_AUTOUPDATER: "0" });
    assert.equal(r.status, 2, `${v}: ${r.stderr}`);
    assert.match(r.stderr, re, v);
    assert.equal(fs.existsSync(out), false, `${v}: claude was started`);
  }
  const out = path.join(sb.dir, "claude-ok.json");
  const ok = runLauncher(sb, ["-p", "x"], { FAKE_CLAUDE_VERSION: "2.1.331", FAKE_CLAUDE_OUT: out, FAKE_CLAUDE_FULL_ENV: "1" });
  assert.equal(ok.status, 0, ok.stderr);
  const rec = JSON.parse(fs.readFileSync(out, "utf8"));
  // Claude Code's updates are off in the session: its environment and its generated settings.
  assert.equal(rec.processEnv.DISABLE_AUTOUPDATER, "1");
  assert.equal(rec.processEnv.DISABLE_UPDATES, "1");
  assert.equal(rec.settings.env.DISABLE_AUTOUPDATER, "1");
  assert.equal(rec.settings.env.DISABLE_UPDATES, "1");
});

test("the generated session settings always carry Claude Code's update switches, over any lower settings value", () => {
  const { settings } = buildSettings([{ env: { DISABLE_AUTOUPDATER: "0", DISABLE_UPDATES: "", OTHER: "x" } }], "hook");
  assert.deepEqual(SESSION_UPDATE_ENV, { DISABLE_AUTOUPDATER: "1", DISABLE_UPDATES: "1" });
  assert.equal(settings.env.DISABLE_AUTOUPDATER, "1");
  assert.equal(settings.env.DISABLE_UPDATES, "1");
  assert.equal(settings.env.OTHER, "x");
  assert.deepEqual(buildSettings([], "hook").settings.env, { DISABLE_AUTOUPDATER: "1", DISABLE_UPDATES: "1" });
});

test("a managed hook run by an unreviewed or unreadable Claude Code denies the call, saying why; a reviewed one decides as usual", () => {
  const entry = path.join(ROOT, "test", "fixtures", "hook-entry.mjs");
  const run = (managedClaudeVersion) => {
    const authority = { ...sb.authority, managedSettingsDir: path.join(sb.admin, "no-managed"), managedHome: sb.home, managedClaudeVersion };
    return spawnSync(process.execPath, [entry, JSON.stringify(authority), "--origin", "managed"], { input: JSON.stringify(pre(sb, "Read", { file_path: "a" })), cwd: sb.project, env: { ...sb.env, CLAUDE_PROJECT_DIR: sb.project }, encoding: "utf8" });
  };
  for (const [v, re] of [
    ["2.1.332", /Claude Code 2\.1\.332 .* is not a version Enclawed Code has reviewed/],
    [null, /could not be read/],
  ]) {
    const r = run(v);
    assert.equal(r.status, 2, r.stderr);
    const out = JSON.parse(r.stdout);
    assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
    assert.match(out.hookSpecificOutput.permissionDecisionReason, re);
  }
  const ok = run("2.1.331");
  assert.doesNotMatch(ok.stdout, /not a version Enclawed Code has reviewed/);
});

test("the release gate: unchanged pages pass; a changed page, or one that cannot be fetched, fails and is named", async () => {
  const pageA = "<html><head><title>T</title><script>var nonce='1'</script></head><body><nav>menu</nav><main><h1>Terms</h1>\n<p>Clause&nbsp;one &amp; two.</p><!-- c --><style>p{}</style></main><footer>f</footer></body></html>";
  const terms = { reviewed: "2026-11-25", normalization: NORMALIZATION, pages: [{ url: "https://a.test/terms", form: "html-text-v1", sha256: fingerprint(normalizeTermsText(pageA)) }, { url: "https://b.test/aup", form: "html-text-v1", sha256: fingerprint("AUP") }, { url: "https://c.test/x.md", form: "raw", sha256: fingerprint(Buffer.from("# X\n")) }] };
  assert.equal(normalizeTermsText(pageA), "Terms Clause one & two.");
  // Markup, scripts, styles, comments and whitespace outside the text do not change the fingerprint.
  assert.equal(normalizeTermsText(pageA.replace("var nonce='1'", "var nonce='2'").replace("\n", "\n\n  ")), normalizeTermsText(pageA));
  const pages = { "https://a.test/terms": pageA, "https://b.test/aup": "<main>AUP</main>", "https://c.test/x.md": Buffer.from("# X\n") };
  // The raw form is byte-exact: one more space is a change.
  assert.notEqual(pageFingerprint(Buffer.from("# X \n"), "raw"), terms.pages[2].sha256);
  const same = await checkTerms({ terms, fetchText: async (u) => pages[u] });
  assert.equal(same.ok, true, JSON.stringify(same));
  const changed = await checkTerms({ terms, fetchText: async (u) => (u.includes("a.test") ? pageA.replace("Clause", "Section") : pages[u]) });
  assert.equal(changed.ok, false);
  assert.deepEqual(changed.pages.filter((p) => !p.ok).map((p) => p.url), ["https://a.test/terms"]);
  const down = await checkTerms({ terms, fetchText: async (u) => (u.includes("b.test") ? Promise.reject(new Error("HTTP 503")) : pages[u]) });
  assert.equal(down.ok, false);
  assert.deepEqual(down.pages.filter((p) => !p.ok).map((p) => [p.url, p.error]), [["https://b.test/aup", "HTTP 503"]]);
  assert.equal((await checkTerms({ terms: { ...terms, normalization: "other" }, fetchText: async (u) => pages[u] })).ok, false);
});

test("the release gate runs on every pack and every public publish", () => {
  assert.match(fs.readFileSync(path.join(ROOT, "scripts", "check-pack.mjs"), "utf8"), /check-legal-terms\.mjs/);
  assert.match(fs.readFileSync(path.join(ROOT, "scripts", "publish-public.sh"), "utf8"), /check-legal-terms\.mjs/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).scripts.prepack, "node scripts/check-pack.mjs");
  assert.equal(REVIEWED_TERMS_FILE, path.join(ROOT, "legal", "reviewed-terms.json"));
});
