// Enclawed Code's own commands, run as `ecwctl` (src/ctl.mjs); `ecwcode` reserves nothing (args.mjs):
//
//   ecwctl history list [--path P] [--limit N] [--all] [--json]
//   ecwctl history restore <id|hash> [--to P] [--unverified]   (two-factor: your security key or device-bound passkey)
//   ecwctl history prune
//   ecwctl audit verify [--json]
//   ecwctl audit reconcile [--json] [--no-transcripts]
//   ecwctl audit path
//   ecwctl managed print [--hook-command CMD] [--flavor F] [--hardware-root required|optional]
//   ecwctl doctor | demo [--json] [--scenario IDS] | version | help
//   ecwctl policy ... | auth ... | recover-root | recover-anchor
//   ecwctl --version | --help
//
// Every command validates its options (unknown options and missing values
// are errors), and loads the framework only once it knows what it will do.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { ECWCODE_LAUNCH_OPTIONS } from "./args.mjs";
import { LockedAuditLog, installRuntime, segmentFiles, verifyAuditLog } from "./audit.mjs";
import { AuthError, ENROLL_STEPS, launchAuthContext, legacyMethod, readAuthState, validTicket, verifyUser } from "./auth.mjs";
import { activateLaunch } from "./device-activation.mjs";
import { AUTH_HELP, authCommand, recoverAnchor, recoverRoot } from "./auth-cli.mjs";
import { MIN_CLAUDE_VERSION, claudeVersion, locateClaude, versionAtLeast } from "./claude.mjs";
import { UsageError, ask, isInteractive, parseFlags, positiveInt } from "./cli-util.mjs";
import { boundDevice, checkDeviceAnchor, deviceAnchorFails, measurementDrift } from "./device.mjs";
import { acceptAnchorBaseline, launchAnchorGate } from "./anchor-gate.mjs";
import { userNamespaceDeviceRisk } from "./userns.mjs";
import { FRAMEWORK_ENTRY, FRAMEWORK_PACKAGE, loadFramework } from "./framework.mjs";
import { kit } from "./kit.mjs";
import { HistoryError, resolveEntry, restoreEntry, unverifiedEntries, verifiedEntries } from "./history.mjs";
import { legacyManagedHookFiles, managedHooksStatus, managedTemplate, readManagedSettings } from "./managed.mjs";
import { effectivePermissionMode, modeDoctorLine } from "./permission-mode.mjs";
import { APP_ROOT, HOOK_BIN, auditLogPath, historyDir, managedSettingsDir, realpathNearest, stateDir } from "./paths.mjs";
import { loadPolicy } from "./policy.mjs";
import { shellFlavor } from "./env-authority.mjs";
import { authority } from "./authority.mjs";
import { POLICY_HELP, policyCommand } from "./policy-cli.mjs";
import { reconcile } from "./reconcile.mjs";
import { policyCandidates } from "./session.mjs";
import { VERSION } from "./version.mjs";
import { ADMISSION_HELP, admissionCommand } from "./admission-cli.mjs";

const HELP = `Enclawed Code ${VERSION}: Claude Code, with every tool call checked by Enclawed.

Claude Code: type ecwcode wherever you would type claude; every argument goes to claude unchanged
(ecwcode --help is claude's help). Enclawed Code's own commands:

  ecwctl history list [--path P] [--limit N] [--all] [--json]
                                                     file versions kept before writes
  ecwctl history restore <id> [--to P]               put a kept version back
  ecwctl history prune                               drop versions past retention
  ecwctl audit verify [--json]                       check the audit log (chain, head anchor, device anchor)
  ecwctl audit reconcile [--json] [--no-transcripts] find calls without a recorded decision
  ecwctl audit path                                  print the audit log's location
  ecwctl audit accept                                accept the log as found as the device-anchor baseline (after a refused launch)
  ecwctl managed print [--hook-command CMD] [--flavor F] [--hardware-root required|optional]
                                                     organization-wide settings for Claude Code
  ecwctl managed login-policy print|status|install|remove
                                                     on a managed install (root): plain claude cannot sign in or use a stored login
  ecwctl doctor                                      check this installation
  ecwctl demo [--json] [--scenario IDS]              replay planted-instruction attacks offline and show what Enclawed Code does
  ecwctl conformance [--json]                        check Enclawed's guarantees through Enclawed Code's own mapping
  ecwctl policy init|show|path|edit|validate|use|add-tool|remove-tool|add-host|remove-host
                                                     create or change Enclawed Code's policy
  ecwctl policy workflow list|show|bind|unbind       workflow profiles (select one at launch: ecwcode --workflow NAME)
  ecwctl auth enroll|status|test|unlock|lock|remove  two-factor auth, mandatory (this computer's device-bound passkey, or a FIDO2 security key)
  ecwctl recover-root                                clear a DIRTY hardware-root latch with the genuine device
  ecwctl recover-anchor [--operator-offline N]       free a BUSY anchor channel (operator takeover signed off this host; without it: the procedure)
  ecwctl login status|seal [--replace]               keep Claude Code's login sealed under the Enclaweder (opened only inside sessions)
  ecwctl login new [--replace]                       sign in inside Enclawed Code; the login is sealed under the Enclaweder at once
  ecwctl login resolve [--replace|--discard]         a login made outside Enclawed Code (held by the watcher): adopt or discard it
  ecwctl login watch [--once|install|remove|status]  the watcher that seals or quarantines a plaintext login as it appears
  ecwctl context status|discard                      the session context and session tool logins, sealed under the Enclaweder between sessions
  ecwctl files [accept PATH...|--all]                project files changed outside the agent; accept reviewed ones (security key or passkey)
  ecwctl measurement approve                         approve this Enclawed Code's measured code with a code the Enclaweder checks (after install or upgrade)
  ecwctl review [status|enable|disable|run|label|export]
                                                     experimental, opt-in, after the fact: a model reviews decided calls; you label only its disagreements with the gate
  ecwctl probe <Tool> ['<input JSON>'] [--mode M]    ask the hook for one decision, as Claude Code would (runs nothing)
  ecwctl skills list|verify|sign|unsign              skill admission (signed formal bundles, the biconditional criterion)
  ecwctl mcp list|pin|import|unpin|show              MCP server admission (pinned identity and tool definitions)
  ecwctl trust list|add|remove                       who may attest skills and MCP servers
  ecwctl version | --version
  ecwctl help | --help
`;

function audit(fw, env = process.env) {
  return new LockedAuditLog(fw, auditLogPath(env));
}

async function framework(env = process.env) {
  const { fw } = await loadFramework();
  const loaded = loadPolicy(fw, { candidates: policyCandidates(env, { fw }), flavor: shellFlavor(env).flavor });
  const log = audit(fw, env);
  installRuntime(fw, { audit: log, policy: loaded.policy, flavor: loaded.flavor });
  const store = new fw.HistoryStore({ dir: historyDir(env), limits: loaded.policy.history });
  return { fw, loaded, audit: log, store };
}

const HISTORY_USAGE = "usage: ecwctl history list [--path P] [--limit N] [--all] [--json] | restore <id> [--to P] [--unverified] | prune\n";

async function history(args, out, err) {
  const sub = args[0];
  const rest = args.slice(1);
  // Check the command before loading anything (docs-agent bug 9).
  let parsed;
  if (sub === "list") {
    parsed = parseFlags(rest, { bool: ["--json", "--all"], value: ["--path", "--limit"], maxPositionals: 0 });
    if (parsed.flags["--limit"] !== undefined) {
      positiveInt(parsed.flags["--limit"], "--limit");
    }
  } else if (sub === "restore") {
    parsed = parseFlags(rest, { bool: ["--unverified"], value: ["--to", "--passphrase-fd"], maxPositionals: 1 });
    if (parsed.positionals.length === 0) {
      throw new UsageError("history restore needs an entry id (see: ecwctl history list)");
    }
  } else if (sub === "prune") {
    parsed = parseFlags(rest, { maxPositionals: 0 });
  } else {
    err.write(HISTORY_USAGE);
    return 2;
  }
  const { fw, loaded, audit: log, store } = await framework();
  try {
    const file = auditLogPath();
    if (sub === "list") {
      const limit = parsed.flags["--limit"] !== undefined ? Number(parsed.flags["--limit"]) : 50;
      const verified = await verifiedEntries(file);
      let entries = parsed.flags["--all"] ? [...verified, ...(await unverifiedEntries(store, verified))] : verified;
      if (parsed.flags["--path"]) {
        const want = realpathNearest(path.resolve(parsed.flags["--path"]));
        entries = entries.filter((e) => e.realPath === want || path.resolve(e.path ?? "") === want);
      }
      entries.sort((a, b) => a.ts - b.ts);
      const shown = entries.slice(-limit);
      if (parsed.flags["--json"]) {
        out.write(`${JSON.stringify(shown, null, 2)}\n`);
        return 0;
      }
      if (shown.length === 0) {
        out.write(`no kept versions recorded in ${file}\n`);
        return 0;
      }
      for (const e of shown) {
        const when = new Date(e.ts).toISOString();
        const what = e.hash ? e.hash.slice(0, 12) : "(new file)  ";
        const flag = e.verified ? "" : e.sandbox ? "  [unverified, gateway sandbox]" : "  [unverified]";
        out.write(`${e.id.padEnd(13)} ${when}  ${String(e.op).padEnd(7)} ${what}  ${e.realPath}  [${e.tool}]${flag}\n`);
      }
      out.write("\nRestore one with: ecwctl history restore <id>\n");
      return 0;
    }
    if (sub === "restore") {
      const chain = await fw.verifyHistory(file).catch((e) => ({ ok: false, reason: e.message }));
      if (fs.existsSync(file) && !chain.ok) {
        throw new HistoryError("audit-broken", `the audit log does not verify (${chain.reason}), so kept versions cannot be authenticated`);
      }
      const verified = await verifiedEntries(file);
      const pool = parsed.flags["--unverified"] ? [...verified, ...(await unverifiedEntries(store, verified))] : verified;
      const entry = resolveEntry(pool, parsed.positionals[0]);
      // Mandatory two-factor: a restore of protected history needs a touch of an enrolled key.
      await verifyUser({ purpose: "history-restore", interactive: isInteractive(), passphraseFd: parsed.flags["--passphrase-fd"], audit: (r) => log.append(r), options: loaded.options, allowTicket: false });
      const r = await restoreEntry({ entry, to: parsed.flags["--to"], store, audit: (rec) => log.append(rec) });
      out.write(`restored ${r.id} (${r.hash.slice(0, 12)}) to ${r.to}`);
      out.write(r.replacedSnapshot ? ` (what it replaced is kept as ${r.replacedSnapshot.slice(0, 12)})\n` : "\n");
      return 0;
    }
    const r = await store.prune();
    out.write(`removed ${r.removedEntries} entries and ${r.removedObjects} stored versions\n`);
    return 0;
  } finally {
    await log.close();
  }
}

// Every record hash, sealed rotation segments first, so an anchor made
// before a rotation is still found (the anchor history, round 3 N10b).
async function recordHashes(file) {
  const out = [];
  for (const f of [...segmentFiles(file).map((x) => x.file), file]) {
    try {
      for (const line of fs.readFileSync(f, "utf8").split("\n")) {
        if (line.trim()) {
          out.push(JSON.parse(line).recordHash);
        }
      }
    } catch {
      /* verification reports bad lines */
    }
  }
  return out;
}

/** Every record of the log and its sealed segments, in order (unparsable lines skipped: the chain check reports them). */
function allRecords(file) {
  const out = [];
  for (const f of [...segmentFiles(file).map((x) => x.file), file]) {
    try {
      for (const line of fs.readFileSync(f, "utf8").split("\n")) {
        if (line.trim()) {
          try {
            out.push(JSON.parse(line));
          } catch {
            /* reported by the chain check */
          }
        }
      }
    } catch {
      /* a missing segment is reported by the chain check */
    }
  }
  return out;
}

function lastMeasurements(file) {
  let m = null;
  try {
    for (const line of fs.readFileSync(file, "utf8").split("\n")) {
      if (line.includes("claude-code.session.start") && line.includes("measurements")) {
        try {
          m = JSON.parse(line).payload?.measurements ?? m;
        } catch {
          /* skip */
        }
      }
    }
  } catch {
    /* no log */
  }
  return m;
}

async function auditCmd(args, out, err) {
  const sub = args[0];
  const rest = args.slice(1);
  const file = auditLogPath();
  if (sub === "path") {
    parseFlags(rest, { maxPositionals: 0 });
    out.write(`${file}\n`);
    return 0;
  }
  if (sub === "verify") {
    const { flags } = parseFlags(rest, { bool: ["--json", "--no-device"], maxPositionals: 0 });
    const { fw } = await loadFramework();
    const r = await verifyAuditLog(fw, file);
    if (!r.empty && r.ok && !flags["--no-device"]) {
      r.device = await checkDeviceAnchor(fw, file, await recordHashes(file));
    }
    if (!r.empty) {
      r.drift = measurementDrift(lastMeasurements(file));
      const records = allRecords(file);
      // The device anchor's verdict is the kit's (decideAuditAnchorVerdict),
      // from what the log's own launch records say about the hardware root:
      // a MISMATCH, or superseded (round 3, N10b: it cannot be told apart from
      // a truncation behind a restored anchor copy), fails; and a log whose
      // launches held or required the root is proven complete only by a FRESH
      // device anchor read. An offline copy, an unavailable device or
      // --no-device is not a match (the chain's own head file never counts).
      // Command set 0.5: a held log verifies only with a fresh read over this verification's nonce whose head
      // was set by a session bound to one of the log's own launch activations (else anchor-read-unproven / anchor-unbound).
      r.anchorVerdict = fw.decideAuditAnchorVerdict({
        claims: fw.launchRootClaims(records),
        device: r.device?.status ?? null,
        chainAnchor: null,
        attestation: r.device?.attestation ?? null,
        activations: typeof fw.deviceFactorActivations === "function" ? fw.deviceFactorActivations(records) : [],
      });
      if (r.ok && !r.anchorVerdict.ok && r.anchorVerdict.code === "anchor-mismatch") {
        r.ok = false;
        r.reason = `device anchor ${r.device.status}: ${r.device.detail}${r.device.status === "superseded" ? " (if another log shares this device, compare the device counter with your anchor records)" : ""}`;
      }
      // Per-call device commitments of every launch that held the hardware
      // root (commitments.mjs, kit verifyCallChain): signed, chained, and each
      // decision consistent with the policy recorded at launch.
      const { verifyLogCommitments } = await import("./commitments.mjs");
      const { checkAttestation } = await import("./device.mjs");
      r.commitments = verifyLogCommitments(records, {
        checkSignature: (nonce, answer, devices) =>
          checkAttestation(fw, { nonce, answer, pinnedPub: devices.length === 1 ? devices[0].pub : null, pinnedPubs: devices.length ? devices.map((d) => d.pub) : null }),
      });
      if (r.ok && !r.commitments.ok) {
        r.ok = false;
        const first = r.commitments.sessions.find((x) => !x.ok)?.issues[0];
        r.reason = `a session that held the hardware root has calls the device did not commit as recorded (${first?.code}: ${first?.detail})`;
      }
      if (r.ok && !r.anchorVerdict.ok) {
        r.ok = false;
        r.reason = `${r.anchorVerdict.detail}${r.device ? ` (device anchor: ${r.device.detail})` : flags["--no-device"] ? " (the device was not checked: --no-device)" : ""}`;
      }
    }
    if (flags["--json"]) {
      out.write(`${JSON.stringify(r, null, 2)}\n`);
    } else if (r.empty) {
      out.write(`no audit log yet at ${file}\n`);
    } else if (r.ok) {
      out.write(
        `audit log verifies: ${r.count} records, head ${r.head.slice(0, 16)}…, ` +
          `head anchor ${r.anchor === "absent" ? "absent (completeness unproven)" : r.anchor}\n`,
      );
    } else {
      out.write(`audit log does NOT verify: ${r.reason}${r.gaps?.length || deviceAnchorFails(r.device?.status) || r.anchorVerdict?.ok === false ? "" : ` (${r.file}, record ${r.brokenAt ?? "seam"})`}\n`);
      for (const g of r.gaps ?? []) {
        out.write(`  gap at ${new Date(g.ts).toISOString()}: ${g.reason} (anchor ${g.expectedHead?.slice(0, 12) ?? "none"}, found ${String(g.foundTail).slice(0, 12)})\n`);
      }
    }
    if (!flags["--json"] && r.device) {
      out.write(`device anchor: ${r.device.status === "matched" ? "matched" : r.device.status}: ${r.device.detail}${r.device.unanchoredTail ? ` (${r.device.unanchoredTail} newer records not anchored yet)` : ""}\n`);
    }
    if (!flags["--json"] && r.commitments?.held) {
      for (const x of r.commitments.sessions) {
        out.write(`device commitments, launch ${x.nonce.slice(0, 8)}: ${x.ok ? `${x.committed} call(s) committed and consistent` : `NOT consistent: ${x.issues.map((i) => `${i.code} (${i.detail})`).join("; ")}`}${x.notes.length ? ` [${x.notes.join("; ")}]` : ""}\n`);
      }
    }
    if (!flags["--json"] && r.drift?.length) {
      out.write(`measured launch: changed since the last measured session: ${r.drift.join(", ")}\n`);
    }
    return r.ok ? 0 : 1;
  }
  if (sub === "reconcile") {
    const { flags } = parseFlags(rest, { bool: ["--json", "--no-transcripts"], maxPositionals: 0 });
    const r = await reconcile(file, { checkTranscripts: !flags["--no-transcripts"] });
    if (flags["--json"]) {
      out.write(`${JSON.stringify(r, null, 2)}\n`);
    } else {
      out.write(`${r.sessions} sessions, ${r.launches ?? 0} launches, ${r.findings.length} findings\n`);
      for (const f of r.findings) {
        out.write(`  [${f.severity}] ${f.session}: ${f.code} ${f.detail}\n`);
      }
    }
    return r.findings.some((f) => f.severity === "error") ? 1 : 0;
  }
  if (sub === "accept") {
    return await auditAccept(rest, { out, err, file });
  }
  err.write("usage: ecwctl audit verify|reconcile|accept|path\n");
  return 2;
}

/**
 * `ecwctl audit accept` (round 5, R5-A): accept the audit log as found as
 * the new device-anchor baseline, after the launcher refused to start because
 * the log, its anchor file or its anchor history did not match the device.
 * Interactive terminal only; the device serial and the word ACCEPT typed in;
 * then the same activation a launch needs (kit.activateSession, no unlock
 * ticket): the person's security key or device-bound passkey AND an
 * authenticator code the Enclaweder itself verifies (relayed through the
 * device's owner for a client of it). The accept record is anchored under a
 * session bound to that activation, so the log verifies afterwards. Recorded
 * either way.
 */
async function auditAccept(args, { out, err, file, env = process.env }) {
  const { flags } = parseFlags(args, { value: ["--passphrase-fd"], maxPositionals: 0 });
  const { fw, audit: log } = await framework(env);
  const rec = (payload) => log.append({ type: "claude-code.audit.accept-attempt", actor: "enclawed-code", level: null, payload });
  try {
    if (!isInteractive()) {
      err.write("ecwctl: audit accept requires an interactive terminal; run it yourself at a console, with the Enclaweder plugged in\n");
      await rec({ outcome: "refused", code: "no-tty" });
      return 1;
    }
    if (!readAuthState(env)?.method) {
      err.write(`ecwctl: audit accept needs two-factor authentication.\n${ENROLL_STEPS}\n`);
      await rec({ outcome: "refused", code: "no-auth" });
      return 1;
    }
    if (flags["--passphrase-fd"] !== undefined) {
      // A passphrase is no factor (the launch refuses it the same way, audited).
      await launchAuthContext({ env, interactive: true, passphraseFd: flags["--passphrase-fd"], audit: (r) => log.append(r) });
    }
    const nsRisk = userNamespaceDeviceRisk();
    if (nsRisk) {
      err.write(`ecwctl: ${nsRisk}\n`);
      await rec({ outcome: "refused", code: "user-namespace-device" });
      return 1;
    }
    const quiet = console.error;
    console.error = () => {};
    try {
      await fw.bootHardwareRoot();
    } finally {
      console.error = quiet;
    }
    const device = await boundDevice(fw).catch(() => null);
    if (!device?.canAnchor) {
      err.write("ecwctl: no Enclaweder that can anchor is bound to this process (none attached, or another process owns it)\n");
      await rec({ outcome: "refused", code: "no-device" });
      return 1;
    }
    await log.flush();
    // The comparison spends nothing on the device (a fresh read, no open, no unlock use).
    const found = await launchAnchorGate(fw, device, file);
    if (found.ok) {
      out.write(`Nothing to accept: the audit log matches the device (${found.status}: ${found.detail}).\n`);
      return 0;
    }
    out.write(
      `The audit log does not match what the Enclaweder ${device.serial ?? device.uid} anchored:\n  ${found.status}${found.code ? ` (${found.code})` : ""}: ${found.detail}\n` +
        "Accepting makes the log AS IT IS NOW the new baseline: the old anchor file and history are kept beside it (renamed .superseded-<time>), and records before this point can no longer be proven complete by the device.\n",
    );
    const serial = (await ask("Type the device's serial to continue (anything else aborts): ")).trim();
    if (!device.serial || serial.toUpperCase() !== device.serial.toUpperCase()) {
      out.write("Aborted: the serial did not match. Nothing was changed.\n");
      await rec({ outcome: "aborted", code: "serial-mismatch", found });
      return 1;
    }
    const word = (await ask("Type ACCEPT to accept the log as found (anything else aborts): ")).trim();
    if (word !== "ACCEPT") {
      out.write("Aborted. Nothing was changed.\n");
      await rec({ outcome: "aborted", code: "not-confirmed", found });
      return 1;
    }
    // The activation, last, so it is fresh when the accept record is anchored
    // (the bound open must follow it within the device's activation window).
    const ctx = await launchAuthContext({ env, interactive: true, audit: (r) => log.append(r), readCode: (q) => ask(q) });
    // One factor: the code the Enclaweder verifies (device-activation.mjs activateLaunch; it refuses when the device cannot ask).
    await activateLaunch(ctx, { fw, env, held: true, interactive: true, detail: "audit-accept", allowTicket: false });
    const r = await acceptAnchorBaseline(fw, device, file, { found, append: (x) => log.append(x) });
    out.write(`Accepted: the log head ${r.head.slice(0, 16)}… is anchored as the new baseline${r.counter ? ` (counter ${r.counter})` : ""}. Previous anchor files: ${r.moved.join(", ") || "(none)"}.\n`);
    return 0;
  } catch (e) {
    await rec({ outcome: "refused", detail: String(e?.message ?? e).slice(0, 500) }).catch(() => {});
    throw e;
  } finally {
    try {
      fw.closeHardwareRootSession();
    } catch {
      /* nothing to close */
    }
    await log.close();
  }
}

/** Paths a managed hook depends on: every one must be writable only by administrators. */
function managedDependencies() {
  const list = new Set([process.execPath, HOOK_BIN, APP_ROOT]);
  for (const p of [process.execPath, HOOK_BIN]) {
    try {
      list.add(fs.realpathSync(p));
    } catch {
      /* missing: reported by doctor */
    }
  }
  for (const d of ["bin", "src", "managed", ".enclawed-dev/framework"]) {
    const dir = path.join(APP_ROOT, d);
    try {
      list.add(dir);
      for (const f of fs.readdirSync(dir)) {
        list.add(path.join(dir, f));
      }
    } catch {
      /* not present */
    }
  }
  try {
    list.add(fs.realpathSync(path.join(APP_ROOT, ".enclawed-dev", "node_modules")));
  } catch {
    /* not built */
  }
  // An npm install: the enclawed package (the framework), its entry directory's files,
  // and the node_modules directory that holds it and its dependencies.
  if (FRAMEWORK_PACKAGE) {
    list.add(FRAMEWORK_PACKAGE.root);
    if (FRAMEWORK_PACKAGE.nodeModules) {
      list.add(FRAMEWORK_PACKAGE.nodeModules);
    }
    const fwDir = path.dirname(FRAMEWORK_ENTRY);
    list.add(fwDir);
    try {
      for (const f of fs.readdirSync(fwDir)) {
        list.add(path.join(fwDir, f));
      }
    } catch {
      /* reported by doctor */
    }
  }
  // A writable ancestor lets the user rename the directory away and replace it.
  for (const p of [...list]) {
    for (let d = path.dirname(p); d !== path.dirname(d); d = path.dirname(d)) {
      list.add(d);
    }
  }
  return [...list].sort();
}

async function managed(args, out, err) {
  if (args[0] === "login-policy") {
    // Plain claude cannot sign in or use a stored login (managed-login.mjs); install and remove are root's, recorded in root's audit log.
    const { loginPolicyCommand, LOGIN_POLICY_HELP } = await import("./managed-login.mjs");
    if (!args[1] || args[1] === "help") {
      out.write(LOGIN_POLICY_HELP);
      return args[1] ? 0 : 2;
    }
    const writes = args[1] === "install" || args[1] === "remove";
    const { fw } = writes ? await loadFramework() : { fw: null };
    const log = writes ? audit(fw) : null;
    try {
      return await loginPolicyCommand(args.slice(1), { out, err, audit: log ? (r) => log.append(r) : async () => {} });
    } finally {
      await log?.close();
    }
  }
  if (args[0] !== "print") {
    err.write("usage: ecwctl managed print [--hook-command CMD] [--flavor open|enclaved] [--hardware-root required|optional]\n       ecwctl managed login-policy print|status|install|remove\n");
    return 2;
  }
  const { flags } = parseFlags(args.slice(1), { value: ["--hook-command", "--flavor", "--hardware-root"], maxPositionals: 0 });
  if (flags["--flavor"] !== undefined && !["open", "enclaved"].includes(flags["--flavor"])) {
    throw new UsageError("--flavor takes open or enclaved");
  }
  if (flags["--hardware-root"] !== undefined && !["required", "optional"].includes(flags["--hardware-root"])) {
    throw new UsageError("--hardware-root takes required or optional");
  }
  const command = flags["--hook-command"];
  if (!command) {
    // Managed hooks must run code the user cannot change.
    const writable = managedDependencies().filter((p) => {
      try {
        fs.accessSync(p, fs.constants.W_OK);
        return true;
      } catch {
        return false;
      }
    });
    for (const p of writable.slice(0, 20)) {
      err.write(`ecwctl: warning: ${p} is writable by the current user\n`);
    }
    if (writable.length > 0) {
      err.write(
        `ecwctl: warning: ${writable.length} path(s) the managed hook runs from are user-writable; install Node and Enclawed Code where only administrators can write before deploying these settings\n`,
      );
    }
  }
  out.write(`${JSON.stringify(managedTemplate({ command, flavor: flags["--flavor"] ?? null, hardwareRoot: flags["--hardware-root"] ?? null }), null, 2)}\n`);
  return 0;
}

/** doctor: the workflow profile, skills and MCP servers a session started here would get. */
async function doctorAdmission(line, { fw, options, cwd }) {
  const { selectWorkflow } = await import("./workflow.mjs");
  const sel = selectWorkflow({ requested: null, options, projectDir: cwd });
  line(
    null,
    sel.ok && sel.profile
      ? `workflow profile here: ${sel.profile.name} (bound to ${sel.boundTo} by the policy; anything outside it is denied)`
      : `workflow profile here: none bound (base policy only; select one at launch with --workflow ${Object.keys((await import("./workflow.mjs")).allProfiles(options.workflows)).sort().join("|")})`,
  );
  try {
    const { loadFormal } = await import("./formal.mjs");
    const { discoverSkills, verifyAll } = await import("./skills.mjs");
    const results = verifyAll({ formal: await loadFormal(), discovered: discoverSkills({ projectDir: cwd, env: process.env }) });
    const bad = results.filter((r) => r.status !== "verified");
    line(
      bad.length === 0 || options.skills?.unverified === "exclude" ? (results.length ? true : null) : false,
      `skills: ${results.length - bad.length} verified, ${bad.length} not admissible${bad.length ? ` (${bad.slice(0, 3).map((r) => `${r.name}: ${r.status}`).join(", ")}${bad.length > 3 ? ", ..." : ""}; ${options.skills?.unverified === "exclude" ? "they are switched off" : "a launch here is refused"}; see: ecwctl skills list)` : ""}`,
    );
  } catch (e) {
    line(false, `skills: ${e.message}`);
  }
  try {
    const { admitServers, candidateServers } = await import("./mcp.mjs");
    const adm = admitServers({ fw, env: process.env, candidates: candidateServers({ projectDir: cwd, env: process.env }), cwd });
    const conn = options.claudeAiConnectors ?? [];
    line(null, `claude.ai connectors: ${conn.length ? `allowed only for ${conn.join(", ")} (and, under a workflow, its mcpTools)` : "off (they would let tools act outside Enclawed's checks); to allow some, list them under enclawedCode.claudeAiConnectors with: ecwctl policy edit"}`);
    line(adm.ok ? null : false, adm.ok ? `MCP servers a session here starts: ${adm.admitted.map((a) => a.name).join(", ") || "none configured"}${adm.skipped.length ? `; not started, because only pinned servers run (not pinned or changed): ${adm.skipped.map((x) => x.name).join(", ")}; to admit one: ecwctl mcp pin <name>` : ""}` : `MCP: ${adm.message}`);
  } catch (e) {
    line(false, `MCP: ${e.message}`);
  }
}

/**
 * doctor: what an earlier release admitted that does not start any more and
 * must be pinned or granted again. MCP records made before containment (a
 * local server's record needs a signed containment, a remote one its signed
 * URL and transport) and records that no longer verify (kit
 * mcpRecordProblems, signedMcpPinStore); hooks with no grant for their
 * current digest, and grants that match no hook (kit decideHooks,
 * staleHookGrants). Each line says what to run.
 */
async function doctorMigration(line, { fw, cwd }) {
  const env = process.env;
  const { readPins } = await import("./mcp.mjs");
  const pins = readPins(fw, env);
  const valid = pins.filter((p) => p.ok && p.record).map((p) => p.record);
  const repin = kit.mcpRecordProblems(valid);
  for (const p of pins.filter((x) => !x.ok)) {
    const name = p.record?.name ?? path.basename(p.file, ".json");
    line(false, `MCP server ${name}: its admission record (${p.file}) is not valid any more (${p.reason}). Pin it again: ecwctl mcp pin ${name} --containment <file.json> (a remote server: ecwctl mcp pin ${name}), or remove it: ecwctl mcp unpin ${name}`);
  }
  for (const r of repin) {
    line(
      false,
      r.code === "mcp-remote-not-admitted"
        ? `MCP server ${r.name} does not connect: ${r.why}. Pin it again: ecwctl mcp pin ${r.name}`
        : `MCP server ${r.name} does not start: ${r.why}. Pin it again with the folders, programs and hosts it needs: ecwctl mcp pin ${r.name} --containment <file.json>`,
    );
  }
  if (pins.length > 0 && repin.length === 0 && pins.every((x) => x.ok)) {
    line(true, `MCP admission records: all ${pins.length} can start their servers`);
  }
  const { otherHooks } = await import("./session.mjs");
  const { matchGrant, matchHookGrant, staleGrants } = await import("./project-grants.mjs");
  const { resolveGrants, SYSTEM_POLICY_DIR, OPT_OUT_FILENAME } = await import("./opt-outs.mjs");
  const grants = resolveGrants(env).grants;
  const grantFile = `${SYSTEM_POLICY_DIR}/${OPT_OUT_FILENAME}`;
  const hooks = otherHooks({ projectDir: cwd, env });
  let ungranted = 0;
  for (const h of hooks) {
    const repo = h.scope === "project" || h.scope === "local";
    const m = repo
      ? matchGrant({ kind: "hook", file: h.file, event: h.event, matcher: h.matcher, value: h.raw ?? h.command }, cwd, grants.projectHooks)
      : matchHookGrant(h, { home: env.HOME, projectDir: cwd, grants: grants.hooks });
    if (!m.granted) {
      ungranted++;
      line(
        false,
        m.error
          ? `the ${h.event} hook in ${h.file} cannot be granted: ${m.error}`
          : `the ${h.event} hook in ${h.file} (${h.scope}) has no grant for what it is now, so ${repo ? "a launch here is refused" : "a launch at a terminal asks whether to start without it (switching its source off for that session), and a -p or other non-interactive launch is refused"}. If you trust it, an administrator adds this to "${repo ? "projectHooks" : "hooks"}" in ${grantFile} (root-owned): ${JSON.stringify(m.grant)}`,
      );
    }
  }
  const stale = staleGrants(hooks, { home: env.HOME, projectDir: cwd, grants });
  for (const [key, list] of [["projectHooks", stale.projectHooks], ["hooks", stale.hooks]]) {
    for (const g of list) {
      line(null, `the grant ${JSON.stringify(g)} in "${key}" of ${grantFile} matches no hook here now (its hook changed or is gone); an administrator removes it`);
    }
  }
  if (hooks.length > 0 && ungranted === 0) {
    line(true, `hooks: all ${hooks.length} granted for what they are now`);
  }
}

/** doctor: the managed login policy, logins held by an earlier build, and stray watcher processes. */
async function doctorLoginGuard(line) {
  const env = process.env;
  const { managedLoginPolicyStatus } = await import("./managed-login.mjs");
  const { pendingNotice, strayWatchers, sweepLogins, watcherRunning } = await import("./login-watch.mjs");
  const lp = managedLoginPolicyStatus();
  line(
    null,
    lp.installed
      ? `managed login policy: in force (an administrator's choice: plain claude cannot sign in or use a stored login on this machine; Enclawed Code keeps a plaintext login out of Claude Code's storage; sign in with: ecwctl login new)`
      : `managed login policy: not in force (${lp.reason}); Enclawed Code never touches your own Claude Code login`,
  );
  if (lp.installed) {
    // Under the policy: a login that appeared is taken out of Claude Code's reach now, then reported.
    const swept = await sweepLogins({ env, where: "doctor" });
    for (const e of swept.filter((x) => !x.result.ok)) {
      line(false, `a plaintext Claude Code login at ${e.found.file} could not be taken out of plain claude's reach: ${e.result.message}`);
    }
    line(watcherRunning(env) ? true : null, `login watcher: ${watcherRunning(env) ? "running" : "not running (every Enclawed Code launch starts it; to keep it running: ecwctl login watch install)"}`);
  }
  const notice = pendingNotice(env);
  if (notice) {
    line(lp.installed ? false : null, notice);
  }
  for (const w of strayWatchers(env)) {
    line(false, `a login watcher process ${w.pid} (${w.command}) is ${w.why}: stop it with: kill ${w.pid}`);
  }
}

async function doctor(out) {
  let problems = 0;
  const line = (ok, text) => {
    out.write(`${ok === null ? "-" : ok ? "ok " : "!! "} ${text}\n`);
    if (ok === false) {
      problems++;
    }
  };
  out.write(`Enclawed Code ${VERSION} (${APP_ROOT})\n`);
  const claude = locateClaude();
  line(!!claude, claude ? `claude: ${claude}` : "claude: not found on PATH");
  if (claude) {
    const v = claudeVersion(claude);
    line(!!v && versionAtLeast(v, MIN_CLAUDE_VERSION), `claude version ${v ?? "unknown"} (needs ${MIN_CLAUDE_VERSION}+)`);
    // ecwcode passes every argument to claude but its own two launch options
    // (args.mjs); a claude that gained an option of either name would lose it.
    const help = spawnSync(claude, ["--help"], { encoding: "utf8", timeout: 30_000 });
    const clash = ECWCODE_LAUNCH_OPTIONS.filter((o) => new RegExp(`(^|[\\s,])${o}(?![\\w-])`, "m").test(help.stdout ?? ""));
    line(clash.length === 0, clash.length ? `claude now has options named ${clash.join(", ")}; ecwcode takes them as its own launch options` : "no claude option is taken by ecwcode's own launch options (--workflow, --passphrase-fd)");
  }
  const cwd = realpathNearest(process.cwd());
  // The launch's own overlap decision (kit decideProjectOverlap, as prepareLaunch).
  const overlap = kit.decideProjectOverlap({ projectDir: cwd, roots: [{ label: "Enclawed Code's installation", path: APP_ROOT }, { label: "the Enclawed state directory", path: stateDir() }] });
  if (overlap) {
    line(false, `${overlap.message}; Enclawed Code refuses to start a session here`);
  }
  let options = null;
  try {
    const { fw, source } = await loadFramework();
    line(true, `enclawed framework: ${source}`);
    try {
      const p = loadPolicy(fw, { candidates: policyCandidates(process.env, { fw }), flavor: shellFlavor(process.env).flavor });
      options = p.options;
      line(true, `policy: ${p.source}${p.kind ? ` (${p.kind})` : ""} (flavor ${p.flavor}, allowlists ${p.policy.enforceAllowlists ? "enforced" : "not enforced"})`);
      if (p.note) {
        line(false, p.note);
      }
      line(null, `pre-approved irreversible tools: ${[...p.policy.preApprovedIrreversibleTools].join(", ") || "none, so each irreversible call is asked about (to pre-approve a tool: preApprovedIrreversibleTools, with ecwctl policy edit)"}`);
      line(null, `WebFetch hosts allowed without asking: ${[...p.policy.allowedHosts].join(", ") || "none, so a fetch from any host is asked about (to allow one: ecwctl policy add-host <host>)"}`);
      line(null, `on hardware halt: ${p.options.onHardwareHalt.eraseClaudeCredentials ? "erase Enclawed Code's own Claude Code login" : "keep Enclawed Code's own Claude Code login"} (change it: ecwctl policy edit, enclawedCode.onHardwareHalt.eraseClaudeCredentials)`);
      await doctorAdmission(line, { fw, options: p.options, cwd });
      await doctorMigration(line, { fw, cwd });
    } catch (e) {
      line(false, `policy: ${e.message}`);
    }
    line(null, `history: ${historyDir()}`);
    const file = auditLogPath();
    const r = await verifyAuditLog(fw, file);
    line(r.ok, r.empty ? `audit log: ${file} (not created yet: the first session writes it)` : r.ok ? `audit log: ${file} (${r.count} records, verifies)` : `audit log: ${file} does NOT verify: ${r.reason}`);
    const notes = [];
    const orig = console.error;
    console.error = (...a) => notes.push(a.join(" "));
    try {
      await fw.bootHardwareRoot();
      const hw = fw.checkHardwareRootForToolCall("doctor");
      line(hw.allowed, `hardware root: ${fw.hardwareRootInfo().status}${hw.allowed ? "" : ` (${hw.reason})`}`);
    } catch (e) {
      line(false, `hardware root: ${e.message}`);
    } finally {
      console.error = orig;
      fw.closeHardwareRootSession();
    }
  } catch (e) {
    line(false, `enclawed framework: ${e.message}`);
  }
  const state = readAuthState();
  if (state?.method) {
    line(state.keys > 1, `two-factor auth: ${state.securityKeys} FIDO2 security key(s) and ${state.passkeys} device-bound passkey(s) enrolled${state.keys > 1 ? "" : " (enroll a backup: this account's passkey on another device, or a security key: ecwctl auth enroll --security-key --label backup)"}${validTicket() ? "; unlock ticket valid" : ""}`);
  } else {
    const legacy = legacyMethod();
    line(false, `two-factor auth: no security key or passkey enrolled${legacy ? ` (the earlier "${legacy}" method no longer qualifies)` : ""}; every launch is refused until you run: ecwctl auth enroll (this computer's passkey; a security key instead: --security-key)`);
  }
  const ms = managedHooksStatus();
  line(null, `managed hooks: ${ms.installed ? `installed in ${managedSettingsDir()}` : `not installed, which is fine: each ecwcode session adds Enclawed's hooks itself (${ms.reason}); to check plain claude too, an administrator installs them: ecwctl managed print`}`);
  for (const f of legacyManagedHookFiles()) {
    line(false, `${f} runs an earlier release's hook program, which no longer exists: Claude Code blocks every tool call until an administrator replaces it with the output of ecwctl managed print`);
  }
  line(null, modeDoctorLine(effectivePermissionMode([], { managedDocs: readManagedSettings(), env: process.env })));
  line(null, `managed policy: ${fs.existsSync(authority().managedPolicyPath) ? authority().managedPolicyPath : `none: your own policy applies (see ecwctl policy show); an organization's policy would go in ${authority().managedPolicyPath}`}`);
  await doctorLoginGuard(line);
  return problems === 0 ? 0 : 1;
}

async function ctlCommand(args, out, err) {
  const sub = args[0];
  const env = process.env;
  switch (sub) {
    case "doctor":
      parseFlags(args.slice(1), { maxPositionals: 0 });
      return doctor(out);
    case "demo": {
      const { runDemo } = await import("./demo.mjs");
      return runDemo({ args: args.slice(1), out });
    }
    case "conformance": {
      // Enclawed's guarantees, and its adapter invariants through Enclawed Code's own mapping.
      const { flags } = parseFlags(args.slice(1), { bool: ["--json"], maxPositionals: 0 });
      const { runConformance } = await import("./conformance.mjs");
      return runConformance({ json: Boolean(flags["--json"]), out });
    }
    case "version":
      out.write(`${VERSION}\n`);
      return 0;
    case "help":
    case undefined:
      out.write(HELP);
      return 0;
    case "probe": {
      // Ask ecwcode-hook for one PreToolUse decision exactly the way Claude
      // Code would: a session file from this shell's environment, the
      // generated hook command, the event on stdin. Nothing is executed.
      const { positionals, flags } = parseFlags(args.slice(1), { value: ["--mode", "--cwd", "--event", "--transcript"], bool: ["--json"], maxPositionals: 2 });
      if (flags["--event"] !== undefined && flags["--event"] !== "SessionStart") {
        throw new UsageError("probe --event takes SessionStart (PreToolUse is the default)");
      }
      if (positionals.length < 1 && !flags["--event"]) {
        throw new UsageError("usage: ecwctl probe <Tool> ['<tool_input JSON>'] [--mode MODE] [--cwd DIR] [--json]");
      }
      let toolInput = {};
      try {
        toolInput = positionals[1] ? JSON.parse(positionals[1]) : {};
      } catch (e) {
        throw new UsageError(`the tool input is not JSON: ${e.message}`);
      }
      const cwd = path.resolve(flags["--cwd"] ?? process.cwd());
      const { createSession } = await import("./session.mjs");
      const { hookCommand } = await import("./settings.mjs");
      const s = createSession({ env, cwd });
      try {
        const input = flags["--event"]
          ? { session_id: "probe", cwd, hook_event_name: "SessionStart", source: "startup", transcript_path: flags["--transcript"] ? path.resolve(flags["--transcript"]) : null }
          : { session_id: "probe", cwd, permission_mode: flags["--mode"] ?? "default", hook_event_name: "PreToolUse", tool_name: positionals[0], tool_input: toolInput, tool_use_id: `toolu_probe_${Date.now()}` };
        const r = spawnSync("/bin/sh", ["-c", hookCommand({ origin: "launcher", session: s.file, digest: s.digest })], { input: JSON.stringify(input), cwd, env: { ...env, CLAUDE_PROJECT_DIR: cwd }, encoding: "utf8" });
        if (flags["--event"]) {
          out.write(r.status === 0 ? "recorded SessionStart\n" : `error: ${r.stderr.trim()}\n`);
          return r.status === 0 ? 0 : 1;
        }
        const o = JSON.parse(r.stdout || "{}").hookSpecificOutput ?? {};
        out.write(flags["--json"] ? `${r.stdout.trim()}\n` : `${o.permissionDecision ?? "error"}: ${o.permissionDecisionReason ?? r.stderr.trim()}\n`);
        return o.permissionDecision ? 0 : 1;
      } finally {
        fs.rmSync(s.dir, { recursive: true, force: true });
      }
    }
    case "policy": {
      if (!args[1] || args[1] === "help") {
        out.write(POLICY_HELP);
        return args[1] ? 0 : 2;
      }
      const { fw } = await loadFramework();
      const log = audit(fw, env);
      try {
        return await policyCommand(args.slice(1), { out, err, fw, env, audit: (r) => log.append(r) });
      } finally {
        await log.close();
      }
    }
    case "files": {
      // Files changed outside the agent: review, and accept with the person's second factor (file-integrity.mjs).
      const { filesCommand } = await import("./file-integrity.mjs");
      const { audit: log } = await framework(env);
      try {
        return await filesCommand(args.slice(1), { out, err, env, cwd: process.cwd(), audit: (r) => log.append(r) });
      } finally {
        await log.close();
      }
    }
    case "measurement": {
      // After installing or upgrading ecwctl: the person approves the
      // measured code with a code the Enclaweder checks (commitments.mjs).
      if (args[1] !== "approve" || args.length > 2) {
        out.write("usage: ecwctl measurement approve   approve this Enclawed Code's measured code (hook, launcher, framework) with an authenticator code the Enclaweder checks; needed with the hardware root required\n");
        return args[1] === "help" ? 0 : 2;
      }
      const nsRisk = userNamespaceDeviceRisk();
      if (nsRisk) {
        err.write(`ecwctl: not approving: ${nsRisk}\n`);
        return 1;
      }
      const { fw, audit: log } = await framework(env);
      try {
        const { approveCurrent } = await import("./commitments.mjs");
        const { ask } = await import("./cli-util.mjs");
        const r = await approveCurrent({ kind: "measurement", fw, env, readCode: (q) => ask(q), out });
        await log.append({ type: "claude-code.measurement.approved", actor: "enclawed-code", level: null, payload: { digest: r.digest } });
        out.write(`approved by the Enclaweder: Enclawed Code ${r.digest}\n`);
        return 0;
      } catch (e) {
        err.write(`ecwctl: not approved: ${e.message}\n`);
        return 1;
      } finally {
        await log.close();
      }
    }
    case "auth": {
      if (!args[1] || args[1] === "help") {
        out.write(AUTH_HELP);
        return args[1] ? 0 : 2;
      }
      const { fw, loaded, audit: log } = await framework(env);
      try {
        return await authCommand(args.slice(1), { out, err, env, audit: (r) => log.append(r), options: loaded.options });
      } finally {
        await log.close();
      }
    }
    case "skills":
    case "mcp":
    case "trust": {
      if (!args[1] || args[1] === "help") {
        out.write(ADMISSION_HELP);
        return args[1] ? 0 : 2;
      }
      const { fw } = await loadFramework();
      const log = audit(fw, env);
      try {
        return await admissionCommand(sub, args.slice(1), { out, err, fw, env, audit: (r) => log.append(r) });
      } finally {
        await log.close();
      }
    }
    case "login": {
      // Claude Code's login sealed under the Enclaweder (login-seal.mjs); a login made outside Enclawed Code held by the watcher (login-watch.mjs). N16: never from a user namespace with a device visible.
      const { loginCommand } = await import("./login-seal.mjs");
      const nsRisk = ["seal", "resolve", "new"].includes(args[1]) ? userNamespaceDeviceRisk() : null;
      if (nsRisk) {
        err.write(`ecwctl: not sealing: ${nsRisk}\n`);
        return 1;
      }
      const { fw, audit: log } = await framework(env);
      const { holdSessionRoot } = await import("./hardware.mjs");
      try {
        if (["watch", "resolve", "new"].includes(args[1])) {
          const { loginWatchCommand } = await import("./login-watch.mjs");
          return await loginWatchCommand(args.slice(1), { out, err, env, fw, audit: (r) => log.append(r), hold: holdSessionRoot, readCode: (q) => ask(q) });
        }
        return await loginCommand(args.slice(1), { out, err, env, fw, audit: (r) => log.append(r), hold: holdSessionRoot, readCode: (q) => ask(q) });
      } finally {
        await log.close();
      }
    }
    case "review": {
      // The evaluation-only review judge (review.mjs): after the fact, never on the decision path.
      const { reviewCommand, REVIEW_HELP } = await import("./review.mjs");
      if (args[1] === "help") {
        out.write(REVIEW_HELP);
        return 0;
      }
      const { audit: log } = await framework(env);
      try {
        return await reviewCommand(args.slice(1), { out, err, env, audit: (r) => log.append(r) });
      } finally {
        await log.close();
      }
    }
    case "context": {
      // The person's session context and the session tools' credentials, sealed under the Enclaweder (session-state.mjs).
      const { contextCommand } = await import("./session-state.mjs");
      const { audit: log } = await framework(env);
      try {
        return await contextCommand(args.slice(1), { out, err, env, audit: (r) => log.append(r) });
      } finally {
        await log.close();
      }
    }
    case "recover-root": {
      const { fw, loaded, audit: log } = await framework(env);
      try {
        return await recoverRoot(args.slice(1), { out, err, env, fw, audit: (r) => log.append(r), options: loaded.options, readLine: (q) => ask(q) });
      } finally {
        await log.close();
      }
    }
    case "recover-anchor": {
      const { fw, loaded, audit: log } = await framework(env);
      try {
        return await recoverAnchor(args.slice(1), { out, err, env, fw, audit: (r) => log.append(r), options: loaded.options, readLine: (q) => ask(q) });
      } finally {
        await log.close();
      }
    }
    default:
      err.write(`ecwctl: unknown command "${sub}"\n${HELP}`);
      return 2;
  }
}

/**
 * `ecwctl <command> ...`: Enclawed Code's own commands (bin/ecwctl.mjs via
 * src/ctl.mjs). `ecwcode` never reaches this: it passes every argument to claude.
 */
export async function runCtlCommand(argv, out = process.stdout, err = process.stderr) {
  const [first, ...rest] = argv;
  const command = first === undefined || first === "help" || first === "--help" || first === "-h" ? "--help" : first === "version" || first === "--version" || first === "-v" ? "--version" : first;
  const args = rest;
  try {
    // A login made outside Enclawed Code and held by the watcher is resolved by the person: said at every command but the resolving ones.
    if (command !== "--version" && command !== "login") {
      const { pendingNotice } = await import("./login-watch.mjs");
      const notice = pendingNotice();
      if (notice) {
        err.write(`ecwctl: ${notice}\n`);
      }
    }
    switch (command) {
      case "--version":
        out.write(`${VERSION}\n`);
        return 0;
      case "--help":
        out.write(HELP);
        return 0;
      case "history":
        return await history(args, out, err);
      case "audit":
        return await auditCmd(args, out, err);
      case "managed":
        return await managed(args, out, err);
      default:
        return await ctlCommand(argv, out, err);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      err.write(`ecwctl: ${e.message}\n`);
      return 2;
    }
    if (e instanceof AuthError || e instanceof HistoryError) {
      err.write(`ecwctl: ${e.message}\n`);
      return 1;
    }
    // A framework that cannot load, or anything else: a clear message, never an unhandled rejection.
    err.write(`ecwctl: ${e?.message ?? String(e)}\n`);
    return 1;
  }
}
