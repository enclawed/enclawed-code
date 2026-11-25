// Launcher-level PoCs with the fake claude (no model).
//   I10 managedHookInstalled() is a substring test: any managed-settings file or
//       drop-in that merely MENTIONS "ecwcode-hook" (a deny rule, a note, a
//       hook for one tool only, a hook disabled by another key) makes the
//       launcher inject no hooks at all.
//   I11 `ecwcode agents` is passed through as a non-session command, without
//       --settings, but `claude agents` dispatches sessions from its agent view.
import fs from "node:fs";
import path from "node:path";
import { prepareLaunch } from "../../../src/launcher.mjs";
import { ecwcode, result, sandbox } from "./lib.mjs";

{
  const sb = sandbox("managed");
  const cases = {
    denyRule: { permissions: { deny: ["Bash(ecwcode-hook *)"] } },
    oneToolOnly: { hooks: { PreToolUse: [{ matcher: "WebFetch", hooks: [{ type: "command", command: "/opt/enclawed-code/bin/ecwcode-hook --origin managed" }] }] } },
    commentLike: { "$comment": "TODO: roll out ecwcode-hook next quarter" },
  };
  let hits = 0;
  for (const [name, doc] of Object.entries(cases)) {
    const dir = path.join(sb.dir, `managed-${name}`);
    fs.mkdirSync(path.join(dir, "managed-settings.d"), { recursive: true });
    fs.writeFileSync(path.join(dir, "managed-settings.d", "50-note.json"), JSON.stringify(doc));
    const plan = prepareLaunch(["-p", "hi"], { env: sb.env, cwd: sb.project, managedDir: dir });
    // The launcher injects its hooks unless the managed settings really run them.
    const injected = plan.ok && plan.session && !plan.managed;
    console.log(`  ${name}: hooks injected by launcher: ${injected}`);
    if (!injected) hits++;
  }
  result("I10", hits > 0, `${hits}/${Object.keys(cases).length} managed files that only mention ecwcode-hook switch the launcher's hooks off`);
  sb.cleanup();
}

{
  const sb = sandbox("agents");
  const out = path.join(sb.dir, "rec.json");
  ecwcode(sb, ["agents"], { FAKE_CLAUDE_OUT: out });
  const rec = JSON.parse(fs.readFileSync(out, "utf8"));
  console.log(`  ecwcode agents -> claude argv ${JSON.stringify(rec.argv)}; ECWCODE_SESSION=${rec.env.ECWCODE_SESSION}`);
  result("I11", !rec.argv.includes("--settings"), "`ecwcode agents` starts the agent view (which dispatches sessions) without Enclawed's hooks, silently");
  sb.cleanup();
}
