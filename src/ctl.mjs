// ecwctl: Enclawed Code's own commands (history, audit, managed, doctor,
// policy, auth, ...). `ecwcode` is Claude Code itself and reserves no word,
// so these live in their own program (admin.mjs runCtlCommand).

import { launchAuthority } from "./launcher.mjs";
import { replaceEnvInPlace } from "./env-authority.mjs";
import { setProgram } from "./program.mjs";

export async function main(argv = process.argv.slice(2), env = { ...process.env }) {
  setProgram("ecwctl");
  // The commands load the framework in this process: it reads process.env,
  // so only the resolved, allowlisted variables stay there (as for a launch).
  const auth = launchAuthority(env);
  if (!auth.ok) {
    process.stderr.write(`ecwctl: ${auth.message}\n`);
    process.exit(2);
  }
  replaceEnvInPlace(process.env, auth.env);
  try {
    const { runCtlCommand } = await import("./admin.mjs");
    process.exit(await runCtlCommand(argv));
  } catch (err) {
    process.stderr.write(`ecwctl: ${err?.message ?? String(err)}\n`);
    process.exit(1);
  }
}
