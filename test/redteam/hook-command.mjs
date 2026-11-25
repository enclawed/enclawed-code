#!/usr/bin/env node
// Print the hook command line the Enclawed Code launcher would put in its
// generated settings for this environment and project (writing the session
// file it names). Red-team harnesses run the hook through it, exactly as
// Claude Code does.   Usage: node hook-command.mjs <project-dir>
import { createSession } from "../../src/session.mjs";
import { hookCommand } from "../../src/settings.mjs";

const s = createSession({ env: process.env, cwd: process.argv[2] ?? process.cwd() });
process.stdout.write(hookCommand({ origin: "launcher", session: s.file, digest: s.digest }));
