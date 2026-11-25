#!/usr/bin/env node
// The hook, as the test suite runs it in managed mode: `bin/ecwcode-hook.mjs`
// plus the suite's stand-in authority (src/authority.mjs setTestAuthority),
// passed as the first argument (JSON): the managed-settings directory and the
// home a managed hook runs in are the sandbox's, never the account's. A
// function call, not an environment variable or a file (see launcher-entry.mjs).
import { setTestAuthority } from "../../src/authority.mjs";

const [cfg, ...argv] = process.argv.slice(2);
setTestAuthority(JSON.parse(cfg));
const { main } = await import("../../src/hook.mjs");
await main(argv);
