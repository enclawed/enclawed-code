#!/usr/bin/env node
// ecwctl, as the test suite runs it: `bin/ecwctl.mjs` plus the
// suite's stand-in authority (src/authority.mjs setTestAuthority), passed as
// the first argument (JSON). A function call, not an environment variable or
// a file: a user install has no way to reach it, and the published package
// ships no test/ directory. Everything after the first argument is the
// command line of ecwctl.
import { setTestAuthority } from "../../src/authority.mjs";

const [cfg, ...argv] = process.argv.slice(2);
setTestAuthority(JSON.parse(cfg));
const { main } = await import("../../src/ctl.mjs");
await main(argv);
