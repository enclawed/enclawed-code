#!/usr/bin/env node
// The command Claude Code runs for each hook event (see src/hook.mjs).
import { main } from "../src/hook.mjs";

await main();
