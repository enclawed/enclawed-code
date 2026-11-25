#!/usr/bin/env node
// The stdio MCP server Claude Code starts for each admitted server (see src/mcp-proxy.mjs).
import { main } from "../src/mcp-proxy.mjs";

await main();
