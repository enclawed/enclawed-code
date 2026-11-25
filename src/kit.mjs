// The Enclawed adapter kit (enclawed-oss src/enclawed/adapter), loaded once
// from the framework's public entry point (framework.mjs). Every security
// decision Enclawed Code applies is made by these functions; Enclawed Code only
// maps Claude Code's hook input, settings and tool names onto them.

import { loadFramework } from "./framework.mjs";

const { fw } = await loadFramework();

/** The framework's `adapterKit` namespace. */
export const kit = fw.adapterKit;

/** The framework's `containment` namespace (what a session launches runs contained). */
export const containment = fw.containment;

/** The framework itself (policy, history, audit, hardware root). */
export const framework = fw;
