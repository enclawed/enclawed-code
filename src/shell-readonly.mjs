// The strict read-only shell allowlist is Enclawed's (the adapter kit's
// shell-readonly: a getopt-exact parser, ported from Enclawed Code). These are
// the kit's functions, for Enclawed Code's CLI and tests.

import { kit } from "./kit.mjs";

export const splitSimpleCommand = (command) => kit.splitSimpleCommand(command);
export const classifyShellCommand = (command) => kit.classifyShellCommand(command);
export const classifyPowerShellCommand = (command) => kit.classifyPowerShellCommand(command);
export const gitConfigRisk = (cwd) => kit.gitConfigRiskOf(cwd);
export const abbreviatesRefused = (name, exact = null) => kit.abbreviatesRefused(name, exact);
