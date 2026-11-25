// The words of a shell command that may name files (the kit's pathWords).
// Which reads and commands may reach Enclawed Code's or Claude Code's secrets
// is decided by Enclawed's adapter kit (kit.decidePreAction, secretPaths).

import { kit } from "./kit.mjs";

export const pathWords = (command) => kit.pathWords(typeof command === "string" ? command : "");
