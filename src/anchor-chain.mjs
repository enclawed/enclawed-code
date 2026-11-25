// The audit log's anchor chain is followed, and the anchor files guarded, by
// Enclawed's adapter kit (anchor-chain.ts: followChain, anchorFilesGuard,
// AnchorTamper with a closed reason). Enclawed Code names no rule of its own.

import { kit } from "./kit.mjs";

export const AnchorTamper = kit.AnchorTamper;
export const followChain = (file) => kit.followChain(file);
export const anchorFilesGuard = (anchorPath, historyPath) => kit.anchorFilesGuard(anchorPath, historyPath);
