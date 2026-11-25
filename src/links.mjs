// Hard links and bind mounts onto Enclawed Code's protected files, decided by
// Enclawed's adapter kit (fs-probe: FsProbe.hardLink, protectedInodeIndex,
// writeProtectedInodeIndex). Enclawed Code only says where its launch-time index
// is kept (its session directory, which the agent may not write).

import { kit } from "./kit.mjs";

/** Write the protected inode index at launch; its digest goes into the session file. */
export function writeProtectedInodeIndex(prot, file) {
  return kit.writeProtectedInodeIndex(prot, file);
}

/** The protected inodes (the launch-time index while its digest matches, plus a live walk of the state first). */
export function protectedInodeIndex(prot) {
  return kit.protectedInodeIndex(prot ?? { paths: [], prefixes: [] });
}

/** The hard-link verdict for a write target (its realpath): the kit's FsProbe.hardLink. */
export function hardLinkVerdict(realPath, { protected: prot, projectDir, budget }) {
  const probe = kit.nodeFsProbe(budget ? { budget } : {});
  return probe.hardLink(realPath, prot ?? null, projectDir ? { projectDir, isExecConfig: (p) => kit.isExecConfigPath(p) } : null);
}
