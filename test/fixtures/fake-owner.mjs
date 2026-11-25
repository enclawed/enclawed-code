#!/usr/bin/env node
// A stand-in for the process that owns the Enclaweder: it speaks the
// framework's owner/client socket protocol (one JSON request per line) and
// reports the health it is told to. No device is involved.
//   node fake-owner.mjs <socket> <CLEAN|DIRTY|UNAVAILABLE|HALT|SILENT>
import fs from "node:fs";
import net from "node:net";

const [sock, state] = process.argv.slice(2);
fs.rmSync(sock, { force: true });
const server = net.createServer((c) => {
  let buf = "";
  c.on("error", () => {});
  c.on("data", (d) => {
    buf += d;
    for (let nl = buf.indexOf("\n"); nl >= 0; nl = buf.indexOf("\n")) {
      const req = JSON.parse(buf.slice(0, nl));
      buf = buf.slice(nl + 1);
      if (state === "SILENT") {
        continue;
      }
      let res;
      if (state === "HALT") {
        res = { id: req.id, ok: false, halt: true, error: "latched DIRTY by an earlier tamper" };
      } else if (req.op === "members") {
        res = { id: req.id, ok: true, members: [{ uid: "00", pubkey: "11", serial: "ENCLW-FAKE" }] };
      } else if (req.op === "health") {
        res = {
          id: req.id,
          ok: true,
          health: state === "CLEAN" ? { status: "CLEAN" } : { status: state, reason: "device removed" },
        };
      } else {
        res = { id: req.id, ok: false, error: "bad request" };
      }
      c.write(`${JSON.stringify(res)}\n`);
    }
  });
});
server.listen(sock, () => process.stdout.write("ready\n"));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
