import "./isolation-guard.mjs"; // first: refuses unless no Enclaweder is reachable
// The remote MCP credential store's refusals reach Enclawed Code's audit log
// (the kit's remoteCredentialStore audit; src/mcp.mjs remoteCredentialStoreFor):
// a stored record that does not open is refused by name and recorded, with no
// secret in the record.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { remoteCredentialDir, remoteCredentialStoreFor } from "../src/mcp.mjs";
import { auditRecords, sandbox } from "./helpers.mjs";

let sb;
before(() => {
  sb = sandbox();
});
after(() => sb.cleanup());

test("a stored remote credential that does not open is refused and the refusal is audited (no secret)", async () => {
  const url = "https://mcp.remote.test/mcp";
  const rec = {
    v: 1,
    resource: url,
    origin: "https://mcp.remote.test",
    issuer: "https://auth.remote.test",
    tokenEndpoint: "https://auth.remote.test/token",
    client: { clientId: "c1", registered: true },
    tokens: { accessToken: "access-token-AUDIT-SECRET", refreshToken: "refresh-AUDIT-SECRET", expiresAt: null },
  };
  const store = await remoteCredentialStoreFor(sb.env);
  store.set(url, rec);
  const dir = remoteCredentialDir(sb.env);
  const f = path.join(dir, fs.readdirSync(dir).find((x) => x.endsWith(".json")));
  const sealed = JSON.parse(fs.readFileSync(f, "utf8"));
  const data = Buffer.from(sealed.data, "base64");
  data[0] ^= 1;
  fs.writeFileSync(f, JSON.stringify({ ...sealed, data: data.toString("base64") }));
  assert.throws(() => store.get(url), /do not open/);
  await store.settled();
  const refused = auditRecords(sb).filter((r) => r.type === "claude-code.auth.remote-credential.refused");
  assert.equal(refused.length, 1);
  assert.deepEqual(refused[0].payload, { origin: "https://mcp.remote.test", code: "remote-credential-mismatch", reason: "does-not-open", keyKind: "file" });
  assert.ok(!JSON.stringify(auditRecords(sb)).includes("AUDIT-SECRET"));
});
