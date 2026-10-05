// Integration test: boots the real Hono app on an ephemeral port and walks the
// full flow: issue -> verify -> replay-protection -> revoke -> legacy compare.
// Run: npm run e2e
process.env.ZEROPII_DEV = "1";

import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";
import { app } from "./server/index.ts";
import { store } from "./server/store.ts";
import {
  generateSigningKeypair,
  presentCredential,
  type IssuedCredential,
} from "./lib/sdjwt.ts";

await store.init();
const server = serve({ fetch: app.fetch, port: 0 });
const port = (server.address() as AddressInfo).port;
const B = `http://localhost:${port}`;
const AUD = "mini-sake-shop";
const ADMIN_TOKEN = "dev-admin-token";

let pass = 0;
let fail = 0;

function ok(name: string): void {
  pass++;
  console.log(`  ok   ${name}`);
}

function bad(name: string, msg: unknown): void {
  fail++;
  console.log(`  FAIL ${name}: ${msg instanceof Error ? msg.message : msg}`);
}

async function post(
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await fetch(`${B}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

const holder = await generateSigningKeypair();
const license = { birthdate: "1990-01-01" };
const legacyPii = { name: "山田 太郎", birthdate: "1995-04-01", address: "東京都千代田区1-2-3" };

console.log("== e2e ==");

// 1. health
{
  const res = await fetch(`${B}/api/health`);
  res.ok ? ok("GET /api/health") : bad("GET /api/health", res.status);
}

// 2. dev issue
let cred: IssuedCredential;
try {
  const { status, json } = await post("/api/dev/issue", { holderPubJwk: holder.publicKeyJwk, license });
  if (status !== 200 || !json.vcId) throw new Error(JSON.stringify(json));
  cred = { vcId: String(json.vcId), token: String(json.token), disclosures: json.disclosures as IssuedCredential["disclosures"] };
  ok(`POST /api/dev/issue -> ${cred.vcId}`);
} catch (e) {
  bad("POST /api/dev/issue", e);
  process.exit(1);
}

// 3. issued credential stores only the age predicate
try {
  const claims = cred!.disclosures.map((d) => d.claim);
  if (claims.length !== 1 || claims[0] !== "over20") throw new Error(`unexpected claims: ${claims.join(",")}`);
  const serialized = JSON.stringify(cred);
  for (const pii of [legacyPii.name, legacyPii.address, license.birthdate]) {
    if (serialized.includes(pii)) throw new Error(`credential serialized raw PII: ${pii}`);
  }
  ok("issued credential contains only the age predicate");
} catch (e) {
  bad("credential minimization", e);
}

// 4. invalid DOBs are rejected
for (const [birthdate, reason] of [
  ["2021-02-29", "invalid leap day"],
  ["2021-13-01", "invalid month"],
  ["2020-02-31", "invalid day"],
  ["not-a-date", "malformed date"],
] as const) {
  try {
    const { status } = await post("/api/dev/issue", { holderPubJwk: holder.publicKeyJwk, license: { birthdate } });
    if (status !== 400) throw new Error(`${reason} should be rejected`);
    ok(`DOB validation rejects ${reason}`);
  } catch (e) {
    bad(`DOB validation: ${reason}`, e);
  }
}

// 5. credential identifiers are unique
try {
  const { status, json } = await post("/api/dev/issue", { holderPubJwk: holder.publicKeyJwk, license });
  if (status !== 200 || !json.vcId) throw new Error(JSON.stringify(json));
  if (String(json.vcId) === cred!.vcId) throw new Error(`duplicate vcId: ${cred!.vcId}`);
  ok(`second credential has a distinct vcId (${String(json.vcId)})`);
} catch (e) {
  bad("unique credential ids", e);
}

// 6. verify (only over20 travels)
try {
  const { nonce: nonceJson } = (await (await fetch(`${B}/api/nonce?aud=${AUD}`)).json()) as { nonce: string };
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: nonceJson,
    aud: AUD,
  });
  for (const pii of [legacyPii.name, legacyPii.address, license.birthdate]) {
    if (presentation.includes(pii)) throw new Error(`presentation serialized raw PII: ${pii}`);
  }
  const { status, json } = await post("/api/shop/verify", { presentation, nonce: nonceJson });
  if (status !== 200 || !json.ok) throw new Error(JSON.stringify(json));
  const claims = json.claims as Record<string, unknown>;
  const keys = Object.keys(claims);
  if (keys.length !== 1 || keys[0] !== "over20" || claims["over20"] !== true) {
    throw new Error(`verifier saw: ${keys.join(",")}`);
  }
  ok("verify passes and verifier only saw {over20: true}");
} catch (e) {
  bad("verify", e);
}

// 7. nonce is one-time
try {
  const { nonce: nonceJson } = (await (await fetch(`${B}/api/nonce?aud=${AUD}`)).json()) as { nonce: string };
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: nonceJson,
    aud: AUD,
  });
  const first = await post("/api/shop/verify", { presentation, nonce: nonceJson });
  const second = await post("/api/shop/verify", { presentation, nonce: nonceJson });
  if (first.status !== 200) throw new Error("first use should pass");
  if (second.status === 200) throw new Error("replay with same nonce should fail");
  ok("nonce is one-time (replay rejected)");
} catch (e) {
  bad("nonce one-time", e);
}

// 8. legacy compare
try {
  const { status, json } = await post("/api/shop/verify/legacy", {
    ...legacyPii,
    phone: "090-XXXX-XXXX",
  });
  if (status !== 200 || json.receivedPii !== true) throw new Error(JSON.stringify(json));
  ok("legacy endpoint receives full PII (for comparison)");
} catch (e) {
  bad("legacy compare", e);
}

// 9. unauthorized revocation is rejected
try {
  const { status, json } = await post("/api/admin/revoke", { vcId: cred!.vcId });
  if (status !== 401 || json.error !== "admin token required") throw new Error(JSON.stringify({ status, json }));
  ok("revocation endpoint requires an admin token");
} catch (e) {
  bad("unauthorized revocation", e);
}

// 10. revoke then verify -> rejected
try {
  const { status: rStatus } = await post(
    "/api/admin/revoke",
    { vcId: cred!.vcId },
    { Authorization: `Bearer ${ADMIN_TOKEN}` },
  );
  if (rStatus !== 200) throw new Error(`revoke failed: ${rStatus}`);
  const { nonce: nonceJson } = (await (await fetch(`${B}/api/nonce?aud=${AUD}`)).json()) as { nonce: string };
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: nonceJson,
    aud: AUD,
  });
  const { status, json } = await post("/api/shop/verify", { presentation, nonce: nonceJson });
  if (status !== 403 || json.error !== "credential revoked") throw new Error(JSON.stringify(json));
  ok("revoked credential is rejected at verification");
} catch (e) {
  bad("revocation", e);
}

// 11. log shows the contrast
try {
  const { entries } = (await (await fetch(`${B}/api/shop/log`)).json()) as {
    entries: { kind: string; received: Record<string, unknown> }[];
  };
  const zpi = entries.find((e) => e.kind === "zpi");
  const legacy = entries.find((e) => e.kind === "legacy");
  if (!zpi || !legacy) throw new Error("log entries missing");
  if (Object.keys(zpi.received).length !== 1) throw new Error(`zpi received ${JSON.stringify(zpi.received)}`);
  if (Object.keys(legacy.received).length !== 4) throw new Error(`legacy received ${JSON.stringify(legacy.received)}`);
  ok("server log: zero-PII=1 claim vs legacy=4 PII fields");
} catch (e) {
  bad("log contrast", e);
}

// 12. status list remains available without a public issuance ledger
try {
  const ledgerRes = await fetch(`${B}/api/ledger`);
  if (ledgerRes.status !== 404) throw new Error(`ledger endpoint should be removed, got ${ledgerRes.status}`);
  const statusRes = await fetch(`${B}/api/status-list`);
  const statusJson = (await statusRes.json()) as { bits?: string };
  if (!statusRes.ok || typeof statusJson.bits !== "string") throw new Error("status list missing");
  ok("revocation uses status list without exposing a public issuance ledger");
} catch (e) {
  bad("ledger removal", e);
}

server.close();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
