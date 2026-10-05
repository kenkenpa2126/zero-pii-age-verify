// Smoke test: issue -> present -> verify, plus tamper cases. Run: npx tsx src/smoke.ts
import {
  b64uDecode,
  b64uEncode,
  generateSigningKeypair,
  issueCredential,
  presentCredential,
  verifyPresentation,
  type IssuedCredential,
} from "./lib/sdjwt.ts";

const issuer = await generateSigningKeypair();
const holder = await generateSigningKeypair();
let pass = 0;
let fail = 0;

function check(name: string, fn: () => Promise<void>) {
  return fn()
    .then(() => {
      pass++;
      console.log(`  ok   ${name}`);
    })
    .catch((e: unknown) => {
      fail++;
      console.log(`  FAIL ${name}: ${e instanceof Error ? e.message : e}`);
    });
}

/** Negative test: the promise must reject with `wantMsg`. */
function checkReject(name: string, wantMsg: string, fn: () => Promise<void>) {
  return fn()
    .then(() => {
      fail++;
      console.log(`  FAIL ${name}: should have been rejected`);
    })
    .catch((e: unknown) => {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes(wantMsg)) {
        pass++;
        console.log(`  ok   ${name} (rejected: ${msg})`);
      } else {
        fail++;
        console.log(`  FAIL ${name}: rejected but wrong reason: ${msg}`);
      }
    });
}

console.log("== zero-pii core smoke test ==");

let cred: IssuedCredential;
await check("issue + present over20 only + verify", async () => {
  cred = await issueCredential({
    issuer,
    issuerName: "demo-trust-root",
    holderPubJwk: holder.publicKeyJwk,
    vcId: "vc-0001",
    ttlSec: 3600,
    statusIdx: 0,
    claims: { over20: true, name: "山田 太郎", address: "東京都千代田区1-2-3", birthdate: "1990-01-01" },
  });
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  });
  const result = await verifyPresentation({
    presentation,
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
  const keys = Object.keys(result.claims);
  if (keys.length !== 1 || keys[0] !== "over20") {
    throw new Error(`verifier saw extra claims: ${keys.join(",")}`);
  }
  if (result.claims["over20"] !== true) throw new Error("over20 should be true");
});

await checkReject("wrong nonce is rejected", "nonce mismatch", async () => {
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  });
  await verifyPresentation({
    presentation,
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "different-nonce",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("presentation replay across audiences is rejected", "audience mismatch", async () => {
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-xyz",
    aud: "evil-site",
  });
  await verifyPresentation({
    presentation,
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-xyz",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("tampered disclosure is rejected", 'claim "name" does not match', async () => {
  // attacker flips the revealed value inside a disclosure
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["name"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  });
  const parts = presentation.split("~");
  const disc = JSON.parse(new TextDecoder().decode(b64uDecode(parts[1]!)));
  disc[2] = "偽物 氏名";
  parts[1] = b64uEncode(JSON.stringify(disc));
  await verifyPresentation({
    presentation: parts.join("~"),
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("credential used from another device fails key binding", "key binding", async () => {
  const thief = await generateSigningKeypair();
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder: thief,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  });
  await verifyPresentation({
    presentation,
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("expired credential is rejected", "expired", async () => {
  const shortLived = await issueCredential({
    issuer,
    issuerName: "demo-trust-root",
    holderPubJwk: holder.publicKeyJwk,
    vcId: "vc-0002",
    ttlSec: -10,
    statusIdx: 0,
    claims: { over20: true },
  });
  const presentation = await presentCredential({
    credential: shortLived,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  });
  await verifyPresentation({
    presentation,
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
