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
import { isOverAgeThreshold, parseBirthdate } from "./server/age.ts";

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
    claims: { over20: true },
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

await check("credential and presentation do not serialize raw PII", async () => {
  const pii = ["山田 太郎", "東京都千代田区1-2-3", "1990-01-01"];
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-no-pii",
    aud: "mini-sake-shop",
  });
  const serialized = JSON.stringify(cred) + presentation;
  for (const value of pii) {
    if (serialized.includes(value)) throw new Error(`serialized credential contains ${value}`);
  }
  const disclosedClaims = cred!.disclosures.map((d) => d.claim).join(",");
  if (disclosedClaims !== "over20") throw new Error(`unexpected disclosures: ${disclosedClaims}`);
});

await check("valid leap day is accepted", async () => {
  const parsed = parseBirthdate("2004-02-29");
  if (parsed.month !== 2 || parsed.day !== 29) throw new Error("valid leap day rejected");
});

await checkReject("invalid leap day is rejected", "invalid day", async () => {
  parseBirthdate("2021-02-29");
});

await checkReject("invalid month is rejected", "invalid month", async () => {
  parseBirthdate("2021-13-01");
});

await checkReject("invalid day is rejected", "invalid day", async () => {
  parseBirthdate("2020-02-31");
});

await check("age threshold is inclusive on the birthday", async () => {
  const now = new Date(2026, 9, 6);
  if (!isOverAgeThreshold("2006-10-06", now)) throw new Error("exact threshold should pass");
  if (isOverAgeThreshold("2006-10-07", now)) throw new Error("one day below threshold should fail");
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

await checkReject("wrong issuer key is rejected", "issuer signature verification failed", async () => {
  const otherIssuer = await generateSigningKeypair();
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  });
  await verifyPresentation({
    presentation,
    issuerPubJwk: otherIssuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
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

await checkReject("tampered disclosure is rejected", 'claim "over20" does not match', async () => {
  // attacker flips the revealed value inside a disclosure
  const presentation = await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  });
  const parts = presentation.split("~");
  const disc = JSON.parse(new TextDecoder().decode(b64uDecode(parts[1]!)));
  disc[2] = false;
  parts[1] = b64uEncode(JSON.stringify(disc));
  await verifyPresentation({
    presentation: parts.join("~"),
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

function replaceJwtHeader(jwt: string, header: Record<string, unknown>): string {
  const [, payload, sig] = jwt.split(".");
  return `${b64uEncode(JSON.stringify(header))}.${payload}.${sig}`;
}

function replaceJwtPayload(jwt: string, payload: Record<string, unknown>): string {
  const [header, , sig] = jwt.split(".");
  return `${header}.${b64uEncode(JSON.stringify(payload))}.${sig}`;
}

await checkReject("tampered credential payload is rejected", "issuer signature verification failed", async () => {
  const parts = (await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  })).split("~");
  const [, payload] = parts[0]!.split(".");
  const parsed = JSON.parse(new TextDecoder().decode(b64uDecode(payload!))) as Record<string, unknown>;
  parts[0] = replaceJwtPayload(parts[0]!, { ...parsed, jti: "vc-tampered" });
  await verifyPresentation({
    presentation: parts.join("~"),
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("unsupported credential alg is rejected", "unsupported JWT alg", async () => {
  const parts = (await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  })).split("~");
  parts[0] = replaceJwtHeader(parts[0]!, { alg: "none", typ: "SD-JWT" });
  await verifyPresentation({
    presentation: parts.join("~"),
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("unexpected credential typ is rejected", "unexpected JWT typ", async () => {
  const parts = (await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  })).split("~");
  parts[0] = replaceJwtHeader(parts[0]!, { alg: "ES256", typ: "JWT" });
  await verifyPresentation({
    presentation: parts.join("~"),
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("unsupported KB-JWT alg is rejected", "unsupported JWT alg", async () => {
  const parts = (await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  })).split("~");
  parts[parts.length - 1] = replaceJwtHeader(parts.at(-1)!, { alg: "none", typ: "kb+jwt" });
  await verifyPresentation({
    presentation: parts.join("~"),
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("unexpected KB-JWT typ is rejected", "unexpected JWT typ", async () => {
  const parts = (await presentCredential({
    credential: cred!,
    reveal: ["over20"],
    holder,
    nonce: "nonce-abc",
    aud: "mini-sake-shop",
  })).split("~");
  parts[parts.length - 1] = replaceJwtHeader(parts.at(-1)!, { alg: "ES256", typ: "JWT" });
  await verifyPresentation({
    presentation: parts.join("~"),
    issuerPubJwk: issuer.publicKeyJwk,
    expectedNonce: "nonce-abc",
    expectedAud: "mini-sake-shop",
  });
});

await checkReject("malformed credential is rejected", "malformed", async () => {
  await verifyPresentation({
    presentation: "not-a-jwt~not-a-disclosure~not-a-kb-jwt",
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
