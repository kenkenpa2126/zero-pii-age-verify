import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { serveStatic } from "@hono/node-server/serve-static";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { b64uDecode, b64uEncode, issueCredential, verifyPresentation } from "../lib/sdjwt.ts";
import { store } from "./store.ts";

export const app = new Hono();
const enc = new TextEncoder();
const dec = new TextDecoder();

type RegResp = Parameters<typeof verifyRegistrationResponse>[0]["response"];
type AuthResp = Parameters<typeof verifyAuthenticationResponse>[0]["response"];

const SHOP_AUD = "mini-sake-shop";
const DEV_ADMIN_TOKEN = "dev-admin-token";

function clientDataChallenge(resp: { clientDataJSON: string }): string {
  try {
    const data = JSON.parse(dec.decode(b64uDecode(resp.clientDataJSON))) as { challenge?: string };
    return data.challenge ?? "";
  } catch {
    return "";
  }
}

function siteOrigin(c: { req: { url: string } }): string {
  return new URL(c.req.url).origin;
}

function rpId(c: { req: { url: string } }): string {
  return new URL(c.req.url).hostname;
}

function adminToken(): string | undefined {
  return process.env.ZEROPII_ADMIN_TOKEN || (process.env.ZEROPII_DEV ? DEV_ADMIN_TOKEN : undefined);
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  let diff = ab.length ^ bb.length;
  const len = Math.max(ab.length, bb.length);
  for (let i = 0; i < len; i++) diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}

function isOver20(birthdate: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(birthdate);
  if (!m) return false;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return false;
  const now = new Date();
  const cutoff = new Date(now.getFullYear() - 20, now.getMonth(), now.getDate());
  return new Date(y, mo - 1, d) <= cutoff;
}

interface IssueBody {
  holderPubJwk?: JsonWebKey;
  license?: { name?: string; birthdate?: string; address?: string };
}

async function issueFor(holderPubJwk: JsonWebKey, license: IssueBody["license"]) {
  const name = license?.name?.trim();
  const birthdate = license?.birthdate?.trim();
  const address = license?.address?.trim();
  if (!name || !birthdate || !address) throw new Error("license fields (name/birthdate/address) are required");
  if (!holderPubJwk?.kty) throw new Error("holderPubJwk is required");

  const vcId = store.nextVcId();
  const statusIdx = store.nextStatusIdx++;
  const issued = await issueCredential({
    issuer: store.issuer,
    issuerName: store.issuerName,
    holderPubJwk,
    vcId,
    ttlSec: 3600,
    statusIdx,
    claims: {
      over20: isOver20(birthdate),
      name,
      birthdate,
      address,
    },
  });
  await store.recordIssuance(vcId, statusIdx);
  console.log(`[issue] ${vcId} -> statusIdx=${statusIdx} over20=${issued.disclosures[0]?.value}`);
  return { vcId, token: issued.token, disclosures: issued.disclosures };
}

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

app.get("/api/health", (c) => c.json({ ok: true, name: "zero-pii-age-verify", issuer: store.issuerName }));

// ---------------------------------------------------------------------------
// passkey auth (wallet unlock)
// ---------------------------------------------------------------------------

app.post("/api/passkey/register/options", async (c) => {
  const { userName } = await c.req.json<{ userName?: string }>();
  const name = userName?.trim() || "yamada";
  const user = store.users.get(name) ?? { userId: crypto.randomUUID(), userName: name, credentials: [] };
  store.users.set(name, user);
  const options = await generateRegistrationOptions({
    rpName: "zero-pii demo",
    rpID: rpId(c),
    userID: enc.encode(user.userId),
    userName: name,
    attestationType: "none",
    excludeCredentials: user.credentials.map((cr) => ({ id: cr.id })),
  });
  store.putChallenge(options.challenge, name, "reg");
  return c.json(options);
});

app.post("/api/passkey/register/verify", async (c) => {
  const body = await c.req.json<{ userName?: string; response: RegResp }>();
  const name = body.userName?.trim() || "yamada";
  const challenge = clientDataChallenge(body.response.response);
  const challengeEntry = store.takeChallenge(challenge);
  if (!challengeEntry || challengeEntry.kind !== "reg") {
    return c.json({ error: "challenge not found or expired" }, 400);
  }
  const user = store.users.get(name);
  if (!user) return c.json({ error: "user missing" }, 400);
  const verification = await verifyRegistrationResponse({
    response: body.response,
    expectedChallenge: challenge,
    expectedOrigin: siteOrigin(c),
    expectedRPID: rpId(c),
    requireUserVerification: false,
  });
  if (!verification.verified || !verification.registrationInfo) {
    return c.json({ error: "registration verification failed" }, 400);
  }
  // v14 shape with fallback for older shapes
  const ri = verification.registrationInfo as unknown as {
    credential?: { id: string; publicKey: Uint8Array; counter: number };
    credentialID?: Uint8Array;
    credentialPublicKey?: Uint8Array;
    counter?: number;
  };
  const cred = ri.credential ?? {
    id: b64uEncode(ri.credentialID!),
    publicKey: ri.credentialPublicKey!,
    counter: ri.counter ?? 0,
  };
  user.credentials.push({ id: cred.id, publicKeyB64: b64uEncode(cred.publicKey), counter: cred.counter });
  store.persist();
  const sid = store.newSession(name);
  setCookie(c, "sid", sid, { httpOnly: true, sameSite: "Lax", path: "/" });
  return c.json({ ok: true, userName: name });
});

app.post("/api/passkey/login/options", async (c) => {
  const { userName } = await c.req.json<{ userName?: string }>();
  const name = userName?.trim() || "yamada";
  const user = store.users.get(name);
  const options = await generateAuthenticationOptions({
    rpID: rpId(c),
    allowCredentials: user?.credentials.map((cr) => ({ id: cr.id })) ?? [],
  });
  store.putChallenge(options.challenge, name, "auth");
  return c.json(options);
});

app.post("/api/passkey/login/verify", async (c) => {
  const body = await c.req.json<{ userName?: string; response: AuthResp }>();
  const name = body.userName?.trim() || "yamada";
  const challenge = clientDataChallenge(body.response.response);
  const challengeEntry = store.takeChallenge(challenge);
  if (!challengeEntry || challengeEntry.kind !== "auth") {
    return c.json({ error: "challenge not found or expired" }, 400);
  }
  const user = store.users.get(challengeEntry.userName);
  if (!user) return c.json({ error: "user missing" }, 400);
  const credentialId = body.response?.id;
  const stored = user.credentials.find((cr) => cr.id === credentialId);
  if (!stored) return c.json({ error: "unknown credential" }, 400);
  const verification = await verifyAuthenticationResponse({
    response: body.response,
    expectedChallenge: challenge,
    expectedOrigin: siteOrigin(c),
    expectedRPID: rpId(c),
    requireUserVerification: false,
    credential: { id: stored.id, publicKey: b64uDecode(stored.publicKeyB64), counter: stored.counter },
  });
  if (!verification.verified) return c.json({ error: "authentication failed" }, 400);
  stored.counter = verification.authenticationInfo.newCounter;
  store.persist();
  const sid = store.newSession(user.userName);
  setCookie(c, "sid", sid, { httpOnly: true, sameSite: "Lax", path: "/" });
  return c.json({ ok: true, userName: user.userName });
});

app.get("/api/me", (c) => {
  return c.json({ userName: store.sessionUser(getCookie(c, "sid")) ?? null });
});

// ---------------------------------------------------------------------------
// issuance (mock eKYC behind passkey session)
// ---------------------------------------------------------------------------

app.post("/api/issue", async (c) => {
  const userName = store.sessionUser(getCookie(c, "sid"));
  if (!userName) return c.json({ error: "passkey login required" }, 401);
  const body = await c.req.json<IssueBody>();
  try {
    return c.json(await issueFor(body.holderPubJwk!, body.license));
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : "issue failed" }, 400);
  }
});

// dev-only issuance without session, for automated tests
app.post("/api/dev/issue", async (c) => {
  if (!process.env.ZEROPII_DEV) return c.json({ error: "disabled outside dev" }, 403);
  const body = await c.req.json<IssueBody>();
  try {
    return c.json(await issueFor(body.holderPubJwk!, body.license));
  } catch (e) {
    return c.json({ error: e instanceof Error ? e.message : "issue failed" }, 400);
  }
});

// ---------------------------------------------------------------------------
// verifier (the demo shop)
// ---------------------------------------------------------------------------

app.get("/api/nonce", (c) => {
  const aud = c.req.query("aud") ?? "";
  if (!aud) return c.json({ error: "aud is required" }, 400);
  return c.json({ nonce: store.newNonce(aud) });
});

app.post("/api/shop/verify", async (c) => {
  const { presentation, nonce } = await c.req.json<{ presentation?: string; nonce?: string }>();
  if (!presentation || !nonce) return c.json({ error: "presentation and nonce are required" }, 400);
  if (!store.consumeNonce(nonce, SHOP_AUD)) return c.json({ error: "invalid or used nonce" }, 400);
  try {
    const result = await verifyPresentation({
      presentation,
      issuerPubJwk: store.issuer.publicKeyJwk,
      expectedNonce: nonce,
      expectedAud: SHOP_AUD,
      kbMaxAgeSec: 120,
    });
    if (store.isRevoked(result.vcId)) {
      return c.json({ ok: false, error: "credential revoked", vcId: result.vcId }, 403);
    }
    // The verifier only ever receives the revealed claims. Log proves it.
    store.pushLog({ ts: Date.now(), kind: "zpi", aud: SHOP_AUD, received: result.claims });
    return c.json({ ok: true, vcId: result.vcId, claims: result.claims, receivedPii: false });
  } catch (e) {
    return c.json({ ok: false, error: e instanceof Error ? e.message : "verification failed" }, 400);
  }
});

// legacy flow for comparison: the shop receives full PII
app.post("/api/shop/verify/legacy", async (c) => {
  const received = await c.req.json<Record<string, unknown>>();
  store.pushLog({ ts: Date.now(), kind: "legacy", aud: SHOP_AUD, received });
  return c.json({ ok: true, receivedPii: true, received });
});

app.get("/api/shop/log", (c) => {
  return c.json({ entries: [...store.log].reverse().slice(0, 30) });
});

// ---------------------------------------------------------------------------
// transparency / status / admin
// ---------------------------------------------------------------------------

app.get("/api/ledger", (c) => {
  return c.json({
    issuer: store.issuerName,
    note: "主張（名前・住所など）は台帳に含まれません。証明書番号と失効状態のみ。",
    chain: store.ledger,
  });
});

app.get("/api/status-list", (c) => {
  return c.json({ bits: b64uEncode(store.statusBits) });
});

app.post("/api/admin/revoke", async (c) => {
  const expectedToken = adminToken();
  if (!expectedToken) return c.json({ error: "admin revocation is not configured" }, 403);
  const auth = c.req.header("authorization") ?? "";
  const suppliedToken = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
  if (!suppliedToken || !constantTimeEqual(suppliedToken, expectedToken)) {
    return c.json({ error: "admin token required" }, 401);
  }
  const { vcId } = await c.req.json<{ vcId?: string }>();
  if (!vcId) return c.json({ error: "vcId is required" }, 400);
  const ok = store.revoke(vcId);
  if (!ok) return c.json({ error: "credential not found" }, 404);
  return c.json({ ok: true, vcId });
});

// ---------------------------------------------------------------------------
// static demo pages
// ---------------------------------------------------------------------------

app.get("/", (c) => c.redirect("/wallet.html"));
app.use("/*", serveStatic({ root: "./public" }));
