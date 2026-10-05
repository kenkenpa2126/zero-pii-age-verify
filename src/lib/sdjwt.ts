/**
 * Minimal SD-JWT style selective disclosure engine.
 *
 * Roles:
 *   - Issuer  signs a credential whose claims are hidden behind salted hashes.
 *   - Holder  reveals only selected claims (disclosures) and proves possession
 *             of the bound device key with a Key Binding JWT (KB-JWT).
 *   - Verifier checks the issuer signature, recomputes disclosure hashes,
 *             and validates nonce/audience/sd_hash in the KB-JWT.
 *             It only ever learns the revealed claims.
 *
 * Crypto: ECDSA P-256 (ES256) + SHA-256, via WebCrypto. Runs on Node and in
 * browsers alike. Deliberately dependency-free: every step is inspectable.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();
const SUPPORTED_JWT_ALG = "ES256";
const SD_JWT_TYP = "SD-JWT";
const KB_JWT_TYP = "kb+jwt";

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------

export function b64uEncode(input: Uint8Array<ArrayBufferLike> | ArrayBuffer | string): string {
  const bytes =
    typeof input === "string"
      ? enc.encode(input)
      : input instanceof ArrayBuffer
        ? new Uint8Array(input)
        : input;
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(input: string): Uint8Array<ArrayBuffer> {
  let s = input.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function randomSalt(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return b64uEncode(buf);
}

async function sha256B64(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return b64uEncode(new Uint8Array(digest));
}

function decodeJson<T>(part: string): T {
  return JSON.parse(dec.decode(b64uDecode(part))) as T;
}

function validateJoseHeader(header: { alg?: unknown; typ?: unknown }, expectedTyp: string): void {
  if (header.alg !== SUPPORTED_JWT_ALG) throw new Error(`unsupported JWT alg: ${String(header.alg)}`);
  if (header.typ !== expectedTyp) throw new Error(`unexpected JWT typ: ${String(header.typ)}`);
}

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

export interface Disclosure {
  salt: string;
  claim: string;
  value: unknown;
}

export interface SigningKeypair {
  publicKeyJwk: JsonWebKey;
  privateKey: CryptoKey;
}

export interface IssuedCredential {
  /** SD-JWT: base64url(header).base64url(payload).base64url(signature) */
  token: string;
  /** Held by the holder. Never sent in full; sent only for revealed claims. */
  disclosures: Disclosure[];
  vcId: string;
}

export interface VerifiedPresentation {
  vcId: string;
  statusIdx: number;
  /** Only the claims the holder chose to reveal. Nothing else. */
  claims: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// key generation
// ---------------------------------------------------------------------------

export async function generateSigningKeypair(extractable = false): Promise<SigningKeypair> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    extractable,
    ["sign", "verify"],
  );
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { publicKeyJwk, privateKey: pair.privateKey };
}

// ---------------------------------------------------------------------------
// issuer side
// ---------------------------------------------------------------------------

export async function issueCredential(opts: {
  issuer: SigningKeypair;
  issuerName: string;
  holderPubJwk: JsonWebKey;
  vcId: string;
  ttlSec: number;
  statusIdx: number;
  /** Each entry becomes an individually disclosable claim. */
  claims: Record<string, unknown>;
}): Promise<IssuedCredential> {
  const now = Math.floor(Date.now() / 1000);
  const disclosures: Disclosure[] = [];
  const sdHashes: string[] = [];

  for (const [claim, value] of Object.entries(opts.claims)) {
    const salt = randomSalt();
    disclosures.push({ salt, claim, value });
    sdHashes.push(await sha256B64(`${salt}~${JSON.stringify(claim)}~${JSON.stringify(value)}`));
  }

  const header = { alg: SUPPORTED_JWT_ALG, typ: SD_JWT_TYP };
  const payload = {
    iss: opts.issuerName,
    iat: now,
    exp: now + opts.ttlSec,
    jti: opts.vcId,
    status: { idx: opts.statusIdx },
    cnf: { jwk: opts.holderPubJwk },
    _sd_alg: "sha-256",
    _sd: sdHashes,
  };

  const signingInput = `${b64uEncode(JSON.stringify(header))}.${b64uEncode(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    opts.issuer.privateKey,
    enc.encode(signingInput),
  );
  const token = `${signingInput}.${b64uEncode(new Uint8Array(sig))}`;
  return { token, disclosures, vcId: opts.vcId };
}

// ---------------------------------------------------------------------------
// holder side
// ---------------------------------------------------------------------------

export async function presentCredential(opts: {
  credential: IssuedCredential;
  /** Claim names the holder agrees to reveal to this verifier. */
  reveal: string[];
  holder: SigningKeypair;
  nonce: string;
  aud: string;
}): Promise<string> {
  const selected = opts.credential.disclosures.filter((d) => opts.reveal.includes(d.claim));
  const encodedDisclosures = selected.map((d) => b64uEncode(JSON.stringify([d.salt, d.claim, d.value])));

  // sd_hash covers the SD-JWT and disclosures up to (and including) the last "~".
  const sdHashInput = [opts.credential.token, ...encodedDisclosures, ""].join("~");

  const kbHeader = { alg: SUPPORTED_JWT_ALG, typ: KB_JWT_TYP };
  const kbPayload = {
    nonce: opts.nonce,
    aud: opts.aud,
    iat: Math.floor(Date.now() / 1000),
    sd_hash: b64uEncode(await crypto.subtle.digest("SHA-256", enc.encode(sdHashInput))),
  };
  const kbInput = `${b64uEncode(JSON.stringify(kbHeader))}.${b64uEncode(JSON.stringify(kbPayload))}`;
  const kbSig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    opts.holder.privateKey,
    enc.encode(kbInput),
  );
  const kbJwt = `${kbInput}.${b64uEncode(new Uint8Array(kbSig))}`;

  return [opts.credential.token, ...encodedDisclosures, kbJwt].join("~");
}

// ---------------------------------------------------------------------------
// verifier side
// ---------------------------------------------------------------------------

export async function verifyPresentation(opts: {
  presentation: string;
  issuerPubJwk: JsonWebKey;
  expectedNonce: string;
  expectedAud: string;
  /** Max age of the KB-JWT. Default 300s. */
  kbMaxAgeSec?: number;
}): Promise<VerifiedPresentation> {
  const parts = opts.presentation.split("~");
  if (parts.length < 3) {
    throw new Error("malformed presentation: expected token~disclosures~kb-jwt");
  }
  const token = parts[0]!;
  const kbJwt = parts[parts.length - 1]!;
  const encodedDisclosures = parts.slice(1, -1);

  // --- 1. issuer signature -------------------------------------------------
  const tokenParts = token.split(".");
  if (tokenParts.length !== 3) throw new Error("malformed SD-JWT");
  const [jwtHeader, jwtPayload, jwtSig] = tokenParts;
  if (!jwtHeader || !jwtPayload || !jwtSig) throw new Error("malformed SD-JWT");
  const header = decodeJson<{ alg?: unknown; typ?: unknown }>(jwtHeader);
  validateJoseHeader(header, SD_JWT_TYP);

  const payload = decodeJson<SdJwtPayload>(jwtPayload);
  if (!Number.isInteger(payload.status?.idx) || payload.status.idx < 0) {
    throw new Error("invalid status index");
  }
  const issuerKey = await crypto.subtle.importKey(
    "jwk",
    opts.issuerPubJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const sigOk = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    issuerKey,
    b64uDecode(jwtSig),
    enc.encode(`${jwtHeader}.${jwtPayload}`),
  );
  if (!sigOk) throw new Error("issuer signature verification failed");

  if (payload.exp <= Math.floor(Date.now() / 1000)) throw new Error("credential expired");

  // --- 2. disclosures match the salted hashes ------------------------------
  const sdSet = new Set(payload._sd);
  const revealed: Disclosure[] = [];
  for (const encoded of encodedDisclosures) {
    const [salt, claim, value] = decodeJson<[string, string, unknown]>(encoded);
    if (salt === undefined || claim === undefined || value === undefined) {
      throw new Error("malformed disclosure");
    }
    const hash = await sha256B64(`${salt}~${JSON.stringify(claim)}~${JSON.stringify(value)}`);
    if (!sdSet.has(hash)) {
      throw new Error(`disclosure for claim "${claim}" does not match the credential`);
    }
    sdSet.delete(hash);
    revealed.push({ salt, claim, value });
  }

  // --- 3. key binding JWT ---------------------------------------------------
  const kbParts = kbJwt.split(".");
  if (kbParts.length !== 3) throw new Error("malformed KB-JWT");
  const [kbHeaderB64, kbPayloadB64, kbSigB64] = kbParts;
  if (!kbHeaderB64 || !kbPayloadB64 || !kbSigB64) throw new Error("malformed KB-JWT");
  const kbHeader = decodeJson<{ alg?: unknown; typ?: unknown }>(kbHeaderB64);
  validateJoseHeader(kbHeader, KB_JWT_TYP);
  const kbPayload = decodeJson<{ nonce: string; aud: string; iat: number; sd_hash: string }>(kbPayloadB64);

  const maxAge = opts.kbMaxAgeSec ?? 300;
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - kbPayload.iat) > maxAge) throw new Error("KB-JWT too old");
  if (kbPayload.nonce !== opts.expectedNonce) throw new Error("nonce mismatch");
  if (kbPayload.aud !== opts.expectedAud) throw new Error("audience mismatch");

  const sdHashInput = [token, ...encodedDisclosures, ""].join("~");
  const expectedSdHash = await sha256B64(sdHashInput);
  if (kbPayload.sd_hash !== expectedSdHash) throw new Error("sd_hash mismatch");

  if (!payload.cnf?.jwk) throw new Error("credential has no bound holder key");
  const holderKey = await crypto.subtle.importKey(
    "jwk",
    payload.cnf.jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const kbOk = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    holderKey,
    b64uDecode(kbSigB64),
    enc.encode(`${kbHeaderB64}.${kbPayloadB64}`),
  );
  if (!kbOk) throw new Error("holder key binding verification failed");

  // --- 4. return only revealed claims ---------------------------------------
  const claims: Record<string, unknown> = {};
  for (const d of revealed) claims[d.claim] = d.value;
  return { vcId: payload.jti, statusIdx: payload.status.idx, claims };
}

// ---------------------------------------------------------------------------
// internal
// ---------------------------------------------------------------------------

interface SdJwtPayload {
  iss: string;
  iat: number;
  exp: number;
  jti: string;
  status: { idx: number };
  cnf: { jwk: JsonWebKey };
  _sd_alg: string;
  _sd: string[];
}
