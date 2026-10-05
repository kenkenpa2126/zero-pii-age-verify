import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { b64uDecode, b64uEncode, generateSigningKeypair, type SigningKeypair } from "../lib/sdjwt.ts";

const DATA_DIR = "data";
const STATE_FILE = "data/state.json";

export interface IssuedRecord {
  vcId: string;
  statusIdx: number;
  revoked: boolean;
}

export interface PasskeyCredential {
  id: string;
  publicKeyB64: string;
  counter: number;
}

export interface User {
  userId: string;
  userName: string;
  credentials: PasskeyCredential[];
}

export interface LogEntry {
  ts: number;
  kind: "zpi" | "legacy";
  aud: string;
  received: Record<string, unknown>;
}

interface PersistShape {
  issuer: { publicKeyJwk: JsonWebKey; privateKeyJwk: JsonWebKey };
  users: User[];
  issued: IssuedRecord[];
  statusBitsB64: string;
  nextStatusIdx: number;
  nextVcSeq: number;
}

class Store {
  issuer!: SigningKeypair;
  readonly issuerName = "demo-trust-root";
  users = new Map<string, User>();
  issued = new Map<string, IssuedRecord>();
  statusBits = new Uint8Array(64);
  nextStatusIdx = 0;
  nextVcSeq = 1;
  nonces = new Map<string, { aud: string; exp: number }>();
  challenges = new Map<string, { userName: string; kind: "reg" | "auth"; exp: number }>();
  sessions = new Map<string, { userName: string; exp: number }>();
  log: LogEntry[] = [];

  async init(): Promise<void> {
    mkdirSync(DATA_DIR, { recursive: true });
    if (existsSync(STATE_FILE)) {
      try {
        await this.load();
        console.log(`state restored from ${STATE_FILE}`);
        return;
      } catch (e) {
        console.warn("state load failed, starting fresh:", e);
      }
    }
    // NOTE: 本番はHSMに置く。デモでは抽出可能鍵をファイル保管して再起動に耐える。
    const kp = await generateSigningKeypair(true);
    const privateKeyJwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    this.issuer = kp;
    this.privJwk = privateKeyJwk;
    this.persist();
    console.log("new issuer key generated");
  }

  privJwk!: JsonWebKey;

  private async load(): Promise<void> {
    const raw = JSON.parse(readFileSync(STATE_FILE, "utf8")) as PersistShape;
    const pubKey = await crypto.subtle.importKey(
      "jwk",
      raw.issuer.publicKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
    const privKey = await crypto.subtle.importKey(
      "jwk",
      raw.issuer.privateKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    this.issuer = { publicKeyJwk: raw.issuer.publicKeyJwk, privateKey: privKey };
    void pubKey;
    this.privJwk = raw.issuer.privateKeyJwk;
    for (const u of raw.users) this.users.set(u.userName, u);
    for (const r of raw.issued) this.issued.set(r.vcId, r);
    this.statusBits = b64uDecode(raw.statusBitsB64);
    this.nextStatusIdx = raw.nextStatusIdx;
    this.nextVcSeq = raw.nextVcSeq;
  }

  persist(): void {
    const shape: PersistShape = {
      issuer: { publicKeyJwk: this.issuer.publicKeyJwk, privateKeyJwk: this.privJwk },
      users: [...this.users.values()],
      issued: [...this.issued.values()],
      statusBitsB64: b64uEncode(this.statusBits),
      nextStatusIdx: this.nextStatusIdx,
      nextVcSeq: this.nextVcSeq,
    };
    writeFileSync(STATE_FILE, JSON.stringify(shape, null, 2));
  }

  // --- nonces (one-time, audience-bound) -----------------------------------
  newNonce(aud: string): string {
    const nonce = b64uEncode(crypto.getRandomValues(new Uint8Array(24)));
    this.nonces.set(nonce, { aud, exp: Date.now() + 120_000 });
    return nonce;
  }

  consumeNonce(nonce: string, aud: string): boolean {
    const entry = this.nonces.get(nonce);
    if (!entry || entry.aud !== aud || entry.exp < Date.now()) return false;
    this.nonces.delete(nonce);
    return true;
  }

  // --- challenges / sessions ------------------------------------------------
  putChallenge(challenge: string, userName: string, kind: "reg" | "auth"): void {
    this.challenges.set(challenge, { userName, kind, exp: Date.now() + 300_000 });
  }

  takeChallenge(challenge: string): { userName: string; kind: "reg" | "auth" } | undefined {
    const entry = this.challenges.get(challenge);
    if (!entry || entry.exp < Date.now()) return undefined;
    this.challenges.delete(challenge);
    return { userName: entry.userName, kind: entry.kind };
  }

  newSession(userName: string): string {
    const sid = crypto.randomUUID();
    this.sessions.set(sid, { userName, exp: Date.now() + 86_400_000 });
    return sid;
  }

  sessionUser(sid: string | undefined): string | undefined {
    if (!sid) return undefined;
    const s = this.sessions.get(sid);
    if (!s || s.exp < Date.now()) return undefined;
    return s.userName;
  }

  // --- credentials / status -------------------------------------------------
  nextVcId(): string {
    let vcId: string;
    do {
      vcId = `vc-${String(this.nextVcSeq).padStart(4, "0")}`;
      this.nextVcSeq++;
    } while (this.issued.has(vcId));
    this.persist();
    return vcId;
  }

  recordIssuance(vcId: string, statusIdx: number): void {
    if (statusIdx >= this.statusBits.length * 8) {
      const grown = new Uint8Array(this.statusBits.length * 2);
      grown.set(this.statusBits);
      this.statusBits = grown;
    }
    this.issued.set(vcId, { vcId, statusIdx, revoked: false });
    this.persist();
  }

  revoke(vcId: string): boolean {
    const rec = this.issued.get(vcId);
    if (!rec) return false;
    rec.revoked = true;
    this.statusBits[rec.statusIdx >> 3]! |= 1 << (rec.statusIdx & 7);
    this.persist();
    return true;
  }

  isRevoked(vcId: string): boolean {
    return this.issued.get(vcId)?.revoked ?? true;
  }

  pushLog(entry: LogEntry): void {
    this.log.push(entry);
    if (this.log.length > 200) this.log.shift();
  }
}

export const store = new Store();
