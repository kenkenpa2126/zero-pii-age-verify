import "../style.css";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { generateSigningKeypair, type Disclosure } from "../lib/sdjwt.ts";
import { idbGet, idbSet } from "./idb.ts";

const $ = (id: string) => document.getElementById(id) as HTMLElement;

interface HolderKey {
  publicKeyJwk: JsonWebKey;
  privateKey: CryptoKey;
}

interface StoredCredential {
  vcId: string;
  token: string;
  disclosures: Disclosure[];
  ts: number;
}

async function jsonPost(
  url: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ ok: boolean; status: number; json: Record<string, unknown> }> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { ok: res.ok, status: res.status, json: await res.json() };
}

function setStatus(msg: string, isError = false): void {
  const el = $("auth-status");
  el.textContent = msg;
  el.classList.toggle("error", isError);
}

async function ensureHolderKey(): Promise<HolderKey> {
  let key = (await idbGet<HolderKey>("holderKey")) ?? null;
  if (!key) {
    key = await generateSigningKeypair(false);
    await idbSet("holderKey", key);
  }
  return key;
}

function userName(): string {
  return ($("username") as HTMLInputElement).value.trim() || "yamada";
}

function adminBearerHeader(): Record<string, string> | undefined {
  const stored = localStorage.getItem("zpi-admin-token") ?? "";
  const token = prompt("管理者デモ用トークンを入力してください", stored || "dev-admin-token");
  if (!token) return undefined;
  localStorage.setItem("zpi-admin-token", token);
  return { Authorization: `Bearer ${token}` };
}

// --- passkey ---------------------------------------------------------------

$("btn-register").addEventListener("click", async () => {
  try {
    const { json } = await jsonPost("/api/passkey/register/options", { userName: userName() });
    const attResp = await startRegistration({ optionsJSON: json as unknown as Parameters<typeof startRegistration>[0]["optionsJSON"] });
    const v = await jsonPost("/api/passkey/register/verify", { userName: userName(), response: attResp });
    if (v.ok && v.json.ok) {
      setStatus(`登録完了：${String(v.json.userName)} としてログイン中`);
      await renderCreds();
    } else {
      setStatus(`登録失敗: ${String(v.json.error)}`, true);
    }
  } catch (e) {
    setStatus(`登録失敗: ${e instanceof Error ? e.message : e}`, true);
  }
});

$("btn-login").addEventListener("click", async () => {
  try {
    const { json } = await jsonPost("/api/passkey/login/options", { userName: userName() });
    const authResp = await startAuthentication({ optionsJSON: json as unknown as Parameters<typeof startAuthentication>[0]["optionsJSON"] });
    const v = await jsonPost("/api/passkey/login/verify", { userName: userName(), response: authResp });
    if (v.ok && v.json.ok) {
      setStatus(`ログイン中：${String(v.json.userName)}`);
      await renderCreds();
    } else {
      setStatus(`ログイン失敗: ${String(v.json.error)}`, true);
    }
  } catch (e) {
    setStatus(`ログイン失敗: ${e instanceof Error ? e.message : e}`, true);
  }
});

// --- issuance ----------------------------------------------------------------

$("btn-issue").addEventListener("click", async () => {
  const key = await ensureHolderKey();
  const license = {
    name: ($("lic-name") as HTMLInputElement).value,
    birthdate: ($("lic-birth") as HTMLInputElement).value,
    address: ($("lic-addr") as HTMLInputElement).value,
  };
  const v = await jsonPost("/api/issue", { holderPubJwk: key.publicKeyJwk, license });
  if (!v.ok || !v.json.ok) {
    setStatus(`発行失敗: ${String(v.json.error)}（先にパスキーログイン）`, true);
    return;
  }
  const creds = (await idbGet<StoredCredential[]>("credentials")) ?? [];
  creds.push({ vcId: String(v.json.vcId), token: String(v.json.token), disclosures: v.json.disclosures as Disclosure[], ts: Date.now() });
  await idbSet("credentials", creds);
  setStatus(`証明書 ${String(v.json.vcId)} を発行し、この端末に保管しました`);
  await renderCreds();
});

// --- credential list -----------------------------------------------------------

async function renderCreds(): Promise<void> {
  const me = await fetch("/api/me").then((r) => r.json()) as { userName: string | null };
  if (me.userName) setStatus(`ログイン中：${me.userName}`);
  const creds = (await idbGet<StoredCredential[]>("credentials")) ?? [];
  const list = $("cred-list");
  list.textContent = "";
  for (const cred of creds) {
    const card = document.createElement("div");
    card.className = "cred";
    const title = document.createElement("div");
    title.className = "cred-title";
    title.textContent = `${cred.vcId}（${new Date(cred.ts).toLocaleString("ja-JP")}）`;
    card.appendChild(title);
    const chips = document.createElement("div");
    chips.className = "chips";
    for (const d of cred.disclosures) {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = `${d.claim}: ${JSON.stringify(d.value)}`;
      chips.appendChild(chip);
    }
    card.appendChild(chips);
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "ECサイトに送られるのは「over20」だけ。氏名・住所・生年月日はissuerへの発行リクエストでは使いますが、verifierには送りません。";
    card.appendChild(note);
    const btn = document.createElement("button");
    btn.className = "danger";
    btn.textContent = "失効させる（管理者デモ）";
    btn.addEventListener("click", async () => {
      const headers = adminBearerHeader();
      if (!headers) return;
      const v = await jsonPost("/api/admin/revoke", { vcId: cred.vcId }, headers);
      if (v.ok) {
        await idbSet("credentials", creds.filter((c) => c.vcId !== cred.vcId));
        setStatus(`${cred.vcId} を失効させました。ミニ酒屋で年齢確認すると拒否されます。`);
        await renderCreds();
      } else {
        setStatus(`失効失敗: ${String(v.json.error)}`, true);
      }
    });
    card.appendChild(btn);
    list.appendChild(card);
  }
  if (creds.length === 0) {
    list.textContent = "まだ証明書がありません。上のフォームから発行してください。";
    list.className = "muted";
  }
}

renderCreds().catch(console.error);
