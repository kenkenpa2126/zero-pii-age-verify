import "../style.css";
import { presentCredential, type Disclosure, type IssuedCredential } from "../lib/sdjwt.ts";
import { idbGet } from "./idb.ts";

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

const SHOP_AUD = "mini-sake-shop";

async function ensureHolderKey(): Promise<HolderKey> {
  const key = (await idbGet<HolderKey>("holderKey")) ?? null;
  if (!key) throw new Error("先にウォレットページで証明書を発行してください");
  return key;
}

async function latestCredential(): Promise<StoredCredential | undefined> {
  const creds = (await idbGet<StoredCredential[]>("credentials")) ?? [];
  return creds.at(-1);
}

async function refreshLog(): Promise<void> {
  const { entries } = (await (await fetch("/api/shop/log")).json()) as {
    entries: { ts: number; kind: "zpi" | "legacy"; received: Record<string, unknown> }[];
  };
  const log = $("log");
  log.textContent = "";
  for (const e of entries) {
    const row = document.createElement("tr");
    const tdTs = document.createElement("td");
    tdTs.textContent = new Date(e.ts).toLocaleTimeString("ja-JP");
    const tdKind = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = e.kind === "zpi" ? "badge ok" : "badge bad";
    badge.textContent = e.kind === "zpi" ? "zero-PII" : "従来方式";
    tdKind.appendChild(badge);
    const tdRecv = document.createElement("td");
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(e.received, null, 2);
    tdRecv.appendChild(pre);
    const tdPii = document.createElement("td");
    const keys = Object.keys(e.received);
    const piiKeys = keys.filter((k) => k !== "over20");
    tdPii.textContent = piiKeys.length === 0 ? "なし ✅" : `流出対象: ${piiKeys.join(", ")} ❌`;
    tdPii.className = piiKeys.length === 0 ? "ok" : "bad";
    row.append(tdTs, tdKind, tdRecv, tdPii);
    log.appendChild(row);
  }
  if (entries.length === 0) {
    const row = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.textContent = "まだ検証は行われていません";
    td.className = "muted";
    row.appendChild(td);
    log.appendChild(row);
  }
}

$("btn-buy").addEventListener("click", async () => {
  const out = $("result");
  try {
    const cred = await latestCredential();
    if (!cred) throw new Error("証明書がありません。ウォレットページで発行してください。");
    const holder = await ensureHolderKey();
    const { nonce } = (await (await fetch(`/api/nonce?aud=${SHOP_AUD}`)).json()) as { nonce: string };
    const credential: IssuedCredential = {
      token: cred.token,
      disclosures: cred.disclosures,
      vcId: cred.vcId,
    };
    // ★ ここで送るのは「over20」だけ。名前・住所・生年月日は開示しない
    const presentation = await presentCredential({
      credential,
      reveal: ["over20"],
      holder,
      nonce,
      aud: SHOP_AUD,
    });
    const res = await fetch("/api/shop/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ presentation, nonce }),
    });
    const j = (await res.json()) as { ok?: boolean; error?: string; claims?: Record<string, unknown> };
    if (j.ok) {
      out.className = "result ok";
      out.innerHTML = `✅ 年齢確認OK（over20）— 購入できます。<br>
        <span class="muted">サーバーが受け取った主張: <code>${JSON.stringify(j.claims)}</code><br>
        名前・住所・生年月日はネットワーク上に一度も流れていません（開発者ツールのNetworkタブでも確認できます）。</span>`;
    } else {
      out.className = "result bad";
      out.textContent = `❌ 年齢確認失敗: ${j.error}`;
    }
  } catch (e) {
    out.className = "result bad";
    out.textContent = `❌ ${e instanceof Error ? e.message : e}`;
  }
  await refreshLog();
});

$("btn-legacy").addEventListener("click", async () => {
  await fetch("/api/shop/verify/legacy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: "山田 太郎",
      birthdate: "1995-04-01",
      address: "東京都千代田区1-2-3",
      phone: "090-XXXX-XXXX",
    }),
  });
  $("result").className = "result";
  $("result").textContent = "従来方式：氏名・生年月日・住所・電話番号をそのまま送信しました（下のサーバーログ参照）";
  await refreshLog();
});

refreshLog().catch(console.error);
