# zero-pii-age-verify

個人情報を一切渡さずに「属性」（例: 20歳以上）だけを証明するデモ。
Zero-PII attribute verification demo: prove "over 20" without revealing name, address, or birthdate.

## アーキテクチャ

```
[発行元 Issuer]   一度だけ本人確認 → "over20: true" に署名して発行        src/server/
[ホルダー Holder] 証明を保持し、見せたい主張だけ選んで提示                src/client/
[検証者 Verifier] 署名検証し、明示された主張だけを受け取る                /api/shop/verify
```

検証者が受け取るのは署名された主張のみ。名前・住所・生年月日は**ネットワーク上に一度も流れない**。
発行元の台帳（透明性ログ）に残るのも**証明書番号と失効状態のみ**。

## コア（デモに依存しない再利用パーツ）

- `src/lib/sdjwt.ts` — SD-JWT方式の選択開示エンジン（依存ゼロ、WebCryptoのみ）
  - `issueCredential()` — 主張をソルト付きハッシュで隠して発行元が署名
  - `presentCredential()` — 見せたい主張だけ開示＋デバイス鍵による KB-JWT（nonce/aud/sd_hash 束縛）
  - `verifyPresentation()` — 発行元署名・開示整合性・鍵束縛・期限を検証し、**明示された主張だけ**を返す

## デモの流れ

1. `/wallet.html` — パスキー登録 → eKYC（モック）→ 証明書発行（端末のIndexedDBに保管。ホルダー鍵は non-extractable）
2. `/shop.html` — 「20歳以上です → 購入」で over20 のみを送信して通過
3. 「従来方式で送信（比較）」で、氏名・住所・生年月日・電話番号をそのまま送る場合との**サーバーログの差**を確認
4. ウォレットで「失効させる」→ 再度年齢確認すると拒否される

## 実行

```bash
npm install
npm run build        # クライアントビルド → public/
npm run dev          # http://localhost:8787  (wallet: /wallet.html, shop: /shop.html)
```

テスト:

```bash
npm run smoke        # コア暗号エンジンの単体テスト（6ケース）
npm run e2e          # サーバー起動〜発行・検証・リプレイ拒否・失効までの結合テスト（8ケース）
npm run typecheck
```

パスキーの動作には `localhost`（https ではなくても可）が必要。Chrome/Edge/Safari で動く。

## 進捗

- [x] コアエンジン（sdjwt.ts）
- [x] 発行元API（モックeKYC）＋透明性ログ（ハッシュチェーン）＋失効
- [x] 検証者API＋受信ログ（「個人情報: なし」の証明用）
- [x] パスキーログイン＋ホルダー鍵（IndexedDB, non-extractable）
- [x] ミニ酒屋デモページ＋従来方式との比較ページ
- [ ] Zenn/Qiita 記事

## デモとして意図的に簡略化している点（本番ではこう直す）

| デモ | 本番 |
| --- | --- |
| eKYCはフォーム入力を「確認済み」扱い | 運転免許・マイナンバーでの実検証（eKYCベンダー接続） |
| 発行元の署名鍵を data/state.json にファイル保管 | HSM に封入＋閾値署名（鍵の分割管理） |
| 透明性ログは単一サーバーのメモリ/ファイル | マークル木＋公開照会（Certificate Transparency 方式） |
| パスキーセッションは Cookie | 同等だが属性発行にも再認証（step-up）を要求 |
| ユーザー管理・セッションをメモリ | 永続DB、監査ログ |

## 参考

- IETF SD-JWT (draft-ietf-oauth-selective-disclosure-jwt) — 本実装は学習用に簡略化した独自サブセット（開示は `_sd` 配列とソルト付きハッシュ、KB-JWT は nonce/aud/sd_hash）
- OpenID4VP / EUDI Wallet — 同じ発想の標準化・国家実装
