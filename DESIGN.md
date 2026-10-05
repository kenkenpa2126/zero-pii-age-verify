# Design

This document describes the current PoC protocol. It is intentionally small and readable.

## Issuance Flow

1. The wallet creates or loads a holder ECDSA P-256 key pair.
2. The holder sends `holderPubJwk` plus mock license fields to the issuer:
   - `name`
   - `birthdate`
   - `address`
3. The issuer computes `over20` from `birthdate`.
4. The issuer allocates a unique `vcId` and status-list index.
5. The issuer creates an SD-JWT-style credential with salted disclosure hashes.
6. The wallet stores the credential and disclosures in IndexedDB.

The issuer sees the full mock license data during issuance. The verifier does not.

## SD-JWT / Selective Disclosure Structure

`issueCredential()` creates one disclosure per claim:

```text
[salt, claim, value]
```

The credential payload stores salted hashes in `_sd` instead of storing claim values directly. The signed payload includes:

- `iss`
- `iat`
- `exp`
- `jti`
- `status.idx`
- `cnf.jwk`
- `_sd_alg`
- `_sd`

The holder presents only the disclosures selected for a verifier. In the shop demo, the holder reveals only `over20`.

## Holder Key Binding

The issuer embeds the holder public key in `cnf.jwk`.

For each presentation, the holder signs a key binding JWT with the holder private key. The verifier imports `cnf.jwk` from the issuer-signed credential and verifies the KB-JWT signature.

This prevents a copied credential from being used without the holder private key.

## Nonce

The verifier creates a random nonce with `/api/nonce?aud=mini-sake-shop`.

The holder includes that nonce in the KB-JWT. The verifier consumes the nonce once before validating the presentation. Reusing the same nonce is rejected.

## Audience Binding

The KB-JWT also includes `aud`. The shop expects:

```text
mini-sake-shop
```

A presentation created for another audience is rejected.

## Verification

`verifyPresentation()` checks:

1. The SD-JWT structure.
2. The issuer signature.
3. Credential expiration.
4. That each disclosed value hashes to a signed `_sd` entry.
5. KB-JWT age.
6. Nonce equality.
7. Audience equality.
8. `sd_hash`, binding the KB-JWT to the exact SD-JWT and disclosed claims.
9. Holder key signature.

`/api/shop/verify` then checks revocation by `vcId`.

## Revocation

The issuer records each issued credential with:

- `vcId`
- `statusIdx`
- timestamp
- revoked flag

`/api/admin/revoke` marks a credential revoked and sets a status bit. The endpoint requires a bearer admin token. In dev mode the demo token is `dev-admin-token`; outside dev, set `ZEROPII_ADMIN_TOKEN`.

The verifier rejects a credential if `store.isRevoked(result.vcId)` is true.

## Stable Values Across Presentations

The following values are stable when the same credential is reused:

- `vcId`
- issuer identifier
- holder public key in `cnf.jwk`
- the SD-JWT
- status-list index

Because of these stable values, presentations can be linked across different verifiers if they collude or compare logs.

## What This Project Intentionally Does Not Solve

- Fully trustless age verification
- Cross-site unlinkability
- Credential sharing / lending
- Compromised issuer signing keys
- Deciding who should act as issuer
- Privacy against issuer-verifier collusion
- Production key management
- Production wallet security
- Real eKYC integration

## Current Security Properties

- Issuer signature verification: implemented.
- Holder key binding: implemented.
- Nonce / replay protection: implemented by verifier nonce storage.
- Audience binding: implemented in the KB-JWT.
- Expiration: implemented with `exp` on the credential and max age on the KB-JWT.
- Revocation: implemented with a local status list and verifier check.

## Known PoC Simplifications

- Issuer state is stored in a local JSON file.
- Status list and ledger are local demo structures.
- Wallet state is browser IndexedDB.
- The implementation is an educational SD-JWT-style subset, not a full standards-compliant SD-JWT stack.
- Verifier logs intentionally store received claims so the demo can show the difference between selective disclosure and the legacy flow.
