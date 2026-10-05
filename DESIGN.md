# Design

This document describes the current PoC protocol. It is intentionally narrow: prove an age predicate without turning the credential into a general-purpose identity document.

## Issuance Flow

1. The wallet creates or loads a holder ECDSA P-256 key pair.
2. The holder sends `holderPubJwk` and a mock `birthdate` to the issuer.
3. The issuer validates that the birthdate is a real `YYYY-MM-DD` calendar date.
4. The issuer computes whether the holder satisfies the age threshold.
5. The issuer allocates a unique `vcId` and status-list index.
6. The issuer creates an SD-JWT-style credential whose only disclosable claim is `over20`.
7. The wallet stores the credential, the `over20` disclosure, and the holder key in IndexedDB.

The issuer sees the exact birthdate during issuance. The issued credential and wallet storage do not contain the exact birthdate, name, address, or identity document.

## Age Calculation

The demo threshold is 20 years.

Date parsing is strict:

- accepted format: `YYYY-MM-DD`
- invalid calendar dates such as `2020-02-31` and `2021-02-29` are rejected
- JavaScript `Date` normalization is not used for validation

Age threshold semantics are simple and inclusive: a user satisfies the threshold on the calendar day of their 20th birthday.

## SD-JWT / Selective Disclosure Structure

`issueCredential()` creates one disclosure:

```text
[salt, "over20", true]
```

or:

```text
[salt, "over20", false]
```

The credential payload stores a salted hash of that disclosure in `_sd`. The signed payload includes:

- `iss`
- `iat`
- `exp`
- `jti`
- `status.idx`
- `cnf.jwk`
- `_sd_alg`
- `_sd`

Raw PII is not embedded in the signed credential and is not present in disclosures.

## JOSE Header Validation

The verifier uses an explicit allowlist.

Issuer-signed credentials must use:

- `alg: "ES256"`
- `typ: "SD-JWT"`

Key-binding JWTs must use:

- `alg: "ES256"`
- `typ: "kb+jwt"`

The implementation does not dynamically trust header-declared algorithms.

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
2. The credential JOSE header allowlist.
3. The issuer signature.
4. Credential expiration.
5. That each disclosed value hashes to a signed `_sd` entry.
6. The KB-JWT structure.
7. The KB-JWT JOSE header allowlist.
8. KB-JWT age.
9. Nonce equality.
10. Audience equality.
11. `sd_hash`, binding the KB-JWT to the exact SD-JWT and disclosed claims.
12. Holder key signature.

`/api/shop/verify` then checks revocation by `vcId`.

## Revocation

The issuer records each issued credential with:

- `vcId`
- `statusIdx`
- timestamp
- revoked flag

`/api/admin/revoke` marks a credential revoked and sets a status bit. The endpoint requires a bearer admin token. In dev mode the demo token is `dev-admin-token`; outside dev, set `ZEROPII_ADMIN_TOKEN`.

The verifier rejects a credential if `store.isRevoked(result.vcId)` is true.

## Public Metadata

The original demo exposed a public issuance chain containing stable credential identifiers and timestamps. That made correlation easier without materially helping this narrow age-verification PoC.

The public `/api/ledger` endpoint now exposes only:

- issuer name
- aggregate issued count

The internal store still needs credential IDs and status indices for revocation, but the public demo view does not publish the full issuance chain.

## Stable Values Across Presentations

The following values are stable when the same credential is reused:

- `vcId`
- issuer identifier
- holder public key in `cnf.jwk`
- the SD-JWT
- status-list index

Because of these stable values, presentations can be linked across different verifiers if they collude or compare logs.

Data minimization is not the same as anonymity or unlinkability.

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
- Raw PII minimization: issuer input is reduced to birthdate, and only `over20` is issued.

## Known PoC Simplifications

- Issuer state is stored in a local JSON file.
- Status list and internal issuance log are local demo structures.
- Wallet state is browser IndexedDB.
- The implementation is an educational SD-JWT-style subset, not a full standards-compliant SD-JWT stack.
- Verifier logs intentionally store received claims so the demo can show the difference between predicate disclosure and the legacy flow.
