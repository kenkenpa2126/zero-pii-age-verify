# Threat Model

This project is a small PoC for age-verification data minimization. It is not a production identity platform.

## Actors

- Issuer: receives a mock birthdate during issuance, evaluates the age threshold, and signs a credential containing only `over20`.
- Holder / wallet: stores the issued credential, the `over20` disclosure, and the holder signing key locally.
- Verifier: asks for an age-threshold proof and verifies the presentation.
- Attacker: may replay presentations, steal stored data, operate a malicious verifier, compromise service data, or collude with another party.

## Trust Assumptions

Two issuer assumptions are intentionally separate.

Correctness trust:

- The issuer is trusted to evaluate and attest the age attribute correctly.
- The issuer is trusted to sign credentials correctly with its legitimate signing key.

Confidentiality trust:

- The issuer should not be assumed to be immune to data breaches.
- The issuer should not be treated as a perfect privacy custodian.

The design minimizes dependence on issuer confidentiality by avoiding unnecessary retention. The issuer sees the mock birthdate during issuance, but the issued credential, wallet storage, and verifier logs do not contain the exact birthdate. The verifier is not trusted with PII. The wallet is designed to contain as little valuable PII as possible.

## Scenario: Verifier Database Breach

Protected:

- The verifier should not have stored name, address, birthdate, or identity document data from the selective-disclosure flow.
- A breach of the verifier log should reveal only the claims the holder disclosed, such as `over20`.

May leak:

- `vcId`
- issuer identifier
- holder public key embedded in the credential
- timestamps, audience, and verifier-local logs

Remaining assumptions:

- The verifier implementation must avoid logging full presentations if it wants the breach impact to stay small.

## Scenario: Malicious Verifier

Protected:

- A verifier asking for the demo presentation learns only `over20`.
- The credential does not contain hidden name, address, or birthdate disclosures for the verifier to request later.
- Tampered disclosures fail hash verification.

May leak:

- A malicious verifier can retain `vcId`, holder public key, and presentation metadata.

Remaining assumptions:

- The holder must still know which verifier they are presenting to.
- This PoC does not implement verifier reputation or policy controls.

## Scenario: Issuer Database Breach

Protected:

- The issued credential and wallet copy do not contain raw PII.
- There is no public issuance ledger exposing credential IDs or issuance timestamps.

May leak:

- Any raw birthdate data the issuer logs or retains outside this PoC.
- Internal issued records such as credential IDs and status indices if the local state file is breached.

Remaining assumptions:

- A real issuer should avoid retaining raw PII, encrypt sensitive records, and have operational controls. This PoC demonstrates the minimization direction but does not implement production issuer operations.

## Scenario: Issuer Signing Key Compromise

Protected:

- Existing verifier checks still detect malformed signatures, but not signatures made by a stolen issuer key.

May leak or fail:

- Issuer impersonation and weak identity-proofing attacks are not solved.
- An attacker with the issuer private key can mint fraudulent credentials.
- Verifiers cannot distinguish legitimate issuer signatures from signatures made with a compromised key.

Remaining assumptions:

- Production systems need HSM-backed keys, rotation, key transparency, and incident response. This PoC stores the demo key in `data/state.json`.

## Scenario: Stolen Credential

Protected:

- Presentations require a holder key binding JWT signed by the holder private key.
- Copying only the SD-JWT and disclosure is not enough to create a valid presentation.
- The stolen credential has lower PII value because it contains only the age predicate and protocol metadata.

May leak or fail:

- If the holder private key is also stolen, an attacker can present the credential.
- A stolen wallet may still expose stable identifiers such as `vcId` and holder public key.
- Credential lending, device lending, and shared-device misuse are not fully solved.
- This PoC does not prove that the person holding the device is the original subject at presentation time.

Remaining assumptions:

- The wallet storage and device key protection matter. Browser IndexedDB is a demo convenience, not a complete wallet security model.

## Scenario: Replay Attack

Protected:

- The verifier issues a nonce.
- The server consumes the nonce once.
- The KB-JWT includes the nonce and has a short maximum age.

May leak or fail:

- A verifier that forgets to consume nonces would allow replay within the KB-JWT time window.

Remaining assumptions:

- Nonce storage must remain available and consistent for each verifier.

## Scenario: Verifier Collusion

Protected:

- Raw PII is still not disclosed if each verifier receives only `over20`.

May leak:

- This PoC does not provide cross-site unlinkability.
- The same `vcId`, holder public key, and SD-JWT can be stable across presentations and can be used for linking.

Remaining assumptions:

- Preventing verifier-to-verifier linkage requires different protocol choices, such as pairwise identifiers or unlinkable credential presentations. This PoC intentionally does not implement that.

## Scenario: Issuer / Verifier Collusion

Protected:

- The verifier does not receive raw PII from the presentation alone.

May leak:

- If the issuer can map `vcId` or holder public key to a person and shares that mapping with the verifier, the verifier can learn the holder identity.

Remaining assumptions:

- Privacy against issuer-verifier collusion is out of scope for this PoC.

## Important Boundary

Data minimization is not the same as anonymity or unlinkability. This version intentionally focuses on reducing raw PII in the credential, wallet, verifier, and public metadata. It does not try to solve cross-site correlation.

Known v1 limitations:

- issuer impersonation / weak identity-proofing attacks are not solved
- issuer compromise is not fully solved
- issuer signing-key compromise is not fully solved
- cross-verifier unlinkability is not provided
- credential lending / device lending is not fully solved
- wallet/device compromise remains relevant
- this is not a production identity system
