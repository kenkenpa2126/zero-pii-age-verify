# Threat Model

This project is a small PoC for verifier-side PII minimization. It is not a production identity platform.

## Actors

- Issuer: receives mock identity data during issuance, decides whether the holder is over the age threshold, and signs a credential.
- Holder / wallet: stores the issued credential, disclosures, and holder signing key locally.
- Verifier: asks for an age-threshold proof and verifies the presentation.
- Attacker: may replay presentations, steal stored data, operate a malicious verifier, compromise service data, or collude with another party.

## Trust Assumptions

Two issuer assumptions are intentionally separate:

- The issuer is trusted to attest the age attribute correctly.
- The issuer is trusted to securely retain any PII it collected during issuance.

The first assumption is necessary for the verifier to trust `over20`. The second assumption is a separate privacy and operational risk. This PoC reduces what the verifier receives; it does not remove issuer-side PII handling.

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

- A verifier asking only for `over20` cannot learn hidden claims from the credential because it receives only selected disclosures.
- Tampered disclosures fail hash verification.

May leak:

- A malicious verifier can retain `vcId`, holder public key, and presentation metadata.
- A malicious verifier can ask the user to reveal more claims; the wallet UX must make that explicit.

Remaining assumptions:

- The holder must understand and approve the requested disclosures.
- This PoC does not implement a policy engine that restricts what a verifier may request.

## Scenario: Issuer Database Breach

Protected:

- The verifier-side minimization still helps verifier breaches, but it does not protect PII held by the issuer.

May leak:

- Any PII retained by the issuer during issuance.
- Issuance records such as credential IDs and status indices.

Remaining assumptions:

- A real issuer should minimize retention, encrypt sensitive records, and have operational controls. This PoC does not implement those controls.

## Scenario: Issuer Signing Key Compromise

Protected:

- Existing verifier checks still detect malformed signatures, but not signatures made by a stolen issuer key.

May leak or fail:

- An attacker with the issuer private key can mint fraudulent credentials.
- Verifiers cannot distinguish legitimate issuer signatures from signatures made with a compromised key.

Remaining assumptions:

- Production systems need HSM-backed keys, rotation, key transparency, and incident response. This PoC stores the demo key in `data/state.json`.

## Scenario: Stolen Credential

Protected:

- Presentations require a holder key binding JWT signed by the holder private key.
- Copying only the SD-JWT and disclosures is not enough to create a valid presentation.

May leak or fail:

- If the holder private key is also stolen, an attacker can present the credential.
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

- Hidden PII claims are still not disclosed if each verifier receives only `over20`.

May leak:

- This PoC does not provide cross-site unlinkability.
- The same `vcId`, holder public key, and SD-JWT can be stable across presentations and can be used for linking.

Remaining assumptions:

- Preventing verifier-to-verifier linkage requires different protocol choices, such as pairwise identifiers or unlinkable credential presentations. This PoC intentionally does not implement that.

## Scenario: Issuer / Verifier Collusion

Protected:

- The cryptographic selective-disclosure mechanism still hides undisclosed claims from a verifier acting alone.

May leak:

- If the issuer can map `vcId` or holder public key to a person and shares that mapping with the verifier, the verifier can learn the holder identity.

Remaining assumptions:

- Privacy against issuer-verifier collusion is out of scope for this PoC.
