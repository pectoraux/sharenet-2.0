# ShareNet 2.0 — Security Invariants

**Status:** Normative. This document fixes the security invariants that
every implementation MUST uphold. Violations are build-stopping (see
`spec/01-architecture.md` §4).

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Human Identity (Account) Security

Human accounts (the `UserId` class in `spec/02-identity.md` §1) MUST
be secured by:

1. **Password hashing.** Passwords MUST be hashed with bcrypt
   (cost ≥ 12) or Argon2id (m ≥ 64 MiB, t ≥ 3, p ≥ 1). Plaintext
   passwords MUST NOT be stored anywhere, in any form.
2. **No password in JWT payload.** A JWT (or any session token) MUST
   NOT contain the password, the password hash, or any derivative of
   the password. The token's `sub` claim is the `UserId`; nothing
   more.
3. **2FA.** Operator accounts MUST support TOTP-based 2FA. The 2FA
   secret is stored encrypted at rest.
4. **Secure sessions.** Session tokens MUST be cryptographically random
   (≥ 256 bits) and MUST be stored server-side with a binding to the
   `UserId` and an expiration.
5. **Secure cookies.** Session cookies MUST be marked `HttpOnly`,
   `Secure`, `SameSite=Strict` (or `Lax` where cross-site top-level
   navigation is required).
6. **Session expiration.** Sessions MUST expire: default 8 hours of
   inactivity, 24 hours absolute. Sliding expiration resets the
   inactivity timer but NOT the absolute timer.

## 2. Authorization Middleware

1. Every authenticated endpoint MUST be wrapped by an authorization
   middleware that checks the session, the `UserId`, and the role
   required for the endpoint.
2. The middleware MUST NOT trust client-supplied `UserId` values.
3. Role checks MUST be on the server side. The client MAY show or hide
   UI; the server MUST enforce.
4. Account disable: a disabled `UserId` MUST have all sessions
   invalidated immediately. Subsequent session-presented requests
   from a disabled account MUST be rejected with `401`.

## 3. Persistent Sequence Floors

A **sequence floor** is the highest `sequence` value observed for a
given key. Sequence floors are used in:

- NodeAdvertisement: `(node_id, sequence)` (see
  `spec/03-node-advertisements.md` §5 step 7).
- RemoteNodeHint: `(reporter_id, subject_id, sequence)` (see
  `spec/06-topology.md` §2.2 step 6).
- ContributionProof: `(issuer_id, proof_nonce)` (see
  `spec/11-contribution.md` §3.1).
- Circuit frames: `(circuit_id, frame_sequence)` (see
  `spec/08-circuits.md` §4.5).

The invariant:

> **Expiration of a prior object does NOT lower the sequence floor.**

A new object with a sequence below or equal to the floor MUST be
rejected, even if the prior object that established the floor has
expired.

This prevents the following replay attack: an attacker captures an
old advertisement, waits for it to expire, and replays it with a fresh
`timestamp`/`expiry` but the same `sequence`. Without the persistent
floor, the receiver would accept the replay as a "new" advertisement.

Sequence floors are persisted to disk and survive process restarts.
They MAY be garbage-collected after a long retention period (default
90 days), but the retention period MUST exceed any object's
`MAX_*_TTL` (see `spec/03-node-advertisements.md` §5 step 6).

## 4. Domain Separation for Signatures and KDFs

Every signature and every KDF `info` string in ShareNet MUST be
prefixed by a unique domain-separation string. The full register of
domain strings:

| Domain String                              | Use                                                  | Spec                              |
|--------------------------------------------|------------------------------------------------------|-----------------------------------|
| `sharenet-node-id-v1`                      | NodeId derivation.                                    | `spec/02-identity.md` §2.1.       |
| `sharenet-advertisement-v1`                | NodeAdvertisement signature.                          | `spec/03-node-advertisements.md` §4. |
| `sharenet-link-challenge-v1`               | Link handshake challenge signature.                  | `spec/04-links.md` §3.2.          |
| `sharenet-remote-node-hint-v1`             | RemoteNodeHint signature.                             | `spec/06-topology.md` §2.1.       |
| `sharenet-route-proposal-v1`               | RouteProposal signature.                             | `spec/07-routing.md` §5.1.        |
| `sharenet-route-acceptance-v1`             | RouteAcceptance signature.                            | `spec/07-routing.md` §5.2.        |
| `sharenet-route-commitment-v1`             | RouteCommitment source signature.                     | `spec/07-routing.md` §5.3.        |
| `sharenet-circuit-id-v1`                   | CircuitId derivation.                                 | `spec/08-circuits.md` §3.        |
| `sharenet-circuit-hop-key-v1`              | Per-hop AEAD key derivation.                          | `spec/08-circuits.md` §4.1.      |
| `sharenet-circuit-nonce-prefix-v1`         | Per-circuit nonce prefix.                            | `spec/08-circuits.md` §4.3.      |
| `sharenet-circuit-setup-ack-v1`            | Per-hop setup ack signature.                          | `spec/08-circuits.md` §4.4.      |
| `sharenet-circuit-possession-v1`           | Possession proof signature.                          | `spec/08-circuits.md` §4.4.      |
| `sharenet-circuit-frame-v1`                | AEAD associated data prefix.                          | `spec/08-circuits.md` §4.6.      |
| `sharenet-gateway-agreement-gateway-v1`    | Gateway signature on service agreement.              | `spec/09-internet-gateway.md` §3.1. |
| `sharenet-gateway-agreement-source-v1`     | Source signature on service agreement.               | `spec/09-internet-gateway.md` §3.1. |
| `sharenet-gateway-payment-request-v1`     | Gateway payment request signature.                    | `spec/13-external-crypto.md` §3.1. |
| `sharenet-content-id-v1`                   | ContentId derivation.                                 | `spec/10-content.md` §2.         |
| `sharenet-manifest-v1`                     | Manifest signature.                                   | `spec/10-content.md` §4.         |
| `sharenet-contribution-proof-v1`           | ContributionProof signature.                         | `spec/11-contribution.md` §3.    |
| `sharenet-settlement-v1`                   | Settlement signature.                                 | `spec/12-civic-points.md` §4.    |

A pull request that reuses a domain string across two distinct uses
MUST fail code review and MUST fail the conformance test
`spec/17-conformance.md` §3.4.

## 5. Audit Logging

1. Every authorization decision (allow or deny) MUST produce an audit
   log entry.
2. Every session creation, session expiration, and session invalidation
   MUST be logged.
3. Every account disable, every revocation list mutation, every
   settlement, every issuance MUST be logged.
4. Audit log entries are append-only; tampering is detectable by a
   hash chain (each entry's `prev_hash = SHA-256(prev_entry)`).
5. Audit logs MUST be retained for at least 90 days (operator-configurable).

## 6. SSRF Protection at Gateway

The gateway MUST enforce SSRF protections as specified in
`spec/09-internet-gateway.md` §5.5. Concretely, the gateway MUST
maintain an internal "SSF Guard" that:

- Rejects disallowed URL schemes (only `http`, `https` permitted).
- Rejects disallowed destination addresses (private, loopback,
  link-local, broadcast, multicast — see §5.2 of that document).
- Re-resolves DNS at egress time and re-checks, defeating DNS
  rebinding.
- Caps redirect depth at 3.
- Refuses to honor redirects to disallowed schemes or addresses.

The SSRF guard is a hard dependency; a gateway that bypasses it for any
request is in violation.

## 7. Canonical Encoding Enforcement

1. Every signed object MUST be canonically encoded as defined in
   `spec/03-node-advertisements.md` §3 (CBOR deterministic, RFC 8949
   §4.2.2).
2. The verifier MUST re-encode received objects canonically and check
   byte equality before signature verification.
3. Two different encodings of the same logical object MUST NOT both
   verify; this is the canonical-encoding invariant.

This eliminates semantic ambiguity in the wire format and prevents
malleability attacks where an attacker re-encodes a signed object to
produce a different but still-verifying byte sequence.

## 8. Replay Protection

1. Every signed object carries a `nonce` and a `sequence` (or
   equivalent).
2. Nonce uniqueness is enforced over a validity window.
3. Sequence floors are persistent and survive expiration (see §3).
4. Replays of expired objects MUST be rejected, even if the bytes
   still verify.

## 9. Nonce Uniqueness

1. Nonces are 16-byte cryptographically random values.
2. Uniqueness is enforced per `(signer_id, nonce)` over the validity
   window.
3. After the validity window, nonces MAY be garbage-collected.
4. A collision (two objects with the same `(signer_id, nonce)`) MUST
   be treated as a security incident and logged.

## 10. Other Invariants

1. Ed25519 keys MUST NOT be reused as X25519 keys (see
   `spec/02-identity.md` §3).
2. Private keys MUST be zeroized from memory when no longer in use.
3. Cryptographic RNG MUST be used for all key generation and all
   nonces. `Math.random()` and similar non-CSPRNG sources are
   forbidden.
4. Hash algorithms: BLAKE2b-256 for content and identity derivation;
   SHA-256 for hash chains; SHA-256 inside HKDF for KDFs.
5. AEAD: ChaCha20-Poly1305 preferred; AES-256-GCM permitted only with
   hardware acceleration.
6. All timing comparisons in verification MUST be constant-time where
   the comparison is on secrets. (For non-secret values like NodeIds,
   constant-time is not required but is permitted.)

## 11. Cross-References

- Stop conditions: `spec/01-architecture.md` §4.
- Forbidden pipelines: `spec/17-conformance.md` §3.
- Privacy invariants: `spec/15-privacy.md`.
- Gateway protections: `spec/09-internet-gateway.md` §5.
