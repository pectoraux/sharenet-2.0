# ShareNet 2.0 — Contribution Pipeline

**Status:** Normative. This document defines how a node earns credit
for forwarding traffic or operating a gateway. The pipeline MUST be
followed; self-reported contributions MUST NOT be credited.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Definitions

The following five objects MUST NOT be conflated. They are listed in
strict order of lifecycle:

| Object                  | Meaning                                                             | Spec Reference            |
|-------------------------|---------------------------------------------------------------------|---------------------------|
| `Contribution`         | The raw fact that a node forwarded traffic or ran a gateway session. | This document, §2.       |
| `ContributionProof`    | A signed receipt from the gateway (or destination) attesting the contribution. | This document, §3. |
| `CivicPoints`          | Internal accounting credits derived from verified proofs.          | `spec/12-civic-points.md`. |
| `Settlement`           | An internal accounting transfer between two ShareNet accounts.      | `spec/12-civic-points.md`. |
| `ExternalCryptocurrency` | On-chain assets held outside ShareNet.                            | `spec/13-external-crypto.md`. |

A `Contribution` is **not** a `ContributionProof`. A `ContributionProof`
is **not** `CivicPoints`. `CivicPoints` are **not** `Settlement`.
None of the above is `ExternalCryptocurrency`.

## 2. Contribution

A `Contribution` arises **only** from a real gateway session in which
the gateway actually forwarded traffic to the real Internet (see
`spec/09-internet-gateway.md` §4).

A contribution MAY be one of:

| Contribution Kind       | Measured Quantity                                          |
|-------------------------|-----------------------------------------------------------|
| `GATEWAY_EGRESS`        | Bytes egressed to the real Internet by a gateway node.     |
| `RELAY_FORWARD`         | Bytes forwarded by a relay node (counted at each hop).     |
| `UPTIME`                | Seconds of `LINK_UP` availability for a relay node.       |

A claim of "I forwarded 10 GB" made by a node about itself is
**not** a contribution that yields credit. It is unverified
self-report and MUST be discarded. Only signed receipts from a
counterparty (the gateway for `GATEWAY_EGRESS`, the next hop for
`RELAY_FORWARD`, the prior hop for `UPTIME`) constitute a
`ContributionProof`.

## 3. ContributionProof

A `ContributionProof` is a signed receipt issued by the measuring
counterparty.

```
ContributionProof = {
  proof_version:    1,
  kind:            "GATEWAY_EGRESS" | "RELAY_FORWARD" | "UPTIME",
  issuer_id:        text,           ; NodeId of the counterparty that measured
  issuer_pubkey:    bstr .size 32,  ; Ed25519 public key of issuer
  beneficiary_id:  text,           ; NodeId that receives the credit
  circuit_id:       text,          ; circuit on which the contribution occurred
  route_id:         text,          ; route that the circuit was bound to
  bytes_count:      uint,           ; 0 for UPTIME
  uptime_seconds:   uint,           ; 0 for byte-based kinds
  measured_at:      uint,           ; Unix seconds, issuer's clock
  valid_until:     uint,           ; Unix seconds, proof expiration
  proof_nonce:     bstr .size 16,
  signature:       bstr .size 64,  ; Ed25519 by issuer
}
```

Signature domain: `"sharenet-contribution-proof-v1"`.

### 3.1 Verification

A verifier MUST check:

1. Canonical encoding (re-encode, byte-equal).
2. `issuer_id == canonicalNodeIdText(issuer_pubkey)`.
3. Signature verifies.
4. `valid_until` is in the future.
5. The `issuer_id` is, depending on `kind`:
   - `GATEWAY_EGRESS`: the terminal gateway hop of `circuit_id`'s
     `route_id`.
   - `RELAY_FORWARD`: a relay hop listed in `route_id`.
   - `UPTIME`: either endpoint of the measured Link.
6. The `beneficiary_id` is also a participant in `route_id`.
7. The `proof_nonce` has not been seen for this `issuer_id` within
   the validity window.
8. The `issuer_id` is not on the revocation list.

A proof that fails any check MUST be rejected and MUST NOT yield
credit.

### 3.2 Anti-Double-Spend

Each proof's `(issuer_id, proof_nonce)` pair MUST be unique. A
second proof with the same pair MUST be rejected as a replay.

The sequence floor for contributions is keyed on
`(issuer_id, beneficiary_id, proof_nonce)` and is persistent. A
re-issued proof with a fresh `proof_nonce` but identical
`(bytes_count, measured_at)` MUST be flagged for audit; this does not
automatically yield double credit but is recorded.

## 4. ContributionLedger

Verified proofs are appended to a `ContributionLedger`. The ledger is
an append-only log; entries MUST NOT be modified or deleted (only
marked void by an explicit revocation record signed by the original
issuer or by an operator key).

```
LedgerEntry = {
  sequence:         uint,         ; monotonic ledger-wide counter
  proof:            ContributionProof,
  verified_at:      uint,
  verifier_id:      text,         ; NodeId of the verifying node
  verifier_signature: bstr .size 64, ; Ed25519 by verifier over the rest
}
```

Ledger entries are hash-chained: `entry_n.prev_hash = SHA-256(entry_{n-1})`.
Tampering with any entry breaks the chain.

## 5. From Proofs to Civic Points

For every verified `LedgerEntry`, the beneficiary receives
`CivicPoints` per the rate table in `spec/12-civic-points.md` §3.
The conversion MUST be deterministic; no discretionary issuance.

A node MAY accumulate proofs and submit them in batches; the
conversion rate per proof is fixed at the time of verification.

## 6. Forbidden Credit Patterns

The following are forbidden and MUST fail conformance:

1. Crediting CivicPoints for self-reported bytes without a signed proof.
2. Crediting CivicPoints for a contribution that did not actually
   traverse the real Internet (e.g., crediting `GATEWAY_EGRESS` for
   traffic that the gateway dropped at policy check).
3. Crediting CivicPoints to a beneficiary that is not a participant in
   the route.
4. Crediting CivicPoints twice for the same proof.
5. Promoting `CivicPoints` to `ExternalCryptocurrency` without going
   through the Phase 11 bridge (see `spec/13-external-crypto.md`).

## 7. Invariants

1. No credit without a signed proof.
2. No proof without a real contribution.
3. No contribution without a real gateway session or relay forward.
4. Proofs are anti-replay-protected by `(issuer_id, proof_nonce)`.
5. The ledger is append-only and hash-chained.
6. Conversion to CivicPoints is deterministic.

## 8. Cross-References

- Gateway sessions: `spec/09-internet-gateway.md`.
- Circuit and route identifiers: `spec/08-circuits.md` §3,
  `spec/07-routing.md` §5.
- Civic Points: `spec/12-civic-points.md`.
- External crypto bridge: `spec/13-external-crypto.md`.
- Forbidden credit patterns (executable guards):
  `spec/17-conformance.md` §3.
