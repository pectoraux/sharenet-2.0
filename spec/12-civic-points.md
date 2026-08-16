# ShareNet 2.0 — Civic Points

**Status:** Normative. This document defines Civic Points, the internal
credit unit of ShareNet. It is explicitly NOT a blockchain, NOT a
freely transferable token, and NOT external cryptocurrency.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. What Civic Points Are

Civic Points (CP) are ShareNet's **internal accounting credits**. They
are issued deterministically from verified `ContributionProof`s (see
`spec/11-contribution.md` §3) and are recorded in a per-account ledger.

A Civic Point balance is a number associated with a `NodeId` (or, in
later phases, with an `AccountId` — see `spec/02-identity.md` §1). It
is **not**:

- A blockchain token.
- A freely transferable asset.
- An external cryptocurrency.
- A security, a commodity, or a financial instrument.
- A representation of fiat currency.

## 2. What Civic Points Are NOT

| Statement                                            | Truth Value                                |
|------------------------------------------------------|--------------------------------------------|
| Civic Points are on a blockchain.                    | FALSE.                                     |
| Civic Points can be sent peer-to-peer freely.        | FALSE — settlement is internal and limited. |
| Civic Points can be exchanged for fiat.              | FALSE in this phase.                       |
| Civic Points can be exchanged for external crypto.   | FALSE in this phase (Phase 11 bridge required). |
| Civic Points can be mined.                           | FALSE — issued only from verified proofs.   |
| Civic Points are a security.                         | FALSE — internal accounting only.          |

Premature "free-transfer" semantics — e.g., allowing a node to gift
its Civic Points to another node without an operator-mediated
settlement — are a specification violation. They MUST NOT be added
without a new spec version.

## 3. Issuance

Civic Points are issued **only** by the deterministic conversion of a
verified `LedgerEntry` (see `spec/11-contribution.md` §4). The rate
table is fixed by spec:

| Contribution Kind       | Rate                                  |
|-------------------------|---------------------------------------|
| `GATEWAY_EGRESS`       | 1 CP per 1 MiB egressed.              |
| `RELAY_FORWARD`        | 1 CP per 10 MiB forwarded.            |
| `UPTIME`               | 1 CP per hour of `LINK_UP` for a relay.|

Rates are integer arithmetic; fractional points are NOT issued. Any
remainder below the unit is discarded and MUST NOT accumulate across
proofs.

Issuance is performed by the verifying node and recorded in the
ledger with a hash-chain entry (see `spec/11-contribution.md` §4).

## 4. Settlement (Internal Accounting)

A `Settlement` is an internal accounting transfer of Civic Points
between two ShareNet accounts. It is the ONLY mechanism by which Civic
Points move between accounts in this phase.

```
Settlement = {
  settlement_version: 1,
  from_account:       text,   ; AccountId
  to_account:         text,   ; AccountId
  points:             uint,   ; whole units only
  reason:             text,   ; free-form, e.g. "operator adjustment"
  settlement_nonce:   bstr .size 16,
  operator_signature: bstr .size 64, ; Ed25519 by operator key
}
```

Signature domain: `"sharenet-settlement-v1"`.

A settlement is **only** valid when signed by an operator key whose
`NodeId` is on the operator allow-list for both accounts. Peer-to-peer
settlement (a node signing its own settlement to another node) is
**forbidden** in this phase.

Settlements are recorded in the ledger with a hash-chain entry,
parallel to contribution entries.

## 5. Consumption

Civic Points MAY be consumed to:

1. Authorize gateway usage (see `spec/09-internet-gateway.md` §3
   authorization step).
2. Prioritize a route proposal in congested conditions (see
   `spec/07-routing.md` §5.1 — `requested_bps` MAY be flagged as
   "backed by N CP").
3. Bid for relay forwarding priority (later phase).

Consumption MUST be recorded in the ledger as a settlement from the
consuming account to the issuing operator account, signed by the
operator.

## 6. Anti-Abuse

1. Issuance is deterministic from proofs; no discretionary issuance.
2. Settlements require operator signature.
3. Negative balances are forbidden; a settlement that would drive the
   source account negative MUST be rejected.
4. Per-account rate limits on settlement volume: default 1000 CP /
   day outbound per account, operator-configurable.
5. Audit log entries MUST be produced for every issuance, every
   settlement, every consumption.

## 7. Phase Boundary

Civic Points are introduced in Phase 9 (`spec/01-architecture.md` §3).
Phase 9 is the earliest phase at which CP issuance occurs. Phase 11
introduces the external-cryptocurrency bridge (`spec/13-external-crypto.md`)
which is the ONLY permitted path from CP to external assets.

## 8. Invariants

1. No blockchain.
2. No premature free-transfer semantics.
3. Issuance is deterministic from verified proofs.
4. Settlement is operator-mediated and signed.
5. Negative balances are forbidden.
6. Audit log is mandatory.

## 9. Cross-References

- Contribution proofs: `spec/11-contribution.md` §3.
- Gateway authorization: `spec/09-internet-gateway.md` §3.
- Route proposals: `spec/07-routing.md` §5.1.
- External crypto bridge: `spec/13-external-crypto.md`.
- Identity separation: `spec/02-identity.md` §1.
- Audit logging: `spec/14-security.md` §5.
