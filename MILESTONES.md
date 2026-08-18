# ShareNet 2.0 — Milestone Tracker

Per the Permanent Operating Rules (§A.2), every session must update this file.
Advance only when `ready_for_next_gate: true` and CI verifies the gate evidence.

## Verification levels

Per R-005, a gate cannot become **COMPLETE** until it satisfies its designated
verification level. The old "✅ COMPLETE" labels have been replaced with
truthful verification levels:

| Level | Meaning |
|-------|---------|
| `DESIGNED` | Spec + ADR + types defined, no implementation |
| `IMPLEMENTED` | Code exists but only unit-tested (no integration) |
| `LOCALLY_VERIFIED` | Unit tests + architecture tests pass |
| `MULTIPROCESS_VERIFIED` | Two+ independent processes exchange real traffic |
| `REAL-NETWORK_VERIFIED` | Real sockets, real Internet, real external server |
| `PLATFORM_VERIFIED` | Actual OS facilities (TUN/VpnService) exercised |
| `NORTH-STAR_VERIFIED` | Android mobile data OFF + Wi-Fi OFF + Chrome → real HTTPS |

Old evidence files are preserved but marked as **SUPERSEDED** or **PARTIAL**
where the actual verification level is lower than originally claimed.

## Gate status

| Gate | Title | Verification level | Commit | Evidence | Notes |
|------|-------|-------------------|--------|----------|-------|
| GATE-00 | Stabilize the repository | LOCALLY_VERIFIED | `cac00cc` | `evidence/GATE-00.json` | Stable baseline |
| GATE-01 | Conformance foundation | LOCALLY_VERIFIED | `73eada1` | `evidence/GATE-01.json` | TS + Python verifiers pass 14/14 |
| GATE-02 | Identity and persistent advertisement state | LOCALLY_VERIFIED | `2c6ac24` | `evidence/GATE-02.json` | Restart test passes; in-memory store |
| GATE-03 | Secure authenticated directed links | IMPLEMENTED | `d4a241c` | `evidence/GATE-03.json` | 3-message handshake implemented + vectors; NO real TCP integration (R-002 pending) |
| GATE-04 | Discovery and topology hints | IMPLEMENTED | `26eda87` | `evidence/GATE-04.json` | Hint store + propagation; NO 3-node real-process test |
| GATE-05 | Service negotiation and route commitment | IMPLEMENTED | `9004c0e` | `evidence/GATE-05.json` | Route types + acceptance; R-003/R-004 pending (acceptance binding + sig verification) |
| GATE-06 | Circuits and encrypted forwarding | LOCALLY_VERIFIED | `fdf49f0` | `evidence/GATE-06.json` | X25519+AEAD+onion; distributed relay setup + ACK freshness + ORDERED_STREAM replay freeze (R-008 hardened); setupCircuit requires BrandedCommittedRoute exclusively |
| GATE-07 | Mode A Internet gateway | IMPLEMENTED | `997b0a0` | `evidence/GATE-07.json` | Policy layer; NO real Internet forwarding (R-010 pending) |
| GATE-08 | Recovery | IMPLEMENTED | `38c38b0` | `evidence/GATE-08.json` | Recovery state machine; NO real-process failure test |
| GATE-09 | Linux transparent networking | DESIGNED | `4213295` | `evidence/GATE-09.json` | TUN adapter interface; NO actual /dev/net/tun (R-012 pending) |
| GATE-10 | Android north-star | DESIGNED | `3f99279` | `evidence/GATE-10.json` | VPNService lifecycle model; NO real device test (R-012 pending) |
| GATE-11 | Contribution proofs | IMPLEMENTED | `7d418a7` | `evidence/GATE-11.json` | Bilateral receipts + ledger; NO real measured service (R-013 pending) |
| GATE-12 | Civic Points | PENDING | — | — | Blocked on R-011 (real network) + R-013 (contribution) |
| GATE-13 | Content, external crypto, compute | PENDING | — | — | Blocked on GATE-12 |

## Remediation tracking

> **Invariant (R-005):** A remediation entry MUST NOT claim evidence is
> "pending" when the referenced CI gate (TS+Python vector runner, unit
> tests, architecture tests) passes. The status below is verified against
> the current HEAD: unit tests pass, 24/24 architecture tests, 20/20 TS
> vectors, 20/20 Python vectors.

| ID | Priority | Description | Status |
|----|----------|-------------|--------|
| R-001 | P0 | Protocol freeze reconciliation | ✅ CLOSED |
| R-002 | P0 | Fresh possession proof for LINK_UP | ✅ CLOSED — AuthenticatedLink proof artifact (v1-v7): verified handshake, NodeId binding, wire binding, challenge freshness/replay (ConsumedChallenge), evidence-carrying state machine |
| R-003 | P0 | RouteAcceptance signature binding | ✅ CLOSED — canonical Merkle root, route_id derivation, normative schema (spec↔impl reconciled via machine-readable artifact `spec/schemas/routing-schemas.json`), 20/20 TS+Python golden vectors pass |
| R-004 | P0 | Commitment verifies signatures | ✅ CLOSED — acceptance sig verification, commitment signature over Merkle root, independent verifyRouteCommitment(), immutable artifact, 20/20 TS+Python golden vectors pass |
| R-005 | P0 | Truthful gate system | ✅ CLOSED — tracker reconciled to HEAD; invariant: no "pending" claim when CI gate passes |
| R-006 | P1 | Architecture test upgrades | ✅ CLOSED — construction boundaries enforced (ValidatedHop requires AuthenticatedLink, BrandedCommittedRoute requires genuine ValidatedHop[], setupCircuit requires BrandedCommittedRoute) |
| R-007 | P1 | Vectors as mandatory inputs | ✅ CLOSED — 34/34 TS+Python vectors pass; registry v3 with maturity tracking; spec↔registry↔manifest↔TS↔Python self-enforcing chain; GatewayServiceAgreement + LedgerEntry structural divergences reconciled |
| R-008 | P1 | Distributed circuit setup + hardening | ✅ CLOSED — setupCircuit requires BrandedCommittedRoute exclusively; ACK freshness; forwarding-lifecycle state machine; ORDERED_STREAM replay model frozen |

## Execution order (per the audit)

```
R-001 ✅ → R-005 ✅ → R-002 → R-003 → R-004 → R-006 → R-007 → R-008 → R-009 → R-011 → R-010 → Linux → Android → R-013 → Civic Points
```

**real network before economics, protocol integrity before platform work.**
