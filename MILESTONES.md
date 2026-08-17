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

| ID | Priority | Description | Status |
|----|----------|-------------|--------|
| R-001 | P0 | Protocol freeze reconciliation | ✅ DONE (`ed61a1a`) |
| R-002 | P0 | Fresh possession proof for LINK_UP | ⚠️ OPEN (P1 follow-up: state-machine transitions still caller-driven) |
| R-003 | P0 | RouteAcceptance signature binding | ✅ CLOSED — acceptance binding + canonical commitment_root / route_id derivation |
| R-004 | P0 | Commitment verifies signatures | ✅ CLOSED — commitment_root = BLAKE3(proposal_digest || acceptance_root || commitment_nonce); route_id = toHex(commitment_root); signature over commitment_root |
| R-005 | P0 | Truthful gate system | ✅ DONE (this update) — tracker reconciled to HEAD |
| R-006 | P1 | Architecture test upgrades | ⚠️ PARTIAL: setupCircuit legacy-bypass CLOSED by R-008 hardening; broader vector/arch invariants remain |
| R-007 | P1 | Vectors as mandatory inputs | ⚠️ OPEN (vectors cover identity/encoding/advertisement/link only; routing/circuit/service vectors absent) |
| R-008 | P1 | Distributed circuit setup + hardening | ✅ HARDENED: setupCircuit requires BrandedCommittedRoute exclusively (no legacy bypass); ACK freshness (ackTimestamp/ackExpiry + max age/TTL + clock skew); forwarding-lifecycle state machine; circuit replay model frozen as ORDERED_STREAM before R-009 |
| R-009 | P1 | Circuit packet semantics | ⏳ PENDING (builds on the R-008 ORDERED_STREAM freeze) |
| R-010 | P1 | Real gateway forwarding | ⏳ PENDING |
| R-011 | P1 | Real multiprocess network test | ⏳ PENDING |
| R-012 | P1 | Platform (TUN/VpnService) | ⏳ PENDING |
| R-013 | P1 | Contribution bound to real service | ⏳ PENDING |
| R-014 | P2 | Persistence durability | ⏳ PENDING |
| R-015 | P2 | Standalone protocol build | ⏳ PENDING |

## Execution order (per the audit)

```
R-001 ✅ → R-005 ✅ → R-002 → R-003 → R-004 → R-006 → R-007 → R-008 → R-009 → R-011 → R-010 → Linux → Android → R-013 → Civic Points
```

**real network before economics, protocol integrity before platform work.**
