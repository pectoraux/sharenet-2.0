# ShareNet 2.0 — Conformance Coverage Ledger

**Status:** 3 NodeId vectors RATIFIED, 1 CBOR vector DRAFT (cross-language ratification pending).

Per spec/00 §3 (Protocol-First Rule) the conformance sequence is:

```text
Normative Specification
    ↓
ADR
    ↓
Canonical Schema
    ↓
Golden Vector
    ↓
Conformance Test
    ↓
Reference Implementation
    ↓
Platform Implementation
```

This ledger tracks the state of each required vector. A vector is one of:

- `planned` — required by spec, not yet authored. **No fake values, no
  placeholder hashes, no zero signatures, no invented expected values
  are committed under this status.** The vector's slot is reserved and
  documented; the actual bytes will be filled in by a follow-up task
  with real computed values.
- `draft` — authored but not yet ratified by the Principal Architect.
- `ratified` — frozen; any conformant implementation MUST produce these
  exact bytes.

## Vector inventory

| ID | Vector | Source spec | Status | File | Notes |
|----|--------|-------------|--------|------|-------|
| V-NODEID-001 | Canonical NodeId derivation (BLAKE3 + base32) | spec/02 §2.1, ADR-0015 (RESOLVED) | `ratified` | `conformance/vectors/V-NODEID-001.json` | Principal-Architect-approved canonical scheme. Real computed values, not placeholders. |
| V-NODEID-002 | NodeId binding rejection (wrong key) | spec/02 §3 | `ratified` | `conformance/vectors/V-NODEID-002.json` | Asserts verifyNodeIdBinding rejects a NodeId paired with an unrelated public key. |
| V-NODEID-003 | NodeId format validation (malformed inputs) | spec/02 §2.2 | `ratified` | `conformance/vectors/V-NODEID-003.json` | 12 cases including the retired `node:`+hex scheme (MUST be rejected), wrong length, uppercase, non-base32 chars, non-canonical trailing bits. |
| V-CBOR-001 | Canonical CBOR encoding (RFC 8949 §4.2.2) | spec/17 §2.1, ADR-0004 | `draft` | `conformance/vectors/V-CBOR-001.json` | 17 vectors authored and verified against the reference implementation. Cross-language ratification is `planned` — no independent consumer exists yet. |
| V-ADV-001 | Valid advertisement signature | spec/03 §5, spec/17 §2.2 | `planned` | — | No committed vector. Architecture test #3 generates one at runtime but does not freeze it. |
| V-ADV-002 | Invalid advertisement signature (rejection) | spec/03 §5.1 | `planned` | — | Architecture test #4 generates one at runtime. |
| V-ADV-003 | Sequence rollback rejection | spec/03 §5.5, ADR-0006 | `planned` | — | Architecture test #5 covers the logic but no frozen vector. |
| V-ADV-004 | Expired advertisement does not reset sequence floor | spec/14 §3, ADR-0006 | `planned` | — | Architecture test #6 covers the logic but no frozen vector. |
| V-HINT-001 | RemoteNodeHint cannot become AuthenticatedNodeRecord | spec/06 §3, ADR-0007 | `planned` | — | Architecture test #7 covers the guard but no frozen vector. |
| V-LINK-001 | LinkId directionality (A→B ≠ B→A) | spec/04 §2, ADR-0014 | `planned` | — | Architecture test #24 covers the property but no frozen vector. **Blocked by ADR-0016** — the handshake replay defect means link-establishment vectors cannot be truthfully claimed yet. |
| V-LINK-002 | Two-process advertisement-verification exchange | spec/00 §37, ADR-0014 | `planned` | — | Architecture test #25 covers the property. **NOT an "authenticated link"** until ADR-0016 is resolved. |
| V-CIRCUIT-001 | Circuit establishment from committed route | spec/08, spec/00 §38 | `planned` | — | Phase 6 work. Not started. |
| V-GATEWAY-001 | Gateway policy enforcement (SSRF + quota guards) | spec/09, ADR-0011 | `planned` | — | The stub enforces guards but no frozen vector. |

## Cross-language conformance — NOT CLAIMED

The repository contains exactly one implementation (TypeScript, in
`reference/`). Per spec/00 §3, cross-language conformance requires **at
least one independent consumer** (a Rust, Go, or C implementation that
imports the same vectors and verifies them). No such consumer exists.

**Until an independent consumer exists, no cross-language conformance claim
is made anywhere in this repository.** The V-NODEID-001/002/003 vectors are
`ratified` against the reference TypeScript implementation only.

## What this ledger does NOT do

- Does NOT commit fake vectors.
- Does NOT commit placeholder hashes.
- Does NOT commit zero signatures as "expected values."
- Does NOT claim conformance where none exists.
- Does NOT proceed to routing, circuits, gateway forwarding, Android, or any other protocol work.
