# ADR-0015 — RESOLVED: NodeId Derivation Algorithm Authority Conflict

**Date:** 2026-08-16 (PROPOSAL); 2026-08-16 (RESOLVED)
**Status:** RESOLVED — Principal Architect approved the canonical scheme.

## Resolution

The Principal Architect has reviewed the conflict inventory below and
**APPROVED** the following canonical NodeId derivation:

```
NodeIdBytes = BLAKE3-256( utf8("SHARENET/NODEID/1") || Ed25519PublicKey )
NodeIdText  = lowercase_unpadded_base32( NodeIdBytes )   // RFC 4648
```

Properties:
- `Ed25519PublicKey` is exactly 32 raw bytes.
- `NodeIdText` is exactly 52 lowercase base32 characters `[a-z2-7]`.
- No `node:` prefix. No hex. No padding.
- The interim BLAKE2b-256 + `node:` + hex scheme is **RETIRED**.
- No dual parsing, no fallback derivation, no silent migration.
- The interim test/development NodeIds are retired.

This ADR is now CLOSED. The canonical scheme is recorded in:
- `spec/02-identity.md` §2 (normative specification)
- `adr/0003-nodeid-derivation-frozen.md` (the decision ADR)
- `conformance/vectors/V-NODEID-001.json` (frozen vector)
- `reference/identity/keys.ts` (implementation)

---

## Original PROPOSAL (preserved for audit trail)

### Context

The master implementation prompt (spec/00 §13 "Identity") instructed:

> Use: Ed25519 signing key
> and derive: NodeId
> from the public key using a domain-separated cryptographic hash.
> Freeze the exact derivation in the specification.
> Create golden vectors.

The master prompt **did not specify which hash algorithm** (BLAKE2b, SHA-256,
SHA-3, or another). It delegated that choice to the specification phase but
required the choice be frozen once made.

In the course of building the first deliverable, the build orchestrator
**unilaterally selected BLAKE2b-256** and froze it across spec/02, ADR-0003,
reference/identity/keys.ts, golden-vectors.ts, and all dependent code.

This was a **protocol-authority violation** per spec/00 §3 (Protocol-First
Rule) and §35 (Stop Conditions): the choice of hash algorithm is a
cryptographic primitive decision that should have been escalated as a
proposal, not frozen as a decision.

### Exact current wire behavior (as implemented, interim)

```text
deriveNodeId(publicKey: Uint8Array[32]) -> string
  domainBytes = UTF-8 encode("sharenet-node-id-v1")    // 20 bytes
  input = domainBytes || publicKey                      // 52 bytes
  hash = BLAKE2b(input, dkLen=32)                       // 32 bytes
  return "node:" + lowercase_hex(hash)                  // 71 chars total
```

### Affected code, schemas, vectors, persistence, and links

If the Principal Architect chose a different algorithm, the following
must change in lockstep:

#### Code (Layer 3 — protocol core)
- `reference/identity/keys.ts` — `deriveNodeId()` body, `NODE_ID_DOMAIN` constant
- `reference/identity/golden-vectors.ts` — `TEST_PUBLIC_KEY_HEX`, `EXPECTED_NODE_ID`
- `reference/advertisement/advertisement.ts` — `verifyAdvertisement()` calls `verifyNodeIdBinding()` which calls `deriveNodeId()`
- `reference/transport/handshake.ts` — `verifyPeerHandshake()` calls `verifyAdvertisement()`
- `reference/link/link.ts` — `deriveLinkId()` uses NodeId strings as input (transitive)
- `reference/topology/remote-node-hint.ts` — `createRemoteNodeHint()` accepts NodeId strings (transitive)

#### Schemas
- `spec/02-identity.md` §2.1 — the algorithm description
- `spec/03-node-advertisements.md` — references NodeId binding
- `spec/14-security.md` §4 — domain-separation register entry
- `adr/0003-nodeid-derivation-frozen.md` — the decision

#### Vectors
- `reference/identity/golden-vectors.ts` — `EXPECTED_NODE_ID` frozen hex
- `conformance/vectors/` — needs the vector once an algorithm is chosen

#### Persistence
- `prisma/schema.prisma` — `NodeRecord.nodeId` (primary key), `SequenceFloor.nodeId` (primary key), `AuditLog.targetNodeId`
- All existing rows would become invalid if the derivation changes
- Migration impact: destructive — all node records and sequence floors must be purged

#### Links (Phase 3)
- `mini-services/node-link/data/`-keypair.json files — store NodeId derived from the chosen algorithm
- All live `DirectedLink` records — keyed by LinkId which transitively depends on NodeId

### Migration / interoperability consequences

#### If BLAKE2b-256 is ratified (current behavior)
- No code changes.

#### If SHA-256 (or another algorithm) is chosen
- All existing NodeIds become invalid. Every node must re-derive and re-advertise.
- All `NodeRecord` and `SequenceFloor` database rows must be purged.
- All golden vectors must be recomputed and re-frozen.
- Spec version bump required.

### Decision required from the Principal Architect

Choose exactly one:

1. RATIFY BLAKE2b-256 as the permanent NodeId derivation algorithm.
2. CHANGE to SHA-256.
3. CHANGE to another algorithm (specify).
4. DEFER the decision.

### Principal Architect's decision (2026-08-16)

**Option 5 (write-in): CHANGE to BLAKE3-256 + lowercase unpadded RFC 4648 base32.**

The Principal Architect chose BLAKE3 (not BLAKE2b, not SHA-256) and base32
(not hex) for the canonical scheme. The domain tag is `SHARENET/NODEID/1`
(uppercase, slash-separated, to match the conventional domain-tag style
used in other protocols). The encoding is lowercase unpadded base32 for
compactness and case-insensitive friendliness.

## What this ADR does NOT do

- Does NOT retain the interim scheme.
- Does NOT provide dual parsing or fallback.
- Does NOT rewrite git history (the interim NodeIds remain in prior commits
  and are documented as retired).
- Does NOT proceed to routing, circuits, gateway forwarding, Android, or any other protocol work.

## References

- spec/00 §13 (Identity — original instruction)
- spec/00 §3 (Protocol-First Rule)
- spec/00 §35 (Stop Conditions)
- spec/02-identity.md §2 (canonical algorithm)
- adr/0003-nodeid-derivation-frozen.md (the decision ADR, updated to canonical)
- conformance/vectors/V-NODEID-001.json (frozen vector)
- reference/identity/keys.ts (implementation)
