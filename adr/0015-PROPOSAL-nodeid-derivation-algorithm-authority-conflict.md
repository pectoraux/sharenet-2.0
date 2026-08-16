# ADR-0015 — PROPOSAL: NodeId Derivation Algorithm Authority Conflict

**Date:** 2026-08-16
**Status:** PROPOSAL — awaiting Principal Architect decision. **Do not implement.**

## Context

The master implementation prompt (spec/00 §13 "Identity") instructs:

> Use: Ed25519 signing key
> and derive: NodeId
> from the public key using a domain-separated cryptographic hash.
> Freeze the exact derivation in the specification.
> Create golden vectors.

The master prompt **did not specify which hash algorithm** (BLAKE2b, SHA-256,
SHA-3, or another). It delegated that choice to the specification phase but
required the choice be frozen once made.

In the course of building the first deliverable, the build orchestrator
**unilaterally selected BLAKE2b-256** and froze it across:

- `spec/02-identity.md` §2.1 — "NodeId = BLAKE2b-256(\"sharenet-node-id-v1\" ‖ pk)"
- `spec/02-identity.md` §2.1 — "BLAKE2b-256 is the only hash permitted for this derivation. SHA-256 is reserved for hash chains"
- `adr/0003-nodeid-derivation-frozen.md` — "Decision: NodeId = \"node:\" + hex(BLAKE2b-256(...))"
- `reference/identity/keys.ts` — `import { blake2b } from "@noble/hashes/blake2.js"` + `deriveNodeId()` implementation
- `reference/identity/golden-vectors.ts` — `EXPECTED_NODE_ID` frozen hex vector computed from BLAKE2b-256
- `reference/advertisement/advertisement.ts` — signature verification depends on the NodeId binding (which depends on the derivation)
- `reference/transport/handshake.ts` — peer authentication depends on advertisement verification
- All persisted `NodeRecord` and `SequenceFloor` rows in the database — keyed by NodeId
- All accepted links in the mini-service in-memory registries — keyed by NodeId

This is a **protocol-authority violation** per spec/00 §3 (Protocol-First Rule)
and §35 (Stop Conditions):

> STOP and request architectural review if you encounter:
>   ambiguous identity semantics
>   ambiguous canonical encoding
>   cryptographic primitive substitution

The choice of hash algorithm is a cryptographic primitive decision. The
build orchestrator is not the Principal Architect. The choice should have
been escalated as a proposal, not frozen as a decision.

## Exact current wire behavior (as implemented)

```text
deriveNodeId(publicKey: Uint8Array[32]) -> string
  domainBytes = UTF-8 encode("sharenet-node-id-v1")    // 20 bytes
  input = domainBytes || publicKey                      // 52 bytes
  hash = BLAKE2b(input, dkLen=32)                       // 32 bytes
  return "node:" + lowercase_hex(hash)                  // 71 chars total
```

Concrete golden vector (from `reference/identity/golden-vectors.ts`):

```text
TEST_SEED (hex)        = 0000000000000000000000000000000000000000000000000000000000000001
TEST_PUBLIC_KEY (hex)  = 4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29
EXPECTED_NODE_ID       = node:824d26d78fa3b39119eaedfa513d98b254d788f8b9c22f428c8a0895bbb5fd2d
```

Any conformant implementation MUST produce this exact NodeId for this exact
seed. Any implementation producing a different value is non-conformant with
the current (possibly illegitimate) frozen derivation.

## Affected code, schemas, vectors, persistence, and links

If the Principal Architect chooses a different algorithm (e.g. SHA-256 or
SHA-3-256), the following must change in lockstep:

### Code (Layer 3 — protocol core)
- `reference/identity/keys.ts` — `deriveNodeId()` body, `NODE_ID_DOMAIN` constant
- `reference/identity/golden-vectors.ts` — `TEST_PUBLIC_KEY_HEX`, `EXPECTED_NODE_ID`
- `reference/advertisement/advertisement.ts` — `verifyAdvertisement()` calls `verifyNodeIdBinding()` which calls `deriveNodeId()`
- `reference/transport/handshake.ts` — `verifyPeerHandshake()` calls `verifyAdvertisement()`
- `reference/link/link.ts` — `deriveLinkId()` uses NodeId strings as input (transitive)
- `reference/topology/remote-node-hint.ts` — `createRemoteNodeHint()` accepts NodeId strings (transitive)

### Schemas
- `spec/02-identity.md` §2.1 — the algorithm description
- `spec/02-identity.md` §2.1 — "BLAKE2b-256 is the only hash permitted" (must be removed/relaxed)
- `spec/03-node-advertisements.md` — references NodeId binding
- `spec/14-security.md` §4 — domain-separation register entry for `sharenet-node-id-v1`
- `adr/0003-nodeid-derivation-frozen.md` — the "Decision" section

### Vectors
- `reference/identity/golden-vectors.ts` — `EXPECTED_NODE_ID` frozen hex
- `reference/encoding/golden-vectors.ts` — not affected (CBOR vectors are algorithm-independent)
- `conformance/vectors/` (to be created per ADR-0015-companion) — needs the vector once an algorithm is chosen

### Persistence
- `prisma/schema.prisma` — `NodeRecord.nodeId` (primary key), `SequenceFloor.nodeId` (primary key), `AuditLog.targetNodeId`
- All existing rows in these tables would become invalid if the derivation changes (the same Ed25519 public key would map to a different NodeId string)
- Migration impact: destructive — all node records and sequence floors must be purged and re-accepted

### Links (Phase 3)
- `mini-services/node-link/data/*/`-keypair.json files — store NodeId derived from the chosen algorithm
- All live `DirectedLink` records in mini-service registries — keyed by LinkId which transitively depends on NodeId
- The two-process test (#25) — verifies NodeId binding; would fail if the algorithm changes without updating the test vectors

## Migration / interoperability consequences

### If BLAKE2b-256 is ratified (current behavior)
- No code changes.
- `adr/0003` is upgraded from "Decision" to "Ratified by Principal Architect".
- This ADR-0015 is closed as "resolved — ratified".
- All existing NodeIds remain valid.

### If SHA-256 (or another algorithm) is chosen
- All existing NodeIds become invalid. Every node must re-derive its NodeId and re-advertise.
- All `NodeRecord` and `SequenceFloor` database rows must be purged.
- All golden vectors must be recomputed and re-frozen.
- The mini-service keypair files (already flagged for removal in ADR-0015's sibling corrective) must be regenerated; the old NodeIds are retired.
- Cross-implementation interoperability: any third-party implementation that already adopted the BLAKE2b-256 derivation would break. (Currently no such implementation exists — the only consumer is this repository.)
- Spec version bump required: `sharenet-node-id-v1` → `sharenet-node-id-v2`. Per ADR-0003, a version bump creates a new NodeId namespace; old NodeIds and new NodeIds are NOT interchangeable.

### If a third option is chosen (SHA-3-256, BLAKE3, etc.)
- Same as the SHA-256 case, plus a new library dependency.

## Decision required from the Principal Architect

Choose exactly one:

1. **RATIFY BLAKE2b-256** as the permanent NodeId derivation algorithm.
   - Pro: no migration, no re-freeze, current golden vectors remain valid.
   - Con: BLAKE2b is less widely standardized than SHA-256 (NIST FIPS 180-4); some auditors prefer NIST curves + hashes.

2. **CHANGE to SHA-256** (`BLAKE2b-256` → `SHA-256`).
   - Pro: NIST-standardized; matches the most common cross-language library availability.
   - Con: full re-freeze of vectors; database purge; mini-service keys rotated.

3. **CHANGE to another algorithm** (specify which — SHA-3-256, BLAKE3, etc.).
   - Pro/Con depend on the algorithm.

4. **DEFER the decision** — keep BLAKE2b-256 as the current interim derivation, but mark it as `INTERIM` (not `FROZEN`) in spec/02 and ADR-0003 until a formal review with the security team is complete.

## What this ADR does NOT do

- Does NOT change any code.
- Does NOT re-freeze any vector.
- Does NOT rewrite git history.
- Does NOT make any claim about which algorithm is "correct".
- Does NOT proceed to routing, circuits, gateway forwarding, Android, or any other protocol work.

## References

- spec/00 §13 (Identity — original instruction)
- spec/00 §3 (Protocol-First Rule — stop and request review on primitive substitution)
- spec/00 §35 (Stop Conditions — cryptographic primitive substitution)
- spec/02-identity.md §2.1 (current frozen algorithm — possibly illegitimate)
- adr/0003-nodeid-derivation-frozen.md (the decision that should have been a proposal)
- reference/identity/keys.ts (the implementation)
- reference/identity/golden-vectors.ts (the frozen vector that must be recomputed if the algorithm changes)
