# ADR 0003 — NodeId Derivation (CANONICAL, Principal-Architect-APPROVED)

Date: 2024-Q3 (first deliverable); REVISED 2026-08-16 (canonical scheme approved)
Decision Maker: Principal Architect (approved 2026-08-16)

## Status

**ACCEPTED (CANONICAL).** This decision records the Principal-Architect-approved
canonical NodeId derivation for ShareNet 2.0. The derivation is FROZEN and
MUST NOT be changed without a new spec version, a new domain tag, a new NodeId
namespace, and a coordinated migration plan.

## Context

The master implementation prompt (spec/00 §13 "Identity") instructed:

> Use: Ed25519 signing key
> and derive: NodeId
> from the public key using a domain-separated cryptographic hash.
> Freeze the exact derivation in the specification.
> Create golden vectors.

The master prompt did NOT specify which hash algorithm or encoding. The
build orchestrator previously selected BLAKE2b-256 + `node:` + lowercase-hex
without Principal-Architect authority. That interim scheme was flagged in
ADR-0015 (PROPOSAL) and is now RETIRED.

The Principal Architect has APPROVED the canonical scheme:

```
NodeIdBytes = BLAKE3-256( utf8("SHARENET/NODEID/1") || Ed25519PublicKey )
NodeIdText  = lowercase_unpadded_base32( NodeIdBytes )   // RFC 4648
```

## Decision

The canonical NodeId derivation is:

- **Hash function:** BLAKE3-256 (32-byte output)
- **Domain-separation tag:** `SHARENET/NODEID/1` (ASCII, 16 bytes, no NUL)
- **Encoding:** RFC 4648 base32, lowercase, unpadded (no `=` fill)
- **Output length:** exactly 52 characters from the alphabet `[a-z2-7]`
- **No prefix:** the retired `node:` prefix is REMOVED. There is no prefix.

### Properties

- `Ed25519PublicKey` is exactly 32 raw bytes.
- `NodeIdBytes` is exactly 32 bytes.
- `NodeIdText` is exactly 52 lowercase base32 characters.
- The final base32 character encodes 5 bits, of which only the top 1 is
  meaningful (4 bits are leftover). The final character's value MUST be
  0 (`a`) or 1 (`b`). Values 2-31 indicate a non-canonical NodeId and
  MUST be rejected by `isValidNodeIdFormat`.

### Frozen conformance vector

`conformance/vectors/V-NODEID-001.json` records the canonical NodeId for
the fixed test seed `0000...0001`. The expected `NodeIdText` is:

```
yv37fyi6lmqqm7gk3skgdeszc2ngdjh2ruenmkfn2dc2kztakhia
```

Any conformant implementation (TypeScript, Rust, Go, C, Python) MUST
produce this exact `NodeIdText` for the test seed's public key.

## Consequences

- The interim BLAKE2b-256 + `node:` + hex scheme is RETIRED. All NodeIds
  produced under the interim scheme are invalid in the canonical scheme.
- No dual parsing, no fallback derivation, no silent migration.
- The interim test/development NodeIds (documented in
  `mini-services/node-link/data/README.md`) are retired and must never
  be reused.
- All `NodeRecord` and `SequenceFloor` database rows (if any) must be
  purged before deploying the canonical scheme — the same Ed25519 public
  key now maps to a different NodeId string.
- Cross-implementation interoperability: any third-party implementation
  that adopted the interim scheme would break. (No such implementation
  exists — the only consumer is this repository.)

## Alternatives Considered

1. **BLAKE2b-256 + hex (the interim scheme).** Retired — the build
   orchestrator selected it without authority; the Principal Architect
   chose BLAKE3 + base32 for cross-language library availability and
   more compact text representation.

2. **SHA-256 + hex.** Considered in ADR-0015. Not selected — BLAKE3 is
   faster, has a cleaner domain-separation story, and is increasingly
   the default in modern protocol design.

3. **SHA-3-256.** Considered. Not selected — BLAKE3 is faster in software
   and the @noble/hashes implementation is audited.

4. **Base58 encoding.** Considered for the text form. Not selected —
   base32 is case-insensitive-friendly and decodes more cheaply; base58's
   ambiguity-resistance is not needed here.

## References

- spec/02-identity.md §2 (canonical algorithm)
- ADR-0015 (PROPOSAL that this decision resolves — now CLOSED)
- conformance/vectors/V-NODEID-001.json (frozen vector)
- reference/identity/keys.ts (implementation)
- reference/identity/golden-vectors.ts (runtime verification)
