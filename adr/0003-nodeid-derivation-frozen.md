# ADR 0003 — NodeId Derivation (Frozen)

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision records the freezing of the NodeId
derivation algorithm. The algorithm itself is frozen in
`spec/02-identity.md` §2.1; this ADR records WHY the algorithm is
the way it is, and makes the freeze contractually binding on every
future contributor.

The freeze means: the domain string `sharenet-node-id-v1` MUST NOT
be changed without a new spec version, a new derivation domain
string, a new NodeId namespace, and a migration plan that re-binds
every existing advertisement, hint, circuit, and receipt to the
new namespace.

## Context

`spec/02-identity.md` §2 freezes the NodeId derivation. The
constraints on the derivation are:

1. **Deterministic.** Given the same Ed25519 public key, every
   implementation on every platform MUST produce the identical
   NodeId. A divergence is a conformance failure (`spec/17-conformance.md`
   §2 test 1).
2. **Collision-resistant.** Two different Ed25519 public keys MUST
   NOT produce the same NodeId except with negligible probability
   (≤ 2^-128 for a 256-bit digest).
3. **Domain-separated.** The derivation MUST NOT produce a NodeId
   that is the same as a hash of the same public key under a
   different protocol's derivation (e.g., a Tor v3 onion address, a
   libp2p PeerId, an IPFS CID). A dedicated domain string achieves
   this.
4. **Immutable across implementations.** The derivation MUST be a
   pure function of the public key. There MUST be no per-implementation
   salt, no per-deployment salt, no per-version salt baked into the
   implementation. Salt would break cross-implementation NodeId
   equality.
5. **Avalanche.** A single-bit change in the public key MUST change
   approximately half of the bits in the NodeId. Verified by the
   conformance suite (`spec/17-conformance.md` §1.2).

The derivation must also be cheap to compute (called on every
signed object verification per `spec/02-identity.md` §4).

## Decision

Freeze the NodeId derivation algorithm as:

```
NodeId = "node:" + hex(BLAKE2b-256("sharenet-node-id-v1" || Ed25519PublicKey))
```

Where:

- `Ed25519PublicKey` is the 32-byte raw Ed25519 public key (NOT a
  DER/PEM-wrapped key).
- `"sharenet-node-id-v1"` is the **frozen domain-separation
  string**, encoded as UTF-8 (20 bytes, no NUL terminator).
- `BLAKE2b-256` is BLAKE2b with a 32-byte digest and the default
  empty salt and empty personalization.
- `||` is byte concatenation. Total input to BLAKE2b is exactly
  52 bytes (`20 + 32`).
- The textual form is the lowercase hex encoding of the digest,
  prefixed with the ASCII string `node:`. Total length: 69 ASCII
  characters.

The domain string `sharenet-node-id-v1` is **frozen forever**. A
future spec version that introduces a new derivation (e.g., a
post-quantum signature scheme) MUST use a new domain string (e.g.,
`sharenet-node-id-v2`) and a new NodeId namespace. Old and new
namespaces coexist; they are not interchangeable.

A node MUST NOT claim an arbitrary NodeId. The NodeId is not
chosen; it is computed. The only way to obtain a given NodeId is
to possess the corresponding Ed25519 private key. This is verified
at every advertisement, hint, and circuit step.

## Consequences

- **NodeId is permanently bound to one keypair.** Rotating the
  signing key produces a new NodeId, which is a new node identity.
  All references to the old NodeId remain valid under the old
  NodeId; nothing is migrated.
- **Key rotation = new identity.** This is a feature, not a bug.
  It prevents key reuse across identities and prevents silent
  identity hijacking via key rotation. See `spec/02-identity.md`
  §3.
- **No claim-and-verify attack surface.** An attacker cannot
  pre-claim a NodeId and wait for a victim to generate the matching
  key — the key is the identity. A victim generating a fresh
  Ed25519 keypair automatically gets a fresh, uncollided NodeId
  with overwhelming probability.
- **Cross-implementation reproducibility is a hard contract.**
  Any port of ShareNet to Python, Rust, Go, or a browser plugin
  MUST produce identical NodeIds for the same public key. The
  conformance golden vectors (`conformance/vectors/identity/*.json`)
  lock this.
- **Domain separation is auditable.** The conformance test
  `spec/17-conformance.md` §3.4 scans the codebase for the literal
  `sharenet-node-id-v1` and asserts it appears in exactly one
  location (the identity module).
- **BLAKE2b-256 is the only hash permitted for this derivation.**
  SHA-256 is reserved for hash chains (`spec/14-security.md` §5)
  and HKDF inputs; using SHA-256 for NodeId would create a
  different namespace and is forbidden.

## Alternatives Considered

1. **SHA-256 instead of BLAKE2b-256.** Rejected — BLAKE2b-256 has
   a cleaner domain-separation story, is faster in pure JS, and
   is not on any NIST-standardization controversy list. SHA-256
   is reserved for hash chains per `spec/14-security.md` §5.
2. **Truncation to 16 bytes (128-bit NodeId).** Rejected —
   collision risk at scale. ShareNet expects on the order of 2^20
   nodes in the medium term; 128-bit NodeIds would still be safe,
   but the cost of 16 extra bytes per NodeId is negligible. A
   256-bit NodeId preserves headroom and matches the Ed25519 key
   size.
3. **A custom base32 or bech32 encoding instead of hex.** Considered
   and rejected — hex is the lowest-friction encoding, debuggable
   in any tool, and the textual length (64 chars) is acceptable
   for the wire and the UI. Bech32 would add a checksum but cost
   code complexity.
4. **Including a network or deployment identifier in the
   derivation.** Rejected — would break cross-deployment NodeId
   equality. A node that moves between networks would lose its
   identity.
5. **No domain string (just `BLAKE2b-256(pk)`).** Rejected —
   would collide with any other protocol that hashes a 32-byte
   Ed25519 public key the same way (libp2p PeerId, Tor v3 onion).
   The domain string is the cheapest possible defense.

## References

- `spec/02-identity.md` §2 — frozen derivation algorithm.
- `spec/02-identity.md` §3 — key lifecycle (rotation = new
  identity).
- `spec/02-identity.md` §4 — identity binding verification on
  every signed object.
- `spec/14-security.md` §4 — domain separation register entry for
  `sharenet-node-id-v1`.
- `spec/17-conformance.md` §2 tests 1-2 — NodeId derivation golden
  vectors and invariant test.
- `spec/17-conformance.md` §1.2 — avalanche vector requirement.
- ADR 0002 — crypto library choice (`@noble/hashes` BLAKE2b-256).
- Michael Nygard ADR template — structural source.
