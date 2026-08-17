# ADR-0017 — Protocol Freeze Reconciliation

**Date:** 2026-08-16
**Status:** ACCEPTED — mandatory reconciliation before any further implementation

## Context

The ShareNet 2.0 repository accumulated protocol constructions across multiple
implementation sessions. The NodeId derivation was reconciled to BLAKE3 + base32
(ADR-0015), but several other constructions retained older conventions:

- Advertisement signature domain: `sharenet-advertisement-v1` (lowercase, old convention)
- LinkId derivation: `sharenet-link-id-v1` + BLAKE2b-256 (old hash + old convention)
- Hint signature domain: `sharenet-remote-node-hint-v1` (lowercase, old convention)

While the newer constructions (transcript, possession proofs, circuit ID,
gateway measurement, contribution receipt, route signing) all use:

- Uppercase domain tags: `SHARENET/.../1`
- BLAKE3-256 for hashing (where hashing is needed)
- Ed25519 for signatures (over the domain-prefixed canonical CBOR, no pre-hash)

The older constructions used:

- Lowercase domain tags: `sharenet-...-v1`
- BLAKE2b-256 for hashing (LinkId)
- Inconsistent naming

Per R-001: "The normative protocol must say exactly which construction is current,
with no contradictory historical semantics left in normative documents."

## Decision

### Canonical protocol construction table

Every signature, hash, and encoding in the ShareNet protocol MUST use exactly
one construction per category, as defined below:

| Construction | Domain tag | Hash | Signature | Canonical representation | Version |
|---|---|---|---|---|---|
| NodeId derivation | `SHARENET/NODEID/1` | BLAKE3-256 | N/A (hash only) | lowercase unpadded base32 (52 chars) | 1 |
| Advertisement signature | `SHARENET/ADVERTISEMENT/1` | N/A (Ed25519 signs raw domain‖CBOR) | Ed25519 | canonical CBOR (integer-keyed map, ADR-0004) | 1 |
| LinkId derivation | `SHARENET/LINK/ID/1` | BLAKE3-256 | N/A (hash only) | lowercase hex (64 chars) with `link:` prefix | 1 |
| Hint signature | `SHARENET/HINT/1` | N/A (Ed25519 signs raw domain‖CBOR) | Ed25519 | canonical CBOR (integer-keyed map) | 1 |
| Transcript hash | `SHARENET/LINK/TRANSCRIPT/1` | BLAKE3-256 | N/A | u32be-length-prefixed message sequence | 1 |
| Possession proof (initiator) | `SHARENET/LINK/POSSESSION/INITIATOR/1` | N/A (Ed25519 signs raw payload) | Ed25519 | domain‖transcript_hash‖link_id‖challenge‖role_byte | 1 |
| Possession proof (responder) | `SHARENET/LINK/POSSESSION/RESPONDER/1` | N/A (Ed25519 signs raw payload) | Ed25519 | domain‖transcript_hash‖link_id‖challenge‖role_byte | 1 |
| Circuit ID | `SHARENET/CIRCUIT/ID/1` | BLAKE3-256 | N/A (hash only) | raw 32 bytes | 1 |
| Circuit key schedule | `SHARENET/CIRCUIT/KEY/1` | HKDF-SHA256 | N/A (KDF) | HKDF extract+expand (SHA-256 is correct for KDFs) | 1 |
| Route proposal signature | `SHARENET/ROUTE/PROPOSAL/1` | N/A (Ed25519 signs raw domain‖CBOR) | Ed25519 | canonical CBOR (integer-keyed map) | 1 |
| Route acceptance signature | `SHARENET/ROUTE/ACCEPTANCE/1` | N/A (Ed25519 signs raw domain‖CBOR) | Ed25519 | canonical CBOR (integer-keyed map) | 1 |
| Route commitment signature | `SHARENET/ROUTE/COMMITMENT/1` | N/A (Ed25519 signs raw domain‖CBOR) | Ed25519 | canonical CBOR (integer-keyed map) | 1 |
| Gateway measurement | `SHARENET/GATEWAY/MEASUREMENT/1` | N/A (Ed25519 signs raw domain‖CBOR) | Ed25519 | canonical CBOR (integer-keyed map) | 1 |
| Contribution receipt | `SHARENET/CONTRIBUTION/RECEIPT/1` | BLAKE3-256 (receipt hash for dedup) | Ed25519 (bilateral) | canonical CBOR (integer-keyed map) | 1 |
| Contribution proof | `SHARENET/CONTRIBUTION/PROOF/1` | N/A (derived from receipt) | N/A (carries receipt signatures) | derived | 1 |

### Rules

1. **Domain tags**: All domain tags MUST use the uppercase `SHARENET/.../1` convention.
   Old lowercase tags (`sharenet-...-v1`) are RETIRED.

2. **Hashing**: All protocol hashing (NodeId, LinkId, circuit ID, transcript,
   receipt hash) MUST use BLAKE3-256. BLAKE2b is RETIRED for protocol hashing.

3. **Key derivation**: HKDF-SHA256 is the ONLY KDF (correct — HKDF is defined
   over SHA-2; using BLAKE3 for HKDF would be non-standard).

4. **Signatures**: All signatures are Ed25519 over `domain_tag || canonical_cbor(body)`.
   No pre-hashing before signing (Ed25519 signs the raw message).

5. **Canonical representation**: All wire formats use canonical CBOR (RFC 8949
   §4.2.2) with integer-keyed maps (ADR-0004).

6. **Versioning**: Each domain tag ends with `/1` (version 1). A future protocol
   change requires a new domain tag with `/2`.

### Retired constructions

| Construction | Retired domain | Retired hash | Replacement domain | Replacement hash |
|---|---|---|---|---|
| Advertisement signature | `sharenet-advertisement-v1` | (none — signs raw) | `SHARENET/ADVERTISEMENT/1` | (none — signs raw) |
| LinkId derivation | `sharenet-link-id-v1` | BLAKE2b-256 | `SHARENET/LINK/ID/1` | BLAKE3-256 |
| Hint signature | `sharenet-remote-node-hint-v1` | (none — signs raw) | `SHARENET/HINT/1` | (none — signs raw) |

### Impact

Changing the domain tags and hash functions INVALIDATES all existing conformance
vectors that use the old constructions. The following vectors must be regenerated:

- V-ADV-001 through V-ADV-005 (advertisement vectors — new domain tag)
- V-LINK-HANDSHAKE-001 through V-LINK-HANDSHAKE-005 (handshake vectors —
  these use `computeLinkIdBytes` which currently uses BLAKE2b)

The following vectors are UNAFFECTED (they use constructions that were already canonical):

- V-NODEID-001, V-NODEID-002, V-NODEID-003 (NodeId — already BLAKE3)
- V-CBOR-001 (CBOR encoding — no domain tags)

## Consequences

- All advertisement vectors must be regenerated with the new domain tag.
- All handshake vectors must be regenerated because LinkId bytes change
  (BLAKE2b → BLAKE3 + new domain tag).
- The TypeScript and Python verifiers must be updated to use the new constructions.
- Old vectors are RETIRED (not deleted — marked as superseded).

## What this ADR does NOT do

- Does NOT change the Ed25519 signature algorithm.
- Does NOT change the canonical CBOR encoding.
- Does NOT change the NodeId derivation (already canonical per ADR-0015).
- Does NOT add new protocol features.

## References

- R-001 (Protocol reconciliation requirement)
- ADR-0003 (NodeId derivation — canonical BLAKE3 + base32)
- ADR-0004 (Canonical CBOR wire format)
- ADR-0014 (LinkId derivation — to be updated from BLAKE2b to BLAKE3)
- ADR-0015 (NodeId authority conflict — RESOLVED)
- ADR-0016 (Link handshake — RESOLVED, uses BLAKE3 for transcript)
