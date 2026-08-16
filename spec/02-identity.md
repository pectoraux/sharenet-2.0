# ShareNet 2.0 — Identity Model

**Status:** Normative. This document freezes the NodeId derivation, the
Ed25519 binding, and the five-way identity separation.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Identity Separation

ShareNet distinguishes five identity classes. They MUST NOT be
conflated.

| Identity Class        | Object                    | Lifetime           | Attested By                              |
|-----------------------|---------------------------|--------------------|------------------------------------------|
| Human Identity        | `UserId`                  | Account lifetime   | Password + 2FA (see `spec/14-security.md`). |
| Device Identity       | `DeviceId`                | Device enrollment  | Signed by `UserId` key.                  |
| Node Identity         | `NodeId`                  | Key lifetime       | Ed25519 self-attestation (this document). |
| Application Identity  | `AppId`                   | Application install| Signed by `DeviceId` key.                |
| Economic Identity     | `AccountId`               | Billing lifetime   | Linked to `UserId` but separate object.  |

A `NodeId` authenticates **only** the possession of an Ed25519 private
key. It does not authenticate the human, the device, or the billing
account. Statements like "this node is operated by Alice" MUST be
carried by a separate attestation object signed by Alice's `UserId`
key, never inferred from the `NodeId` alone.

## 2. NodeId Derivation (INTERIM — pending ADR-0015)

> **⚠️ STATUS CORRECTION (2026-08-16, corrective milestone):**
> The derivation was previously labeled `FROZEN` in this section and in
> ADR-0003. That label is **retracted**. The build orchestrator
> unilaterally selected BLAKE2b-256 without Principal-Architect approval.
> Per spec/00 §3 (Protocol-First Rule) and §35 (Stop Conditions —
> cryptographic primitive substitution), the algorithm choice is now
> under formal review in **ADR-0015 (PROPOSAL)**.
>
> Until ADR-0015 is resolved, the derivation is labeled **INTERIM**:
> - The current implementation uses BLAKE2b-256 with domain
>   `sharenet-node-id-v1`.
> - This is the behavior the reference implementation produces today.
> - It is NOT ratified as the permanent ShareNet NodeId derivation.
> - A change in algorithm will require recomputing all golden vectors,
>   purging all NodeRecord + SequenceFloor rows, and bumping the
>   domain string to `sharenet-node-id-v2`.

A node's identity is its Ed25519 signing public key. The NodeId is a
**deterministic, collision-resistant** derivation of that public key.

### 2.1 Algorithm (INTERIM — see ADR-0015)

Given an Ed25519 public key `pk` (32 raw bytes):

```
NodeId = BLAKE2b-256("sharenet-node-id-v1" || pk)
```

Where:

- `BLAKE2b-256` is BLAKE2b with a 32-byte (256-bit) digest and the
  default 16-byte salt and 16-byte personalization left empty.
- `"sharenet-node-id-v1"` is the **domain-separation string**, encoded
  as UTF-8 (20 bytes, no NUL terminator).
- `||` is byte concatenation.
- The input to BLAKE2b is exactly `20 + 32 = 52` bytes.

The textual NodeId is the lowercase hex encoding of the 32-byte digest,
prefixed with the ASCII string `node:`. Example:

```
node:9f3c1a4b2e8d0f5c6a7b8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9
```

Total textual length: `5 + 64 = 69` ASCII characters.

### 2.2 Invariant

```
NodeId == CanonicalNodeId(Ed25519PublicKey)
```

This invariant MUST hold for every advertisement, every circuit, every
receipt, and every persistence record. Any code path that produces a
`NodeId` not derivable from the corresponding public key is a
specification violation and MUST fail conformance.

A node MUST NOT claim an arbitrary NodeId. The NodeId is not chosen; it
is computed. The only way to obtain a given NodeId is to possess the
corresponding Ed25519 private key.

### 2.3 Reference Pseudocode

```typescript
import { blake2b } from "@noble/hashes/blake2b";
import { utf8ToBytes } from "@noble/hashes/utils";

const DOMAIN = utf8ToBytes("sharenet-node-id-v1");

export function deriveNodeId(ed25519PublicKey: Uint8Array): Uint8Array {
  if (ed25519PublicKey.length !== 32) {
    throw new Error("Ed25519 public key must be 32 bytes");
  }
  return blake2b.create({ dkLen: 32 })
    .update(DOMAIN)
    .update(ed25519PublicKey)
    .digest();
}

export function canonicalNodeIdText(ed25519PublicKey: Uint8Array): string {
  const digest = deriveNodeId(ed25519PublicKey);
  const hex = Buffer.from(digest).toString("hex");
  return `node:${hex}`;
}
```

## 3. Key Lifecycle

| Operation        | Rule                                                                                              |
|------------------|---------------------------------------------------------------------------------------------------|
| Key generation   | MUST use a cryptographically secure RNG.                                                          |
| Key storage      | Private key MUST be stored at rest encrypted, or in a platform keystore (see `spec/16-platforms.md`). |
| Key rotation     | Permitted; the new key produces a new NodeId. The old NodeId's advertisements MUST expire.         |
| Key compromise   | The NodeId MUST be added to a revocation list. Advertisements signed by the compromised key MUST be rejected. |
| Key reuse        | An Ed25519 signing key MUST NOT be reused as an X25519 circuit key. See `spec/08-circuits.md`.      |

## 4. Identity Binding Verification

Every signed object in ShareNet carries two fields: a `node_id` and a
`signing_public_key`. The verifier MUST check:

1. `node_id == canonicalNodeIdText(signing_public_key)`.
2. The signature verifies under `signing_public_key` over the
   domain-separated canonical body of the object (see
   `spec/03-node-advertisements.md` §4 for the advertisement case).
3. The `signing_public_key` is not on the active revocation list.

Failure of any check MUST cause the object to be rejected as
unauthenticated. It MAY be retained as `REPORTED` evidence if the
verifier is recording topology metadata (see `spec/06-topology.md`).

## 5. Golden Vectors

The conformance suite MUST include golden vectors for NodeId
derivation. Each vector is a `(public_key_hex, expected_node_id_text)`
pair. Vectors MUST cover at least:

1. The all-zero public key (deterministic, well-defined output).
2. A vector from the RFC 8032 Ed25519 test suite.
3. A vector generated by `@noble/curves` `ed25519.utils.getPublicKey()`.
4. A vector where the first byte of the public key differs by one bit
   from vector 2 — the NodeIds MUST differ in at least half their bits
   (avalanche check).

Vector files live in `conformance/vectors/identity/*.json`.

## 6. Cross-References

- Advertisement identity binding: `spec/03-node-advertisements.md` §4.
- Receipts and contribution proofs: `spec/11-contribution.md` §3.
- Password / account security (Human Identity): `spec/14-security.md` §1.
- Privacy implications of NodeId stability: `spec/15-privacy.md` §4.
