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

## 2. NodeId Derivation (CANONICAL — APPROVED by Principal Architect 2026-08-16, ADR-0015 RESOLVED)

A node's identity is its Ed25519 signing public key. The NodeId is a
**deterministic, collision-resistant** derivation of that public key.

### 2.1 Algorithm (canonical Phase 0 scheme)

Given an Ed25519 public key `pk` (32 raw bytes):

```
NodeIdBytes = BLAKE3-256( utf8("SHARENET/NODEID/1") || pk )
NodeIdText  = lowercase_unpadded_base32( NodeIdBytes )   // RFC 4648
```

Where:

- `BLAKE3-256` is the BLAKE3 hash function with a 32-byte (256-bit) output.
- `"SHARENET/NODEID/1"` is the **domain-separation tag**, encoded as
  ASCII (16 bytes, no NUL terminator). The bytes are
  `53484152454e45542f4e4f444549442f31` in hex.
- `||` is byte concatenation. The input to BLAKE3 is exactly `16 + 32 = 48` bytes.
- `lowercase_unpadded_base32` is RFC 4648 base32 with the lowercase alphabet
  `abcdefghijklmnopqrstuvwxyz234567` and no `=` padding.

The textual NodeId is exactly **52 lowercase base32 characters**. There is
no `node:` prefix. There is no hex. There is no padding. Example:

```
yv37fyi6lmqqm7gk3skgdeszc2ngdjh2ruenmkfn2dc2kztakhia
```

**Canonical trailing bits:** 32 bytes (256 bits) encoded into 52 base32 chars
(260 bits) leaves 4 unused bits in the final character. These bits MUST be
zero on encode (the final character's 5-bit value is 0 or 1). On decode,
these bits MUST be verified to be zero; a non-zero value indicates a
malformed or non-canonical NodeId and MUST be rejected.

### 2.2 Invariant

```
NodeIdText == CanonicalNodeId(Ed25519PublicKey)
```

This invariant MUST hold for every advertisement, every circuit, every
receipt, and every persistence record. Any code path that produces a
`NodeId` not derivable from the corresponding public key is a
specification violation and MUST fail conformance.

A node MUST NOT claim an arbitrary NodeId. The NodeId is not chosen; it
is computed. The only way to obtain a given NodeId is to possess the
corresponding Ed25519 private key.

### 2.3 Retired scheme (NO compatibility)

The interim BLAKE2b-256 + `node:` + lowercase-hex scheme is **RETIRED**.
Implementations MUST NOT parse, accept, or derive the retired scheme.
There is **no dual parsing, no fallback derivation, and no silent migration**.
NodeIds produced under the retired scheme are not valid in the canonical
scheme and MUST be rejected.

| Property | Retired (interim) | Canonical (current) |
|----------|-------------------|---------------------|
| Hash function | BLAKE2b-256 | BLAKE3-256 |
| Domain tag | `sharenet-node-id-v1` | `SHARENET/NODEID/1` |
| Encoding | lowercase hex | lowercase RFC 4648 base32 |
| Prefix | `node:` | (none) |
| Text length | 71 chars | 52 chars |

### 2.4 Reference Pseudocode

```typescript
import { blake3 } from "@noble/hashes/blake3";
import { utf8ToBytes } from "@noble/hashes/utils";

const DOMAIN_TAG = utf8ToBytes("SHARENET/NODEID/1");  // 16 bytes

export function deriveNodeIdBytes(ed25519PublicKey: Uint8Array): Uint8Array {
  if (ed25519PublicKey.length !== 32) {
    throw new Error("Ed25519 public key must be 32 bytes");
  }
  const input = new Uint8Array(DOMAIN_TAG.length + ed25519PublicKey.length);
  input.set(DOMAIN_TAG, 0);
  input.set(ed25519PublicKey, DOMAIN_TAG.length);
  return blake3(input, { dkLen: 32 });
}

// RFC 4648 lowercase unpadded base32
const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

export function canonicalNodeIdText(ed25519PublicKey: Uint8Array): string {
  const digest = deriveNodeIdBytes(ed25519PublicKey);
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < digest.length; i++) {
    buffer = (buffer << 8) | digest[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(buffer >> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += ALPHABET[(buffer << (5 - bits)) & 0x1f];
  }
  return out;  // 52 chars, no padding
}
```

### 2.5 Conformance vectors

The frozen conformance vector `V-NODEID-001` (in `conformance/vectors/`)
records the canonical NodeId for a fixed test seed. Any conformant
implementation (TypeScript, Rust, Go, C, Python) MUST produce the
identical `NodeIdText` for the identical `Ed25519PublicKey`.

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
