# ShareNet 2.0 — Node Advertisements

**Status:** Normative. This document freezes the NodeAdvertisement
wire format, the signature domain, and the verification algorithm.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Purpose

A NodeAdvertisement is a signed, expiring, monotonic statement by a
node about itself. It declares the node's NodeId, capabilities,
endpoints, and optional policy hooks. It is the **only** authenticated
self-description of a node.

An advertisement is **not** a routing instruction. It is **not** a
link. It is **not** an authorization. It is a signed self-description
that other nodes MAY use to initiate discovery and authentication (see
`spec/04-links.md`, `spec/05-discovery.md`).

## 2. Fields

| Field                    | Type (CBOR)         | Required | Meaning                                                       |
|--------------------------|---------------------|----------|---------------------------------------------------------------|
| `protocol_version`       | unsigned integer   | yes      | ShareNet protocol major version. Current: `2`.                 |
| `node_id`                | text string         | yes      | `node:`-prefixed hex NodeId. See `spec/02-identity.md` §2.1.  |
| `signing_public_key`     | byte string (32B)  | yes      | Ed25519 public key.                                           |
| `capabilities`           | array of text      | yes      | Closed set; e.g. `["RELAY","INTERNET_GATEWAY"]`.              |
| `endpoints`              | array of endpoint  | yes      | Candidate transport endpoints. MAY be empty.                  |
| `circuit_public_key`     | byte string (32B)  | no       | X25519 circuit public key (if `RELAY` capability).            |
| `gateway_policy`         | map                 | no       | Gateway policy digest (if `INTERNET_GATEWAY`).                |
| `sequence`               | unsigned integer   | yes      | Monotonic per-node counter; starts at `1`.                     |
| `timestamp`              | unsigned integer   | yes      | Unix seconds at signing.                                      |
| `expiry`                 | unsigned integer   | yes      | Unix seconds after which the advertisement MUST be ignored.   |
| `nonce`                  | byte string (16B)  | yes      | Fresh random per advertisement.                               |
| `signature`              | byte string (64B)  | yes      | Ed25519 signature. See §4.                                     |

The `endpoint` element is itself a CBOR map:

```
{
  "transport": "tcp" | "ws" | "quic" | "lan-multicast",
  "address":   text,        // host:port, IP literal, or multicast group
  "priority":  unsigned,    // lower = preferred
  "metadata":  map          // optional, e.g. {"tls": true}
}
```

## 3. Canonical Wire Format

The canonical wire format is **CBOR deterministic encoding** as defined
in RFC 8949 §4.2.2, with the additional ShareNet-specific constraints:

1. Map keys MUST be sorted by byte-wise lexicographic order of the
   UTF-8 key string (RFC 8949 §4.2.2 "length-first" ordering).
2. Integers MUST be in the shortest form (RFC 8949 §3.1).
3. Strings MUST be in the shortest definite form.
4. Indefinite-length encodings MUST NOT be used.
5. Undefined (`0x1F`) MUST NOT appear.
6. Floating-point values MUST NOT appear; timestamps are integers.
7. The `signature` field, if present in the encoded map, MUST be set to
   the empty byte string `h''` (`0x40`) before canonicalization for
   signing. The signed payload omits the signature value but keeps the
   key.

### 3.1 CDDL Sketch

```
ShareNetAdvertisement = {
  1: uint,                ; protocol_version
  2: tstr,                ; node_id
  3: bstr .size 32,       ; signing_public_key
  4: [+ tstr],            ; capabilities
  5: [+ Endpoint],       ; endpoints
  ? 6: bstr .size 32,     ; circuit_public_key
  ? 7: GatewayPolicyDigest,
  8: uint,                ; sequence
  9: uint,                ; timestamp
  10: uint,               ; expiry
  11: bstr .size 16,      ; nonce
  12: bstr .size 64,      ; signature
}
```

Keys are integers to make lexicographic ordering unambiguous across
implementations.

## 4. Signature Construction

The signature is Ed25519 over the BLAKE2b-256 digest of a
domain-prefixed canonical CBOR body.

```
signing_input = "sharenet-advertisement-v1" || canonical_cbor(adv_without_signature_value)
digest        = BLAKE2b-256(signing_input)
signature     = Ed25519Sign(private_key, digest)
```

Where `canonical_cbor(adv_without_signature_value)` is the
deterministically-encoded CBOR map with the `signature` value set to
the empty byte string `h''` and all other fields populated as in §3.

The domain-separation string `"sharenet-advertisement-v1"` is exactly
27 bytes of UTF-8, with no NUL terminator, and MUST NOT be reused for
any other signature type (see `spec/14-security.md` §4).

## 5. Verification Algorithm

A verifier receiving an advertisement MUST perform the following
checks in order. Failure of any check MUST cause the advertisement
to be rejected.

1. **Canonical encoding.** Re-encode the received CBOR canonically and
   check byte-equality with the received bytes. If unequal, REJECT.
2. **Field presence and types.** Validate that all required fields are
   present, correctly typed, and within length limits.
3. **Identity binding.** Compute `canonicalNodeIdText(signing_public_key)`
   and check equality with the `node_id` field. See
   `spec/02-identity.md` §2.2.
4. **Signature.** Compute the signing input as in §4 and verify the
   Ed25519 signature under `signing_public_key`.
5. **Timestamp validity.** Reject if `|now - timestamp| > CLOCK_SKEW`,
   where `CLOCK_SKEW = 300` seconds.
6. **Expiry.** Reject if `now > expiry`. Reject if `expiry - timestamp
   > MAX_ADVERTISEMENT_TTL`, where `MAX_ADVERTISEMENT_TTL = 86400`
   seconds (24h).
7. **Monotonic sequence.** Compare the `sequence` against the highest
   previously-observed sequence for this `node_id`. Reject if less than
   or equal to the prior high-water mark. **Expiry of a prior
   advertisement does NOT lower the sequence floor** (see
   `spec/14-security.md` §3).
8. **Nonce uniqueness.** Reject if the `(node_id, nonce)` pair has
   been observed within the past `MAX_ADVERTISEMENT_TTL` seconds.
9. **Revocation list.** Reject if `node_id` is on the active
   revocation list.

## 6. Capabilities — Closed Set

The `capabilities` array elements are drawn from a closed set.
Unrecognized capabilities MUST cause the advertisement to be rejected
as malformed.

| Capability         | Reference                          |
|--------------------|------------------------------------|
| `RELAY`            | `spec/08-circuits.md`              |
| `INTERNET_GATEWAY` | `spec/09-internet-gateway.md`      |
| `CONTENT_STORE`    | `spec/10-content.md`               |
| `BOOTSTRAP`        | `spec/05-discovery.md`             |
| `LEDGER_WITNESS`   | `spec/11-contribution.md`          |

## 7. Cross-References

- Identity binding rule: `spec/02-identity.md` §4.
- Link creation from advertisements: `spec/04-links.md` §3.
- Discovery output: `spec/05-discovery.md` §3.
- Sequence floor invariant: `spec/14-security.md` §3.
- Golden vectors: `conformance/vectors/advertisement/*.json`.
