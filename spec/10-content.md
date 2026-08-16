# ShareNet 2.0 — Content Layer

**Status:** Normative, later phase. This document defines the content
layer that sits ABOVE the core mesh. The content layer MUST NOT
contaminate the network layer.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Scope and Layering

The content layer provides content-addressed storage (CAS), chunking,
Merkle-structured manifests, seeding, and resumable transfer of
arbitrary blobs. It runs over circuits (see `spec/08-circuits.md`) and
MAY run directly over authenticated Links for local transfer.

The content layer MUST NOT:

1. Introduce new protocol semantics into the network core (identity,
   links, discovery, topology, routing, circuits, gateway).
2. Define a new signing algorithm or a new identity class.
3. Bypass circuit construction to move content between non-adjacent
   nodes.
4. Be a prerequisite for the proof diagram in `spec/00-thesis.md`
   §1.1. The first deliverable MUST function without the content layer.

## 2. Content-Addressed Storage

Every blob is addressed by the BLAKE2b-256 hash of its raw bytes:

```
ContentId = "content:" || hex(BLAKE2b-256("sharenet-content-id-v1" || blob))
```

Domain-separation string `"sharenet-content-id-v1"` is exactly 22 bytes
of UTF-8, no NUL terminator, and MUST NOT be reused.

`ContentId` is the ONLY canonical handle for a blob. Filenames, paths,
and metadata are NOT part of the ContentId.

## 3. Chunks

Blobs larger than `CHUNK_TARGET_SIZE = 1 MiB` MUST be split into chunks
for transfer and storage. Chunking algorithm:

1. Chunk boundaries determined by a rolling hash (default: buzhash,
   window 48 bytes, mask `0x0003FFFF` ⇒ average ~256 KiB chunks, max
   1 MiB).
2. Each chunk is content-addressed as in §2.
3. The chunk list is itself a blob (`manifest`), content-addressed.

The chunking algorithm MUST be deterministic for a given blob: two
implementations chunking the same bytes MUST produce identical chunk
boundaries. Conformance vectors MUST verify this.

## 4. Merkle Manifests

A manifest is a CBOR map:

```
Manifest = {
  manifest_version: 1,
  total_size:       uint,
  chunk_count:      uint,
  chunks: [{
    index:   uint,
    content_id: text,        ; "content:…"
    offset:  uint,
    length:  uint,
  }],
  merkle_root:      bstr .size 32, ; BLAKE2b-256 over concatenated chunk hashes
  blob_content_id:  text,
  metadata:         map,           ; optional, application-defined
  manifest_nonce:   bstr .size 16,
  signature:        bstr .size 64, ; Ed25519 by publisher
}
```

Signature domain: `"sharenet-manifest-v1"`.

`merkle_root` is computed as the BLAKE2b-256 over the concatenation of
each chunk's 32-byte hash, in index order. It is the canonical
integrity proof for the blob.

## 5. Storage

A node MAY store any subset of:

- The manifest.
- Any subset of chunks.
- The full blob.

A node that advertises the `CONTENT_STORE` capability (see
`spec/03-node-advertisements.md` §6) MUST respond to `GET content:…`
queries with either the chunk bytes (if stored) or a signed "not
stored" acknowledgement.

A node MUST NOT lie about which chunks it stores. A node that returns
bytes that do not hash to the claimed ContentId is in violation; the
conformance suite MUST include a test that blacklists such nodes.

## 6. Seeding

A "seeder" is a node that, by policy, advertises availability of one
or more ContentIds and responds to requests for them. Seeding is
voluntary; no node is required to seed.

A seeder MAY attach a `seed_policy` map to its advertisement:

```
{
  "max_bytes_per_hour":  uint,
  "max_chunks_stored":   uint,
  "allowed_content_ids": [+ text] | "*",
}
```

## 7. Resumable Transfer

Content transfer MUST be resumable: a transfer interrupted at any
chunk boundary MUST resume from the next un-downloaded chunk, without
re-downloading completed chunks. The receiver tracks a bitset of
completed chunks per ContentId.

Transfer is performed over a circuit (see `spec/08-circuits.md`) using
the standard data-frame mechanism; the content layer does not introduce
a new transport.

## 8. Privacy Considerations

- A seeder reveals which ContentIds it stores. Operators SHOULD consider
  the privacy implications before enabling `CONTENT_STORE`.
- A receiver's interest in a ContentId is revealed to the seeder. This
  is inherent to the model.
- The content layer MUST NOT introduce persistent tracking identifiers
  beyond the NodeId (see `spec/15-privacy.md` §4).

## 9. Phase

This layer is specified for completeness. It is NOT built in the first
deliverable. Phase 10 (`spec/01-architecture.md` §3) is the earliest
phase at which it MAY be built.

## 10. Cross-References

- Capability advertisement: `spec/03-node-advertisements.md` §6.
- Circuit carrying content traffic: `spec/08-circuits.md` §5.
- Privacy: `spec/15-privacy.md` §4.
- Conformance vectors: `conformance/vectors/content/*.json` (later
  phase).
