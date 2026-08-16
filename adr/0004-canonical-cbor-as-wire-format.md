# ADR 0004 — Canonical CBOR as Wire Format

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision fixes the wire format for every signed
ShareNet object as CBOR Deterministic Encoding (RFC 8949 §4.2.2)
with ShareNet-specific additional constraints, and fixes the choice
of encoder library as `cborg` with `canonical: true`.

## Context

Every signed object in ShareNet (NodeAdvertisement, RemoteNodeHint,
RouteProposal, RouteAcceptance, RouteCommitment, CircuitSetupAck,
ContributionProof, Settlement, GatewayServiceAgreement) is signed
over its canonical byte representation. Signature verification
requires that the verifier reconstruct the exact bytes that the
signer signed; any byte-level divergence causes the signature to
fail.

This places a hard requirement on the wire format:

1. **Deterministic.** Every implementation MUST produce byte-identical
   output for the same logical input. There is one canonical encoding.
2. **Re-encodable.** A verifier MUST be able to re-encode a received
   object and compare byte-for-byte against the received bytes.
   Mismatch indicates a non-canonical sender (protocol violation) or
   tampering (`spec/14-security.md` §7).
3. **Cross-language.** The format MUST be implementable in JS, TS,
   Python, Rust, Go, and any future platform adapter language. The
   specification MUST NOT depend on a single library's quirks.
4. **Compact.** Advertisements and hints are exchanged at discovery
   time, potentially over low-bandwidth links.
5. **Type-rich.** The format must distinguish byte strings from text
   strings, integers from floats. JSON's lack of a byte-string type
   is a real problem for cryptographic material.

## Decision

Use **RFC 8949 Section 4.2.2 "Deterministically Encoded CBOR"** as
the canonical wire format, with ShareNet-specific additional
constraints:

1. Map keys MUST be sorted by byte-wise lexicographic order of the
   encoded key (RFC 8949 §4.2.2 "length-first" ordering).
2. Integers MUST be in the shortest form (RFC 8949 §3.1).
3. Strings MUST be in the shortest definite form.
4. Indefinite-length encodings MUST NOT be used.
5. Undefined (`0x1F`) MUST NOT appear.
6. Floating-point values MUST NOT appear; timestamps are encoded as
   unsigned integers (Unix seconds).
7. Tags MUST NOT appear except where explicitly registered in the
   ShareNet tag registry (currently empty for the first deliverable).
8. Map keys for advertisements and hints are **integers** (see the
   CDDL sketch in `spec/03-node-advertisements.md` §3.1), not
   strings. This eliminates locale/encoding ambiguity in key
   ordering.

The encoder library is **`cborg`** invoked with `canonical: true`.
The decoder is `cborg`'s default decoder. Every signing path:

1. Constructs the logical object as a Map or plain object with
   integer keys.
2. Sets the `signature` field's value to the empty byte string
   `h''`.
3. Encodes via `cborg.encode(obj, { canonical: true })`.
4. Prepends the domain string (e.g.,
   `"sharenet-advertisement-v1"`).
5. Hashes with BLAKE2b-256 (ADR 0002).
6. Signs with Ed25519.

The verifier:

1. Decodes the received CBOR.
2. Re-encodes canonically; mismatch with received bytes is a protocol
   violation.
3. Sets the `signature` value to `h''`, re-encodes, prepends the
   domain string, hashes, and verifies the signature.

## Consequences

- **Implementations MUST use a deterministic CBOR encoder.** A naive
  CBOR encoder that emits map keys in insertion order is a
  conformance failure. The conformance test `spec/17-conformance.md`
  §2 test 3 checks this for advertisements; equivalent tests will
  exist for hints, routes, and circuits.
- **Re-encoding for verification is mandatory, not optional.** A
  verifier that trusts the sender's bytes without re-encoding is
  vulnerable to malleability attacks (a sender can produce two
  different byte sequences that decode to the same logical object,
  both of which verify, defeating audit-trail uniqueness).
- **Integer map keys eliminate locale/encoding ambiguity.** Sorting
  by UTF-8 byte order is well-defined but subtle. Integer keys
  sort by encoded length and value, which is trivially
  well-defined.
- **No tags.** CBOR tags are a flexibility point that can introduce
  implementation variance. Future extensions MUST register a tag
  in a new ADR before use.
- **No floats.** Timestamps are integers (Unix seconds). Sub-second
  precision is not needed for the protocol (the freshness window
  is 300s; sequence numbers handle ordering within a second).
- **Compact.** A typical NodeAdvertisement is on the order of 200
  bytes encoded. Fits in a single UDP datagram if a future
  transport requires it.
- **Decoder must be strict.** A decoder that silently accepts
  indefinite-length encodings or non-canonical integer forms would
  weaken the canonical-encoding invariant. `cborg`'s default decoder
  is strict enough; if it loosens in the future, ShareNet must pin
  the version or fork.

## Alternatives Considered

1. **Protocol Buffers.** Rejected — requires a schema compiler and a
   `.proto` file. The schema is also not self-describing. CBOR is
   self-describing and schema-free.
2. **MessagePack.** Considered and rejected — canonical form proposal
   is less rigorously specified than CBOR deterministic encoding, and
   less widely implemented.
3. **JSON.** Rejected — key ordering is not guaranteed by RFC 8259,
   number precision is implementation-defined (parsers lose precision
   on integers > 2^53), and there is no native byte-string type.
4. **Custom binary format.** Rejected — would re-derive every
   decision CBOR has already made. A permanent maintenance burden
   and a barrier to cross-language ports.
5. **CBOR with string keys instead of integer keys.** Rejected —
   string keys introduce locale/encoding ambiguity in canonical
   ordering and are larger on the wire.
6. **ASN.1 DER.** Rejected — DER is canonical but the tooling is
   heavyweight, the format is verbose, and the format is associated
   with X.509 baggage.

## References

- `spec/03-node-advertisements.md` §3 — canonical wire format
  definition.
- `spec/03-node-advertisements.md` §3.1 — CDDL sketch with integer
  map keys.
- `spec/14-security.md` §7 — canonical encoding enforcement rule.
- `spec/17-conformance.md` §2 test 3 — advertisement canonical
  re-encode equality test.
- `spec/17-conformance.md` §1.1 — canonical CBOR encoding golden
  vector set.
- RFC 8949 §4.2.2 — Deterministically Encoded CBOR.
- ADR 0002 — crypto library selection (hash primitive for signing
  input).
- ADR 0007 — AuthenticatedNodeRecord pipeline (depends on
  canonical re-encoding at verification time).
- Michael Nygard ADR template — structural source.
