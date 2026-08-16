# ADR 0002 — Crypto Library Selection

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision fixes the cryptographic primitive library
selection for the reference implementation and for any platform adapter
that ships in the first deliverable. Reconsideration requires a new ADR
and a re-run of the entire conformance suite.

## Context

The ShareNet 2.0 protocol (`spec/02-identity.md`, `spec/03-node-advertisements.md`,
`spec/08-circuits.md`) requires:

- **Ed25519** for signing (NodeId binding, advertisement signatures,
  hint signatures, route commitments, gateway agreements).
- **X25519** for ECDH key agreement (per-hop circuit keys).
- **BLAKE2b-256** for hashing (NodeId derivation, advertisement
  signing input, CircuitId derivation, manifest roots).
- **SHA-256** for hash chains (audit log, evidence chains).
- **HKDF** for KDF expansion (circuit hop keys from commitment root).
- **ChaCha20-Poly1305** AEAD (circuit frame encryption, per
  `spec/08-circuits.md` §4).

The library selection has hard constraints:

1. **Audited.** The protocol's security rests on these primitives.
   Hobbyist or unmaintained libraries are unacceptable.
2. **No native dependencies.** The reference implementation runs in the
   Next.js Node runtime. Native bindings complicate deployment, break
   on ARM and on locked-down cloud runtimes, and make the
   architecture regression tests (ADR 0010) harder to run.
3. **Works in the Next.js Node runtime AND in mini-services.** The
   same library set must be importable from `reference/`, `web/`, and
   any future mini-service. WASM modules that require special webpack
   loaders are a friction.
4. **Constant-time implementations where it matters.** Secret-key
   operations must use constant-time primitives. Public-key operations
   (signature verification, public-key derivation) need not be
   constant-time but should not leak key material.
5. **Browser-compatible.** Some primitives (e.g., Ed25519 verification
   in a future platform adapter) may need to run in the browser. Pure
   JS that imports cleanly into both Node and a bundler is preferred.

## Decision

Use the **`@noble`** family of cryptographic libraries as the single
source of primitives:

- `@noble/curves` for Ed25519 signing and X25519 ECDH.
- `@noble/hashes` for BLAKE2b-256, SHA-256, and HKDF.
- `cborg` for canonical CBOR encoding (see ADR 0004).

Reject `libsodium` and `libsodium-wrappers` for the reference
implementation. Native/WASM bindings complicate deployment, and the
`@noble` family covers every primitive ShareNet requires in pure JS.

Reject `tweetnacl` as the primary library. It is less audited than
`@noble` and has a less rigorous API surface around BLAKE2b.

Reject Node's `crypto` built-in as the primary library. It is not
portable to the browser or to mini-services uniformly, and BLAKE2b is
not in the standard set of FIPS algorithms Node exposes by default.

The AEAD choice is ChaCha20-Poly1305. `@noble/chacha` provides a
constant-time implementation; if `@noble/chacha` is unavailable, a
thin wrapper over `@noble/ciphers` is acceptable. AES-256-GCM is
permitted only where hardware acceleration is present, per
`spec/14-security.md` §10.

## Consequences

- **Pure-JS crypto is slower than native.** A single Ed25519 sign in
  `@noble/curves` is on the order of a few milliseconds on commodity
  hardware. For the first deliverable's workloads (advertisement
  verification, a handful of sign operations per request) this is
  acceptable. Production deployment at high throughput will need to
  revisit this ADR.
- **Constant-time guarantee.** `@noble/curves` and `@noble/hashes` are
  written with constant-time discipline for secret-key operations.
  This is the minimum bar for the protocol's signing paths.
- **No WASM, no native bindings.** The reference implementation deploys
  to any Node host that can run `npm install`. No special build
  toolchain, no `node-gyp`, no platform-specific binaries.
- **Browser path remains open.** A future platform adapter that runs
  protocol verification in the browser can import the same `@noble`
  packages without a separate codebase.
- **Single dependency surface to audit.** When a CVE is published
  against `@noble/*`, the blast radius is one upgrade.
- **AEAD library decision deferred slightly.** This ADR fixes
  ChaCha20-Poly1305 as the algorithm; the specific package
  (`@noble/chacha` vs `@noble/ciphers`) is recorded at Task 4 (canonical
  CBOR + crypto reference) and reflected in `package.json`.
- **Domain separation must be enforced in callers.** The `@noble`
  primitives do not enforce domain strings; ShareNet code must
  concatenate the frozen domain string (per `spec/14-security.md` §4)
  before hashing or signing. ADR 0004 and the conformance test
  `spec/17-conformance.md` §3.4 guard against omission.

## Alternatives Considered

1. **`libsodium-wrappers` (WASM).** Rejected — WASM loader integration
   with Next.js's bundler is fragile; deployment to serverless
   runtimes that do not allow WASM is a known issue; the `@noble`
   family covers every primitive ShareNet needs.
2. **`tweetnacl`.** Rejected — less audited than `@noble`; no native
   BLAKE2b (would require a separate library); signature API returns
   combined signature+public-key bytes that are awkward to split for
   the canonical-CBOR wire format.
3. **Node's `crypto` built-in.** Rejected — Ed25519 sign/verify is
   supported but BLAKE2b is not in the default set; not portable to
   the browser; cannot be the single source.
4. **`@stablelib/ed25519` + `@stablelib/blake2b`.** Considered and
   rejected — `@stablelib` is a fine alternative but `@noble` has a
   stronger audit trail and a single author with a track record of
   constant-time fixes.
5. **A custom Ed25519 implementation.** Rejected unconditionally —
   custom crypto violates `spec/14-security.md` §10 ("no custom
   crypto") and would not pass the architecture regression suite.

## References

- `spec/02-identity.md` §2 — NodeId derivation via BLAKE2b-256.
- `spec/03-node-advertisements.md` §4 — Ed25519-over-BLAKE2b signature.
- `spec/08-circuits.md` §4 — X25519 ECDH and ChaCha20-Poly1305 AEAD.
- `spec/14-security.md` §4 — domain separation register.
- `spec/14-security.md` §10 — algorithm choices (BLAKE2b-256, SHA-256,
  ChaCha20-Poly1305 preferred, AES-256-GCM only with hardware
  acceleration).
- ADR 0003 — NodeId derivation design (depends on this ADR).
- ADR 0004 — canonical CBOR wire format (depends on this ADR for hash
  primitive choice).
- Michael Nygard ADR template — structural source.
