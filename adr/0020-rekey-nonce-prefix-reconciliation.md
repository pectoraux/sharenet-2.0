# ADR-0020: Re-key nonce-prefix reconciliation (R-009 Stage 1 final)

**Date:** 2026-08-18
**Status:** ACCEPTED
**Phase:** R-009 Stage 1 (circuit substrate freeze)
**Supersedes:** The nonce-prefix derivation in `eaca43b` through `980ced6` (which bound the nonce prefix to `commitment_root` only).
**Superseded by:** None

## Context

The R-009 Stage 1 re-audit of `980ced6` found a protocol contradiction
between the normative spec and the implementation:

- `spec/08 §4.7` says: "a new circuit MUST start from a fresh `(eph_priv,
  eph_pub)` and a new `circuit_nonce_prefix`."
- But `deriveNoncePrefix()` derived the nonce prefix solely from
  `commitment_root`:

  ```text
  HKDF(salt = commitment_root, ikm = "nonce-prefix", info = "SHARENET/CIRCUIT/NONCE/1")[0:8]
  ```

This meant two circuits on the **same route** with **different ephemeral
keys** got the **same** nonce prefix:

```text
Circuit A: root = R, eph = A → noncePrefix = P
Circuit B: root = R, eph = B → noncePrefix = P    ← same
```

The `CircuitId` was different (it includes the initiator ephemeral public
key), but the nonce space was not uniquely scoped to a circuit instance.

Nonce uniqueness across re-key relied solely on the persistent sequence
floor. That is a valid safety mechanism, but it did not match the
normative text — and the contradiction needed to be resolved before the
circuit substrate could be considered frozen.

## Decision

### Bind nonce derivation to the circuit instance

The nonce prefix is now derived from `(commitment_root, initiator_x25519_pub)`:

```text
nonce_prefix =
  HKDF-SHA256(
    salt = commitment_root,
    ikm  = initiator_x25519_pub,   ; 32 bytes — the circuit-instance binding
    info = "SHARENET/CIRCUIT/NONCE/1"
  )[0:8]
```

The `ikm` is the raw 32-byte initiator ephemeral X25519 public key — the
same key used in `CircuitId` derivation (§3). This means:

```text
new eph keypair → new CircuitId → new nonce prefix
```

Two circuits on the same route with different ephemeral keys now get
**different** nonce prefixes — satisfying §4.7 by construction.

### The frozen derivation (per spec/08 §4.3, amended)

```text
nonce_prefix = first 8 bytes of HKDF-SHA256(
  salt = commitment_root,
  ikm  = initiator_x25519_pub,
  info = "SHARENET/CIRCUIT/NONCE/1"
)
```

The domain tag `SHARENET/CIRCUIT/NONCE/1` is unchanged (FROZEN per R-001 /
ADR-0017). Only the `ikm` input changed (from the string `"nonce-prefix"`
to the 32-byte initiator ephemeral public key).

### Relationship to the receiver-local sequence floor (ADR-0019)

The nonce-prefix binding (this ADR) and the receiver-local sequence floor
(ADR-0019) are **complementary, independent** protections:

- **Nonce-prefix binding (ADR-0020):** guarantees nonce uniqueness across
  re-key on the same route — a fresh ephemeral key produces a fresh nonce
  prefix, so `(nonce_prefix, frame_sequence)` pairs cannot repeat across
  circuit instances on the same route.
- **Receiver-local sequence floor (ADR-0019):** guarantees replay detection
  at every receiver — a frame with `seq ≤ floor` is rejected, even if the
  AEAD succeeds (e.g., a malicious upstream relay replaying a captured
  ciphertext). Keyed by `(commitmentRoot, hopIndex, direction)`.

Both are required. Neither substitutes for the other.

## Consequences

### Positive

- The implementation now matches the normative spec: a re-key produces a
  fresh nonce prefix, satisfying `spec/08 §4.7`.
- Nonce uniqueness across re-key is guaranteed by construction (fresh
  ephemeral key → fresh nonce prefix), not solely by the persistent
  sequence floor.
- The `CircuitId` and `nonce_prefix` are now both bound to the same
  circuit-instance identity `(commitment_root, initiator_x25519_pub)` —
  consistent cryptographic binding.

### Negative

- The `deriveNoncePrefix()` signature changed (now takes
  `initiatorX25519PublicKey` as a second argument). All callers updated:
  `setupCircuit`, `handleCircuitSetup`, `processCircuitSetupAck`,
  `establishDistributedCircuit`, the conformance runners, and the vector
  generator.
- The frozen golden vectors `V-CIRCUIT-001` (nonce-prefix-deterministic)
  and `V-CIRCUIT-FRAME-001` (sealed-frame hex) were regenerated with the
  new derivation. The `initiatorX25519PubHex` input is now carried in the
  vector's `sharedInputs`/`input` so the derivation is reproducible.

## Conformance evidence

- `V-CIRCUIT-001` vector `nonce-prefix-deterministic`: updated to take
  `initiatorX25519PubHex` and expect the new `noncePrefixHex`.
- `V-CIRCUIT-001` vector `nonce-prefix-re-key-freshness` (NEW): proves two
  circuits on the same route with different ephemeral keys get different
  nonce prefixes.
- `V-CIRCUIT-FRAME-001`: regenerated — the sealed-frame hex changes because
  the nonce prefix (used in AEAD nonces) changed. The `sharedInputs` now
  carries `initiatorX25519PubHex` so the verifier can re-derive the prefix.

## Cross-references

- `spec/08-circuits.md` §4.3 (Nonce Uniqueness — amended)
- `spec/08-circuits.md` §4.7 (Expiration — clarifying note added)
- `reference/circuit/circuit.ts` `deriveNoncePrefix()` — the corrected derivation
- ADR-0017 (protocol freeze reconciliation — the domain tag is unchanged)
- ADR-0019 (receiver-local replay protection — complementary, independent)
