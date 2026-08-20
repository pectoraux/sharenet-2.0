# ADR-0023: CircuitDestroy propagation semantics

**Date:** 2026-08-19
**Status:** ACCEPTED
**Phase:** R-009 Stage 3 Phase 3 (destroy propagation + true multi-process teardown)
**Supersedes:** None
**Superseded by:** None
**Amends:** ADR-0022 (adds propagation semantics to the teardown model)

## Context

R-009 Stage 3 Phase 2 (closed at commit `893c491`) established the canonical
teardown path: `processCircuitDestroy` authenticates the destroyer, durably
revokes the circuit (atomic ACTIVE→REVOKED transition), zeroizes local keys,
and returns the decoded `CircuitDestroy` for the caller to propagate.

However, Phase 2 did **not** define the propagation semantics:

- No formal direction model (which way does an initiator-originated destroy
  travel vs a gateway-originated destroy?).
- No byte-for-byte propagation invariant (a relay MUST forward the EXACT
  wire bytes it received — it MUST NOT re-sign or re-encode).
- No propagation-direction derivation from protocol state (the direction
  MUST be derived from the signed `destroyerRole`, not caller-supplied).
- No replay/duplicate-suppression model for propagation (the destroy nonce
  is per-event; each participant has its own durable store).
- No local-effect ordering mandate (decode → verify → revoke → zeroize →
  propagate — the destroy MUST NOT be propagated before the local
  participant has established its own revoked state).

This ADR freezes those semantics.

## Decision

### 1. Originators

Only **INITIATOR** and **GATEWAY** may originate a `CircuitDestroy`.

**Relays** (intermediate hops):
- MUST NOT originate a destroy.
- MUST NOT rewrite the original destroyer identity (`destroyerNodeId`,
  `destroyerEd25519PublicKey`, `destroyerRole`).
- MUST NOT replace the signature.
- MAY propagate a successfully authenticated destroy (byte-for-byte
  unchanged).

This is already enforced by `processCircuitDestroy`'s authorization model
(ADR-0022 §3): the `destroyerRole` + `verifyNodeIdBinding` + the
portable terminal-hop proof chain (for GATEWAY) bind the destroyer's
identity cryptographically. A relay cannot forge a destroy as the initiator
or gateway because it does not hold their Ed25519 secret keys.

### 2. Propagation direction (derived from protocol state, NOT caller-supplied)

The propagation direction is **derived from the signed `destroyerRole`**:

```
destroyerRole = INITIATOR (0x01) → propagate FORWARD
    INITIATOR → hop 0 → hop 1 → ... → GATEWAY

destroyerRole = GATEWAY (0x02) → propagate BACKWARD
    GATEWAY → hop N-1 → hop N-2 → ... → INITIATOR
```

A relay does NOT choose the direction — the `destroyerRole` field (signed by
the destroyer, verified by every participant) determines it. The helper
`propagationDirection(destroy)` derives `"FORWARD" | "BACKWARD"` from
`destroyerRole`. This makes it impossible for an unauthorized relay to claim
it originated the message or to redirect propagation.

There is NO caller-controlled `propagate: true` or `origin: "gateway"` boolean.
The direction is protocol state.

### 3. Propagated artifact (byte-for-byte unchanged + digest-bound)

The destroy message MUST remain **byte-for-byte identical** across all hops:

```
original CircuitDestroy wire bytes
    ↓
verify
    ↓
forward unchanged
```

A relay MUST NOT re-sign as itself. A relay MUST NOT re-encode the destroy.
`processCircuitDestroy` returns the original `wireBytes` in its result so the
caller can forward them directly without re-encoding.

**The PropagationChannelProof is bound to the EXACT destroy bytes via
`destroyDigest = BLAKE3(exact wire bytes)`** (R-009 Stage 3 Phase 3 final
transport-proof hardening). The sender hashes the raw wireBytes BEFORE any
decoding; the receiver hashes the raw received bytes + compares with
`proof.destroyDigest`. A mismatch (destroy substitution, byte mutation) is
REJECTED. The digest is covered by the proof's Ed25519 signature, so an
attacker cannot tamper with the digest without invalidating the signature.

If ANY field of the destroy is changed by a relay:
- `destroyerNodeId`, `destroyerRole`, `destroyReason`, `destroyNonce`,
  `circuitId`, `commitmentRoot`, `issuedAt`, `expiry`,
  `destroyerEd25519PublicKey`, `signature`

→ the `destroyDigest` check catches the substitution (the received bytes'
BLAKE3 digest will not match `proof.destroyDigest`), AND the signature
verification at the next hop FAILS (the signature covers all binding fields).

### 3a. PropagationChannelProof = portable cryptographic channel authentication

The `PropagationChannelProof` is the **portable network credential** for
destroy propagation. It attests:

```
sender      (senderNodeId + senderEd25519PublicKey + verifyNodeIdBinding)
receiver    (receiverNodeId)
circuit     (circuitId)
route       (commitmentRoot)
direction   (FORWARD or BACKWARD, derived from the signed destroyerRole)
EXACT destroy artifact (destroyDigest = BLAKE3(exact wire bytes))
```

All six are covered by the sender's Ed25519 signature. The receiver verifies
ALL six before delivering the destroy to `processCircuitDestroy()`.

The `AuthenticatedLink` remains a **local-only topology/proof artifact**
(WeakSet-registered, in-process). It MUST NOT be treated as the portable
network credential. The `PropagationChannelProof` is the sole portable
authentication for the transport hop — it crosses process/language boundaries
as canonical CBOR + is independently verifiable by any implementation.

### 3b. Direction enforcement at the receive boundary

The proof's `direction` is verified at the receive boundary, AFTER decoding
the destroy:

```
raw destroy
  ↓
decode
  ↓
verify CircuitDestroy (signature + routeId + role + semantic validity)
  ↓
propagationDirection(destroy.destroyerRole)  → derived direction
  ↓
verify proof.direction === derived direction
  ↓
verify destroyDigest
  ↓
processCircuitDestroy
```

The direction is NOT caller-supplied — it is derived from the signed
`destroyerRole`. A proof with the wrong direction (e.g., a BACKWARD proof
for a FORWARD destroy) is REJECTED. This prevents an attacker from
redirecting propagation by tampering with the proof's direction field.

### 4. Local effect (processing order)

Upon successful verification, each participant:

```
decode
    ↓
canonical validation (verifyCircuitDestroy: role + routeId + issuedAt<=expiry + signature)
    ↓
circuit binding (circuitId + commitmentRoot match local circuit context)
    ↓
destroy freshness validation (issuedAt <= now + SKEW, now < expiry, expiry <= circuit.expiry)
    ↓
destroyer authorization (verifyNodeIdBinding + role proof: initiator match OR gateway proof chain)
    ↓
durable atomic revoke (consumeDestroyAndRevoke — single transaction, ACTIVE→REVOKED)
    ↓
zeroize local secrets (forwardingKey, returnKey, K_ret, noncePrefix, initiatorX25519SecretKey)
    ↓
remove local forwarding state (implementation-specific; the circuit object's keys are zeroized)
    ↓
propagate ORIGINAL destroy bytes (forward unchanged to the next hop)
    ↓
retain replay floor + retain revocation tombstone (for audit + re-key protection)
```

**The destroy MUST NOT be propagated before the local participant has
successfully established its own revoked state.** A persistence failure
MUST NOT falsely propagate successful teardown. If `consumeDestroyAndRevoke`
fails, the destroy is NOT propagated (the result is `{ ok: false }`).

If already revoked (idempotent):
- `action: "ALREADY_REVOKED"`, `propagate: false`.
- The participant MUST NOT resurrect anything.
- Propagation MAY be suppressed (the destroy has already been forwarded by
  a prior receipt — re-forwarding would create duplicate traffic but is
  not a security violation since each downstream participant will also
  see it as idempotent).

**Duplicate propagation is ALLOWED but suppressed**: a relay that receives
the same destroy twice (after already revoking) returns
`{ action: "ALREADY_REVOKED", propagate: false }`. The relay does NOT
re-forward. This prevents infinite propagation loops.

### 5. Propagation replay semantics (ORIGIN replay vs PROPAGATION duplicate suppression)

The destroy nonce identifies ONE destroy event. The existing replay namespace
`(commitmentRoot, circuitId, destroyNonce)` is **per-participant** (each
participant has its own durable store). This is the correct model:

- **ORIGIN replay protection**: a participant that receives the SAME destroy
  (same nonce) twice consumes it once (the first `consumeDestroyAndRevoke`
  wins — the tombstone create is the authoritative transition); the second
  receipt sees the tombstone → idempotent. The nonce is NOT re-consumed.
- **PROPAGATION duplicate suppression**: each participant has its OWN
  `ConsumedCircuitDestroy` record in its OWN store. A destroy that
  propagates hop 0 → hop 1 → hop 2 is consumed independently at each hop
  (each hop's store records the nonce). A replay to the SAME hop is
  idempotent (tombstone exists). A first-time receipt by a DIFFERENT hop
  is accepted (fresh in that hop's store).

The existing namespace `(commitmentRoot, circuitId, destroyNonce)` is
**retained unchanged**. It is per-participant by construction (each
participant's durable store is independent). There is no global nonce
record — the destroy event is identified by the nonce, and each participant
records its own consumption + tombstone.

This is derived from the threat model: the destroy is a single signed
event that must reach every participant. Each participant independently
verifies + consumes + revokes. A malicious relay that replays the destroy
to a participant that has already processed it is caught by that
participant's tombstone (idempotent). A malicious relay that DOES NOT
forward the destroy cannot prevent the operator from re-issuing a new
destroy with a fresh nonce (the old nonce is consumed at the relays that
received it, but a new destroy with a new nonce is a new event).

### 6. Failure modes

**Local revoke succeeds + downstream transport fails:**
- The local circuit remains REVOKED. The local tombstone is persisted.
- The destroy was NOT propagated to the next hop.
- Retry semantics: the operator (or a propagation-retry layer) re-sends
  the SAME destroy to the next hop. The next hop receives it for the first
  time → fresh revoke. The local hop (already revoked) sees the retry as
  idempotent if the retry passes through it.
- The local participant MUST NOT roll back its tombstone if propagation
  fails — the local terminal state is authoritative.

**Local revoke persistence fails:**
- `consumeDestroyAndRevoke` returns `{ ok: false }`.
- The destroy is NOT propagated (`propagate` is not set; the result is a
  failure).
- No destructive "already propagated" state. The operator may retry the
  SAME destroy (the nonce is still fresh — the failed transaction rolled
  back, no split state).

### 7. Multi-process topology

A real multi-process test MUST:
- spawn each participant (initiator, relay 0, relay 1, gateway) as an
  INDEPENDENT process (its own V8 isolate / its own memory).
- pass ONLY serialized protocol artifacts (wire bytes, hex strings) across
  process boundaries.
- NOT pass `BrandedCommittedRoute`, `WeakSet`-backed objects, or in-memory
  circuit objects between processes.
- use a per-process durable store (or a per-process InMemory store that
  simulates the durable boundary).

The existing `tests/r009-multiprocess.test.ts` (R-009 Stage 2) established
this pattern for circuit-frame forwarding. Phase 3 extends it to destroy
propagation.

## Consequences

### Positive

- The propagation direction is protocol state (derived from `destroyerRole`),
  not caller-supplied — an unauthorized relay cannot redirect propagation.
- The byte-for-byte propagation invariant is verifiable: compare canonical
  wire bytes at each hop.
- The local-effect ordering (revoke → zeroize → propagate) ensures a
  persistence failure does not falsely propagate.
- The per-participant replay namespace is retained (no schema change);
  ORIGIN replay + PROPAGATION duplicate suppression are both handled.
- Duplicate propagation is suppressed (no infinite loops).

### Negative

- A relay that does not forward the destroy leaves downstream participants
  unaware. This is a liveness issue (not a safety issue) — the operator
  must re-issue or the propagation-retry layer must re-send. A future
  failure-detection integration (R-009 Stage 3 Phase 4+) will address this.
- The destroy nonce is consumed independently at each participant; a
  malicious relay that drops the destroy cannot be detected by the nonce
  consumption alone (the downstream participant simply never sees the nonce).

## Cross-references

- ADR-0022 (CircuitDestroy + teardown semantics — amended by this ADR).
- ADR-0019 (receiver-local replay protection — per-participant floors).
- `reference/circuit/destroy.ts` `processCircuitDestroy` (the canonical
  teardown path — extended with `action`/`propagate`/`wireBytes`).
- `tests/r009-multiprocess.test.ts` (R-009 Stage 2 multi-process pattern).
- `tests/r009-destroy-propagation.test.ts` (R-009 Stage 3 Phase 3 multi-process
  propagation tests — new).
