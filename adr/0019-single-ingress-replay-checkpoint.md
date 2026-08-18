# ADR-0019: Single ingress replay checkpoint (R-009 Stage 1)

**Date:** 2026-08-18
**Status:** ACCEPTED
**Phase:** R-009 Stage 1 (forward traffic)
**Supersedes:** None
**Superseded by:** (future ADR when Stage 2 freezes return-onion semantics)

## Context

R-009 Stage 1 implements the `CircuitFrame` data-plane packet protocol for
**forward** traffic (source → gateway). The durable sequence floor
(`CircuitSequenceFloorStore`, keyed by `commitmentRoot`) provides ORDERED_STREAM
replay protection per spec/08 §4.5 (FROZEN per R-008).

A frame with `frameSequence=N` is processed by **every hop** on the route
(hop 0 peels the outermost layer, hop 1 peels the next, ..., the terminal hop
delivers plaintext). But the durable floor is keyed by `commitmentRoot` (the
route), **not by hop**. This creates a question: which hop commits the floor?

### The defect found in the re-audit of `eaca43b`

The initial Stage 1 implementation (`f166693`) introduced a `commitFloor`
boolean parameter on `processCircuitWireFrame()`:

```ts
processCircuitWireFrame(circuit, hopIndex, wireBytes, commitFloor = true)
```

The intent was:
- hop 0 → `commitFloor=true` (ingress checkpoint)
- hop 1+ → `commitFloor=false` (forward only)

But this made the security invariant **caller-controlled**. A bad production
integration could:
- call hop 0 with `commitFloor=false` → never advance the floor (replay protection disabled)
- call hop 1 with `commitFloor=true` → commit the same sequence after hop 0 (self-replay)

This is the same class of problem ShareNet has systematically eliminated
elsewhere (e.g., R-008 made durable stores mandatory at the type level rather
than relying on callers to supply them).

### The architectural lesson

> A security-critical fact should be derived from protocol state, not supplied
> as a caller-controlled boolean.

## Decision

### 1. Commit ownership is protocol-enforced (not caller-controlled)

The `commitFloor` boolean is **removed** from `processCircuitWireFrame()`.
Commit ownership is **derived from protocol semantics**:

```text
direction == FORWARD && hopIndex == 0
    → COMMIT the durable sequence floor (ingress checkpoint)

direction == FORWARD && hopIndex > 0
    → forward only (no commit — the floor was committed at hop 0)
```

This is the **single ingress replay checkpoint** per route. The protocol
itself determines commit ownership — a caller cannot disable the commit at
hop 0, nor claim it at hop 1.

### 2. Stage 1 rejects BACKWARD direction

Stage 1 implements **FORWARD traffic only**. The backward/return-onion protocol
is Stage 2 work. Until Stage 2 freezes the return-onion semantics (including
the replay-floor keying question — see "Open question for Stage 2" below),
the Stage 1 production path (`processCircuitWireFrame`) **rejects backward
frames**:

```text
direction != FORWARD → REJECT (Stage 1 — fail closed)
```

The generic `CircuitFrame` decoder (`decodeCircuitFrame`) still accepts both
enum values (`0x01` FORWARD + `0x02` BACKWARD) so the wire schema stays
compatible with Stage 2. Only the production path fails closed on BACKWARD.

### 3. The frozen pipeline (R-008 + R-009 Stage 1)

```text
processCircuitWireFrame(circuit, hopIndex, wireBytes)
    1. decode (strict canonical CBOR)
    2. reject BACKWARD direction (Stage 1 — fail closed)
    3. AEAD authenticate + decrypt one layer (openFrame)
       → reject if tag fails (floor UNCHANGED — DoS fix from R-008)
    4. atomic durable sequence commit (ONLY at ingress checkpoint:
       direction==FORWARD && hopIndex==0)
       → reject if replay/stale (seq ≤ floor) or persistence fails (fail-closed)
    5. forward / deliver
       → terminal hop: deliver plaintext
       → intermediate hop: encode nextFrame → forward bytes to next hop
```

The durable commit (step 4) happens ONLY after AEAD succeeds (step 3) — the
R-008 frozen ordering (AEAD-before-commit) is preserved. An unauthenticated
frame is rejected at step 3 and the floor is never touched.

## Consequences

### Positive

- The "exactly one ingress point commits the frame sequence" invariant is now
  **protocol-enforced**, not caller-enforced. A bad integration cannot
  accidentally disable replay protection or cause a self-replay.
- The Stage 1 production path fails closed on BACKWARD, preventing ambiguous
  state where backward frames are accepted before the return-onion replay
  semantics are frozen.
- The frozen R-008 crypto substrate is untouched — this ADR only affects the
  R-009 production path layer.

### Negative

- Stage 1 cannot process backward traffic. This is intentional — the
  return-onion protocol is Stage 2 work, and accepting backward frames
  before the replay-floor keying question is resolved would create
  ambiguous state.

### Neutral

- `processWireFrame()` (the decode + AEAD helper, no commit) is kept as a
  TEST-ONLY helper for the conformance vectors + unit tests that verify the
  decode + AEAD mechanics in isolation. It is clearly marked as not for
  production use.

## Open question for Stage 2

There is currently one durable sequence floor per:

```text
commitmentRoot
```

But the frame protocol has two directions:

```text
FORWARD
BACKWARD
```

If both directions use independent sequence streams, then the durable state
logically becomes:

```text
(commitmentRoot, direction)
    → sequence floor
```

rather than:

```text
commitmentRoot
    → one sequence floor
```

Otherwise:

```text
forward seq 10
    ↓
backward seq 1
    ↓
shared floor = 10
    ↓
backward frame rejected (1 ≤ 10)
```

Stage 2 MUST explicitly freeze whether:

```text
one sequence namespace per route
```

or:

```text
direction-specific sequence namespaces per route
```

is normative. The expected resolution is **direction-specific floors** (so
forward and backward sequences advance independently), but this requires an
explicit spec amendment + a Stage 2 ADR.

When Stage 2 freezes this, the BACKWARD rejection in `processCircuitWireFrame`
is lifted, and the return-onion processing path is added with its own
ingress checkpoint semantics (likely: the gateway is the ingress checkpoint
for backward traffic, mirroring how hop 0 is the ingress checkpoint for
forward traffic).

## Cross-references

- `spec/08-circuits.md` §4.5 (ORDERED_STREAM replay model — FROZEN per R-008)
- `spec/08-circuits.md` §4.6 (CircuitFrame wire object — direction field)
- `reference/circuit/forwarding.ts` `processCircuitWireFrame()` — the
  canonical production entry point that implements this ADR.
- `reference/circuit/replay-stores.ts` `CircuitSequenceFloorStore` — the
  durable floor store (keyed by `commitmentRoot` for Stage 1).
- ADR-0013 (three-layer separation — the protocol core stays DB-free).
- R-008 final hardening (mandatory durable stores + AEAD-before-commit ordering).
