# ADR-0019: Receiver-local replay protection (R-009 Stage 1 + Stage 2)

**Date:** 2026-08-18 (revised for Stage 2)
**Status:** ACCEPTED
**Phase:** R-009 Stage 1 (forward traffic) + Stage 2 (backward/return traffic)
**Supersedes:** The "single ingress replay checkpoint" model from the initial 9726418 version of this ADR.
**Superseded by:** None

## Context

R-009 Stage 1 implements the `CircuitFrame` data-plane packet protocol for
**forward** traffic (source → gateway). The durable sequence floor
(`CircuitSequenceFloorStore`) provides ORDERED_STREAM replay protection per
spec/08 §4.5 (FROZEN per R-008).

A frame with `frameSequence=N` is processed by **every hop** on the route
(hop 0 peels the outermost layer, hop 1 peels the next, ..., the terminal hop
delivers plaintext).

### The defect found in the re-audit of `9726418`

The initial Stage 1 implementation (commits `eaca43b` → `f166693` → `9726418`)
went through three iterations on the commit-ownership question:

1. `eaca43b`: a `commitFloor` boolean (caller-controlled — a bad integration
   could disable the commit at hop 0 or claim it at hop 1).
2. `9726418`: commit ownership derived from protocol state
   (`direction==FORWARD && hopIndex==0` → commit; `hopIndex>0` → no commit).
   This eliminated the caller-controlled boolean but introduced a worse problem.

The `9726418` model committed the floor **only at the ingress relay** (hop 0).
Downstream hops (hop 1+) did AEAD + forward without any durable commit.

### Why ingress-only commit is insufficient

The circuit spec (spec/08 §4.5) says:

> "frame_sequence is strictly increasing per circuit; a receiver rejects any
> frame whose sequence is <= the highest sequence already accepted."

The normative rule is **receiver-local** — every receiver on the circuit
enforces replay protection, not just the ingress. ShareNet's threat model
explicitly includes **malicious relays**. Consider:

```text
Source → Relay A → Relay B → Gateway
```

A legitimate frame with sequence 10 reaches Relay B. Relay B does AEAD (passes)
+ forward (no commit, per the ingress-only model). Now a malicious Relay A can
replay the already-valid inner ciphertext for sequence 10 toward Relay B.
Relay B has no local floor, so:

```text
replayed authenticated frame → Relay B → AEAD succeeds → accepted again
```

The ingress floor at Relay A does not protect Relay B because the replay occurs
**after** the ingress checkpoint.

## Decision

### 1. Receiver-local replay namespace

The durable replay namespace is changed from:

```text
commitmentRoot
```

to:

```text
(commitmentRoot, hopIndex, direction)
```

Each hop has a different AEAD key (per spec/08 §4.1), and therefore needs its
own replay state. Every receiver commits its own floor.

### 2. Every hop commits (no ingress-only checkpoint)

`processCircuitWireFrame()` performs the durable `checkAndAdvance` at
`(commitmentRoot, hopIndex, DIRECTION_FORWARD)` on **every** hop — not just
hop 0. There is no "ingress-only" checkpoint; every receiver enforces replay
protection against its own floor.

```text
Source
  ↓
Hop 0: floor(root, 0, FORWARD) = N  ← commits
  ↓
Hop 1: floor(root, 1, FORWARD) = N  ← commits (its OWN floor, independent)
  ↓
Hop 2: floor(root, 2, FORWARD) = N  ← commits (its OWN floor, independent)
  ↓
Gateway
```

Each hop executes:

```text
decode → reject BACKWARD → AEAD authenticate → receiver-local durable commit → forward
```

A malicious upstream relay replaying an already-valid inner ciphertext toward
a downstream hop is caught by the downstream hop's own floor (the AEAD succeeds
— the ciphertext is valid — but `seq ≤ floor` rejects it).

### 3. Re-key continuation is per-receiver

Per spec/08 §4.5: "Sequence floors persist across circuit re-key events; a
re-key MUST continue the counter from the prior floor." This holds **per
receiver**: a re-key on the same `(route, hop, direction)` continues from that
receiver's prior floor. The durable store (keyed by `(commitmentRoot, hopIndex,
direction)`) persists this across process restart.

### 4. Stage 1 rejects BACKWARD direction (unchanged from 9726418)

Stage 1 implements FORWARD traffic only. The return-onion protocol is Stage 2
work. `processCircuitWireFrame()` fails closed on `direction != FORWARD`.
The generic `CircuitFrame` decoder still accepts both enum values (0x01 +
0x02) so the wire schema stays compatible with Stage 2.

### 5. The frozen pipeline (R-008 + R-009 Stage 1, revised)

```text
processCircuitWireFrame(circuit, hopIndex, wireBytes)
    1. decode (strict canonical CBOR)
    2. reject BACKWARD direction (Stage 1 — fail closed)
    3. AEAD authenticate + decrypt one layer (openFrame)
       → reject if tag fails (floor UNCHANGED — DoS fix from R-008)
    4. atomic durable sequence commit at THIS RECEIVER's floor
       (circuit.floorStore.checkAndAdvance(root, hopIndex, FORWARD, seq))
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

- Replay protection is enforced at **every receiver**, not just the ingress.
  A malicious upstream relay cannot replay an already-valid inner ciphertext
  toward a downstream hop — the downstream hop's own floor catches it.
- The model matches the normative spec rule (receiver-local) and ShareNet's
  threat model (malicious relays).
- Re-key continuation is preserved per-receiver.
- The frozen R-008 crypto substrate is untouched — this ADR only affects the
  replay-namespace keying + the commit location.

### Negative

- More durable state: one floor row per (route, hop, direction) instead of
  one per route. For an N-hop circuit, N floor rows per direction. This is
  acceptable — the rows are small + the security benefit is essential.

## Stage 2 resolution (backward/return traffic — RESOLVED)

With the receiver-local namespace `(commitmentRoot, hopIndex, direction)`,
forward and backward sequences are **already independent** (different
`direction` values → different floor rows). The "direction-specific floors"
question from the previous version of this ADR is **resolved by
construction** — the namespace already includes `direction`.

R-009 Stage 2 (this revision) completes the bidirectional model:
1. The BACKWARD rejection in `processCircuitWireFrame()` is **lifted** —
   backward frames are now accepted.
2. The return-onion sealing (`sealReturnFrame`) is implemented: the gateway
   seals the return payload using each hop's `returnKey`, from the innermost
   hop (hop 0, the source) to the outermost hop (hop N-1, the gateway's
   neighbor). This is the MIRROR of the forward onion.
3. `openFrame` computes `isTerminal` correctly for both directions:
   - FORWARD: terminal = hop N-1 (the gateway).
   - BACKWARD: terminal = hop 0 (the source).
4. `processCircuitWireFrame` commits at `(root, hopIndex, frame.direction)`
   — so every hop commits its own floor for BOTH directions. A forward
   frame at seq=1 + a backward frame at seq=1 are BOTH accepted at the
   same hop (different `direction` → different floor row). A replay in
   either direction is caught by that direction's own floor.

The bidirectional replay model is now frozen. See `spec/08 §4.6a`.

## Architectural lesson (carried forward from 9726418)

> A security-critical fact should be derived from protocol state, not supplied
> as a caller-controlled boolean.

The `9726418` version derived commit ownership from protocol state
(`hopIndex==0`) — which was correct as far as it went, but the deeper
principle is that the **replay state itself** belongs to the receiving
security context (`(commitmentRoot, hopIndex, direction)`), not merely the
route. The "which hop commits" question is answered by "every hop commits,
at its own floor" — there is no single checkpoint to derive ownership of.

## Cross-references

- `spec/08-circuits.md` §4.5 (ORDERED_STREAM replay model — FROZEN per R-008)
- `spec/08-circuits.md` §4.6 (CircuitFrame wire object — direction field)
- `reference/circuit/replay-stores.ts` `CircuitSequenceFloorStore` — the
  durable floor store interface (now keyed by `(commitmentRoot, hopIndex, direction)`).
- `reference/circuit/forwarding.ts` `processCircuitWireFrame()` — the
  canonical production entry point that commits at every receiver.
- `reference/circuit/circuit.ts` `processCircuitFrame()` — the lower-level
  frame processor (also commits at `(root, hopIndex, direction)`).
- `src/lib/sharenet/circuit-persistence.ts` — the Prisma-backed durable
  substrate (schema keyed by `(commitmentRootHex, hopIndex, direction)`).
- ADR-0013 (three-layer separation — the protocol core stays DB-free).
- R-008 final hardening (mandatory durable stores + AEAD-before-commit ordering).
