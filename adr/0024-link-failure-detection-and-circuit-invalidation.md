# ADR-0024: Link failure detection + durable circuit invalidation

**Date:** 2026-08-20
**Status:** ACCEPTED
**Phase:** R-009 Stage 3 Phase 4 (failure detection + durable circuit invalidation)
**Supersedes:** None
**Superseded by:** None
**Amends:** ADR-0022 (adds failure-triggered invalidation semantics), ADR-0023 (adds failure-propagation path)

## Context

R-009 Stage 3 Phase 3 (closed at commit `e6d779a`) established the complete
destroy-propagation transport: `propagateCircuitDestroy()` → authenticated
transport → `receiveAuthenticatedCircuitDestroy()` → `processCircuitDestroy()`.

However, there is **no failure detection** connecting real transport/link
failures to durable circuit invalidation:

- A TCP socket close/error in `TcpCircuitDestroyTransport.send()` returns
  `{ ok: false, reason }` but does NOT cascade to `LinkAuthStateMachine.goToLinkDown()`
  or `RecoveryManager.handleLinkEvent()`.
- A single AEAD authentication failure in `processCircuitWireFrame()` rejects
  the frame but does NOT generate a failure observation.
- `RecoveryManager` is a callable state machine — nothing feeds it real
  production signals.
- A confirmed link failure does NOT durably invalidate the circuit.

This ADR freezes the failure-detection semantics + the invalidation chain.

## Decision

### 1. Three failure categories (frozen)

**1a. Transport-confirmed failure** — an authenticated transport channel
permanently closes. Examples: TCP connection reset (ECONNRESET), connection
refused (ECONNREFUSED), socket timeout, peer process killed.

A transport-confirmed failure MAY immediately generate `LINK_DOWN`. No
threshold is needed — the transport itself confirms the peer is unreachable.

**1b. Protocol-authentication failure** — a single bad frame, AEAD tag
failure, malformed packet, invalid proof, or invalid CircuitDestroy. These
are evidence of a possible attacker OR a buggy peer — NOT evidence the peer
is dead.

A single protocol-authentication failure MUST NOT automatically generate
`LINK_DOWN`. Reason: an attacker can inject one bad packet to trigger
LINK_DOWN on a healthy link — a denial-of-service.

**1c. Repeated protocol failures** — multiple protocol-authentication
failures within an observation window. This IS evidence the peer is either
malicious or broken.

### 2. Failure detector state machine (frozen)

```
HEALTHY
   ↓ single protocol failure
DEGRADED
   ↓ repeated failures reach threshold (within window)
   OR transport-confirmed failure
LINK_DOWN (terminal)
```

**Frozen threshold:**

```
PROTOCOL_FAILURE_THRESHOLD = 3
PROTOCOL_FAILURE_WINDOW_SECONDS = 60
```

- A single protocol failure → `DEGRADED` (link is suspect but not dead).
- Within `PROTOCOL_FAILURE_WINDOW_SECONDS` (60s) of the FIRST failure, if
  `PROTOCOL_FAILURE_THRESHOLD` (3) total failures are observed → `LINK_DOWN`.
- A transport-confirmed failure → `LINK_DOWN` immediately (regardless of
  current state).
- Successful authenticated traffic resets the failure count + returns to
  `HEALTHY` (from `DEGRADED`).
- `LINK_DOWN` is terminal — no automatic recovery. Recovery execution is
  Phase 5 (out of scope).
- Duplicate `LINK_DOWN` is idempotent (no re-invalidation).

**Why 3 failures / 60 seconds:**
- 1 failure is too aggressive (attacker can trivially DoS).
- 10+ failures is too lenient (a broken peer can leak data for minutes).
- 3 failures in 60s is tight enough to detect a broken/malicious peer
  quickly, while tolerating occasional network corruption (1-2 bad frames
  are common on lossy mesh links).
- These values are FROZEN — changing them requires a new ADR.

### 3. FailureObservation type (protocol core)

A local diagnostic structure (NOT a portable signed protocol object). It
captures enough information for the detector to classify the failure:

```
FailureObservation = {
  linkId: string
  localNodeId: string
  remoteNodeId: string
  circuitId?: Uint8Array  (if applicable)
  category: "TRANSPORT_CONFIRMED" | "PROTOCOL_AUTHENTICATION"
  reason: string
  observedAt: number  (unix seconds)
}
```

This is NOT signed or serialized across the wire. It is a local
implementation artifact used by the `LinkFailureDetector`.

### 4. LinkFailureDetector (protocol core)

```
LinkFailureDetector
  recordObservation(observation: FailureObservation): LinkHealthState
  getState(linkId: string): LinkHealthState
  getLinkHealthEvents(): LinkHealthEvent[]
```

- `recordObservation()` updates the per-link state machine.
- `TRANSPORT_CONFIRMED` → immediate `LINK_DOWN`.
- `PROTOCOL_AUTHENTICATION` → increment failure count; if threshold reached
  within window → `LINK_DOWN`; else → `DEGRADED`.
- Emits `LinkHealthEvent` (the existing type from recovery.ts) on state
  transitions → these events feed `RecoveryManager.handleLinkEvent()`.

**Security: the caller CANNOT assert `confirmed=true`.** The classification
is derived from the evidence category — `TRANSPORT_CONFIRMED` is only
produced by the platform layer (real socket events), not by a caller
assertion.

### 5. Durable circuit invalidation on LINK_DOWN

When a link reaches `LINK_DOWN`:

```
LINK_DOWN
  ↓
identify affected circuit(s) via RecoveryManager route/link mapping
  ↓
durable revocation via CircuitDestroyStore.consumeDestroyAndRevoke()
  (destroyReason = DESTROY_REASON_LINK_FAILURE (0x03)
   or DESTROY_REASON_GATEWAY_DISAPPEARANCE (0x04))
  ↓
zeroize circuit key material (zeroizeCircuit)
  ↓
retain replay floors
  ↓
emit RecoveryPlan (no execution)
```

**The authoritative invariant remains:**
- `ACTIVE ≡ no revocation tombstone`
- `REVOKED ≡ durable revocation tombstone exists`

Failure-triggered invalidation uses the SAME tombstone as explicit destroy
and natural expiry. The `destroyReason` field in the tombstone distinguishes:
- `0x01` = `OPERATOR_INITIATED` (explicit CircuitDestroy)
- `0x02` = `CIRCUIT_EXPIRED` (natural expiry)
- `0x03` = `LINK_FAILURE` (failure-triggered)
- `0x04` = `GATEWAY_DISAPPEARANCE` (failure-triggered)
- `0x05` = `PROTOCOL_VIOLATION` (failure-triggered)

**The tombstone is the SOLE terminal-state authority.** No competing
terminal-state database.

### 6. Failure invalidation atomicity

For confirmed failure:

```
confirmed failure (LINK_DOWN)
  ↓
durable invalidation (consumeDestroyAndRevoke — atomic, fail-closed)
  ↓
zeroize keys
  ↓
emit recovery-planning event
```

If durable invalidation fails:
- MUST NOT claim REVOKED.
- MUST NOT emit false recovery signal.
- MUST NOT pretend zeroization completed the terminal transition.
- Retry must remain possible (the nonce is NOT consumed if the transaction
  rolled back — no split state).

### 7. RecoveryManager integration

```
LinkFailureDetector
  ↓ LinkHealthEvent (newStatus: "DOWN", reason: "LINK_DOWN")
RecoveryManager.handleLinkEvent(event)
  ↓ invalidates routes using the link
  ↓ invalidates affected circuits
  ↓
RecoveryPlan (NO execution)
```

The `RecoveryPlan` is descriptive — it identifies the next step but does NOT
execute recovery. Recovery execution is Phase 5 (out of scope).

### 8. Architecture (ADR-0013 layer separation)

- `reference/failure/` — protocol core: `LinkFailureDetector`,
  `FailureObservation`, `LinkHealthState`, frozen constants. NO Prisma,
  NO platform socket imports.
- `src/lib/sharenet/` — platform layer: TCP socket integration, durable
  adapters, platform failure hooks (bridging socket errors to the detector).
- Architecture tests #21/#23 MUST remain green.

## Consequences

### Positive

- Real transport failures (socket close, ECONNRESET) are detected + cascade
  to durable circuit invalidation.
- A single forged bad packet does NOT kill a link (anti-DoS).
- The existing authoritative tombstone model is reused — no new terminal-state
  database.
- The `destroyReason` field distinguishes failure-triggered invalidation from
  explicit destroy and natural expiry.
- `RecoveryManager` receives real production signals (not just test calls).

### Negative

- The 3/60 threshold is a policy choice — it may need tuning for different
  deployment environments. Changing it requires a new ADR.
- `LINK_DOWN` is terminal — no automatic recovery. The operator must
  establish a new circuit (Phase 5).
- The `FailureObservation` is local-only — it does not cross trust boundaries.
  A future phase may need signed failure evidence for cross-participant
  failure consensus.

## Cross-references

- ADR-0022 (CircuitDestroy + teardown semantics — amended: failure-triggered
  invalidation uses the same tombstone).
- ADR-0023 (CircuitDestroy propagation — amended: failure propagation path).
- `reference/link/link.ts` (LinkState — LINK_DOWN is a terminal state).
- `reference/transport/link-auth-state.ts` (LinkAuthStateMachine — goToLinkDown).
- `reference/routing/recovery.ts` (RecoveryManager — handleLinkEvent).
- `reference/circuit/destroy.ts` (DESTROY_REASON_LINK_FAILURE = 0x03).
- `reference/circuit/replay-stores.ts` (CircuitDestroyStore — atomic tombstone).
- `src/lib/sharenet/durable-circuit-replay-stores.ts` (DurableSqliteCircuitDestroyStore).
- `src/lib/sharenet/circuit-destroy-transport.ts` (TcpCircuitDestroyTransport).
