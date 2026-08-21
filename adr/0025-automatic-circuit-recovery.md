# ADR-0025: Automatic circuit recovery execution

**Date:** 2026-08-21
**Status:** ACCEPTED
**Phase:** R-009 Stage 3 Phase 5 (automatic circuit recovery execution)
**Supersedes:** None
**Superseded by:** None
**Amends:** ADR-0024 (adds recovery execution after failure detection)

## Context

R-009 Stage 3 Phase 4 (closed at commit `31ad0d5`) established the full
failure-detection → durable-invalidation → RecoveryPlan chain. However,
the `RecoveryPlan` is **descriptive only** — no production code executes it.

Every primitive for recovery execution already exists:
- `discoverAlternativeGateways()` — gateway candidate discovery
- `signRouteAcceptance()` / `createRouteCommitment()` — route construction
- `createBrandedCommittedRoute()` — route branding
- `establishDistributedCircuit()` — circuit setup
- `handleCircuitSetup()` — per-relay ack processing

But nothing wires the `invalidatedRouteIds` from `RecoveryManager.handleLinkEvent()`
into the full pipeline. The recovery primitives are dead code in production.

This ADR freezes the recovery execution semantics.

## Decision

### 1. Recovery state machine (frozen)

```
RECOVERY_PENDING
   ↓ (triggered by LINK_DOWN → invalidated route)
DISCOVERING
   ↓ (discoverAlternativeGateways)
ROUTING
   ↓ (new RouteProposal + RouteAcceptance + RouteCommitment)
COMMITTING
   ↓ (createBrandedCommittedRoute)
ESTABLISHING_CIRCUIT
   ↓ (establishDistributedCircuit)
VERIFYING
   ↓ (verify new circuit is ACTIVE)
RECOVERED (terminal success)

Failure from any state:
   ↓
FAILED (terminal)
```

**Terminal states:** `RECOVERED` and `FAILED` are terminal. No transition out.
A retry MUST create a NEW recovery attempt with a new `recoveryAttemptId`.

**No `FAILED → ACTIVE`:** A failed recovery cannot resurrect the old circuit
or the partially-created new circuit.

### 2. Recovery attempt identity (frozen)

Every recovery execution has a unique `recoveryAttemptId`:

```
recoveryAttemptId = BLAKE3-256(
  "SHARENET/RECOVERY/ATTEMPT/1" ||
  failedCircuitId ||
  failedCommitmentRoot ||
  failureEventTimestamp ||
  recoveryAttemptNonce  (16 bytes random)
)
```

Bound to: failed circuit identity, failed route identity, failure event,
attempt nonce, creation timestamp. It is impossible to confuse attempt A
with attempt B.

### 3. Candidate gateway selection (frozen)

Uses the existing `discoverAlternativeGateways()`. Selection considers:
- capability (must match required service)
- policy (must pass gateway policy)
- availability (must be in the healthy node set)
- route constraints (must not be the failed gateway)
- previous failure evidence (failed gateway is excluded)

**Deterministic ordering:** candidates are ordered by NodeId (lexicographic).
The first eligible candidate is selected.

If no candidate exists: `RecoveryPlan → FAILED / NO_RECOVERY_POSSIBLE`.
No fabricated fallback.

### 4. New route proposal (frozen)

Recovery MUST create a NEW `RouteProposal` using the existing canonical
route construction. It MUST NOT reuse:
- old proposal
- old routeId
- old commitmentRoot
- old acceptances

The new proposal uses the existing `signRouteAcceptance()` +
`createRouteCommitment()` machinery. The new `commitmentRoot` is derived
from the new proposal + new acceptances via the Merkle tree.

### 5. New circuit establishment (frozen)

Uses the existing `establishDistributedCircuit()`. A new circuit gets:
- new initiator ephemeral X25519 keypair (fresh)
- new CircuitId = BLAKE3(commitmentRoot || initiatorX25519Pub)
- new noncePrefix = HKDF(commitmentRoot, initiatorX25519Pub)[0:8]
- new hop keys (from fresh ECDH)
- new replay-floor namespace (keyed by new commitmentRoot)
- new return template / gateway authorization

The frozen R-009 invariant guarantees: `CircuitId` and `noncePrefix` are
cryptographically bound to the new `commitmentRoot` + new ephemeral key.
Therefore recovery naturally produces a NEW circuitId + noncePrefix
even when the same gateway is selected.

### 6. Old circuit isolation (frozen)

The old circuit MUST remain `REVOKED` throughout recovery:
- old circuit → cannot process frames (tombstone check)
- old circuit → cannot be resurrected
- old replay floor → retained (durable)
- old destroy evidence → retained (durable)

The new circuit gets:
- new CircuitId
- new replay floors (separate durable namespace)
- new sequence state

### 7. Recovery atomicity (frozen)

Recovery is marked successful ONLY when ALL stages succeed:
1. candidate selected ✓
2. route proposal succeeds ✓
3. route commitment succeeds ✓
4. circuit establishment succeeds ✓
5. circuit verification succeeds ✓

Only then: `RECOVERY → RECOVERED`.

Partial success → `RECOVERY → FAILED`. No claim of service restoration.
If a partially-created route/circuit must be revoked, use the existing
durable teardown mechanisms (CircuitDestroyStore).

### 8. Retry policy (frozen)

```
MAX_RECOVERY_ATTEMPTS = 3
RECOVERY_BACKOFF_BASE_SECONDS = 5
RECOVERY_BACKOFF_MAX_SECONDS = 60
```

- Attempt 1: immediate
- Attempt 2: wait 5s
- Attempt 3: wait 10s (capped at 60s)
- After 3 failed attempts: `FAILED` (terminal — operator intervention)

Every retry produces a distinct `recoveryAttemptId`.
No recursive recovery loops.
A successful recovery terminates the old RecoveryPlan.

### 9. Failure during recovery (frozen)

If a failure occurs during recovery:
1. Current recovery attempt → `FAILED`
2. Any partially-created circuit/route → revoked (durable teardown)
3. System may create a NEW recovery attempt (up to MAX_RECOVERY_ATTEMPTS)
4. No two active replacement circuits can race into service

### 10. RecoveryExecutor (production class)

The `RecoveryExecutor` consumes a `RecoveryPlan` and executes the full
recovery pipeline. It is separate from `RecoveryManager` (which detects/
invalidates/plans) and from the route/circuit construction primitives.

```
RecoveryManager
  = detects/invalidate/plans

RecoveryExecutor
  = executes the plan

Route modules
  = construct/commit routes

Circuit modules
  = establish circuits
```

### 11. Durable recovery state (frozen)

Recovery state that survives restart:
- `recoveryAttemptId`
- `failedCircuitId`
- `failedCommitmentRoot`
- `state` (RECOVERY_PENDING → ... → RECOVERED/FAILED)
- `attemptCount`
- `timestamps`
- `selectedCandidate`
- `resultingRouteId` (if successful)
- `resultingCircuitId` (if successful)
- `terminalFailureReason` (if FAILED)

If recovery is interrupted by restart:
- Old circuit remains REVOKED (durable tombstone)
- Recovery attempt resumes OR safely restarts (new attemptId)
- No duplicate active recovery result

## Consequences

### Positive

- Real automatic recovery from circuit failure
- New circuit is cryptographically independent from the old one
- Old circuit permanently invalidated
- Retry with backoff prevents recovery storms
- Partial failures handled cleanly

### Negative

- Recovery is not seamless — there is a service gap during recovery
- The recovery executor needs access to the full node topology + gateway list
- Multi-process circuit setup requires real transport (not yet production-wired)

## Cross-references

- ADR-0024 (failure detection — Phase 4)
- ADR-0022 (circuit teardown semantics)
- ADR-0023 (circuit destroy propagation)
- `reference/routing/recovery.ts` (RecoveryManager)
- `reference/routing/route.ts` (route construction)
- `reference/circuit/circuit.ts` (circuit setup)
- `reference/circuit/distributed-setup.ts` (distributed circuit establishment)
