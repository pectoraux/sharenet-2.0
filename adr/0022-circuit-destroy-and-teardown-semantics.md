# ADR-0022: CircuitDestroy and teardown semantics

**Date:** 2026-08-19
**Status:** ACCEPTED
**Phase:** R-009 Stage 3 (teardown, failure detection, recovery)
**Supersedes:** The informal lifecycle type in `distributed-setup.ts` (`ForwardingLifecycle`).
**Superseded by:** None

## Context

R-009 Stage 2 closed the bidirectional circuit data plane with a portable
gateway authorization proof, Merkle inclusion proof, confidential K_ret
delivery, and durable single-use authorization consumption. The circuit
substrate is cryptographically complete for traffic flow.

However, there is **no teardown protocol**. The spec (§6) defines four
circuit states (`CIRCUIT_PENDING`, `CIRCUIT_ACTIVE`, `CIRCUIT_EXPIRED`,
`CIRCUIT_REVOKED`) with a zeroize mandate + floor retention rule, but:

- No `CircuitDestroy` wire object exists.
- No circuit state field exists on `ActiveCircuit`.
- No expiry check exists in the production path (`processCircuitWireFrame`).
- No key zeroization is implemented.
- No durable circuit-state/revocation model exists.
- No destroy replay protection exists.

After a process restart, the gateway/relay has no durable record of whether
a circuit was revoked — it will accept frames for a revoked circuit.

## Decision

### 1. Teardown state machine

```
CIRCUIT_ACTIVE
       │
       ├── CircuitDestroy (authenticated wire event)
       │   ↓
       │   CIRCUIT_REVOKED (terminal)
       │
       └── now > valid_until (local expiry event)
           ↓
           CIRCUIT_REVOKED (terminal, same state)
```

**One terminal state:** `CIRCUIT_REVOKED`. Both explicit destroy and natural
expiry lead to the same terminal state. `CIRCUIT_EXPIRED` is NOT a separate
terminal state — it is an event that transitions to `CIRCUIT_REVOKED`.

**No `CIRCUIT_DESTROYING` intermediate wire state:** The destroyer signs +
sends the destroy. Each recipient verifies + revokes locally. The destroy
IS the revocation. (A `DESTROYING` intermediate state may exist in local
memory for async key cleanup, but it is not wire-visible.)

**No `CIRCUIT_PENDING` in the production path:** `CIRCUIT_PENDING` exists
only during setup. Once `establishDistributedCircuit` returns an
`ActiveCircuit`, the circuit is `CIRCUIT_ACTIVE`. There is no transition
from `CIRCUIT_PENDING` to `CIRCUIT_REVOKED` — a pending circuit that is
aborted during setup simply never becomes `ACTIVE`.

### 2. Authorized destroy originators

- **Initiator (source):** authorized. The initiator created the circuit;
  it can destroy it.
- **Gateway (terminal hop):** authorized. The gateway holds K_ret + the
  return template; it can destroy the circuit.
- **Relay (intermediate hop):** NOT authorized to originate a destroy.
  Relays MAY propagate an authenticated destroy unchanged. A relay MUST
  NOT re-sign as the destroyer — the original destroyer's signature is
  preserved end-to-end.

### 3. Portable authorization model

The `CircuitDestroy` authorization is **portable across process/language
boundaries** — no WeakSet or in-process `BrandedCommittedRoute` dependency.

**Initiator destroy authorization:**
The destroyer proves it is the circuit's initiator by signing the destroy
with the same Ed25519 key that established the circuit. The binding is:
- `destroyerNodeId` matches the route's `initiatorNodeId`.
- `destroyerEd25519PublicKey` is the initiator's node identity key.
- The signature is verified using `destroyerEd25519PublicKey`.

**Gateway destroy authorization:**
The destroyer proves it is the terminal hop using the same portable proof
chain established in Stage 2 (`GatewayReturnAuthorization`):
- The terminal `RouteAcceptance` signature (signed by the terminal relay's
  Ed25519 key, binding `acceptorNodeId` + `hopIndex`).
- The Merkle inclusion proof (proving the acceptance belongs to
  `commitmentRoot`).
- The `routeId` derivation check (`routeId = "route:" + hex(commitmentRoot)`).
- `destroyerNodeId` matches the terminal acceptance's `acceptorNodeId`.
- `destroyerEd25519PublicKey` verifies the acceptance signature.

This reuses the established portable proof model from Stage 2 — no new
trust infrastructure.

### 4. CircuitDestroy wire object

Canonical CBOR wire object (integer-keyed map per ADR-0004):

```
CircuitDestroy = {
    1:  circuitId                  (bstr .size 32)
    2:  commitmentRoot              (bstr .size 32)
    3:  routeId                     (text)
    4:  destroyerNodeId             (text)
    5:  destroyerRole               (uint — 0x01 = initiator, 0x02 = gateway)
    6:  destroyReason               (uint — enumerated reason codes)
    7:  destroyNonce                (bstr .size 16)
    8:  issuedAt                    (uint — unix seconds)
    9:  expiry                      (uint — circuit expiry, for lifetime binding)
    10: destroyerEd25519PublicKey   (bstr .size 32)
    11: signature                   (bstr .size 64 — Ed25519 over the binding payload)
}
```

Domain tag: `SHARENET/CIRCUIT/DESTROY/1`

Signing payload: `domain || circuitId || commitmentRoot || routeId || destroyerNodeId || destroyerRole || destroyReason || destroyNonce || issuedAt || expiry`

**Reason codes:**
- `0x01` = `OPERATOR_INITIATED` (explicit teardown)
- `0x02` = `CIRCUIT_EXPIRED` (expiry-triggered)
- `0x03` = `LINK_FAILURE` (destroy due to confirmed link failure)
- `0x04` = `GATEWAY_DISAPPEARANCE` (gateway-originated, gateway going down)
- `0x05` = `PROTOCOL_VIOLATION` (destroy due to repeated AEAD/replay failures)

### 5. Durable revocation model

The revocation tombstone is the **authoritative terminal state**. It is
keyed by `(circuitIdHex, commitmentRootHex)` — the circuit instance
identity, NOT the destroy nonce.

```
Prisma: CircuitRevocation {
    circuitIdHex      String   (32-byte circuit ID hex)
    commitmentRootHex String   (32-byte route identity hex)
    revokedAt         DateTime
    destroyerNodeId   String
    destroyerRole     Int      (0x01 or 0x02)
    destroyReason     Int
    destroyNonceHex   String   (16-byte nonce hex — evidence, not state identity)
    @@unique([circuitIdHex, commitmentRootHex])
    @@index([commitmentRootHex])
}
```

**Survives process restart.** Before accepting circuit traffic, the
production path checks the durable revocation store:
```
checkRevoked(circuitId, commitmentRoot)
    → revoked → REJECT frame
    → not revoked → continue
```

### 6. Destroy replay protection

Separate from the revocation tombstone. The destroy message carries a
`destroyNonce` (16 bytes). Each participant durably consumes
`(commitmentRoot, circuitId, destroyNonce)` — a distinct namespace from
`ConsumedGatewayAuthorization` (which uses `ackNonce`).

```
GatewayDestroyReplayStore.consume(commitmentRoot, circuitId, destroyNonce)
    → first call → true (consumed)
    → second call → false (replay)
    → persistence failure → false (fail-closed)
```

**Idempotent destroy:** A destroy received after the circuit is already
revoked (the durable revocation record exists) returns success without
re-consuming the replay nonce. The revocation tombstone is the source of
truth — if it exists, the destroy is idempotent.

### 7. Expiry as a durable terminal-state transition

Expiry is NOT merely a local frame rejection. When `now > valid_until`:

1. The circuit transitions to `CIRCUIT_REVOKED`.
2. A durable revocation record is written (reason = `CIRCUIT_EXPIRED`).
3. Keys are zeroized (best-effort).
4. The replay floor is RETAINED.

After a process restart, the durable revocation record ensures the
circuit is still known to be dead.

### 8. Production path integration

```
processCircuitWireFrame():
    decode
    ↓
    check circuit.expiry > now        ← NEW (expiry enforcement)
    ↓
    check durable revocation          ← NEW (revoked → reject)
    ↓
    direction-specific AEAD
    ↓
    receiver-local durable replay commit
    ↓
    forward / deliver
```

The frozen ordering (AEAD → commit → forward) is preserved. Expiry/revocation
checks happen BEFORE AEAD — a rejected frame due to expiry/revocation never
reaches the replay floor. No replay state advances on a rejected frame.

### 9. Key zeroization (best-effort)

When a circuit is revoked:
- `forwardingKey[]` → zeroized (filled with zeros)
- `returnKey[]` → zeroized
- `K_ret` → zeroized
- `noncePrefix` → zeroized
- `initiatorX25519SecretKey` → zeroized
- Per-relay forwarding state → removed

**Retained:**
- Replay floors (durable, in the database)
- Revocation tombstone (durable)
- Circuit identity (for audit)
- Route identity (for anti-replay/audit)
- Destroy evidence (the signed CircuitDestroy message)

**Not claimed:** Guaranteed memory erasure. This is explicit best-effort
zeroization. The GC may have copied keys; the OS may have paged them.
The zeroization is defense-in-depth, not a hard memory-erasure guarantee.

### 10. Destroy propagation

For initiator-originated destroy:
```
initiator → relay 0 → relay 1 → gateway
```

For gateway-originated destroy:
```
gateway → relay N-1 → ... → relay 0 → initiator
```

Each hop:
1. Decode the CircuitDestroy wire bytes.
2. Verify the destroyer's Ed25519 signature.
3. Verify the destroyer is authorized (initiator or gateway, per the
   portable proof model).
4. Check durable revocation (if already revoked → idempotent success).
5. Consume the destroy replay nonce (durable, fail-closed).
6. Write the durable revocation record.
7. Zeroize local keys (best-effort).
8. Propagate the original CircuitDestroy unchanged (no re-signing).

### 11. Relationship to existing RecoveryManager

The existing `RecoveryManager` (`reference/routing/recovery.ts`) is
currently standalone. It will be integrated AFTER the durable circuit
invalidation path works:

```
transport/link failure
    → RecoveryManager.handleLinkEvent()
    → circuit invalidation (durable revocation)
    → recovery planning (createRecoveryPlan)
    → actual new route/circuit establishment
```

Recovery creates a NEW circuit with a NEW CircuitId + NEW nonce prefix.
It does NOT migrate existing TCP flows. Old circuit frames are rejected
by the durable revocation check. Receiver-local replay floors persist
across the re-key/recovery (keyed by commitmentRoot, not circuitId).

## Consequences

### Positive

- Circuits have a defined lifecycle with a terminal state.
- Revoked circuits are durably remembered after process restart.
- Key material is best-effort zeroized at teardown.
- The destroy protocol is portable (no WeakSet dependency).
- The frozen AEAD→commit→forward ordering is preserved.
- Replay floors survive teardown (for re-key/recovery protection).

### Negative

- Key zeroization is best-effort, not guaranteed (language/runtime limitation).
- The destroy protocol adds a new wire object + conformance vector family.
- The durable revocation check adds one database query per frame (acceptable).

## Cross-references

- `spec/08-circuits.md` §6 (State) — amended to formalize the state machine.
- `spec/08-circuits.md` §4.7 (Expiration) — amended for durable transition.
- ADR-0019 (receiver-local replay protection — floors retained at teardown).
- ADR-0021 (return-onion template distribution — gateway authorization model reused).
- `reference/routing/recovery.ts` (RecoveryManager — to be integrated post-teardown).
