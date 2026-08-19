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

**The durable `CircuitRevocation` tombstone is the AUTHORITATIVE terminal
security state** (re-audit of 6936831, finalizing lifecycle semantics):

- `CIRCUIT_ACTIVE` ≡ no durable tombstone exists for `(circuitId, commitmentRoot)`.
- `CIRCUIT_REVOKED` ≡ a durable tombstone exists for `(circuitId, commitmentRoot)`.

There is exactly ONE state machine and ONE source of truth. A local
implementation MAY have an implementation-only transient cleanup state
(e.g., an in-memory `DESTROYING` flag for async key erasure bookkeeping),
but that transient state MUST NEVER contradict the durable tombstone: if
the tombstone exists, the circuit is `CIRCUIT_REVOKED` (full stop); if it
does not exist, the circuit is `CIRCUIT_ACTIVE` (subject to expiry).
No second competing state machine is permitted.

**No `CIRCUIT_DESTROYING` intermediate wire state:** The destroyer signs +
sends the destroy. Each recipient verifies + revokes locally. The destroy
IS the revocation. (A `DESTROYING` intermediate state may exist in local
memory for async key cleanup, but it is not wire-visible and does not
affect the authoritative tombstone.)

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
with the same Ed25519 key that established the circuit. The binding is
TWO-LAYERED (re-audit of 6936831 — closes the identity authorization bypass):
- **Layer 1 (identity binding):** `verifyNodeIdBinding(destroyerNodeId,
  destroyerEd25519PublicKey)` MUST hold — the claimed `destroyerNodeId` MUST
  be the canonical BLAKE3-256 derivation of the claimed public key. This is
  enforced inside `processCircuitDestroy()` BEFORE the role check. Without
  this layer, an attacker who merely learns a legitimate initiator's public
  NodeId string could sign a forged destroy with their own keypair while
  setting `destroyerNodeId` to the legitimate value; the signature would
  verify (against the attacker's own pubkey in the destroy) and the role
  check (`destroyerNodeId === expectedInitiatorNodeId`) would pass.
- **Layer 2 (role binding):** `destroyerNodeId` matches the route's
  `initiatorNodeId`; `destroyerEd25519PublicKey` is the initiator's node
  identity key; the signature is verified using `destroyerEd25519PublicKey`.

The portable verifier `verifyCircuitDestroy()` performs Layer 2's
signature check only (it is structure + signature verification); Layer 1
(identity binding) + the role authorization are enforced by the production
path `processCircuitDestroy()`, which is the only path that has the circuit
context (`expectedInitiatorNodeId` / `expectedGatewayNodeId`).

**Gateway destroy authorization:**
The destroyer proves it is the terminal hop using the same portable proof
chain established in Stage 2 (`GatewayReturnAuthorization`):
- **Layer 1 (identity binding):** `verifyNodeIdBinding(destroyerNodeId,
  destroyerEd25519PublicKey)` MUST hold — same two-layer model as initiator.
- **Layer 2 (role binding via portable proof chain):** the destroyer MUST
  provide a serialized `GatewayReturnAuthorization` (`gatewayProofBytes`).
  This is the SAME frozen proof chain from R-009 Stage 2 — the verifier
  (`verifyTerminalHopProof`) checks from wire bytes alone (no
  WeakSet/BrandedCommittedRoute dependency):
  - the terminal `RouteAcceptance` Ed25519 signature (signed by the
    `relayEd25519PublicKey` embedded in the proof)
  - the Merkle inclusion proof (proving the acceptance belongs to the
    `commitmentRoot`)
  - the `commitmentRoot` matches `circuit.commitmentRoot` (the proof is
    for THIS circuit's route, not a different route)
  - the terminal hop identity (`hopIndex == hopNodeIds.length - 1` AND
    `hopNodeIds[hopIndex] == terminalNodeId`)
  - the terminal `CircuitSetupAck` Ed25519 signature (signed by the SAME
    `relayEd25519PublicKey`)
  - ack freshness (`ackExpiry > now` — defense-in-depth)
  - the `routeId` derivation check
  Additionally, the destroy's `destroyerEd25519PublicKey` MUST equal the
  proof's `relayEd25519PublicKey` (the destroy signer IS the ack/acceptance
  signer), and the destroy's `destroyerNodeId` MUST equal the proof's
  `terminalNodeId`.

  This replaces the previous caller-supplied-only check
  (`destroyerNodeId === expectedGatewayNodeId`) which was insufficient
  because `expectedGatewayNodeId` is a string parameter with no
  cryptographic binding to the actual terminal hop (re-audit of 60e4364).
  `expectedGatewayNodeId` is now checked only as a redundant defense-in-depth.
  The proof chain is the SOLE authority for gateway authorization.

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

### 12. CircuitDestroy freshness + clock skew (R-009 Stage 3 Phase 2)

Per the re-audit of 60e4364: `processCircuitDestroy` receives `now` but did
not enforce `issuedAt` / `expiry`. A validly signed but expired destroy could
be processed (consuming the nonce + writing the tombstone) even though the
destroy was stale. The freshness checks MUST be enforced BEFORE nonce
consumption (so the nonce remains fresh for a valid retry).

**Checks (all BEFORE step 7 — nonce consumption):**

1. `issuedAt <= now + CIRCUIT_DESTROY_MAX_CLOCK_SKEW_SECONDS` — the destroy
   was not issued too far in the future. Permits clock skew between the
   destroyer's clock and the receiver's clock.
2. `now < expiry` (strict) — the destroy has not expired. Boundary:
   `now == expiry` → REJECT (consistent with `circuit.expiry <= now` in
   `processCircuitWireFrame`).
3. `expiry <= circuit.expiry` — the destroy's expiry does not exceed the
   circuit's actual expiry. Prevents an attacker from extending the circuit's
   lifetime via a destroy with a later expiry.

**Frozen clock skew:** `CIRCUIT_DESTROY_MAX_CLOCK_SKEW_SECONDS = 300` (5
minutes). This is generous for a delay-tolerant network with potentially
drifted mesh-node clocks, while still being tight enough to prevent
meaningful future-dated forgery. The skew applies ONLY to the `issuedAt`
check — the `expiry` checks are strict (no skew).

A validly signed but expired/future-dated destroy is rejected with an
explicit reason. The nonce is NOT consumed — a retry with a valid (non-expired,
non-future-dated) destroy with the SAME nonce will succeed.

### 13. Atomic consume-nonce + revoke-tombstone (R-009 Stage 3 Phase 2)

Per the re-audit of 60e4364: the previous design used two separate operations
(`CircuitDestroyReplayStore.consume()` + `CircuitRevocationStore.revoke()`).
If the nonce was consumed but the tombstone write failed, the circuit was left
in a SPLIT security state: the nonce is spent (a retry would be rejected as a
replay) but there is no tombstone (the circuit is not durably revoked). This
is unsafe — the operator cannot retry, and the circuit is not durably dead.

**Fix:** a new `CircuitDestroyStore` interface provides a SINGLE ATOMIC
operation `consumeDestroyAndRevoke()` that consumes the nonce AND writes the
tombstone in one transaction. Both succeed or both fail. There is no split
state.

The `processCircuitDestroy` pipeline (step 7) now calls
`destroyStore.consumeDestroyAndRevoke()` instead of separate `consume()` +
`revoke()`. The `destroyStore` is REQUIRED (not optional).

**Atomicity guarantee:**
- If the transaction commits: the nonce is consumed AND the tombstone exists.
  A subsequent retry is idempotent (the tombstone already exists).
- If the transaction aborts (persistence failure, unique-constraint violation):
  NEITHER the nonce is consumed NOR the tombstone exists. The operator can
  safely retry with the SAME destroy (the nonce is still fresh).

**Durable implementation:** `DurableSqliteCircuitDestroyStore` uses a Prisma
`$transaction` to atomically insert into `ConsumedCircuitDestroy` + CREATE
into `CircuitRevocation` (NOT upsert — the tombstone create is the AUTHORITATIVE
ACTIVE→REVOKED transition; the unique constraint ensures exactly ONE
transaction wins; concurrent transactions roll back + re-check isRevoked →
idempotent). If either fails, the entire transaction rolls back — no split state.

### 14. Expiry tombstones are SYSTEM-generated revocations (R-009 Stage 3 Phase 2 final)

**Expiry tombstones are SYSTEM-generated revocations, NOT initiator-authenticated
CircuitDestroy evidence.** The expiry path in `processCircuitWireFrame` calls
`revocationStore.revoke()` directly (with `destroyerNodeId = "system"`,
`destroyerRole = 0x01`, `destroyReason = CIRCUIT_EXPIRED`, `destroyNonce = 0^16`).
This tombstone is NOT a signed CircuitDestroy wire object — it has no Ed25519
signature, no destroy nonce, and no destroyer identity. It is a SYSTEM-generated
record of a temporal event (the circuit's lifetime elapsed).

This distinction is important for audit trails:
- An **initiator/gateway-authenticated CircuitDestroy** carries a signed wire
  object (verifiable by any participant from the wire bytes alone) + a fresh
  destroy nonce. The tombstone records the destroyer's NodeId + the signed
  destroy evidence.
- A **SYSTEM-generated expiry tombstone** carries no signature + a zero nonce.
  The tombstone records `destroyerNodeId = "system"` + `destroyReason =
  CIRCUIT_EXPIRED`. Any participant can verify the expiry by checking
  `circuit.expiry <= now` (the expiry is in the circuit's established state).

Both produce the SAME authoritative terminal state (`CIRCUIT_REVOKED`), but
the evidence type differs. A future audit can distinguish "the initiator
explicitly destroyed this circuit" from "this circuit expired naturally"
by inspecting the tombstone's `destroyReason` + `destroyerNodeId`.

Expiry is NOT merely a local frame rejection. When `now > valid_until`:

1. The circuit transitions to `CIRCUIT_REVOKED`.
2. A durable revocation record is written (reason = `CIRCUIT_EXPIRED`).
3. Keys are zeroized (best-effort) — **only AFTER the tombstone is confirmed persisted**.
4. The replay floor is RETAINED.

**Fail-closed (re-audit of 6936831):** if the durable revocation write
FAILS (the `CircuitRevocationStore.revoke()` call returns `false`), the
production path MUST:
- reject the frame with an explicit persistence-failure reason;
- NOT claim the circuit is "durably revoked" (no false success state);
- NOT zeroize keys (the terminal state was not durably recorded; the
  operator may retry, and zeroized keys cannot be recovered).

There is no false "durably revoked" state. Either the tombstone is
persisted (and the circuit is durably dead + keys destroyed), or it is
not (and the circuit is still live-but-expired, awaiting a retry).

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

### 9. Key zeroization (best-effort) — OWNED by processCircuitDestroy

`processCircuitDestroy()` owns the full teardown pipeline, including
zeroization (re-audit of 6936831). The pipeline is:

```
decode → verify signature → verify circuit binding →
  verifyNodeIdBinding (Layer 1) →
  authorize role (Layer 2) →
  check durable revocation (idempotent? zeroize + return) →
  consume destroy nonce (durable, fail-closed) →
  write durable revocation record (fail-closed: reject if not persisted) →
  zeroize keys →
  return CircuitDestroy for propagation
```

The caller is NOT responsible for calling `zeroizeCircuit()`. The canonical
teardown path performs it itself, in both the fresh-destroy and idempotent
(re-destroy of an already-revoked circuit) branches.

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
