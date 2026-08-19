/**
 * ShareNet 2.0 — Protocol-level circuit replay persistence interfaces (R-008).
 *
 * This module defines the **security boundary for durable circuit replay
 * protection**. Per the R-008 hardening directive and the integration audit:
 *
 *   "The correct architecture is:
 *
 *        CircuitReplayPersistence
 *                │
 *                ├── DurableSqliteCircuitReplayStore
 *                ├── InMemoryCircuitReplayStore   (tests only)
 *                └── future platform stores
 *
 *    Then:
 *
 *        reference/circuit/circuit.ts
 *                ↓
 *        CircuitReplayPersistence
 *
 *    and `processCircuitSetupAck()` similarly consumes
 *    `CircuitAckReplayStore` rather than knowing about Prisma.
 *
 *    The core should fail closed if the replay-state persistence operation
 *    cannot complete."
 *
 * ARCHITECTURE (critical):
 *
 *   The protocol core (`reference/`) MUST NOT import `@/lib/db` or any
 *   database client — this is enforced by architecture test #23
 *   (ADR-0013 layer-separation). Therefore these interfaces are defined
 *   here in the protocol core, with NO Prisma dependency. The durable
 *   SQLite implementation lives in `src/lib/sharenet/` and adapts Prisma
 *   to these interfaces.
 *
 *   A protocol engineer in Rust or Kotlin can implement these interfaces
 *   against any durable substrate (LMDB, RocksDB, SQLite, etc.) and the
 *   reference protocol path will use it. The security boundary is inside
 *   the protocol engine, with persistence abstracted behind these
 *   interfaces.
 *
 * The two store interfaces correspond to the two R-008 replay protections:
 *
 *   1. CircuitSequenceFloorStore — receiver-local ORDERED_STREAM sequence
 *      floor, keyed by (commitmentRoot, hopIndex, direction) — the receiving
 *      security context. Every hop has its own floor (per ADR-0019). Survives
 *      process restart + re-key (per receiver). Per spec/08 §4.5: "Sequence
 *      floors persist across circuit re-key events; a re-key MUST continue
 *      the counter from the prior floor" — this holds per receiver.
 *
 *   2. CircuitAckReplayStore — single-use consumption of setup acks, keyed
 *      by (commitmentRoot, hopIndex, ackNonce). Per R-008 hardening: an
 *      identical, still-fresh ack MUST be rejected on second processing.
 *
 * Both interfaces are ASYNC because durable persistence is inherently
 * async (database I/O). The in-memory implementations resolve
 * immediately; the durable implementations perform real atomic database
 * transactions.
 *
 * FAIL-CLOSED CONTRACT:
 *
 *   Every method that mutates state (`checkAndAdvance`, `consume`) MUST
 *   fail closed: if the persistence operation cannot complete (DB error,
 *   unique constraint violation, etc.), the method returns `{ ok: false }`
 *   (for the floor store) or `false` (for the ack store). The caller
 *   MUST treat the circuit/ack as rejected. Persistence success is
 *   REQUIRED before acceptance — the operation is atomic (check + persist
 *   in a single transaction).
 */

import { toHex } from "../encoding/cbor";

// -----------------------------------------------------------------------
// CircuitSequenceFloorStore — durable per-circuit sequence floor
// -----------------------------------------------------------------------

/**
 * Result of an atomic check-and-advance operation on the sequence floor.
 *
 * - `{ ok: true }`: the sequence was strictly higher than the persisted
 *   floor, AND the new floor was durably persisted. The frame is accepted.
 * - `{ ok: false, reason }`: the sequence was ≤ the floor (replay/stale),
 *   OR the durable persistence operation failed (fail-closed). The frame
 *   is rejected.
 */
export type SequenceFloorCheckResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Durable, **receiver-local** sequence-floor persistence.
 *
 * Keyed by `(commitment_root, hopIndex, direction)` — the **receiving
 * security context**. Each hop has a different AEAD key (per spec/08 §4.1),
 * and therefore needs its own replay state. A re-key on the same route +
 * hop + direction continues from the prior floor.
 *
 * Per spec/08 §4.5 (FROZEN per R-008): "frame_sequence is strictly increasing
 * per circuit; a receiver rejects any frame whose sequence is <= the highest
 * sequence already accepted." The normative rule is **receiver-local** —
 * EVERY receiver on the circuit enforces replay protection, not just the
 * ingress relay. This is critical under ShareNet's threat model, which
 * explicitly includes malicious relays: a malicious upstream relay can
 * replay an already-valid inner ciphertext toward a downstream hop, and
 * the downstream hop's own floor must catch it.
 *
 * Per spec/08 §4.5: "Sequence floors persist across circuit re-key events;
 * a re-key MUST continue the counter from the prior floor." This holds
 * per receiver: a re-key on the same (route, hop, direction) continues
 * from that receiver's prior floor.
 *
 * The floor survives process restart because the durable implementation
 * persists to a database (not in-memory). The in-memory implementation
 * (for tests) does not survive restart — it exists only for conformance
 * vector verification and single-process unit tests.
 *
 * R-009 Stage 1 final replay-model correction (per the re-audit of 9726418):
 * the previous namespace was `commitmentRoot` only (a single shared floor
 * per route). That left downstream hops vulnerable to replay by a malicious
 * upstream relay. The corrected namespace is `(commitmentRoot, hopIndex,
 * direction)` — every hop has its own floor. See ADR-0019.
 */
export interface CircuitSequenceFloorStore {
  /**
   * Read the current sequence floor for a receiving context.
   * Returns 0n if no prior frame has been accepted on this (route, hop, direction).
   *
   * @param commitmentRoot - the 32-byte route commitment root (Merkle root)
   * @param hopIndex - which relay hop is the receiver (0-based)
   * @param direction - 0x01 (forward) or 0x02 (backward)
   */
  getFloor(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    direction: number,
  ): Promise<bigint>;

  /**
   * Atomically check whether `attemptedSequence` is strictly higher than
   * the persisted floor for this (route, hop, direction), and if so,
   * durably persist the new floor.
   *
   * This is the core fail-closed operation: the check and the persist
   * happen in a single atomic transaction. If either fails, the frame
   * is rejected.
   *
   * Per spec/08 §4.5 + R-008: this is the ONLY operation that advances
   * the floor. A caller MUST NOT treat a sequence as accepted until this
   * returns `{ ok: true }`.
   *
   * @param commitmentRoot - the 32-byte route commitment root
   * @param hopIndex - which relay hop is the receiver (0-based)
   * @param direction - 0x01 (forward) or 0x02 (backward)
   * @param attemptedSequence - the frame sequence being checked
   * @returns `{ ok: true }` if accepted + persisted; `{ ok: false, reason }`
   *          if rejected (replay/stale) or persistence failed (fail-closed).
   */
  checkAndAdvance(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    direction: number,
    attemptedSequence: bigint,
  ): Promise<SequenceFloorCheckResult>;
}

// -----------------------------------------------------------------------
// CircuitAckReplayStore — single-use setup-ack consumption
// -----------------------------------------------------------------------

/**
 * Durable, single-use setup-ack replay protection.
 *
 * Keyed by `(commitmentRoot, hopIndex, ackNonce)`. Once the initiator has
 * processed an ack with a given key, the same ack MUST NOT be accepted
 * again — even if it is still within its freshness window.
 *
 * Per R-008 hardening: the ack is single-use. The consumption is atomic
 * (unique constraint on the key). A second processing of the same ack
 * is rejected as a replay.
 */
export interface CircuitAckReplayStore {
  /**
   * Check whether an ack has already been consumed.
   *
   * @returns `true` if the ack has NOT been consumed yet (safe to process),
   *          `false` if it has already been consumed (replay).
   *
   * NOTE: this is a non-atomic read. The atomic operation is `consume()`.
   * Callers that need atomic single-use semantics MUST use `consume()`
   * (which returns `false` on duplicate) rather than checking `isFresh()`
   * then `consume()` (which has a TOCTOU race).
   */
  isFresh(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    ackNonce: Uint8Array,
  ): Promise<boolean>;

  /**
   * Atomically mark an ack as consumed (single-use).
   *
   * This is the atomic fail-closed operation: the consumption is a single
   * atomic insert with a unique constraint on
   * `(commitmentRoot, hopIndex, ackNonce)`.
   *
   * @returns `true` if this is the first consumption (the ack is genuine
   *          and was successfully recorded — safe to proceed),
   *          `false` if the ack was already consumed (duplicate/replay)
   *          or the persistence operation failed (fail-closed).
   *
   * Per R-008: `processCircuitSetupAck()` MUST call this BEFORE returning
   * success. If this returns `false`, the ack is a replay and MUST be
   * rejected.
   */
  consume(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    ackNonce: Uint8Array,
  ): Promise<boolean>;
}

// -----------------------------------------------------------------------
// In-memory implementations (for tests + conformance vectors)
// -----------------------------------------------------------------------

/**
 * In-memory `CircuitSequenceFloorStore` for tests and conformance vectors.
 *
 * Does NOT survive process restart. Used by:
 *   - Conformance vector verification (V-CIRCUIT-001 — ORDERED_STREAM model)
 *   - Single-process unit tests that don't need durability
 *   - The default store when no durable store is provided
 *
 * For production / integration tests that must survive restart, use
 * `DurableSqliteCircuitSequenceFloorStore` (in `src/lib/sharenet/`).
 */
export class InMemoryCircuitSequenceFloorStore implements CircuitSequenceFloorStore {
  // Keyed by (commitmentRootHex, hopIndex, direction) — receiver-local.
  private floors = new Map<string, bigint>();

  private key(commitmentRoot: Uint8Array, hopIndex: number, direction: number): string {
    return `${toHex(commitmentRoot)}:${hopIndex}:${direction}`;
  }

  async getFloor(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    direction: number,
  ): Promise<bigint> {
    return this.floors.get(this.key(commitmentRoot, hopIndex, direction)) ?? 0n;
  }

  async checkAndAdvance(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    direction: number,
    attemptedSequence: bigint,
  ): Promise<SequenceFloorCheckResult> {
    const k = this.key(commitmentRoot, hopIndex, direction);
    const current = this.floors.get(k) ?? 0n;
    if (attemptedSequence <= current) {
      return {
        ok: false,
        reason: `sequence ${attemptedSequence} ≤ floor ${current} (replay/stale) at (hop ${hopIndex}, dir ${direction})`,
      };
    }
    // Atomic in-memory update (single-threaded JS — no race).
    this.floors.set(k, attemptedSequence);
    return { ok: true };
  }

  /** Test-only: directly set the floor for a receiver context (e.g. to simulate prior traffic). */
  setFloorForTest(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    direction: number,
    floor: bigint,
  ): void {
    this.floors.set(this.key(commitmentRoot, hopIndex, direction), floor);
  }
}

/**
 * In-memory `CircuitAckReplayStore` for tests and conformance vectors.
 *
 * Does NOT survive process restart. Used by:
 *   - Single-process unit tests that don't need durability
 *   - The default store when no durable store is provided
 *
 * For production / integration tests that must survive restart, use
 * `DurableSqliteCircuitAckReplayStore` (in `src/lib/sharenet/`).
 */
export class InMemoryCircuitAckReplayStore implements CircuitAckReplayStore {
  private consumed = new Set<string>();

  private key(cr: Uint8Array, hop: number, nonce: Uint8Array): string {
    return `${toHex(cr)}:${hop}:${toHex(nonce)}`;
  }

  async isFresh(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    ackNonce: Uint8Array,
  ): Promise<boolean> {
    return !this.consumed.has(this.key(commitmentRoot, hopIndex, ackNonce));
  }

  async consume(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    ackNonce: Uint8Array,
  ): Promise<boolean> {
    const k = this.key(commitmentRoot, hopIndex, ackNonce);
    if (this.consumed.has(k)) return false; // duplicate — replay
    this.consumed.add(k);
    return true; // first use — successfully consumed
  }
}

// -----------------------------------------------------------------------
// Convenience: a bundled pair of in-memory stores (for tests + defaults)
// -----------------------------------------------------------------------

/**
 * A bundled pair of in-memory replay stores (floor + ack), for tests that
 * want both with a single allocation.
 */
export interface CircuitReplayStores {
  floorStore: CircuitSequenceFloorStore;
  ackStore: CircuitAckReplayStore;
}

/**
 * Create a fresh pair of in-memory replay stores.
 *
 * Use this in tests that don't need durability. For production or
 * restart-survival integration tests, use the durable SQLite implementations
 * from `src/lib/sharenet/durable-circuit-replay-stores.ts`.
 */
export function createInMemoryCircuitReplayStores(): CircuitReplayStores {
  return {
    floorStore: new InMemoryCircuitSequenceFloorStore(),
    ackStore: new InMemoryCircuitAckReplayStore(),
  };
}

// -----------------------------------------------------------------------
// GatewayAuthorizationReplayStore — single-use gateway authorization (R-009 Stage 2)
// -----------------------------------------------------------------------

/**
 * Durable, single-use consumption for GatewayReturnAuthorization.
 *
 * Per the re-audit of cbdc0cc: the authorization verification verified
 * signatures + Merkle proof + ECDH decrypt, but did NOT consume the
 * authorization. The same valid, unexpired authorization could be replayed
 * to the gateway. This store closes that gap.
 *
 * Keyed by `(commitmentRoot, circuitId, ackNonce)` — the authorization
 * belongs to a particular circuit instance (not merely the route).
 *
 * The `consume` operation is atomic + fail-closed:
 *   - first call → true (consumed, authorization accepted)
 *   - second call → false (replay rejected)
 *   - persistence failure → false (fail-closed: treat as replay)
 */
export interface GatewayAuthorizationReplayStore {
  /**
   * Atomically consume a gateway authorization.
   *
   * @param commitmentRoot - the 32-byte route commitment root
   * @param circuitId - the 32-byte circuit ID (instance identity)
   * @param ackNonce - the 16-byte ack nonce from the CircuitSetupAck
   * @returns `true` if this is the first consumption (safe to proceed),
   *          `false` if already consumed (replay) or persistence failed (fail-closed).
   */
  consume(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    ackNonce: Uint8Array,
  ): Promise<boolean>;
}

/**
 * In-memory `GatewayAuthorizationReplayStore` for tests.
 *
 * Does NOT survive process restart. Use `DurableSqliteGatewayAuthorizationReplayStore`
 * (in `src/lib/sharenet/`) for production.
 */
export class InMemoryGatewayAuthorizationReplayStore implements GatewayAuthorizationReplayStore {
  private consumed = new Set<string>();

  private key(cr: Uint8Array, cid: Uint8Array, nonce: Uint8Array): string {
    return `${toHex(cr)}:${toHex(cid)}:${toHex(nonce)}`;
  }

  async consume(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    ackNonce: Uint8Array,
  ): Promise<boolean> {
    const k = this.key(commitmentRoot, circuitId, ackNonce);
    if (this.consumed.has(k)) return false; // replay
    this.consumed.add(k);
    return true; // first use
  }
}

// -----------------------------------------------------------------------
// CircuitRevocationStore — durable terminal-state tombstone (R-009 Stage 3)
// -----------------------------------------------------------------------

/**
 * Durable circuit revocation store.
 *
 * Per ADR-0022: when a circuit is destroyed or expired, a durable
 * revocation record is written. Keyed by (circuitId, commitmentRoot).
 * Survives process restart.
 *
 * Before accepting circuit traffic, the production path checks:
 *   isRevoked(circuitId, commitmentRoot) → true → REJECT
 *
 * A revoked circuit MUST NOT be resurrected after restart.
 */
export interface CircuitRevocationStore {
  /**
   * Check if a circuit is revoked.
   * @returns true if the circuit has a durable revocation record.
   */
  isRevoked(circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean>;

  /**
   * Write a durable revocation record.
   * If the circuit is already revoked, this is idempotent (returns true).
   * @returns true if the revocation was written (or already existed).
   *          false if the persistence operation failed (fail-closed).
   */
  revoke(
    circuitId: Uint8Array,
    commitmentRoot: Uint8Array,
    destroyerNodeId: string,
    destroyerRole: number,
    destroyReason: number,
    destroyNonce: Uint8Array,
  ): Promise<boolean>;
}

/**
 * In-memory CircuitRevocationStore for tests.
 */
export class InMemoryCircuitRevocationStore implements CircuitRevocationStore {
  private revoked = new Map<string, { destroyerNodeId: string; destroyerRole: number; destroyReason: number; destroyNonce: Uint8Array }>();

  private key(cid: Uint8Array, cr: Uint8Array): string {
    return `${toHex(cid)}:${toHex(cr)}`;
  }

  async isRevoked(circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean> {
    return this.revoked.has(this.key(circuitId, commitmentRoot));
  }

  async revoke(
    circuitId: Uint8Array,
    commitmentRoot: Uint8Array,
    destroyerNodeId: string,
    destroyerRole: number,
    destroyReason: number,
    destroyNonce: Uint8Array,
  ): Promise<boolean> {
    const k = this.key(circuitId, commitmentRoot);
    if (this.revoked.has(k)) return true; // idempotent
    this.revoked.set(k, { destroyerNodeId, destroyerRole, destroyReason, destroyNonce });
    return true;
  }
}

// -----------------------------------------------------------------------
// CircuitDestroyReplayStore — single-use destroy consumption (R-009 Stage 3)
// -----------------------------------------------------------------------

/**
 * Durable, single-use consumption for CircuitDestroy messages.
 *
 * Per ADR-0022: separate namespace from ConsumedCircuitAck +
 * ConsumedGatewayAuthorization. Keyed by (commitmentRoot, circuitId,
 * destroyNonce). Fail-closed on persistence failure.
 */
export interface CircuitDestroyReplayStore {
  /**
   * Atomically consume a destroy message.
   * @returns true if first consumption, false if replay or persistence failure.
   */
  consume(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    destroyNonce: Uint8Array,
  ): Promise<boolean>;
}

/**
 * In-memory CircuitDestroyReplayStore for tests.
 */
export class InMemoryCircuitDestroyReplayStore implements CircuitDestroyReplayStore {
  private consumed = new Set<string>();

  private key(cr: Uint8Array, cid: Uint8Array, nonce: Uint8Array): string {
    return `${toHex(cr)}:${toHex(cid)}:${toHex(nonce)}`;
  }

  async consume(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    destroyNonce: Uint8Array,
  ): Promise<boolean> {
    const k = this.key(commitmentRoot, circuitId, destroyNonce);
    if (this.consumed.has(k)) return false;
    this.consumed.add(k);
    return true;
  }
}

// -----------------------------------------------------------------------
// CircuitDestroyStore — atomic consume-nonce + revoke-tombstone (R-009 Stage 3 Phase 2)
// -----------------------------------------------------------------------

/**
 * Result of an atomic consume-destroy-nonce + write-revocation-tombstone.
 *
 * - `{ ok: true, idempotent: false }`: the destroy nonce was consumed AND the
 *   tombstone was durably written in a single atomic transaction. The circuit
 *   is now durably revoked. This is the first processing of this destroy.
 * - `{ ok: true, idempotent: true }`: the tombstone already existed (the
 *   circuit was already revoked by a prior destroy). The nonce was NOT
 *   re-consumed. Idempotent success — the circuit is still revoked.
 * - `{ ok: false, reason }`: the atomic transaction FAILED (persistence
 *   failure). NEITHER the nonce was consumed NOR the tombstone was written.
 *   No split security state. The caller MUST reject the destroy (fail-closed).
 */
export type ConsumeDestroyAndRevokeResult =
  | { ok: true; idempotent: boolean }
  | { ok: false; reason: string };

/**
 * Durable, ATOMIC circuit-destroy store.
 *
 * Per the re-audit of 60e4364 (R-009 Stage 3 Phase 2): the previous design
 * used two separate stores (`CircuitRevocationStore` + `CircuitDestroyReplayStore`)
 * with two separate operations (`revoke()` + `consume()`). If the nonce was
 * consumed but the tombstone write failed, the circuit was left in a SPLIT
 * security state: the nonce is spent (a retry would be rejected as a replay)
 * but there is no tombstone (the circuit is not durably revoked). This is
 * unsafe — the operator cannot retry, and the circuit is not durably dead.
 *
 * This interface provides a SINGLE ATOMIC operation that consumes the nonce
 * AND writes the tombstone in one transaction. Both succeed or both fail.
 * There is no split state.
 *
 * The atomicity guarantee:
 *   - If the transaction commits: the nonce is consumed AND the tombstone
 *     exists. A subsequent retry is idempotent (the tombstone already exists).
 *   - If the transaction aborts (persistence failure, unique-constraint
 *     violation, etc.): NEITHER the nonce is consumed NOR the tombstone
 *     exists. The operator can safely retry with the SAME destroy (the
 *     nonce is still fresh).
 *
 * Idempotency: if the tombstone already exists (the circuit was already
 * revoked by a prior destroy), the operation returns `{ ok: true, idempotent: true }`
 * without re-consuming the nonce. The tombstone is the authoritative terminal
 * state — if it exists, the circuit is REVOKED regardless of the nonce state.
 *
 * ARCHITECTURE: this interface lives in the protocol core (`reference/`) with
 * NO Prisma dependency. The durable SQLite implementation (in `src/lib/sharenet/`)
 * uses a Prisma `$transaction` to atomically insert into `ConsumedCircuitDestroy`
 * + upsert into `CircuitRevocation`. A protocol engineer in Rust/Kotlin
 * implements the same interface against any durable substrate (LMDB, RocksDB,
 * SQLite, etc.) using a native transaction.
 */
export interface CircuitDestroyStore {
  /**
   * Check if a circuit is revoked (durable tombstone exists).
   *
   * Per ADR-0022: the tombstone is the authoritative terminal-state record.
   * `CIRCUIT_REVOKED ≡ isRevoked() === true`.
   */
  isRevoked(circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean>;

  /**
   * ATOMICALLY consume the destroy nonce AND write the revocation tombstone.
   *
   * Single transaction: both succeed or both fail. Fail-closed: if the
   * transaction cannot complete, returns `{ ok: false, reason }` and NEITHER
   * the nonce is consumed NOR the tombstone is written (no split state).
   *
   * Idempotent: if the tombstone already exists, returns
   * `{ ok: true, idempotent: true }` without re-consuming the nonce.
   *
   * @param commitmentRoot - the 32-byte route commitment root
   * @param circuitId - the 32-byte circuit ID (instance identity)
   * @param destroyNonce - the 16-byte destroy nonce (replay protection)
   * @param destroyerNodeId - the destroyer's NodeId (evidence in the tombstone)
   * @param destroyerRole - 0x01 (INITIATOR) or 0x02 (GATEWAY)
   * @param destroyReason - enumerated reason code
   * @returns `{ ok: true, idempotent }` on success; `{ ok: false, reason }` on
   *   persistence failure (fail-closed, no split state).
   */
  consumeDestroyAndRevoke(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    destroyNonce: Uint8Array,
    destroyerNodeId: string,
    destroyerRole: number,
    destroyReason: number,
  ): Promise<ConsumeDestroyAndRevokeResult>;
}

/**
 * In-memory `CircuitDestroyStore` for tests + conformance vectors.
 *
 * Does NOT survive process restart. The atomic operation is implemented as a
 * single synchronous check + insert (single-threaded JS — no race). For
 * production / restart-survival integration tests, use
 * `DurableSqliteCircuitDestroyStore` (in `src/lib/sharenet/`).
 */
export class InMemoryCircuitDestroyStore implements CircuitDestroyStore {
  // Tombstone: keyed by (circuitIdHex, commitmentRootHex).
  private revoked = new Map<string, { destroyerNodeId: string; destroyerRole: number; destroyReason: number; destroyNonce: Uint8Array }>();
  // Consumed nonces: keyed by (commitmentRootHex, circuitIdHex, destroyNonceHex).
  private consumed = new Set<string>();

  private tombstoneKey(cid: Uint8Array, cr: Uint8Array): string {
    return `${toHex(cid)}:${toHex(cr)}`;
  }
  private nonceKey(cr: Uint8Array, cid: Uint8Array, nonce: Uint8Array): string {
    return `${toHex(cr)}:${toHex(cid)}:${toHex(nonce)}`;
  }

  async isRevoked(circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean> {
    return this.revoked.has(this.tombstoneKey(circuitId, commitmentRoot));
  }

  async consumeDestroyAndRevoke(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    destroyNonce: Uint8Array,
    destroyerNodeId: string,
    destroyerRole: number,
    destroyReason: number,
  ): Promise<ConsumeDestroyAndRevokeResult> {
    const tKey = this.tombstoneKey(circuitId, commitmentRoot);
    const nKey = this.nonceKey(commitmentRoot, circuitId, destroyNonce);

    // Idempotency: if the tombstone already exists, the circuit is already
    // revoked. Return idempotent success WITHOUT re-consuming the nonce.
    if (this.revoked.has(tKey)) {
      return { ok: true, idempotent: true };
    }

    // Atomic check + insert (single-threaded JS — no race between check + insert).
    // If the nonce was already consumed (but no tombstone — shouldn't happen in
    // normal operation since we always write the tombstone with the nonce, but
    // could happen if a prior transaction was rolled back after the nonce insert
    // in a non-atomic implementation), reject as a replay.
    if (this.consumed.has(nKey)) {
      return {
        ok: false,
        reason: "destroy replay: (commitmentRoot, circuitId, destroyNonce) already consumed but no tombstone exists (inconsistent state — reject as replay, fail-closed)",
      };
    }

    // Atomic: consume the nonce AND write the tombstone. In single-threaded JS,
    // these two mutations are atomic (no interleaving possible). In a durable
    // implementation, this is a single DB transaction.
    this.consumed.add(nKey);
    this.revoked.set(tKey, { destroyerNodeId, destroyerRole, destroyReason, destroyNonce });
    return { ok: true, idempotent: false };
  }

  /**
   * Also implement `CircuitRevocationStore.revoke()` so this store can be
   * passed to `processCircuitWireFrame` (which takes `CircuitRevocationStore`)
   * AND `processCircuitDestroy` (which takes `CircuitDestroyStore`). This is
   * structural typing — no explicit `implements` needed. The same tombstone
   * Map is shared, so a tombstone written by `consumeDestroyAndRevoke` is
   * visible to `isRevoked` (called by `processCircuitWireFrame`).
   */
  async revoke(
    circuitId: Uint8Array,
    commitmentRoot: Uint8Array,
    destroyerNodeId: string,
    destroyerRole: number,
    destroyReason: number,
    destroyNonce: Uint8Array,
  ): Promise<boolean> {
    const tKey = this.tombstoneKey(circuitId, commitmentRoot);
    if (this.revoked.has(tKey)) return true; // idempotent
    this.revoked.set(tKey, { destroyerNodeId, destroyerRole, destroyReason, destroyNonce });
    return true;
  }
}
