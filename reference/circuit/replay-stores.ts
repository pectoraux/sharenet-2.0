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
 *   1. CircuitSequenceFloorStore — per-circuit ORDERED_STREAM sequence
 *      floor, keyed by commitment_root. Survives process restart + re-key.
 *      Per spec/08 §4.5: "Sequence floors persist across circuit re-key
 *      events; a re-key MUST continue the counter from the prior floor."
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
 * Durable, per-circuit sequence-floor persistence.
 *
 * Keyed by `commitment_root` (the route identity). A re-key on the same
 * route continues from the prior floor. A different route gets a fresh
 * floor (0).
 *
 * Per spec/08 §4.5: "Sequence floors persist across circuit re-key events;
 * a re-key MUST continue the counter from the prior floor."
 *
 * The floor survives process restart because the durable implementation
 * persists to a database (not in-memory). The in-memory implementation
 * (for tests) does not survive restart — it exists only for conformance
 * vector verification and single-process unit tests.
 */
export interface CircuitSequenceFloorStore {
  /**
   * Read the current sequence floor for a circuit route.
   * Returns 0n if no prior circuit has been established on this route.
   *
   * @param commitmentRoot - the 32-byte route commitment root (Merkle root)
   */
  getFloor(commitmentRoot: Uint8Array): Promise<bigint>;

  /**
   * Atomically check whether `attemptedSequence` is strictly higher than
   * the persisted floor, and if so, durably persist the new floor.
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
   * @param attemptedSequence - the frame sequence being checked
   * @returns `{ ok: true }` if accepted + persisted; `{ ok: false, reason }`
   *          if rejected (replay/stale) or persistence failed (fail-closed).
   */
  checkAndAdvance(
    commitmentRoot: Uint8Array,
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
  private floors = new Map<string, bigint>();

  async getFloor(commitmentRoot: Uint8Array): Promise<bigint> {
    return this.floors.get(toHex(commitmentRoot)) ?? 0n;
  }

  async checkAndAdvance(
    commitmentRoot: Uint8Array,
    attemptedSequence: bigint,
  ): Promise<SequenceFloorCheckResult> {
    const key = toHex(commitmentRoot);
    const current = this.floors.get(key) ?? 0n;
    if (attemptedSequence <= current) {
      return {
        ok: false,
        reason: `sequence ${attemptedSequence} ≤ floor ${current} (replay/stale)`,
      };
    }
    // Atomic in-memory update (single-threaded JS — no race).
    this.floors.set(key, attemptedSequence);
    return { ok: true };
  }

  /** Test-only: directly set the floor (e.g. to simulate a prior circuit). */
  setFloorForTest(commitmentRoot: Uint8Array, floor: bigint): void {
    this.floors.set(toHex(commitmentRoot), floor);
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
