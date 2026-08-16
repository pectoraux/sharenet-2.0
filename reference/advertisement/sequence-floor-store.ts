/**
 * ShareNet 2.0 — Atomic Local Persistence Abstraction for Sequence Floors.
 *
 * Per GATE-02 requirement: "atomic local persistence abstraction."
 *
 * This module defines a storage-agnostic interface (`SequenceFloorStore`)
 * for persisting peer sequence floors, plus an in-memory implementation
 * (`InMemorySequenceFloorStore`) that is suitable for testing.
 *
 * The protocol core (`reference/`) MUST NOT depend on any hosted database
 * (per ADR-0013 Layer 3 purity + GATE-02 requirement). The Prisma-backed
 * implementation lives in `src/lib/sharenet/sequence-floor.ts` (Layer 2,
 * service layer). This interface allows the protocol core to define the
 * persistence contract without importing Prisma.
 *
 * Atomicity: the `checkAndAdvance` method MUST be atomic — it must load
 * the current floor, check the sequence, and update the floor in a single
 * transaction so that concurrent calls cannot race.
 *
 * Restart safety: the `InMemorySequenceFloorStore` supports `serialize()`
 * and `restore()` for simulating restarts in tests. A real implementation
 * (e.g. SQLite, Postgres) would persist to disk and survive process restart
 * naturally.
 */

import { checkSequence, type SequenceCheckResult } from "./sequence-floor";

/**
 * Interface for atomic sequence-floor persistence.
 *
 * Implementations MUST guarantee:
 *   1. Atomicity: `checkAndAdvance` is a single transaction.
 *   2. Durability: a stored floor survives restart (in-memory impl simulates
 *      this via serialize/restore; a real impl persists to disk).
 *   3. Monotonicity: the floor NEVER decreases, even after expiry (ADR-0006).
 */
export interface SequenceFloorStore {
  /**
   * Atomically check if `attemptedSequence` is acceptable for `nodeId`
   * and, if so, advance the floor. Returns the check result.
   *
   * This is the ONLY method that modifies the floor. It MUST be atomic
   * (load + check + update in one transaction).
   */
  checkAndAdvance(nodeId: string, attemptedSequence: number): SequenceCheckResult;

  /**
   * Read the current floor for `nodeId` without modifying it.
   * Returns null if the node has never been seen.
   */
  getFloor(nodeId: string): number | null;

  /**
   * Serialize all floors (for restart simulation in tests).
   * Returns a plain object that can be passed to `restore()`.
   */
  serialize(): Record<string, { floor: number; lastAdvancedAt: number }>;

  /**
   * Restore floors from a serialized snapshot (for restart simulation).
   * Replaces all current state.
   */
  restore(data: Record<string, { floor: number; lastAdvancedAt: number }>): void;
}

/**
 * In-memory implementation of `SequenceFloorStore`.
 *
 * Suitable for tests and for single-process reference implementations.
 * NOT suitable for production multi-process deployments (use the Prisma-backed
 * implementation in `src/lib/sharenet/sequence-floor.ts`).
 *
 * Restart simulation: call `serialize()` before "restart", create a new
 * store instance, call `restore()` with the serialized data.
 */
export class InMemorySequenceFloorStore implements SequenceFloorStore {
  private floors = new Map<string, { floor: number; lastAdvancedAt: number }>();

  /**
   * Atomically check and advance the sequence floor.
   *
   * Atomicity: JavaScript is single-threaded, so the load + check + update
   * is naturally atomic (no other code runs between them in the same
   * event loop tick). A real implementation (SQLite/Postgres) MUST use
   * a transaction or SELECT-FOR-UPDATE.
   */
  checkAndAdvance(nodeId: string, attemptedSequence: number): SequenceCheckResult {
    const current = this.floors.get(nodeId);
    const currentFloor = current?.floor ?? null;
    const decision = checkSequence(currentFloor, attemptedSequence);
    if (decision.ok) {
      this.floors.set(nodeId, {
        floor: decision.newFloor,
        lastAdvancedAt: Date.now(),
      });
    }
    return decision;
  }

  getFloor(nodeId: string): number | null {
    return this.floors.get(nodeId)?.floor ?? null;
  }

  serialize(): Record<string, { floor: number; lastAdvancedAt: number }> {
    const out: Record<string, { floor: number; lastAdvancedAt: number }> = {};
    for (const [nodeId, data] of this.floors) {
      out[nodeId] = { ...data };
    }
    return out;
  }

  restore(data: Record<string, { floor: number; lastAdvancedAt: number }>): void {
    this.floors.clear();
    for (const [nodeId, val] of Object.entries(data)) {
      this.floors.set(nodeId, { floor: val.floor, lastAdvancedAt: val.lastAdvancedAt });
    }
  }

  /**
   * Simulate a process restart: the store is replaced but the serialized
   * state is restored. This is the key operation for the GATE-02 restart test.
   *
   * Per ADR-0006: the floor MUST survive restart. An expired advertisement
   * MUST NOT reset the floor.
   */
  restart(): SequenceFloorStore {
    const snapshot = this.serialize();
    const newStore = new InMemorySequenceFloorStore();
    newStore.restore(snapshot);
    return newStore;
  }
}
