/**
 * ShareNet 2.0 — Durable SQLite implementations of the circuit replay stores.
 *
 * This module is the **durable substrate** for the protocol-level replay
 * store interfaces defined in `reference/circuit/replay-stores.ts`. It
 * adapts the Prisma-backed persistence helpers in
 * `src/lib/sharenet/circuit-persistence.ts` to the protocol interfaces.
 *
 * ARCHITECTURE (per the R-008 integration audit):
 *
 *   CircuitReplayPersistence   (interface, in reference/)
 *           │
 *           ├── DurableSqliteCircuitReplayStore   (THIS FILE — src/lib/sharenet/)
 *           ├── InMemoryCircuitReplayStore          (in reference/, for tests)
 *           └── future platform stores
 *
 *   reference/circuit/circuit.ts  →  CircuitReplayPersistence
 *
 * The protocol core (`reference/`) depends ONLY on the interface — it never
 * imports Prisma or `@/lib/db` (enforced by architecture test #23,
 * ADR-0013). This module is the adapter that binds the durable SQLite
 * substrate to the protocol interface.
 *
 * A protocol engineer in Rust or Kotlin can implement the same interface
 * against any durable substrate (LMDB, RocksDB, SQLite, etc.) and the
 * reference protocol path — `processCircuitFrame`, `processCircuitSetupAck`,
 * `establishDistributedCircuit` — will use it without modification.
 *
 * FAIL-CLOSED: every mutating operation fails closed. If the database write
 * cannot complete, the frame/ack is rejected. This is the contract the
 * protocol path relies on.
 */

import type {
  CircuitSequenceFloorStore,
  CircuitAckReplayStore,
  SequenceFloorCheckResult,
} from "@reference/circuit/replay-stores";
import { toHex } from "@reference/encoding/cbor";
import {
  getDurableCircuitFloor,
  checkAndUpdateDurableCircuitFloor,
  isAckFresh,
  consumeAck,
} from "@/lib/sharenet/circuit-persistence";

// -----------------------------------------------------------------------
// DurableSqliteCircuitSequenceFloorStore
// -----------------------------------------------------------------------

/**
 * Durable SQLite-backed implementation of `CircuitSequenceFloorStore`.
 *
 * Backed by the Prisma `CircuitSequenceFloor` model (keyed by
 * `commitmentRootHex`). Survives process restart because the floor is
 * persisted in the database, not in memory.
 *
 * Per spec/08 §4.5: "Sequence floors persist across circuit re-key events;
 * a re-key MUST continue the counter from the prior floor."
 *
 * The `checkAndAdvance` operation is atomic: the check (sequence > floor)
 * and the persist (update floor) happen in a single Prisma transaction
 * (see `checkAndUpdateDurableCircuitFloor`). Fail-closed: if the
 * transaction cannot complete, the frame is rejected.
 */
export class DurableSqliteCircuitSequenceFloorStore implements CircuitSequenceFloorStore {
  async getFloor(commitmentRoot: Uint8Array): Promise<bigint> {
    return getDurableCircuitFloor(toHex(commitmentRoot));
  }

  async checkAndAdvance(
    commitmentRoot: Uint8Array,
    attemptedSequence: bigint,
  ): Promise<SequenceFloorCheckResult> {
    return checkAndUpdateDurableCircuitFloor(
      toHex(commitmentRoot),
      attemptedSequence,
    );
  }
}

// -----------------------------------------------------------------------
// DurableSqliteCircuitAckReplayStore
// -----------------------------------------------------------------------

/**
 * Durable SQLite-backed implementation of `CircuitAckReplayStore`.
 *
 * Backed by the Prisma `ConsumedCircuitAck` model with a unique constraint
 * on `(commitmentRootHex, hopIndex, ackNonceHex)`. Survives process restart
 * because consumed acks are persisted in the database.
 *
 * The `consume` operation is atomic: the insert relies on the unique
 * constraint. A second insert with the same key fails (unique violation)
 * and returns `false` — the ack is a replay. Fail-closed: if the insert
 * cannot complete for any reason, `false` is returned and the ack is
 * rejected.
 */
export class DurableSqliteCircuitAckReplayStore implements CircuitAckReplayStore {
  async isFresh(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    ackNonce: Uint8Array,
  ): Promise<boolean> {
    return isAckFresh(toHex(commitmentRoot), hopIndex, toHex(ackNonce));
  }

  async consume(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    ackNonce: Uint8Array,
  ): Promise<boolean> {
    return consumeAck(toHex(commitmentRoot), hopIndex, toHex(ackNonce));
  }
}

// -----------------------------------------------------------------------
// Convenience: a bundled pair of durable stores
// -----------------------------------------------------------------------

/**
 * A bundled pair of durable SQLite replay stores (floor + ack).
 *
 * Use this in production / integration paths that must survive process
 * restart. Both stores share the same Prisma `db` client (the app's
 * single database connection).
 */
export function createDurableCircuitReplayStores(): {
  floorStore: DurableSqliteCircuitSequenceFloorStore;
  ackStore: DurableSqliteCircuitAckReplayStore;
} {
  return {
    floorStore: new DurableSqliteCircuitSequenceFloorStore(),
    ackStore: new DurableSqliteCircuitAckReplayStore(),
  };
}
