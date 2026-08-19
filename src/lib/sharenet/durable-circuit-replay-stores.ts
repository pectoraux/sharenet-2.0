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
 * Backed by the Prisma `CircuitSequenceFloor` model, keyed by
 * `(commitmentRootHex, hopIndex, direction)` — the receiving security
 * context. Survives process restart because the floor is persisted in
 * the database, not in memory.
 *
 * Per spec/08 §4.5: "Sequence floors persist across circuit re-key events;
 * a re-key MUST continue the counter from the prior floor." This holds
 * per receiver: a re-key on the same (route, hop, direction) continues
 * from that receiver's prior floor.
 *
 * The `checkAndAdvance` operation is atomic: the check (sequence > floor)
 * and the persist (update floor) happen in a single Prisma transaction
 * (see `checkAndUpdateDurableCircuitFloor`). Fail-closed: if the
 * transaction cannot complete, the frame is rejected.
 *
 * R-009 Stage 1 final replay-model correction: the namespace is
 * (commitmentRoot, hopIndex, direction) — receiver-local, not route-shared.
 * Every hop has its own floor; a malicious upstream relay replaying an
 * already-valid inner ciphertext toward a downstream hop is caught by
 * the downstream hop's own floor. See ADR-0019.
 */
export class DurableSqliteCircuitSequenceFloorStore implements CircuitSequenceFloorStore {
  async getFloor(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    direction: number,
  ): Promise<bigint> {
    return getDurableCircuitFloor(toHex(commitmentRoot), hopIndex, direction);
  }

  async checkAndAdvance(
    commitmentRoot: Uint8Array,
    hopIndex: number,
    direction: number,
    attemptedSequence: bigint,
  ): Promise<SequenceFloorCheckResult> {
    return checkAndUpdateDurableCircuitFloor(
      toHex(commitmentRoot),
      hopIndex,
      direction,
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

// -----------------------------------------------------------------------
// DurableSqliteGatewayAuthorizationReplayStore (R-009 Stage 2 final)
// -----------------------------------------------------------------------

import { db } from "@/lib/db";
import type { GatewayAuthorizationReplayStore } from "@reference/circuit/replay-stores";

/**
 * Durable SQLite-backed implementation of `GatewayAuthorizationReplayStore`.
 *
 * Backed by the Prisma `ConsumedGatewayAuthorization` model with a unique
 * constraint on `(commitmentRootHex, circuitIdHex, ackNonceHex)`. Survives
 * process restart because consumed authorizations are persisted in the
 * database.
 *
 * The `consume` operation is atomic: the insert relies on the unique
 * constraint. A second insert with the same key fails (unique violation)
 * and returns `false` — the authorization is a replay. Fail-closed: if the
 * insert cannot complete for any reason, `false` is returned and the
 * authorization is rejected.
 */
export class DurableSqliteGatewayAuthorizationReplayStore implements GatewayAuthorizationReplayStore {
  async consume(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    ackNonce: Uint8Array,
  ): Promise<boolean> {
    try {
      await db.consumedGatewayAuthorization.create({
        data: {
          commitmentRootHex: toHex(commitmentRoot),
          circuitIdHex: toHex(circuitId),
          ackNonceHex: toHex(ackNonce),
        },
      });
      return true; // first use — successfully consumed
    } catch {
      return false; // unique constraint violation — already consumed (replay)
    }
  }
}

// -----------------------------------------------------------------------
// DurableSqliteCircuitRevocationStore (R-009 Stage 3)
// -----------------------------------------------------------------------

import type {
  CircuitRevocationStore,
  CircuitDestroyReplayStore,
} from "@reference/circuit/replay-stores";

/**
 * Durable SQLite-backed implementation of CircuitRevocationStore.
 *
 * Per ADR-0022: keyed by (circuitIdHex, commitmentRootHex). Survives process
 * restart. Idempotent: if the circuit is already revoked, revoke() returns true.
 */
export class DurableSqliteCircuitRevocationStore implements CircuitRevocationStore {
  async isRevoked(circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean> {
    const row = await db.circuitRevocation.findUnique({
      where: {
        circuitIdHex_commitmentRootHex: {
          circuitIdHex: toHex(circuitId),
          commitmentRootHex: toHex(commitmentRoot),
        },
      },
    });
    return row !== null;
  }

  async revoke(
    circuitId: Uint8Array,
    commitmentRoot: Uint8Array,
    destroyerNodeId: string,
    destroyerRole: number,
    destroyReason: number,
    destroyNonce: Uint8Array,
  ): Promise<boolean> {
    try {
      await db.circuitRevocation.upsert({
        where: {
          circuitIdHex_commitmentRootHex: {
            circuitIdHex: toHex(circuitId),
            commitmentRootHex: toHex(commitmentRoot),
          },
        },
        update: {}, // idempotent — don't overwrite if exists
        create: {
          circuitIdHex: toHex(circuitId),
          commitmentRootHex: toHex(commitmentRoot),
          destroyerNodeId,
          destroyerRole,
          destroyReason,
          destroyNonceHex: toHex(destroyNonce),
        },
      });
      return true;
    } catch {
      return false; // fail-closed
    }
  }
}

// -----------------------------------------------------------------------
// DurableSqliteCircuitDestroyReplayStore (R-009 Stage 3)
// -----------------------------------------------------------------------

/**
 * Durable SQLite-backed implementation of CircuitDestroyReplayStore.
 *
 * Per ADR-0022: separate namespace from ConsumedCircuitAck +
 * ConsumedGatewayAuthorization. Keyed by (commitmentRoot, circuitId,
 * destroyNonce). Fail-closed on persistence failure.
 */
export class DurableSqliteCircuitDestroyReplayStore implements CircuitDestroyReplayStore {
  async consume(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    destroyNonce: Uint8Array,
  ): Promise<boolean> {
    try {
      await db.consumedCircuitDestroy.create({
        data: {
          commitmentRootHex: toHex(commitmentRoot),
          circuitIdHex: toHex(circuitId),
          destroyNonceHex: toHex(destroyNonce),
        },
      });
      return true;
    } catch {
      return false; // unique constraint — replay or persistence failure
    }
  }
}

// -----------------------------------------------------------------------
// DurableSqliteCircuitDestroyStore (R-009 Stage 3 Phase 2 — atomic)
// -----------------------------------------------------------------------

import type {
  CircuitDestroyStore,
  ConsumeDestroyAndRevokeResult,
} from "@reference/circuit/replay-stores";

/**
 * Durable SQLite-backed implementation of `CircuitDestroyStore`.
 *
 * Per the re-audit of 60e4364 (R-009 Stage 3 Phase 2): the previous design
 * used two separate operations (`revoke()` + `consume()`) that could leave
 * a SPLIT security state if one succeeded and the other failed. This
 * implementation uses a single Prisma `$transaction` to atomically:
 *   1. Insert into `ConsumedCircuitDestroy` (unique constraint on
 *      `(commitmentRootHex, circuitIdHex, destroyNonceHex)` — catches replays).
 *   2. Upsert into `CircuitRevocation` (idempotent — if the tombstone already
 *      exists, the upsert is a no-op).
 *
 * If EITHER operation fails, the ENTIRE transaction rolls back — no split state.
 * The nonce is NOT consumed if the tombstone cannot be written; the tombstone is
 * NOT written if the nonce is a replay.
 *
 * Idempotency: if the tombstone already exists (the circuit was already
 * revoked by a prior destroy), the operation returns `{ ok: true, idempotent: true }`
 * WITHOUT attempting to insert the nonce (checked first via `isRevoked`).
 *
 * The `$transaction` uses the default isolation level (Read Committed in
 * SQLite). The unique constraint on `ConsumedCircuitDestroy` provides the
 * replay protection — a concurrent destroy with the same nonce will fail the
 * insert (unique violation → transaction abort → rollback → no split state).
 */
export class DurableSqliteCircuitDestroyStore implements CircuitDestroyStore {
  async isRevoked(circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean> {
    const row = await db.circuitRevocation.findUnique({
      where: {
        circuitIdHex_commitmentRootHex: {
          circuitIdHex: toHex(circuitId),
          commitmentRootHex: toHex(commitmentRoot),
        },
      },
    });
    return row !== null;
  }

  async consumeDestroyAndRevoke(
    commitmentRoot: Uint8Array,
    circuitId: Uint8Array,
    destroyNonce: Uint8Array,
    destroyerNodeId: string,
    destroyerRole: number,
    destroyReason: number,
  ): Promise<ConsumeDestroyAndRevokeResult> {
    // Idempotency: if the tombstone already exists, return idempotent success
    // WITHOUT consuming the nonce. The tombstone is the authoritative state.
    const alreadyRevoked = await this.isRevoked(circuitId, commitmentRoot);
    if (alreadyRevoked) {
      return { ok: true, idempotent: true };
    }

    // ATOMIC transaction: consume the nonce + write the tombstone.
    // If EITHER fails, the ENTIRE transaction rolls back — no split state.
    try {
      await db.$transaction([
        // 1. Consume the destroy nonce (unique constraint catches replays).
        db.consumedCircuitDestroy.create({
          data: {
            commitmentRootHex: toHex(commitmentRoot),
            circuitIdHex: toHex(circuitId),
            destroyNonceHex: toHex(destroyNonce),
          },
        }),
        // 2. Write the revocation tombstone (upsert — idempotent if a concurrent
        //    transaction wrote it first; the upsert avoids a unique-constraint
        //    failure on the tombstone that would abort the whole transaction).
        db.circuitRevocation.upsert({
          where: {
            circuitIdHex_commitmentRootHex: {
              circuitIdHex: toHex(circuitId),
              commitmentRootHex: toHex(commitmentRoot),
            },
          },
          update: {}, // idempotent — don't overwrite if exists
          create: {
            circuitIdHex: toHex(circuitId),
            commitmentRootHex: toHex(commitmentRoot),
            destroyerNodeId,
            destroyerRole,
            destroyReason,
            destroyNonceHex: toHex(destroyNonce),
          },
        }),
      ]);
      return { ok: true, idempotent: false };
    } catch {
      // Transaction failed (unique-constraint violation on the nonce → replay,
      // OR a persistence failure → disk error, DB down, etc.). The ENTIRE
      // transaction rolled back — no split state. The nonce was NOT consumed
      // (unless the failure was a replay of the SAME nonce, in which case the
      // tombstone would have been written by the first transaction). Either way,
      // the caller MUST reject the destroy (fail-closed). A retry with the SAME
      // nonce will be rejected as a replay (the nonce insert failed on the
      // unique constraint, but the rollback removed it — a retry is safe ONLY
      // if the first transaction fully committed; if it aborted, the nonce is
      // still fresh and the retry will succeed).
      return {
        ok: false,
        reason: "atomic consumeDestroyAndRevoke transaction failed (replay or persistence failure, fail-closed, no split state)",
      };
    }
  }

  /**
   * Also implement `CircuitRevocationStore.revoke()` so this store can be
   * passed to `processCircuitWireFrame` (which takes `CircuitRevocationStore`)
   * AND `processCircuitDestroy` (which takes `CircuitDestroyStore`). The same
   * `CircuitRevocation` DB table is shared, so a tombstone written by
   * `consumeDestroyAndRevoke` is visible to `isRevoked` (called by
   * `processCircuitWireFrame`). This is structural typing — no explicit
   * `implements` needed.
   */
  async revoke(
    circuitId: Uint8Array,
    commitmentRoot: Uint8Array,
    destroyerNodeId: string,
    destroyerRole: number,
    destroyReason: number,
    destroyNonce: Uint8Array,
  ): Promise<boolean> {
    try {
      await db.circuitRevocation.upsert({
        where: {
          circuitIdHex_commitmentRootHex: {
            circuitIdHex: toHex(circuitId),
            commitmentRootHex: toHex(commitmentRoot),
          },
        },
        update: {}, // idempotent — don't overwrite if exists
        create: {
          circuitIdHex: toHex(circuitId),
          commitmentRootHex: toHex(commitmentRoot),
          destroyerNodeId,
          destroyerRole,
          destroyReason,
          destroyNonceHex: toHex(destroyNonce),
        },
      });
      return true;
    } catch {
      return false; // fail-closed
    }
  }
}
