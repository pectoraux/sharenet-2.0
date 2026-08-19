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
import { PrismaClient } from "@prisma/client";
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
  /**
   * Optional per-instance Prisma client. Defaults to the app-global `db`.
   *
   * Per R-009 Stage 3 Phase 3 (real multi-process propagation): each
   * participant process needs its OWN durable store / DB namespace. A test
   * (or production deployment) can pass a dedicated `PrismaClient` pointing
   * at a per-participant SQLite file. Production code that uses the default
   * app-global `db` is unaffected.
   */
  private readonly client: PrismaClient;

  constructor(client?: PrismaClient) {
    this.client = client ?? db;
  }

  async isRevoked(circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean> {
    const row = await this.client.circuitRevocation.findUnique({
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
      await this.client.circuitRevocation.upsert({
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
 * Per the re-audit of 3536797 (R-009 Stage 3 Phase 2 final hardening):
 * the previous design used `circuitRevocation.upsert` for the tombstone,
 * which is idempotent — but it could not distinguish "I wrote the tombstone"
 * from "the tombstone already existed". Two concurrent destroys with
 * different nonces could BOTH return `{ ok: true, idempotent: false }`,
 * even though only ONE actually performed the ACTIVE→REVOKED transition.
 *
 * This implementation uses `circuitRevocation.create` (NOT upsert) for the
 * tombstone. The unique constraint on `(circuitIdHex, commitmentRootHex)` is
 * the AUTHORITATIVE ACTIVE→REVOKED transition: exactly ONE transaction's
 * `create` succeeds (the winner); all concurrent transactions' `create`
 * fails with a unique-constraint violation → the transaction rolls back →
 * the loser re-checks `isRevoked` → true → returns `{ ok: true, idempotent: true }`.
 *
 * This guarantees: concurrent destroys for the same circuit (regardless of
 * nonce) produce EXACTLY ONE terminal transition; all subsequent requests
 * are idempotent/already-revoked.
 *
 * The destroy nonce is recorded in the SAME `$transaction` (point 3 of the
 * final hardening): `consumedCircuitDestroy.create` + `circuitRevocation.create`
 * are a single atomic transaction. Both succeed or both fail — no split state.
 *
 * Idempotency (pre-check): if the tombstone already exists (the circuit was
 * already revoked by a prior destroy or expiry), the operation returns
 * `{ ok: true, idempotent: true }` WITHOUT entering the transaction.
 *
 * Idempotency (post-failure): if the transaction fails (unique-constraint
 * violation on the tombstone — a concurrent destroy won — OR a genuine
 * persistence failure), the operation re-checks `isRevoked`:
 *   - true → another transaction won the race → return idempotent.
 *   - false → genuine persistence failure → return fail-closed.
 */
export class DurableSqliteCircuitDestroyStore implements CircuitDestroyStore {
  /**
   * Optional per-instance Prisma client. Defaults to the app-global `db`.
   *
   * Per R-009 Stage 3 Phase 3 (real multi-process propagation): each
   * participant process needs its OWN durable store / DB namespace. A test
   * (or production deployment) can pass a dedicated `PrismaClient` pointing
   * at a per-participant SQLite file. Production code that uses the default
   * app-global `db` is unaffected.
   */
  private readonly client: PrismaClient;

  constructor(client?: PrismaClient) {
    this.client = client ?? db;
  }

  async isRevoked(circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean> {
    const row = await this.client.circuitRevocation.findUnique({
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
    // Pre-check idempotency: if the tombstone already exists, the circuit is
    // already revoked. Return idempotent success WITHOUT entering the transaction.
    const alreadyRevoked = await this.isRevoked(circuitId, commitmentRoot);
    if (alreadyRevoked) {
      return { ok: true, idempotent: true };
    }

    // ATOMIC transaction: consume the nonce + create the tombstone (authoritative
    // ACTIVE→REVOKED transition). Both in the SAME transaction — no split state.
    try {
      await this.client.$transaction([
        // 1. Consume the destroy nonce (unique constraint catches replays).
        this.client.consumedCircuitDestroy.create({
          data: {
            commitmentRootHex: toHex(commitmentRoot),
            circuitIdHex: toHex(circuitId),
            destroyNonceHex: toHex(destroyNonce),
          },
        }),
        // 2. CREATE the tombstone (NOT upsert). The unique constraint on
        //    (circuitIdHex, commitmentRootHex) is the AUTHORITATIVE transition:
        //    exactly ONE transaction's create succeeds. Concurrent transactions'
        //    create fails → rollback → re-check isRevoked → idempotent.
        this.client.circuitRevocation.create({
          data: {
            circuitIdHex: toHex(circuitId),
            commitmentRootHex: toHex(commitmentRoot),
            destroyerNodeId,
            destroyerRole,
            destroyReason,
            destroyNonceHex: toHex(destroyNonce),
          },
        }),
      ]);
      // This transaction performed the terminal transition.
      return { ok: true, idempotent: false };
    } catch {
      // Transaction failed — EITHER a concurrent destroy won the race
      // (tombstone create unique-constraint violation) OR a nonce replay
      // (consumedCircuitDestroy create unique-constraint violation) OR a
      // genuine persistence failure. The ENTIRE transaction rolled back —
      // no split state (the nonce was NOT consumed if the tombstone create
      // failed, and vice versa).
      //
      // Re-check isRevoked to distinguish:
      //   - true → another transaction won the race (the circuit is now
      //     durably revoked) → return idempotent.
      //   - false → genuine persistence failure (DB error, etc.) OR a nonce
      //     replay of a nonce whose transaction was rolled back (shouldn't
      //     happen in normal operation since nonce + tombstone are atomic,
      //     but if it did, isRevoked would be false) → return fail-closed.
      const nowRevoked = await this.isRevoked(circuitId, commitmentRoot);
      if (nowRevoked) {
        // Another transaction won the race — the circuit is now durably revoked.
        // This destroy is idempotent (the terminal transition was performed by
        // the winner). The loser's nonce was NOT consumed (rolled back), but
        // that's correct — the circuit is already revoked, so the nonce is
        // irrelevant. A retry with the same nonce would hit the pre-check
        // idempotency (isRevoked → true) and return idempotent.
        return { ok: true, idempotent: true };
      }
      // Genuine persistence failure — fail closed. The nonce was NOT consumed
      // (rolled back). The operator can safely retry with the SAME destroy.
      return {
        ok: false,
        reason: "atomic consumeDestroyAndRevoke transaction failed (persistence failure, fail-closed, no split state — safe to retry)",
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
      await this.client.circuitRevocation.upsert({
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
