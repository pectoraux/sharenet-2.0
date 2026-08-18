/**
 * ShareNet 2.0 — Durable circuit sequence-floor + ack replay persistence.
 *
 * Per spec/08 §4.5: "Sequence floors persist across circuit re-key events."
 * Per R-008 hardening: setup acks are single-use.
 *
 * This module provides Prisma-backed durable persistence for:
 *   1. CircuitSequenceFloor — keyed by commitment_root, survives process restart
 *   2. ConsumedCircuitAck — (commitmentRoot, hopIndex, ackNonce) single-use
 *
 * ARCHITECTURE (R-008 integration fix):
 *
 *   These Prisma helpers are the durable SUBSTRATE. They are adapted to the
 *   protocol-level `CircuitSequenceFloorStore` + `CircuitAckReplayStore`
 *   interfaces (defined in `reference/circuit/replay-stores.ts`) by
 *   `src/lib/sharenet/durable-circuit-replay-stores.ts`.
 *
 *   The protocol core (`reference/`) consumes the INTERFACES — not these
 *   helpers directly — so it never imports `@/lib/db` (enforced by arch
 *   test #23, ADR-0013). The protocol path (`processCircuitFrame`,
 *   `processCircuitSetupAck`, `establishDistributedCircuit`) is wired to
 *   the durable substrate through these adapters.
 *
 *   This closes the R-008 integration gap flagged by the audit: the
 *   durable persistence layer is no longer a separate application-level
 *   concern — the reference protocol path itself uses it (via the
 *   interface), so process-restart protection is proven end-to-end.
 */

import { db } from "@/lib/db";

// -----------------------------------------------------------------------
// Durable sequence-floor persistence
// -----------------------------------------------------------------------

/**
 * Read the current durable sequence floor for a receiving context.
 * Returns 0n if no prior frame has been accepted on this (route, hop, direction).
 *
 * Per spec/08 §4.5: survives process restart because it is persisted
 * in the database (not in-memory).
 *
 * R-009 Stage 1 final replay-model correction: the namespace is
 * (commitmentRoot, hopIndex, direction) — receiver-local, not route-shared.
 */
export async function getDurableCircuitFloor(
  commitmentRootHex: string,
  hopIndex: number,
  direction: number,
): Promise<bigint> {
  const row = await db.circuitSequenceFloor.findUnique({
    where: {
      commitmentRootHex_hopIndex_direction: {
        commitmentRootHex,
        hopIndex,
        direction,
      },
    },
  });
  if (!row) return 0n;
  try {
    return BigInt(row.currentMaxSequence);
  } catch {
    return 0n;
  }
}

/**
 * Atomically update the durable sequence floor for a receiving context.
 *
 * Per spec/08 §4.5: "a re-key MUST continue the counter from the prior floor."
 * This holds per receiver: a re-key on the same (route, hop, direction)
 * continues from that receiver's prior floor.
 *
 * This function is fail-closed: if the database write fails, the floor
 * is NOT updated in memory, and the caller MUST treat the circuit as
 * unusable (cannot guarantee replay protection).
 *
 * @returns true if the floor was successfully persisted, false on failure.
 */
export async function updateDurableCircuitFloor(
  commitmentRootHex: string,
  hopIndex: number,
  direction: number,
  newFloor: bigint,
): Promise<boolean> {
  try {
    await db.circuitSequenceFloor.upsert({
      where: {
        commitmentRootHex_hopIndex_direction: {
          commitmentRootHex,
          hopIndex,
          direction,
        },
      },
      update: {
        currentMaxSequence: newFloor.toString(),
        lastAdvancedAt: new Date(),
      },
      create: {
        commitmentRootHex,
        hopIndex,
        direction,
        currentMaxSequence: newFloor.toString(),
      },
    });
    return true;
  } catch {
    return false; // fail-closed: caller treats as unusable
  }
}

/**
 * Atomically check + update the durable sequence floor for a receiving context.
 *
 * Returns { ok: true } if the sequence is strictly higher than the
 * persisted floor (and the floor was updated), or { ok: false, reason }
 * if the sequence is <= floor (replay/stale) or the database write failed.
 *
 * R-009 Stage 1 final replay-model correction: the namespace is
 * (commitmentRoot, hopIndex, direction) — receiver-local, not route-shared.
 */
export async function checkAndUpdateDurableCircuitFloor(
  commitmentRootHex: string,
  hopIndex: number,
  direction: number,
  attemptedSequence: bigint,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  return await db.$transaction(async (tx) => {
    const current = await tx.circuitSequenceFloor.findUnique({
      where: {
        commitmentRootHex_hopIndex_direction: {
          commitmentRootHex,
          hopIndex,
          direction,
        },
      },
    });
    const currentFloor = current ? BigInt(current.currentMaxSequence) : 0n;

    if (attemptedSequence <= currentFloor) {
      return {
        ok: false,
        reason: `sequence ${attemptedSequence} ≤ floor ${currentFloor} (replay/stale) at (hop ${hopIndex}, dir ${direction})`,
      };
    }

    // Accept — update the floor atomically
    await tx.circuitSequenceFloor.upsert({
      where: {
        commitmentRootHex_hopIndex_direction: {
          commitmentRootHex,
          hopIndex,
          direction,
        },
      },
      update: {
        currentMaxSequence: attemptedSequence.toString(),
        lastAdvancedAt: new Date(),
      },
      create: {
        commitmentRootHex,
        hopIndex,
        direction,
        currentMaxSequence: attemptedSequence.toString(),
      },
    });

    return { ok: true };
  });
}

// -----------------------------------------------------------------------
// Setup-ack single-use consumption
// -----------------------------------------------------------------------

/**
 * Check if a circuit setup ack has already been consumed.
 *
 * Per R-008 hardening: (commitmentRoot, hopIndex, ackNonce) is single-use.
 * An identical, still-fresh ack MUST be rejected on second processing.
 *
 * @returns true if the ack has NOT been consumed yet (safe to process),
 *          false if it has already been consumed (replay).
 */
export async function isAckFresh(
  commitmentRootHex: string,
  hopIndex: number,
  ackNonceHex: string,
): Promise<boolean> {
  const existing = await db.consumedCircuitAck.findUnique({
    where: {
      commitmentRootHex_hopIndex_ackNonceHex: {
        commitmentRootHex,
        hopIndex,
        ackNonceHex,
      },
    },
  });
  return existing === null;
}

/**
 * Mark a circuit setup ack as consumed (single-use).
 *
 * Per R-008 hardening: after successfully processing an ack, the initiator
 * MUST record (commitmentRoot, hopIndex, ackNonce) so a replayed ack
 * is rejected.
 *
 * @returns true if the ack was successfully marked consumed (first use),
 *          false if it was already consumed (duplicate/replay).
 */
export async function consumeAck(
  commitmentRootHex: string,
  hopIndex: number,
  ackNonceHex: string,
): Promise<boolean> {
  try {
    await db.consumedCircuitAck.create({
      data: { commitmentRootHex, hopIndex, ackNonceHex },
    });
    return true; // first use — successfully consumed
  } catch {
    return false; // unique constraint violation — already consumed (replay)
  }
}

/**
 * Purge consumed acks older than the TTL.
 * Should be called periodically to prevent unbounded growth.
 *
 * @param ttlSeconds — acks older than this are deleted.
 */
export async function purgeOldConsumedAcks(ttlSeconds: number = 3600): Promise<number> {
  const cutoff = new Date(Date.now() - ttlSeconds * 1000);
  const result = await db.consumedCircuitAck.deleteMany({
    where: { consumedAt: { lt: cutoff } },
  });
  return result.count;
}
