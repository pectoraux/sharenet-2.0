/**
 * ShareNet 2.0 — Sequence Floor persistence (Prisma-backed).
 *
 * Per spec/14 §3 + ADR-0006. Wraps the pure `checkSequence` function with
 * a database lookup + atomic update. Expiration does NOT reset the floor.
 */

import { db } from "@/lib/db";
import { checkSequence, type SequenceCheckResult } from "@reference/advertisement/sequence-floor";

/**
 * Read the current sequence floor for a node. Returns null if the node
 * has never been seen.
 */
export async function getSequenceFloor(nodeId: string): Promise<number | null> {
  const row = await db.sequenceFloor.findUnique({ where: { nodeId } });
  return row?.currentMaxSequence ?? null;
}

/**
 * Atomically check + update the sequence floor for a node.
 *
 * Per ADR-0006, the check is monotonic-only. n <= floor is rejected
 * (STALE for n<floor, DUPLICATE for n==floor). n > floor is accepted and
 * the floor is updated. Expiration does NOT reset the floor — we never
 * delete SequenceFloor rows here.
 *
 * Implementation note: SQLite (and Postgres, when we migrate) supports
 * `upsert` with a where-clause guard. We use a transaction with a fresh
 * read inside to minimize the race window. For a first deliverable this
 * is sufficient; a production system would use SELECT ... FOR UPDATE.
 */
export async function checkAndUpdateSequenceFloor(
  nodeId: string,
  attemptedSequence: number,
  nonceHex?: string,
): Promise<SequenceCheckResult> {
  return await db.$transaction(async (tx) => {
    const current = await tx.sequenceFloor.findUnique({ where: { nodeId } });
    const currentFloor = current?.currentMaxSequence ?? null;
    const decision = checkSequence(currentFloor, attemptedSequence);
    if (decision.ok) {
      // Accept — upsert the floor.
      await tx.sequenceFloor.upsert({
        where: { nodeId },
        update: {
          currentMaxSequence: decision.newFloor,
          lastNonceHex: nonceHex ?? null,
          lastAdvancedAt: new Date(),
        },
        create: {
          nodeId,
          currentMaxSequence: decision.newFloor,
          lastNonceHex: nonceHex ?? null,
        },
      });
      await tx.auditLog.create({
        data: {
          action: "SEQUENCE_FLOOR_UPDATED",
          targetNodeId: nodeId,
          detail: JSON.stringify({
            previousFloor: decision.previousFloor,
            newFloor: decision.newFloor,
          }),
        },
      });
    }
    return decision;
  });
}
