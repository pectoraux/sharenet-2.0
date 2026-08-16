/**
 * ShareNet 2.0 — AuthenticatedNodeRecord service.
 *
 * Per ADR-0007, the ONLY legal pipeline from a wire advertisement to a
 * persisted AuthenticatedNodeRecord is:
 *
 *   NodeAdvertisement
 *      ↓ verifyAdvertisement (crypto + binding + timestamps + canonical)
 *   VerifiedNodeAdvertisement
 *      ↓ acceptAdvertisement (sequence floor + acceptance policy)
 *   AuthenticatedNodeRecordStub
 *      ↓ persistNodeRecord (here)
 *   NodeRecord (database row)
 *
 * This module NEVER accepts a RemoteNodeHint. Architecture regression test #7
 * asserts the hint-to-record path is impossible.
 */

import { db } from "@/lib/db";
import { verifyAdvertisement, advertisementToHex, type NodeAdvertisement } from "@reference/advertisement/advertisement";
import { acceptAdvertisement } from "@reference/advertisement/sequence-floor";
import { checkAndUpdateSequenceFloor } from "./sequence-floor";

/** Acceptance outcome returned to API callers. */
export type NodeAcceptanceResult =
  | {
      ok: true;
      nodeId: string;
      publicKeyHex: string;
      capabilities: readonly string[];
      sequence: number;
      acceptedAt: Date;
      firstSeenAt: Date;
    }
  | {
      ok: false;
      stage: "VERIFICATION" | "SEQUENCE" | "ACCEPTANCE";
      reason: string;
      /** Machine-readable error code for the dashboard. */
      code: string;
    };

/**
 * Accept (or reject) a NodeAdvertisement through the full pipeline.
 *
 * Steps (spec/03 §5):
 *   1. verifyAdvertisement — signature, identity binding, timestamps, expiry, canonical
 *   2. checkAndUpdateSequenceFloor — monotonic sequence + persistent replay protection
 *   3. acceptAdvertisement — combine results into AuthenticatedNodeRecordStub
 *   4. persistNodeRecord — upsert the NodeRecord row
 *
 * @param adv The advertisement to accept.
 * @param actorUserId The user (if any) who triggered this acceptance — for audit.
 */
export async function acceptNodeAdvertisement(
  adv: NodeAdvertisement,
  actorUserId?: string,
): Promise<NodeAcceptanceResult> {
  // Step 1: cryptographic + structural verification.
  const verification = verifyAdvertisement(adv);
  if (!verification.ok) {
    return {
      ok: false,
      stage: "VERIFICATION",
      reason: verification.detail,
      code: verification.error,
    };
  }

  // Step 2: persistent sequence floor check + update.
  const nonceHex = Array.from(adv.nonce)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const sequenceCheck = await checkAndUpdateSequenceFloor(adv.nodeId, adv.sequence, nonceHex);
  if (!sequenceCheck.ok) {
    return {
      ok: false,
      stage: "SEQUENCE",
      reason: `${sequenceCheck.reason} (floor=${sequenceCheck.currentFloor}, attempted=${sequenceCheck.attemptedSequence})`,
      code: sequenceCheck.reason,
    };
  }

  // Step 3: combine into AuthenticatedNodeRecordStub.
  const acceptance = acceptAdvertisement(
    adv.nodeId,
    adv.signingPublicKey,
    adv.capabilities,
    adv.sequence,
    verification.verified.verifiedAt,
    { verificationOk: true, sequenceCheck },
  );
  if (!acceptance.ok) {
    return {
      ok: false,
      stage: "ACCEPTANCE",
      reason: acceptance.reason,
      code: "ACCEPTANCE_FAILED",
    };
  }

  // Step 4: persist.
  const capabilitiesJson = JSON.stringify(acceptance.record.capabilities);
  const advertisementHex = advertisementToHex(adv);
  const upserted = await db.nodeRecord.upsert({
    where: { nodeId: acceptance.record.nodeId },
    update: {
      publicKeyHex: acceptance.record.publicKeyHex,
      capabilities: capabilitiesJson,
      sequence: acceptance.record.sequence,
      advertisementHex,
      acceptedAt: new Date(acceptance.record.acceptedAt * 1000),
      expiresAt: new Date(adv.expiry * 1000),
    },
    create: {
      nodeId: acceptance.record.nodeId,
      publicKeyHex: acceptance.record.publicKeyHex,
      capabilities: capabilitiesJson,
      sequence: acceptance.record.sequence,
      advertisementHex,
      acceptedAt: new Date(acceptance.record.acceptedAt * 1000),
      expiresAt: new Date(adv.expiry * 1000),
    },
  });

  await db.auditLog.create({
    data: {
      action: "NODE_RECORD_ACCEPTED",
      actorUserId: actorUserId ?? null,
      targetNodeId: acceptance.record.nodeId,
      detail: JSON.stringify({
        sequence: acceptance.record.sequence,
        capabilities: acceptance.record.capabilities,
        expiresAt: adv.expiry,
      }),
    },
  });

  return {
    ok: true,
    nodeId: upserted.nodeId,
    publicKeyHex: upserted.publicKeyHex,
    capabilities: acceptance.record.capabilities,
    sequence: upserted.sequence,
    acceptedAt: upserted.acceptedAt,
    firstSeenAt: upserted.firstSeenAt,
  };
}

/** List all accepted node records, most-recently-accepted first. */
export async function listAcceptedNodes(limit = 100): Promise<
  Array<{
    nodeId: string;
    publicKeyHex: string;
    capabilities: string[];
    sequence: number;
    acceptedAt: Date;
    firstSeenAt: Date;
    expiresAt: Date;
  }>
> {
  const rows = await db.nodeRecord.findMany({
    orderBy: { acceptedAt: "desc" },
    take: Math.min(limit, 500),
  });
  return rows.map((r) => ({
    nodeId: r.nodeId,
    publicKeyHex: r.publicKeyHex,
    capabilities: safeParseCapabilities(r.capabilities),
    sequence: r.sequence,
    acceptedAt: r.acceptedAt,
    firstSeenAt: r.firstSeenAt,
    expiresAt: r.expiresAt,
  }));
}

function safeParseCapabilities(s: string): string[] {
  try {
    const v = JSON.parse(s);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
}
