/**
 * POST /api/sharenet/protocol/accept-advertisement
 * Runs the FULL AuthenticatedNodeRecord pipeline:
 *   verifyAdvertisement → checkAndUpdateSequenceFloor → acceptAdvertisement → persist.
 *
 * Per ADR-0007 this is the ONLY legal pipeline from a wire advertisement
 * to a persisted AuthenticatedNodeRecord. RemoteNodeHint CANNOT reach this endpoint.
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import { requireSession } from "@/lib/auth/api";
import { advertisementFromHex } from "@reference/advertisement/advertisement";
import { acceptNodeAdvertisement } from "@/lib/sharenet/node-record";

export const POST = withErrors(async (req: NextRequest) => {
  const session = await requireSession();
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const advertisementHex = String(body.advertisementHex ?? "");
  if (!advertisementHex) return jsonError("advertisementHex required", 400, "BAD_HEX");

  let adv;
  try {
    adv = advertisementFromHex(advertisementHex);
  } catch (e) {
    return jsonError(`failed to decode advertisement: ${(e as Error).message}`, 400, "DECODE_FAILED");
  }

  const result = await acceptNodeAdvertisement(adv, session.userId);
  if (!result.ok) {
    // Record a rejected acceptance for the audit trail.
    const { db } = await import("@/lib/db");
    await db.auditLog.create({
      data: {
        action: "NODE_RECORD_REJECTED",
        actorUserId: session.userId,
        targetNodeId: adv.nodeId,
        detail: JSON.stringify({ stage: result.stage, code: result.code, reason: result.reason }),
      },
    });
    return json(result);
  }

  return json(result);
});
