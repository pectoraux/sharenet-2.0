/**
 * POST /api/sharenet/protocol/verify-advertisement
 * Cryptographically verifies a NodeAdvertisement (hex) WITHOUT persisting.
 * Runs spec/03 §5 checks 1,2,3,4,6 (sequence check requires DB; run /accept-advertisement for full pipeline).
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import { advertisementFromHex, verifyAdvertisement } from "@reference/advertisement/advertisement";

export const POST = withErrors(async (req: NextRequest) => {
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

  const result = verifyAdvertisement(adv);
  if (!result.ok) {
    return json({
      ok: false,
      stage: "VERIFICATION",
      code: result.error,
      reason: result.detail,
      advertisement: {
        protocolVersion: adv.protocolVersion,
        nodeId: adv.nodeId,
        sequence: adv.sequence,
        timestamp: adv.timestamp,
        expiry: adv.expiry,
        capabilities: adv.capabilities,
      },
    });
  }

  return json({
    ok: true,
    stage: "VERIFICATION",
    verifiedAt: result.verified.verifiedAt,
    bodyBytesHex: bytesToHex(result.verified.bodyBytes),
    advertisement: {
      protocolVersion: adv.protocolVersion,
      nodeId: adv.nodeId,
      publicKeyHex: bytesToHex(adv.signingPublicKey),
      capabilities: adv.capabilities,
      endpoints: adv.endpoints,
      sequence: adv.sequence,
      timestamp: adv.timestamp,
      expiry: adv.expiry,
      nonceHex: bytesToHex(adv.nonce),
      signatureHex: bytesToHex(adv.signature),
    },
    checks: {
      signature: "PASS",
      identityBinding: "PASS",
      timestampValidity: "PASS",
      expiry: "PASS",
      canonicalEncoding: "PASS",
    },
    note: "Sequence floor check is NOT performed here. Use /accept-advertisement to run the full pipeline.",
  });
});

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}
