/**
 * POST /api/sharenet/protocol/sign-advertisement
 * Builds and signs a NodeAdvertisement from inputs.
 *
 * The caller supplies the secret key (hex). The server computes the
 * public key, derives the NodeId, builds the canonical CBOR body, signs it,
 * and returns the full advertisement (hex + decoded fields).
 *
 * This endpoint exists for the protocol playground UI. Real nodes sign
 * their own advertisements locally and never transmit their secret key.
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import {
  keypairFromSecretKey,
  bytesToHex,
  hexToBytes,
  randomBytes,
  type NodeCapability,
} from "@reference/identity/keys";
import {
  signAdvertisement,
  advertisementToHex,
  type NodeEndpoint,
  ALL_CAPABILITIES,
} from "@reference/advertisement/advertisement";

export const POST = withErrors(async (req: NextRequest) => {
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const secretKeyHex = String(body.secretKeyHex ?? "");
  const capabilities = Array.isArray(body.capabilities) ? body.capabilities.map(String) : [];
  const endpointsRaw = Array.isArray(body.endpoints) ? body.endpoints : [];
  const ttlSeconds = Math.min(Math.max(parseInt(body.ttlSeconds ?? "3600", 10) || 3600, 60), 86400);

  if (!secretKeyHex || secretKeyHex.length !== 64) {
    return jsonError("secretKeyHex must be 64 hex chars (32 bytes)", 400, "BAD_SECRET");
  }
  if (capabilities.length === 0) {
    return jsonError("at least one capability required", 400, "BAD_CAPABILITIES");
  }
  for (const cap of capabilities) {
    if (!ALL_CAPABILITIES.includes(cap as NodeCapability)) {
      return jsonError(`invalid capability: ${cap}`, 400, "BAD_CAPABILITY");
    }
  }
  const endpoints: NodeEndpoint[] = endpointsRaw.slice(0, 8).map((e: unknown) => {
    const obj = e as Record<string, unknown>;
    return {
      type: String(obj.type ?? "tcp") as NodeEndpoint["type"],
      address: String(obj.address ?? "").slice(0, 200),
      port: Math.min(Math.max(parseInt(String(obj.port ?? "0"), 10) || 0, 1), 65535),
    };
  });

  let kp;
  try {
    kp = keypairFromSecretKey(hexToBytes(secretKeyHex));
  } catch (e) {
    return jsonError(`invalid secret key: ${(e as Error).message}`, 400, "BAD_SECRET");
  }

  const now = Math.floor(Date.now() / 1000);
  const adv = signAdvertisement(
    {
      protocolVersion: 1,
      nodeId: kp.nodeId,
      signingPublicKey: kp.publicKey,
      capabilities: capabilities as NodeCapability[],
      endpoints,
      sequence: parseInt(body.sequence ?? "1", 10) || 1,
      timestamp: now,
      expiry: now + ttlSeconds,
      nonce: randomBytes(16),
    },
    kp.secretKey,
  );

  return json({
    ok: true,
    advertisementHex: advertisementToHex(adv),
    fields: {
      protocolVersion: adv.protocolVersion,
      nodeId: adv.nodeId,
      publicKeyHex: bytesToHex(adv.signingPublicKey),
      capabilities: adv.capabilities,
      endpoints: adv.endpoints,
      sequence: adv.sequence,
      timestamp: adv.timestamp,
      expiry: adv.expiry,
      ttlSeconds: adv.expiry - adv.timestamp,
      nonceHex: bytesToHex(adv.nonce),
      signatureHex: bytesToHex(adv.signature),
    },
  });
});
