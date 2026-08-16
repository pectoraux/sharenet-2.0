/**
 * POST /api/sharenet/protocol/gateway-policy
 * Evaluates the gateway policy stub (ADR-0011).
 * Runs ALL spec/09 §3 guards. Returns ALLOW/DENY + reason + guard.
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import { requireSession } from "@/lib/auth/api";
import { evaluateGatewayPolicy } from "@/lib/sharenet/gateway";
import { db } from "@/lib/db";

export const POST = withErrors(async (req: NextRequest) => {
  const session = await requireSession();
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const gatewayNodeId = String(body.gatewayNodeId ?? "");
  const peerNodeId = String(body.peerNodeId ?? "");
  const destination = String(body.destination ?? "");
  if (!gatewayNodeId || !peerNodeId || !destination) {
    return jsonError("gatewayNodeId, peerNodeId, destination required", 400, "BAD_INPUT");
  }

  // Ensure a GatewayPolicy row exists for this gateway (secure defaults).
  // Use findFirst + create-if-missing since (gatewayNodeId) is not unique-indexed.
  const existing = await db.gatewayPolicy.findFirst({ where: { gatewayNodeId } });
  if (!existing) {
    await db.gatewayPolicy.create({
      data: {
        gatewayNodeId,
        // Empty allowedDestinationsJson would mean "deny all" — the secure default.
        // For the playground, default-allow example.com + *.sharenet.local so the
        // user can see ALLOW decisions without configuring a policy first.
        allowedDestinationsJson: body.allowedDestinations
          ? JSON.stringify(body.allowedDestinations)
          : JSON.stringify(["example.com", "*.sharenet.local"]),
      },
    });
  } else if (body.allowedDestinations) {
    await db.gatewayPolicy.update({
      where: { id: existing.id },
      data: { allowedDestinationsJson: JSON.stringify(body.allowedDestinations) },
    });
  }

  const result = await evaluateGatewayPolicy({
    gatewayNodeId,
    peerNodeId,
    destination,
  });

  return json({
    ok: true,
    actor: { userId: session.userId, isDemo: session.isDemo },
    result,
    guards: [
      "ENABLED",
      "DESTINATION_POLICY",
      "PRIVATE_ADDRESS",
      "LOOPBACK",
      "LINK_LOCAL",
      "SSRF",
      "PER_PEER_QUOTA",
      "GLOBAL_QUOTA",
      "RATE_LIMIT",
      "REVOKED_PEER",
      "BANDWIDTH_SHAPING",
    ],
    note: "Per ADR-0011 the gateway stub enforces all guards but does NOT yet forward to the real Internet. Forwarding is Phase 8.",
  });
});
