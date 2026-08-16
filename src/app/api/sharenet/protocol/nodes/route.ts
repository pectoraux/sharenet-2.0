/**
 * GET /api/sharenet/protocol/nodes
 * Lists all accepted AuthenticatedNodeRecords.
 * Public (read-only) — demonstrates the live node registry.
 */

import { json, withErrors } from "@/lib/http/api-helpers";
import { listAcceptedNodes } from "@/lib/sharenet/node-record";

export const GET = withErrors(async () => {
  const nodes = await listAcceptedNodes(100);
  return json({
    ok: true,
    count: nodes.length,
    nodes: nodes.map((n) => ({
      nodeId: n.nodeId,
      publicKeyHex: n.publicKeyHex,
      capabilities: n.capabilities,
      sequence: n.sequence,
      acceptedAt: n.acceptedAt,
      firstSeenAt: n.firstSeenAt,
      expiresAt: n.expiresAt,
      expired: n.expiresAt.getTime() < Date.now(),
    })),
  });
});
