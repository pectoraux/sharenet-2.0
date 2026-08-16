/**
 * GET /api/sharenet/mesh/mesh-state
 * Aggregates status + links from ALL known node-link services.
 * The dashboard uses this to render the live mesh visualization.
 *
 * Known nodes: Node A (3001, wire 7788) + Node B (3002, wire 7789).
 * Per spec/00 §37: real independent processes, no shared in-memory graph —
 * so we query each process individually and stitch the view here.
 */

import { json, withErrors } from "@/lib/http/api-helpers";

interface NodeStatus {
  ok: boolean;
  node?: {
    name: string;
    nodeId: string;
    publicKeyHex: string;
    wirePort: number;
    controlPort: number;
  };
  advertisement?: {
    nodeId: string;
    capabilities: string[];
    endpoints: Array<{ type: string; address: string; port: number }>;
    sequence: number;
    timestamp: number;
    expiry: number;
  } | null;
}
interface NodeLinks {
  ok: boolean;
  count?: number;
  links?: Array<{
    linkId: string;
    localNodeId: string;
    remoteNodeId: string;
    remoteEndpoint: string;
    remoteCapabilities: string[];
    state: string;
    createdAt: number;
    stateChangedAt: number;
  }>;
  events?: Array<{ type: string; linkId: string; remoteNodeId?: string; remoteEndpoint?: string; at: number }>;
}

const KNOWN_NODES = [
  { name: "node-a", controlPort: 3001, wirePort: 7788 },
  { name: "node-b", controlPort: 3002, wirePort: 7789 },
];

export const GET = withErrors(async () => {
  const nodes: Array<{
    name: string;
    controlPort: number;
    wirePort: number;
    reachable: boolean;
    status: NodeStatus | null;
    links: NodeLinks | null;
  }> = [];

  for (const known of KNOWN_NODES) {
    const [statusRes, linksRes] = await Promise.allSettled([
      fetch(`http://localhost:${known.controlPort}/status`, { signal: AbortSignal.timeout(3000) }).then((r) => r.json() as Promise<NodeStatus>),
      fetch(`http://localhost:${known.controlPort}/links`, { signal: AbortSignal.timeout(3000) }).then((r) => r.json() as Promise<NodeLinks>),
    ]);
    nodes.push({
      name: known.name,
      controlPort: known.controlPort,
      wirePort: known.wirePort,
      reachable: statusRes.status === "fulfilled",
      status: statusRes.status === "fulfilled" ? statusRes.value : null,
      links: linksRes.status === "fulfilled" ? linksRes.value : null,
    });
  }

  // Derive a list of distinct node identities (dedup by nodeId).
  const nodeMap = new Map<string, { nodeId: string; name: string; publicKeyHex: string; wireEndpoint: string; reachable: boolean }>();
  for (const n of nodes) {
    if (!n.status?.node) continue;
    const nodeId = n.status.node.nodeId;
    if (!nodeMap.has(nodeId)) {
      nodeMap.set(nodeId, {
        nodeId,
        name: n.status.node.name,
        publicKeyHex: n.status.node.publicKeyHex,
        wireEndpoint: `127.0.0.1:${n.wirePort}`,
        reachable: n.reachable,
      });
    }
  }

  // Collect all directed links across all nodes.
  const allLinks: Array<{
    linkId: string;
    localNodeId: string;
    remoteNodeId: string;
    remoteEndpoint: string;
    remoteCapabilities: string[];
    state: string;
    observedFromNode: string;
    createdAt: number;
    stateChangedAt: number;
  }> = [];
  for (const n of nodes) {
    if (!n.links?.links) continue;
    for (const l of n.links.links) {
      allLinks.push({ ...l, observedFromNode: n.name });
    }
  }

  return json({
    ok: true,
    nodes: Array.from(nodeMap.values()),
    links: allLinks,
    nodeProcesses: nodes.map((n) => ({
      name: n.name,
      controlPort: n.controlPort,
      wirePort: n.wirePort,
      reachable: n.reachable,
      nodeId: n.status?.node?.nodeId ?? null,
      eventCount: n.links?.events?.length ?? 0,
      recentEvents: (n.links?.events ?? []).slice(-5),
    })),
    directionalInvariantHolds: (() => {
      // Verify: every LinkId is unique across processes (no two links share an ID).
      const ids = new Set(allLinks.map((l) => l.linkId));
      return ids.size === allLinks.length;
    })(),
  });
});
