/**
 * GET /api/sharenet/mesh/status
 * Proxies to the node-link mini-service at ?XTransformPort=<port>.
 * Per the gateway rules: cross-service requests use the XTransformPort query.
 *
 * The dashboard calls this with the port of the node it wants to query
 * (e.g., 3001 for Node A, 3002 for Node B).
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";

export const GET = withErrors(async (req: NextRequest) => {
  const url = new URL(req.url);
  const port = url.searchParams.get("XTransformPort");
  if (!port) return jsonError("XTransformPort query required (e.g. ?XTransformPort=3001)", 400, "BAD_PORT");

  // Forward to the node-link mini-service.
  // We make a server-side fetch to http://localhost:<port>/status.
  const upstream = await fetch(`http://localhost:${port}/status`, {
    signal: AbortSignal.timeout(5000),
  }).catch((e) => ({ error: e.message } as const));

  if ("error" in upstream) {
    return jsonError(`node-link at port ${port} unreachable: ${upstream.error}`, 502, "UPSTREAM_UNREACHABLE");
  }
  const data = await upstream.json();
  return json(data);
});
