/**
 * POST /api/sharenet/mesh/dial?XTransformPort=<port>
 * Proxies the /dial endpoint of a node-link mini-service.
 * Body: { host, port, expectedNodeId? }
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";

export const POST = withErrors(async (req: NextRequest) => {
  const url = new URL(req.url);
  const port = url.searchParams.get("XTransformPort");
  if (!port) return jsonError("XTransformPort query required (the dialing node's control port)", 400, "BAD_PORT");
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body { host, port, expectedNodeId? }", 400, "BAD_BODY");

  const upstream = await fetch(`http://localhost:${port}/dial`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  }).catch((e) => ({ error: e.message } as const));
  if ("error" in upstream) {
    return jsonError(`node-link at port ${port} unreachable: ${upstream.error}`, 502, "UPSTREAM_UNREACHABLE");
  }
  const data = await upstream.json();
  return json(data);
});
