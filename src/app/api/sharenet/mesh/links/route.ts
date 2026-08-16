/**
 * GET /api/sharenet/mesh/links?XTransformPort=<port>
 * Proxies the /links endpoint of a node-link mini-service.
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";

export const GET = withErrors(async (req: NextRequest) => {
  const url = new URL(req.url);
  const port = url.searchParams.get("XTransformPort");
  if (!port) return jsonError("XTransformPort query required", 400, "BAD_PORT");
  const upstream = await fetch(`http://localhost:${port}/links`, {
    signal: AbortSignal.timeout(5000),
  }).catch((e) => ({ error: e.message } as const));
  if ("error" in upstream) {
    return jsonError(`node-link at port ${port} unreachable: ${upstream.error}`, 502, "UPSTREAM_UNREACHABLE");
  }
  const data = await upstream.json();
  return json(data);
});
