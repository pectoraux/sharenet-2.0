/**
 * ShareNet 2.0 — Shared API route helpers.
 *
 * Provides a typed JSON-response wrapper and an error-to-status mapper so
 * route handlers stay tiny and consistent.
 */

import { NextResponse, type NextRequest } from "next/server";
import { AuthError, authErrorStatus } from "@/lib/auth/api";

/** Standard JSON success response. */
export function json<T>(body: T, status = 200): NextResponse {
  return NextResponse.json(body, { status });
}

/** Standard JSON error response. */
export function jsonError(message: string, status: number, code?: string, detail?: unknown): NextResponse {
  return NextResponse.json({ error: message, code, detail }, { status });
}

/**
 * Wrap a route handler with try/catch that maps AuthError → HTTP status
 * and surfaces other errors as 500.
 */
export function withErrors<TArgs extends unknown[]>(
  fn: (...args: TArgs) => Promise<NextResponse>,
): (...args: TArgs) => Promise<NextResponse> {
  return async (...args) => {
    try {
      return await fn(...args);
    } catch (e) {
      if (e instanceof AuthError) {
        return jsonError(e.message, authErrorStatus(e), e.code);
      }
      console.error("[api] unhandled error:", e);
      const msg = e instanceof Error ? e.message : "internal error";
      return jsonError(msg, 500, "INTERNAL");
    }
  };
}

/** Extract a request IP from common headers. */
export function getRequestIp(req: NextRequest): string | undefined {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0]?.trim();
  const xri = req.headers.get("x-real-ip");
  if (xri) return xri.trim();
  return undefined;
}

/** Get the user-agent header. */
export function getRequestUserAgent(req: NextRequest): string | undefined {
  return req.headers.get("user-agent") ?? undefined;
}
