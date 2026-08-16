/**
 * ShareNet 2.0 — Auth helpers for Next.js API routes.
 *
 * Reads the session cookie, looks up the session, returns a SessionContext
 * or null. Also provides role-gating helpers.
 */

import { cookies } from "next/headers";
import { getSession, touchSession, type SessionContext, SESSION_COOKIE_NAMES } from "./session";
import { sessionExpiry } from "./crypto";

/** Read the session token from the request cookies (real or demo). */
export async function readSessionToken(): Promise<string | null> {
  const store = await cookies();
  for (const name of SESSION_COOKIE_NAMES) {
    const c = store.get(name);
    if (c?.value) return c.value;
  }
  return null;
}

/** Get the current session, if any. Auto-touches sliding expiry. */
export async function getCurrentSession(): Promise<SessionContext | null> {
  const token = await readSessionToken();
  if (!token) return null;
  const session = await getSession(token);
  if (!session) return null;
  // Sliding expiry: extend the session on each authenticated request.
  await touchSession(session.sessionId, sessionExpiry());
  return session;
}

/** Require an authenticated session. Throws a structured error if missing. */
export async function requireSession(): Promise<SessionContext> {
  const session = await getCurrentSession();
  if (!session) {
    throw new AuthError("UNAUTHORIZED", "authentication required");
  }
  return session;
}

/** Require a session with one of the given roles. */
export async function requireRole(...roles: SessionContext["role"][]): Promise<SessionContext> {
  const session = await requireSession();
  if (!roles.includes(session.role)) {
    throw new AuthError("FORBIDDEN", `role ${session.role} not permitted; required one of: ${roles.join(", ")}`);
  }
  return session;
}

/** Require the admin role specifically. */
export async function requireAdmin(): Promise<SessionContext> {
  return requireRole("ADMIN");
}

/** Require a non-demo session. Demo accounts cannot perform real mutations. */
export async function requireRealSession(): Promise<SessionContext> {
  const session = await requireSession();
  if (session.isDemo) {
    throw new AuthError("FORBIDDEN", "demo accounts cannot perform this action");
  }
  return session;
}

/** Require admin AND non-demo. Demo admin is NOT the real admin (ADR-0009). */
export async function requireRealAdmin(): Promise<SessionContext> {
  const session = await requireAdmin();
  if (session.isDemo) {
    throw new AuthError("FORBIDDEN", "demo admin cannot perform real administrative actions (ADR-0009)");
  }
  return session;
}

/** Structured auth error with a code suitable for HTTP response mapping. */
export class AuthError extends Error {
  constructor(
    public code: "UNAUTHORIZED" | "FORBIDDEN" | "BAD_REQUEST" | "NOT_FOUND" | "CONFLICT",
    message: string,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

/** Map an AuthError to an HTTP status code. */
export function authErrorStatus(err: AuthError): number {
  switch (err.code) {
    case "UNAUTHORIZED":
      return 401;
    case "FORBIDDEN":
      return 403;
    case "BAD_REQUEST":
      return 400;
    case "NOT_FOUND":
      return 404;
    case "CONFLICT":
      return 409;
  }
}
