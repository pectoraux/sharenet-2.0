/**
 * ShareNet 2.0 — Session service.
 *
 * Per ADR-0012: server-side Session table; HttpOnly cookie; sliding 24h expiry.
 * Account disable invalidates all sessions for that user.
 */

import { db } from "@/lib/db";
import {
  generateSessionToken,
  sessionExpiry,
  isSessionExpired,
  SESSION_COOKIE_NAME,
  DEMO_SESSION_COOKIE_NAME,
} from "./crypto";
import type { Role } from "@prisma/client";

/** Public shape of a session that we attach to API responses / Next.js context. */
export interface SessionContext {
  sessionId: string;
  userId: string;
  email: string;
  name: string | null;
  role: Role;
  isDemo: boolean;
  disabled: boolean;
  expiresAt: Date;
}

/** Cookie names to check (real first, then demo). */
export const SESSION_COOKIE_NAMES = [SESSION_COOKIE_NAME, DEMO_SESSION_COOKIE_NAME] as const;

/**
 * Create a new session for a user. Stores it in the DB and returns the
 * token to set as a cookie. Also records an audit log entry.
 */
export async function createSession(opts: {
  userId: string;
  ip?: string;
  userAgent?: string;
  isDemo?: boolean;
  actorUserId?: string | null; // for audit; if demo login, the real admin who triggered it
}): Promise<{ token: string; session: SessionContext }> {
  const token = generateSessionToken();
  const expiresAt = sessionExpiry();
  const isDemo = opts.isDemo ?? false;

  const session = await db.session.create({
    data: {
      token,
      userId: opts.userId,
      expiresAt,
      lastActivityAt: new Date(),
      ip: opts.ip,
      userAgent: opts.userAgent,
      isDemo,
    },
    include: { user: true },
  });

  await db.auditLog.create({
    data: {
      action: isDemo ? "DEMO_LOGIN" : "LOGIN_SUCCESS",
      actorUserId: opts.actorUserId ?? opts.userId,
      targetUserId: opts.userId,
      ip: opts.ip,
      userAgent: opts.userAgent,
      detail: JSON.stringify({ sessionId: session.id, isDemo }),
    },
  });

  return {
    token,
    session: {
      sessionId: session.id,
      userId: session.userId,
      email: session.user.email,
      name: session.user.name,
      role: session.user.role,
      isDemo: session.isDemo,
      disabled: session.user.disabled,
      expiresAt: session.expiresAt,
    },
  };
}

/**
 * Look up a session by its token. Returns null if not found, expired,
 * or belonging to a disabled user (the disabled-user check enforces
 * spec/00 §11: account disable invalidates sessions).
 */
export async function getSession(token: string): Promise<SessionContext | null> {
  if (!token || token.length < 32) return null;
  const session = await db.session.findUnique({
    where: { token },
    include: { user: true },
  });
  if (!session) return null;
  if (isSessionExpired(session.expiresAt)) {
    // Clean up expired session and record audit event.
    await db.session.delete({ where: { id: session.id } }).catch(() => {});
    await db.auditLog
      .create({
        data: {
          action: "SESSION_EXPIRED",
          targetUserId: session.userId,
          detail: JSON.stringify({ sessionId: session.id }),
        },
      })
      .catch(() => {});
    return null;
  }
  // Account disabled — invalidate all sessions for that user.
  if (session.user.disabled) {
    await db.session.deleteMany({ where: { userId: session.userId } }).catch(() => {});
    return null;
  }
  return {
    sessionId: session.id,
    userId: session.userId,
    email: session.user.email,
    name: session.user.name,
    role: session.user.role,
    isDemo: session.isDemo,
    disabled: session.user.disabled,
    expiresAt: session.expiresAt,
  };
}

/**
 * Touch a session's lastActivityAt for sliding expiry. Cheap update —
 * does not audit (auditing every page-load would be excessive).
 */
export async function touchSession(sessionId: string, expiresAt: Date): Promise<void> {
  await db.session
    .update({
      where: { id: sessionId },
      data: { lastActivityAt: new Date(), expiresAt },
    })
    .catch(() => {});
}

/**
 * Destroy a session by token (logout). Records an audit entry.
 */
export async function destroySession(token: string, ip?: string, userAgent?: string): Promise<void> {
  const session = await db.session.findUnique({ where: { token } });
  if (!session) return;
  await db.session.delete({ where: { id: session.id } }).catch(() => {});
  await db.auditLog.create({
    data: {
      action: "LOGOUT",
      actorUserId: session.userId,
      targetUserId: session.userId,
      ip,
      userAgent,
      detail: JSON.stringify({ sessionId: session.id }),
    },
  });
}

/** Invalidate all sessions for a user (used on account disable). */
export async function invalidateAllUserSessions(userId: string): Promise<number> {
  const result = await db.session.deleteMany({ where: { userId } });
  return result.count;
}
