/**
 * POST /api/sharenet/auth/login
 *
 * Authenticates a real (non-demo) user. Issues a session cookie.
 * Per ADR-0012: server-side Session table; HttpOnly; SameSite=Lax; Secure in prod.
 */

import { NextRequest, NextResponse } from "next/server";
import { json, jsonError, withErrors, getRequestIp, getRequestUserAgent } from "@/lib/http/api-helpers";
import { db } from "@/lib/db";
import { verifyPassword, hashPassword } from "@/lib/auth/crypto";
import { createSession } from "@/lib/auth/session";
import { sessionCookieOptions, SESSION_COOKIE_NAME } from "@/lib/auth/crypto";
import { ensureDemoAccounts } from "@/lib/auth/demo";

export const POST = withErrors(async (req: NextRequest) => {
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const email = String(body.email ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  if (!email || !password) return jsonError("email and password required", 400, "BAD_CREDENTIALS");

  // Bootstrap: if ADMIN_BOOTSTRAP_USERNAME / ADMIN_BOOTSTRAP_PASSWORD envs are set
  // and the email matches, create the real admin account on first login.
  // Per spec/00 §8: the real admin is provisioned from env secrets, NOT hard-coded.
  const bootstrapEmail = process.env.ADMIN_BOOTSTRAP_USERNAME;
  const bootstrapPassword = process.env.ADMIN_BOOTSTRAP_PASSWORD;
  if (
    bootstrapEmail &&
    bootstrapPassword &&
    email === bootstrapEmail.toLowerCase()
  ) {
    let admin = await db.user.findUnique({ where: { email } });
    if (!admin) {
      const passwordHash = await hashPassword(bootstrapPassword);
      admin = await db.user.create({
        data: {
          email,
          name: "Bootstrap Administrator",
          passwordHash,
          role: "ADMIN",
          isDemo: false,
        },
      });
    } else if (admin.role !== "ADMIN") {
      admin = await db.user.update({ where: { id: admin.id }, data: { role: "ADMIN", isDemo: false } });
    }
    // Fall through to password verification below.
  }

  const user = await db.user.findUnique({ where: { email } });
  if (!user || user.isDemo) {
    // Demo accounts cannot authenticate via this endpoint — they use quick-login.
    await db.auditLog.create({
      data: {
        action: "LOGIN_FAILURE",
        targetEmail: email,
        ip: getRequestIp(req),
        userAgent: getRequestUserAgent(req),
        detail: JSON.stringify({ reason: user ? "demo-account-via-login" : "no-user" }),
      },
    });
    return jsonError("invalid credentials", 401, "INVALID_CREDENTIALS");
  }
  if (user.disabled) {
    await db.auditLog.create({
      data: {
        action: "LOGIN_FAILURE",
        targetUserId: user.id,
        targetEmail: email,
        ip: getRequestIp(req),
        userAgent: getRequestUserAgent(req),
        detail: JSON.stringify({ reason: "account-disabled" }),
      },
    });
    return jsonError("account disabled", 403, "ACCOUNT_DISABLED");
  }
  const passwordOk = await verifyPassword(password, user.passwordHash);
  if (!passwordOk) {
    await db.auditLog.create({
      data: {
        action: "LOGIN_FAILURE",
        targetUserId: user.id,
        targetEmail: email,
        ip: getRequestIp(req),
        userAgent: getRequestUserAgent(req),
        detail: JSON.stringify({ reason: "bad-password" }),
      },
    });
    return jsonError("invalid credentials", 401, "INVALID_CREDENTIALS");
  }

  const { token, session } = await createSession({
    userId: user.id,
    ip: getRequestIp(req),
    userAgent: getRequestUserAgent(req),
    isDemo: false,
  });

  const res = NextResponse.json({
    ok: true,
    session: {
      userId: session.userId,
      email: session.email,
      name: session.name,
      role: session.role,
      isDemo: session.isDemo,
    },
  });
  const opts = sessionCookieOptions(false, process.env.NODE_ENV === "production");
  res.cookies.set(opts.name, token, opts);
  return res;
});

/** Ensure demo accounts exist on every cold start. Cheap and idempotent. */
export async function GET() {
  await ensureDemoAccounts();
  return NextResponse.json({ ok: true, message: "demo accounts ensured" });
}
