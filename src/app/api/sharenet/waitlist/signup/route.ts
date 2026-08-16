/**
 * POST /api/sharenet/waitlist/signup
 *
 * Per spec/00 §7: public signup does NOT create an active user account.
 * Creates a PENDING WaitlistEntry. Admin review decides whether to
 * create a User (ACCOUNT_CREATED) or reject.
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors, getRequestIp, getRequestUserAgent } from "@/lib/http/api-helpers";
import { db } from "@/lib/db";
import type { Role } from "@prisma/client";

const VALID_ROLES: Role[] = [
  "USER",
  "RELAY_OPERATOR",
  "GATEWAY_OPERATOR",
  "CONTENT_PROVIDER",
  "STORAGE_PROVIDER",
  "COMPUTE_PROVIDER",
];

export const POST = withErrors(async (req: NextRequest) => {
  const body = await req.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return jsonError("invalid JSON body", 400, "BAD_BODY");
  }
  const email = String(body.email ?? "").trim().toLowerCase();
  const name = body.name ? String(body.name).trim().slice(0, 200) : null;
  const requestedRole = String(body.requestedUserType ?? "USER") as Role;
  const notes = body.notes ? String(body.notes).slice(0, 2000) : null;

  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return jsonError("invalid email", 400, "BAD_EMAIL");
  }
  if (email.length > 320) {
    return jsonError("email too long", 400, "BAD_EMAIL");
  }
  if (!VALID_ROLES.includes(requestedRole)) {
    return jsonError(`invalid requestedUserType: ${requestedRole}`, 400, "BAD_ROLE");
  }

  // Idempotent: if a waitlist entry already exists for this email, return
  // "already pending" rather than leaking existence via 409.
  const existing = await db.waitlistEntry.findUnique({ where: { email } });
  if (existing) {
    return json({
      ok: true,
      status: existing.status,
      alreadySubmitted: true,
      message: "your waitlist request was already received",
    });
  }

  const entry = await db.waitlistEntry.create({
    data: { email, name, requestedUserType: requestedRole, status: "PENDING", notes },
  });

  await db.auditLog.create({
    data: {
      action: "WAITLIST_SUBMITTED",
      targetEmail: email,
      ip: getRequestIp(req),
      userAgent: getRequestUserAgent(req),
      detail: JSON.stringify({
        waitlistId: entry.id,
        requestedUserType: requestedRole,
        name,
      }),
    },
  });

  return json({
    ok: true,
    waitlistId: entry.id,
    status: entry.status,
    message: "your request has been added to the waitlist; an administrator will review it",
  });
});
