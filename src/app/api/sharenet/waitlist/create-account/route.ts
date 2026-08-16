/**
 * POST /api/sharenet/waitlist/create-account
 * Admin-only. Creates a real User account from an APPROVED waitlist entry.
 * Sets the waitlist entry status to ACCOUNT_CREATED.
 * The account is created with a random initial password (admin must
 * communicate it out-of-band OR the user uses password-reset later).
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { db } from "@/lib/db";
import { hashPassword } from "@/lib/auth/crypto";
import { randomBytes } from "@noble/hashes/utils.js";
import { base64url } from "@/lib/auth/crypto";

export const POST = withErrors(async (req: NextRequest) => {
  const session = await requireRealAdmin();
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const waitlistId = String(body.waitlistId ?? "");
  if (!waitlistId) return jsonError("waitlistId required", 400, "BAD_ID");

  const entry = await db.waitlistEntry.findUnique({ where: { id: waitlistId } });
  if (!entry) return jsonError("waitlist entry not found", 404, "NOT_FOUND");
  if (entry.status !== "APPROVED" && entry.status !== "INVITED") {
    return jsonError(`waitlist entry must be APPROVED or INVITED to create account (was ${entry.status})`, 400, "BAD_STATUS");
  }

  // Check no existing user with this email.
  const existing = await db.user.findUnique({ where: { email: entry.email } });
  if (existing) {
    return jsonError("a user with this email already exists", 409, "USER_EXISTS");
  }

  // Generate a random initial password. The admin must communicate this
  // to the new user out-of-band (or trigger password-reset flow).
  const initialPassword = base64url(randomBytes(24));
  const passwordHash = await hashPassword(initialPassword);

  const user = await db.user.create({
    data: {
      email: entry.email,
      name: entry.name,
      passwordHash,
      role: entry.requestedUserType,
      isDemo: false,
    },
  });

  await db.waitlistEntry.update({
    where: { id: entry.id },
    data: {
      status: "ACCOUNT_CREATED",
      createdUserId: user.id,
      reviewedAt: new Date(),
      reviewedById: session.userId,
    },
  });

  await db.auditLog.create({
    data: {
      action: "ACCOUNT_CREATED_FROM_WAITLIST",
      actorUserId: session.userId,
      targetUserId: user.id,
      targetEmail: user.email,
      detail: JSON.stringify({
        waitlistId: entry.id,
        role: user.role,
        note: "initial password generated; admin must communicate out-of-band",
      }),
    },
  });

  return json({
    ok: true,
    userId: user.id,
    email: user.email,
    role: user.role,
    initialPassword, // returned ONLY to the admin who created it; never re-displayed
    message: "account created; communicate the initial password to the user out-of-band",
  });
});
