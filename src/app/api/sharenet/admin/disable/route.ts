/**
 * POST /api/sharenet/admin/disable
 * Real-admin-only. Disables a user account and invalidates all sessions.
 * Per spec/00 §11 + ADR-0012.
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { db } from "@/lib/db";
import { invalidateAllUserSessions } from "@/lib/auth/session";

export const POST = withErrors(async (req: NextRequest) => {
  const session = await requireRealAdmin();
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const userId = String(body.userId ?? "");
  if (!userId) return jsonError("userId required", 400, "BAD_ID");
  if (userId === session.userId) return jsonError("cannot disable your own account", 400, "SELF_DISABLE");

  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user) return jsonError("user not found", 404, "NOT_FOUND");
  if (user.isDemo) return jsonError("cannot disable demo accounts via this endpoint", 400, "DEMO_ACCOUNT");

  await db.user.update({
    where: { id: userId },
    data: { disabled: true, disabledAt: new Date(), disabledById: session.userId },
  });
  const invalidated = await invalidateAllUserSessions(userId);

  await db.auditLog.create({
    data: {
      action: "ACCOUNT_DISABLED",
      actorUserId: session.userId,
      targetUserId: userId,
      targetEmail: user.email,
      detail: JSON.stringify({ invalidatedSessions: invalidated }),
    },
  });

  return json({ ok: true, userId, disabled: true, invalidatedSessions: invalidated });
});
