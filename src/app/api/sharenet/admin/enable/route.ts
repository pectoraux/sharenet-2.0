/**
 * POST /api/sharenet/admin/enable
 * Real-admin-only. Re-enables a previously-disabled account.
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { db } from "@/lib/db";

export const POST = withErrors(async (req: NextRequest) => {
  const session = await requireRealAdmin();
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const userId = String(body.userId ?? "");
  if (!userId) return jsonError("userId required", 400, "BAD_ID");

  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user) return jsonError("user not found", 404, "NOT_FOUND");

  await db.user.update({
    where: { id: userId },
    data: { disabled: false, disabledAt: null, disabledById: session.userId },
  });

  await db.auditLog.create({
    data: {
      action: "ACCOUNT_ENABLED",
      actorUserId: session.userId,
      targetUserId: userId,
      targetEmail: user.email,
    },
  });

  return json({ ok: true, userId, disabled: false });
});
