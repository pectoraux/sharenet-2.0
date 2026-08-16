/**
 * POST /api/sharenet/admin/role
 * Real-admin-only. Changes a user's role.
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { db } from "@/lib/db";
import type { Role } from "@prisma/client";

const VALID_ROLES: Role[] = [
  "USER", "RELAY_OPERATOR", "GATEWAY_OPERATOR",
  "CONTENT_PROVIDER", "STORAGE_PROVIDER", "COMPUTE_PROVIDER", "ADMIN",
];

export const POST = withErrors(async (req: NextRequest) => {
  const session = await requireRealAdmin();
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const userId = String(body.userId ?? "");
  const newRole = String(body.role ?? "") as Role;
  if (!userId) return jsonError("userId required", 400, "BAD_ID");
  if (!VALID_ROLES.includes(newRole)) return jsonError(`invalid role: ${newRole}`, 400, "BAD_ROLE");

  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user) return jsonError("user not found", 404, "NOT_FOUND");
  if (user.isDemo) return jsonError("cannot change demo account roles", 400, "DEMO_ACCOUNT");
  if (user.id === session.userId && newRole !== "ADMIN") {
    return jsonError("admins cannot demote themselves", 400, "SELF_DEMOTE");
  }

  const previousRole = user.role;
  await db.user.update({ where: { id: userId }, data: { role: newRole } });

  await db.auditLog.create({
    data: {
      action: "ROLE_CHANGED",
      actorUserId: session.userId,
      targetUserId: userId,
      targetEmail: user.email,
      detail: JSON.stringify({ previousRole, newRole }),
    },
  });

  return json({ ok: true, userId, previousRole, newRole });
});
