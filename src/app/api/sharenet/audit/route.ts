/**
 * GET /api/sharenet/audit
 * Real-admin-only. Returns recent audit log entries.
 */

import { NextRequest } from "next/server";
import { json, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { db } from "@/lib/db";

export const GET = withErrors(async (req: NextRequest) => {
  await requireRealAdmin();
  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "100", 10) || 100, 500);
  const entries = await db.auditLog.findMany({
    orderBy: { createdAt: "desc" },
    take: limit,
    include: { actorUser: { select: { email: true, name: true, isDemo: true } } },
  });
  return json({
    ok: true,
    count: entries.length,
    entries: entries.map((e) => ({
      id: e.id,
      action: e.action,
      actorUserId: e.actorUserId,
      actor: e.actorUser ? { email: e.actorUser.email, name: e.actorUser.name, isDemo: e.actorUser.isDemo } : null,
      targetUserId: e.targetUserId,
      targetEmail: e.targetEmail,
      targetNodeId: e.targetNodeId,
      detail: e.detail,
      ip: e.ip,
      userAgent: e.userAgent,
      createdAt: e.createdAt,
    })),
  });
});
