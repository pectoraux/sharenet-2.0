/**
 * GET /api/sharenet/waitlist/list
 * Admin-only. Lists waitlist entries (default: PENDING first).
 * Per ADR-0009, demo admin CANNOT call this (must be real admin).
 */

import { NextRequest } from "next/server";
import { json, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { db } from "@/lib/db";
import type { WaitlistStatus } from "@prisma/client";

export const GET = withErrors(async (req: NextRequest) => {
  await requireRealAdmin();
  const url = new URL(req.url);
  const statusFilter = url.searchParams.get("status") as WaitlistStatus | "ALL" | null;
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "100", 10) || 100, 500);

  const where = statusFilter && statusFilter !== "ALL" ? { status: statusFilter } : undefined;
  const entries = await db.waitlistEntry.findMany({
    where,
    orderBy: [{ status: "asc" }, { createdAt: "desc" }],
    take: limit,
    include: { reviewedBy: { select: { email: true, name: true } } },
  });

  return json({
    ok: true,
    count: entries.length,
    entries: entries.map((e) => ({
      id: e.id,
      email: e.email,
      name: e.name,
      requestedUserType: e.requestedUserType,
      status: e.status,
      notes: e.notes,
      createdAt: e.createdAt,
      reviewedAt: e.reviewedAt,
      reviewedBy: e.reviewedBy ? { email: e.reviewedBy.email, name: e.reviewedBy.name } : null,
    })),
  });
});
