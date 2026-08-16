/**
 * POST /api/sharenet/waitlist/review
 * Admin-only. Approve or reject a waitlist entry. Approve moves it to
 * APPROVED status; reject moves to REJECTED. Account creation is a
 * separate explicit step (/waitlist/create-account) per spec/00 §7
 * "ADMIN REVIEW → ACCOUNT CREATION → USER MAY LOGIN".
 */

import { NextRequest } from "next/server";
import { json, jsonError, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { db } from "@/lib/db";

export const POST = withErrors(async (req: NextRequest) => {
  const session = await requireRealAdmin();
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const waitlistId = String(body.waitlistId ?? "");
  const decision = String(body.decision ?? ""); // "APPROVE" | "REJECT" | "INVITE"
  const notes = body.notes ? String(body.notes).slice(0, 2000) : null;

  if (!waitlistId) return jsonError("waitlistId required", 400, "BAD_ID");
  if (!["APPROVE", "REJECT", "INVITE"].includes(decision)) {
    return jsonError("decision must be APPROVE | REJECT | INVITE", 400, "BAD_DECISION");
  }

  const entry = await db.waitlistEntry.findUnique({ where: { id: waitlistId } });
  if (!entry) return jsonError("waitlist entry not found", 404, "NOT_FOUND");

  const newStatus = decision === "APPROVE" ? "APPROVED" : decision === "REJECT" ? "REJECTED" : "INVITED";
  const auditAction = decision === "APPROVE" ? "WAITLIST_APPROVED" : decision === "REJECT" ? "WAITLIST_REJECTED" : "WAITLIST_INVITED";

  await db.waitlistEntry.update({
    where: { id: entry.id },
    data: {
      status: newStatus,
      reviewedAt: new Date(),
      reviewedById: session.userId,
      notes: notes ?? entry.notes,
    },
  });

  await db.auditLog.create({
    data: {
      action: auditAction,
      actorUserId: session.userId,
      targetEmail: entry.email,
      detail: JSON.stringify({
        waitlistId: entry.id,
        previousStatus: entry.status,
        newStatus,
        notes,
      }),
    },
  });

  return json({ ok: true, waitlistId: entry.id, status: newStatus });
});
