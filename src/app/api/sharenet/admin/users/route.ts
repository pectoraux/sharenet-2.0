/**
 * GET /api/sharenet/admin/users
 * Admin-only. Lists real (non-demo) user accounts.
 */

import { NextRequest } from "next/server";
import { json, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { db } from "@/lib/db";

export const GET = withErrors(async (req: NextRequest) => {
  await requireRealAdmin();
  const url = new URL(req.url);
  const includeDemo = url.searchParams.get("includeDemo") === "1";
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "100", 10) || 100, 500);

  const users = await db.user.findMany({
    where: includeDemo ? undefined : { isDemo: false },
    orderBy: { createdAt: "desc" },
    take: limit,
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      disabled: true,
      isDemo: true,
      createdAt: true,
      updatedAt: true,
      disabledAt: true,
    },
  });

  return json({
    ok: true,
    count: users.length,
    users,
  });
});
