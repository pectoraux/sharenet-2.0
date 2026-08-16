/**
 * POST /api/sharenet/architecture/run
 * Runs the architecture regression test suite. Real-admin-only (auditable).
 */

import { json, withErrors } from "@/lib/http/api-helpers";
import { requireRealAdmin } from "@/lib/auth/api";
import { runArchitectureTests } from "@/lib/sharenet/architecture-tests";
import { db } from "@/lib/db";

export const POST = withErrors(async () => {
  const session = await requireRealAdmin();
  const result = await runArchitectureTests();
  await db.auditLog.create({
    data: {
      action: "ARCHITECTURE_TEST_RUN",
      actorUserId: session.userId,
      detail: JSON.stringify({
        total: result.totalTests,
        passed: result.passed,
        failed: result.failed,
        durationMs: result.durationMs,
      }),
    },
  });
  return json(result);
});
