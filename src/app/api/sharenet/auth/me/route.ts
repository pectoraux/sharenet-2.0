/**
 * GET /api/sharenet/auth/me
 * Returns the current session, if any. Also runs ensureDemoAccounts on cold start.
 */

import { json, withErrors } from "@/lib/http/api-helpers";
import { getCurrentSession } from "@/lib/auth/api";
import { ensureDemoAccounts } from "@/lib/auth/demo";

export const GET = withErrors(async () => {
  // Cheap + idempotent — runs on every /me call so demo accounts are always available.
  await ensureDemoAccounts().catch(() => {});
  const session = await getCurrentSession();
  if (!session) {
    return json({ ok: true, session: null });
  }
  return json({
    ok: true,
    session: {
      userId: session.userId,
      email: session.email,
      name: session.name,
      role: session.role,
      isDemo: session.isDemo,
      expiresAt: session.expiresAt,
    },
  });
});
