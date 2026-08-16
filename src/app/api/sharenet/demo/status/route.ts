/**
 * GET /api/sharenet/demo/status
 * Reports whether demo login is enabled and lists available personas.
 * Per ADR-0009: ENABLE_DEMO_LOGIN gates the surface.
 */

import { json, withErrors } from "@/lib/http/api-helpers";
import { isDemoLoginEnabled, DEMO_PERSONAS } from "@/lib/auth/demo";

export const GET = withErrors(async () => {
  return json({
    ok: true,
    enabled: isDemoLoginEnabled(),
    personas: DEMO_PERSONAS.map((p) => ({
      slug: p.slug,
      label: p.label,
      description: p.description,
      role: p.role,
      sortOrder: p.sortOrder,
    })),
  });
});
