/**
 * GET /api/sharenet/architecture/summary
 * Public read-only summary. Runs the full suite (cheap; pure functions)
 * and returns pass/fail counts + per-test results. Used for the dashboard
 * conformance badge so anonymous visitors can verify the system holds.
 */

import { json, withErrors } from "@/lib/http/api-helpers";
import { runArchitectureTests } from "@/lib/sharenet/architecture-tests";

export const GET = withErrors(async () => {
  const result = await runArchitectureTests();
  return json(result);
});
