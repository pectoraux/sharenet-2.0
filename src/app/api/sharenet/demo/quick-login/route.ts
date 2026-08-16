/**
 * POST /api/sharenet/demo/quick-login
 * Per spec/00 §28 + ADR-0009: demo quick-login issues a demo session cookie.
 * Refuses if ENABLE_DEMO_LOGIN is not truthy. Demo admin is NOT the real admin.
 */

import { NextRequest, NextResponse } from "next/server";
import { json, jsonError, withErrors, getRequestIp, getRequestUserAgent } from "@/lib/http/api-helpers";
import { demoQuickLogin, isDemoLoginEnabled } from "@/lib/auth/demo";
import { sessionCookieOptions } from "@/lib/auth/crypto";

export const POST = withErrors(async (req: NextRequest) => {
  if (!isDemoLoginEnabled()) {
    return jsonError("demo login is disabled", 403, "DEMO_DISABLED");
  }
  const body = await req.json().catch(() => null);
  if (!body) return jsonError("invalid JSON body", 400, "BAD_BODY");
  const slug = String(body.slug ?? "").trim();
  if (!slug) return jsonError("slug required", 400, "BAD_SLUG");
  try {
    const { token, persona } = await demoQuickLogin(slug, {
      ip: getRequestIp(req),
      userAgent: getRequestUserAgent(req),
    });
    const res = NextResponse.json({
      ok: true,
      persona: {
        slug: persona.slug,
        label: persona.label,
        role: persona.role,
      },
      isDemo: true,
    });
    const opts = sessionCookieOptions(true, process.env.NODE_ENV === "production");
    res.cookies.set(opts.name, token, opts);
    return res;
  } catch (e) {
    return jsonError((e as Error).message, 400, "DEMO_LOGIN_FAILED");
  }
});
