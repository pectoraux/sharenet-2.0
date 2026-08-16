/**
 * POST /api/sharenet/auth/logout
 * Destroys the current session.
 */

import { NextResponse } from "next/server";
import { json, withErrors } from "@/lib/http/api-helpers";
import { readSessionToken } from "@/lib/auth/api";
import { destroySession, SESSION_COOKIE_NAMES } from "@/lib/auth/session";

export const POST = withErrors(async () => {
  const token = await readSessionToken();
  if (token) {
    await destroySession(token);
  }
  const res = NextResponse.json({ ok: true });
  for (const name of SESSION_COOKIE_NAMES) {
    res.cookies.set(name, "", { path: "/", maxAge: 0 });
  }
  return res;
});
