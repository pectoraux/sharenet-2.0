/**
 * ShareNet 2.0 — Password hashing, session token, and audit helpers.
 *
 * Per spec/00 §11, spec/14 §5, and ADR-0012:
 *   - bcrypt cost 12 for password hashing. NEVER plaintext.
 *   - 32-byte cryptographically-random session tokens (base64url).
 *   - Server-side Session table; HttpOnly+SameSite=Lax+Secure cookie.
 *   - 24h sliding expiry.
 *   - Account disable invalidates all sessions for that user.
 *   - Audit log records every auth event.
 *
 * Per spec/00 §11: NO passwords in JWT payloads. We use server-side sessions.
 */

import bcrypt from "bcryptjs";
import { randomBytes } from "@noble/hashes/utils.js";

/** bcrypt cost factor. Per ADR-0012. */
export const BCRYPT_COST = 12;

/** Session cookie name for real accounts. */
export const SESSION_COOKIE_NAME = "sharenet_session";

/** Session cookie name for demo accounts (separate namespace, ADR-0009). */
export const DEMO_SESSION_COOKIE_NAME = "sharenet_demo_session";

/** Sliding session expiry in seconds. Per ADR-0012: 24h. */
export const SESSION_EXPIRY_SECONDS = 24 * 60 * 60;

/** Hash a plaintext password using bcrypt. Returns the bcrypt hash string. */
export async function hashPassword(plaintext: string): Promise<string> {
  if (plaintext.length < 8) {
    throw new Error("password too short: minimum 8 characters");
  }
  if (plaintext.length > 1024) {
    throw new Error("password too long: maximum 1024 characters");
  }
  return bcrypt.hash(plaintext, BCRYPT_COST);
}

/** Verify a plaintext password against a bcrypt hash. Constant-time in bcrypt. */
export async function verifyPassword(plaintext: string, hash: string): Promise<boolean> {
  if (!hash || !hash.startsWith("$2")) return false;
  try {
    return await bcrypt.compare(plaintext, hash);
  } catch {
    return false;
  }
}

/**
 * Generate a 32-byte cryptographically-random session token.
 * Returns base64url (no padding) so it is safe in cookies and URLs.
 */
export function generateSessionToken(): string {
  const bytes = randomBytes(32);
  return base64url(bytes);
}

/** base64url encode (no padding) — safe for cookies/URLs. */
export function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Parse a base64url string back to bytes. */
export function parseBase64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Sliding-window expiry: returns a Date `SESSION_EXPIRY_SECONDS` from now. */
export function sessionExpiry(from: Date = new Date()): Date {
  return new Date(from.getTime() + SESSION_EXPIRY_SECONDS * 1000);
}

/** True if a session is past its expiry. */
export function isSessionExpired(expiresAt: Date, now: Date = new Date()): boolean {
  return expiresAt.getTime() <= now.getTime();
}

/** Cookie options for the session cookie. Per ADR-0012. */
export function sessionCookieOptions(isDemo: boolean, isProduction: boolean) {
  return {
    name: isDemo ? DEMO_SESSION_COOKIE_NAME : SESSION_COOKIE_NAME,
    httpOnly: true,
    sameSite: "lax" as const,
    secure: isProduction,
    path: "/",
    maxAge: SESSION_EXPIRY_SECONDS,
  };
}
