/**
 * ShareNet 2.0 — Demo account system.
 *
 * Per spec/00 §10, §28 and ADR-0009:
 *   - Demo accounts are isolated from real accounts (User.isDemo = true).
 *   - Demo quick-login uses a SEPARATE cookie `sharenet_demo_session`.
 *   - Demo admin is NOT the real admin bootstrap account.
 *   - `ENABLE_DEMO_LOGIN` env flag gates the entire demo login surface
 *     (default false in production, true in sandbox).
 *   - Demo accounts cannot mutate real waitlist or real audit log entries.
 */

import { db } from "@/lib/db";
import { hashPassword } from "./crypto";
import { createSession } from "./session";
import type { Role } from "@prisma/client";

/** Env flag that gates demo quick-login. Default: enabled in dev, disabled in prod. */
export function isDemoLoginEnabled(): boolean {
  const v = process.env.ENABLE_DEMO_LOGIN;
  if (v === undefined) {
    // Default: enabled in non-production (sandbox-friendly).
    return process.env.NODE_ENV !== "production";
  }
  return v === "1" || v.toLowerCase() === "true";
}

/** Definition of a demo persona. */
export interface DemoPersona {
  slug: string;
  label: string;
  description: string;
  role: Role;
  sortOrder: number;
}

/** The canonical demo personas. Order matches spec/00 §28. */
export const DEMO_PERSONAS: readonly DemoPersona[] = [
  {
    slug: "user",
    label: "Demo User",
    description: "A regular ShareNet participant. Can join waitlist, view public dashboard, browse the spec.",
    role: "USER",
    sortOrder: 0,
  },
  {
    slug: "relay-operator",
    label: "Demo Relay Operator",
    description: "Operates a MESH_RELAY node. Can inspect their own node advertisement and sequence floor.",
    role: "RELAY_OPERATOR",
    sortOrder: 1,
  },
  {
    slug: "gateway-operator",
    label: "Demo Gateway Operator",
    description: "Operates an INTERNET_GATEWAY node. Can inspect gateway policy + guard decisions.",
    role: "GATEWAY_OPERATOR",
    sortOrder: 2,
  },
  {
    slug: "content-provider",
    label: "Demo Content Provider",
    description: "Seeds CONTENT_SEED content into the mesh.",
    role: "CONTENT_PROVIDER",
    sortOrder: 3,
  },
  {
    slug: "storage-provider",
    label: "Demo Storage Provider",
    description: "Offers STORAGE capacity on their node.",
    role: "STORAGE_PROVIDER",
    sortOrder: 4,
  },
  {
    slug: "compute-provider",
    label: "Demo Compute Provider",
    description: "Offers COMPUTE capacity on their node.",
    role: "COMPUTE_PROVIDER",
    sortOrder: 5,
  },
  {
    slug: "admin",
    label: "Demo Admin",
    description: "Demo-only administrator. Can review the DEMO waitlist only. Is NOT the real admin bootstrap account (ADR-0009).",
    role: "ADMIN",
    sortOrder: 6,
  },
];

/** Email convention for demo accounts. */
export function demoEmail(slug: string): string {
  return `demo-${slug}@demo.sharenet.local`;
}

/**
 * Ensure all demo personas exist in the database. Idempotent: safe to call
 * on every server boot. Creates demo User rows (with isDemo=true) and
 * DemoAccount registry entries. Demo passwords are random per boot and
 * never exposed — login is via the quick-login endpoint.
 */
export async function ensureDemoAccounts(): Promise<void> {
  for (const persona of DEMO_PERSONAS) {
    const email = demoEmail(persona.slug);
    let user = await db.user.findUnique({ where: { email }, include: { demoAccount: true } });
    if (!user) {
      // Create with a random password that nobody knows. Quick-login bypasses
      // the password check by directly issuing a session for the demo user.
      const randomPasswordHash = await hashPassword(
        `nobody-knows-this-${Math.random().toString(36).slice(2)}-${Date.now()}`,
      );
      user = await db.user.create({
        data: {
          email,
          name: persona.label,
          passwordHash: randomPasswordHash,
          role: persona.role,
          isDemo: true,
          demoAccount: {
            create: {
              slug: persona.slug,
              label: persona.label,
              description: persona.description,
              role: persona.role,
              sortOrder: persona.sortOrder,
            },
          },
        },
        include: { demoAccount: true },
      });
    } else {
      // Ensure role is up-to-date if the persona definition changed.
      if (user.role !== persona.role || !user.demoAccount) {
        await db.user.update({ where: { id: user.id }, data: { role: persona.role } });
        if (!user.demoAccount) {
          await db.demoAccount.create({
            data: {
              slug: persona.slug,
              label: persona.label,
              description: persona.description,
              role: persona.role,
              sortOrder: persona.sortOrder,
              userId: user.id,
            },
          });
        } else {
          await db.demoAccount.update({
            where: { slug: persona.slug },
            data: {
              label: persona.label,
              description: persona.description,
              role: persona.role,
              sortOrder: persona.sortOrder,
            },
          });
        }
      }
    }
  }
}

/**
 * Quick-login a demo persona by slug. Returns a session token + context.
 *
 * The session is marked isDemo=true so the API layer can refuse real
 * mutations. Per ADR-0009, demo sessions use a separate cookie name.
 *
 * Throws if demo login is disabled (ENABLE_DEMO_LOGIN=0) or if the slug
 * does not match a known persona.
 */
export async function demoQuickLogin(
  slug: string,
  opts: { ip?: string; userAgent?: string } = {},
): Promise<{ token: string; persona: DemoPersona }> {
  if (!isDemoLoginEnabled()) {
    throw new Error("demo login is disabled (ENABLE_DEMO_LOGIN is not truthy)");
  }
  const persona = DEMO_PERSONAS.find((p) => p.slug === slug);
  if (!persona) {
    throw new Error(`unknown demo persona: ${slug}`);
  }
  const email = demoEmail(persona.slug);
  const user = await db.user.findUnique({ where: { email } });
  if (!user) {
    // ensureDemoAccounts may not have run yet. Run it and retry.
    await ensureDemoAccounts();
  }
  const userRow = await db.user.findUnique({ where: { email } });
  if (!userRow) {
    throw new Error(`demo persona user not found after ensure: ${slug}`);
  }
  const { token, session } = await createSession({
    userId: userRow.id,
    ip: opts.ip,
    userAgent: opts.userAgent,
    isDemo: true,
    actorUserId: null, // self-issued demo login
  });
  return { token, persona };
}

/** List all demo personas with their backing User ids. */
export async function listDemoAccounts(): Promise<
  Array<{ persona: DemoPersona; userId: string | null }>
> {
  const result: Array<{ persona: DemoPersona; userId: string | null }> = [];
  for (const persona of DEMO_PERSONAS) {
    const user = await db.user.findUnique({ where: { email: demoEmail(persona.slug) } });
    result.push({ persona, userId: user?.id ?? null });
  }
  return result;
}
