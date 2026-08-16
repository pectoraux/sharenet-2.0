# ADR-0013: Three-Layer Separation — Web Auth / Service / Protocol

**Date:** 2026-08-16
**Status:** Accepted

## Context

The ShareNet 2.0 specification (spec/00 §2, §27) mandates strict identity
separation: a human account is NOT a node identity, and application
authentication must not couple to NodeId. The master prompt (§27) states
explicitly:

> Do not couple application authentication to NodeId.
> A human account is not a node identity.

The waitlist, admin, and demo authentication system is application /
control-plane functionality. It serves the web dashboard and the operator
workflow. It is NOT part of the ShareNet node protocol.

If the protocol layer (or the service layer beneath it) were to import from
the web auth layer, the protocol would silently become dependent on the web
auth system. A non-browser implementation — a Rust node, a Go relay, a C
gateway — could not use the protocol without reimplementing the web auth
system. This would violate spec/00 §2 (Identity separation) and spec/16
(Platform-agnostic protocol core).

The risk is **accidental coupling**: a developer adds a convenient import
(`from "@/lib/auth/session"`) to a service-layer file, the build still
passes, and the violation ships. Code review alone is insufficient per
ADR-0010 — this must be an executable guard.

## Decision

Establish a **three-layer architecture** with strict, machine-enforced import
boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1 — Web Application                                   │
│   src/app/         (routes, pages)                          │
│   src/lib/auth/    (human accounts, sessions, waitlist,    │
│                     admin, demo identities, user roles)      │
│   src/lib/http/    (HTTP response helpers, error mapping)   │
│   src/components/  (UI)                                     │
│                                                             │
│   May import from: Layer 1, Layer 2, Layer 3               │
└───────────────────────────┬─────────────────────────────────┘
                            │ may authorize actions
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2 — Service / Control Plane                          │
│   src/lib/sharenet/                                         │
│     node-record.ts      (AuthenticatedNodeRecord pipeline)  │
│     sequence-floor.ts   (persistent replay protection)      │
│     gateway.ts          (gateway policy + guard layer)     │
│     architecture-tests.ts (forbidden-pipeline guards)      │
│                                                             │
│   May import from: Layer 2, Layer 3, @/lib/db (persistence)│
│   MUST NOT import from: @/lib/auth/, @/lib/http/            │
└───────────────────────────┬─────────────────────────────────┘
                            │ uses protocol primitives
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3 — Protocol Core (reference/)                        │
│   encoding/cbor.ts          (canonical CBOR)                │
│   identity/keys.ts          (Ed25519 + NodeId derivation)   │
│   advertisement/            (NodeAdvertisement sign/verify)  │
│   topology/remote-node-hint.ts (RemoteNodeHint type)        │
│                                                             │
│   May import from: Layer 3 only + external packages         │
│   MUST NOT import from: @/ (anything in src/)               │
│   MUST NOT import from: @/lib/db                            │
└─────────────────────────────────────────────────────────────┘
```

### Import boundary rules (machine-enforced)

| Layer | Directory | MAY import from | MUST NOT import from |
|-------|-----------|-----------------|----------------------|
| 1 — Web App | `src/app/`, `src/lib/auth/`, `src/lib/http/`, `src/components/` | Layers 1, 2, 3 + `@/lib/db` | — (no restrictions) |
| 2 — Service | `src/lib/sharenet/` | Layer 2, Layer 3, `@/lib/db` | `@/lib/auth/`, `@/lib/http/`, `src/app/` |
| 3 — Protocol | `reference/` | Layer 3 + external packages | `@/` (anything in `src/`), `@/lib/db`, `@/lib/auth/`, `@/lib/http/` |

### What this preserves

- **spec/00 §2 Identity separation**: a human account (Layer 1) is never
  confused with a node identity (Layer 3). The protocol core has no concept
  of "user."
- **spec/00 §27 Application auth decoupled from NodeId**: the web login
  system cannot become an accidental part of the wire protocol because the
  protocol layer physically cannot import from the auth layer.
- **spec/16 Platform portability**: the `reference/` directory is pure
  TypeScript with zero dependencies on the web application. It can be
  extracted into a standalone package and ported to Rust / Go / C without
  carrying any web-auth baggage.

### How authorization flows (without coupling)

When a human operator (Layer 1) triggers a node-acceptance action through
the dashboard:

1. The HTTP route handler (Layer 1) calls `requireSession()` or
   `requireRealAdmin()` to authorize the **action** (is this human allowed
   to trigger this?).
2. The HTTP route handler calls `acceptNodeAdvertisement(adv, actorUserId)`
   in the service layer (Layer 2). The `actorUserId` is an **optional audit
   parameter** — it records WHO triggered the action in the audit log. It is
   NOT an authorization input to the protocol.
3. The service layer calls `verifyAdvertisement(adv)` in the protocol core
   (Layer 3). This function is pure: it takes bytes and returns a
   verification result. It has no concept of "user."

The protocol verification is user-agnostic. A real node (Phase 3+) would
call `verifyAdvertisement` directly — no HTTP, no session, no user.

## Consequences

- **`src/lib/http/api-helpers.ts`** (HTTP response helpers that map
  `AuthError` to HTTP status) lives in Layer 1, NOT Layer 2. It was
  previously at `src/lib/sharenet/api-helpers.ts` and imported from
  `@/lib/auth/api` — a violation. It has been moved.
- The service layer (`src/lib/sharenet/`) is now auth-free. It can be
  extracted and reused by a CLI tool, a daemon, or a non-HTTP service
  without carrying web-auth dependencies.
- The protocol core (`reference/`) remains pure and portable. It has zero
  knowledge of databases, sessions, users, or HTTP.
- Future developers who accidentally add an auth import to the service layer
  or a src import to the protocol core will be caught by architecture
  regression tests #21 and #22 (executable static-analysis guards).

## Alternatives Considered

1. **Single-layer (everything in src/)** — rejected. Couples protocol to web
   auth. A non-browser implementation cannot reuse the protocol.

2. **Two-layer (merge service + protocol)** — rejected. The service layer
   needs database access (for persistent sequence floors, node records).
   The protocol core must stay pure (no DB) to remain portable and
   testable with golden vectors.

3. **Two-layer (merge web + service)** — rejected. The web auth system
   (sessions, bcrypt, cookies) is a heavy dependency that the service layer
   should not carry. Keeping them separate allows the service layer to be
   reused by non-HTTP callers (CLI, daemon, tests).

4. **Convention-only (no executable guard)** — rejected per ADR-0010.
   Code review alone is insufficient; the forbidden import must fail CI.

## References

- spec/00-thesis.md §2 (Architectural invariants — Identity separation)
- spec/00-thesis.md §27 (Web auth / waitlist roadmap — "Do not couple
  application authentication to NodeId")
- spec/16-platforms.md (Platform-agnostic protocol core)
- ADR-0007 (AuthenticatedNodeRecord pipeline — the service-layer entry point)
- ADR-0010 (Architecture regression tests as build gate)
- ADR-0012 (Session and password handling — Layer 1 only)
- Architecture regression tests #21, #22 (executable import-boundary guards)
