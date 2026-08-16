# ADR 0001 — Sandbox SQLite Substitution for Neon Postgres

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted** — local development substitution only.

**NOT superseded.** A prior draft of this ADR claimed "Superseded — cutover
to Neon PostgreSQL complete (2026-08-16)". That claim was **false**. The
cutover commit was never actually pushed to the remote repository; the
checked-in schema at `prisma/schema.prisma` remains `provider = "sqlite"`.
The false claim is hereby retracted (see corrective milestone 2026-08-16,
work item F4).

The normative spec mandates Neon PostgreSQL. The substitution documented
here applies to the LOCAL DEVELOPMENT environment only. A real cutover
requires:
1. `provider = "postgresql"` checked into `prisma/schema.prisma`.
2. `directUrl = env("DIRECT_DATABASE_URL")` checked in.
3. Reproducible migration files in `migrations/`.
4. A real verification (e.g. `bun run db:migrate deploy` succeeds against
   the Neon direct connection).
5. This ADR updated to "Superseded" with a pointer to a new ADR recording
   the cutover.

Until all five conditions are met, this ADR remains **Accepted (local
development substitution)** and no Neon cutover is claimed.

## Context

The normative specification (see `spec/01-architecture.md` §2 "Repository
Layout" and `spec/14-security.md` §3 "Persistent Sequence Floors") mandates
Neon PostgreSQL as the production database. The production connection
model uses two DSNs:

- `DATABASE_URL` — pooled connection string used by the runtime for normal
  request handling (Neon's pooled endpoint).
- `DIRECT_DATABASE_URL` — direct (non-pooled) connection string used by
  Prisma Migrate for schema migrations, because Neon's pooler does not
  support `ALTER TABLE ...` and similar DDL in the same transaction
  semantics that migrations require.

The build sandbox in which this first deliverable is compiled and
exercised only supports SQLite via Prisma. No external Postgres instance
is provisioned, no network egress to a hosted Postgres is available, and
the build must run end-to-end inside the sandbox for verification
purposes (including the architecture regression tests of ADR 0010).

This creates a tension: the spec is normative for Postgres, but the
sandbox cannot honor that mandate without changing the build
environment. We need a substitution that (a) preserves every protocol
invariant, (b) is mechanically convertible to Postgres later, and
(c) does not require us to fork the spec.

## Decision

Use SQLite as the sandbox database via the Prisma `sqlite` provider. The
Prisma schema (Task 7) is written so that its shape mirrors the
production Postgres schema: same model names, same field names, same
relations, same indexes (where SQLite supports them), same enum
representations, and the same constraint intent.

Concretely:

1. `prisma/schema.prisma` declares `datasource db { provider = "sqlite" }`
   in the sandbox branch. A one-line change to `provider = "postgresql"`
   plus the two DSNs is the only edit required at cutover.
2. Fields that would be `Bytes` or `Json` in Postgres are stored as
   `String` (hex / canonical-CBOR-encoded) in SQLite. The model layer
   converts at the boundary; no business logic touches the encoded form.
3. Indexes that SQLite supports (single-column, composite, unique) are
   declared identically. Postgres-specific index types (GIN, GiST,
   partial indexes) are documented in schema comments and added at
   cutover.
4. Migrations are written using Prisma's migration workflow and are
   portable: every migration runs on both providers in CI.

The migration to Postgres is mechanical: change the provider, run
`prisma migrate deploy` against the production DSN, and verify the
architecture regression tests (ADR 0010) still pass.

## Consequences

- **Lost Postgres-specific features.** Row-Level Security (RLS), JSONB
  operators, native array columns, and `gen_random_uuid()` are not
  available in SQLite. The application layer compensates: RLS-equivalent
  authorization is enforced in middleware (see `spec/14-security.md`
  §2); JSONB fields are stored as canonical CBOR-encoded byte strings
  and decoded at the boundary.
- **Sufficient for first deliverable.** The first deliverable's scope is
  waitlist, users, audit log, sequence floors, identity derivation,
  advertisement verification, and the architecture regression test
  suite. None of these require Postgres-specific features. Concurrent
  write contention is acceptable because the workload is dominated by a
  single admin reviewer (see ADR 0008).
- **Schema shape preservation is mandatory.** Any model that would
  require a SQLite-only shape (e.g., a type that has no Postgres
  equivalent) is forbidden. The reviewer must reject such a model.
- **Cutover risk is bounded but non-zero.** Once the cutover happens,
  Postgres-specific features may be retrofitted. Each retrofit must be
  recorded as a follow-up ADR.
- **No use of SQLite-specific pragmas that change semantics.** The
  schema must not depend on `WITHOUT ROWID`, `STRICT`, or generated
  columns in ways that would not translate.

## Alternatives Considered

1. **Use Prisma's `sqlite` provider with a thin abstraction that swaps
   to `postgresql` later.** Chosen. The abstraction is the Prisma
   client itself plus a hex/CBOR boundary encoder for unsupported
   types. Minimal code, maximal portability.
2. **Provision a hosted Postgres inside the sandbox.** Rejected — the
   sandbox does not allow external services and a self-hosted Postgres
   inside the build container would slow iteration and add a failure
   mode unrelated to the protocol work being verified.
3. **Use a pure in-memory store with no persistence.** Rejected —
   `spec/14-security.md` §3 mandates persistent sequence floors that
   survive process restarts, and ADR 0006 makes that an executable test.
4. **Write the schema in Postgres-only dialect and skip SQLite
   tests.** Rejected — would break the architecture regression tests
   (ADR 0010), which must run in the sandbox.
5. **Use a different ORM (Drizzle, Kysely).** Rejected — Prisma is the
   declared dependency per Task 1; switching would invalidate Task 1's
   installed dependency set.

## References

- `spec/01-architecture.md` §2 — repository layout and database role.
- `spec/14-security.md` §3 — persistent sequence floors (durability
  requirement).
- `spec/14-security.md` §2 — authorization middleware (compensates for
  absent RLS in SQLite).
- `spec/17-conformance.md` §4 — phase exit conditions, several of
  which exercise the database.
- ADR 0006 — sequence floor persistence design (depends on this ADR).
- ADR 0008 — waitlist-before-account design (depends on this ADR).
- ADR 0010 — architecture regression tests (must run against this
  database).
- Michael Nygard ADR template — structural source.
