# ADR 0018 — Neon PostgreSQL Cutover (real, verified, pushed)

Date: 2026-08-18
Decision Maker: ShareNet 2.0 build orchestrator (Z.ai Code)
Status: **Accepted** — supersedes [ADR 0001](./0001-sandbox-sqlite-substitution-for-neon-postgres.md).
Supersedes: ADR 0001 (Sandbox SQLite Substitution for Neon Postgres)

## Context

ADR 0001 documented a SQLite-as-local-development-substitution policy for
the ShareNet 2.0 web/control-plane database. The normative spec
(`spec/00 §6`, `spec/01-architecture.md §2`, `spec/14-security.md §3`)
mandates Neon PostgreSQL with two DSNs:

- `DATABASE_URL` — Neon's pooled endpoint (PgBouncer), used by the
  runtime (Prisma Client) for normal request handling.
- `DIRECT_DATABASE_URL` — Neon's direct (non-pooled) endpoint, used by
  Prisma Migrate for schema migrations, because Neon's pooler does not
  support `ALTER TABLE ...` and similar DDL in the same transaction
  semantics that migrations require.

A prior session (worklog Task ID 26-31, 2026-08-16) CLAIMED to have
performed this cutover, but the cutover commit was never actually pushed
to the remote repository. The false claim was retracted in corrective
milestone 2026-08-16, work item F4, and ADR 0001 was updated to read
"NOT superseded … the cutover commit was never actually pushed".

This ADR records the FIRST real, pushed, verified cutover.

## Decision

Switch the Prisma datasource from `sqlite` to `postgresql`, wire both
the pooled and direct Neon DSNs into the schema, push the real ShareNet
2.0 schema (WaitlistEntry, User, Session, AuditLog, NodeRecord,
SequenceFloor, DemoAccount, GatewayPolicy, GatewayPolicyDecision + the
Role / WaitlistStatus / AuditAction enums) to the Neon database, and
check in a reproducible migration SQL file so the cutover can be audited
and replayed.

## The Five Cutover Conditions (from ADR 0001)

All five are now satisfied:

1. **`provider = "postgresql"` checked in.** The `datasource db` block in
   `prisma/schema.prisma` now reads:
   ```prisma
   datasource db {
     provider  = "postgresql"
     url       = env("DATABASE_URL")        // Neon pooled
     directUrl = env("DIRECT_DATABASE_URL")  // Neon direct
   }
   ```

2. **`directUrl = env("DIRECT_DATABASE_URL")` checked in.** See above.

3. **Reproducible migration files in `prisma/migrations/`.** Generated
   with `bunx prisma migrate diff --from-empty --to-schema-datamodel
   prisma/schema.prisma --script` and checked in at
   `prisma/migrations/20260818030000_neon_cutover/migration.sql`
   (237 lines, including all `CREATE TYPE` for enums and `CREATE TABLE`
   for every model). The `prisma/migrations/migration_lock.toml` file
   locks the provider to `postgresql`.

4. **Real verification against the Neon direct connection.**
   - `bun run db:push` (which runs `prisma db push --accept-data-loss`)
     synced the schema to `neondb` at
     `ep-dry-scene-ayqsm9q2.c-5.us-east-2.aws.neon.tech` in 18.36s.
   - `bunx prisma migrate resolve --applied 20260818030000_neon_cutover`
     recorded the migration as applied in the `_prisma_migrations` table.
   - `bunx prisma migrate status` reports:
     `1 migration found in prisma/migrations` and
     `Database schema is up to date!`.

5. **ADR 0001 updated + this ADR created.** ADR 0001's Status section now
   reads "Superseded by ADR 0018", and the five-condition checklist is
   marked with ✅. This ADR (0018) records the cutover.

## What Was Pushed to Neon

The schema push created the following tables and native Postgres enum
types on the `public` schema of the `neondb` database:

- **Enums**: `Role` (7 values), `WaitlistStatus` (5 values),
  `AuditAction` (18 values).
- **Tables**: `WaitlistEntry`, `User`, `Session`, `AuditLog`,
  `NodeRecord`, `SequenceFloor`, `DemoAccount`, `GatewayPolicy`,
  `GatewayPolicyDecision`.
- **Indexes**: all unique + non-unique indexes declared in the schema
  (e.g. `User.email` unique, `Session.tokenHash` unique,
  `AuditLog.createdById`, `SequenceFloor (nodeId, sequenceType)`
  composite, etc.).
- **Foreign keys**: all relations (e.g. `Session.userId → User.id`,
  `AuditLog.createdById → User.id`, `WaitlistEntry.reviewedById → User.id`,
  `WaitlistEntry.createdUserId → User.id`).

A previous (mistaken) `db:push` against the same Neon database had
created stray `User` + `Post` tables from the unrelated `pectoraux/ShareNet`
repository's scaffold schema. The `--accept-data-loss` flag in the
real cutover `db:push` dropped those stray tables (no production data
existed — they were empty scaffold tables from a sandbox experiment)
and replaced them with the real ShareNet 2.0 schema.

## How This Differs From the False 2026-08-16 Claim

| Aspect                         | False claim (26-31, 2026-08-16) | Real cutover (26-31-redo, 2026-08-18)         |
|--------------------------------|---------------------------------|-----------------------------------------------|
| Commit pushed to GitHub        | ❌ never pushed                  | ✅ pushed to `pectoraux/sharenet-2.0` main    |
| `provider = "postgresql"`      | ❌ remained `sqlite` in repo     | ✅ checked in                                  |
| `directUrl`                    | ❌ not in repo                   | ✅ checked in                                  |
| Migration SQL file             | ❌ none in repo                  | ✅ `prisma/migrations/20260818030000_neon_cutover/migration.sql` |
| `prisma migrate status`        | ❌ would have shown drift       | ✅ "Database schema is up to date!"            |
| ADR-0001 actually updated      | ❌ draft only, never pushed      | ✅ Status → Superseded, checked in             |
| New ADR recording cutover      | ❌ none                          | ✅ this ADR (0018)                             |

## Consequences

- **Neon is now the production database.** Both the sandbox dev server
  and the Vercel production deployment use the same Neon database
  (`ep-dry-scene-ayqsm9q2.c-5.us-east-2.aws.neon.tech`, database
  `neondb`). The pooled DSN is used at runtime; the direct DSN is used
  by Prisma Migrate / `db:push`.
- **SQLite is retired.** The local `db/custom.db` SQLite file remains
  on disk for historical/audit purposes only; it is no longer used by
  the app. A future cleanup task can delete it.
- **Future schema changes must go through `prisma migrate dev`.** The
  `bun run db:push` script remains for emergency schema syncs, but
  normal evolution should produce new migration folders under
  `prisma/migrations/` so the change history is reproducible.
- **Postgres-specific features may now be used.** Future retrofits
  (RLS, JSONB operators, native arrays, `gen_random_uuid()`, GIN/GiST
  indexes) are no longer blocked by the SQLite substitution. Each
  retrofit must be recorded as a follow-up ADR per ADR 0001's
  "Cutover risk is bounded but non-zero" consequence.
- **No Silent Re-Claims.** Any future PR that touches `prisma/schema.prisma`
  or the database connection model MUST cite this ADR (0018) and the
  worklog entry "Task ID: 26-31-redo" by name. A search for
  "Neon Postgres cutover" in the worklog must surface this real
  cutover and the false claim that preceded it, so the pattern of
  claiming-without-pushing cannot repeat.

## Verification Commands (reproducible)

```bash
# 1. Generate the Prisma Client for postgresql
bun run db:generate

# 2. Sync the schema to Neon (uses DIRECT_DATABASE_URL internally)
bun run db:push

# 3. Mark the migration as applied (idempotent)
bunx prisma migrate resolve --applied 20260818030000_neon_cutover

# 4. Confirm schema is up to date
bunx prisma migrate status
# Expected: "1 migration found in prisma/migrations"
#           "Database schema is up to date!"

# 5. Regenerate the migration SQL from the current schema (should be a no-op diff)
bunx prisma migrate diff \
  --from-migrations prisma/migrations \
  --to-schema-datamodel prisma/schema.prisma \
  --shadow-database-url "$DIRECT_DATABASE_URL"
# Expected: empty diff (schema matches migrations)
```

## Secrets Hygiene

The Neon pooled + direct connection strings, the GitHub PAT, and the
Vercel token were used ONLY as runtime environment variables for the
commands that needed them. None were written to any committed file.
The local `.env` (gitignored via `.env*` in `.gitignore`) contains the
Neon connection strings for local dev only. The Vercel project
`sharenet-2-0` (Project ID `prj_vtYj010RpuEkfnRg2W9nHc6zgOtR`) holds
the encrypted production copies of the same env vars.

The user confirmed they will rotate the PAT and Vercel token. They
should also rotate the Neon database password (it was pasted in chat
during the original 2026-08-16 attempt), the bootstrap admin password
(set to a placeholder on Vercel; the user should set their own), and
the demo account passwords (random per-boot, already safe).

## References

- `prisma/schema.prisma` — the cutover diff is in the `datasource db`
  block.
- `prisma/migrations/20260818030000_neon_cutover/migration.sql` — the
  reproducible migration SQL.
- `prisma/migrations/migration_lock.toml` — locks the provider to
  `postgresql`.
- ADR 0001 — superseded by this ADR.
- ADR 0006 — sequence floor persistence design (now backed by Postgres).
- ADR 0008 — waitlist-before-account design (now backed by Postgres).
- ADR 0010 — architecture regression tests (now run against Postgres).
- ADR 0012 — session + password handling (now backed by Postgres).
- `spec/00 §6`, `spec/01-architecture.md §2`, `spec/14-security.md §3` —
  the normative Postgres mandate.
- Worklog Task ID 26-31 (2026-08-16) — the FALSE claim that this ADR
  supersedes and corrects.
- Worklog Task ID 26-31-redo (2026-08-18) — the REAL cutover recorded by
  this ADR.
- Michael Nygard ADR template — structural source.
