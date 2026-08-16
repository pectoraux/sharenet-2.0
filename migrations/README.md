# ShareNet 2.0 — Database Migrations

**Status:** `planned` — no migrations authored yet.

Per spec/00 §6 (Database Rule) and the corrective milestone (2026-08-16):

> The schema must be reproducible from migrations.

The current `prisma/schema.prisma` defines the schema but no migration
files exist. `prisma db push` is used for local development (and was used
to push the schema to the Neon sandbox), but `prisma db push` is NOT
reproducible — it does not generate migration files and does not record
the schema history.

## Why migrations are `planned`, not authored

The checked-in schema uses `provider = "sqlite"` (local development
substitution — see ADR-0001 and the corrective work item F4). The Neon
Postgres cutover was claimed but the checked-in schema does NOT reflect
it. Until the database truthfulness issue is resolved (the schema is
either honestly relabeled as a local dev substitution OR the cutover is
real and the schema is checked in as `postgresql` with real migration
files), no migrations can be truthfully authored.

## What this directory WILL contain (once migrations are authored)

```
migrations/
  00000000000000_init/
    migration.sql       # the SQL DDL
    migration.toml     # Prisma migration metadata
```

Plus a `migrations/migration_lock.toml` recording the provider.

## What this directory does NOT contain

- No fake migration files.
- No placeholder SQL.
- No claim that migrations are reproducible when they are not.
- No database files (`*.db`, `*.db-journal`).
- No credentials.
