# ShareNet 2.0 — Test Strategy

Per the corrective milestone (2026-08-16, B4), tests are separated into
three STRICTLY ENFORCED tiers:

- **`test:unit`** — deterministic unit tests. No network, no DB, no mesh.
- **`test:arch`** — deterministic architecture regression tests. No HTTP
  server, no localhost network calls, no database initialization, bounded
  execution. Must complete in under 30 seconds.
- **`test:integration:mesh`** — the ONLY command allowed to start/query
  node-link processes or use localhost sockets.

**A skipped test MUST be reported as skipped, never as passed.** Each tier
reports pass / fail / skipped separately.

## Tier 1 — Unit tests (`bun run test:unit`)

```bash
bun run test:unit
```

Runs every `*.test.ts` under `tests/`. These tests:
- Do not require the Next.js dev server.
- Do not require the database.
- Do not require the node-link mini-services.
- Do not make any localhost or network calls.
- Are deterministic — same input always produces same output.
- Are suitable for CI.

Currently includes:
- `tests/no-tracked-private-keys.test.ts`:
  - no tracked keypair files (spec/00 §5)
  - no file anywhere in the repo (including `conformance/`, fixtures, ADRs,
    docs, test snapshots) contains `secretKeyHex` / `ed25519SecretKeyHex` /
    `secretKey` / seed material outside narrowly documented protocol-core
    test code (corrective B3)
  - the 2 retired interim NodeIds appear in the retired-keys list
  - **every file under `conformance/vectors/` parses as valid JSON** (corrective B1)

## Tier 2 — Architecture regression tests (`bun run test:arch`)

```bash
bun run test:arch
```

Runs `src/lib/sharenet/run-arch-tests.ts` directly (no HTTP server, no curl).
These tests:
- Do NOT require the Next.js dev server.
- Do NOT require the database (the gateway check #13 is a STATIC source-text
  check, not a runtime import — it reads `src/lib/sharenet/gateway.ts` as
  text and asserts the exports, never initializing Prisma).
- Do NOT make any localhost or network calls.
- Are deterministic and bounded — must complete in under 30 seconds.
- Report `passed`, `failed`, AND `skipped` separately.

Test #25 (two-process advertisement-verification exchange) has been MOVED
to Tier 3 (`src/lib/sharenet/integration-mesh-tests.ts`). It does NOT run
in `test:arch`.

## Tier 3 — Manually-provisioned local-network integration tests (`bun run test:integration:mesh`)

```bash
bun run test:integration:mesh
```

Runs `src/lib/sharenet/integration-mesh-tests.ts` after starting the node-link
mini-services. These tests:
- Require real independent Bun processes (the node-link mini-services) to
  be running on localhost:3001 + localhost:3002 with TCP wire ports 7788 +
  7789.
- Are the ONLY tests that can truthfully claim "two real processes completed
  an advertisement-verification exchange" (per spec/00 §37).
- Report `passed` / `failed` / `skipped` separately. When the mini-services
  are unreachable, the test reports `SKIPPED` (exit code 2) — NOT `passed`.
- Are NOT suitable for headless CI without the mini-services provisioned.

## What does NOT count as a pass

- A `skipped` test is not a pass.
- A `failed` test is not a pass.
- A test that runs in Tier 2 but depends on Tier 3 services is `skipped`,
  not `passed`, when those services are absent. (Now moved entirely to Tier 3.)
- `test:arch` MUST NOT make localhost fetches or import database-coupled
  gateway code (corrective B4).

## What this directory does NOT contain

- No fake test vectors.
- No tests that always pass regardless of input.
- No tests that claim properties the code does not have.
- No tests that proceed to routing, circuits, gateway forwarding, Android,
  or any other protocol work.
