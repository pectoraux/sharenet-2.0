# ShareNet 2.0 — Test Strategy

Per the corrective milestone (2026-08-16, F6), tests are separated into
three tiers. **A skipped test MUST be reported as skipped, never as passed.**
**A manually-provisioned local-network test MUST NOT be used as a CI pass
claim when its services are absent.**

## Tier 1 — Unit tests (deterministic, no network, no DB, no mini-services)

```bash
bun run test:unit
```

Runs every `*.test.ts` under `tests/`. These tests:
- Do not require the Next.js dev server.
- Do not require the database.
- Do not require the node-link mini-services.
- Are deterministic — same input always produces same output.
- Are suitable for CI.

Currently includes:
- `tests/no-tracked-private-keys.test.ts` — verifies no tracked file contains
  Ed25519 secret key material (spec/00 §5 enforcement).

## Tier 2 — Architecture regression tests (require the Next.js dev server)

```bash
bun run dev         # in one terminal
bun run test:arch   # in another
```

Runs the architecture test suite at `/api/sharenet/architecture/summary`.
These tests:
- Require the Next.js dev server to be running on port 3000.
- Are deterministic for tests #1-24, #25 returns `skipped` (see below).
- Report `passed`, `failed`, AND `skipped` separately.
- Are suitable for CI **with the caveat that test #25 will be `skipped`**
  if the node-link mini-services are not running.

Test #25 (two-process authenticated directed link) is a **local integration
test** (Tier 3) that the architecture suite also reports. When the
mini-services are not reachable, it returns `status: "skipped"` — NOT
`status: "passed"`. CI MUST treat `skipped` as a non-failure but MUST NOT
count it as a pass.

## Tier 3 — Manually-provisioned local-network integration tests

```bash
bash mini-services/node-link/start-mesh.sh   # starts Node A + Node B
bun run test:integration:mesh                 # runs test #25 against them
```

These tests:
- Require real independent Bun processes (the node-link mini-services) to
  be running on localhost:3001 + localhost:3002 with TCP wire ports 7788 +
  7789.
- Cannot run on Vercel or any environment where localhost ports cannot be
  bound.
- Are the ONLY tests that can truthfully claim "two real processes
  established an authenticated directed link" (per spec/00 §37).
- Are NOT suitable for headless CI without the mini-services provisioned.

## What does NOT count as a pass

- A `skipped` test is not a pass.
- A `failed` test is not a pass.
- A test that runs in Tier 2 but depends on Tier 3 services is `skipped`,
  not `passed`, when those services are absent.
- A test that runs in Tier 3 but is invoked from Tier 2 without the
  services is `skipped`, not `passed`.

## What this directory does NOT contain

- No fake test vectors.
- No tests that always pass regardless of input.
- No tests that claim properties the code does not have.
- No tests that proceed to routing, circuits, gateway forwarding, Android,
  or any other protocol work.
