# ADR 0010 — Architecture Regression Tests as Build Gate

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision fixes the executable architecture
regression test suite as a hard build gate: a forbidden pipeline
that compiles or runs MUST fail CI and block merge. The suite lives
in `reference/architecture-tests/`.

## Context

`spec/17-conformance.md` §3 enumerates ten forbidden pipelines.
Each is a class of code path that, if permitted, would violate a
core invariant of the protocol. Examples:

- `RemoteNodeHint → AuthenticatedNodeRecord` (identity confusion).
- `TopologyGraph → Dijkstra → Route` (collapses the multi-phase
  routing pipeline).
- `RouteProposal → Circuit` (skips commitment).
- Signature domain reuse (collapses two distinct signature uses).
- Expiration resets sequence floor (opens a replay window).
- Gateway egress without authorization (open proxy).
- Self-reported contribution crediting (inflates credits).
- Authentication-free link usage (unauthorized routing).

`spec/00-thesis.md` §4 ("Architectural Invariants") says these
invariants are "non-negotiable." `spec/01-architecture.md` §4 ("Stop
Conditions") makes them build-stopping.

The challenge: code review alone cannot enforce these. A reviewer
might miss a single function that accepts a `RemoteNodeHint` and
returns an `AuthenticatedNodeRecord`. A reviewer might miss a code
path that re-uses a domain string. The forbidden pipelines are
specific enough that an automated test can detect them with very
high signal-to-noise.

The architecture regression tests MUST be executable in the sandbox
first deliverable. They MUST run on every commit. They MUST fail
loudly and stop the build. They MUST be visible to the dashboard so
that a reviewer can see, at a glance, that the build is conformant.

## Decision

Implement an executable test suite at `reference/architecture-tests/`
(in Task 11) that asserts each forbidden pipeline throws, fails to
compile, or fails at runtime. The suite covers:

1. Every forbidden pipeline enumerated in `spec/17-conformance.md`
   §3.1 through §3.10.
2. Every architecture regression test enumerated in
   `spec/17-conformance.md` §2 tests 1-10.
3. The forbidden-pipeline list is codified as a TypeScript module
   that exports a list of `{ name, forbidden_signature_pattern,
   runtime_test }` tuples. Adding a forbidden pipeline to the spec
   requires adding a tuple here; the suite grows with the spec.

The suite is invoked by:

1. **CI on every commit.** A GitHub Actions workflow (or sandbox
   equivalent) runs `npm run test:architecture`. A failure blocks
   merge.
2. **Admin-only endpoint `POST /api/architecture-tests/run`.**
   Triggers a fresh run on demand. Returns a structured result
   (per-test pass/fail, timing, last-commit hash).
3. **Public read-only endpoint
   `GET /api/architecture-tests/summary`.** Returns a JSON summary:
   `{ last_run_at, commit_hash, passed, failed, total, suites:
   [...] }`. The dashboard (Task 12) renders this as a live
   "Conformance: GREEN/RED" badge.

The suite's tests fall into three categories:

1. **Static type tests.** `tsc` is invoked with a fixture file that
   attempts the forbidden assignment (e.g., assigning a
   `RemoteNodeHint` to an `AuthenticatedNodeRecord` variable). The
   fixture must produce a compile error; if it compiles, the test
   fails. Implemented via `tsd` or a custom `tsc --noEmit` run on
   a fixture directory.
2. **Static source scans.** A grep-based scan asserts that
   forbidden patterns do not appear. Example: the literal
   `"sharenet-node-id-v1"` appears in exactly one source file.
3. **Runtime tests.** A test that calls every public function whose
   parameter type accepts a forbidden input and asserts that the
   return value is not a forbidden output. Implemented via Vitest
   or Jest.

A test that is intentionally skipped (e.g., a Phase 10 test in a
Phase 8 build) MUST be marked `it.skip` with a comment referencing
the phase, per `spec/17-conformance.md` §5. Skipped tests are
visible in the dashboard summary but do not fail the build.

## Consequences

- **Every protocol PR must keep the suite green.** A PR that adds a
  forbidden pipeline (intentionally or not) fails CI. The reviewer
  sees the failure; the merge is blocked.
- **The forbidden-pipeline list is codified, not just documented.**
  Adding a forbidden pipeline to the spec requires adding a test
  here; the test is the executable contract. Conversely, removing
  one requires removing the test, which is a visible change in
  code review.
- **The dashboard shows a live conformance badge.** Reviewers and
  operators can see, at a glance, whether the running build is
  conformant. A red badge is a deployment blocker.
- **Admins can re-run the suite on demand.** Useful after a
  deployment, after a database migration, or after a configuration
  change.
- **The suite's runtime is non-trivial.** Static type checks via
  `tsc` are fast (seconds); source scans are fast; runtime tests
  are fast for the first deliverable's small codebase. The suite
  completes in under 30 seconds.
- **Test maintenance is a real cost.** Each new module that exposes
  a public function must be added to the relevant runtime test's
  enumeration. Code review enforces this.
- **The suite is part of the reference implementation, not a
  separate repo.** `spec/17-conformance.md` §5 considered a
  separate CI-only test repo and rejected it.
- **The public summary endpoint does NOT leak sensitive data.**
  It reports pass/fail counts and test names, not source code paths
  or stack traces. Stack traces are visible only to authenticated
  admins.

## Alternatives Considered

1. **Pure documentation (no executable tests).** Rejected —
   `spec/00-thesis.md` §4 and `spec/17-conformance.md` §5 forbid
   relying on documentation alone. A forbidden pipeline in code
   that compiles is a live vulnerability.
2. **Separate CI-only test repo.** Rejected — adds operational
   overhead (two repos to keep in sync, two CI configurations,
   cross-repo test discovery).
3. **Runtime-only tests (no static type checks).** Rejected — a
   forbidden pipeline that is a compile-time error in TypeScript
   (e.g., assigning a branded type to another branded type, per
   ADR 0005) is best enforced at compile time.
4. **Static type checks only (no runtime tests).** Rejected —
   some forbidden pipelines are runtime behaviors (e.g., a circuit
   constructed from a RouteProposal throws at runtime).
5. **Lint rules (ESLint plugin).** Considered — useful as a first
   line of defense but limited to syntactic patterns. The
   forbidden-pipeline list is semantic.
6. **Formal verification (Dafny, Coq).** Considered and rejected —
   out of scope for the first deliverable.

## References

- `spec/00-thesis.md` §4 — architectural invariants (non-negotiable).
- `spec/01-architecture.md` §4 — stop conditions.
- `spec/17-conformance.md` §2, §3, §5 — architecture regression tests,
  executable guards, build-stopping failures policy.
- ADR 0005 — evidence type system (branded types enable static
  type tests).
- ADR 0006 — sequence floor persistence (runtime test for
  expiration-resets-floor).
- ADR 0007 — AuthenticatedNodeRecord pipeline (static + runtime
  test for hint → record promotion).
- ADR 0011 — gateway SSRF and capacity guards (runtime test for
  gateway-without-authorization).
- Michael Nygard ADR template — structural source.
