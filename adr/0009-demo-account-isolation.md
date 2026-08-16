# ADR 0009 — Demo Account Isolation

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision fixes the design of demo accounts:
visually distinct, isolated from real accounts, marked internally,
disableable, never exposing real admin credentials.

## Context

`spec/00-thesis.md` §2 establishes ShareNet as a network operator's
curated system. A first deliverable that wants to be evaluated by
reviewers, demoed at conferences, or shown to potential operators
needs a way to let visitors try the dashboard without:

1. Creating real User rows that pollute the production user table.
2. Exposing real admin credentials to the public.
3. Letting demo sessions mutate real waitlist or audit-log data.
4. Letting a compromised demo session escalate to real admin
   privileges.

`spec/14-security.md` §2 records the authorization model: every
authenticated endpoint is wrapped by middleware that checks the
session, the UserId, and the role. A demo session that holds the
same role as a real admin would be indistinguishable from a real
admin session to the middleware, unless the demo-ness is tracked
explicitly.

The sandbox first deliverable is a demoable artifact: the
architecture regression tests (ADR 0010), the dashboard (Task 12),
and the waitlist/admin UI (Task 9) are all designed to be shown to
reviewers. We need a "click here to try it" path that does not
require a manual account-provisioning step.

## Decision

Demo accounts are full `User` rows with the `isDemo: true` flag set
in the `User` table. The flag is a non-nullable `Boolean` column
with a default of `false`. Real accounts have `isDemo: false`.

Demo authentication uses a separate session surface:

1. **Separate cookie name.** Real sessions use the `sharenet_session`
   cookie (per ADR 0012). Demo sessions use the
   `sharenet_demo_session` cookie. The two cookies never coexist in
   the same browser session.
2. **Separate login endpoint.** Real login is `POST /api/auth/login`.
   Demo login is `POST /api/demo/login`. The demo login endpoint is
   gated by the `ENABLE_DEMO_LOGIN` environment variable (default
   `false` in production, `true` in the sandbox).
3. **Separate session table column.** The `Session` table has an
   `isDemo: Boolean` column. The middleware checks `session.isDemo`
   and refuses to allow demo sessions to access real-admin endpoints
   even if the demo user holds an admin role.

The demo admin user is a SEPARATE identity from the real admin
bootstrap account. The real admin bootstrap is created by the seed
migration with `isDemo: false`. The demo admin is created by a
separate seed with `isDemo: true`. The two have different UserIds,
different emails (e.g., `admin@real.sharenet` vs
`admin@demo.sharenet`), and different passwords.

Demo accounts operate on a parallel demo-scoped dataset where
applicable. Concretely:

- **Waitlist.** Demo accounts see a separate demo waitlist. Demo
  signup inserts into `WaitlistEntry` with `isDemo: true`. Demo
  approve/reject mutates only demo-scoped rows.
- **Audit log.** Demo actions are recorded in the audit log with
  `actor_isDemo: true` and are queryable separately. The real
  audit log is read-only for demo accounts.
- **Identity / advertisement / circuit stores.** Demo accounts can
  generate demo NodeIds, sign demo advertisements, and observe demo
  sequence floors. These do NOT pollute the real sequence floor
  store; a separate `isDemo` column or a separate table partitions
  the data.

The UI displays a visible banner ("DEMO SESSION — actions are
isolated and may be reset") whenever the session is a demo session.

The `ENABLE_DEMO_LOGIN` env flag is the kill switch. In production
it defaults to `false`; the demo login endpoint returns `404` and
the demo session cookie is rejected. In the sandbox it defaults to
`true`.

## Consequences

- **Demo sessions are visually distinct.** The banner prevents a
  reviewer from accidentally believing they are operating on real
  data. A screenshot of the dashboard shows the DEMO banner
  clearly.
- **Demo accounts cannot mutate real data.** The middleware
  enforces this at every endpoint; the `isDemo` flag is checked
  alongside the role check.
- **Demo is disableable.** The `ENABLE_DEMO_LOGIN=false` flag
  removes the demo login surface entirely.
- **Real admin credentials are never exposed.** The real admin
  bootstrap password is set by environment variable at first boot
  and is rotated; the demo admin password is a documented, fixed
  string that is useless against real data.
- **The User table carries the `isDemo` flag.** Every query that
  enumerates real users MUST filter `WHERE isDemo = false`. Code
  review enforces this; a missing filter is a security bug.
- **Session table carries the `isDemo` flag.** Same enforcement.
- **Audit log carries `actor_isDemo`.** Real-admin audit-log views
  filter demo entries by default; a reviewer can toggle to see
  them.
- **Demo data is resettable.** A `RESET_DEMO_DATA` env flag or an
  admin endpoint wipes the demo-scoped rows. Real data is
  untouched.
- **Demo is a deployment-time choice, not a runtime choice.** The
  `ENABLE_DEMO_LOGIN` flag is read at process start; toggling it
  requires a restart. This prevents a runtime compromise from
  enabling demo login.
- **Slightly more complex middleware.** The middleware checks both
  `session.userId` and `session.isDemo`; an endpoint that is
  real-admin-only rejects demo sessions even if the demo user has
  admin role.

## Alternatives Considered

1. **Demo accounts in a separate database.** Rejected — over-
   engineering for the first deliverable. The `isDemo` flag and
   middleware checks achieve the same isolation at a fraction of
   the operational complexity.
2. **No demo accounts.** Rejected — `spec/00-thesis.md` §2 implies
   a curated system that reviewers must be able to see and try
   without manual account provisioning.
3. **Demo accounts with the same identity as real admin (read-only
   mode).** Rejected — would expose real admin credentials to
   anyone with the demo URL, and would let a compromised demo
   session read real waitlist and audit-log data.
4. **JWT-based demo sessions (stateless).** Rejected —
   `spec/14-security.md` §1 forbids passwords in JWT, and
   stateless JWT revocation is hard (per ADR 0012). Server-side
   demo sessions are consistent with server-side real sessions.
5. **Demo as a separate role (`DEMO_ADMIN`).** Considered — would
   work, but the role model in `spec/14-security.md` §2 is meant
   for real roles (`USER`, `OPERATOR`, `ADMIN`). The `isDemo` flag
   is orthogonal to role.

## References

- `spec/00-thesis.md` §2 — operator-gated model.
- `spec/00-thesis.md` §3 — what ShareNet IS NOT.
- `spec/14-security.md` §1 — human account security.
- `spec/14-security.md` §2 — authorization middleware.
- `spec/14-security.md` §5 — audit logging.
- ADR 0008 — waitlist-before-account (demo waitlist is the
  parallel demo-scoped dataset).
- ADR 0012 — session and password handling (the real-session design
  that this ADR forks for demo sessions).
- Michael Nygard ADR template — structural source.
