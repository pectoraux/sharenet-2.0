# ADR 0008 — Waitlist Before Account

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision fixes the signup flow: public signup
creates a WaitlistEntry, NOT an active User account. Account
creation requires explicit admin approval. Unapproved waitlist
users cannot authenticate.

## Context

`spec/00-thesis.md` §2 defines ShareNet as a network of
"independently operated nodes that agree to forward traffic under
explicit, signed, revocable authorization." The thesis is
operator-gated: a ShareNet deployment is not an open sign-up
free-for-all; it is a network operator's curated set of peers.

`spec/00-thesis.md` §3 ("What ShareNet IS NOT") is explicit:

> ShareNet is NOT "free Internet." A gateway's bandwidth, a relay's
> electricity, and a path's latency all have real economic cost.

This implies that the operator must know who is on the network, must
be able to gate entry, and must be able to revoke. A free-for-all
signup that creates an immediately-active account would violate the
operator-gated model and would create an abuse surface (mass signup,
sybil attacks, spam).

`spec/14-security.md` §1-§2 records the security model: bcrypt
password hashing, secure sessions, authorization middleware,
account disable. None of these mechanisms are useful if the
attacker can create unlimited accounts at will.

The first deliverable includes a public-facing web application that
accepts signups. We need a flow that:

1. Lets members of the public express interest (signup).
2. Lets the operator review and approve/reject.
3. Does NOT create a usable account until approval.
4. Distinguishes waitlist state explicitly so the operator can see
   the queue.
5. Is auditable (every state transition is logged).

## Decision

Implement the signup flow as a two-stage pipeline:

```
Public signup form
    │  POST /api/waitlist/submit
    ▼
WaitlistEntry (status=PENDING)
    │  admin reviews
    ▼
Admin approve  →  WaitlistEntry (APPROVED → ACCOUNT_CREATED)  +  User row created
Admin reject   →  WaitlistEntry (REJECTED)
```

The `WaitlistEntry` table (Task 7) has the schema:

```
WaitlistEntry {
  id              String   @id @default(cuid())
  email           String   @unique
  displayName     String
  requestedRole   String   // free text, e.g. "operator", "researcher"
  status          WaitlistStatus  // PENDING | APPROVED | REJECTED | INVITED | ACCOUNT_CREATED
  submittedAt     DateTime @default(now())
  reviewedAt      DateTime?
  reviewedBy      String?  // UserId of admin
  adminNotes      String?
  rejectionReason String?
  createdAt       DateTime @default(now())
  updatedAt       DateTime @updatedAt
}
```

Public signup inserts a `WaitlistEntry` with `status=PENDING`. The
public signup endpoint does NOT hash a password, does NOT create a
`User` row, does NOT issue a session. The submitter receives an
acknowledgment ("your request is in the queue") and nothing else.

Admin review (via the admin UI of Task 9) lists PENDING entries. An
admin can:

- **Approve** → status becomes `APPROVED`, then `ACCOUNT_CREATED`
  after the user-creation step runs. The user-creation step inserts
  into the `User` table (with a randomly-generated initial password
  that the user must reset on first login) and sets
  `WaitlistEntry.status = ACCOUNT_CREATED`.
- **Reject** → status becomes `REJECTED`. The `rejectionReason` is
  recorded. The email is not blocked from re-submitting (the
  operator may change their mind) but the entry remains in the
  table for audit.
- **Invite** (deferred) → status becomes `INVITED`; an invitation
  email is sent with a one-time signup link.

Unapproved waitlist users CANNOT authenticate. The login endpoint
queries the `User` table by email; if no `User` row exists (because
the waitlist entry is still PENDING, REJECTED, or INVITED), the
login returns a generic "invalid credentials" error. The error
message is deliberately identical to the wrong-password case to
avoid leaking which emails are in the waitlist.

## Consequences

- **Adds an admin step before any public user can log in.** This is
  appropriate for a network-operator-gated system. For the first
  deliverable, the admin is the bootstrap account created by the
  seed migration.
- **Sybil resistance.** A mass-signup attack fills the waitlist but
  does not create accounts; the operator reviews and rejects. The
  waitlist table grows but the user table does not.
- **Email enumeration resistance.** The login endpoint returns the
  same error for "email not in user table" and "wrong password".
  The signup endpoint returns a generic success for duplicate emails
  (does NOT reveal that the email is already in the waitlist).
- **Auditability.** Every status transition is logged in the audit
  log (per `spec/14-security.md` §5). The admin reviewer's UserId
  is recorded.
- **No password storage until account creation.** The waitlist
  entry does not store a password. This eliminates an entire class
  of password-leak attacks against pending signups.
- **The waitlist table grows unboundedly.** For the first
  deliverable, this is acceptable. A future ADR may add retention
  rules (e.g., delete REJECTED entries after 90 days).
- **Self-service discovery is preserved.** Unlike an invite-only
  system with no public form, members of the public CAN express
  interest.
- **Account creation is the only step that hashes a password.**
  bcrypt is run exactly once per user (at account creation, with a
  random initial password that the user resets on first login) and
  again whenever the user changes their password.

## Alternatives Considered

1. **Open signup with email verification.** Rejected — too
   permissive for the protocol operator model. Email verification
   proves control of an email address but not fitness to participate
   in a network with real economic cost.
2. **Invite-only with no public form.** Rejected — no self-service
   discovery.
3. **Open signup with rate-limiting and CAPTCHA.** Rejected —
   mitigates automation but does not gate entry.
4. **Two-factor signup (referral code required).** Considered —
   would gate entry behind an existing member's referral. Adds
   complexity to the first deliverable.
5. **Waitlist with automated approval (e.g., approve all signups
   from a specific email domain).** Rejected — defeats the
   operator-gating purpose.
6. **No waitlist; the bootstrap admin manually creates every User
   row.** Considered — equivalent to invite-only.

## References

- `spec/00-thesis.md` §2, §3 — operator-gated model; what ShareNet
  IS NOT (no free Internet).
- `spec/14-security.md` §1, §2, §5 — human account security,
  authorization middleware, audit logging.
- ADR 0001 — sandbox database.
- ADR 0009 — demo account isolation.
- ADR 0012 — session and password handling.
- Michael Nygard ADR template — structural source.
