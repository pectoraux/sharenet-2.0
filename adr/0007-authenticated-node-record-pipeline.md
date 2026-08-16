# ADR 0007 — AuthenticatedNodeRecord Pipeline

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision fixes the pipeline by which a
NodeAdvertisement becomes an AuthenticatedNodeRecord, and the
contract that a `RemoteNodeHint` MUST NOT be promotable to an
AuthenticatedNodeRecord without a full advertisement round-trip.

## Context

`spec/06-topology.md` §3 records the architectural guard:

> The pipeline `RemoteNodeHint → AuthenticatedNodeRecord` MUST be
> impossible. There MUST be no function, method, or operator in the
> reference implementation that accepts a `RemoteNodeHint` and
> returns an `AuthenticatedNodeRecord` without first completing the
> Link handshake of `spec/04-links.md` §3.

This guard is reinforced by the executable conformance test in
`spec/17-conformance.md` §3.2: a static type check on the reference
implementation's public exports plus a runtime check that calling any
function accepting a `RemoteNodeHint` does not produce an
`AuthenticatedNodeRecord`.

`spec/03-node-advertisements.md` §5 records the 9-step verification
algorithm for an advertisement; `spec/06-topology.md` §2.2 records
the 8-step verification for a hint. The two are deliberately
distinct: a hint is verified about the **reporter**, not about the
subject, and a hint carries no claim that the subject has been
cryptographically authenticated by the verifier.

The risk being prevented: a malicious node R could sign a hint
claiming that subject S "has the INTERNET_GATEWAY capability" or
"is at endpoint E". If a naive verifier accepted the hint as an
AuthenticatedNodeRecord about S, R could trick the verifier into
routing traffic to a fake gateway endpoint controlled by R, or into
trusting S's claimed identity without S ever having cryptographically
spoken.

The only legitimate promotion path documented in `spec/06-topology.md`
§3 is:

```
RemoteNodeHint → CandidateDestination → Link handshake → AuthenticatedNodeRecord
                (see spec/05 §2)        (see spec/04 §3)
```

A hint yields a candidate destination (still REPORTED evidence); a
candidate destination initiates a Link handshake; a successful
handshake yields a NodeAdvertisement verified by the verifier; the
verified advertisement yields an AuthenticatedNodeRecord. Each
transition is explicit and auditable.

## Decision

Implement the AuthenticatedNodeRecord pipeline as two distinct
functions, each with a strict type signature that the TypeScript
compiler enforces:

```typescript
export function verifyAdvertisement(
  ad: NodeAdvertisement
): VerifiedNodeAdvertisement | ValidationError;

export function acceptNode(
  verified: VerifiedNodeAdvertisement,
  policy: AcceptancePolicy
): AuthenticatedNodeRecord | RejectionReason;
```

Where:

- `NodeAdvertisement` is the raw, untrusted type (decoded CBOR,
  unverified signature, unverified identity binding).
- `VerifiedNodeAdvertisement` is a branded type (per ADR 0005)
  constructed ONLY by `verifyAdvertisement` on successful completion
  of all 9 steps in `spec/03-node-advertisements.md` §5.
- `AuthenticatedNodeRecord` is a branded type constructed ONLY by
  `acceptNode` on successful completion of the acceptance policy
  check (revocation list, capability allowlist, etc.).

The `RemoteNodeHint` type is defined in a separate module that exports
`verifyHint(hint): VerifiedHint | ValidationError` and
`applyHint(verifiedHint, topologyStore): void`. `applyHint` stores the
hint as `REPORTED` evidence about the subject (per `spec/06-topology.md`
§6). The `RemoteNodeHint` module does NOT import `AuthenticatedNodeRecord`;
the TypeScript compiler enforces this via module-level type visibility.
The brand on `AuthenticatedNodeRecord` is private to the
identity/advertisement module; no other module can construct the brand.

Architecture regression test #7 (`spec/17-conformance.md` §2 test
7, `remote_node_hint_promotion_forbidden`) asserts: (1) **static type
check** — a grep across the codebase for any function whose parameter
type includes `RemoteNodeHint` and whose return type includes
`AuthenticatedNodeRecord` returns zero matches; (2) **runtime check**
— every function exported from `reference/discovery` and
`reference/topology` that accepts a `RemoteNodeHint` is invoked with a
fixture hint, and the return value is asserted NOT to be an instance
of `AuthenticatedNodeRecord`.

## Consequences

- **Discovery hints require a separate full advertisement round-trip
  before they can become authoritative.** A hint cannot promote S to
  AuthenticatedNodeRecord status until the verifier contacts S,
  receives and verifies an advertisement, and passes the
  acceptance policy.
- **Slightly slower onboarding.** The first time a verifier hears
  about a remote node, it must perform a network round-trip before
  the node can participate in routing or circuit construction.
- **Eliminates an entire class of identity-confusion attacks.** A
  malicious reporter cannot inject a fake AuthenticatedNodeRecord
  via a hint; the verifier re-authenticates the subject directly.
- **Module-level type discipline is mandatory.** The
  `AuthenticatedNodeRecord` brand is private to the
  `reference/identity` module. Code review enforces that no other
  module imports the brand constructor.
- **The acceptance policy is pluggable.** `acceptNode` takes an
  `AcceptancePolicy` parameter; the default checks the revocation
  list and the capabilities allowlist.
- **Tests must cover the negative path.** Without the architecture
  regression test, a careless future contributor could add a
  `fromHint(hint): AuthenticatedNodeRecord` function and break the
  invariant silently.
- **Cross-implementation contract.** Any port of ShareNet to another
  language must replicate the type-level prohibition.

## Alternatives Considered

1. **"Trust on first use" (TOFU) promotion of hints.** Rejected —
   violates `spec/06-topology.md` §3 directly. TOFU would allow a
   malicious reporter to inject a fake AuthenticatedNodeRecord via a
   single hint, breaking the identity-binding invariant of
   `spec/02-identity.md` §2.2.
2. **Promotion with a "confidence" score.** Considered — a hint
   could yield a low-confidence AuthenticatedNodeRecord later
   upgraded. Rejected because it requires the type to carry a
   confidence field, which is a backdoor for promotion.
3. **A single function `verifyAndAccept(adOrHint):
   AuthenticatedNodeRecord` that branches internally.** Rejected —
   the type signature advertises that a hint is an acceptable input,
   which is the violation.
4. **No AuthenticatedNodeRecord type; verify advertisements in
   place.** Considered — would simplify the pipeline but loses the
   acceptance-policy hook. A node might be verified (signature
   valid) but not acceptable (revoked, capability not allowlisted).
5. **Runtime check only (no compile-time guarantee).** Rejected —
   `spec/17-conformance.md` §3.2 demands both static and runtime
   checks.

## References

- `spec/03-node-advertisements.md` §5 — advertisement verification
  algorithm (input to `verifyAdvertisement`).
- `spec/06-topology.md` §2, §3 — RemoteNodeHint type, verification,
  and the architectural guard this ADR implements.
- `spec/02-identity.md` §4 — identity binding verification.
- `spec/17-conformance.md` §2 test 7 —
  `remote_node_hint_promotion_forbidden`.
- `spec/17-conformance.md` §3.2 — `RemoteNodeHint →
  AuthenticatedNodeRecord` forbidden pipeline guard.
- ADR 0005 — evidence type system (branding discipline).
- ADR 0010 — architecture regression tests (executable guard).
- Michael Nygard ADR template — structural source.
