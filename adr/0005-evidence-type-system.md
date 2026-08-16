# ADR 0005 — Evidence Type System

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision fixes the TypeScript type representation
of ShareNet's evidence categories as branded types / discriminated
unions, and fixes the contract that the architecture regression
test suite MUST assert that no implicit conversion between
categories compiles or passes at runtime.

## Context

`spec/00-thesis.md` §4.6 ("Evidence Types") mandates that every
claim a node records about another node MUST carry an explicit
evidence type drawn from this closed enumeration:

| Evidence Type     | Meaning                                                                | Replayable as Authenticated? |
|-------------------|------------------------------------------------------------------------|------------------------------|
| `AUTHENTICATED`   | Recording node performed direct cryptographic verification.            | Yes (within validity window) |
| `OBSERVED`        | Recording node observed directly but did not cryptographically verify. | No — must be re-observed.    |
| `REPORTED`        | Another node claimed the fact; recording node did not verify.          | No — must be re-verified.    |
| `DERIVED`         | Recording node computed the fact from prior authenticated/observed facts via a documented derivation rule. | Only with the derivation chain. |
| `INFERRED`        | Recording node guessed heuristically; no crypto or observational basis. | Never.                       |

`spec/00-thesis.md` §4.2 ("Knowledge Separation") and
`spec/06-topology.md` §1 reinforce this: a node's directly observed
facts are not the same as facts it has been told. Treating a
`REPORTED` fact as `AUTHENTICATED` without a fresh verification step
is a specification violation.

The forbidden pipeline enumerated in `spec/17-conformance.md` §3.2
(hint → AuthenticatedNodeRecord) is one specific instance of a
general class: any code path that promotes a lower-trust evidence
value to a higher-trust evidence value without the required
verification step is forbidden.

If evidence categories were represented by a single generic type
(e.g., `Metric<T>` with a `kind: "REPORTED" | "AUTHENTICATED"`
field), the type system would not prevent misuse. A function
expecting an `AUTHENTICATED` metric could silently accept a
`REPORTED` metric, and the only defense would be a runtime check
that a developer must remember to write.

## Decision

Implement TypeScript **branded types** / **discriminated unions**
for each evidence category. Concretely:

```typescript
type Brand<T, B> = T & { readonly __brand: B };

export type AuthenticatedClaim =
  Brand<{ kind: "AUTHENTICATED"; node_id: NodeId; payload: ClaimPayload }, "AuthenticatedClaim">;
export type ObservedMetric =
  Brand<{ kind: "OBSERVED"; node_id: NodeId; metric: MetricValue }, "ObservedMetric">;
export type ReportedMetric =
  Brand<{ kind: "REPORTED"; reporter_id: NodeId; metric: MetricValue }, "ReportedMetric">;
export type DerivedMetric =
  Brand<{ kind: "DERIVED"; sources: AuthenticatedClaim[] | ObservedMetric[]; metric: MetricValue }, "DerivedMetric">;
export type InferredMetric =
  Brand<{ kind: "INFERRED"; basis: string; metric: MetricValue }, "InferredMetric">;
```

The brand symbols (`__brand`) make it impossible to assign one
evidence category's value to another category's variable at
compile time. The `kind` discriminant makes runtime pattern-matching
safe and exhaustive.

A function that consumes an `AuthenticatedClaim` MUST take the
branded type, not the unbranded underlying shape. A function that
produces an `AuthenticatedClaim` MUST be the only path through
which the brand is acquired; the brand constructor is a single
internal function `markAuthenticated(claim)` that performs the
required cryptographic verification before branding.

The architecture regression test suite (Task 11) asserts:

- `tsc` rejects any attempt to assign `ReportedMetric` to a variable
  of type `AuthenticatedClaim`.
- Runtime tests attempt to construct an `AuthenticatedClaim` without
  going through `markAuthenticated` and assert that the constructor
  throws or is not exported.
- The forbidden pipeline list in `spec/17-conformance.md` §3 is
  walked end-to-end; each forbidden promotion is attempted at
  runtime and asserted to throw.

## Consequences

- **Slightly more code.** Five branded types instead of one
  generic. Each type carries its own constructor and its own
  accessor. The cost is on the order of a few hundred lines of
  TypeScript; the benefit is a permanent guard against an entire
  class of identity-confusion attacks.
- **Strong guarantee that `ReportedMetric` cannot be silently
  promoted to `ObservedMetric` or `AuthenticatedClaim`.** The brand
  prevents assignment; the absence of a public constructor
  prevents fabrication.
- **The derivation chain is in the type.** A `DerivedMetric` MUST
  carry its `sources` array; the type system enforces that the
  sources are themselves `AuthenticatedClaim` or `ObservedMetric`
  (never `InferredMetric` or another `DerivedMetric` without a
  documented rule).
- **JSON serialization requires explicit encode/decode.** The brand
  is a phantom field that does not serialize; round-tripping
  requires a verifier that re-runs `markAuthenticated`. This is
  intentional: a value that survived a JSON round-trip is no longer
  trusted until re-verified.
- **Future languages porting ShareNet must replicate the type
  discipline.** Rust's newtype pattern, Go's named types, Python's
  `NewType` are all viable. The conformance suite's architecture
  tests are the cross-language contract.
- **`InferredMetric` is allowed but cannot seed trust.** Any code
  that reads an `InferredMetric` MUST treat its `metric` as a hint,
  not as input to authorization, routing, or settlement decisions.
  The type system does not enforce this; review must.

## Alternatives Considered

1. **Single `Metric<T>` generic with a `kind` field.** Rejected — too
   easy to misuse. A function that takes `Metric<unknown>` accepts any
   kind; the runtime check is the only defense and is easy to forget.
   The branded-type approach makes the misuse a compile error.
2. **Runtime-only checks (no compile-time enforcement).** Rejected —
   `spec/00-thesis.md` §4.6 and `spec/17-conformance.md` §3 require
   that the forbidden pipelines be impossible. "Impossible" means the
   type system rejects them; runtime catches misuse only when
   exercised, which is too late.
3. **A single `Evidence<T>` type with a private constructor.**
   Considered — closer to the chosen design, but the brand makes the
   evidence category part of the type signature of every function
   that handles evidence, which makes the API self-documenting.
4. **A class hierarchy (OOP).** Rejected — adds boilerplate;
   TypeScript's structural typing makes class-based brand isolation
   less rigid than the phantom-brand approach.
5. **`@tsplus/data/Brand` or `io-ts`.** Considered — would be
   acceptable but adds a runtime dependency. The hand-rolled brand is
   one line of TypeScript with no dependencies.

## References

- `spec/00-thesis.md` §4.2 — Knowledge Separation invariant.
- `spec/00-thesis.md` §4.6 — Evidence Types table.
- `spec/06-topology.md` §1 — topology as provenance-tagged evidence
  store.
- `spec/17-conformance.md` §3 — executable guards against forbidden
  pipelines (the meta-rule this ADR operationalizes).
- `spec/17-conformance.md` §3.2 — `RemoteNodeHint → AuthenticatedNodeRecord`
  forbidden pipeline (one specific instance of evidence promotion
  forbidden).
- ADR 0007 — AuthenticatedNodeRecord pipeline design (one specific
  evidence-boundary enforcement).
- ADR 0010 — architecture regression tests as build gate (where the
  executable enforcement lives).
- Michael Nygard ADR template — structural source.
