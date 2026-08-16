# ShareNet 2.0 — Protocol Architecture

**Status:** Normative. This document fixes the build order of every
artifact in the project, the repository layout, the phase progression,
and the stop conditions.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. The Protocol-First Rule

Every behavioral feature in ShareNet 2.0 MUST be produced in the
following order. No step MAY begin before its predecessor is merged.

```
Spec  →  ADR  →  Schema  →  Golden Vector  →  Conformance Test  →  Reference Implementation  →  Platform Implementation
```

| # | Artifact                   | Owner            | Acceptance                                                                                |
|---|----------------------------|------------------|-------------------------------------------------------------------------------------------|
| 1 | `spec/NN-*.md`             | Spec author      | Normative prose + wire format; merged to `main`.                                          |
| 2 | `adr/NNNN-*.md`            | ADR author       | Records the decision and its alternatives; merged to `main`.                              |
| 3 | `conformance/schemas/*`    | Schema author    | Machine-checkable JSON Schema / CDDL for the wire format.                                |
| 4 | `conformance/vectors/*`    | Vector author    | Canonical byte vectors with expected hashes / signatures.                                 |
| 5 | `conformance/tests/*`      | Conformance author | Test that consumes the schema + vectors and fails on deviation.                       |
| 6 | `reference/*` (TypeScript) | Reference author | Implements the spec; passes the conformance test.                                         |
| 7 | `platform/*`               | Platform author  | Wraps the reference implementation for a specific OS; MUST NOT introduce new semantics.  |

A platform adapter that introduces a new protocol behavior without
steps 1–6 MUST be rejected at code review. The protocol core is
platform-agnostic by construction.

## 2. Repository Layout

The repository MUST match this layout. Directories marked `(later)`
MAY be empty in the first deliverable but MUST exist.

```
spec/                       Normative specifications (this directory).
adr/                        Architecture Decision Records.
conformance/
  vectors/                  Canonical byte vectors (golden).
  schemas/                  JSON Schema / CDDL for wire formats.
  fixtures/                 Example advertisement, route, circuit bytes.
  tests/                    Executable architecture regression tests.
reference/
  crypto/                   Canonical CBOR, BLAKE2b, Ed25519, X25519 wrappers.
  encoding/                 CBOR deterministic encoding helpers.
  identity/                 NodeId derivation + Ed25519 keypair.
  advertisement/            NodeAdvertisement canonical form + verification.
  link/                     Link state machine.
  discovery/                Discovery sources.
  topology/                 RemoteNodeHint type + propagation.
  routing/                  RouteProposal, RouteAcceptance, RouteCommitment.
  circuit/                  CircuitSetup, ActiveCircuit, AEAD framing.
  gateway/                  Gateway policy, authorization, measurement.
  ledger/                   ContributionLedger, CivicPoints.
platform/
  linux/tun/                Linux TUN adapter.
  windows/    (later)
  macos/      (later)
  android/    (later)
  ios/        (later)
web/                        Web application (auth, dashboard, admin, demo).
  auth/  waitlist/  admin/  demo/
migrations/                 SQL migrations.
docs/                       Operator + developer documentation.
legacy/                     Frozen artifacts from ShareNet 1.x, kept for audit only.
```

## 3. Phase Progression

The project advances through twelve phases. Each phase has an explicit
exit condition. No phase MAY be skipped.

| Phase | Name                         | Exit Condition                                                                                            |
|-------|------------------------------|-----------------------------------------------------------------------------------------------------------|
| 0     | Spec + ADR scaffolding       | This directory + `adr/` merged to `main`.                                                                  |
| 1     | Crypto primitives            | Canonical CBOR + BLAKE2b + Ed25519 + X25519 pass golden vectors.                                          |
| 2     | Identity                     | NodeId derivation passes golden vectors; identity binding invariant holds.                                |
| 3     | Advertisements              | NodeAdvertisement canonical form + verification pass conformance.                                         |
| 4     | Links                        | Authenticated transport link brings a peer from `LINK_PENDING` to `LINK_UP`.                              |
| 5     | Discovery + Topology         | Bootstrap, peer referrals, DNS, LAN multicast produce `RemoteNodeHint`s; promotion guard passes.         |
| 6     | Routing                      | Full pipeline Discovery → … → CommittedRoute produces a committed route with participant acceptance.       |
| 7     | Circuits                     | CommittedRoute → CircuitSetup → ActiveCircuit; AEAD framing, nonces, replay protection verified.           |
| 8     | Internet Gateway             | First end-to-end proof: HTTP(S) request → ShareNet → relay(s) → gateway → real HTTPS server → response.   |
| 9     | Contribution + Civic Points  | Gateway session produces signed receipt → ContributionProof → CivicPoints credit.                         |
| 10    | Platform adapters             | Linux TUN adapter passes the Phase 8 proof diagram on a single host.                                       |
| 11    | External crypto bridge        | Wallet → ShareNet → gateway → real network, with custody never leaving the user.                          |

## 4. Stop Conditions (Section 35)

A build MUST be stopped and re-architected if any of the following
becomes true:

1. A platform adapter introduces a new protocol semantic that is not in
   `spec/`.
2. A conformance test is modified to make a forbidden pipeline pass.
3. An `AUTHENTICATED`-typed claim is produced from a `REPORTED`-typed
   claim without fresh cryptographic verification.
4. A `RemoteNodeHint` is accepted as an `AuthenticatedNodeRecord` (see
   `spec/06-topology.md` §3).
5. A circuit is constructed from anything other than a `CommittedRoute`
   (see `spec/08-circuits.md` §2).
6. A gateway forwards traffic without an `GatewayAuthorization` (see
   `spec/09-internet-gateway.md` §3).
7. A contribution is credited on the basis of self-reported byte counts
   without a signed receipt from the gateway (see
   `spec/11-contribution.md` §2).
8. An expiration causes a sequence floor to reset (see
   `spec/14-security.md` §3).
9. A signature domain is reused across two distinct claim types (see
   `spec/14-security.md` §4).
10. The proof diagram in `spec/00-thesis.md` §1.1 stops working.

## 5. Smallest Correct Implementation Discipline

Every reference module MUST be the **smallest correct implementation**
that satisfies the conformance test for its phase. Adding behavior that
is not required by a conformance test is a code-review failure.

Concretely:

- A module MAY add helpers, but MUST NOT add protocol semantics.
- A module MAY delay work it does not yet need to do, but MUST NOT
  silently substitute a weaker primitive.
- A module MAY stub a later-phase function, but the stub MUST throw at
  runtime, not return an incorrect success.
- A platform adapter MUST NOT carry protocol logic. It MUST ONLY adapt
  between the reference implementation and the OS networking API.

## 6. Cross-References

- Wire-format rules: `spec/03-node-advertisements.md` §3 (canonical CBOR).
- Identity invariants: `spec/02-identity.md` §2.
- Forbidden pipelines (executable guards): `spec/17-conformance.md` §3.
- Phase exit conditions detail: `spec/17-conformance.md` §4.
