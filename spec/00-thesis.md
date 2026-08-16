# ShareNet 2.0 — Core Thesis

**Status:** Normative. This document defines what ShareNet 2.0 IS, what it IS
NOT, and the architectural invariants that all subsequent specifications,
ADRs, schemas, golden vectors, conformance tests, and implementations
MUST respect.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Product Thesis

ShareNet 2.0 is a **cross-platform, delay-tolerant, distributed network**
that allows devices with no direct Internet reachability to access the
real Internet through a chain of cooperating nodes — relays and
gateways — without surrendering end-to-end cryptographic authenticity or
economic accountability.

A device that has no working Internet transport of its own (mobile data
off, Wi-Fi off, captive portal blocking, hostile NAT, censorship) MAY
still send and receive authenticated traffic to the public Internet if
and only if:

1. It can establish at least one authenticated transport link to another
   ShareNet node, and
2. A path exists, through that node and zero or more further relays, to a
   node that holds an active, authorized **Internet Gateway** capability
   with available capacity, and
3. The originating node (or a sponsoring principal) is authorized under
   that gateway's policy to use the gateway, and
4. Every relay and gateway on the path accepts the circuit.

### 1.1 Proof Diagram

The single canonical proof of ShareNet's thesis is the following traffic
flow:

```
+--------+       +-----------+      +-----------+      +-----------+      +-----------+      +--------------+
| Device | ----> | ShareNet  | ---> | Relay A   | ---> | Relay B   | ---> | Internet  | ---> | REAL         |
| (no    |  auth | local     |      | (ShareNet |      | (ShareNet |      | Gateway   |      | INTERNET     |
|  net)  |       | node      |      |  relay)   |      |  relay)   |      | (egress)  |      | HTTPS server |
+--------+       +-----------+      +-----------+      +-----------+      +-----------+      +--------------+
                                                                                                  |
                                                       response flows back over same circuit         |
                                                                                                  v
```

Every phase of the build MUST advance the system toward making this
diagram work end-to-end with **all** invariants preserved. Any feature
that cannot be located on this diagram MUST NOT be added to the protocol
core.

## 2. What ShareNet IS

1. A **protocol** for authenticating peers, advertising capabilities,
   discovering candidate destinations, validating paths, constructing
   committed routes, and establishing cryptographic circuits.
2. A **distributed network** of independently operated nodes that agree
   to forward traffic under explicit, signed, revocable authorization.
3. An **accountability layer**: every byte forwarded by a gateway is
   attributable to a NodeId, a circuit, an authorization, and a signed
   receipt.
4. A **gateway framework** that allows a node operator with real
   Internet egress to expose that egress to other ShareNet principals
   under their own policy, quota, and revocation rules.

## 3. What ShareNet IS NOT

1. ShareNet is **NOT "free Internet."** A gateway's bandwidth, a relay's
   electricity, and a path's latency all have real economic cost.
   ShareNet MUST NOT imply that any participant is obligated to forward
   traffic without compensation agreed under explicit policy.
2. ShareNet is **NOT a circumvention tool in the legal sense.** It is a
   network architecture. Jurisdictional compliance is the operator's
   responsibility; the protocol does not encode jurisdictional bypass.
3. ShareNet is **NOT a content-distribution network at the core.** The
   content layer (see `spec/10-content.md`) is layered above the mesh
   and MUST NOT contaminate the network layer.
4. ShareNet is **NOT a blockchain.** Civic Points (see
   `spec/12-civic-points.md`) begin as internal accounting credits, not
   as on-chain assets.
5. ShareNet is **NOT an open proxy.** A gateway MUST never forward
   arbitrary traffic to arbitrary destinations without policy, capacity,
   and authorization checks (see `spec/09-internet-gateway.md`).

## 4. Architectural Invariants

These six invariants are **non-negotiable**. Any implementation,
platform adapter, or future ADR that violates one MUST be rejected at
conformance review.

### 4.1 Identity Separation

Human Identity ≠ Device Identity ≠ Node Identity ≠ Application
Identity ≠ Economic Identity. These are distinct objects with distinct
lifetimes, distinct attestation mechanisms, and distinct revocation
paths. See `spec/02-identity.md`.

A NodeId authenticates a cryptographic key. It does not authenticate a
human, a billing account, or a legal entity. Conflating these is a
specification violation.

### 4.2 Knowledge Separation

What a node **has observed directly** is not the same as what a node
**has been told** by another node. The protocol MUST distinguish these
two knowledge classes at the type level — see the Evidence Type
enumeration in §4.6 below. Treating a reported fact as an authenticated
fact is a specification violation.

### 4.3 Gateway Semantics Separation

Possessing the `INTERNET_GATEWAY` capability (see
`spec/09-internet-gateway.md`) does not imply that the gateway is
usable, authorized, or has capacity. Five distinct objects —
GatewayCapability, GatewayPolicy, GatewayAuthorization,
GatewayCapacity, GatewayMeasurement — MUST NOT be collapsed into a
single boolean "is a gateway".

### 4.4 Economics Separation

Contribution (forwarded bytes) ≠ ContributionProof (signed receipt) ≠
CivicPoints (internal credit) ≠ Settlement (accounting transfer) ≠
ExternalCryptocurrency (on-chain asset). See `spec/11-contribution.md`,
`spec/12-civic-points.md`, and `spec/13-external-crypto.md`. Each is a
distinct type with a distinct lifecycle.

### 4.5 Routing Separation

Discovery, path validation, route construction, and circuit
establishment are four distinct phases with distinct objects. A
topology graph is NOT a routing table; a route proposal is NOT a
committed route; a committed route is NOT an active circuit. See
`spec/07-routing.md` and `spec/08-circuits.md`.

### 4.6 Evidence Types

Every claim that a node records about another node MUST carry an
explicit evidence type drawn from this closed enumeration:

| Evidence Type    | Meaning                                                         | Replayable as Authenticated? |
|------------------|-----------------------------------------------------------------|------------------------------|
| `AUTHENTICATED`  | The recording node performed direct cryptographic verification. | Yes (within validity window) |
| `OBSERVED`       | The recording node observed the fact directly but did not cryptographically verify it (e.g., saw a transport-level packet). | No — must be re-observed. |
| `REPORTED`       | Another node claimed the fact; the recording node did not verify it. | No — must be re-verified. |
| `DERIVED`        | The recording node computed the fact from prior authenticated or observed facts by a documented derivation rule. | Only with the derivation chain. |
| `INFERRED`       | The recording node guessed the fact heuristically; no cryptographic or observational basis. | Never. |

A fact stored as `REPORTED` MUST NOT be promoted to `AUTHENTICATED`
without a fresh `AUTHENTICATED`-typed observation. The conformance suite
MUST include a regression test that fails any pipeline which performs
such a promotion (see `spec/17-conformance.md`).

## 5. Out-of-Scope for the First Deliverable

The following are explicitly out of scope for the first deliverable but
are listed here to constrain over-implementation:

- The content layer (`spec/10-content.md`) is specified but not built.
- The contribution and civic-points pipelines (`spec/11-contribution.md`,
  `spec/12-civic-points.md`) are specified but not built.
- The external-cryptocurrency bridge (`spec/13-external-crypto.md`) is
  specified but not built.
- Platform adapters (`spec/16-platforms.md`) beyond Linux TUN are
  specified but not built.

The first deliverable MUST demonstrate the proof diagram of §1.1 on a
single Linux host using TUN, with at least two relays and one gateway,
end-to-end, with all identity, advertisement, link, discovery,
topology, routing, and circuit invariants preserved.
