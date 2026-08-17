# ShareNet 2.0 — Routing

**Status:** Normative. This document fixes the routing pipeline,
enumerates the distinct routing objects, and forbids the
"topology-graph → Dijkstra → route" shortcut.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Routing Is Not Dijkstra

A common implementation error is:

```
TopologyGraph ──> Dijkstra ──> Route
```

This collapse is **forbidden**. It treats `REPORTED` hints as if they
were `AUTHENTICATED` links, treats distance hints as if they were
routing metrics, and treats the source's view of the graph as if it
were a participant-accepted route.

The correct ShareNet pipeline is the nine-step sequence of §2.

## 2. The Routing Pipeline

```
1. Discovery                    (spec/05)
        │  produces CandidateDestination[]
        ▼
2. Candidate Destination        (this section)
        │  source node picks one or more candidate destinations
        ▼
3. Destination Authentication  (spec/04 §3)
        │  source completes Link handshake with destination
        ▼
4. Next-Hop Discovery            (spec/05)
        │  for each candidate relay, source discovers the next hop
        ▼
5. Path Validation               (this section §4)
        │  source verifies each hop can actually carry traffic
        ▼
6. Service Negotiation           (spec/09 §4)
        │  source negotiates service class with the destination
        ▼
7. Route Proposal                (this section §5.1)
        │  source emits RouteProposal to all hops
        ▼
8. Route Acceptance              (this section §5.2)
        │  each hop returns a signed RouteAcceptance
        ▼
9. Committed Route              (this section §5.3)
        │  source assembles acceptances into a RouteCommitment
        ▼
        Circuit Establishment    (spec/08)
```

No step MAY be skipped. In particular, step 8 (Route Acceptance) is
REQUIRED: a source signature on a RouteProposal does NOT constitute
participant acceptance.

## 3. Distance Hints Are Not Routing Metrics

`distance_hint` values produced by Discovery (see `spec/05-discovery.md`
§4) are **metadata**. They MAY inform the order in which candidate
destinations are tried in step 2. They MUST NOT:

1. Be summed across hops to compute an end-to-end metric.
2. Be used as edge weights in a Dijkstra computation.
3. Be used as the sole basis for next-hop selection in step 4.

Next-hop selection in step 4 MUST be based on `AUTHENTICATED` Link
records (see `spec/04-links.md` §4) and on Path Validation results
from step 5.

## 4. Path Validation

Path Validation is the process by which the source node verifies that
a candidate next-hop can actually carry traffic toward the destination.
It produces a `PathValidationResult`:

```
PathValidationResult = {
  source_id:       text,
  next_hop_id:     text,
  destination_id:  text,
  measured_rtt_ms: uint,
  measured_loss_pct: uint,
  valid_until:     uint,           ; Unix seconds
  signature:       bstr .size 64,  ; Ed25519 by source over the rest
}
```

Path Validation is performed by sending a probe over each Link and
receiving an authenticated acknowledgement. It is **per-link**, not
end-to-end. The source accumulates `PathValidationResult`s for each
hop in the candidate path.

## 5. Routing Objects

Routing uses four distinct object types. They MUST NOT be conflated.

### 5.1 RouteProposal

Emitted by the source. Describes the proposed path, the service class,
and the requested bandwidth.

```
RouteProposal = {
  proposal_version:   1,
  source_id:          text,
  source_pubkey:      bstr .size 32,
  destination_id:     text,
  hops:               [+ text],    ; ordered NodeId list, excluding source
  service_class:      text,        ; e.g. "internet-egress-https"
  requested_bps:      uint,
  requested_duration: uint,        ; seconds
  proposal_nonce:     bstr .size 16,
  proposal_sequence:  uint,        ; source's monotonic counter
  expiry:             uint,        ; Unix seconds
  signature:          bstr .size 64, ; Ed25519 by source
}
```

Signature domain: `"SHARENET/ROUTE/PROPOSAL/1"`.

### 5.2 RouteAcceptance

Emitted by **each hop** (and by the destination) in response to a
RouteProposal. Acceptance is per-hop: a hop accepts the proposal as
it applies to that hop's role in the path.

```
RouteAcceptance = {
  acceptance_version:  1,
  proposal_hash:        bstr .size 32, ; BLAKE2b-256 of canonical RouteProposal
  acceptor_id:          text,
  acceptor_pubkey:      bstr .size 32,
  accepted_role:        "relay" | "gateway",
  accepted_bps:         uint,        ; may be less than requested
  accepted_duration:    uint,
  acceptance_nonce:     bstr .size 16,
  expiry:               uint,
  signature:            bstr .size 64, ; Ed25519 by acceptor
}
```

Signature domain: `"SHARENET/ROUTE/ACCEPTANCE/1"`.

### 5.3 RouteCommitment

Assembled by the source after collecting one `RouteAcceptance` per hop
in the proposal. The commitment is a Merkle root over the ordered
acceptances plus the proposal; this root becomes the route's identity.

```
RouteCommitment = {
  commitment_version: 1,
  proposal:           RouteProposal,
  acceptances:        [+ RouteAcceptance],
  commitment_root:    bstr .size 32, ; BLAKE2b-256 of canonical merkle
  commitment_nonce:   bstr .size 16,
  source_signature:   bstr .size 64, ; Ed25519 by source over the rest
}
```

Signature domain: `"SHARENET/ROUTE/COMMITMENT/1"`.

### 5.4 CommittedRoute

The state object a node holds once a `RouteCommitment` is finalized.
It is the **only** input that the Circuit layer MAY consume (see
`spec/08-circuits.md` §2).

```
CommittedRoute = {
  commitment:         RouteCommitment,
  route_id:           text,    ; hex of commitment_root
  established_at:      uint,
  state:              "ACTIVE" | "EXPIRED" | "REVOKED",
}
```

`route_id` is `route:hex(commitment_root)` and is the canonical handle
for the route.

## 6. Invariants

1. A `RouteProposal` is **not** a route. It is a request.
2. A source signature on a `RouteProposal` does **not** constitute
   participant acceptance. Every hop MUST sign its own
   `RouteAcceptance`.
3. A `CommittedRoute` exists only when the source has one
   `RouteAcceptance` per hop in the proposal.
4. A `CommittedRoute` is the **only** input to circuit construction.
5. Distance hints are discovery metadata; they are not routing metrics.
6. Routing decisions MUST be re-evaluated when any Link in the path
   leaves `LINK_UP` state (see `spec/04-links.md` §4).

## 7. Cross-References

- Discovery: `spec/05-discovery.md`.
- Link state machine: `spec/04-links.md` §4.
- Topology hints (which MUST NOT be used as routing input):
  `spec/06-topology.md` §3.
- Circuit construction from a CommittedRoute: `spec/08-circuits.md` §2.
- Forbidden pipelines: `spec/17-conformance.md` §3.
