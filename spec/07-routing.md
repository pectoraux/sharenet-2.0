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

Emitted by the source. Describes the proposed path and the negotiated
service terms.

Per R-003/R-004 final reconciliation: `RouteProposal` does NOT contain
a `routeId` field. The only route identity is the `commitment_root`
(derived via the Merkle construction in §5.3.1). A caller-chosen
pre-ID MUST NOT influence the final `route_id`.

```
RouteProposal = {
  hops:               [+ RouteHop],   ; ordered hop descriptors
  requirementDigest:  text,           ; hex of BLAKE3-256 of ServiceRequirement
  expiry:             uint,           ; Unix seconds
  initiatorNodeId:    text,           ; NodeId of the source
  agreementDigest:    text,           ; hex of BLAKE3-256 of negotiated terms
}

RouteHop = {
  nodeId:        text,                ; NodeId of the hop
  capability:    text,                ; "MESH_RELAY" | "INTERNET_GATEWAY" | ...
  endpoint:      text,                ; e.g. "10.0.0.1:7788"
  linkUp:        bool,                ; MUST be true for committed routes
  serviceAgreement?: ServiceAgreement, ; optional at proposal, required at commitment
}
```

Signature domain: `"SHARENET/ROUTE/PROPOSAL/1"`.

The canonical encoding for signing and Merkle leaf construction uses
integer-keyed CBOR maps (ADR-0004) over the semantically-significant
fields. The `routeId` field is NOT included in the proposal or its
canonical encoding.

### 5.2 RouteAcceptance

Emitted by **each hop** in response to a RouteProposal. Acceptance is
per-hop: a hop accepts the proposal as it applies to that hop's role
in the path.

Per R-003: the acceptance cryptographically binds the exact proposal,
hop descriptor, and service agreement via carried digests (no TOCTOU).

```
RouteAcceptance = {
  proposalDigestHex:  text,           ; hex of BLAKE3-256 of canonical RouteProposal
  hopIndex:           uint,           ; which hop this acceptance is for
  hopDigestHex:       text,           ; hex of BLAKE3-256 of canonical HopDescriptor
  serviceDigestHex:   text,           ; hex of BLAKE3-256 of canonical ServiceAgreement
  acceptorNodeId:     text,           ; NodeId of the acceptor
  acceptanceNonce:   bstr .size 16,   ; fresh per-acceptance nonce
  expiry:             uint,           ; Unix seconds
  signature:         bstr .size 64,   ; Ed25519 by acceptor
}
```

Signature domain: `"SHARENET/ROUTE/ACCEPTANCE/1"`.

The acceptance signature payload binds: `domain || proposal_digest ||
hop_index || hop_digest || service_digest || acceptor_node_id ||
nonce || expiry`. The digests are carried explicitly (not recomputed
from mutable objects) to prevent TOCTOU.

### 5.3 RouteCommitment

Assembled by the source after collecting one `RouteAcceptance` per hop
in the proposal. The commitment is a Merkle root over the ordered
acceptances plus the proposal; this root becomes the route's identity.

```
RouteCommitment = {
  commitment_version: 1,
  proposal:           RouteProposal,
  acceptances:        [+ RouteAcceptance],
  commitment_root:    bstr .size 32, ; BLAKE3-256 of canonical merkle
  commitment_nonce:   bstr .size 16,
  source_signature:   bstr .size 64, ; Ed25519 by source over the rest
}
```

Signature domain: `"SHARENET/ROUTE/COMMITMENT/1"`.

#### 5.3.1 Canonical Merkle Commitment Construction (FROZEN)

The `commitment_root` is computed via a canonical Merkle tree. The
exact algorithm is frozen here; all implementations MUST produce
identical bytes for the same inputs.

**Domain separation:**
`"SHARENET/ROUTE/COMMITMENT/MERKLE/1"`

**Leaf encoding:**

Each leaf is a BLAKE3-256 hash of a domain-prefixed canonical encoding:

```
proposal_leaf  = BLAKE3-256(
    utf8("SHARENET/ROUTE/COMMITMENT/MERKLE/1")
    || u8(0x00)                          ; leaf-type: proposal (0x00)
    || canonicalEncode(RouteProposal)    ; canonical CBOR of the proposal
)

acceptance_leaf_i = BLAKE3-256(
    utf8("SHARENET/ROUTE/COMMITMENT/MERKLE/1")
    || u8(0x01)                          ; leaf-type: acceptance (0x01)
    || u32be(i)                          ; hop index (4 bytes, big-endian)
    || canonicalEncode(RouteAcceptance_i) ; canonical CBOR of acceptance i
)
```

**Leaf ordering:**

The leaves are ordered as:
```
[proposal_leaf, acceptance_leaf_0, acceptance_leaf_1, ..., acceptance_leaf_N-1]
```

The proposal leaf is always first; acceptance leaves follow in hop-index
order (0, 1, 2, ...). This ordering is fixed and MUST NOT vary.

**Parent hashing:**

Each internal node is:
```
parent = BLAKE3-256(
    utf8("SHARENET/ROUTE/COMMITMENT/MERKLE/1")
    || u8(0x02)                          ; node-type: internal (0x02)
    || left_child                         ; 32 bytes
    || right_child                        ; 32 bytes
)
```

**Odd-node handling:**

When a level has an odd number of nodes, the last node is duplicated
(promoted to the next level by pairing with itself). This is the
standard "duplicate last" Merkle approach.

**Tree shape:**

The tree is built bottom-up: hash all leaves at level 0, then pair and
hash to produce level 1, and so on until a single root remains. If there
is only one leaf, that leaf IS the root (no duplication at the
single-leaf level).

**Commitment nonce inclusion:**

The `commitment_nonce` (16 bytes) is NOT part of the Merkle tree. It
is included in the `source_signature` signing payload (see §5.3.2) to
ensure each commitment is unique even with identical proposal +
acceptances. The `commitment_root` itself does not depend on the nonce.

**commitment_root:**

The `commitment_root` is the final single hash at the root of the
Merkle tree (32 bytes). It is the canonical cryptographic identity of
the accepted route.

#### 5.3.2 Source Signature over the Commitment (FROZEN)

The source signs over the `commitment_root` and `commitment_nonce`:

```
signature_payload = utf8("SHARENET/ROUTE/COMMITMENT/1")
    || commitment_root      ; 32 bytes
    || commitment_nonce     ; 16 bytes
```

The signature transitively binds the proposal + all ordered acceptances
(via the commitment_root) plus the fresh nonce.

### 5.4 CommittedRoute

The state object a node holds once a `RouteCommitment` is finalized.
It is the **only** input that the Circuit layer MAY consume (see
`spec/08-circuits.md` §2).

```
CommittedRoute = {
  commitment:         RouteCommitment,
  route_id:           text,    ; "route:" + lowercase_hex(commitment_root)
  established_at:      uint,
  state:              "ACTIVE" | "EXPIRED" | "REVOKED",
}
```

`route_id` is `"route:" + lowercase_hex(commitment_root)` and is the
canonical handle for the route. The `route:` prefix distinguishes route
identifiers from other hex-encoded identifiers in the ShareNet
ecosystem (e.g. NodeId, CircuitId).

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
