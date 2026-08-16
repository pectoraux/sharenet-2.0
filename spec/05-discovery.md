# ShareNet 2.0 — Discovery

**Status:** Normative. This document defines the Discovery phase, its
outputs, its sources, and the strict separation between Discovery and
the three phases that follow it.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Discovery Is Not Routing

ShareNet defines four distinct, non-interchangeable phases:

| Phase                   | Output                                                | Specification                  |
|-------------------------|-------------------------------------------------------|--------------------------------|
| Discovery               | Candidate destinations + distance hints (metadata).   | This document.                 |
| Path Validation         | Verified next-hop reachability along a candidate path.| `spec/07-routing.md` §3.       |
| Route Construction      | A `CommittedRoute` with participant acceptance.        | `spec/07-routing.md` §5.       |
| Circuit Establishment   | An `ActiveCircuit` running AEAD over the route.       | `spec/08-circuits.md`.         |

A common implementation error is to collapse these into a single
"topology graph → Dijkstra → route" pipeline. That collapse is
**forbidden** by `spec/17-conformance.md` §3.1.

## 2. Discovery Output

The Discovery phase produces **only** `CandidateDestination` records:

```
CandidateDestination = {
  node_id_hint:   text,            ; claimed NodeId, NOT yet authenticated
  reported_by:    text | "self",   ; NodeId of the reporting node, or "self"
  endpoint_hints: [+ Endpoint],    ; advertised endpoints (per spec/03 §2)
  distance_hint:  uint | null,     ; 0 = same subnet, larger = further
  last_seen:      uint,            ; Unix seconds, per reporter's clock
  evidence_type:  "REPORTED" | "OBSERVED"
}
```

A `CandidateDestination` is **unverified metadata**. It MUST NOT be
used as a routing next-hop. It MUST NOT be used as a circuit relay. It
MUST NOT be persisted as an `AuthenticatedNodeRecord`.

To convert a `CandidateDestination` into a usable peer, the node MUST
complete the Link creation pipeline of `spec/04-links.md` §3, which
produces an `AUTHENTICATED`-evidenced Link.

## 3. Discovery Sources

A node MAY draw `CandidateDestination`s from any of the following
sources. Each source has its own trust profile.

### 3.1 Bootstrap Endpoints

- Source: hard-coded or operator-configured URLs / IP:port pairs.
- Trust: `OBSERVED` (the node directly contacted the bootstrap), but
  the resulting NodeId is not authenticated until handshake completes.
- Mechanism: HTTPS fetch of a signed bootstrap manifest, or direct
  dial to a known node's advertised endpoint.
- The bootstrap manifest MUST itself be signed by an Ed25519 key whose
  NodeId is configured at install time. Bootstrapping with an
  unauthenticated manifest is a specification violation.

### 3.2 Peer Referrals (`RemoteNodeHint`)

- Source: an authenticated peer (Link in state `LINK_UP`) reports
  another node it claims to know.
- Trust: `REPORTED`.
- The referral is carried as a `RemoteNodeHint`; see
  `spec/06-topology.md` for the full type definition.
- A node receiving a referral MUST NOT promote it to an
  `AuthenticatedNodeRecord` without independently completing the Link
  creation pipeline.

### 3.3 DNS-Based Discovery

- Source: DNS TXT / SRV records in a configured zone, e.g.
  `_sharenet._tcp.example.com`.
- Trust: `REPORTED` (the DNS resolver is the reporter).
- Records MUST be signed by the zone's Ed25519 key (DNSSEC or
  application-layer signature in TXT payload).
- The discovered NodeId is unverified until handshake.

### 3.4 Local LAN Multicast

- Source: a node periodically announces itself on the local multicast
  group `238.0.0.1:17890` (IPv4) / `ff02::1` (IPv6).
- Trust: `OBSERVED` (the local node saw the packet on the wire).
- The announcement payload is a NodeAdvertisement (see
  `spec/03-node-advertisements.md`); the Link handshake MUST still be
  completed before the peer is usable.

### 3.5 Local Files / Configuration

- Source: a file on disk listing known peers (operator-curated).
- Trust: `OBSERVED` (the operator wrote the file).
- The file MUST be signed by an operator key whose NodeId is
  provisioned at install time.

## 4. Distance Hints Are Metadata, Not Instructions

A `distance_hint` is a **scalar metadata value** reported by the
reporting node. It MAY be used to prioritize discovery attempts (try
closer candidates first), but it MUST NOT be used as a routing metric
in a Dijkstra-style computation. In particular:

1. Distance hints from different reporters MUST NOT be compared
   directly; each reporter uses its own scale.
2. Distance hints MUST NOT be summed across hops to estimate end-to-end
   cost.
3. Distance hints MUST NOT be used to choose a next-hop; next-hops are
   chosen only after Path Validation (see `spec/07-routing.md` §4).

## 5. Discovery Output Provenance

Every `CandidateDestination` MUST carry the NodeId of its reporter
(or `"self"` for sources the local node observed directly). This
provenance is REQUIRED so that downstream topology propagation (see
`spec/06-topology.md`) can attach the reporter's signature and enforce
bounded propagation.

A `CandidateDestination` with `reported_by == "self"` MAY be promoted
to `AuthenticatedNodeRecord` after the Link handshake succeeds. A
`CandidateDestination` with any other `reported_by` MUST NOT be
promoted without first completing the Link handshake; the resulting
record's `evidence_type` will be `AUTHENTICATED` and its provenance
will be the local node.

## 6. Invariants

1. Discovery MUST NOT execute any routing decision.
2. Discovery MUST NOT construct a circuit.
3. Discovery MUST NOT sign on behalf of any node other than the
   reporter.
4. Discovery output is unverified until authenticated.
5. A `CandidateDestination` whose `reported_by` is on the revocation
   list MUST be discarded.

## 7. Cross-References

- Link creation pipeline: `spec/04-links.md` §3.
- `RemoteNodeHint` type: `spec/06-topology.md` §2.
- Routing pipeline that consumes authenticated peers:
  `spec/07-routing.md` §3.
- Forbidden pipeline: `RemoteNodeHint → Circuit`: `spec/08-circuits.md`
  §2.
