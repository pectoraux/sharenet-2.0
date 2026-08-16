# ShareNet 2.0 — Links

**Status:** Normative. This document defines the Link abstraction, its
directional nature, its state machine, and the pipeline that creates a
Link from an advertisement.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Links Are Directed

A ShareNet Link is a **directed** authenticated transport association
from a local node `A` to a remote node `B`, denoted `A → B`.

- `A → B` does **NOT** imply `B → A`.
- `A → B` and `B → A` are distinct Link objects with distinct state,
  distinct transport connections, and distinct lifetimes.
- A bidirectional association, when it exists, consists of two Links
  in opposite directions. Each MUST be authenticated independently.

The protocol core MUST NOT assume symmetry. Routing decisions, circuit
construction, and topology propagation MUST treat each direction as a
separate fact with separate evidence (see `spec/00-thesis.md` §4.6).

## 2. What a Link Is — and Is Not

A Link **is**:

- A record that node `A` has completed authenticated transport
  connection with node `B`, where `B` presented a NodeAdvertisement
  that verified under the rules in `spec/03-node-advertisements.md` §5.

A Link is **NOT**:

- An advertised endpoint. An endpoint advertised by `B` is a candidate
  for connection; it is not a Link.
- A route. A Link is one hop; routing requires a CommittedRoute (see
  `spec/07-routing.md`).
- A circuit. A Link is a transport association; a circuit is a
  cryptographic tunnel over a route (see `spec/08-circuits.md`).
- An authorization. A Link authenticates identity; it does not grant
  forwarding rights.

## 3. Link Creation Pipeline

A Link MUST be created only through the following pipeline. Any
short-circuit of this pipeline is a specification violation.

```
NodeAdvertisement(B)
        │
        ▼
candidate endpoint selection
        │
        ▼
transport connection attempt  (TCP / WS / QUIC / LAN)
        │
        ▼
handshake: A sends own advertisement + nonce challenge
        │
        ▼
B responds with its advertisement + signature over challenge
        │
        ▼
peer authentication (verify per spec/03 §5)
        │
        ▼
A → B Link state := LINK_UP
        │
        ▼
B independently authenticates A (separate handshake)
        │
        ▼
B → A Link state := LINK_UP    (only if B also succeeds)
```

At every stage before `LINK_UP`, the Link is in `LINK_PENDING` and
MUST NOT be used for routing, circuit construction, or topology
propagation as if it were an established Link.

### 3.1 Endpoint Selection

A MAY try multiple candidate endpoints from B's advertisement in
parallel or in sequence. Each attempt is a separate `LINK_PENDING`
Link object, identified by `(local_node_id, remote_node_id,
endpoint, attempt_nonce)`.

### 3.2 Peer Authentication

Peer authentication MUST verify:

1. The remote advertisement under `spec/03-node-advertisements.md` §5.
2. A fresh challenge: A sends 16 random bytes; B signs
   `BLAKE2b("sharenet-link-challenge-v1" || A_node_id || B_node_id
   || challenge)` with its Ed25519 private key. A verifies under
   `B.signing_public_key`.
3. A and B's advertised NodeIds both bind to the keys used.

Only after all three checks pass does the Link enter `LINK_UP`.

> **⚠️ STATUS CORRECTION (2026-08-16, corrective milestone):**
> The current two-message handshake (ADR-0014) does NOT implement the
> challenge-response described in §3.2 above. It verifies signed
> advertisements but does NOT prove fresh possession of the signing key
> bound to the connection transcript. A captured advertisement is replayable.
>
> Therefore the current exchange does NOT establish `LINK_UP`. It establishes
> a weaker state, `ADV_VERIFIED` (advertisement-verified), which is a
> PREREQUISITE for `LINK_UP` but is NOT `LINK_UP` itself.
>
> `LINK_UP` is reserved for the future authenticated handshake defined in
> ADR-0016 (PROPOSAL — awaiting Principal Architect approval).
>
> The only truthful term for the current exchange is
> **"advertisement-verification exchange."**

## 4. Link State Machine

| State           | Meaning                                                                | Transitions Out                       |
|-----------------|------------------------------------------------------------------------|---------------------------------------|
| `LINK_PENDING`  | Transport attempt or handshake in progress; not yet authenticated.     | → `ADV_VERIFIED`, → `LINK_DOWN`.      |
| `ADV_VERIFIED`  | Advertisements verified; NOT yet authenticated (replay-vulnerable). NOT eligible for routing. | → `LINK_UP` (future, requires ADR-0016), → `LINK_DOWN`. |
| `LINK_UP`       | Authenticated (fresh key possession proven), transport healthy. Eligible for routing. **Not yet implemented** (requires ADR-0016). | → `LINK_DEGRADED`, → `LINK_DOWN`. |
| `LINK_DEGRADED` | Authenticated, but transport exhibiting high loss / latency / errors. **Not yet implemented.** | → `LINK_UP`, → `LINK_DOWN`.           |
| `LINK_DOWN`     | Transport broken or authentication failed. Not eligible for routing.  | → `LINK_PENDING` (re-attempt), or terminal. |

**Current implementation status:** the reference mini-service (`mini-services/node-link/`)
reaches `ADV_VERIFIED` only. It does NOT reach `LINK_UP`. `LINK_UP` is
gated on ADR-0016 (replay-defect repair + transcript binding).

### 4.1 Transition Rules

- `LINK_UP → LINK_DEGRADED`: when round-trip latency exceeds
  `DEGRADED_LATENCY_MS = 800` OR packet loss exceeds
  `DEGRADED_LOSS_PCT = 25` over a sliding 30-second window.
- `LINK_DEGRADED → LINK_UP`: when both metrics return below thresholds
  for a sliding 60-second window.
- Any state → `LINK_DOWN`: on transport close, authentication failure,
  or operator-initiated close.
- `LINK_DOWN → LINK_PENDING`: only via an explicit re-attempt, which
  MUST re-run the full handshake of §3.2.

## 5. Link Records

A Link record MUST contain at minimum:

| Field                | Type            | Notes                                                      |
|----------------------|-----------------|------------------------------------------------------------|
| `local_node_id`      | text            | The NodeId of the node recording the Link.                 |
| `remote_node_id`     | text            | The NodeId at the other end.                               |
| `direction`          | enum            | `OUTBOUND` for `A → B` recorded by A; `INBOUND` for `B → A` recorded by B. |
| `endpoint`            | map              | The endpoint that succeeded.                               |
| `state`              | enum            | See §4.                                                    |
| `established_at`     | uint            | Unix seconds.                                              |
| `last_seen`          | uint            | Unix seconds of last healthy round-trip.                    |
| `evidence_type`      | enum            | Always `AUTHENTICATED` for a `LINK_UP` Link. See `spec/00-thesis.md` §4.6. |
| `latency_ms_p50`     | uint            | Rolling p50 latency.                                       |
| `loss_pct`           | uint            | Rolling loss percentage (0–100).                           |

## 6. Invariants

1. A Link `A → B` in state `LINK_UP` MUST have `evidence_type ==
   AUTHENTICATED`. No other evidence type is acceptable for a usable
   Link.
2. A Link in `LINK_PENDING` MUST NOT be advertised to other peers as a
   usable hop. It MAY be reported as `OBSERVED`-evidenced
   "in-progress attempt" if the local node chooses to publish such
   hints; this is a `RemoteNodeHint` (see `spec/06-topology.md`), not
   a Link.
3. A Link MUST NOT be created from a `RemoteNodeHint`. Hints produce
   candidate destinations for discovery; only an authenticated
   transport handshake produces a Link.
4. A Link's state MUST be re-evaluated on every transport event; stale
   state MUST NOT be served to the routing layer.

## 7. Cross-References

- Advertisement verification: `spec/03-node-advertisements.md` §5.
- Discovery outputs that feed candidate endpoints: `spec/05-discovery.md` §3.
- Topology hint type: `spec/06-topology.md` §2.
- Routing layer that consumes `LINK_UP` Links: `spec/07-routing.md` §3.
- Circuit layer that runs over Links: `spec/08-circuits.md` §5.
