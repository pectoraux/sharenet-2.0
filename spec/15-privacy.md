# ShareNet 2.0 — Privacy

**Status:** Normative. This document defines the privacy principles,
metadata leakage analysis, and the privacy-preserving defaults that
every implementation MUST uphold.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Principles

1. **Minimal metadata leakage.** A node MUST reveal the smallest set
   of identifying fields consistent with the protocol's correctness.
2. **Linkability is a cost.** Every stable identifier increases the
   ability of an adversary to correlate a node's activity across
   sessions. Stable identifiers MUST be limited to the NodeId (see
   §4).
3. **Optional relay-only mode.** A node MAY operate in relay-only mode
   (no `INTERNET_GATEWAY` capability) to avoid the increased exposure
   that gateway operation entails.
4. **No covert tracking.** The protocol MUST NOT embed persistent
   tracking identifiers in any field beyond the NodeId.
5. **User control.** A node operator MUST be able to inspect and
   clear all persisted topology data and all audit logs (subject to
   the retention rules in `spec/14-security.md` §5).

## 2. Metadata Leakage Analysis

The following table lists each object ShareNet emits or stores and
classifies the metadata it reveals. "Revealed to" indicates which
parties can observe the field.

| Object                | Field                | Reveals                                 | Revealed To                       |
|-----------------------|----------------------|-----------------------------------------|-----------------------------------|
| NodeAdvertisement     | `node_id`            | Stable NodeId.                          | Anyone who sees the advertisement. |
| NodeAdvertisement     | `endpoints`          | IP addresses / ports of the node.      | Anyone who sees the advertisement. |
| NodeAdvertisement     | `capabilities`       | Node's role (relay / gateway).          | Anyone who sees the advertisement. |
| NodeAdvertisement     | `circuit_public_key` | Stable X25519 key per key lifetime.     | Anyone who sees the advertisement. |
| Link (A→B)            | (existence)          | A and B communicate.                     | A, B, on-path observers of A↔B.   |
| RemoteNodeHint        | `reporter_id`        | Who reported the hint.                  | Hint recipients.                  |
| RemoteNodeHint        | `subject_id`         | Who the hint is about.                  | Hint recipients.                  |
| Circuit               | `route_id`           | The exact route commitment.             | All hops.                         |
| Circuit frames        | `frame_sequence`     | Per-circuit traffic volume / timing.    | Adjacent hops.                    |
| Gateway receipt       | `bytes_count`        | Volume of egress per session.           | Source, gateway, ledger verifier. |
| Gateway receipt       | `circuit_id`         | Correlation between circuit and session.| Source, gateway.                  |

### 2.1 Mitigation Strategies

- **Endpoint rotation.** A node MAY advertise multiple endpoints and
  rotate them periodically (default: every 24h) to reduce IP-based
  correlation. Rotation does NOT change the NodeId.
- **Circuit re-keying.** Re-keying a circuit (see `spec/08-circuits.md`
  §6) produces a fresh `eph_priv`/`eph_pub` and a fresh nonce prefix,
  reducing frame-level linkability across re-key events.
- **Hop-limited hints.** `RemoteNodeHint` propagation is bounded by
  `MAX_HINT_HOPS = 3` (see `spec/06-topology.md` §4), limiting the
  blast radius of topology leakage.

## 3. Endpoint Privacy

A node's `endpoints` array (see `spec/03-node-advertisements.md` §2)
reveals its IP addresses. To reduce exposure:

1. A relay node MAY advertise only `lan-multicast` and `ws` endpoints
   (no raw TCP/IP), trading off reachability for privacy.
2. A node behind a NAT MAY advertise only its public-facing relay's
   endpoint, using that relay as a forwarder for inbound connections.
3. A node MAY omit `endpoints` entirely from its advertisement,
   accepting that it will only be reachable by peers that already
   know an endpoint out-of-band.

A node MUST NOT advertise an endpoint it does not actually control or
cannot actually listen on. Advertising an endpoint belonging to a third
party without their consent is a specification violation.

## 4. Persistent Tracking Identifiers

The NodeId (see `spec/02-identity.md` §2) is the ONLY persistent
tracking identifier that ShareNet emits. Specifically:

1. `node_id` is stable for the lifetime of the signing key.
2. `circuit_public_key` is stable for the lifetime of the X25519
   keypair, which is bound to the signing keypair's lifetime (see
   `spec/02-identity.md` §3).
3. No other field is a stable cross-session identifier. In particular:
   - `nonce` values are fresh per object.
   - `sequence` values are monotonic but not stable across key
     rotation.
   - `endpoint.address` values MAY rotate.
   - Per-circuit `eph_pub` is fresh per circuit.
   - `frame_sequence` resets per circuit.

The protocol MUST NOT introduce new persistent identifiers without an
explicit spec version bump and a privacy review.

## 5. Optional Relay-Only Mode

A node MAY operate in **relay-only mode**:

- The node's advertisement lists `capabilities = ["RELAY"]` only.
- The node does NOT advertise `INTERNET_GATEWAY`.
- The node does NOT expose a gateway policy, gateway authorization, or
  gateway measurement.
- The node MAY still originate traffic as a source.

Relay-only mode reduces a node's exposure because:

- It cannot be a target for gateway abuse (port scanning attempts,
  SSRF probes, etc.).
- Its advertisement reveals less (no `gateway_policy`).
- It cannot be the terminal hop of a circuit carrying egress traffic,
  reducing the volume of metadata it must log.

Operators SHOULD default to relay-only mode unless they have an
explicit reason to operate a gateway.

## 6. Data Minimization in Advertisements

1. The `gateway_policy` field in a NodeAdvertisement (see
   `spec/03-node-advertisements.md` §2) MUST be a digest
   (BLAKE2b-256), not the full policy document. The full policy is
   disclosed only during service negotiation (see
   `spec/09-internet-gateway.md` §3).
2. The `metadata` field in an endpoint (see
   `spec/03-node-advertisements.md` §2) MUST NOT contain identifying
   information beyond what is necessary for transport (e.g.,
   `{"tls": true}` is acceptable; `{"operator_name": "Alice"}` is
   not, unless the operator has explicitly opted in).
3. The `capabilities` array MUST contain only capabilities the node
   actually has. Advertising a capability the node does not implement
   is a specification violation.

## 7. Privacy in Receipts and Ledgers

1. A `ContributionProof` (see `spec/11-contribution.md` §3) reveals
   the beneficiary's NodeId. This is inherent to the contribution
   model and cannot be avoided.
2. The `ContributionLedger` (see `spec/11-contribution.md` §4) is
   append-only and hash-chained. Entries are visible to anyone with
   read access to the ledger.
3. Operators SHOULD restrict ledger read access to the beneficiary,
   the issuer, and operator keys.
4. Receipts MUST NOT contain the destination URL or hostname of the
   egress traffic; only the byte count and timing.

## 8. Cross-References

- NodeId stability: `spec/02-identity.md` §2.
- Advertisement fields: `spec/03-node-advertisements.md` §2.
- Hint propagation bounds: `spec/06-topology.md` §4.
- Gateway egress privacy: `spec/09-internet-gateway.md` §5.
- Audit log retention: `spec/14-security.md` §5.
