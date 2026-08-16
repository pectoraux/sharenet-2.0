# ShareNet 2.0 — Internet Gateway

**Status:** Normative. This document defines the Internet Gateway
model, the five gateway objects that MUST NOT be collapsed, the
service-agreement flow, and the protections a gateway MUST enforce.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Gateway Model

An Internet Gateway is a ShareNet node that holds the
`INTERNET_GATEWAY` capability (see `spec/03-node-advertisements.md`
§6) and exposes real Internet egress to other ShareNet principals
under explicit policy.

A gateway is **not** an open proxy. A gateway is **not** a NAT. A
gateway is a policy-enforcing, metered, revocable egress service.

## 2. Five Distinct Gateway Objects

The following five objects MUST NOT be collapsed into a single boolean
"is a gateway". Each has its own lifecycle, its own attestation, and
its own revocation path.

| Object                  | Meaning                                                                  |
|-------------------------|--------------------------------------------------------------------------|
| `GatewayCapability`    | The node's advertisement claims `INTERNET_GATEWAY`. Self-attested.        |
| `GatewayPolicy`        | The set of rules the gateway will enforce (destinations, ports, quotas). |
| `GatewayAuthorization` | A signed statement that a specific NodeId is permitted to use the gateway. |
| `GatewayCapacity`      | The gateway's current measured throughput headroom (bytes/sec, conns).  |
| `GatewayMeasurement`   | Per-session measured usage (bytes, duration, errors) signed by gateway.  |

Possessing `GatewayCapability` does **not** imply that the gateway is
usable (it may be at capacity), authorized (the requesting node may
lack an authorization), or that traffic will be forwarded (the
destination may violate policy).

## 3. Service Flow

A gateway session MUST be established through this flow. No step MAY
be skipped.

```
1. Service Requirement
        │   (source declares: "I need egress to https://example.com")
        ▼
2. Capability Offer
        │   (gateway with INTERNET_GATEWAY capability offers itself)
        ▼
3. Policy Check
        │   (gateway checks: is example.com:443 in my allow-list?)
        ▼
4. Capacity Check
        │   (gateway checks: do I have headroom for this session?)
        ▼
5. Authorization Check
        │   (gateway checks: does the requesting NodeId hold a
        │    GatewayAuthorization for this service class?)
        ▼
6. Service Agreement
        │   (gateway and source sign a GatewayServiceAgreement)
        ▼
7. Active Circuit carrying gateway traffic
        │   (per spec/08; circuit's destination is the gateway)
        ▼
8. Gateway forwards to real Internet
        │   (gateway performs egress under its protections, §5)
        ▼
9. Measurement + signed receipt
        │   (gateway returns signed usage; see spec/11)
```

### 3.1 GatewayServiceAgreement

```
GatewayServiceAgreement = {
  agreement_version: 1,
  gateway_id:        text,
  source_id:         text,
  circuit_id:        text,         ; the circuit carrying this session
  service_class:     text,        ; e.g. "internet-egress-https"
  destination_scope: text,        ; e.g. "example.com:443" or "*"
  max_bytes:         uint,
  max_duration:      uint,
  starts_at:         uint,
  expires_at:        uint,
  agreement_nonce:   bstr .size 16,
  gateway_signature: bstr .size 64,
  source_signature:  bstr .size 64,
}
```

Signature domains: `"sharenet-gateway-agreement-gateway-v1"` and
`"sharenet-gateway-agreement-source-v1"`.

## 4. First End-to-End Proof

The Phase 8 exit condition (`spec/01-architecture.md` §3) is:

> HTTP(S) request → ShareNet → relay(s) → gateway → real external HTTPS
> server → response.

Concretely: a source node, configured with no direct Internet,
issues `curl https://example.com`. The request flows over an
`ActiveCircuit` whose terminal hop is a gateway. The gateway performs
the egress, returns the response over the circuit, and issues a signed
receipt for the bytes exchanged. The source receives the response and
the receipt verifies.

This proof MUST be reproducible from the repository without manual
intervention (single script invocation).

## 5. Gateway Protections

A gateway MUST enforce all of the following. Failure of any is a
specification violation.

### 5.1 Destination Policy

- The gateway MUST maintain an allow-list (or deny-list) of
  destinations permitted per service class.
- Default policy when no rule matches is **deny**.

### 5.2 Private-Address Blocking

The gateway MUST NOT egress to any of:

- IPv4 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0/8`.
- IPv6 `::1/128`, `fc00::/7`, `fe80::/10`, `::/128`, `::ffff:0:0/96`
  (IPv4-mapped).
- Link-local, loopback, broadcast.

This protects the gateway's own LAN from being probed by ShareNet
peers (the SSRF risk — see `spec/14-security.md` §6).

### 5.3 Loopback Protection

Even if a destination DNS resolution returns `127.0.0.1`, the
gateway MUST refuse egress. DNS rebinding attacks MUST be mitigated by
re-resolving at egress time and re-checking against §5.2.

### 5.4 Link-Local Protection

The gateway MUST refuse to egress to link-local addresses even if the
operating system would normally route them.

### 5.5 SSRF Protection

Combined with §5.2–5.4, the gateway MUST:

- Refuse to fetch `file://`, `gopher://`, `dict://`, `ftp://`, or any
  scheme other than `http` and `https`.
- Refuse redirects to disallowed schemes or to private addresses.
- Cap redirect chain depth at 3.
- Refuse to honor DNS responses whose TTL is less than 30 seconds when
  the destination is otherwise sensitive.

### 5.6 Per-Peer Quota

- Each `source_id` MUST be subject to a per-window byte quota and a
  per-window request quota.
- Default: 100 MiB / hour, 1000 requests / hour. Operator-configurable.
- Quota exceeded ⇒ request denied with a `429`-style response over
  the circuit.

### 5.7 Global Quota

- The gateway MUST enforce a global aggregate rate limit independent
  of per-peer quotas, to protect the gateway's own uplink.
- Default: 80% of measured uplink bandwidth.

### 5.8 Bandwidth Shaping

- The gateway MUST shape egress traffic to avoid bursting the
  uplink. Token bucket, per circuit.

### 5.9 Rate Limits

- The gateway MUST enforce a request rate limit per circuit and per
  source.
- Default: 10 requests / second per circuit.

### 5.10 Revocation

- A `GatewayAuthorization` is revocable at any time by the gateway
  operator.
- On revocation, the gateway MUST tear down all active circuits
  associated with the revoked authorization and MUST refuse new ones.

### 5.11 Abuse Controls

- Repeated policy violations from a `source_id` MUST trigger
  temporary or permanent block.
- Blocked `NodeId`s are added to the gateway's local revocation list.
- Abusive patterns (port scanning, DNS amplification attempts, etc.)
  are auto-detected and trigger immediate block + audit log entry.

## 6. Receipts

For every gateway session, the gateway MUST issue a signed receipt
containing the measured bytes and duration. Receipts are the basis
for ContributionProofs (see `spec/11-contribution.md` §3). A gateway
that forwards traffic without issuing a receipt is in violation.

Receipt format and verification are normatively defined in
`spec/11-contribution.md` §3.

## 7. Invariants

1. `INTERNET_GATEWAY` capability ≠ usable gateway.
2. No gateway traffic without a `GatewayServiceAgreement`.
3. No egress to private / loopback / link-local addresses.
4. SSRF protections MUST be enforced at egress time, not at request
   time only.
5. Receipts are mandatory and signed.
6. Revocation is immediate and circuit-tearing.

## 8. Cross-References

- Capability advertisement: `spec/03-node-advertisements.md` §6.
- Circuit carrying gateway traffic: `spec/08-circuits.md`.
- Contribution receipts: `spec/11-contribution.md` §3.
- SSRF protection details: `spec/14-security.md` §6.
- Conformance test for "first proof": `spec/17-conformance.md` §4
  Phase 8.
