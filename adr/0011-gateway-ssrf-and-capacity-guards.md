# ADR 0011 — Gateway SSRF and Capacity Guards

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted** for the first deliverable's gateway stub. This ADR
will be **updated** (not superseded) when real Internet forwarding
lands in Phase 8, per `spec/01-architecture.md` §3.

## Context

`spec/09-internet-gateway.md` §5 enumerates eleven mandatory gateway
protections:

1. Destination policy (allow-list of hostnames and ports).
2. Private-address blocking (RFC 1918, RFC 4193, RFC 6598).
3. Loopback protection (`127.0.0.0/8`, `::1`).
4. Link-local protection (`169.254.0.0/16`, `fe80::/10`).
5. SSRF protection (re-resolve DNS at egress time, defeat DNS
   rebinding, cap redirect depth at 3).
6. Per-peer quota (per-source-NodeId byte and connection limits).
7. Global quota (gateway-wide byte and connection limits).
8. Bandwidth shaping (token bucket per peer).
9. Rate limits (requests per second per peer and per destination).
10. Revocation (gateway can revoke an active session mid-flight).
11. Abuse controls (logging, alerting, automatic disable on
    repeated policy violations).

`spec/00-thesis.md` §3 ("What ShareNet IS NOT") is explicit:

> ShareNet is NOT an open proxy. A gateway MUST never forward
> arbitrary traffic to arbitrary destinations without policy,
> capacity, and authorization checks.

`spec/17-conformance.md` §3.9 makes gateway egress without
authorization a forbidden pipeline, enforced by the architecture
regression tests (ADR 0010). `spec/17-conformance.md` §2 test 10
asserts that gateway egress to `127.0.0.1`, `10.0.0.0/8`,
`fc00::/7`, etc., is rejected.

The first deliverable cannot yet prove the north-star proof
diagram of `spec/00-thesis.md` §1.1 — real HTTPS through the
gateway to a real Internet server is a Phase 8 exit condition
(`spec/17-conformance.md` §4 Phase 8). But the first deliverable
MUST prove that the guard layer exists, because every future
gateway implementation MUST pass through it. Deferring the guard
layer to Phase 8 would mean writing the guards and the forwarding
in the same PR, which is a security-review nightmare.

## Decision

For the first deliverable, implement the gateway as a **stub** that
ENFORCES every policy/capacity/quota guard from
`spec/09-internet-gateway.md` §5 but does NOT yet forward to the
real Internet. The stub:

1. Accepts a `GatewayEgressRequest` (destination URL, requested
   bytes, source NodeId, session CircuitId, signed
   `GatewayServiceAgreement`).
2. Runs the eleven guards in order: URL scheme allow-list (http,
   https only); destination address class check (reject private,
   loopback, link-local, broadcast, multicast); DNS re-resolution at
   egress time (the stub performs the DNS lookup; a future forwarding
   implementation MUST re-use the same lookup result, defeating DNS
   rebinding); redirect-depth check (cap at 3, applied to the final
   URL after any redirect chain); per-peer quota check; global quota
   check; token-bucket bandwidth check; rate-limit check (per peer,
   per destination); authorization check (valid signed
   `GatewayServiceAgreement`); revocation check (session not on the
   active revocation list); abuse-control check (source NodeId not
   flagged for repeated violations).
3. Returns a structured **policy decision** response:
   ```
   {
     allowed: boolean,
     reason: "OK" | "DESTINATION_BLOCKED" | "SCHEME_BLOCKED" |
             "QUOTA_EXCEEDED" | "RATE_LIMITED" | "UNAUTHORIZED" |
             "REVOKED" | "ABUSE_FLAGGED" | ...,
     decided_at: uint,
     decision_nonce: bstr .size 16,
     decision_signature: bstr .size 64,  // Ed25519 by gateway
     available_bytes: uint,
     available_connections: uint,
   }
   ```
4. Does NOT open a socket to the destination. The stub returns the
   policy decision; the caller (a future forwarding implementation)
   is responsible for honoring the decision and the
   `decision_nonce` when it eventually opens the socket.

The stub is wired into the architecture regression test suite
(ADR 0010) as test 10 (`gateway_blocks_private_address_egress`)
and as the runtime check for forbidden pipeline §3.9
(`gateway_egress_without_authorization`).

A future ADR (Phase 8) will record the cutover: the forwarding
implementation will be added behind the existing guard layer, and
the guard layer's API will remain unchanged. The Phase 8 exit
condition (`spec/17-conformance.md` §4 Phase 8) is the first time
real HTTPS bytes flow through the gateway.

## Consequences

- **The first deliverable cannot yet prove the north-star** (real
  HTTPS through gateway). It DOES prove the guard layer that any
  future gateway implementation MUST pass through. This is a
  deliberate scope boundary: prove the security boundary first,
  then add the forwarding.
- **The guard layer is testable in isolation.** The architecture
  regression test suite can exercise every guard with a fixture
  request and assert the correct rejection. The tests do not
  require network egress.
- **The stub's policy-decision response is a stable API.** A future
  forwarding implementation MUST consume the policy decision, refuse
  to forward if `allowed == false`, and include the
  `decision_nonce` in its measurement record so audit can
  reconstruct which policy decision authorized which bytes.
- **DNS rebinding is defended in the stub.** The stub performs the
  DNS lookup; the resolved IP is part of the policy decision
  response. A future forwarding implementation MUST use the same
  resolved IP (not re-resolve) when opening the socket.
- **Phase 8 cutover risk is bounded.** The guard layer is already
  battle-tested; the forwarding PR is purely additive.
- **No real egress in the sandbox.** A sandbox reviewer cannot use
  the first deliverable to fetch a real Internet URL. The demo
  dashboard (Task 12) shows the policy-decision response as a
  substitute.
- **Per-peer and global quota tables are created now.** Populated
  with zero usage; the stub maintains them as in production, so
  the cutover requires no schema change.

## Alternatives Considered

1. **Skip the gateway entirely in the first deliverable.** Rejected —
   would defer a critical security boundary to Phase 8, where it
   would be written in the same PR as the forwarding.
2. **Implement real forwarding without guards.** Rejected —
   violates `spec/09-internet-gateway.md` §5 and would fail the
   architecture regression tests at Phase 8 cutover.
3. **Implement real forwarding WITH guards in the first deliverable.**
   Considered — would prove the north-star. Rejected because the
   sandbox does not have stable Internet egress, and because
   combining the guard-layer PR with the forwarding PR is exactly
   the security-review risk the stub design avoids.
4. **Implement guards as a library, not as a stub endpoint.**
   Considered — the stub endpoint IS this library plus a thin HTTP
   surface; the library is the substance, the endpoint is the proof
   that the library is wired in.
5. **Mock the guards (return `allowed: true` always).** Rejected —
   would not pass the architecture regression tests.
6. **Defer the stub to Phase 7 (circuit).** Considered — would let
   the first deliverable ship sooner. Rejected because the guards
   are foundational.

## References

- `spec/00-thesis.md` §3 — what ShareNet IS NOT (no open proxy).
- `spec/09-internet-gateway.md` §1, §2, §5 — gateway model, five
  distinct objects, eleven mandatory protections.
- `spec/14-security.md` §6 — SSRF protection at gateway.
- `spec/17-conformance.md` §2 test 10 —
  `gateway_blocks_private_address_egress`.
- `spec/17-conformance.md` §3.9 — `gateway_egress_without_authorization`
  forbidden pipeline.
- `spec/17-conformance.md` §4 Phase 8 — first end-to-end proof
  (the future cutover exit condition).
- ADR 0010 — architecture regression tests.
- Michael Nygard ADR template — structural source.
