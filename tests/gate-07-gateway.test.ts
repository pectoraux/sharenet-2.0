/**
 * ShareNet 2.0 — GATE-07 Tests: Mode A Internet gateway.
 *
 * Per GATE-07 requirements:
 *   - blocked destination tests prove gateway protections
 *   - no open-proxy behavior
 *   - per-peer/global quotas, rate limits, revocation, shaping
 *   - signed service measurements + structured audit events
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  bytesToHex,
} from "@reference/identity/keys";
import {
  defaultGatewayPolicy,
  defaultGatewayCapacity,
  evaluateGatewayRequest,
  checkResolvedIp,
  extractHost,
  isLoopback,
  isLinkLocal,
  isPrivateAddress,
  isSsrfTarget,
  isBlockedIp,
  matchAllowlist,
  signServiceMeasurement,
  verifyServiceMeasurement,
  createAuditEvent,
  OPEN_PROXY_FORWARD_FORBIDDEN,
  type GatewayPolicy,
  type GatewayCapacity,
  type GatewayRequestInput,
} from "@reference/gateway/gateway";

const REFERENCE_NOW = 1786876545000; // ms

function makePolicy(overrides: Partial<GatewayPolicy> = {}): GatewayPolicy {
  return { ...defaultGatewayPolicy(), ...overrides };
}

function makeCapacity(now: number = REFERENCE_NOW): GatewayCapacity {
  const cap = defaultGatewayCapacity();
  cap.windowStart = now;
  cap.secondStart = now;
  return cap;
}

function makeInput(peer = "peernode1", dest = "example.com:443", bytes = 1024): GatewayRequestInput {
  return { peerNodeId: peer, destination: dest, requestedBytes: bytes };
}

describe("GATE-07: Mode A Internet gateway", () => {
  // --- 1. ALLOW: valid request ---
  test("valid request is ALLOWED", () => {
    const policy = makePolicy();
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput(), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("ALLOW");
  });

  // --- 2. DENY: gateway disabled ---
  test("gateway disabled → DENY", () => {
    const policy = makePolicy({ enabled: false });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput(), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("GATEWAY_DISABLED");
  });

  // --- 3. DENY: SSRF destination ---
  test("SSRF destination (169.254.169.254) → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "169.254.169.254:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_BLOCKED_SSRF");
  });

  test("SSRF destination (metadata.google.internal) → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "metadata.google.internal", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_BLOCKED_SSRF");
  });

  // --- 4. DENY: loopback ---
  test("loopback destination → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "127.0.0.1:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_BLOCKED_LOOPBACK");
  });

  test("localhost → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "localhost:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_BLOCKED_LOOPBACK");
  });

  // --- 5. DENY: link-local ---
  test("link-local destination → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "169.254.1.1:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_BLOCKED_LINK_LOCAL");
  });

  // --- 6. DENY: private address ---
  test("private address (10.x) → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "10.0.0.5:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_BLOCKED_PRIVATE");
  });

  test("private address (192.168.x) → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "192.168.1.1:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_BLOCKED_PRIVATE");
  });

  test("private address (172.16.x) → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "172.16.0.1:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_BLOCKED_PRIVATE");
  });

  test("public address (172.15.x) → ALLOW (not private)", () => {
    const policy = makePolicy({ allowedDestinations: ["*"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "172.15.0.1:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("ALLOW");
  });

  // --- 7. DENY: not in allowlist ---
  test("destination not in allowlist → DENY", () => {
    const policy = makePolicy({ allowedDestinations: ["example.com"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "evil.com:80", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_NOT_ALLOWED");
  });

  test("wildcard allowlist matches subdomain", () => {
    const policy = makePolicy({ allowedDestinations: ["*.sharenet.local"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "relay1.sharenet.local:7788", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("ALLOW");
  });

  // --- 8. DENY: empty allowlist (secure default) ---
  test("empty allowlist → DENY (secure default)", () => {
    const policy = makePolicy({ allowedDestinations: [] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("peer", "example.com:443", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("DESTINATION_NOT_ALLOWED");
  });

  // --- 9. DENY: revoked peer ---
  test("revoked peer → DENY", () => {
    const policy = makePolicy({ revokedPeers: ["badnode"] });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput("badnode", "example.com:443", 100), policy, cap, REFERENCE_NOW);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("PEER_REVOKED");
  });

  // --- 10. DENY: per-peer quota exhausted ---
  test("per-peer quota exhausted → DENY", () => {
    const policy = makePolicy({ perPeerQuota: 3 });
    const cap = makeCapacity();
    // Use 3 requests (the quota)
    for (let i = 0; i < 3; i++) {
      evaluateGatewayRequest(makeInput("peer", "example.com:443", 100), policy, cap, REFERENCE_NOW + i * 200);
    }
    // 4th should fail
    const result = evaluateGatewayRequest(makeInput("peer", "example.com:443", 100), policy, cap, REFERENCE_NOW + 1000);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("PER_PEER_QUOTA_EXHAUSTED");
  });

  // --- 11. DENY: global quota exhausted ---
  test("global quota exhausted → DENY", () => {
    const policy = makePolicy({ globalQuota: 2 });
    const cap = makeCapacity();
    evaluateGatewayRequest(makeInput("peer1", "example.com:443", 100), policy, cap, REFERENCE_NOW);
    evaluateGatewayRequest(makeInput("peer2", "example.com:443", 100), policy, cap, REFERENCE_NOW + 200);
    // 3rd should fail
    const result = evaluateGatewayRequest(makeInput("peer3", "example.com:443", 100), policy, cap, REFERENCE_NOW + 400);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("GLOBAL_QUOTA_EXHAUSTED");
  });

  // --- 12. DENY: rate limit exceeded ---
  test("rate limit exceeded → DENY", () => {
    const policy = makePolicy({ rateLimitPerSec: 1 });
    const cap = makeCapacity();
    // First request OK
    evaluateGatewayRequest(makeInput("peer", "example.com:443", 100), policy, cap, REFERENCE_NOW);
    // Immediate second should fail (within 1s)
    const result = evaluateGatewayRequest(makeInput("peer", "example.com:443", 100), policy, cap, REFERENCE_NOW + 100);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("RATE_LIMIT_EXCEEDED");
  });

  // --- 13. DENY: bandwidth exceeded ---
  test("bandwidth exceeded → DENY", () => {
    const policy = makePolicy({ bandwidthBps: 500 });
    const cap = makeCapacity();
    // First request uses 400 bytes
    evaluateGatewayRequest(makeInput("peer", "example.com:443", 400), policy, cap, REFERENCE_NOW);
    // Second request needs 200 more → total 600 > 500
    const result = evaluateGatewayRequest(makeInput("peer", "example.com:443", 200), policy, cap, REFERENCE_NOW + 100);
    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("BANDWIDTH_EXCEEDED");
  });

  // --- 14. Post-DNS resolution check ---
  test("post-DNS: blocked IP is rejected", () => {
    const policy = makePolicy();
    const r1 = checkResolvedIp("127.0.0.1", policy);
    expect(r1.ok).toBe(false);
    const r2 = checkResolvedIp("169.254.169.254", policy);
    expect(r2.ok).toBe(false);
    const r3 = checkResolvedIp("10.0.0.1", policy);
    expect(r3.ok).toBe(false);
    const r4 = checkResolvedIp("93.184.216.34", policy); // example.com IP
    expect(r4.ok).toBe(true);
  });

  // --- 15. Signed service measurement ---
  test("service measurement signs and verifies", () => {
    const gateway = generateNodeKeypair();
    const measurement = signServiceMeasurement({
      gatewayNodeId: gateway.nodeId,
      peerNodeId: "peernode1",
      destination: "example.com:443",
      bytesSent: 1024,
      bytesReceived: 4096,
      requestTimestamp: 1786876545,
      responseTimestamp: 1786876546,
      httpStatus: 200,
    }, gateway.secretKey);

    const ok = verifyServiceMeasurement(measurement, gateway.publicKey);
    expect(ok).toBe(true);
  });

  test("service measurement with wrong key fails", () => {
    const gatewayA = generateNodeKeypair();
    const gatewayB = generateNodeKeypair();
    const measurement = signServiceMeasurement({
      gatewayNodeId: gatewayA.nodeId,
      peerNodeId: "peernode1",
      destination: "example.com:443",
      bytesSent: 1024,
      bytesReceived: 4096,
      requestTimestamp: 1786876545,
      responseTimestamp: 1786876546,
      httpStatus: 200,
    }, gatewayA.secretKey);

    const ok = verifyServiceMeasurement(measurement, gatewayB.publicKey);
    expect(ok).toBe(false);
  });

  // --- 16. Audit event creation ---
  test("audit event created for ALLOW", () => {
    const policy = makePolicy();
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput(), policy, cap, REFERENCE_NOW);
    const event = createAuditEvent(result, "gateway1");
    expect(event.type).toBe("GATEWAY_REQUEST_ALLOWED");
    expect(event.decision).toBe("ALLOW");
  });

  test("audit event created for DENY", () => {
    const policy = makePolicy({ enabled: false });
    const cap = makeCapacity();
    const result = evaluateGatewayRequest(makeInput(), policy, cap, REFERENCE_NOW);
    const event = createAuditEvent(result, "gateway1");
    expect(event.type).toBe("GATEWAY_REQUEST_DENIED");
    expect(event.decision).toBe("DENY");
    expect(event.reason).toBe("GATEWAY_DISABLED");
  });

  // --- 17. No open-proxy guard ---
  test("OPEN_PROXY_FORWARD_FORBIDDEN throws", () => {
    expect(() => OPEN_PROXY_FORWARD_FORBIDDEN("evil.com")).toThrow();
  });

  // --- 18. Allowlist wildcard matching ---
  test("wildcard allowlist matching", () => {
    expect(matchAllowlist("*", "anything.com")).toBe(true);
    expect(matchAllowlist("example.com", "example.com")).toBe(true);
    expect(matchAllowlist("*.sharenet.local", "relay1.sharenet.local")).toBe(true);
    expect(matchAllowlist("*.sharenet.local", "sharenet.local")).toBe(true);
    expect(matchAllowlist("*.sharenet.local", "evil.com")).toBe(false);
  });

  // --- 19. Quota window reset ---
  test("quota window resets after 60 seconds", () => {
    const policy = makePolicy({ perPeerQuota: 1, globalQuota: 1 });
    const cap = makeCapacity();
    // Use the quota
    evaluateGatewayRequest(makeInput("peer", "example.com:443", 100), policy, cap, REFERENCE_NOW);
    // Should be exhausted
    const r1 = evaluateGatewayRequest(makeInput("peer", "example.com:443", 100), policy, cap, REFERENCE_NOW + 1000);
    expect(r1.decision).toBe("DENY");
    // After 61 seconds, window resets
    const r2 = evaluateGatewayRequest(makeInput("peer", "example.com:443", 100), policy, cap, REFERENCE_NOW + 61000);
    expect(r2.decision).toBe("ALLOW");
  });
});
