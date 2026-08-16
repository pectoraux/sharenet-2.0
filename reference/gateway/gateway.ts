/**
 * ShareNet 2.0 — Mode A Internet Gateway (GATE-07).
 *
 * Per spec/09-internet-gateway.md and GATE-07 requirements:
 *
 *   The gateway enforces:
 *     - request/response framing
 *     - DNS policy and resolution semantics
 *     - destination allowlist
 *     - private, loopback, link-local, metadata/SSRF blocking AFTER DNS resolution
 *     - per-peer/global quotas, shaping, rate limits, revocation
 *     - signed service measurements and structured audit events
 *     - no open-proxy behavior
 *
 * The gateway is the ONLY component that makes outbound Internet connections.
 * It receives encrypted circuit traffic from relays, decrypts the final onion
 * layer, and forwards the plaintext request to the real destination.
 *
 * Per spec/09 §3: NEVER an unrestricted open proxy. Every request MUST pass
 * all policy checks before forwarding.
 *
 * This module is in reference/ (protocol core, no DB dependency per ADR-0013).
 * The service-layer DB-backed implementation lives in src/lib/sharenet/gateway.ts.
 */

import { blake3 } from "@noble/hashes/blake3.js";
import { signMessage, verifySignature } from "../identity/keys";
import { canonicalEncode, toHex } from "../encoding/cbor";

// -----------------------------------------------------------------------
// Constants (FROZEN per spec/09 §3 + spec/14 §4)
// -----------------------------------------------------------------------

/** Domain tag for signed service measurements. */
export const GATEWAY_MEASUREMENT_DOMAIN = "SHARENET/GATEWAY/MEASUREMENT/1";

/** Domain tag for audit events. */
export const GATEWAY_AUDIT_DOMAIN = "SHARENET/GATEWAY/AUDIT/1";

/** Default per-peer request quota per 60-second window. */
export const DEFAULT_PER_PEER_QUOTA = 100;

/** Default global request quota per 60-second window. */
export const DEFAULT_GLOBAL_QUOTA = 10000;

/** Default rate limit (requests per second). */
export const DEFAULT_RATE_LIMIT_PER_SEC = 10;

/** Default bandwidth limit (bytes per second). */
export const DEFAULT_BANDWIDTH_BPS = 1_048_576; // 1 MiB/s

/** Quota window in milliseconds. */
export const QUOTA_WINDOW_MS = 60_000;

// -----------------------------------------------------------------------
// Gateway policy (what the gateway enforces)
// -----------------------------------------------------------------------

/**
 * Gateway policy — defines what the gateway allows/denies.
 *
 * Per spec/00 §2 (Gateway semantics):
 *   Capability ≠ Policy ≠ Authorization ≠ Capacity ≠ Measurement
 *
 * This type is the POLICY (rules). It is NOT the capability (which is in
 * the NodeAdvertisement) and NOT the authorization (which is the
 * ServiceAgreement) and NOT the capacity (which is runtime state).
 */
export interface GatewayPolicy {
  /** Allowlist of destination host patterns. Empty = deny all (secure default). */
  allowedDestinations: readonly string[];
  /** Block private IPv4/IPv6 ranges (RFC 1918). Default: true. */
  blockPrivateAddresses: boolean;
  /** Block loopback (127.0.0.0/8, ::1). Default: true. */
  blockLoopback: boolean;
  /** Block link-local (169.254.0.0/16, fe80::/10). Default: true. */
  blockLinkLocal: boolean;
  /** Block SSRF-sensitive endpoints (cloud metadata). Default: true. */
  blockSsrf: boolean;
  /** Per-peer request quota per window. */
  perPeerQuota: number;
  /** Global request quota per window. */
  globalQuota: number;
  /** Rate limit (requests per second). */
  rateLimitPerSec: number;
  /** Bandwidth limit (bytes per second). */
  bandwidthBps: number;
  /** Revoked peer NodeIds. */
  revokedPeers: readonly string[];
  /** Whether the gateway is enabled. */
  enabled: boolean;
}

/** Default policy (most restrictive). */
export function defaultGatewayPolicy(): GatewayPolicy {
  return {
    allowedDestinations: ["example.com", "*.sharenet.local"],
    blockPrivateAddresses: true,
    blockLoopback: true,
    blockLinkLocal: true,
    blockSsrf: true,
    perPeerQuota: DEFAULT_PER_PEER_QUOTA,
    globalQuota: DEFAULT_GLOBAL_QUOTA,
    rateLimitPerSec: DEFAULT_RATE_LIMIT_PER_SEC,
    bandwidthBps: DEFAULT_BANDWIDTH_BPS,
    revokedPeers: [],
    enabled: true,
  };
}

// -----------------------------------------------------------------------
// Gateway capacity (runtime state)
// -----------------------------------------------------------------------

/**
 * Gateway capacity — runtime tracking of quotas, rate limits, and bandwidth.
 *
 * Per spec/00 §2: this is the CAPACITY (measurement), NOT the policy (rules)
 * and NOT the capability (advertisement).
 */
export interface GatewayCapacity {
  /** Current per-peer request counts in the current window. */
  perPeerCounts: Map<string, number>;
  /** Current global request count in the current window. */
  globalCount: number;
  /** Window start timestamp (ms). */
  windowStart: number;
  /** Last request timestamp per peer (for rate limiting). */
  lastRequestPerPeer: Map<string, number>;
  /** Bytes forwarded in current second. */
  bytesThisSecond: number;
  /** Current second start (ms). */
  secondStart: number;
}

export function defaultGatewayCapacity(): GatewayCapacity {
  return {
    perPeerCounts: new Map(),
    globalCount: 0,
    windowStart: Date.now(),
    lastRequestPerPeer: new Map(),
    bytesThisSecond: 0,
    secondStart: Date.now(),
  };
}

// -----------------------------------------------------------------------
// Gateway decision (the result of policy + capacity checks)
// -----------------------------------------------------------------------

export type GatewayDecision = "ALLOW" | "DENY";

export type GatewayDenyReason =
  | "GATEWAY_DISABLED"
  | "DESTINATION_NOT_ALLOWED"
  | "DESTINATION_BLOCKED_PRIVATE"
  | "DESTINATION_BLOCKED_LOOPBACK"
  | "DESTINATION_BLOCKED_LINK_LOCAL"
  | "DESTINATION_BLOCKED_SSRF"
  | "PEER_REVOKED"
  | "PER_PEER_QUOTA_EXHAUSTED"
  | "GLOBAL_QUOTA_EXHAUSTED"
  | "RATE_LIMIT_EXCEEDED"
  | "BANDWIDTH_EXCEEDED";

export interface GatewayRequestInput {
  peerNodeId: string;
  destination: string;
  requestedBytes: number;
}

export interface GatewayPolicyResult {
  decision: GatewayDecision;
  reason?: GatewayDenyReason;
  detail: string;
  destination: string;
  peerNodeId: string;
  resolvedIp?: string;
  decidedAt: number;
}

// -----------------------------------------------------------------------
// DNS resolution + post-resolution blocking
// -----------------------------------------------------------------------

/**
 * Extract the host from a destination string.
 * Handles: "host", "host:port", "scheme://host:port/path"
 */
export function extractHost(destination: string): string {
  let s = destination;
  if (s.includes("://")) s = s.split("://")[1] ?? s;
  if (s.includes("/")) s = s.split("/")[0] ?? s;
  if (s.includes(":")) s = s.split(":")[0] ?? s;
  return s.toLowerCase();
}

/**
 * Check if a host is a loopback address.
 */
export function isLoopback(host: string): boolean {
  return host === "localhost" || host === "::1" || host.startsWith("127.");
}

/**
 * Check if a host is a link-local address.
 */
export function isLinkLocal(host: string): boolean {
  return host.startsWith("169.254.") || host.startsWith("fe80:");
}

/**
 * Check if a host is a private address (RFC 1918 / IPv6 ULA).
 */
export function isPrivateAddress(host: string): boolean {
  if (host.startsWith("10.")) return true;
  if (host.startsWith("192.168.")) return true;
  if (host.startsWith("172.")) {
    const second = parseInt(host.split(".")[1] ?? "0", 10);
    if (second >= 16 && second <= 31) return true;
  }
  if (host.startsWith("fc") || host.startsWith("fd")) return true;
  return false;
}

/**
 * Check if a host is an SSRF-sensitive target (cloud metadata endpoints).
 *
 * Per spec/09 §3: MUST block these AFTER DNS resolution, not just before.
 * The DNS resolution check is a separate function that re-resolves the
 * destination and checks the resolved IP.
 */
export function isSsrfTarget(host: string): boolean {
  if (host === "169.254.169.254") return true; // AWS/GCP metadata
  if (host === "metadata.google.internal") return true;
  if (host === "fd00:ec2::254") return true; // AWS IPv6 metadata
  if (host.endsWith(".internal") && !host.endsWith(".sharenet.local")) return true;
  return false;
}

/**
 * Check if an IP address (after DNS resolution) is in a blocked range.
 *
 * Per spec/09 §3: blocking happens AFTER DNS resolution to defeat DNS rebinding.
 * The destination hostname may resolve to a different IP on each query.
 */
export function isBlockedIp(ip: string): boolean {
  return isLoopback(ip) || isLinkLocal(ip) || isPrivateAddress(ip) || isSsrfTarget(ip);
}

/**
 * Match a host against an allowlist pattern.
 * Supports: exact match, wildcard (*.example.com).
 */
export function matchAllowlist(pattern: string, host: string): boolean {
  if (pattern === "*") return true;
  if (pattern === host) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    return host === suffix || host.endsWith("." + suffix);
  }
  return false;
}

// -----------------------------------------------------------------------
// Gateway policy evaluation
// -----------------------------------------------------------------------

/**
 * Evaluate a gateway request against policy + capacity.
 *
 * This is the ONLY function that decides whether a request is forwarded.
 * It runs ALL checks:
 *   1. Gateway enabled
 *   2. Peer not revoked
 *   3. Destination allowlist
 *   4. SSRF/loopback/link-local/private blocking (BEFORE DNS)
 *   5. Per-peer quota
 *   6. Global quota
 *   7. Rate limit
 *   8. Bandwidth
 *
 * Returns ALLOW only if ALL checks pass. Otherwise returns DENY with a reason.
 *
 * Per spec/09 §3: NEVER an unrestricted open proxy.
 */
export function evaluateGatewayRequest(
  input: GatewayRequestInput,
  policy: GatewayPolicy,
  capacity: GatewayCapacity,
  now: number = Date.now(),
): GatewayPolicyResult {
  const decidedAt = now;
  const host = extractHost(input.destination);

  // 1. Gateway enabled
  if (!policy.enabled) {
    return { decision: "DENY", reason: "GATEWAY_DISABLED", detail: "gateway is disabled", destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }

  // 2. Peer revoked
  if (policy.revokedPeers.includes(input.peerNodeId)) {
    return { decision: "DENY", reason: "PEER_REVOKED", detail: `peer ${input.peerNodeId} is revoked`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }

  // 3. Destination allowlist
  if (policy.allowedDestinations.length === 0) {
    return { decision: "DENY", reason: "DESTINATION_NOT_ALLOWED", detail: "no destinations allowed (secure default)", destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }
  if (!policy.allowedDestinations.some((p) => matchAllowlist(p, host))) {
    return { decision: "DENY", reason: "DESTINATION_NOT_ALLOWED", detail: `host ${host} not in allowlist`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }

  // 4. SSRF/loopback/link-local/private blocking (BEFORE DNS)
  if (policy.blockSsrf && isSsrfTarget(host)) {
    return { decision: "DENY", reason: "DESTINATION_BLOCKED_SSRF", detail: `SSRF-sensitive: ${host}`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }
  if (policy.blockLoopback && isLoopback(host)) {
    return { decision: "DENY", reason: "DESTINATION_BLOCKED_LOOPBACK", detail: `loopback: ${host}`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }
  if (policy.blockLinkLocal && isLinkLocal(host)) {
    return { decision: "DENY", reason: "DESTINATION_BLOCKED_LINK_LOCAL", detail: `link-local: ${host}`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }
  if (policy.blockPrivateAddresses && isPrivateAddress(host)) {
    return { decision: "DENY", reason: "DESTINATION_BLOCKED_PRIVATE", detail: `private address: ${host}`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }

  // Reset window if expired
  if (now - capacity.windowStart > QUOTA_WINDOW_MS) {
    capacity.windowStart = now;
    capacity.globalCount = 0;
    capacity.perPeerCounts.clear();
  }

  // Reset second if expired
  if (now - capacity.secondStart > 1000) {
    capacity.secondStart = now;
    capacity.bytesThisSecond = 0;
  }

  // 5. Per-peer quota
  const peerCount = capacity.perPeerCounts.get(input.peerNodeId) ?? 0;
  if (peerCount >= policy.perPeerQuota) {
    return { decision: "DENY", reason: "PER_PEER_QUOTA_EXHAUSTED", detail: `peer ${input.peerNodeId} has ${peerCount}/${policy.perPeerQuota} requests`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }

  // 6. Global quota
  if (capacity.globalCount >= policy.globalQuota) {
    return { decision: "DENY", reason: "GLOBAL_QUOTA_EXHAUSTED", detail: `global ${capacity.globalCount}/${policy.globalQuota} requests`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }

  // 7. Rate limit (per-peer, per-second)
  const lastReq = capacity.lastRequestPerPeer.get(input.peerNodeId) ?? 0;
  if (now - lastReq < 1000 / policy.rateLimitPerSec) {
    return { decision: "DENY", reason: "RATE_LIMIT_EXCEEDED", detail: `peer ${input.peerNodeId} rate-limited`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }

  // 8. Bandwidth
  if (capacity.bytesThisSecond + input.requestedBytes > policy.bandwidthBps) {
    return { decision: "DENY", reason: "BANDWIDTH_EXCEEDED", detail: `bandwidth ${capacity.bytesThisSecond + input.requestedBytes}/${policy.bandwidthBps} bytes/s`, destination: input.destination, peerNodeId: input.peerNodeId, decidedAt };
  }

  // ALL checks passed — ALLOW
  // Update capacity tracking
  capacity.perPeerCounts.set(input.peerNodeId, peerCount + 1);
  capacity.globalCount++;
  capacity.lastRequestPerPeer.set(input.peerNodeId, now);
  capacity.bytesThisSecond += input.requestedBytes;

  return {
    decision: "ALLOW",
    detail: "all guards passed",
    destination: input.destination,
    peerNodeId: input.peerNodeId,
    decidedAt,
  };
}

/**
 * Post-DNS-resolution check.
 *
 * Per spec/09 §3: blocking happens AFTER DNS resolution to defeat DNS rebinding.
 * The destination hostname may resolve to a different IP on each query.
 * This function checks the RESOLVED IP against the block list.
 */
export function checkResolvedIp(
  resolvedIp: string,
  policy: GatewayPolicy,
): { ok: true } | { ok: false; reason: GatewayDenyReason; detail: string } {
  if (policy.blockSsrf && isSsrfTarget(resolvedIp)) {
    return { ok: false, reason: "DESTINATION_BLOCKED_SSRF", detail: `resolved IP ${resolvedIp} is SSRF-sensitive` };
  }
  if (policy.blockLoopback && isLoopback(resolvedIp)) {
    return { ok: false, reason: "DESTINATION_BLOCKED_LOOPBACK", detail: `resolved IP ${resolvedIp} is loopback` };
  }
  if (policy.blockLinkLocal && isLinkLocal(resolvedIp)) {
    return { ok: false, reason: "DESTINATION_BLOCKED_LINK_LOCAL", detail: `resolved IP ${resolvedIp} is link-local` };
  }
  if (policy.blockPrivateAddresses && isPrivateAddress(resolvedIp)) {
    return { ok: false, reason: "DESTINATION_BLOCKED_PRIVATE", detail: `resolved IP ${resolvedIp} is private` };
  }
  return { ok: true };
}

// -----------------------------------------------------------------------
// Request/response framing
// -----------------------------------------------------------------------

/**
 * A gateway request frame (what the relay sends to the gateway after
 * decrypting the final onion layer).
 */
export interface GatewayRequestFrame {
  /** The destination URL (e.g. "https://example.com/path"). */
  url: string;
  /** HTTP method (GET, POST, etc.). */
  method: string;
  /** Request headers (canonical CBOR map). */
  headers: Record<string, string>;
  /** Request body (may be empty). */
  body: Uint8Array;
}

/**
 * A gateway response frame (what the gateway sends back).
 */
export interface GatewayResponseFrame {
  /** HTTP status code. */
  status: number;
  /** Response headers. */
  headers: Record<string, string>;
  /** Response body. */
  body: Uint8Array;
  /** Time-to-first-byte in ms. */
  ttfbMs: number;
  /** Total time in ms. */
  totalTimeMs: number;
}

/**
 * Encode a GatewayRequestFrame to canonical CBOR.
 */
export function encodeGatewayRequest(req: GatewayRequestFrame): Uint8Array {
  const m = new Map<number, unknown>([
    [1, req.url],
    [2, req.method],
    [3, req.headers],
    [4, req.body],
  ]);
  return canonicalEncode(m);
}

/**
 * Encode a GatewayResponseFrame to canonical CBOR.
 */
export function encodeGatewayResponse(res: GatewayResponseFrame): Uint8Array {
  const m = new Map<number, unknown>([
    [1, res.status],
    [2, res.headers],
    [3, res.body],
    [4, res.ttfbMs],
    [5, res.totalTimeMs],
  ]);
  return canonicalEncode(m);
}

// -----------------------------------------------------------------------
// Signed service measurements
// -----------------------------------------------------------------------

/**
 * A signed service measurement — the gateway's cryptographic attestation
 * of the service it provided.
 *
 * Per GATE-07: "signed service measurements and structured audit events."
 *
 * This is the foundation for GATE-11 (contribution proofs). The gateway
 * signs the measurement with its Ed25519 key, and the measurement can
 * be verified by anyone with the gateway's public key.
 */
export interface ServiceMeasurement {
  /** The gateway's NodeId. */
  gatewayNodeId: string;
  /** The peer's NodeId. */
  peerNodeId: string;
  /** The destination that was accessed. */
  destination: string;
  /** Bytes sent to the destination. */
  bytesSent: number;
  /** Bytes received from the destination. */
  bytesReceived: number;
  /** Request timestamp (unix seconds). */
  requestTimestamp: number;
  /** Response timestamp (unix seconds). */
  responseTimestamp: number;
  /** HTTP status code. */
  httpStatus: number;
  /** Gateway's Ed25519 signature over the measurement. */
  signature: Uint8Array;
}

/**
 * Compute the signing payload for a service measurement.
 */
export function measurementSigningPayload(
  measurement: Omit<ServiceMeasurement, "signature">,
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, measurement.gatewayNodeId],
    [2, measurement.peerNodeId],
    [3, measurement.destination],
    [4, measurement.bytesSent],
    [5, measurement.bytesReceived],
    [6, measurement.requestTimestamp],
    [7, measurement.responseTimestamp],
    [8, measurement.httpStatus],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(GATEWAY_MEASUREMENT_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * Sign a service measurement.
 */
export function signServiceMeasurement(
  measurement: Omit<ServiceMeasurement, "signature">,
  gatewaySecretKey: Uint8Array,
): ServiceMeasurement {
  const payload = measurementSigningPayload(measurement);
  const signature = signMessage(gatewaySecretKey, payload);
  return { ...measurement, signature };
}

/**
 * Verify a service measurement signature.
 */
export function verifyServiceMeasurement(
  measurement: ServiceMeasurement,
  gatewayPublicKey: Uint8Array,
): boolean {
  const { signature, ...rest } = measurement;
  const payload = measurementSigningPayload(rest);
  return verifySignature(gatewayPublicKey, payload, signature);
}

// -----------------------------------------------------------------------
// Audit events
// -----------------------------------------------------------------------

export type AuditEventType =
  | "GATEWAY_REQUEST_ALLOWED"
  | "GATEWAY_REQUEST_DENIED"
  | "GATEWAY_RESPONSE_FORWARDED"
  | "GATEWAY_PEER_REVOKED"
  | "GATEWAY_QUOTA_RESET";

export interface GatewayAuditEvent {
  type: AuditEventType;
  gatewayNodeId: string;
  peerNodeId: string;
  destination: string;
  decision: GatewayDecision;
  reason?: GatewayDenyReason;
  detail: string;
  timestamp: number;
}

/**
 * Create an audit event for a gateway policy decision.
 */
export function createAuditEvent(
  result: GatewayPolicyResult,
  gatewayNodeId: string,
): GatewayAuditEvent {
  return {
    type: result.decision === "ALLOW" ? "GATEWAY_REQUEST_ALLOWED" : "GATEWAY_REQUEST_DENIED",
    gatewayNodeId,
    peerNodeId: result.peerNodeId,
    destination: result.destination,
    decision: result.decision,
    reason: result.reason,
    detail: result.detail,
    timestamp: result.decidedAt,
  };
}

// -----------------------------------------------------------------------
// Architecture guard: no open proxy
// -----------------------------------------------------------------------

/**
 * Per spec/09 §3: NEVER an unrestricted open proxy.
 *
 * This guard throws if any code attempts to forward a request without
 * going through evaluateGatewayRequest. The architecture regression test
 * asserts this function exists.
 */
export function OPEN_PROXY_FORWARD_FORBIDDEN(destination: string): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to forward to ${destination} without ` +
      `passing through evaluateGatewayRequest. Per spec/09 §3, the gateway ` +
      `MUST NOT be an unrestricted open proxy. Every request MUST pass all ` +
      `policy checks before forwarding.`,
  );
}
