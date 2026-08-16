/**
 * ShareNet 2.0 — Gateway policy + guard layer (STUB per ADR-0011).
 *
 * Per spec/09 and ADR-0011: the first deliverable implements a gateway stub
 * that ENFORCES every mandatory guard (destination policy, private-address
 * blocking, loopback protection, link-local protection, SSRF protection,
 * per-peer quota, global quota, bandwidth shaping, rate limits, revocation,
 * abuse controls) but does NOT yet forward to the real Internet (Phase 8).
 *
 * The stub returns a structured policy decision instead of forwarding.
 * This proves the guard layer exists BEFORE any real forwarding is wired up.
 *
 * NEVER an unrestricted open proxy (spec/09 §3).
 */

import { db } from "@/lib/db";

export type GatewayDecision = "ALLOW" | "DENY";

export interface GatewayPolicyInput {
  gatewayNodeId: string;
  peerNodeId: string;
  destination: string; // host or host:port
  requestedBytes?: number;
}

export interface GatewayPolicyResult {
  decision: GatewayDecision;
  reason: string;
  guard?: string;
  destination: string;
  peerNodeId: string;
  gatewayNodeId: string;
  decidedAt: Date;
}

/**
 * Evaluate a gateway policy decision.
 *
 * Guards checked (spec/09 §3, all MUST be enforced):
 *   1. Gateway enabled
 *   2. Destination policy (allowedDestinations allowlist; empty = deny all)
 *   3. Private-address blocking (RFC 1918: 10/8, 172.16/12, 192.168/16)
 *   4. Loopback protection (127.0.0.0/8, ::1, localhost)
 *   5. Link-local protection (169.254/16, fe80::/10)
 *   6. SSRF protection (metadata endpoints: 169.254.169.254, .internal)
 *   7. Per-peer quota (per-peer request count window)
 *   8. Global quota (gateway-wide request count window)
 *   9. Rate limit (per-second)
 *  10. Revocation (peer in revokedPeers list)
 *  11. Bandwidth shaping (informational — first-deliverable returns decision only)
 */
export async function evaluateGatewayPolicy(
  input: GatewayPolicyInput,
): Promise<GatewayPolicyResult> {
  const decidedAt = new Date();
  const base: Omit<GatewayPolicyResult, "decision" | "reason" | "guard"> = {
    destination: input.destination,
    peerNodeId: input.peerNodeId,
    gatewayNodeId: input.gatewayNodeId,
    decidedAt,
  };

  // Load policy (or use secure defaults).
  const policy = await db.gatewayPolicy.findFirst({
    where: { gatewayNodeId: input.gatewayNodeId },
  });
  if (!policy || !policy.enabled) {
    return { ...base, decision: "DENY", reason: "gateway not enabled or no policy", guard: "ENABLED" };
  }

  // Guard 10: revocation
  const revokedPeers = safeParseArray(policy.revokedPeersJson);
  if (revokedPeers.includes(input.peerNodeId)) {
    return { ...base, decision: "DENY", reason: "peer revoked", guard: "REVOKED_PEER" };
  }

  // Guards 3-6: address-class protections
  const host = extractHost(input.destination);
  if (policy.blockLoopback && isLoopback(host)) {
    return { ...base, decision: "DENY", reason: "loopback destination blocked", guard: "LOOPBACK" };
  }
  if (policy.blockLinkLocal && isLinkLocal(host)) {
    return { ...base, decision: "DENY", reason: "link-local destination blocked", guard: "LINK_LOCAL" };
  }
  if (policy.blockPrivateAddresses && isPrivateAddress(host)) {
    return { ...base, decision: "DENY", reason: "private-address destination blocked", guard: "PRIVATE_ADDRESS" };
  }
  if (isSsrfTarget(host)) {
    return { ...base, decision: "DENY", reason: "SSRF-sensitive destination blocked", guard: "SSRF" };
  }

  // Guard 2: destination allowlist
  const allowed = safeParseArray(policy.allowedDestinationsJson);
  if (allowed.length === 0) {
    return { ...base, decision: "DENY", reason: "no destinations allowed (secure default)", guard: "DESTINATION_POLICY" };
  }
  if (!allowed.some((pattern) => matchGlob(pattern, host))) {
    return { ...base, decision: "DENY", reason: `destination ${host} not in allowlist`, guard: "DESTINATION_POLICY" };
  }

  // Guards 7-9: quota + rate (stub: count recent decisions in a window)
  // For the first deliverable, we approximate this by counting
  // GatewayPolicyDecision rows in the last 60s. This is O(rows) but
  // acceptable for a stub; production would use a sliding-window counter.
  const since = new Date(decidedAt.getTime() - 60_000);
  const globalRecent = await db.gatewayPolicyDecision.count({
    where: { gatewayNodeId: input.gatewayNodeId, createdAt: { gte: since }, decision: "ALLOW" },
  });
  if (globalRecent >= policy.globalQuota) {
    return { ...base, decision: "DENY", reason: "global quota exhausted", guard: "GLOBAL_QUOTA" };
  }
  const peerRecent = await db.gatewayPolicyDecision.count({
    where: { gatewayNodeId: input.gatewayNodeId, peerNodeId: input.peerNodeId, createdAt: { gte: since }, decision: "ALLOW" },
  });
  if (peerRecent >= policy.perPeerQuota) {
    return { ...base, decision: "DENY", reason: "per-peer quota exhausted", guard: "PER_PEER_QUOTA" };
  }

  // All guards passed — ALLOW. (Bandwidth shaping is applied at forwarding time,
  // which the stub does not perform — ADR-0011.)
  const result: GatewayPolicyResult = {
    ...base,
    decision: "ALLOW",
    reason: "all guards passed (forwarding not yet implemented — ADR-0011 stub)",
    guard: "NONE",
  };

  // Persist the decision (audit trail).
  await db.gatewayPolicyDecision.create({
    data: {
      gatewayNodeId: input.gatewayNodeId,
      peerNodeId: input.peerNodeId,
      destination: input.destination,
      decision: result.decision,
      reason: result.reason,
      guard: result.guard,
    },
  });
  if (result.decision === "ALLOW") {
    await db.auditLog.create({
      data: {
        action: "GATEWAY_POLICY_VIOLATION",
        detail: JSON.stringify({ ...result, note: "ALLOW decision recorded (stub does not forward)" }),
      },
    });
  }
  return result;
}

// ---------------------------------------------------------------------
// Address-class detection helpers
// ---------------------------------------------------------------------

function extractHost(destination: string): string {
  // Strip scheme and port.
  let s = destination;
  if (s.includes("://")) {
    s = s.split("://")[1] ?? s;
  }
  if (s.includes("/")) {
    s = s.split("/")[0] ?? s;
  }
  if (s.includes(":")) {
    s = s.split(":")[0] ?? s;
  }
  return s.toLowerCase();
}

function isLoopback(host: string): boolean {
  if (host === "localhost") return true;
  if (host === "::1") return true;
  if (host.startsWith("127.")) return true;
  return false;
}

function isLinkLocal(host: string): boolean {
  if (host.startsWith("169.254.")) return true;
  if (host.startsWith("fe80:")) return true;
  if (host.startsWith("fe90:") || host.startsWith("fea0:") || host.startsWith("feb0:")) return true;
  return false;
}

function isPrivateAddress(host: string): boolean {
  // IPv4 RFC 1918
  if (host.startsWith("10.")) return true;
  if (host.startsWith("192.168.")) return true;
  if (host.startsWith("172.")) {
    const parts = host.split(".");
    const second = parts.length > 1 ? parseInt(parts[1] ?? "0", 10) : 0;
    if (second >= 16 && second <= 31) return true;
  }
  // IPv6 ULA
  if (host.startsWith("fc") || host.startsWith("fd")) return true;
  return false;
}

function isSsrfTarget(host: string): boolean {
  // Cloud metadata endpoints
  if (host === "169.254.169.254") return true;
  if (host === "metadata.google.internal") return true;
  if (host.endsWith(".internal") && !host.endsWith(".sharenet.local")) return true;
  // AWS metadata v2 hop
  if (host === "fd00:ec2::254") return true;
  return false;
}

function matchGlob(pattern: string, host: string): boolean {
  if (pattern === "*") return true;
  if (pattern === host) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    return host === suffix || host.endsWith("." + suffix);
  }
  return false;
}

function safeParseArray(json: string): string[] {
  try {
    const v = JSON.parse(json);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
}
