/**
 * ShareNet 2.0 — Service Negotiation Types (GATE-05).
 *
 * Per spec/09-internet-gateway.md §2 (Gateway model) and spec/07-routing.md:
 *
 *   Service flow:
 *     Service Requirement
 *         ↓
 *     Capability Offer
 *         ↓
 *     Policy Check
 *         ↓
 *     Capacity Check
 *         ↓
 *     Service Agreement
 *
 * These types are DISTINCT from routing types (RouteProposal etc.) and from
 * link types (LINK_UP, ADV_VERIFIED). A service agreement is a prerequisite
 * for route commitment, NOT a route itself.
 *
 * Per spec/00 §21 (Capabilities):
 *   A capability means: "this node supports this service class."
 *   It does NOT mean: "the service is currently available."
 *   It does NOT mean: "the requester is authorized to use it."
 */

// -----------------------------------------------------------------------
// Capabilities (re-exported from advertisement for convenience)
// -----------------------------------------------------------------------

export type NodeCapability =
  | "MESH_RELAY"
  | "INTERNET_GATEWAY"
  | "CONTENT_SEED"
  | "STORAGE"
  | "DISCOVERY"
  | "SYNC"
  | "COMPUTE"
  | "CRYPTO_RELAY"
  | "CRYPTO_GATEWAY"
  | "PAYMENT_RELAY";

// -----------------------------------------------------------------------
// Service Requirement (what the initiator needs)
// -----------------------------------------------------------------------

/**
 * A service requirement describes what the initiator needs from the network.
 * This is the INPUT to route construction — NOT an executable route.
 */
export interface ServiceRequirement {
  /** The capability the initiator needs (e.g. INTERNET_GATEWAY). */
  requiredCapability: NodeCapability;
  /** The destination (e.g. "example.com:443" for gateway, or a nodeId for relay). */
  destination?: string;
  /** Maximum hops the initiator is willing to traverse. */
  maxHops: number;
  /** Requested bandwidth in bytes/sec (0 = no specific request). */
  bandwidthBps?: number;
  /** Expiry of the requirement (unix seconds). After this, the requirement is void. */
  expiry: number;
}

// -----------------------------------------------------------------------
// Capability Offer (what a node advertises it CAN do)
// -----------------------------------------------------------------------

/**
 * A capability offer is a node's declaration that it supports a service class.
 * This is derived from the node's AuthenticatedNodeRecord + LINK_UP status.
 *
 * Per spec/00 §21: a capability ≠ currently available ≠ authorized.
 * This offer only means "the node claims to support this capability."
 */
export interface CapabilityOffer {
  /** The node offering the capability. Must be an AuthenticatedNodeRecord. */
  nodeId: string;
  /** The capability being offered. */
  capability: NodeCapability;
  /** The node's advertised endpoints. */
  endpoints: readonly string[];
  /** Whether the node has a LINK_UP to the requester (prerequisite for routing). */
  linkUp: boolean;
  /** Whether the node is ADV_VERIFIED only (NOT routable). */
  advVerifiedOnly: boolean;
}

// -----------------------------------------------------------------------
// Policy Check
// -----------------------------------------------------------------------

export type PolicyCheckResult =
  | { ok: true; policyVersion: number }
  | { ok: false; reason: PolicyRejectionReason };

export type PolicyRejectionReason =
  | "DESTINATION_NOT_ALLOWED"   // destination not in allowlist
  | "DESTINATION_BLOCKED_SSRF"  // SSRF-sensitive destination
  | "DESTINATION_BLOCKED_PRIVATE" // RFC 1918 private address
  | "DESTINATION_BLOCKED_LOOPBACK" // 127.0.0.0/8, ::1
  | "DESTINATION_BLOCKED_LINK_LOCAL" // 169.254/16, fe80::/10
  | "PEER_REVOKED"              // peer in revocation list
  | "CAPABILITY_MISMATCH"       // node doesn't offer the required capability
  | "ADV_VERIFIED_ONLY"         // node is ADV_VERIFIED, not LINK_UP — not routable
  | "NO_LINK_UP"                // no LINK_UP to this node
  | "EXPIRED"                   // requirement or offer expired
  | "MAX_HOPS_EXCEEDED"         // route would exceed maxHops

/**
 * Check whether a capability offer satisfies a service requirement's policy.
 *
 * Per spec/09 §3 (gateway guards) and spec/07 (routing):
 *   - ADV_VERIFIED links are NOT routable (only LINK_UP)
 *   - The node must have the required capability
 *   - The destination must pass policy checks (for gateway nodes)
 */
export function checkPolicy(
  requirement: ServiceRequirement,
  offer: CapabilityOffer,
  now: number,
  allowedDestinations?: readonly string[],
  revokedPeers?: readonly string[],
): PolicyCheckResult {
  // Check expiry
  if (requirement.expiry <= now) {
    return { ok: false, reason: "EXPIRED" };
  }

  // Check capability match
  if (offer.capability !== requirement.requiredCapability) {
    return { ok: false, reason: "CAPABILITY_MISMATCH" };
  }

  // Check LINK_UP (ADV_VERIFIED is NOT routable)
  if (offer.advVerifiedOnly) {
    return { ok: false, reason: "ADV_VERIFIED_ONLY" };
  }
  if (!offer.linkUp) {
    return { ok: false, reason: "NO_LINK_UP" };
  }

  // Check peer revocation
  if (revokedPeers?.includes(offer.nodeId)) {
    return { ok: false, reason: "PEER_REVOKED" };
  }

  // For gateway capabilities, check destination policy
  if (offer.capability === "INTERNET_GATEWAY" && requirement.destination) {
    const dest = requirement.destination;
    const host = dest.split(":")[0] ?? dest;

    // SSRF checks
    if (isSsrfTarget(host)) {
      return { ok: false, reason: "DESTINATION_BLOCKED_SSRF" };
    }
    if (isLoopback(host)) {
      return { ok: false, reason: "DESTINATION_BLOCKED_LOOPBACK" };
    }
    if (isLinkLocal(host)) {
      return { ok: false, reason: "DESTINATION_BLOCKED_LINK_LOCAL" };
    }
    if (isPrivateAddress(host)) {
      return { ok: false, reason: "DESTINATION_BLOCKED_PRIVATE" };
    }

    // Allowlist check
    if (allowedDestinations && allowedDestinations.length > 0) {
      if (!allowedDestinations.some((pattern) => matchGlob(pattern, host))) {
        return { ok: false, reason: "DESTINATION_NOT_ALLOWED" };
      }
    }
  }

  return { ok: true, policyVersion: 1 };
}

// -----------------------------------------------------------------------
// Capacity Check
// -----------------------------------------------------------------------

export interface CapacityInfo {
  availableBandwidthBps: number;
  availableConnections: number;
  globalQuotaRemaining: number;
  perPeerQuotaRemaining: number;
}

export type CapacityCheckResult =
  | { ok: true; allocatedBandwidthBps: number }
  | { ok: false; reason: CapacityRejectionReason };

export type CapacityRejectionReason =
  | "INSUFFICIENT_BANDWIDTH"
  | "NO_CONNECTIONS_AVAILABLE"
  | "GLOBAL_QUOTA_EXHAUSTED"
  | "PER_PEER_QUOTA_EXHAUSTED"
  | "RATE_LIMIT_EXCEEDED";

/**
 * Check whether the node has capacity to serve the requirement.
 */
export function checkCapacity(
  requirement: ServiceRequirement,
  capacity: CapacityInfo,
): CapacityCheckResult {
  if (capacity.availableConnections <= 0) {
    return { ok: false, reason: "NO_CONNECTIONS_AVAILABLE" };
  }
  if (capacity.globalQuotaRemaining <= 0) {
    return { ok: false, reason: "GLOBAL_QUOTA_EXHAUSTED" };
  }
  if (capacity.perPeerQuotaRemaining <= 0) {
    return { ok: false, reason: "PER_PEER_QUOTA_EXHAUSTED" };
  }
  const allocated = Math.min(
    requirement.bandwidthBps ?? 0,
    capacity.availableBandwidthBps,
  );
  return { ok: true, allocatedBandwidthBps: allocated };
}

// -----------------------------------------------------------------------
// Service Agreement
// -----------------------------------------------------------------------

/**
 * A service agreement is the result of a successful policy + capacity check.
 * It binds a node to providing a service for a specific requirement.
 *
 * This is NOT a route. It is a prerequisite for route construction.
 */
export interface ServiceAgreement {
  /** The node agreeing to provide the service. */
  nodeId: string;
  /** The capability being agreed to. */
  capability: NodeCapability;
  /** The requirement this agreement satisfies. */
  requirementDigest: string; // SHA-256 of the ServiceRequirement
  /** Allocated bandwidth (bytes/sec). */
  allocatedBandwidthBps: number;
  /** Agreement expiry (unix seconds). */
  expiry: number;
  /** Policy version that was checked. */
  policyVersion: number;
}

/**
 * Create a service agreement after policy + capacity checks pass.
 */
export function createServiceAgreement(
  offer: CapabilityOffer,
  requirement: ServiceRequirement,
  capacityResult: CapacityCheckResult,
  policyResult: PolicyCheckResult,
): ServiceAgreement | null {
  if (!policyResult.ok || !capacityResult.ok) return null;
  return {
    nodeId: offer.nodeId,
    capability: offer.capability,
    requirementDigest: "", // computed by caller (needs hash of ServiceRequirement)
    allocatedBandwidthBps: capacityResult.allocatedBandwidthBps,
    expiry: requirement.expiry,
    policyVersion: policyResult.policyVersion,
  };
}

// -----------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------

function extractHost(destination: string): string {
  let s = destination;
  if (s.includes("://")) s = s.split("://")[1] ?? s;
  if (s.includes("/")) s = s.split("/")[0] ?? s;
  if (s.includes(":")) s = s.split(":")[0] ?? s;
  return s.toLowerCase();
}

function isLoopback(host: string): boolean {
  return host === "localhost" || host === "::1" || host.startsWith("127.");
}

function isLinkLocal(host: string): boolean {
  return host.startsWith("169.254.") || host.startsWith("fe80:");
}

function isPrivateAddress(host: string): boolean {
  if (host.startsWith("10.")) return true;
  if (host.startsWith("192.168.")) return true;
  if (host.startsWith("172.")) {
    const second = parseInt(host.split(".")[1] ?? "0", 10);
    if (second >= 16 && second <= 31) return true;
  }
  return host.startsWith("fc") || host.startsWith("fd");
}

function isSsrfTarget(host: string): boolean {
  return host === "169.254.169.254" ||
    host === "metadata.google.internal" ||
    (host.endsWith(".internal") && !host.endsWith(".sharenet.local"));
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
