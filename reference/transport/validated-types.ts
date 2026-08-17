/**
 * ShareNet 2.0 — Proof-Carrying Validated Types (R-006 Hardening).
 *
 * Per R-006 hardening requirement:
 *
 *   TypeScript interfaces are being used where we really need:
 *     validated state transition → unforgeable artifact → next-layer API
 *
 * This module introduces unforgeable runtime-branded types that can only
 * be constructed through their respective security boundaries:
 *
 *   AuthenticatedNodeRecord  — only from a verified NodeAdvertisement
 *   ValidatedHop              — only from AuthenticatedNodeRecord + LINK_UP + service agreement
 *   BrandedCommittedRoute     — only from createRouteCommitment (which verifies signatures)
 *
 * Each carries a private Symbol brand that cannot be forged by external code.
 * The brand is checked at runtime by the consuming API (e.g. setupCircuit).
 *
 * This replaces "guard function throws" with "type boundary prevents construction."
 */

// -----------------------------------------------------------------------
// Private brand symbols (unforgeable at runtime)
// -----------------------------------------------------------------------

const AUTHENTICATED_NODE_BRAND = Symbol("SHARENET/AUTHENTICATED_NODE");
const VALIDATED_HOP_BRAND = Symbol("SHARENET/VALIDATED_HOP");
const COMMITTED_ROUTE_BRAND = Symbol("SHARENET/COMMITTED_ROUTE");

// -----------------------------------------------------------------------
// AuthenticatedNodeRecord — only from a verified NodeAdvertisement
// -----------------------------------------------------------------------

/**
 * An AuthenticatedNodeRecord is an unforgeable artifact proving that a
 * NodeAdvertisement was cryptographically verified (signature, identity
 * binding, timestamps, expiry, canonical encoding).
 *
 * Per spec/03 §5 and ADR-0007:
 *   NodeAdvertisement → verifyAdvertisement → AuthenticatedNodeRecord
 *
 * A RemoteNodeHint CANNOT produce this type. A raw NodeId string CANNOT
 * produce this type. Only a verified advertisement can.
 */
export interface AuthenticatedNodeRecord {
  readonly __brand: typeof AUTHENTICATED_NODE_BRAND;
  readonly nodeId: string;
  readonly publicKey: Uint8Array;
  readonly capabilities: readonly string[];
  readonly endpoints: readonly string[];
  readonly sequence: number;
  readonly verifiedAt: number;
  readonly expiresAt: number;
}

/**
 * The ONLY function that creates an AuthenticatedNodeRecord.
 * It requires a VerifiedNodeAdvertisement (the output of verifyAdvertisement).
 *
 * Per R-006 hardening: RemoteNodeHint → AuthenticatedNodeRecord is IMPOSSIBLE
 * because this function only accepts the verified advertisement output type.
 */
export function createAuthenticatedNodeRecord(
  verified: {
    advertisement: {
      nodeId: string;
      signingPublicKey: Uint8Array;
      capabilities: readonly string[];
      endpoints: readonly { type: string; address: string; port: number }[];
      sequence: number;
      expiry: number;
    };
    verifiedAt: number;
  },
): AuthenticatedNodeRecord {
  const adv = verified.advertisement;
  return {
    __brand: AUTHENTICATED_NODE_BRAND,
    nodeId: adv.nodeId,
    publicKey: adv.signingPublicKey,
    capabilities: adv.capabilities,
    endpoints: adv.endpoints.map((e) => `${e.address}:${e.port}`),
    sequence: adv.sequence,
    verifiedAt: verified.verifiedAt,
    expiresAt: adv.expiry,
  };
}

/**
 * Runtime check: is this object a genuine AuthenticatedNodeRecord?
 * Checks for the unforgeable Symbol brand stored under the __brand key.
 */
export function isAuthenticatedNodeRecord(obj: unknown): obj is AuthenticatedNodeRecord {
  return typeof obj === "object" && obj !== null &&
    (obj as { __brand?: unknown }).__brand === AUTHENTICATED_NODE_BRAND;
}

// -----------------------------------------------------------------------
// ValidatedHop — only from AuthenticatedNodeRecord + LINK_UP + service agreement
// -----------------------------------------------------------------------

export interface ValidatedHop {
  readonly __brand: typeof VALIDATED_HOP_BRAND;
  readonly nodeId: string;
  readonly capability: string;
  readonly endpoint: string;
  readonly authenticatedNode: AuthenticatedNodeRecord;
  readonly linkUp: true; // always true — only constructible when LINK_UP
  readonly serviceAgreementDigest: string;
}

/**
 * The ONLY function that creates a ValidatedHop.
 * It requires:
 *   1. An AuthenticatedNodeRecord (not a hint, not a string)
 *   2. A linkUp=true confirmation (the link is established)
 *   3. A service agreement digest (service was negotiated)
 *
 * Per R-006 hardening:
 *   RemoteNodeHint → ValidatedHop is IMPOSSIBLE (no AuthenticatedNodeRecord)
 *   arbitrary NodeId → ValidatedHop is IMPOSSIBLE (no AuthenticatedNodeRecord)
 *   ADV_VERIFIED-only link → ValidatedHop is IMPOSSIBLE (linkUp must be true)
 */
export function createValidatedHop(
  node: AuthenticatedNodeRecord,
  endpoint: string,
  capability: string,
  linkUp: boolean,
  serviceAgreementDigest: string,
): ValidatedHop {
  if (!isAuthenticatedNodeRecord(node)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: cannot create ValidatedHop — node is not an AuthenticatedNodeRecord. " +
      "Per R-006 hardening, only verified advertisements can produce executable hops.",
    );
  }
  if (!linkUp) {
    throw new Error(
      "ARCHITECTURE VIOLATION: cannot create ValidatedHop — link is not LINK_UP. " +
      "ADV_VERIFIED is not routable. Only LINK_UP links can produce executable hops.",
    );
  }
  return {
    __brand: VALIDATED_HOP_BRAND,
    nodeId: node.nodeId,
    capability,
    endpoint,
    authenticatedNode: node,
    linkUp: true,
    serviceAgreementDigest,
  };
}

/**
 * Runtime check: is this object a genuine ValidatedHop?
 * Checks for the unforgeable Symbol brand stored under the __brand key.
 */
export function isValidatedHop(obj: unknown): obj is ValidatedHop {
  return typeof obj === "object" && obj !== null &&
    (obj as { __brand?: unknown }).__brand === VALIDATED_HOP_BRAND;
}

// -----------------------------------------------------------------------
// BrandedCommittedRoute — only from createRouteCommitment
// -----------------------------------------------------------------------

/**
 * A BrandedCommittedRoute carries an unforgeable runtime marker proving
 * it was produced by createRouteCommitment (which verifies all signatures).
 *
 * Per R-006 hardening:
 *   RouteProposal → BrandedCommittedRoute is IMPOSSIBLE (no brand)
 *   plain object → BrandedCommittedRoute is IMPOSSIBLE (no brand)
 *   topology data → BrandedCommittedRoute is IMPOSSIBLE (no brand)
 *
 * Only createBrandedCommittedRoute() can produce this type.
 */
export interface BrandedCommittedRoute {
  readonly __brand: typeof COMMITTED_ROUTE_BRAND;
  readonly routeId: string;
  readonly hops: readonly ValidatedHop[];
  readonly expiry: number;
  readonly initiatorNodeId: string;
  readonly agreementDigest: string;
  readonly committedAt: number;
}

/**
 * The ONLY function that creates a BrandedCommittedRoute.
 * It wraps the output of createCommittedRoute with the unforgeable brand.
 *
 * Per R-006 hardening: setupCircuit MUST verify this brand at runtime
 * before accepting the route.
 */
export function createBrandedCommittedRoute(
  commitment: {
    routeId: string;
    hops: readonly ValidatedHop[];
    expiry: number;
    initiatorNodeId: string;
    agreementDigest: string;
    committedAt: number;
  },
): BrandedCommittedRoute {
  // Verify all hops are genuine ValidatedHop instances
  for (const hop of commitment.hops) {
    if (!isValidatedHop(hop)) {
      throw new Error(
        "ARCHITECTURE VIOLATION: cannot create BrandedCommittedRoute — " +
        "a hop is not a ValidatedHop. Only validated hops can enter a committed route.",
      );
    }
  }
  return {
    __brand: COMMITTED_ROUTE_BRAND,
    ...commitment,
  };
}

/**
 * Runtime check: is this object a genuine BrandedCommittedRoute?
 * Checks for the unforgeable Symbol brand stored under the __brand key.
 *
 * Per R-006 hardening: setupCircuit MUST call this before accepting a route.
 * A plain object or RouteProposal will NOT pass this check.
 */
export function isBrandedCommittedRoute(obj: unknown): obj is BrandedCommittedRoute {
  return typeof obj === "object" && obj !== null &&
    (obj as { __brand?: unknown }).__brand === COMMITTED_ROUTE_BRAND;
}

// -----------------------------------------------------------------------
// Architecture guards (preserved for backward compatibility)
// -----------------------------------------------------------------------

/**
 * Per R-006 hardening: RemoteNodeHint → ValidatedHop is IMPOSSIBLE
 * because createValidatedHop requires an AuthenticatedNodeRecord.
 * This guard is a belt-and-suspenders assertion.
 */
export function HINT_TO_VALIDATED_HOP_FORBIDDEN(hint: { subjectNodeId: string }): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create a ValidatedHop from a RemoteNodeHint ` +
      `(subject=${hint.subjectNodeId.slice(0, 24)}...). Per R-006 hardening, only an ` +
      `AuthenticatedNodeRecord (from a verified NodeAdvertisement) can produce a ` +
      `ValidatedHop. Hints are reported identities, not authenticated ones.`,
  );
}

/**
 * Per R-006 hardening: plain object → BrandedCommittedRoute is IMPOSSIBLE
 * because the brand is an unforgeable Symbol. This guard is a belt-and-suspenders assertion.
 */
export function UNBRANDED_ROUTE_FORBIDDEN(obj: unknown): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to use an unbranded object as a CommittedRoute. ` +
      `Per R-006 hardening, only createBrandedCommittedRoute (which verifies all ` +
      `acceptance signatures and requires ValidatedHops) can produce a route ` +
      `acceptable to setupCircuit. Plain objects and RouteProposals are forbidden.`,
  );
}
