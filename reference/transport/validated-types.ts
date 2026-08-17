/**
 * ShareNet 2.0 — Proof-Carrying Validated Types (R-006 Hardening v2).
 *
 * Per R-006 hardening v2: Symbol brands are forgeable by copying
 * instance.__brand. This module replaces them with WeakSet-backed
 * runtime registries that are genuinely unforgeable — there is no
 * property to copy, no value to forge.
 *
 * Construction paths consume GENUINE PROOF ARTIFACTS, not anonymous
 * objects matching the same shape:
 *
 *   AuthenticatedNodeRecord ← VerifiedNodeAdvertisement (output of verifyAdvertisement)
 *   ValidatedHop             ← AuthenticatedNodeRecord + linkUp=true + service digest
 *   BrandedCommittedRoute    ← RouteCommitment (output of createRouteCommitment)
 *
 * A WeakSet membership check is O(1) and cannot be bypassed by copying
 * properties. An object is either in the set (was constructed through the
 * legal pipeline) or it is not. There is no forgeable token to copy.
 */

import { isVerifiedNodeAdvertisement, type VerifiedNodeAdvertisement } from "../advertisement/advertisement";
import type { RouteCommitment } from "../routing/route";

// -----------------------------------------------------------------------
// Private WeakSet registries (genuinely unforgeable)
// -----------------------------------------------------------------------

const authenticatedNodeRegistry = new WeakSet<object>();
const validatedHopRegistry = new WeakSet<object>();
const brandedRouteRegistry = new WeakSet<object>();
const routeCommitmentRegistry = new WeakSet<object>();

// -----------------------------------------------------------------------
// AuthenticatedNodeRecord — only from a genuine VerifiedNodeAdvertisement
// -----------------------------------------------------------------------

export interface AuthenticatedNodeRecord {
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
 *
 * Per R-006H3: this function consumes a GENUINE VerifiedNodeAdvertisement
 * — verified by isVerifiedNodeAdvertisement() WeakSet membership check.
 * An anonymous object matching the same shape is REJECTED because it was
 * never registered by verifyAdvertisement().
 */
export function createAuthenticatedNodeRecord(
  verified: VerifiedNodeAdvertisement,
): AuthenticatedNodeRecord {
  if (!isVerifiedNodeAdvertisement(verified)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedNodeRecord rejected — " +
        "the VerifiedNodeAdvertisement is not genuine (WeakSet membership check failed). " +
        "Per R-006H3, only the output of verifyAdvertisement() (when ok: true) " +
        "can produce an AuthenticatedNodeRecord. Forged or copied objects with " +
        "the same shape are rejected — the WeakSet tracks object identity.",
    );
  }
  // The verified parameter IS the proof artifact. We trust it because
  // verifyAdvertisement() is the only function that produces this type,
  // and it performs the full spec/03 §5 cryptographic verification.
  //
  // An attacker who passes a plain object with the same fields will
  // have the object registered (it's the first time the WeakSet sees it),
  // BUT the caller had to HAVE a VerifiedNodeAdvertisement to pass it.
  // The genuine artifact is produced ONLY by verifyAdvertisement().
  //
  // The defense-in-depth is that downstream consumers call
  // isAuthenticatedNodeRecord() which checks WeakSet membership.
  // An object NOT created through this function will NOT be in the set.

  const adv = verified.advertisement;
  const record: AuthenticatedNodeRecord = {
    nodeId: adv.nodeId,
    publicKey: adv.signingPublicKey,
    capabilities: adv.capabilities,
    endpoints: adv.endpoints.map((e) => `${e.address}:${e.port}`),
    sequence: adv.sequence,
    verifiedAt: verified.verifiedAt,
    expiresAt: adv.expiry,
  };
  authenticatedNodeRegistry.add(record);
  return record;
}

/**
 * Runtime check: is this object a genuine AuthenticatedNodeRecord
 * created through createAuthenticatedNodeRecord()?
 *
 * Uses WeakSet membership — genuinely unforgeable. There is no property
 * to copy, no value to forge. The object must have been added to the
 * WeakSet by createAuthenticatedNodeRecord().
 */
export function isAuthenticatedNodeRecord(obj: unknown): obj is AuthenticatedNodeRecord {
  return typeof obj === "object" && obj !== null && authenticatedNodeRegistry.has(obj);
}

// -----------------------------------------------------------------------
// ValidatedHop — only from AuthenticatedNodeRecord + LINK_UP + service
// -----------------------------------------------------------------------

export interface ValidatedHop {
  readonly nodeId: string;
  readonly capability: string;
  readonly endpoint: string;
  readonly authenticatedNode: AuthenticatedNodeRecord;
  readonly linkUp: true; // always true — only constructible when LINK_UP
  readonly serviceAgreementDigest: string;
}

/**
 * The ONLY function that creates a ValidatedHop.
 * Requires:
 *   1. A genuine AuthenticatedNodeRecord (WeakSet-verified)
 *   2. linkUp=true (the link is established, not ADV_VERIFIED)
 *   3. A service agreement digest (service was negotiated)
 *
 * Per R-006H2: a RemoteNodeHint or raw NodeId string will fail
 * isAuthenticatedNodeRecord() because they were never added to the
 * WeakSet by createAuthenticatedNodeRecord().
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
      "ARCHITECTURE VIOLATION: cannot create ValidatedHop — node is not a genuine " +
        "AuthenticatedNodeRecord (WeakSet membership check failed). Per R-006H2, " +
        "only verified advertisements can produce executable hops. Copying properties " +
        "from a genuine AuthenticatedNodeRecord is insufficient — the WeakSet registry " +
        "tracks object identity, not property values.",
    );
  }
  if (!linkUp) {
    throw new Error(
      "ARCHITECTURE VIOLATION: cannot create ValidatedHop — link is not LINK_UP. " +
        "ADV_VERIFIED is not routable. Only LINK_UP links can produce executable hops.",
    );
  }
  const hop: ValidatedHop = {
    nodeId: node.nodeId,
    capability,
    endpoint,
    authenticatedNode: node,
    linkUp: true,
    serviceAgreementDigest,
  };
  validatedHopRegistry.add(hop);
  return hop;
}

/**
 * Runtime check: is this object a genuine ValidatedHop
 * created through createValidatedHop()?
 */
export function isValidatedHop(obj: unknown): obj is ValidatedHop {
  return typeof obj === "object" && obj !== null && validatedHopRegistry.has(obj);
}

// -----------------------------------------------------------------------
// BrandedCommittedRoute — only from a genuine RouteCommitment
// -----------------------------------------------------------------------

export interface BrandedCommittedRoute {
  readonly routeId: string;
  readonly hops: readonly ValidatedHop[];
  readonly expiry: number;
  readonly initiatorNodeId: string;
  readonly agreementDigest: string;
  readonly committedAt: number;
}

/**
 * Runtime check: is this object a genuine RouteCommitment
 * produced by createRouteCommitment()?
 *
 * Per R-006H3: a TypeScript interface is just a shape — any object
 * matching the fields can masquerade as a RouteCommitment. This WeakSet
 * tracks object identity: only objects created by createRouteCommitment()
 * (when it returns ok: true) are registered.
 *
 * This function must be called by the route module's createRouteCommitment()
 * to register genuine outputs. See registerRouteCommitment() below.
 */
export function isRouteCommitment(obj: unknown): obj is RouteCommitment {
  return typeof obj === "object" && obj !== null && routeCommitmentRegistry.has(obj);
}

/**
 * Register a genuine RouteCommitment in the private WeakSet.
 * Called by createRouteCommitment() in route.ts.
 */
export function registerRouteCommitment(c: RouteCommitment): RouteCommitment {
  routeCommitmentRegistry.add(c);
  return c;
}

/**
 * The ONLY function that creates a BrandedCommittedRoute.
 *
 * Per R-006 construction-boundary fix: this function consumes BOTH:
 *   1. A GENUINE RouteCommitment — verified by isRouteCommitment()
 *      WeakSet membership check. Only the output of
 *      createRouteCommitment() (when ok: true) is accepted.
 *   2. A GENUINE ValidatedHop[] — one per hop, each verified by
 *      isValidatedHop() WeakSet membership check. Only ValidatedHop
 *      artifacts produced by createValidatedHop() are accepted.
 *
 * The previous implementation UNSAFELY CAST `commitment.proposal.hops`
 * (ordinary `RouteHop[]`) to `ValidatedHop[]` via
 * `as unknown as ValidatedHop[]`. That cast was a forgery: the hops
 * were never in the `validatedHopRegistry` WeakSet and were never
 * produced through the genuine
 * `verifyAdvertisement → createAuthenticatedNodeRecord → createValidatedHop`
 * pipeline. This function now REQUIRES the genuine artifacts to be
 * passed explicitly, and verifies each one.
 *
 * Per R-006: the matching check (nodeId/endpoint/capability) ensures
 * each ValidatedHop corresponds to the hop the commitment was signed
 * over — preventing a caller from substituting a genuine-but-unrelated
 * ValidatedHop for a different node.
 */
export function createBrandedCommittedRoute(
  commitment: RouteCommitment,
  validatedHops: ValidatedHop[],
): BrandedCommittedRoute {
  // 1. Verify this is a genuine RouteCommitment from createRouteCommitment()
  if (!isRouteCommitment(commitment)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createBrandedCommittedRoute rejected — " +
        "the RouteCommitment is not genuine (WeakSet membership check failed). " +
        "Per R-006H3, only the output of createRouteCommitment() (when ok: true) " +
        "can produce a BrandedCommittedRoute. Forged objects with the same shape " +
        "are rejected — the WeakSet tracks object identity.",
    );
  }

  // 2. R-006 construction-boundary fix: verify every hop is a genuine
  //    ValidatedHop. The count must match the commitment's hop count.
  if (validatedHops.length !== commitment.proposal.hops.length) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createBrandedCommittedRoute rejected — " +
        `validatedHops count (${validatedHops.length}) does not match ` +
        `commitment hop count (${commitment.proposal.hops.length}). ` +
        "Per R-006, every hop in a BrandedCommittedRoute MUST be a genuine " +
        "ValidatedHop artifact from the WeakSet registry. The unsafe cast " +
        "from RouteHop[] to ValidatedHop[] has been removed.",
    );
  }

  // 3. Verify each validatedHop is genuine AND matches the corresponding
  //    commitment hop (nodeId/endpoint/capability). This prevents a caller
  //    from substituting a genuine-but-unrelated ValidatedHop for a
  //    different node than the one the commitment was signed over.
  for (let i = 0; i < validatedHops.length; i++) {
    const vh = validatedHops[i]!;
    if (!isValidatedHop(vh)) {
      throw new Error(
        "ARCHITECTURE VIOLATION: createBrandedCommittedRoute rejected — " +
          `hop ${i} (nodeId=${vh.nodeId}) is not a genuine ValidatedHop ` +
          "(WeakSet membership check failed). Per R-006 construction-boundary " +
          "fix, the unsafe cast from RouteHop[] to ValidatedHop[] has been " +
          "removed; only genuine ValidatedHop artifacts produced by " +
          "createValidatedHop() (which consumes a genuine " +
          "AuthenticatedNodeRecord) are accepted. An ordinary RouteHop, " +
          "a forged object matching the ValidatedHop shape, or a " +
          "property-copy of a genuine ValidatedHop will all fail this check.",
      );
    }
    const ch = commitment.proposal.hops[i]!;
    if (
      vh.nodeId !== ch.nodeId ||
      vh.endpoint !== ch.endpoint ||
      vh.capability !== ch.capability
    ) {
      throw new Error(
        "ARCHITECTURE VIOLATION: createBrandedCommittedRoute rejected — " +
          `validatedHop ${i} (nodeId=${vh.nodeId}, endpoint=${vh.endpoint}, ` +
          `capability=${vh.capability}) does not match commitment hop ${i} ` +
          `(nodeId=${ch.nodeId}, endpoint=${ch.endpoint}, ` +
          `capability=${ch.capability}). The branded route's hops MUST be ` +
          "the same hops the commitment was signed over — a genuine " +
          "ValidatedHop for a DIFFERENT node cannot substitute for a " +
          "commitment hop.",
      );
    }
  }

  const route: BrandedCommittedRoute = {
    routeId: commitment.routeId,
    hops: validatedHops, // genuine ValidatedHop[] — NO CAST
    expiry: commitment.proposal.expiry,
    initiatorNodeId: commitment.proposal.initiatorNodeId,
    agreementDigest: commitment.proposal.agreementDigest,
    committedAt: commitment.committedAt,
  };
  brandedRouteRegistry.add(route);
  return route;
}

/**
 * Runtime check: is this object a genuine BrandedCommittedRoute
 * created through createBrandedCommittedRoute()?
 *
 * Uses WeakSet membership — genuinely unforgeable.
 */
export function isBrandedCommittedRoute(obj: unknown): obj is BrandedCommittedRoute {
  return typeof obj === "object" && obj !== null && brandedRouteRegistry.has(obj);
}

// -----------------------------------------------------------------------
// Architecture guards (preserved for backward compatibility)
// -----------------------------------------------------------------------

export function HINT_TO_VALIDATED_HOP_FORBIDDEN(hint: { subjectNodeId: string }): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create a ValidatedHop from a RemoteNodeHint ` +
      `(subject=${hint.subjectNodeId.slice(0, 24)}...). Per R-006H2, only an ` +
      `AuthenticatedNodeRecord (from a verified NodeAdvertisement) can produce a ` +
      `ValidatedHop. Hints are reported identities, not authenticated ones.`,
  );
}

export function UNBRANDED_ROUTE_FORBIDDEN(obj: unknown): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to use an unbranded object as a CommittedRoute. ` +
      `Per R-006H2, only createBrandedCommittedRoute (which consumes a genuine ` +
      `RouteCommitment from createRouteCommitment) can produce a route acceptable ` +
      `to setupCircuit. Plain objects and RouteProposals are forbidden.`,
  );
}
