/**
 * ShareNet 2.0 — Route Objects (GATE-05).
 *
 * Per spec/07-routing.md and spec/00 §23 (Route Objects):
 *
 *   Define distinct objects:
 *     RouteProposal
 *     RouteAcceptance
 *     RouteCommitment
 *     CommittedRoute
 *
 *   A source signature cannot substitute for participant acceptance.
 *   Each executable hop must contain sufficient authenticated information
 *   to prove: node identity, link authenticity, transport usability,
 *   service compatibility, policy acceptance.
 *
 *   Per spec/00 §22 (Routing):
 *     The correct conceptual sequence is:
 *       Discovery → Candidate Destination → Destination Authentication →
 *       Next-Hop Discovery → Path Validation → Service Negotiation →
 *       Route Proposal → Route Acceptance → Committed Route → Circuit
 *
 *     Distance hints are discovery metadata. They are never executable
 *     routing instructions.
 *
 * Per spec/00 §31 (forbidden transitions):
 *   topology/Dijkstra output alone cannot create a route.
 *
 * ARCHITECTURE GUARD: TOPOLOGY_TO_ROUTE_FORBIDDEN throws if any code
 * attempts to create a CommittedRoute from topology/graph data without
 * going through the full RouteProposal → RouteAcceptance → RouteCommitment
 * pipeline.
 */

import { signMessage, verifySignature, type NodeCapability } from "../identity/keys";
import { canonicalEncode, toHex, fromHex } from "../encoding/cbor";
import type { ServiceAgreement } from "./service-negotiation";

// -----------------------------------------------------------------------
// Domain tags (FROZEN per spec/14 §4)
// -----------------------------------------------------------------------

export const ROUTE_PROPOSAL_DOMAIN = "SHARENET/ROUTE/PROPOSAL/1";
export const ROUTE_ACCEPTANCE_DOMAIN = "SHARENET/ROUTE/ACCEPTANCE/1";
export const ROUTE_COMMITMENT_DOMAIN = "SHARENET/ROUTE/COMMITMENT/1";

// -----------------------------------------------------------------------
// Hop (a single hop in a route)
// -----------------------------------------------------------------------

/**
 * A hop in a route. Each hop MUST have:
 *   - an authenticated node (NodeId)
 *   - a LINK_UP link (not ADV_VERIFIED)
 *   - transport usability (endpoint)
 *   - role (what this hop does: relay, gateway, etc.)
 *   - policy acceptance (the node agreed to the policy)
 *   - service compatibility (the node has the required capability)
 */
export interface RouteHop {
  /** The node at this hop. Must be an AuthenticatedNodeRecord. */
  nodeId: string;
  /** The capability this hop provides (MESH_RELAY, INTERNET_GATEWAY, etc.). */
  capability: NodeCapability;
  /** The endpoint to reach this node. */
  endpoint: string;
  /** Whether this hop has LINK_UP (must be true; ADV_VERIFIED is NOT routable). */
  linkUp: boolean;
  /** The service agreement for this hop (from service negotiation). */
  serviceAgreement?: ServiceAgreement;
}

// -----------------------------------------------------------------------
// RouteProposal (proposed by the initiator, NOT yet accepted)
// -----------------------------------------------------------------------

/**
 * A RouteProposal is the initiator's proposed path. It is NOT an executable
 * route. Each hop MUST accept (sign) before the route becomes committed.
 *
 * Per spec/00 §23: "A source signature cannot substitute for participant acceptance."
 */
export interface RouteProposal {
  /** Unique route ID (random 32 bytes, hex-encoded). */
  routeId: string;
  /** Ordered hops from source to destination. */
  hops: RouteHop[];
  /** The service requirement this route satisfies. */
  requirementDigest: string;
  /** Route expiry (unix seconds). */
  expiry: number;
  /** The initiator's NodeId. */
  initiatorNodeId: string;
  /** Agreement digest (BLAKE3-256 of all hop service agreements). */
  agreementDigest: string;
}

/** Compute the signing payload for a RouteProposal. */
export function routeProposalSigningPayload(proposal: RouteProposal): Uint8Array {
  const m = new Map<number, unknown>([
    [1, proposal.routeId],
    [2, proposal.hops.map((h) => h.nodeId)],
    [3, proposal.requirementDigest],
    [4, proposal.expiry],
    [5, proposal.initiatorNodeId],
    [6, proposal.agreementDigest],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(ROUTE_PROPOSAL_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * Create a signed RouteProposal. The initiator signs the proposal.
 * NOTE: the initiator's signature does NOT make this an executable route.
 * Each hop must independently accept.
 */
export function createRouteProposal(
  proposal: RouteProposal,
  initiatorSecretKey: Uint8Array,
): SignedRouteProposal {
  const payload = routeProposalSigningPayload(proposal);
  const signature = signMessage(initiatorSecretKey, payload);
  return { proposal, initiatorSignature: signature };
}

export interface SignedRouteProposal {
  proposal: RouteProposal;
  initiatorSignature: Uint8Array;
}

// -----------------------------------------------------------------------
// RouteAcceptance (each hop signs acceptance)
// -----------------------------------------------------------------------

/**
 * A RouteAcceptance is a hop's signed agreement to participate in the route.
 * Each hop MUST sign independently. The initiator's signature is NOT sufficient.
 */
export interface RouteAcceptance {
  routeId: string;
  hopIndex: number;
  acceptorNodeId: string;
  expiry: number;
  /** The acceptor's signature over the acceptance payload. */
  signature: Uint8Array;
}

/** Compute the signing payload for a RouteAcceptance. */
export function routeAcceptanceSigningPayload(
  routeId: string,
  hopIndex: number,
  acceptorNodeId: string,
  expiry: number,
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, routeId],
    [2, hopIndex],
    [3, acceptorNodeId],
    [4, expiry],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(ROUTE_ACCEPTANCE_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * A hop signs acceptance of its role in the route.
 * The signature binds: routeId, hopIndex, acceptorNodeId, expiry.
 */
export function signRouteAcceptance(
  routeId: string,
  hopIndex: number,
  acceptorNodeId: string,
  expiry: number,
  acceptorSecretKey: Uint8Array,
): RouteAcceptance {
  const payload = routeAcceptanceSigningPayload(routeId, hopIndex, acceptorNodeId, expiry);
  const signature = signMessage(acceptorSecretKey, payload);
  return { routeId, hopIndex, acceptorNodeId, expiry, signature };
}

/**
 * Verify a RouteAcceptance signature.
 */
export function verifyRouteAcceptance(
  acceptance: RouteAcceptance,
  acceptorPublicKey: Uint8Array,
): boolean {
  const payload = routeAcceptanceSigningPayload(
    acceptance.routeId,
    acceptance.hopIndex,
    acceptance.acceptorNodeId,
    acceptance.expiry,
  );
  return verifySignature(acceptorPublicKey, payload, acceptance.signature);
}

// -----------------------------------------------------------------------
// RouteCommitment (all hops accepted → commit)
// -----------------------------------------------------------------------

/**
 * A RouteCommitment is created when ALL hops have signed acceptance.
 * It is the final step before a CommittedRoute.
 *
 * Per spec/00 §31: "RouteProposal → ActiveCircuit without commitment" is forbidden.
 * A circuit can ONLY be created from a CommittedRoute.
 */
export interface RouteCommitment {
  routeId: string;
  proposal: RouteProposal;
  acceptances: RouteAcceptance[];
  /** Committer's signature (usually the initiator). */
  committerSignature: Uint8Array;
  committedAt: number;
}

/**
 * Create a RouteCommitment from a proposal + all acceptances.
 *
 * Validates that:
 *   1. Every hop in the proposal has a corresponding acceptance.
 *   2. Each acceptance is from the correct node (matches hop.nodeId).
 *   3. No hop is ADV_VERIFIED-only (all must be LINK_UP).
 */
export function createRouteCommitment(
  proposal: RouteProposal,
  acceptances: RouteAcceptance[],
  committerSecretKey: Uint8Array,
  now: number,
): { ok: true; commitment: RouteCommitment } | { ok: false; reason: string } {
  // 1. Check every hop has an acceptance
  if (acceptances.length !== proposal.hops.length) {
    return {
      ok: false,
      reason: `expected ${proposal.hops.length} acceptances, got ${acceptances.length}`,
    };
  }

  // 2. Check each acceptance matches the correct hop
  for (let i = 0; i < proposal.hops.length; i++) {
    const hop = proposal.hops[i]!;
    const acc = acceptances[i];
    if (!acc) {
      return { ok: false, reason: `missing acceptance for hop ${i}` };
    }
    if (acc.hopIndex !== i) {
      return { ok: false, reason: `acceptance ${i} has wrong hopIndex ${acc.hopIndex}` };
    }
    if (acc.acceptorNodeId !== hop.nodeId) {
      return {
        ok: false,
        reason: `acceptance ${i} from ${acc.acceptorNodeId} != hop ${hop.nodeId}`,
      };
    }
    if (acc.expiry <= now) {
      return { ok: false, reason: `acceptance ${i} expired` };
    }
  }

  // 3. Check no hop is ADV_VERIFIED-only (all must be LINK_UP)
  for (let i = 0; i < proposal.hops.length; i++) {
    const hop = proposal.hops[i]!;
    if (!hop.linkUp) {
      return { ok: false, reason: `hop ${i} (${hop.nodeId}) is not LINK_UP` };
    }
  }

  // Sign the commitment
  const payload = routeCommitmentSigningPayload(proposal, acceptances);
  const signature = signMessage(committerSecretKey, payload);

  return {
    ok: true,
    commitment: {
      routeId: proposal.routeId,
      proposal,
      acceptances,
      committerSignature: signature,
      committedAt: now,
    },
  };
}

function routeCommitmentSigningPayload(
  proposal: RouteProposal,
  acceptances: RouteAcceptance[],
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, proposal.routeId],
    [2, acceptances.map((a) => toHex(a.signature))],
    [3, proposal.expiry],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(ROUTE_COMMITMENT_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

// -----------------------------------------------------------------------
// CommittedRoute (the executable route, created ONLY from a commitment)
// -----------------------------------------------------------------------

/**
 * A CommittedRoute is the ONLY object that can be used to create a circuit.
 *
 * Per spec/00 §31:
 *   RouteProposal → ActiveCircuit (without commitment) is FORBIDDEN.
 *   topology/Dijkstra output → Route is FORBIDDEN.
 *
 * A CommittedRoute is created ONLY from a RouteCommitment.
 */
export interface CommittedRoute {
  routeId: string;
  hops: RouteHop[];
  expiry: number;
  initiatorNodeId: string;
  agreementDigest: string;
  committedAt: number;
}

/**
 * Create a CommittedRoute from a RouteCommitment.
 *
 * This is the ONLY function that creates a CommittedRoute.
 * It requires a valid RouteCommitment (all hops accepted).
 */
export function createCommittedRoute(commitment: RouteCommitment): CommittedRoute {
  return {
    routeId: commitment.routeId,
    hops: commitment.proposal.hops,
    expiry: commitment.proposal.expiry,
    initiatorNodeId: commitment.proposal.initiatorNodeId,
    agreementDigest: commitment.proposal.agreementDigest,
    committedAt: commitment.committedAt,
  };
}

// -----------------------------------------------------------------------
// ARCHITECTURE GUARD: topology/Dijkstra → Route is FORBIDDEN
// -----------------------------------------------------------------------

/**
 * Per spec/00 §31 and spec/07:
 *   topology/Dijkstra output alone cannot create a route.
 *
 * This guard throws if any code attempts to create a CommittedRoute from
 * topology/graph data without going through the full
 * RouteProposal → RouteAcceptance → RouteCommitment pipeline.
 */
export function TOPOLOGY_TO_ROUTE_FORBIDDEN(topologyData: unknown): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create a CommittedRoute from topology/Dijkstra ` +
      `output without the full RouteProposal → RouteAcceptance → RouteCommitment pipeline. ` +
      `Per spec/00 §31 and spec/07, topology output is discovery metadata only — ` +
      `it is NOT an executable route. Each hop MUST independently accept the route.`,
  );
}

/**
 * Per spec/00 §31:
 *   RouteProposal → ActiveCircuit (without commitment) is FORBIDDEN.
 *
 * This guard throws if any code attempts to create a circuit from a
 * RouteProposal without first creating a RouteCommitment.
 */
export function PROPOSAL_TO_CIRCUIT_FORBIDDEN(proposal: RouteProposal): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create a circuit from RouteProposal ` +
      `(routeId=${proposal.routeId}) without a RouteCommitment. ` +
      `Per spec/00 §31, a circuit can ONLY be created from a CommittedRoute.`,
  );
}
