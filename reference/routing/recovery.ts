/**
 * ShareNet 2.0 — Recovery (GATE-08).
 *
 * Per spec/00 §9 (Recovery) and GATE-08 requirements:
 *
 *   Gateway A disappears
 *       ↓
 *   route invalidated
 *       ↓
 *   Gateway B discovered
 *       ↓
 *   new route
 *       ↓
 *   new circuit
 *       ↓
 *   new flow succeeds
 *
 *   Do not claim transparent arbitrary TCP migration initially.
 *
 * This module implements the recovery state machine in the protocol core.
 * It is storage-agnostic (uses in-memory state) and does NOT depend on
 * the database or network — it operates on abstract link/route/circuit
 * state objects.
 *
 * Key invariants:
 *   - A failed link MUST invalidate any route that uses it as a hop.
 *   - An invalidated route MUST invalidate its active circuit.
 *   - Recovery creates a NEW route + NEW circuit (not a migration).
 *   - No claim of transparent TCP migration — the initiator must re-establish.
 */

import type { CommittedRoute, RouteHop } from "./route";
import type { ActiveCircuit } from "../circuit/circuit";
import type { LinkState } from "../link/link";
import type { NodeCapability } from "../identity/keys";

// -----------------------------------------------------------------------
// Recovery state types
// -----------------------------------------------------------------------

/** The health status of a link, route, or circuit. */
export type HealthStatus = "HEALTHY" | "DEGRADED" | "DOWN";

/** Why a link/route/circuit was invalidated. */
export type InvalidationReason =
  | "LINK_DOWN"          // transport closed
  | "LINK_DEGRADED"      // high latency / loss
  | "GATEWAY_DISAPPEARED" // gateway node went offline
  | "CIRCUIT_EXPIRED"    // circuit TTL expired
  | "ROUTE_EXPIRED"       // route commitment expired
  | "PEER_REVOKED"        // peer was revoked
  | "MANUAL_INVALIDATION" // operator-initiated
  | "RELAY_UNREACHABLE";   // relay hop lost connectivity

/** A link health observation. */
export interface LinkHealthEvent {
  linkId: string;
  localNodeId: string;
  remoteNodeId: string;
  newStatus: HealthStatus;
  reason: InvalidationReason;
  observedAt: number;
}

/** A route health record (tracks which routes use which links). */
export interface RouteHealthRecord {
  routeId: string;
  hops: RouteHop[];
  status: HealthStatus;
  invalidationReason?: InvalidationReason;
  invalidatedAt?: number;
  circuitIdHex?: string;
  establishedAt: number;
}

/** A circuit health record. */
export interface CircuitHealthRecord {
  circuitIdHex: string;
  routeId: string;
  status: HealthStatus;
  invalidationReason?: InvalidationReason;
  invalidatedAt?: number;
  establishedAt: number;
}

// -----------------------------------------------------------------------
// Recovery manager (in-memory, protocol core)
// -----------------------------------------------------------------------

/**
 * The RecoveryManager tracks the health of links, routes, and circuits.
 * When a link goes DOWN, it invalidates all routes that use that link,
 * which in turn invalidates their circuits.
 *
 * The manager also tracks alternative gateways for recovery.
 */
export class RecoveryManager {
  private linkHealth = new Map<string, HealthStatus>(); // linkId → status
  private routeHealth = new Map<string, RouteHealthRecord>(); // routeId → record
  private circuitHealth = new Map<string, CircuitHealthRecord>(); // circuitIdHex → record
  private nodeLinks = new Map<string, Set<string>>(); // nodeId → set of linkIds
  private routeLinks = new Map<string, Set<string>>(); // routeId → set of linkIds used

  /**
   * Register a link as HEALTHY.
   */
  registerLink(linkId: string, localNodeId: string, remoteNodeId: string): void {
    this.linkHealth.set(linkId, "HEALTHY");
    if (!this.nodeLinks.has(remoteNodeId)) {
      this.nodeLinks.set(remoteNodeId, new Set());
    }
    this.nodeLinks.get(remoteNodeId)!.add(linkId);
  }

  /**
   * Register a route (with its circuit) as established.
   * Maps which links each hop uses.
   */
  registerRoute(
    route: CommittedRoute,
    circuitIdHex: string,
    linkIdsByHop: string[],
    establishedAt: number,
  ): void {
    const linkIds = new Set<string>();
    for (const lid of linkIdsByHop) {
      linkIds.add(lid);
    }
    this.routeLinks.set(route.routeId, linkIds);

    this.routeHealth.set(route.routeId, {
      routeId: route.routeId,
      hops: route.hops,
      status: "HEALTHY",
      establishedAt,
      circuitIdHex,
    });

    this.circuitHealth.set(circuitIdHex, {
      circuitIdHex,
      routeId: route.routeId,
      status: "HEALTHY",
      establishedAt,
    });
  }

  /**
   * Handle a link health event. If the link goes DOWN, invalidate all
   * routes that use it, which invalidates their circuits.
   *
   * Returns the list of invalidated route IDs (for the caller to trigger
   * recovery: discover alternative gateway, build new route, new circuit).
   */
  handleLinkEvent(event: LinkHealthEvent): string[] {
    this.linkHealth.set(event.linkId, event.newStatus);

    if (event.newStatus === "DOWN") {
      return this.invalidateRoutesUsingLink(event.linkId, event.reason, event.observedAt);
    }
    if (event.newStatus === "DEGRADED") {
      // Mark routes as DEGRADED but don't invalidate yet
      this.markRoutesDegraded(event.linkId);
    }
    return [];
  }

  /**
   * Handle a gateway disappearance. A gateway disappearing means all
   * links to it go DOWN, and all routes that use it as a hop are
   * invalidated.
   */
  handleGatewayDisappearance(gatewayNodeId: string, observedAt: number): string[] {
    const invalidated: string[] = [];
    const linkIds = this.nodeLinks.get(gatewayNodeId);
    if (linkIds) {
      for (const linkId of linkIds) {
        this.linkHealth.set(linkId, "DOWN");
        invalidated.push(...this.invalidateRoutesUsingLink(linkId, "GATEWAY_DISAPPEARED", observedAt));
      }
    }
    // Also invalidate routes where the gateway is a hop (even if no direct link)
    for (const [routeId, record] of this.routeHealth) {
      if (record.status === "HEALTHY") {
        const hasGateway = record.hops.some((h) => h.nodeId === gatewayNodeId);
        if (hasGateway) {
          invalidated.push(...this.invalidateRoute(routeId, "GATEWAY_DISAPPEARED", observedAt));
        }
      }
    }
    return [...new Set(invalidated)]; // dedup
  }

  /**
   * Get the health of a route.
   */
  getRouteHealth(routeId: string): RouteHealthRecord | undefined {
    return this.routeHealth.get(routeId);
  }

  /**
   * Get the health of a circuit.
   */
  getCircuitHealth(circuitIdHex: string): CircuitHealthRecord | undefined {
    return this.circuitHealth.get(circuitIdHex);
  }

  /**
   * Get all HEALTHY routes.
   */
  getHealthyRoutes(): RouteHealthRecord[] {
    return Array.from(this.routeHealth.values()).filter((r) => r.status === "HEALTHY");
  }

  /**
   * Get all invalidated routes (for recovery decisions).
   */
  getInvalidatedRoutes(): RouteHealthRecord[] {
    return Array.from(this.routeHealth.values()).filter((r) => r.status === "DOWN");
  }

  // --- internals ---

  private invalidateRoutesUsingLink(linkId: string, reason: InvalidationReason, at: number): string[] {
    const invalidated: string[] = [];
    for (const [routeId, linkSet] of this.routeLinks) {
      if (linkSet.has(linkId)) {
        invalidated.push(...this.invalidateRoute(routeId, reason, at));
      }
    }
    return invalidated;
  }

  private invalidateRoute(routeId: string, reason: InvalidationReason, at: number): string[] {
    const record = this.routeHealth.get(routeId);
    if (!record || record.status === "DOWN") return []; // already invalidated

    record.status = "DOWN";
    record.invalidationReason = reason;
    record.invalidatedAt = at;

    // Invalidate the circuit too
    if (record.circuitIdHex) {
      const circuit = this.circuitHealth.get(record.circuitIdHex);
      if (circuit && circuit.status !== "DOWN") {
        circuit.status = "DOWN";
        circuit.invalidationReason = reason;
        circuit.invalidatedAt = at;
      }
    }

    return [routeId];
  }

  private markRoutesDegraded(linkId: string): void {
    for (const [routeId, linkSet] of this.routeLinks) {
      if (linkSet.has(linkId)) {
        const record = this.routeHealth.get(routeId);
        if (record && record.status === "HEALTHY") {
          record.status = "DEGRADED";
        }
      }
    }
  }
}

// -----------------------------------------------------------------------
// Alternative gateway discovery
// -----------------------------------------------------------------------

/**
 * A candidate gateway for recovery.
 */
export interface GatewayCandidate {
  nodeId: string;
  capability: NodeCapability;
  endpoint: string;
  linkUp: boolean;
  estimatedLatencyMs?: number;
}

/**
 * Discover alternative gateways from a set of available nodes.
 *
 * This does NOT create a route or circuit — it only identifies candidates.
 * The caller must go through the full RouteProposal → RouteAcceptance →
 * RouteCommitment → CircuitSetup pipeline to establish the new flow.
 */
export function discoverAlternativeGateways(
  availableNodes: GatewayCandidate[],
  requiredCapability: NodeCapability,
  excludeNodeIds: readonly string[] = [],
): GatewayCandidate[] {
  return availableNodes
    .filter((n) => n.capability === requiredCapability)
    .filter((n) => n.linkUp)
    .filter((n) => !excludeNodeIds.includes(n.nodeId))
    .sort((a, b) => a.nodeId.localeCompare(b.nodeId));
}

// -----------------------------------------------------------------------
// Recovery plan
// -----------------------------------------------------------------------

/**
 * A recovery plan describes what the initiator should do after a route
 * is invalidated. It does NOT execute the recovery — it only identifies
 * the next steps.
 */
export interface RecoveryPlan {
  invalidatedRouteIds: string[];
  reason: InvalidationReason;
  candidateGateways: GatewayCandidate[];
  nextStep: "DISCOVER_NEW_GATEWAY" | "WAIT_FOR_LINK_RECOVERY" | "NO_RECOVERY_POSSIBLE";
  recommendation: string;
}

/**
 * Create a recovery plan for a set of invalidated routes.
 *
 * Per GATE-08: "Do not claim transparent arbitrary TCP migration initially."
 * The recovery plan creates a NEW route + NEW circuit — it does NOT migrate
 * the existing TCP flow.
 */
export function createRecoveryPlan(
  invalidatedRouteIds: string[],
  reason: InvalidationReason,
  availableNodes: GatewayCandidate[],
  requiredCapability: NodeCapability,
  excludeNodeIds: readonly string[] = [],
): RecoveryPlan {
  const candidates = discoverAlternativeGateways(availableNodes, requiredCapability, excludeNodeIds);

  let nextStep: RecoveryPlan["nextStep"];
  let recommendation: string;

  if (candidates.length > 0) {
    nextStep = "DISCOVER_NEW_GATEWAY";
    recommendation = `Found ${candidates.length} alternative gateway(s). ` +
      `Initiate a NEW RouteProposal → RouteAcceptance → RouteCommitment → ` +
      `CircuitSetup pipeline through gateway ${candidates[0]!.nodeId}. ` +
      `Do NOT attempt TCP migration of the existing flow.`;
  } else if (reason === "LINK_DEGRADED") {
    nextStep = "WAIT_FOR_LINK_RECOVERY";
    recommendation = "Link is DEGRADED, not DOWN. Wait for link recovery or " +
      "proactively build a new route through a different relay.";
  } else {
    nextStep = "NO_RECOVERY_POSSIBLE";
    recommendation = "No alternative gateways available. Wait for the original " +
      "gateway to reappear, or for new nodes to join the network.";
  }

  return {
    invalidatedRouteIds,
    reason,
    candidateGateways: candidates,
    nextStep,
    recommendation,
  };
}

// -----------------------------------------------------------------------
// Architecture guard: no TCP migration claim
// -----------------------------------------------------------------------

/**
 * Per GATE-08: "Do not claim transparent arbitrary TCP migration initially."
 *
 * This guard throws if any code attempts to migrate a TCP flow to a new
 * route without going through the full recovery pipeline (invalidate →
 * discover → new route → new circuit).
 */
export function TCP_MIGRATION_FORBIDDEN(circuitId: string): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to migrate TCP flow for circuit ${circuitId} ` +
      `without going through the recovery pipeline. Per GATE-08, ShareNet does NOT ` +
      `claim transparent arbitrary TCP migration. The initiator MUST create a NEW ` +
      `route + NEW circuit through the full pipeline.`,
  );
}
