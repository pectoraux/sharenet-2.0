/**
 * ShareNet 2.0 — GATE-08 Tests: Recovery.
 *
 * Per GATE-08 requirements:
 *   - Gateway A disappears → route invalidated → Gateway B discovered →
 *     new route → new circuit → new flow succeeds
 *   - No claim of arbitrary TCP migration
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  randomBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  type RouteHop,
  type RouteProposal,
  signRouteAcceptance,
  createRouteCommitment,
  createCommittedRoute,
} from "@reference/routing/route";
import {
  RecoveryManager,
  discoverAlternativeGateways,
  createRecoveryPlan,
  TCP_MIGRATION_FORBIDDEN,
  type GatewayCandidate,
  type LinkHealthEvent,
} from "@reference/routing/recovery";

const REFERENCE_NOW = 1786876545;

function makeCommittedRoute(nodeIds: string[], initiator: ReturnType<typeof generateNodeKeypair>) {
  const hops: RouteHop[] = nodeIds.map((nodeId, i) => ({
    nodeId,
    capability: i === nodeIds.length - 1 ? "INTERNET_GATEWAY" : "MESH_RELAY",
    endpoint: `10.0.0.${i + 1}:7788`,
    linkUp: true,
  }));
  const proposal: RouteProposal = {
    hops,
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: REFERENCE_NOW + 3600,
    initiatorNodeId: initiator.nodeId,
    agreementDigest: bytesToHex(randomBytes(32)),
  };
  const kps = nodeIds.map(() => generateNodeKeypair());
  const serviceAgreements = new Map<number, any>();
  const hopPublicKeys = new Map<string, Uint8Array>();
  for (let i = 0; i < nodeIds.length; i++) {
    serviceAgreements.set(i, {nodeId:nodeIds[i],capability:hops[i]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    hopPublicKeys.set(nodeIds[i]!, kps[i]!.publicKey);
  }
  const acceptances = nodeIds.map((nodeId, i) =>
    signRouteAcceptance(proposal, i, hops[i]!, serviceAgreements.get(i)!, nodeId, kps[i]!.secretKey, proposal.expiry),
  );
  const result = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, initiator.secretKey, REFERENCE_NOW);
  if (!result.ok) throw new Error("commitment failed");
  return createCommittedRoute(result.commitment);
}

describe("GATE-08: Recovery", () => {
  // --- 1. Link DOWN invalidates routes that use it ---
  test("link DOWN invalidates routes using that link", () => {
    const initiator = generateNodeKeypair();
    const relay = generateNodeKeypair();
    const gateway = generateNodeKeypair();

    const route = makeCommittedRoute([relay.nodeId, gateway.nodeId], initiator);
    const linkId = "link:abc123";
    const circuitIdHex = bytesToHex(randomBytes(32));

    const mgr = new RecoveryManager();
    mgr.registerLink(linkId, initiator.nodeId, relay.nodeId);
    mgr.registerRoute(route, circuitIdHex, [linkId, "link:def456"], REFERENCE_NOW);

    // Route is healthy
    expect(mgr.getRouteHealth(route.routeId)?.status).toBe("HEALTHY");

    // Link goes DOWN
    const event: LinkHealthEvent = {
      linkId,
      localNodeId: initiator.nodeId,
      remoteNodeId: relay.nodeId,
      newStatus: "DOWN",
      reason: "LINK_DOWN",
      observedAt: REFERENCE_NOW + 100,
    };
    const invalidated = mgr.handleLinkEvent(event);

    expect(invalidated).toContain(route.routeId);
    expect(mgr.getRouteHealth(route.routeId)?.status).toBe("DOWN");
    expect(mgr.getRouteHealth(route.routeId)?.invalidationReason).toBe("LINK_DOWN");
    expect(mgr.getCircuitHealth(circuitIdHex)?.status).toBe("DOWN");
  });

  // --- 2. Gateway disappearance invalidates all routes through it ---
  test("gateway disappearance invalidates routes through that gateway", () => {
    const initiator = generateNodeKeypair();
    const relay = generateNodeKeypair();
    const gatewayA = generateNodeKeypair();

    const route = makeCommittedRoute([relay.nodeId, gatewayA.nodeId], initiator);
    const circuitIdHex = bytesToHex(randomBytes(32));

    const mgr = new RecoveryManager();
    mgr.registerLink("link:1", initiator.nodeId, relay.nodeId);
    mgr.registerLink("link:2", relay.nodeId, gatewayA.nodeId);
    mgr.registerRoute(route, circuitIdHex, ["link:1", "link:2"], REFERENCE_NOW);

    // Gateway A disappears
    const invalidated = mgr.handleGatewayDisappearance(gatewayA.nodeId, REFERENCE_NOW + 100);

    expect(invalidated).toContain(route.routeId);
    expect(mgr.getRouteHealth(route.routeId)?.status).toBe("DOWN");
    expect(mgr.getRouteHealth(route.routeId)?.invalidationReason).toBe("GATEWAY_DISAPPEARED");
  });

  // --- 3. Link DEGRADED marks routes as DEGRADED (not DOWN) ---
  test("link DEGRADED marks routes as DEGRADED, not DOWN", () => {
    const initiator = generateNodeKeypair();
    const relay = generateNodeKeypair();
    const gateway = generateNodeKeypair();

    const route = makeCommittedRoute([relay.nodeId, gateway.nodeId], initiator);
    const mgr = new RecoveryManager();
    mgr.registerLink("link:1", initiator.nodeId, relay.nodeId);
    mgr.registerRoute(route, bytesToHex(randomBytes(32)), ["link:1"], REFERENCE_NOW);

    mgr.handleLinkEvent({
      linkId: "link:1",
      localNodeId: initiator.nodeId,
      remoteNodeId: relay.nodeId,
      newStatus: "DEGRADED",
      reason: "LINK_DEGRADED",
      observedAt: REFERENCE_NOW + 100,
    });

    expect(mgr.getRouteHealth(route.routeId)?.status).toBe("DEGRADED");
    // Circuit should still be HEALTHY (degraded link doesn't invalidate circuit)
    // Actually, let me check — we only mark route as DEGRADED, circuit stays HEALTHY
  });

  // --- 4. Alternative gateway discovery ---
  test("discoverAlternativeGateways returns LINK_UP gateways with matching capability", () => {
    const candidates: GatewayCandidate[] = [
      { nodeId: "gwA", capability: "INTERNET_GATEWAY", endpoint: "10.0.0.1:7788", linkUp: false },
      { nodeId: "gwB", capability: "INTERNET_GATEWAY", endpoint: "10.0.0.2:7788", linkUp: true, estimatedLatencyMs: 50 },
      { nodeId: "gwC", capability: "INTERNET_GATEWAY", endpoint: "10.0.0.3:7788", linkUp: true, estimatedLatencyMs: 20 },
      { nodeId: "relay1", capability: "MESH_RELAY", endpoint: "10.0.0.4:7788", linkUp: true },
    ];
    const result = discoverAlternativeGateways(candidates, "INTERNET_GATEWAY");
    expect(result.length).toBe(2); // gwB + gwC (gwA has linkUp=false, relay1 wrong capability)
    expect(result[0]!.nodeId).toBe("gwC"); // sorted by latency (20 < 50)
    expect(result[1]!.nodeId).toBe("gwB");
  });

  test("discoverAlternativeGateways excludes specified nodeIds", () => {
    const candidates: GatewayCandidate[] = [
      { nodeId: "gwA", capability: "INTERNET_GATEWAY", endpoint: "a", linkUp: true },
      { nodeId: "gwB", capability: "INTERNET_GATEWAY", endpoint: "b", linkUp: true },
    ];
    const result = discoverAlternativeGateways(candidates, "INTERNET_GATEWAY", ["gwA"]);
    expect(result.length).toBe(1);
    expect(result[0]!.nodeId).toBe("gwB");
  });

  // --- 5. Recovery plan: gateway disappears → find alternative ---
  test("recovery plan: gateway disappears → alternative found", () => {
    const initiator = generateNodeKeypair();
    const relay = generateNodeKeypair();
    const gwA = generateNodeKeypair();
    const gwB = generateNodeKeypair();

    const route = makeCommittedRoute([relay.nodeId, gwA.nodeId], initiator);
    const mgr = new RecoveryManager();
    mgr.registerLink("link:1", initiator.nodeId, relay.nodeId);
    mgr.registerLink("link:2", relay.nodeId, gwA.nodeId);
    mgr.registerRoute(route, bytesToHex(randomBytes(32)), ["link:1", "link:2"], REFERENCE_NOW);

    // Gateway A disappears
    const invalidated = mgr.handleGatewayDisappearance(gwA.nodeId, REFERENCE_NOW + 100);

    // Create recovery plan
    const plan = createRecoveryPlan(
      invalidated,
      "GATEWAY_DISAPPEARED",
      [
        { nodeId: gwB.nodeId, capability: "INTERNET_GATEWAY", endpoint: "10.0.0.3:7788", linkUp: true, estimatedLatencyMs: 30 },
      ],
      "INTERNET_GATEWAY",
      [gwA.nodeId], // exclude the failed gateway
    );

    expect(plan.nextStep).toBe("DISCOVER_NEW_GATEWAY");
    expect(plan.candidateGateways.length).toBe(1);
    expect(plan.candidateGateways[0]!.nodeId).toBe(gwB.nodeId);
    expect(plan.recommendation).toContain("NEW RouteProposal");
    expect(plan.recommendation).toContain("Do NOT attempt TCP migration");
  });

  // --- 6. Recovery plan: no alternative available ---
  test("recovery plan: no alternative gateway available", () => {
    const plan = createRecoveryPlan(
      ["route1"],
      "GATEWAY_DISAPPEARED",
      [], // no available nodes
      "INTERNET_GATEWAY",
    );
    expect(plan.nextStep).toBe("NO_RECOVERY_POSSIBLE");
    expect(plan.candidateGateways.length).toBe(0);
  });

  // --- 7. Recovery plan: link degraded → wait ---
  test("recovery plan: link degraded → wait for recovery", () => {
    const plan = createRecoveryPlan(
      ["route1"],
      "LINK_DEGRADED",
      [], // no alternatives
      "INTERNET_GATEWAY",
    );
    expect(plan.nextStep).toBe("WAIT_FOR_LINK_RECOVERY");
  });

  // --- 8. TCP migration forbidden ---
  test("TCP_MIGRATION_FORBIDDEN throws", () => {
    expect(() => TCP_MIGRATION_FORBIDDEN("circuit123")).toThrow();
  });

  // --- 9. Full recovery flow: Gateway A disappears → Gateway B takes new traffic ---
  test("full recovery: Gateway A disappears → Gateway B → new route → new circuit", () => {
    const initiator = generateNodeKeypair();
    const relay = generateNodeKeypair();
    const gwA = generateNodeKeypair();
    const gwB = generateNodeKeypair();

    // Original route through Gateway A
    const routeA = makeCommittedRoute([relay.nodeId, gwA.nodeId], initiator);
    const circuitA = bytesToHex(randomBytes(32));
    const mgr = new RecoveryManager();
    mgr.registerLink("link:1", initiator.nodeId, relay.nodeId);
    mgr.registerLink("link:2", relay.nodeId, gwA.nodeId);
    mgr.registerRoute(routeA, circuitA, ["link:1", "link:2"], REFERENCE_NOW);

    // Gateway A disappears
    const invalidated = mgr.handleGatewayDisappearance(gwA.nodeId, REFERENCE_NOW + 100);
    expect(invalidated).toContain(routeA.routeId);
    expect(mgr.getRouteHealth(routeA.routeId)?.status).toBe("DOWN");
    expect(mgr.getCircuitHealth(circuitA)?.status).toBe("DOWN");

    // Discover alternative: Gateway B
    const plan = createRecoveryPlan(
      invalidated,
      "GATEWAY_DISAPPEARED",
      [{ nodeId: gwB.nodeId, capability: "INTERNET_GATEWAY", endpoint: "10.0.0.3:7788", linkUp: true, estimatedLatencyMs: 30 }],
      "INTERNET_GATEWAY",
      [gwA.nodeId],
    );
    expect(plan.nextStep).toBe("DISCOVER_NEW_GATEWAY");
    expect(plan.candidateGateways[0]!.nodeId).toBe(gwB.nodeId);

    // Build NEW route through Gateway B (NOT a migration — a new route)
    const routeB = makeCommittedRoute([relay.nodeId, gwB.nodeId], initiator);
    const circuitB = bytesToHex(randomBytes(32));
    mgr.registerLink("link:3", relay.nodeId, gwB.nodeId);
    mgr.registerRoute(routeB, circuitB, ["link:1", "link:3"], REFERENCE_NOW + 200);

    // New route is HEALTHY
    expect(mgr.getRouteHealth(routeB.routeId)?.status).toBe("HEALTHY");
    expect(mgr.getCircuitHealth(circuitB)?.status).toBe("HEALTHY");

    // Old route is still DOWN
    expect(mgr.getRouteHealth(routeA.routeId)?.status).toBe("DOWN");
  });

  // --- 10. Multiple routes through same link all invalidated ---
  test("multiple routes through same link all invalidated when link goes DOWN", () => {
    const initiator = generateNodeKeypair();
    const relay = generateNodeKeypair();
    const gw1 = generateNodeKeypair();
    const gw2 = generateNodeKeypair();

    const route1 = makeCommittedRoute([relay.nodeId, gw1.nodeId], initiator);
    const route2 = makeCommittedRoute([relay.nodeId, gw2.nodeId], initiator);

    const mgr = new RecoveryManager();
    mgr.registerLink("link:shared", initiator.nodeId, relay.nodeId);
    mgr.registerRoute(route1, bytesToHex(randomBytes(32)), ["link:shared"], REFERENCE_NOW);
    mgr.registerRoute(route2, bytesToHex(randomBytes(32)), ["link:shared"], REFERENCE_NOW);

    // The shared link goes DOWN
    const invalidated = mgr.handleLinkEvent({
      linkId: "link:shared",
      localNodeId: initiator.nodeId,
      remoteNodeId: relay.nodeId,
      newStatus: "DOWN",
      reason: "LINK_DOWN",
      observedAt: REFERENCE_NOW + 100,
    });

    expect(invalidated.length).toBe(2);
    expect(invalidated).toContain(route1.routeId);
    expect(invalidated).toContain(route2.routeId);
  });

  // --- 11. Route not using the failed link stays HEALTHY ---
  test("route not using the failed link stays HEALTHY", () => {
    const initiator = generateNodeKeypair();
    const relay1 = generateNodeKeypair();
    const relay2 = generateNodeKeypair();
    const gw = generateNodeKeypair();

    const route1 = makeCommittedRoute([relay1.nodeId, gw.nodeId], initiator);
    const route2 = makeCommittedRoute([relay2.nodeId, gw.nodeId], initiator);

    const mgr = new RecoveryManager();
    mgr.registerLink("link:1", initiator.nodeId, relay1.nodeId);
    mgr.registerLink("link:2", initiator.nodeId, relay2.nodeId);
    mgr.registerRoute(route1, bytesToHex(randomBytes(32)), ["link:1"], REFERENCE_NOW);
    mgr.registerRoute(route2, bytesToHex(randomBytes(32)), ["link:2"], REFERENCE_NOW);

    // link:1 goes DOWN → route1 invalidated, route2 stays healthy
    const invalidated = mgr.handleLinkEvent({
      linkId: "link:1",
      localNodeId: initiator.nodeId,
      remoteNodeId: relay1.nodeId,
      newStatus: "DOWN",
      reason: "LINK_DOWN",
      observedAt: REFERENCE_NOW + 100,
    });

    expect(invalidated).toContain(route1.routeId);
    expect(invalidated).not.toContain(route2.routeId);
    expect(mgr.getRouteHealth(route2.routeId)?.status).toBe("HEALTHY");
  });
});
