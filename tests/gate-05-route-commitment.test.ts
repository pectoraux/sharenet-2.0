/**
 * ShareNet 2.0 — GATE-05 Tests: Service negotiation and route commitment.
 *
 * Per GATE-05 requirements:
 *   - A → Relay → Gateway produces a committed route
 *   - unauthenticated, ADV_VERIFIED, expired, rejected, or policy-incompatible hop fails
 *   - topology/Dijkstra output alone cannot create a route
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  signMessage,
  verifySignature,
  randomBytes,
  bytesToHex,
  type NodeKeypair,
} from "@reference/identity/keys";
import {
  type ServiceRequirement,
  type CapabilityOffer,
  type CapacityInfo,
  checkPolicy,
  checkCapacity,
  createServiceAgreement,
} from "@reference/routing/service-negotiation";
import {
  type RouteHop,
  type RouteProposal,
  createRouteProposal,
  signRouteAcceptance,
  verifyRouteAcceptance,
  createRouteCommitment,
  createCommittedRoute,
  TOPOLOGY_TO_ROUTE_FORBIDDEN,
  PROPOSAL_TO_CIRCUIT_FORBIDDEN,
} from "@reference/routing/route";

const REFERENCE_NOW = 1786876545;

function makeKeypairs() {
  return {
    initiator: generateNodeKeypair(),
    relay: generateNodeKeypair(),
    gateway: generateNodeKeypair(),
  };
}

function makeRequirement(): ServiceRequirement {
  return {
    requiredCapability: "INTERNET_GATEWAY",
    destination: "example.com:443",
    maxHops: 3,
    bandwidthBps: 1048576,
    expiry: REFERENCE_NOW + 3600,
  };
}

function makeHop(nodeId: string, capability: any, linkUp = true): RouteHop {
  return {
    nodeId,
    capability,
    endpoint: "10.0.0.1:7788",
    linkUp,
  };
}

describe("GATE-05: Service negotiation and route commitment", () => {
  // --- 1. Policy check passes for valid offer ---
  test("policy check passes for valid LINK_UP gateway offer with allowed destination", () => {
    const req = makeRequirement();
    const offer: CapabilityOffer = {
      nodeId: "testnode",
      capability: "INTERNET_GATEWAY",
      endpoints: ["10.0.0.1:7788"],
      linkUp: true,
      advVerifiedOnly: false,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW, ["example.com", "*.sharenet.local"]);
    expect(result.ok).toBe(true);
  });

  // --- 2. Policy check fails for ADV_VERIFIED only ---
  test("policy check fails for ADV_VERIFIED-only offer (not routable)", () => {
    const req = makeRequirement();
    const offer: CapabilityOffer = {
      nodeId: "testnode",
      capability: "INTERNET_GATEWAY",
      endpoints: ["10.0.0.1:7788"],
      linkUp: false,
      advVerifiedOnly: true,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("ADV_VERIFIED_ONLY");
  });

  // --- 3. Policy check fails for no LINK_UP ---
  test("policy check fails for no LINK_UP", () => {
    const req = makeRequirement();
    const offer: CapabilityOffer = {
      nodeId: "testnode",
      capability: "INTERNET_GATEWAY",
      endpoints: ["10.0.0.1:7788"],
      linkUp: false,
      advVerifiedOnly: false,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("NO_LINK_UP");
  });

  // --- 4. Policy check fails for capability mismatch ---
  test("policy check fails for capability mismatch", () => {
    const req = makeRequirement();
    const offer: CapabilityOffer = {
      nodeId: "testnode",
      capability: "STORAGE", // wrong capability
      endpoints: [],
      linkUp: true,
      advVerifiedOnly: false,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("CAPABILITY_MISMATCH");
  });

  // --- 5. Policy check fails for SSRF destination ---
  test("policy check fails for SSRF destination", () => {
    const req: ServiceRequirement = {
      requiredCapability: "INTERNET_GATEWAY",
      destination: "169.254.169.254",
      maxHops: 3,
      expiry: REFERENCE_NOW + 3600,
    };
    const offer: CapabilityOffer = {
      nodeId: "testnode",
      capability: "INTERNET_GATEWAY",
      endpoints: [],
      linkUp: true,
      advVerifiedOnly: false,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("DESTINATION_BLOCKED_SSRF");
  });

  // --- 6. Policy check fails for loopback ---
  test("policy check fails for loopback destination", () => {
    const req: ServiceRequirement = {
      requiredCapability: "INTERNET_GATEWAY",
      destination: "127.0.0.1:80",
      maxHops: 3,
      expiry: REFERENCE_NOW + 3600,
    };
    const offer: CapabilityOffer = {
      nodeId: "testnode",
      capability: "INTERNET_GATEWAY",
      endpoints: [],
      linkUp: true,
      advVerifiedOnly: false,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("DESTINATION_BLOCKED_LOOPBACK");
  });

  // --- 7. Policy check fails for private address ---
  test("policy check fails for private address destination", () => {
    const req: ServiceRequirement = {
      requiredCapability: "INTERNET_GATEWAY",
      destination: "10.0.0.5",
      maxHops: 3,
      expiry: REFERENCE_NOW + 3600,
    };
    const offer: CapabilityOffer = {
      nodeId: "testnode",
      capability: "INTERNET_GATEWAY",
      endpoints: [],
      linkUp: true,
      advVerifiedOnly: false,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("DESTINATION_BLOCKED_PRIVATE");
  });

  // --- 8. Policy check fails for peer revoked ---
  test("policy check fails for revoked peer", () => {
    const req = makeRequirement();
    const offer: CapabilityOffer = {
      nodeId: "revokednode",
      capability: "INTERNET_GATEWAY",
      endpoints: [],
      linkUp: true,
      advVerifiedOnly: false,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW, ["example.com"], ["revokednode"]);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("PEER_REVOKED");
  });

  // --- 9. Policy check fails for expired requirement ---
  test("policy check fails for expired requirement", () => {
    const req: ServiceRequirement = {
      requiredCapability: "INTERNET_GATEWAY",
      destination: "example.com:443",
      maxHops: 3,
      expiry: REFERENCE_NOW - 100, // expired
    };
    const offer: CapabilityOffer = {
      nodeId: "testnode",
      capability: "INTERNET_GATEWAY",
      endpoints: [],
      linkUp: true,
      advVerifiedOnly: false,
    };
    const result = checkPolicy(req, offer, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("EXPIRED");
  });

  // --- 10. Capacity check ---
  test("capacity check passes with available resources", () => {
    const req = makeRequirement();
    const capacity: CapacityInfo = {
      availableBandwidthBps: 5_000_000,
      availableConnections: 10,
      globalQuotaRemaining: 100,
      perPeerQuotaRemaining: 10,
    };
    const result = checkCapacity(req, capacity);
    expect(result.ok).toBe(true);
  });

  test("capacity check fails with no connections", () => {
    const req = makeRequirement();
    const capacity: CapacityInfo = {
      availableBandwidthBps: 5_000_000,
      availableConnections: 0,
      globalQuotaRemaining: 100,
      perPeerQuotaRemaining: 10,
    };
    const result = checkCapacity(req, capacity);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("NO_CONNECTIONS_AVAILABLE");
  });

  // --- 11. A → Relay → Gateway produces a committed route ---
  test("A → Relay → Gateway produces a committed route", () => {
    const kps = makeKeypairs();
    const req = makeRequirement();

    // Build the route proposal: A → Relay → Gateway
    const proposal: RouteProposal = {
      routeId: bytesToHex(randomBytes(32)),
      hops: [
        makeHop(kps.relay.nodeId, "MESH_RELAY"),
        makeHop(kps.gateway.nodeId, "INTERNET_GATEWAY"),
      ],
      requirementDigest: bytesToHex(randomBytes(32)),
      expiry: REFERENCE_NOW + 3600,
      initiatorNodeId: kps.initiator.nodeId,
      agreementDigest: bytesToHex(randomBytes(32)),
    };

    // Build service agreements + public keys
    const serviceAgreements = new Map<number, any>();
    const hopPublicKeys = new Map<string, Uint8Array>();
    serviceAgreements.set(0, {nodeId:kps.relay.nodeId,capability:proposal.hops[0]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    serviceAgreements.set(1, {nodeId:kps.gateway.nodeId,capability:proposal.hops[1]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    hopPublicKeys.set(kps.relay.nodeId, kps.relay.publicKey);
    hopPublicKeys.set(kps.gateway.nodeId, kps.gateway.publicKey);
    // Each hop signs acceptance
    const acceptances = [
      signRouteAcceptance(proposal, 0, proposal.hops[0]!, serviceAgreements.get(0)!, kps.relay.nodeId, kps.relay.secretKey, proposal.expiry),
      signRouteAcceptance(proposal, 1, proposal.hops[1]!, serviceAgreements.get(1)!, kps.gateway.nodeId, kps.gateway.secretKey, proposal.expiry),
    ];

    // Create commitment
    const commitmentResult = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, kps.initiator.secretKey, REFERENCE_NOW);
    expect(commitmentResult.ok).toBe(true);

    if (commitmentResult.ok) {
      // Create committed route
      const route = createCommittedRoute(commitmentResult.commitment);
      // R-003/R-004: route_id is now DERIVED from commitment_root, not proposal.routeId
      // Per spec/07 §5.4: route_id = "route:" + lowercase_hex(commitment_root)
      expect(route.routeId).toBe("route:" + bytesToHex(commitmentResult.commitment.commitmentRoot));
      expect(route.commitmentRoot).toEqual(commitmentResult.commitment.commitmentRoot);
      expect(route.hops.length).toBe(2);
      expect(route.hops[0]!.nodeId).toBe(kps.relay.nodeId);
      expect(route.hops[1]!.nodeId).toBe(kps.gateway.nodeId);
    }
  });

  // --- 12. Missing acceptance fails ---
  test("route commitment fails with missing acceptance", () => {
    const kps = makeKeypairs();
    const proposal: RouteProposal = {
      routeId: bytesToHex(randomBytes(32)),
      hops: [
        makeHop(kps.relay.nodeId, "MESH_RELAY"),
        makeHop(kps.gateway.nodeId, "INTERNET_GATEWAY"),
      ],
      requirementDigest: bytesToHex(randomBytes(32)),
      expiry: REFERENCE_NOW + 3600,
      initiatorNodeId: kps.initiator.nodeId,
      agreementDigest: bytesToHex(randomBytes(32)),
    };

    // Only one acceptance (missing the second)
    const serviceAgreements = new Map<number, any>();
    const hopPublicKeys = new Map<string, Uint8Array>();
    serviceAgreements.set(0, {nodeId:kps.relay.nodeId,capability:proposal.hops[0]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    serviceAgreements.set(1, {nodeId:kps.gateway.nodeId,capability:proposal.hops[1]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    hopPublicKeys.set(kps.relay.nodeId, kps.relay.publicKey);
    hopPublicKeys.set(kps.gateway.nodeId, kps.gateway.publicKey);
    const acceptances = [
      signRouteAcceptance(proposal, 0, proposal.hops[0]!, serviceAgreements.get(0)!, kps.relay.nodeId, kps.relay.secretKey, proposal.expiry),
    ];

    const result = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, kps.initiator.secretKey, REFERENCE_NOW);
    expect(result.ok).toBe(false);
  });

  // --- 13. Wrong acceptor fails ---
  test("route commitment fails with wrong acceptor", () => {
    const kps = makeKeypairs();
    const proposal: RouteProposal = {
      routeId: bytesToHex(randomBytes(32)),
      hops: [
        makeHop(kps.relay.nodeId, "MESH_RELAY"),
        makeHop(kps.gateway.nodeId, "INTERNET_GATEWAY"),
      ],
      requirementDigest: bytesToHex(randomBytes(32)),
      expiry: REFERENCE_NOW + 3600,
      initiatorNodeId: kps.initiator.nodeId,
      agreementDigest: bytesToHex(randomBytes(32)),
    };

    // Build service agreements + public keys
    const serviceAgreements = new Map<number, any>();
    const hopPublicKeys = new Map<string, Uint8Array>();
    serviceAgreements.set(0, {nodeId:kps.relay.nodeId,capability:proposal.hops[0]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    serviceAgreements.set(1, {nodeId:kps.gateway.nodeId,capability:proposal.hops[1]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    hopPublicKeys.set(kps.relay.nodeId, kps.relay.publicKey);
    hopPublicKeys.set(kps.gateway.nodeId, kps.gateway.publicKey);
    // Second acceptance is from the wrong node (relay instead of gateway)
    const acceptances = [
      signRouteAcceptance(proposal, 0, proposal.hops[0]!, serviceAgreements.get(0)!, kps.relay.nodeId, kps.relay.secretKey, proposal.expiry),
      signRouteAcceptance(proposal, 1, proposal.hops[1]!, serviceAgreements.get(1)!, kps.relay.nodeId, kps.relay.secretKey, proposal.expiry), // wrong!
    ];

    const result = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, kps.initiator.secretKey, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("acceptance 1");
  });

  // --- 14. ADV_VERIFIED hop (linkUp=false) fails ---
  test("route commitment fails for ADV_VERIFIED hop (not LINK_UP)", () => {
    const kps = makeKeypairs();
    const proposal: RouteProposal = {
      routeId: bytesToHex(randomBytes(32)),
      hops: [
        makeHop(kps.relay.nodeId, "MESH_RELAY", true),
        makeHop(kps.gateway.nodeId, "INTERNET_GATEWAY", false), // ADV_VERIFIED only!
      ],
      requirementDigest: bytesToHex(randomBytes(32)),
      expiry: REFERENCE_NOW + 3600,
      initiatorNodeId: kps.initiator.nodeId,
      agreementDigest: bytesToHex(randomBytes(32)),
    };

    const serviceAgreements = new Map<number, any>();
    const hopPublicKeys = new Map<string, Uint8Array>();
    serviceAgreements.set(0, {nodeId:kps.relay.nodeId,capability:proposal.hops[0]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    serviceAgreements.set(1, {nodeId:kps.gateway.nodeId,capability:proposal.hops[1]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    hopPublicKeys.set(kps.relay.nodeId, kps.relay.publicKey);
    hopPublicKeys.set(kps.gateway.nodeId, kps.gateway.publicKey);
    const acceptances = [
      signRouteAcceptance(proposal, 0, proposal.hops[0]!, serviceAgreements.get(0)!, kps.relay.nodeId, kps.relay.secretKey, proposal.expiry),
      signRouteAcceptance(proposal, 1, proposal.hops[1]!, serviceAgreements.get(1)!, kps.gateway.nodeId, kps.gateway.secretKey, proposal.expiry),
    ];

    const result = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, kps.initiator.secretKey, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("not LINK_UP");
  });

  // --- 15. Expired acceptance fails ---
  test("route commitment fails for expired acceptance", () => {
    const kps = makeKeypairs();
    const proposal: RouteProposal = {
      routeId: bytesToHex(randomBytes(32)),
      hops: [
        makeHop(kps.relay.nodeId, "MESH_RELAY"),
        makeHop(kps.gateway.nodeId, "INTERNET_GATEWAY"),
      ],
      requirementDigest: bytesToHex(randomBytes(32)),
      expiry: REFERENCE_NOW + 3600,
      initiatorNodeId: kps.initiator.nodeId,
      agreementDigest: bytesToHex(randomBytes(32)),
    };

    // Build service agreements + public keys
    const serviceAgreements = new Map<number, any>();
    const hopPublicKeys = new Map<string, Uint8Array>();
    serviceAgreements.set(0, {nodeId:kps.relay.nodeId,capability:proposal.hops[0]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    serviceAgreements.set(1, {nodeId:kps.gateway.nodeId,capability:proposal.hops[1]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    hopPublicKeys.set(kps.relay.nodeId, kps.relay.publicKey);
    hopPublicKeys.set(kps.gateway.nodeId, kps.gateway.publicKey);
    // Acceptances with expiry in the past
    const acceptances = [
      signRouteAcceptance(proposal, 0, proposal.hops[0]!, serviceAgreements.get(0)!, kps.relay.nodeId, kps.relay.secretKey, REFERENCE_NOW - 100),
      signRouteAcceptance(proposal, 1, proposal.hops[1]!, serviceAgreements.get(1)!, kps.gateway.nodeId, kps.gateway.secretKey, REFERENCE_NOW - 100),
    ];

    const result = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, kps.initiator.secretKey, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("expired");
  });

  // --- 16. Topology/Dijkstra → Route FORBIDDEN ---
  test("TOPOLOGY_TO_ROUTE_FORBIDDEN throws", () => {
    expect(() => TOPOLOGY_TO_ROUTE_FORBIDDEN({ nodes: [], edges: [] })).toThrow();
  });

  // --- 17. Proposal → Circuit FORBIDDEN ---
  test("PROPOSAL_TO_CIRCUIT_FORBIDDEN throws", () => {
    const proposal: RouteProposal = {
      routeId: "test",
      hops: [],
      requirementDigest: "",
      expiry: 0,
      initiatorNodeId: "",
      agreementDigest: "",
    };
    expect(() => PROPOSAL_TO_CIRCUIT_FORBIDDEN(proposal)).toThrow();
  });

  // --- 18. Route acceptance verification ---
  test("route acceptance verifies correctly", () => {
    const kp = generateNodeKeypair();
    const acceptance = signRouteAcceptance({routeId:"route123",hops:[{nodeId:kp.nodeId,capability:"MESH_RELAY",endpoint:"10.0.0.1:7788",linkUp:true}],requirementDigest:"",expiry:REFERENCE_NOW+3600,initiatorNodeId:"",agreementDigest:""} as any, 0, {nodeId:kp.nodeId,capability:"MESH_RELAY",endpoint:"10.0.0.1:7788",linkUp:true} as any, {nodeId:kp.nodeId,capability:"MESH_RELAY",requirementDigest:"",allocatedBandwidthBps:0,expiry:REFERENCE_NOW+3600,policyVersion:1} as any, kp.nodeId, kp.secretKey, REFERENCE_NOW + 3600);
    const ok = verifyRouteAcceptance(acceptance, kp.publicKey);
    expect(ok).toBe(true);
  });

  test("route acceptance with wrong key fails", () => {
    const kpA = generateNodeKeypair();
    const kpB = generateNodeKeypair();
    const acceptance = signRouteAcceptance({routeId:"route123",hops:[{nodeId:kpA.nodeId,capability:"MESH_RELAY",endpoint:"10.0.0.1:7788",linkUp:true}],requirementDigest:"",expiry:REFERENCE_NOW+3600,initiatorNodeId:"",agreementDigest:""} as any, 0, {nodeId:kpA.nodeId,capability:"MESH_RELAY",endpoint:"10.0.0.1:7788",linkUp:true} as any, {nodeId:kpA.nodeId,capability:"MESH_RELAY",requirementDigest:"",allocatedBandwidthBps:0,expiry:REFERENCE_NOW+3600,policyVersion:1} as any, kpA.nodeId, kpA.secretKey, REFERENCE_NOW + 3600);
    const ok = verifyRouteAcceptance(acceptance, kpB.publicKey);
    expect(ok).toBe(false);
  });
});
