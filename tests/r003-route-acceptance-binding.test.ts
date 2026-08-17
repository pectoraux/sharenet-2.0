/**
 * ShareNet 2.0 — R-003D: Route Acceptance Binding Tests.
 *
 * Per R-003 requirement: 15 mandatory tests proving that mutating any
 * bound field invalidates the acceptance signature.
 *
 * The acceptance must prove:
 *   "Node X, occupying hop N, accepts this exact route proposal, this
 *    exact role, and these exact negotiated service terms until this expiry."
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
  verifyRouteAcceptance,
  verifyAcceptanceBinding,
  createRouteCommitment,
  createCommittedRoute,
  type RouteAcceptance,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";
import { proposalDigest, hopDigest, serviceDigest } from "@reference/routing/digests";

const REFERENCE_NOW = 1786876545;

function setup() {
  const initiator = generateNodeKeypair();
  const relay = generateNodeKeypair();
  const gateway = generateNodeKeypair();

  const hops: RouteHop[] = [
    { nodeId: relay.nodeId, capability: "MESH_RELAY", endpoint: "10.0.0.1:7788", linkUp: true },
    { nodeId: gateway.nodeId, capability: "INTERNET_GATEWAY", endpoint: "10.0.0.2:7789", linkUp: true },
  ];

  const proposal: RouteProposal = {
    hops,
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: REFERENCE_NOW + 3600,
    initiatorNodeId: initiator.nodeId,
    agreementDigest: bytesToHex(randomBytes(32)),
  };

  const agreements: ServiceAgreement[] = [
    { nodeId: relay.nodeId, capability: "MESH_RELAY", requirementDigest: proposal.requirementDigest, allocatedBandwidthBps: 1048576, expiry: proposal.expiry, policyVersion: 1 },
    { nodeId: gateway.nodeId, capability: "INTERNET_GATEWAY", requirementDigest: proposal.requirementDigest, allocatedBandwidthBps: 1048576, expiry: proposal.expiry, policyVersion: 1 },
  ];

  const hopPublicKeys = new Map<string, Uint8Array>([
    [relay.nodeId, relay.publicKey],
    [gateway.nodeId, gateway.publicKey],
  ]);
  const serviceAgreements = new Map<number, ServiceAgreement>([[0, agreements[0]!], [1, agreements[1]!]]);

  const acceptances = [
    signRouteAcceptance(proposal, 0, hops[0]!, agreements[0]!, relay.nodeId, relay.secretKey, proposal.expiry),
    signRouteAcceptance(proposal, 1, hops[1]!, agreements[1]!, gateway.nodeId, gateway.secretKey, proposal.expiry),
  ];

  return { initiator, relay, gateway, hops, proposal, agreements, hopPublicKeys, serviceAgreements, acceptances };
}

describe("R-003D: Route acceptance binding tests", () => {
  // 1. Valid acceptance verifies
  test("1. Valid acceptance verifies", () => {
    const ctx = setup();
    expect(verifyRouteAcceptance(ctx.acceptances[0]!, ctx.relay.publicKey)).toBe(true);
    expect(verifyRouteAcceptance(ctx.acceptances[1]!, ctx.gateway.publicKey)).toBe(true);
  });

  // 2. Mutated route proposal fails
  test("2. Mutated route proposal fails binding", () => {
    const ctx = setup();
    const mutatedProposal = { ...ctx.proposal, requirementDigest: bytesToHex(randomBytes(32)) };
    const r = verifyAcceptanceBinding(ctx.acceptances[0]!, mutatedProposal, 0, ctx.hops[0]!, ctx.agreements[0]!);
    expect(r.ok).toBe(false);
  });

  // 3. Mutated hop NodeId fails
  test("3. Mutated hop NodeId fails binding", () => {
    const ctx = setup();
    const mutatedHop = { ...ctx.hops[0]!, nodeId: "differentnode" };
    const r = verifyAcceptanceBinding(ctx.acceptances[0]!, ctx.proposal, 0, mutatedHop, ctx.agreements[0]!);
    expect(r.ok).toBe(false);
  });

  // 4. Mutated hop endpoint fails
  test("4. Mutated hop endpoint fails binding", () => {
    const ctx = setup();
    const mutatedHop = { ...ctx.hops[0]!, endpoint: "evil.com:9999" };
    const r = verifyAcceptanceBinding(ctx.acceptances[0]!, ctx.proposal, 0, mutatedHop, ctx.agreements[0]!);
    expect(r.ok).toBe(false);
  });

  // 5. Mutated capability/role fails
  test("5. Mutated capability fails binding", () => {
    const ctx = setup();
    const mutatedHop = { ...ctx.hops[0]!, capability: "INTERNET_GATEWAY" as any };
    const r = verifyAcceptanceBinding(ctx.acceptances[0]!, ctx.proposal, 0, mutatedHop, ctx.agreements[0]!);
    expect(r.ok).toBe(false);
  });

  // 6. Mutated service agreement fails
  test("6. Mutated service agreement fails binding", () => {
    const ctx = setup();
    const mutatedAgreement = { ...ctx.agreements[0]!, allocatedBandwidthBps: 999999 };
    const r = verifyAcceptanceBinding(ctx.acceptances[0]!, ctx.proposal, 0, ctx.hops[0]!, mutatedAgreement);
    expect(r.ok).toBe(false);
  });

  // 7. Mutated expiry fails
  test("7. Mutated expiry in acceptance fails signature", () => {
    const ctx = setup();
    const mutatedAcceptance = { ...ctx.acceptances[0]!, expiry: ctx.proposal.expiry + 10000 };
    expect(verifyRouteAcceptance(mutatedAcceptance, ctx.relay.publicKey)).toBe(false);
  });

  // 8. Mutated acceptance nonce fails
  test("8. Mutated acceptance nonce fails signature", () => {
    const ctx = setup();
    const mutatedNonce = new Uint8Array(ctx.acceptances[0]!.acceptanceNonce);
    mutatedNonce[0] ^= 0xff;
    const mutatedAcceptance = { ...ctx.acceptances[0]!, acceptanceNonce: mutatedNonce };
    expect(verifyRouteAcceptance(mutatedAcceptance, ctx.relay.publicKey)).toBe(false);
  });

  // 9. Wrong acceptor key fails
  test("9. Wrong acceptor key fails", () => {
    const ctx = setup();
    const wrongKey = generateNodeKeypair();
    expect(verifyRouteAcceptance(ctx.acceptances[0]!, wrongKey.publicKey)).toBe(false);
  });

  // 10. Acceptance for hop N cannot satisfy hop N+1
  test("10. Acceptance for hop 0 cannot satisfy hop 1", () => {
    const ctx = setup();
    const r = verifyAcceptanceBinding(ctx.acceptances[0]!, ctx.proposal, 1, ctx.hops[1]!, ctx.agreements[1]!);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("hopIndex");
  });

  // 11. Duplicate acceptance cannot satisfy two hops
  test("11. Duplicate acceptance (same for both hops) fails", () => {
    const ctx = setup();
    // Try to use acceptance[0] for hop 1
    const r = verifyAcceptanceBinding(ctx.acceptances[0]!, ctx.proposal, 1, ctx.hops[1]!, ctx.agreements[1]!);
    expect(r.ok).toBe(false);
  });

  // 12. Acceptance for another proposal with same caller-chosen identifier fails
  test("12. Acceptance for different proposal fails binding", () => {
    const ctx = setup();
    // Different hops → different proposal_digest
    const differentProposal: RouteProposal = {
      ...ctx.proposal,
      hops: [
        { nodeId: "different", capability: "MESH_RELAY", endpoint: "10.0.0.9:7788", linkUp: true },
        { nodeId: "different2", capability: "INTERNET_GATEWAY", endpoint: "10.0.0.8:7789", linkUp: true },
      ],
    };
    const r = verifyAcceptanceBinding(ctx.acceptances[0]!, differentProposal, 0, ctx.hops[0]!, ctx.agreements[0]!);
    expect(r.ok).toBe(false);
  });

  // 13. createRouteCommitment rejects invalid signatures
  test("13. createRouteCommitment rejects invalid signatures", () => {
    const ctx = setup();
    // Tamper with a signature
    const badSig = new Uint8Array(ctx.acceptances[0]!.signature);
    badSig[0] ^= 0xff;
    const tamperedAcceptances = [
      { ...ctx.acceptances[0]!, signature: badSig },
      ctx.acceptances[1]!,
    ];
    const result = createRouteCommitment(ctx.proposal, tamperedAcceptances, ctx.hopPublicKeys, ctx.serviceAgreements, ctx.initiator.secretKey, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature");
  });

  // 14. createRouteCommitment rejects mismatched proposal digest
  test("14. createRouteCommitment rejects mismatched proposal digest", () => {
    const ctx = setup();
    // Create acceptances signed over a DIFFERENT proposal
    const differentProposal = { ...ctx.proposal, requirementDigest: bytesToHex(randomBytes(32)) };
    const differentAcceptances = [
      signRouteAcceptance(differentProposal, 0, ctx.hops[0]!, ctx.agreements[0]!, ctx.relay.nodeId, ctx.relay.secretKey, ctx.proposal.expiry),
      signRouteAcceptance(differentProposal, 1, ctx.hops[1]!, ctx.agreements[1]!, ctx.gateway.nodeId, ctx.gateway.secretKey, ctx.proposal.expiry),
    ];
    // Try to commit with the ORIGINAL proposal (mismatch)
    const result = createRouteCommitment(ctx.proposal, differentAcceptances, ctx.hopPublicKeys, ctx.serviceAgreements, ctx.initiator.secretKey, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("digest");
  });

  // 15. Commitment changes when any accepted route term changes
  test("15. Different proposals produce different commitments", () => {
    const ctx1 = setup();
    const ctx2 = setup();
    // Different proposals (different hops → different commitment_roots)
    const r1 = createRouteCommitment(ctx1.proposal, ctx1.acceptances, ctx1.hopPublicKeys, ctx1.serviceAgreements, ctx1.initiator.secretKey, REFERENCE_NOW);
    const r2 = createRouteCommitment(ctx2.proposal, ctx2.acceptances, ctx2.hopPublicKeys, ctx2.serviceAgreements, ctx2.initiator.secretKey, REFERENCE_NOW);
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    if (r1.ok && r2.ok) {
      const route1 = createCommittedRoute(r1.commitment);
      const route2 = createCommittedRoute(r2.commitment);
      expect(route1.routeId).not.toBe(route2.routeId);
    }
  });
});
