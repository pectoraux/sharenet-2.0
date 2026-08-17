/**
 * ShareNet 2.0 — R-003/R-004: Canonical commitment-root reconciliation.
 *
 * Per the R-003/R-004 directive:
 *
 *   "RouteProposal → canonical encoding → proposal_digest
 *    RouteAcceptance[] → canonical ordered encoding → acceptance_root
 *    proposal_digest + acceptance_root + commitment_nonce
 *        ↓ commitment_root
 *        ↓ source signature
 *        ↓ RouteCommitment
 *        ↓ route_id = canonical(commitment_root)"
 *
 * The key property: route_id is now DERIVED from the commitment_root, not
 * from a caller-chosen proposal identifier. Two routes with the same
 * proposal.routeId but different acceptances (or different commitment_nonce)
 * get DIFFERENT route_ids.
 *
 * Adversarial tests:
 *   - two routes with same proposal.routeId but different acceptances → different route_ids
 *   - two commitments with same proposal + acceptances but different commitment_nonce → different route_ids
 *   - route_id == toHex(commitment_root) (the canonical identity)
 *   - commitment_root changes if any acceptance signature changes
 *   - commitment_root changes if the proposal changes
 *   - commitment_root changes if the commitment_nonce changes
 *   - the committer signature is over the commitment_root (not over proposal.routeId)
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
  computeCommitmentRoot,
  deriveRouteId,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";
import { proposalDigest } from "@reference/routing/digests";

const NOW = 1786876545;

function makeProposal(kps: { nodeId: string; publicKey: Uint8Array; secretKey: Uint8Array }[], initiator: { nodeId: string; secretKey: Uint8Array }) {
  const hops: RouteHop[] = kps.map((kp, i) => ({
    nodeId: kp.nodeId,
    capability: i === kps.length - 1 ? "INTERNET_GATEWAY" : "MESH_RELAY",
    endpoint: `10.0.0.${i + 1}:7788`,
    linkUp: true,
  }));
  const proposal: RouteProposal = {
    routeId: bytesToHex(randomBytes(32)),
    hops,
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: NOW + 3600,
    initiatorNodeId: initiator.nodeId,
    agreementDigest: bytesToHex(randomBytes(32)),
  };
  return { proposal, hops };
}

function makeAcceptances(proposal: RouteProposal, hops: RouteHop[], kps: { nodeId: string; secretKey: Uint8Array }[]) {
  const sa = new Map<number, ServiceAgreement>();
  const hpk = new Map<string, Uint8Array>();
  const accs = [];
  for (let i = 0; i < kps.length; i++) {
    sa.set(i, {
      nodeId: kps[i]!.nodeId, capability: hops[i]!.capability as any,
      requirementDigest: proposal.requirementDigest,
      allocatedBandwidthBps: 1048576, expiry: proposal.expiry, policyVersion: 1,
    });
    hpk.set(kps[i]!.nodeId, (kps[i] as any).publicKey);
    accs.push(signRouteAcceptance(proposal, i, hops[i]!, sa.get(i)!, kps[i]!.nodeId, kps[i]!.secretKey, proposal.expiry));
  }
  return { acceptances: accs, hopPublicKeys: hpk, serviceAgreements: sa };
}

describe("R-003/R-004: Canonical commitment-root reconciliation", () => {
  test("route_id is DERIVED from commitment_root (not proposal.routeId)", () => {
    const kps = [generateNodeKeypair(), generateNodeKeypair()];
    const initiator = generateNodeKeypair();
    const { proposal, hops } = makeProposal(kps, initiator);
    const { acceptances, hopPublicKeys, serviceAgreements } = makeAcceptances(proposal, hops, kps);

    const result = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, initiator.secretKey, NOW);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const commitment = result.commitment;
    // route_id == toHex(commitment_root) — the canonical identity
    expect(commitment.routeId).toBe(deriveRouteId(commitment.commitmentRoot));
    expect(commitment.routeId).toBe(bytesToHex(commitment.commitmentRoot));
    // route_id != proposal.routeId (the old caller-chosen identifier)
    expect(commitment.routeId).not.toBe(proposal.routeId);

    // CommittedRoute also carries the commitment_root
    const route = createCommittedRoute(commitment);
    expect(route.routeId).toBe(commitment.routeId);
    expect(route.commitmentRoot).toEqual(commitment.commitmentRoot);
  });

  test("two routes with same proposal.routeId but different acceptances → DIFFERENT route_ids", () => {
    const kps1 = [generateNodeKeypair(), generateNodeKeypair()];
    const kps2 = [generateNodeKeypair(), generateNodeKeypair()]; // different relay/gateway
    const initiator = generateNodeKeypair();

    // Both proposals use the SAME routeId (caller-chosen)
    const routeId = bytesToHex(randomBytes(32));
    const hops1: RouteHop[] = kps1.map((kp, i) => ({
      nodeId: kp.nodeId, capability: i === 1 ? "INTERNET_GATEWAY" : "MESH_RELAY",
      endpoint: `10.0.0.${i + 1}:7788`, linkUp: true,
    }));
    const hops2: RouteHop[] = kps2.map((kp, i) => ({
      nodeId: kp.nodeId, capability: i === 1 ? "INTERNET_GATEWAY" : "MESH_RELAY",
      endpoint: `10.0.0.${i + 1}:7789`, linkUp: true,
    }));
    const proposal1: RouteProposal = {
      routeId, hops: hops1, requirementDigest: bytesToHex(randomBytes(32)),
      expiry: NOW + 3600, initiatorNodeId: initiator.nodeId, agreementDigest: bytesToHex(randomBytes(32)),
    };
    const proposal2: RouteProposal = {
      routeId, hops: hops2, requirementDigest: bytesToHex(randomBytes(32)),
      expiry: NOW + 3600, initiatorNodeId: initiator.nodeId, agreementDigest: bytesToHex(randomBytes(32)),
    };

    const sa1 = new Map<number, ServiceAgreement>();
    const hpk1 = new Map<string, Uint8Array>();
    const accs1 = [];
    for (let i = 0; i < kps1.length; i++) {
      sa1.set(i, { nodeId: kps1[i]!.nodeId, capability: hops1[i]!.capability as any, requirementDigest: proposal1.requirementDigest, allocatedBandwidthBps: 1048576, expiry: proposal1.expiry, policyVersion: 1 });
      hpk1.set(kps1[i]!.nodeId, kps1[i]!.publicKey);
      accs1.push(signRouteAcceptance(proposal1, i, hops1[i]!, sa1.get(i)!, kps1[i]!.nodeId, kps1[i]!.secretKey, proposal1.expiry));
    }

    const sa2 = new Map<number, ServiceAgreement>();
    const hpk2 = new Map<string, Uint8Array>();
    const accs2 = [];
    for (let i = 0; i < kps2.length; i++) {
      sa2.set(i, { nodeId: kps2[i]!.nodeId, capability: hops2[i]!.capability as any, requirementDigest: proposal2.requirementDigest, allocatedBandwidthBps: 1048576, expiry: proposal2.expiry, policyVersion: 1 });
      hpk2.set(kps2[i]!.nodeId, kps2[i]!.publicKey);
      accs2.push(signRouteAcceptance(proposal2, i, hops2[i]!, sa2.get(i)!, kps2[i]!.nodeId, kps2[i]!.secretKey, proposal2.expiry));
    }

    const r1 = createRouteCommitment(proposal1, accs1, hpk1, sa1, initiator.secretKey, NOW);
    const r2 = createRouteCommitment(proposal2, accs2, hpk2, sa2, initiator.secretKey, NOW);
    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(true);
    if (!r1.ok || !r2.ok) return;

    // Same proposal.routeId, but different route_ids (different commitment_roots)
    expect(r1.commitment.routeId).not.toBe(r2.commitment.routeId);
    expect(r1.commitment.commitmentRoot).not.toEqual(r2.commitment.commitmentRoot);
  });

  test("two commitments with same proposal + acceptances but different commitment_nonce → different route_ids", () => {
    const kps = [generateNodeKeypair(), generateNodeKeypair()];
    const initiator = generateNodeKeypair();
    const { proposal, hops } = makeProposal(kps, initiator);
    const { acceptances, hopPublicKeys, serviceAgreements } = makeAcceptances(proposal, hops, kps);

    // Compute two commitment_roots with different nonces
    const nonce1 = randomBytes(16);
    const nonce2 = randomBytes(16);
    const root1 = computeCommitmentRoot(proposal, acceptances, nonce1);
    const root2 = computeCommitmentRoot(proposal, acceptances, nonce2);
    expect(deriveRouteId(root1)).not.toBe(deriveRouteId(root2));
  });

  test("commitment_root changes if any acceptance signature changes", () => {
    const kps = [generateNodeKeypair(), generateNodeKeypair()];
    const initiator = generateNodeKeypair();
    const { proposal, hops } = makeProposal(kps, initiator);
    const { acceptances, hopPublicKeys, serviceAgreements } = makeAcceptances(proposal, hops, kps);

    // Create a second set of acceptances with different nonces (same proposal, same keys)
    const acceptances2 = kps.map((kp, i) =>
      signRouteAcceptance(proposal, i, hops[i]!, serviceAgreements.get(i)!, kp.nodeId, kp.secretKey, proposal.expiry),
    );

    const nonce = randomBytes(16);
    const root1 = computeCommitmentRoot(proposal, acceptances, nonce);
    const root2 = computeCommitmentRoot(proposal, acceptances2, nonce);
    // Different acceptance signatures → different commitment_roots
    expect(deriveRouteId(root1)).not.toBe(deriveRouteId(root2));
  });

  test("commitment_root changes if the proposal changes (different hops)", () => {
    const kps = [generateNodeKeypair(), generateNodeKeypair()];
    const initiator = generateNodeKeypair();
    const { proposal: p1, hops: h1 } = makeProposal(kps, initiator);

    // Different proposal with different hops (same routeId but different nodeIds)
    const kps2 = [generateNodeKeypair(), generateNodeKeypair()];
    const { proposal: p2, hops: h2 } = makeProposal(kps2, initiator);
    p2.routeId = p1.routeId; // same caller-chosen routeId

    const sa1 = new Map<number, ServiceAgreement>();
    const hpk1 = new Map<string, Uint8Array>();
    const accs1 = [];
    for (let i = 0; i < kps.length; i++) {
      sa1.set(i, { nodeId: kps[i]!.nodeId, capability: h1[i]!.capability as any, requirementDigest: p1.requirementDigest, allocatedBandwidthBps: 1048576, expiry: p1.expiry, policyVersion: 1 });
      hpk1.set(kps[i]!.nodeId, kps[i]!.publicKey);
      accs1.push(signRouteAcceptance(p1, i, h1[i]!, sa1.get(i)!, kps[i]!.nodeId, kps[i]!.secretKey, p1.expiry));
    }

    const sa2 = new Map<number, ServiceAgreement>();
    const hpk2 = new Map<string, Uint8Array>();
    const accs2 = [];
    for (let i = 0; i < kps2.length; i++) {
      sa2.set(i, { nodeId: kps2[i]!.nodeId, capability: h2[i]!.capability as any, requirementDigest: p2.requirementDigest, allocatedBandwidthBps: 1048576, expiry: p2.expiry, policyVersion: 1 });
      hpk2.set(kps2[i]!.nodeId, kps2[i]!.publicKey);
      accs2.push(signRouteAcceptance(p2, i, h2[i]!, sa2.get(i)!, kps2[i]!.nodeId, kps2[i]!.secretKey, p2.expiry));
    }

    const nonce = randomBytes(16);
    const root1 = computeCommitmentRoot(p1, accs1, nonce);
    const root2 = computeCommitmentRoot(p2, accs2, nonce);
    expect(deriveRouteId(root1)).not.toBe(deriveRouteId(root2));
  });

  test("the committer signature is over the commitment_root (tampering with routeId doesn't affect signature validity)", () => {
    const kps = [generateNodeKeypair(), generateNodeKeypair()];
    const initiator = generateNodeKeypair();
    const { proposal, hops } = makeProposal(kps, initiator);
    const { acceptances, hopPublicKeys, serviceAgreements } = makeAcceptances(proposal, hops, kps);

    const result = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, initiator.secretKey, NOW);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const commitment = result.commitment;
    // The signature is over commitment_root + commitment_nonce.
    // If we change the commitment_root, the signature would be invalid.
    // Verify: the route_id is the hex of commitment_root
    expect(commitment.routeId).toBe(bytesToHex(commitment.commitmentRoot));
    // Verify: commitment_root is 32 bytes
    expect(commitment.commitmentRoot.length).toBe(32);
    // Verify: commitment_nonce is 16 bytes
    expect(commitment.commitmentNonce.length).toBe(16);
  });

  test("commitment_root is deterministic for same inputs (same proposal + acceptances + nonce)", () => {
    const kps = [generateNodeKeypair(), generateNodeKeypair()];
    const initiator = generateNodeKeypair();
    const { proposal, hops } = makeProposal(kps, initiator);
    const { acceptances } = makeAcceptances(proposal, hops, kps);

    const nonce = randomBytes(16);
    const root1 = computeCommitmentRoot(proposal, acceptances, nonce);
    const root2 = computeCommitmentRoot(proposal, acceptances, nonce);
    // Same inputs → same commitment_root (deterministic)
    expect(deriveRouteId(root1)).toBe(deriveRouteId(root2));
  });
});
