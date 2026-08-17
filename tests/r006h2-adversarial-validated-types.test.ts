/**
 * ShareNet 2.0 — R-006H3: Adversarial tests for unforgeable trust chain.
 *
 * Proves that the full trust chain is unforgeable at EVERY construction boundary:
 *   verifyAdvertisement → VerifiedNodeAdvertisement (WeakSet-registered)
 *   createRouteCommitment → RouteCommitment (WeakSet-registered)
 *   createAuthenticatedNodeRecord ← genuine VerifiedNodeAdvertisement only
 *   createBrandedCommittedRoute ← genuine RouteCommitment only
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  randomBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  signAdvertisement,
  verifyAdvertisement,
  isVerifiedNodeAdvertisement,
  type NodeCapability,
  type VerifiedNodeAdvertisement,
} from "@reference/advertisement/advertisement";
import {
  signRouteAcceptance,
  createRouteCommitment,
  type RouteProposal,
  type RouteHop,
  type RouteCommitment,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";
import {
  createAuthenticatedNodeRecord,
  isAuthenticatedNodeRecord,
  createValidatedHop,
  isValidatedHop,
  createBrandedCommittedRoute,
  isBrandedCommittedRoute,
  isRouteCommitment,
  type AuthenticatedNodeRecord,
  type ValidatedHop,
} from "@reference/transport/validated-types";

const NOW = 1786876545;

function makeGenuineVerifiedAdv(kp: ReturnType<typeof generateNodeKeypair>, now = NOW): VerifiedNodeAdvertisement {
  const adv = signAdvertisement({
    protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
    capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
    sequence: 1, timestamp: now, expiry: now + 3600, nonce: randomBytes(16),
  }, kp.secretKey);
  const v = verifyAdvertisement(adv, now);
  if (!v.ok) throw new Error("adv verification failed");
  return v.verified;
}

function makeGenuineCommitment(kp: ReturnType<typeof generateNodeKeypair>): RouteCommitment {
  const proposal: RouteProposal = {
    routeId: bytesToHex(randomBytes(32)),
    hops: [{ nodeId: kp.nodeId, capability: "MESH_RELAY", endpoint: "10.0.0.1:7788", linkUp: true }],
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: NOW + 3600,
    initiatorNodeId: kp.nodeId,
    agreementDigest: bytesToHex(randomBytes(32)),
  };
  const sa = new Map<number, ServiceAgreement>();
  sa.set(0, { nodeId: kp.nodeId, capability: "MESH_RELAY", requirementDigest: proposal.requirementDigest, allocatedBandwidthBps: 1048576, expiry: proposal.expiry, policyVersion: 1 });
  const hpk = new Map<string, Uint8Array>();
  hpk.set(kp.nodeId, kp.publicKey);
  const acc = [signRouteAcceptance(proposal, 0, proposal.hops[0]!, sa.get(0)!, kp.nodeId, kp.secretKey, proposal.expiry)];
  const result = createRouteCommitment(proposal, acc, hpk, sa, kp.secretKey, NOW);
  if (!result.ok) throw new Error("commitment failed");
  return result.commitment;
}

describe("R-006H3: Unforgeable trust chain at every construction boundary", () => {
  // 1. Forged VerifiedNodeAdvertisement → rejected
  test("forged VerifiedNodeAdvertisement (matching shape) → rejected by createAuthenticatedNodeRecord", () => {
    const kp = generateNodeKeypair();
    const genuine = makeGenuineVerifiedAdv(kp);

    // Attacker constructs a forged object matching the exact shape
    const forged: VerifiedNodeAdvertisement = {
      advertisement: genuine.advertisement,
      verifiedAt: genuine.verifiedAt,
      bodyBytes: genuine.bodyBytes,
    };

    // The forged object is NOT in the WeakSet (never went through verifyAdvertisement)
    expect(isVerifiedNodeAdvertisement(forged)).toBe(false);
    expect(isVerifiedNodeAdvertisement(genuine)).toBe(true);

    // createAuthenticatedNodeRecord must reject the forged object
    expect(() => createAuthenticatedNodeRecord(forged)).toThrow();

    // But it accepts the genuine one
    const authNode = createAuthenticatedNodeRecord(genuine);
    expect(isAuthenticatedNodeRecord(authNode)).toBe(true);
  });

  // 2. Copied VerifiedNodeAdvertisement → rejected
  test("copied VerifiedNodeAdvertisement → rejected by WeakSet", () => {
    const kp = generateNodeKeypair();
    const genuine = makeGenuineVerifiedAdv(kp);

    // Attacker copies all properties
    const copy = { ...genuine };

    // The copy is NOT in the WeakSet — property copying doesn't help
    expect(isVerifiedNodeAdvertisement(copy)).toBe(false);
    expect(() => createAuthenticatedNodeRecord(copy)).toThrow();
  });

  // 3. Forged RouteCommitment → rejected
  test("forged RouteCommitment (matching shape) → rejected by createBrandedCommittedRoute", () => {
    const kp = generateNodeKeypair();
    const genuine = makeGenuineCommitment(kp);

    // Attacker constructs a forged object matching the RouteCommitment shape
    const forged: RouteCommitment = {
      routeId: genuine.routeId,
      proposal: genuine.proposal,
      acceptances: genuine.acceptances,
      committerSignature: genuine.committerSignature,
      committedAt: genuine.committedAt,
    };

    // The forged object is NOT in the WeakSet
    expect(isRouteCommitment(forged)).toBe(false);
    expect(isRouteCommitment(genuine)).toBe(true);

    // createBrandedCommittedRoute must reject the forged object
    expect(() => createBrandedCommittedRoute(forged)).toThrow();

    // But it accepts the genuine one
    const branded = createBrandedCommittedRoute(genuine);
    expect(isBrandedCommittedRoute(branded)).toBe(true);
  });

  // 4. Copied RouteCommitment → rejected
  test("copied RouteCommitment → rejected by WeakSet", () => {
    const kp = generateNodeKeypair();
    const genuine = makeGenuineCommitment(kp);

    // Attacker copies all properties
    const copy = { ...genuine };

    // The copy is NOT in the WeakSet
    expect(isRouteCommitment(copy)).toBe(false);
    expect(() => createBrandedCommittedRoute(copy)).toThrow();
  });

  // 5. Ordinary RouteHop[] → cannot produce BrandedCommittedRoute
  test("ordinary RouteHop[] (not from genuine commitment) → cannot produce BrandedCommittedRoute", () => {
    const kp = generateNodeKeypair();

    // Construct an ordinary RouteHop (not a ValidatedHop)
    const ordinaryHop: RouteHop = {
      nodeId: kp.nodeId,
      capability: "MESH_RELAY",
      endpoint: "10.0.0.1:7788",
      linkUp: true,
    };

    // This hop is NOT a ValidatedHop (not in the WeakSet)
    expect(isValidatedHop(ordinaryHop)).toBe(false);

    // Attempt to create a BrandedCommittedRoute from a fake commitment
    // containing ordinary RouteHop[]
    const fakeCommitment = {
      routeId: "fake",
      proposal: {
        routeId: "fake",
        hops: [ordinaryHop],
        requirementDigest: "",
        expiry: NOW + 3600,
        initiatorNodeId: kp.nodeId,
        agreementDigest: "",
      },
      acceptances: [],
      committerSignature: new Uint8Array(64),
      committedAt: NOW,
    };

    // The fake commitment is NOT a genuine RouteCommitment
    expect(isRouteCommitment(fakeCommitment)).toBe(false);
    expect(() => createBrandedCommittedRoute(fakeCommitment as RouteCommitment)).toThrow();
  });

  // 6. Genuine full pipeline → succeeds
  test("genuine full pipeline: verifyAdvertisement → createAuthenticatedNodeRecord → createRouteCommitment → createBrandedCommittedRoute", () => {
    const kp = generateNodeKeypair();

    // Step 1: Verify advertisement → genuine VerifiedNodeAdvertisement
    const verifiedAdv = makeGenuineVerifiedAdv(kp);
    expect(isVerifiedNodeAdvertisement(verifiedAdv)).toBe(true);

    // Step 2: Create AuthenticatedNodeRecord from genuine proof artifact
    const authNode = createAuthenticatedNodeRecord(verifiedAdv);
    expect(isAuthenticatedNodeRecord(authNode)).toBe(true);

    // Step 3: Create ValidatedHop
    const hop = createValidatedHop(authNode, "10.0.0.1:7788", "MESH_RELAY", true, "digest");
    expect(isValidatedHop(hop)).toBe(true);

    // Step 4: Create genuine RouteCommitment through the full pipeline
    const commitment = makeGenuineCommitment(kp);
    expect(isRouteCommitment(commitment)).toBe(true);

    // Step 5: Create BrandedCommittedRoute from genuine commitment
    const branded = createBrandedCommittedRoute(commitment);
    expect(isBrandedCommittedRoute(branded)).toBe(true);

    // Step 6: A copy of the branded route is NOT recognized
    const copy = { ...branded };
    expect(isBrandedCommittedRoute(copy)).toBe(false);
  });
});
