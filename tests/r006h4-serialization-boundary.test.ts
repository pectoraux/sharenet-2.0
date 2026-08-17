/**
 * ShareNet 2.0 — R-006H4: Serialization boundary audit.
 *
 * Per R-006H4: the WeakSet model protects in-memory object identity.
 * It does NOT survive serialize → deserialize. These tests prove that
 * deserialized proof objects are correctly REJECTED — the protocol must
 * never accidentally treat deserialized data as proof artifacts.
 *
 * The correct lifecycle is:
 *   wire object → decode → verify cryptographic validity → create new proof
 *   artifact → WeakSet registration
 *
 * NOT:
 *   wire object → deserialize → pretend proof still exists
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
  advertisementToHex,
  advertisementFromHex,
} from "@reference/advertisement/advertisement";
import {
  signRouteAcceptance,
  createRouteCommitment,
  createCommittedRoute,
  type RouteProposal,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";
import {
  createAuthenticatedNodeRecord,
  isAuthenticatedNodeRecord,
  createBrandedCommittedRoute,
  isBrandedCommittedRoute,
  isRouteCommitment,
} from "@reference/transport/validated-types";

const NOW = 1786876545;

describe("R-006H4: Serialization boundary — deserialized proof objects are rejected", () => {
  // 1. Serialize VerifiedNodeAdvertisement → deserialize → createAuthenticatedNodeRecord MUST FAIL
  test("deserialized VerifiedNodeAdvertisement → rejected by createAuthenticatedNodeRecord", () => {
    const kp = generateNodeKeypair();
    const adv = signAdvertisement({
      protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
      capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
      sequence: 1, timestamp: NOW, expiry: NOW + 3600, nonce: randomBytes(16),
    }, kp.secretKey);
    const v = verifyAdvertisement(adv, NOW);
    if (!v.ok) throw new Error("verify failed");

    // Serialize → deserialize (simulating crossing a process/network boundary)
    const serialized = JSON.stringify({
      advertisement: v.verified.advertisement,
      verifiedAt: v.verified.verifiedAt,
      bodyBytes: bytesToHex(v.verified.bodyBytes),
    });
    const deserialized = JSON.parse(serialized);
    // Reconstruct the shape
    const fakeVerified = {
      advertisement: deserialized.advertisement,
      verifiedAt: deserialized.verifiedAt,
      bodyBytes: new Uint8Array(deserialized.bodyBytes.match(/.{2}/g).map((b: string) => parseInt(b, 16))),
    };

    // The deserialized object is NOT in the WeakSet
    expect(isVerifiedNodeAdvertisement(fakeVerified)).toBe(false);
    expect(() => createAuthenticatedNodeRecord(fakeVerified)).toThrow();
  });

  // 2. Serialize RouteCommitment → deserialize → createBrandedCommittedRoute MUST FAIL
  test("deserialized RouteCommitment → rejected by createBrandedCommittedRoute", () => {
    const kp = generateNodeKeypair();
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
    const commitment = result.commitment;

    // Serialize → deserialize
    const serialized = JSON.stringify(commitment);
    const deserialized = JSON.parse(serialized);

    // The deserialized object is NOT in the WeakSet
    expect(isRouteCommitment(deserialized)).toBe(false);
    expect(() => createBrandedCommittedRoute(deserialized)).toThrow();
  });

  // 3. Serialize BrandedCommittedRoute → deserialize → setupCircuit MUST FAIL
  test("deserialized BrandedCommittedRoute → rejected by isBrandedCommittedRoute", () => {
    const kp = generateNodeKeypair();
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
    const branded = createBrandedCommittedRoute(result.commitment);
    expect(isBrandedCommittedRoute(branded)).toBe(true);

    // Serialize → deserialize
    const serialized = JSON.stringify(branded);
    const deserialized = JSON.parse(serialized);

    // The deserialized object is NOT in the WeakSet
    expect(isBrandedCommittedRoute(deserialized)).toBe(false);

    // A copy of the branded object is also NOT recognized
    const copy = { ...branded };
    expect(isBrandedCommittedRoute(copy)).toBe(false);
  });

  // 4. Correct lifecycle: wire → decode → verify → create new proof → register
  test("correct lifecycle: decode advertisement hex → verify → create AuthenticatedNodeRecord (new proof)", () => {
    const kp = generateNodeKeypair();
    const adv = signAdvertisement({
      protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
      capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
      sequence: 1, timestamp: NOW, expiry: NOW + 3600, nonce: randomBytes(16),
    }, kp.secretKey);

    // Wire format: hex
    const wireHex = advertisementToHex(adv);

    // Step 1: Decode from wire
    const decoded = advertisementFromHex(wireHex);

    // Step 2: Verify cryptographic validity (creates a NEW proof artifact, registered in WeakSet)
    const v = verifyAdvertisement(decoded, NOW);
    expect(v.ok).toBe(true);
    if (!v.ok) return;

    // Step 3: The verified artifact IS genuine (in the WeakSet)
    expect(isVerifiedNodeAdvertisement(v.verified)).toBe(true);

    // Step 4: Create AuthenticatedNodeRecord from the genuine proof
    const authNode = createAuthenticatedNodeRecord(v.verified);
    expect(isAuthenticatedNodeRecord(authNode)).toBe(true);
  });
});
