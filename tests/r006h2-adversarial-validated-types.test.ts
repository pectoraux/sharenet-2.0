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
  type VerifiedNodeAdvertisement,
} from "@reference/advertisement/advertisement";
import {
  type RouteHop,
  type RouteCommitment,
} from "@reference/routing/route";
import {
  createAuthenticatedNodeRecord,
  isAuthenticatedNodeRecord,
  createValidatedHop,
  isValidatedHop,
  createBrandedCommittedRoute,
  isBrandedCommittedRoute,
  isRouteCommitment,
  type ValidatedHop,
} from "@reference/transport/validated-types";
import { isAuthenticatedLink } from "@reference/transport/authenticated-link";
import {
  makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper,
} from "@tests/helpers/branded-route-helper";

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

// R-002-P1: createValidatedHop now consumes a genuine AuthenticatedLink
// (produced by the 3-message handshake) instead of a caller-supplied
// `linkUp: boolean`. Delegate to the shared helper so this file no longer
// hand-rolls the pipeline.
function makeGenuineCommitment(_kp: ReturnType<typeof generateNodeKeypair>): { commitment: RouteCommitment; validatedHops: ValidatedHop[] } {
  const ctx = makeGenuineBrandedRouteHelper(1, NOW);
  return { commitment: ctx.commitment, validatedHops: ctx.validatedHops };
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
    const { commitment: genuine, validatedHops } = makeGenuineCommitment(kp);

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

    // createBrandedCommittedRoute must reject the forged commitment
    // (isRouteCommitment check fires before validatedHops check)
    expect(() => createBrandedCommittedRoute(forged, [])).toThrow();

    // But it accepts the genuine commitment + genuine validatedHops
    const branded = createBrandedCommittedRoute(genuine, validatedHops);
    expect(isBrandedCommittedRoute(branded)).toBe(true);
  });

  // 4. Copied RouteCommitment → rejected
  test("copied RouteCommitment → rejected by WeakSet", () => {
    const kp = generateNodeKeypair();
    const { commitment: genuine } = makeGenuineCommitment(kp);

    // Attacker copies all properties
    const copy = { ...genuine };

    // The copy is NOT in the WeakSet
    expect(isRouteCommitment(copy)).toBe(false);
    expect(() => createBrandedCommittedRoute(copy as RouteCommitment, [])).toThrow();
  });

  // 5. Ordinary RouteHop[] → cannot produce BrandedCommittedRoute
  //    (a) via a fake commitment (isRouteCommitment rejects),
  //    (b) via a GENUINE commitment but ordinary RouteHops as validatedHops
  //        (isValidatedHop rejects — R-006 construction-boundary fix).
  test("ordinary RouteHop[] → cannot produce BrandedCommittedRoute (fake commitment OR genuine commitment + ordinary hops)", () => {
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

    // (a) Attempt to create a BrandedCommittedRoute from a FAKE commitment
    const fakeCommitment = {
      routeId: "fake",
      proposal: {
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
    expect(isRouteCommitment(fakeCommitment)).toBe(false);
    expect(() => createBrandedCommittedRoute(fakeCommitment as RouteCommitment, [])).toThrow();

    // (b) R-006 construction-boundary: a GENUINE commitment + ordinary
    //     RouteHop[] (not genuine ValidatedHops) → REJECTED by
    //     isValidatedHop WeakSet check. This is the exact defect the
    //     unsafe `as unknown as ValidatedHop[]` cast previously masked.
    const { commitment: genuineCommitment } = makeGenuineCommitment(kp);
    const ordinaryHopsAsValidated = genuineCommitment.proposal.hops as unknown as ValidatedHop[];
    expect(() => createBrandedCommittedRoute(genuineCommitment, ordinaryHopsAsValidated)).toThrow(
      /not a genuine ValidatedHop|WeakSet membership check failed/i,
    );
  });

  // 6. Genuine full pipeline → succeeds
  test("genuine full pipeline: verifyAdvertisement → createAuthenticatedNodeRecord → createValidatedHop → createRouteCommitment → createBrandedCommittedRoute", () => {
    const kp = generateNodeKeypair();

    // Step 1: Verify advertisement → genuine VerifiedNodeAdvertisement
    const verifiedAdv = makeGenuineVerifiedAdv(kp);
    expect(isVerifiedNodeAdvertisement(verifiedAdv)).toBe(true);

    // Step 2: Create AuthenticatedNodeRecord from genuine proof artifact
    const authNode = createAuthenticatedNodeRecord(verifiedAdv);
    expect(isAuthenticatedNodeRecord(authNode)).toBe(true);

    // Step 3: Build the full genuine pipeline via the shared helper. R-002-P1
    // added AuthenticatedLink as the new step in the chain — createValidatedHop
    // now consumes a genuine AuthenticatedLink (3-message handshake artifact)
    // instead of a caller-supplied `linkUp: boolean`.
    const ctx = makeGenuineBrandedRouteHelper(1, NOW);
    expect(isAuthenticatedLink(ctx.authenticatedLinks[0])).toBe(true);

    // Step 4: Create ValidatedHop from the genuine AuthenticatedLink
    // (WeakSet-registered). The helper has already produced ctx.validatedHops[0]
    // by calling createValidatedHop(authenticatedLinks[0], ...) — re-assert the
    // construction-boundary invariant here.
    const hop = ctx.validatedHops[0];
    expect(isValidatedHop(hop)).toBe(true);
    expect(isValidatedHop(
      createValidatedHop(
        ctx.authenticatedLinks[0],
        ctx.hops[0]!.endpoint,
        ctx.capabilities[0] as string,
        ctx.validatedHops[0]!.serviceAgreementDigest,
        NOW,
      ),
    )).toBe(true);

    // Step 5: Create genuine RouteCommitment through the full pipeline
    expect(isRouteCommitment(ctx.commitment)).toBe(true);

    // Step 6: Create BrandedCommittedRoute from genuine commitment + genuine validatedHops
    // (R-006 construction-boundary: validatedHops passed explicitly — no cast)
    const branded = createBrandedCommittedRoute(ctx.commitment, ctx.validatedHops);
    expect(isBrandedCommittedRoute(branded)).toBe(true);

    // Step 7: A copy of the branded route is NOT recognized
    const copy = { ...branded };
    expect(isBrandedCommittedRoute(copy)).toBe(false);
  });
});
