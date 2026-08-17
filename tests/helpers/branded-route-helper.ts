/**
 * ShareNet 2.0 — Shared test helper: genuine BrandedCommittedRoute pipeline.
 *
 * Per R-006 construction-boundary fix: createBrandedCommittedRoute now
 * requires a genuine ValidatedHop[] (no cast from RouteHop[]). This
 * helper builds the FULL genuine pipeline so every test that needs a
 * branded route can obtain one without duplicating the boilerplate:
 *
 *   generateNodeKeypair
 *       ↓
 *   signAdvertisement → verifyAdvertisement → VerifiedNodeAdvertisement (WeakSet)
 *       ↓
 *   createAuthenticatedNodeRecord → AuthenticatedNodeRecord (WeakSet)
 *       ↓
 *   createValidatedHop → ValidatedHop (WeakSet)
 *       ↓
 *   RouteProposal (RouteHop[] derived from the same fields)
 *       ↓
 *   signRouteAcceptance × N
 *       ↓
 *   createRouteCommitment → RouteCommitment (WeakSet)
 *       ↓
 *   createBrandedCommittedRoute(commitment, validatedHops) → BrandedCommittedRoute (WeakSet)
 */

import {
  generateNodeKeypair,
  randomBytes,
  bytesToHex,
  type NodeKeypair,
} from "@reference/identity/keys";
import {
  signAdvertisement,
  verifyAdvertisement,
} from "@reference/advertisement/advertisement";
import {
  type RouteHop,
  type RouteProposal,
  type RouteCommitment,
  signRouteAcceptance,
  createRouteCommitment,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";
import type { NodeCapability } from "@reference/identity/keys";
import { serviceDigest } from "@reference/routing/digests";
import { toHex } from "@reference/encoding/cbor";
import {
  createAuthenticatedNodeRecord,
  createValidatedHop,
  createBrandedCommittedRoute,
  type AuthenticatedNodeRecord,
  type ValidatedHop,
  type BrandedCommittedRoute,
} from "@reference/transport/validated-types";

export const BRANDED_ROUTE_HELPER_NOW = 1786876545;

export interface BrandedRouteContext {
  branded: BrandedCommittedRoute;
  commitment: RouteCommitment;
  proposal: RouteProposal;
  hops: RouteHop[];
  validatedHops: ValidatedHop[];
  authNodes: AuthenticatedNodeRecord[];
  kps: NodeKeypair[];
  initiator: NodeKeypair;
  hopPublicKeys: Map<string, Uint8Array>;
  serviceAgreements: Map<number, ServiceAgreement>;
  capabilities: NodeCapability[];
  now: number;
}

/**
 * Build a genuine BrandedCommittedRoute through the full proof-carrying
 * pipeline. Every hop is a genuine ValidatedHop (WeakSet-registered),
 * produced from a genuine AuthenticatedNodeRecord, produced from a
 * verified NodeAdvertisement.
 *
 * @param numHops  number of hops (last hop is INTERNET_GATEWAY, rest MESH_RELAY)
 * @param now      unix-seconds timestamp for the test
 */
export function makeGenuineBrandedRoute(
  numHops = 2,
  now = BRANDED_ROUTE_HELPER_NOW,
): BrandedRouteContext {
  const kps = Array.from({ length: numHops }, () => generateNodeKeypair());
  const initiator = generateNodeKeypair();

  const capabilities: NodeCapability[] = kps.map((_, i) =>
    i === kps.length - 1 ? "INTERNET_GATEWAY" : "MESH_RELAY",
  );

  const endpoints = kps.map((_, i) => `10.0.0.${i + 1}:7788`);

  // --- Per-hop: advertisement → verify → AuthenticatedNodeRecord ---
  const authNodes: AuthenticatedNodeRecord[] = [];
  for (let i = 0; i < kps.length; i++) {
    const kp = kps[i]!;
    const cap = capabilities[i]!;
    const adv = signAdvertisement({
      protocolVersion: 1,
      nodeId: kp.nodeId,
      signingPublicKey: kp.publicKey,
      capabilities: [cap],
      endpoints: [{ type: "tcp", address: `10.0.0.${i + 1}`, port: 7788 }],
      sequence: 1,
      timestamp: now,
      expiry: now + 3600,
      nonce: randomBytes(16),
    }, kp.secretKey);
    const v = verifyAdvertisement(adv, now);
    if (!v.ok) throw new Error(`advertisement verification failed for hop ${i}`);
    authNodes.push(createAuthenticatedNodeRecord(v.verified));
  }

  // --- Build the proposal hops (RouteHop[] for the proposal/acceptance) ---
  const hops: RouteHop[] = kps.map((kp, i) => ({
    nodeId: kp.nodeId,
    capability: capabilities[i]!,
    endpoint: endpoints[i]!,
    linkUp: true,
  }));

  const proposal: RouteProposal = {
    routeId: bytesToHex(randomBytes(32)),
    hops,
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: now + 3600,
    initiatorNodeId: initiator.nodeId,
    agreementDigest: bytesToHex(randomBytes(32)),
  };

  // --- Service agreements + public keys ---
  const serviceAgreements = new Map<number, ServiceAgreement>();
  const hopPublicKeys = new Map<string, Uint8Array>();
  for (let i = 0; i < kps.length; i++) {
    serviceAgreements.set(i, {
      nodeId: kps[i]!.nodeId,
      capability: capabilities[i]!,
      requirementDigest: proposal.requirementDigest,
      allocatedBandwidthBps: 1048576,
      expiry: proposal.expiry,
      policyVersion: 1,
    });
    hopPublicKeys.set(kps[i]!.nodeId, kps[i]!.publicKey);
  }

  // --- ValidatedHops (genuine, WeakSet-registered) ---
  // The serviceAgreementDigest carried in each ValidatedHop MUST match
  // the serviceDigest of the ServiceAgreement that the acceptance is
  // signed over — so the digests are consistent end-to-end.
  const validatedHops: ValidatedHop[] = [];
  for (let i = 0; i < kps.length; i++) {
    const saDigestHex = toHex(serviceDigest(serviceAgreements.get(i)!));
    validatedHops.push(
      createValidatedHop(
        authNodes[i]!,
        endpoints[i]!,
        capabilities[i]!,
        true,
        saDigestHex,
      ),
    );
  }

  // --- Acceptances + commitment ---
  const acceptances = kps.map((kp, i) =>
    signRouteAcceptance(
      proposal, i, hops[i]!,
      serviceAgreements.get(i)!,
      kp.nodeId, kp.secretKey, proposal.expiry,
    ),
  );

  const result = createRouteCommitment(
    proposal, acceptances, hopPublicKeys, serviceAgreements,
    initiator.secretKey, now,
  );
  if (!result.ok) throw new Error(`commitment failed: ${result.reason}`);

  // --- Branded route (genuine ValidatedHop[] passed explicitly — no cast) ---
  const branded = createBrandedCommittedRoute(result.commitment, validatedHops);

  return {
    branded,
    commitment: result.commitment,
    proposal,
    hops,
    validatedHops,
    authNodes,
    kps,
    initiator,
    hopPublicKeys,
    serviceAgreements,
    capabilities,
    now,
  };
}
