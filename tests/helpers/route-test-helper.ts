/**
 * Shared test helpers for route objects (R-003 compatible API).
 */

import { generateNodeKeypair, randomBytes, bytesToHex, type NodeKeypair } from "@reference/identity/keys";
import {
  type RouteHop,
  type RouteProposal,
  signRouteAcceptance,
  createRouteCommitment,
  createCommittedRoute,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";

const REFERENCE_NOW = 1786876545;

export function makeRouteTestSetup(nodeIds: string[], kps: NodeKeypair[], initiator: NodeKeypair) {
  const hops: RouteHop[] = nodeIds.map((nodeId, i) => ({
    nodeId,
    capability: (i === nodeIds.length - 1 ? "INTERNET_GATEWAY" : "MESH_RELAY") as any,
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

  const serviceAgreements = new Map<number, ServiceAgreement>();
  const hopPublicKeys = new Map<string, Uint8Array>();
  for (let i = 0; i < nodeIds.length; i++) {
    const agreement: ServiceAgreement = {
      nodeId: nodeIds[i]!,
      capability: hops[i]!.capability as any,
      requirementDigest: proposal.requirementDigest,
      allocatedBandwidthBps: 1048576,
      expiry: proposal.expiry,
      policyVersion: 1,
    };
    serviceAgreements.set(i, agreement);
    hopPublicKeys.set(nodeIds[i]!, kps[i]!.publicKey);
  }

  const acceptances = nodeIds.map((nodeId, i) =>
    signRouteAcceptance(proposal, i, hops[i]!, serviceAgreements.get(i)!, nodeId, kps[i]!.secretKey, proposal.expiry),
  );

  const commitmentResult = createRouteCommitment(
    proposal, acceptances, hopPublicKeys, serviceAgreements, initiator.secretKey, REFERENCE_NOW,
  );
  if (!commitmentResult.ok) {
    throw new Error(`commitment failed: ${commitmentResult.reason}`);
  }

  return {
    route: createCommittedRoute(commitmentResult.commitment),
    proposal,
    hops,
    acceptances,
    serviceAgreements,
    hopPublicKeys,
    kps,
    initiator,
  };
}

export { REFERENCE_NOW };
