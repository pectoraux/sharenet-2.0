/**
 * ShareNet 2.0 — R-008 hardening: setupCircuit trust boundary.
 *
 * Per the R-008 hardening requirement (closing the legacy bypass flagged
 * in the trust-boundary audit):
 *
 *   "R-008 is complete only when every circuit construction path requires
 *    a genuine BrandedCommittedRoute; there must be no legacy bypass."
 *
 * This file proves that `setupCircuit()` — the single-process circuit
 * construction path — rejects every non-genuine route representation and
 * accepts ONLY a genuine `BrandedCommittedRoute` produced by
 * `createBrandedCommittedRoute`.
 *
 * The five adversarial cases required by the audit:
 *   1. legacy `CommittedRoute` (from `createCommittedRoute`)   → REJECT
 *   2. plain object matching the shape                          → REJECT
 *   3. `RouteProposal`                                          → REJECT
 *   4. property-copy of a genuine branded route (`{ ...branded }`) → REJECT
 *   5. genuine branded route                                    → ACCEPT
 *
 * The rejection mechanism is the WeakSet membership check
 * (`isBrandedCommittedRoute`), which tracks OBJECT IDENTITY — not
 * property values. There is no forgeable token to copy.
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  randomBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  signRouteAcceptance,
  createRouteCommitment,
  createCommittedRoute,
  type RouteProposal,
  type RouteHop,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";
import {
  createBrandedCommittedRoute,
  isBrandedCommittedRoute,
} from "@reference/transport/validated-types";
import { setupCircuit } from "@reference/circuit/circuit";
import { x25519 } from "@noble/curves/ed25519.js";

const NOW = 1786876545;

/** Build a genuine RouteCommitment + BrandedCommittedRoute for one hop. */
function makeGenuineBrandedRoute() {
  const kp = generateNodeKeypair();
  const initiator = generateNodeKeypair();

  const hops: RouteHop[] = [
    { nodeId: kp.nodeId, capability: "MESH_RELAY", endpoint: "10.0.0.1:7788", linkUp: true },
  ];

  const proposal: RouteProposal = {
    routeId: bytesToHex(randomBytes(32)),
    hops,
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: NOW + 3600,
    initiatorNodeId: initiator.nodeId,
    agreementDigest: bytesToHex(randomBytes(32)),
  };

  const sa = new Map<number, ServiceAgreement>();
  sa.set(0, {
    nodeId: kp.nodeId, capability: "MESH_RELAY",
    requirementDigest: proposal.requirementDigest,
    allocatedBandwidthBps: 1048576, expiry: proposal.expiry, policyVersion: 1,
  });
  const hpk = new Map<string, Uint8Array>();
  hpk.set(kp.nodeId, kp.publicKey);

  const acc = [signRouteAcceptance(proposal, 0, hops[0]!, sa.get(0)!, kp.nodeId, kp.secretKey, proposal.expiry)];
  const result = createRouteCommitment(proposal, acc, hpk, sa, initiator.secretKey, NOW);
  if (!result.ok) throw new Error("commitment failed");
  const branded = createBrandedCommittedRoute(result.commitment);
  return { branded, commitment: result.commitment, proposal, kp, initiator };
}

/** Build a matching set of relay X25519 keys for a 1-hop branded route. */
function makeRelayKeys(nodeId: string) {
  const sk = randomBytes(32);
  const pk = x25519.getPublicKey(sk);
  return [{ hopIndex: 0, nodeId, x25519PublicKey: pk }];
}

describe("R-008 hardening: setupCircuit requires a genuine BrandedCommittedRoute (no legacy bypass)", () => {
  // 1. legacy CommittedRoute (from createCommittedRoute) → REJECT
  test("legacy CommittedRoute (createCommittedRoute output) → setupCircuit REJECTS", () => {
    const ctx = makeGenuineBrandedRoute();
    // createCommittedRoute returns a plain CommittedRoute — NOT branded.
    const legacy = createCommittedRoute(ctx.commitment);
    expect(isBrandedCommittedRoute(legacy)).toBe(false);
    const relayKeys = makeRelayKeys(ctx.kp.nodeId);
    expect(() => setupCircuit(legacy as any, relayKeys, NOW)).toThrow(
      /not a genuine BrandedCommittedRoute|WeakSet membership check failed/i,
    );
  });

  // 2. plain object matching the shape → REJECT
  test("plain object matching the BrandedCommittedRoute shape → setupCircuit REJECTS", () => {
    const ctx = makeGenuineBrandedRoute();
    const plainObject = {
      routeId: ctx.branded.routeId,
      hops: ctx.branded.hops,
      expiry: ctx.branded.expiry,
      initiatorNodeId: ctx.branded.initiatorNodeId,
      agreementDigest: ctx.branded.agreementDigest,
      committedAt: ctx.branded.committedAt,
    };
    expect(isBrandedCommittedRoute(plainObject)).toBe(false);
    const relayKeys = makeRelayKeys(ctx.kp.nodeId);
    expect(() => setupCircuit(plainObject as any, relayKeys, NOW)).toThrow(
      /not a genuine BrandedCommittedRoute|WeakSet membership check failed/i,
    );
  });

  // 3. RouteProposal → REJECT
  test("RouteProposal → setupCircuit REJECTS", () => {
    const ctx = makeGenuineBrandedRoute();
    expect(isBrandedCommittedRoute(ctx.proposal)).toBe(false);
    const relayKeys = makeRelayKeys(ctx.kp.nodeId);
    expect(() => setupCircuit(ctx.proposal as any, relayKeys, NOW)).toThrow(
      /not a genuine BrandedCommittedRoute|WeakSet membership check failed/i,
    );
  });

  // 4. property-copy of a genuine branded route → REJECT
  test("property-copy of a genuine branded route ({...branded}) → setupCircuit REJECTS", () => {
    const ctx = makeGenuineBrandedRoute();
    const copy = { ...ctx.branded };
    // The copy is NOT in the WeakSet — copying properties does not transfer identity.
    expect(isBrandedCommittedRoute(copy)).toBe(false);
    expect(isBrandedCommittedRoute(ctx.branded)).toBe(true);
    const relayKeys = makeRelayKeys(ctx.kp.nodeId);
    expect(() => setupCircuit(copy as any, relayKeys, NOW)).toThrow(
      /not a genuine BrandedCommittedRoute|WeakSet membership check failed/i,
    );
  });

  // 5. genuine branded route → ACCEPT
  test("genuine BrandedCommittedRoute → setupCircuit ACCEPTS (circuit established)", () => {
    const ctx = makeGenuineBrandedRoute();
    expect(isBrandedCommittedRoute(ctx.branded)).toBe(true);
    const relayKeys = makeRelayKeys(ctx.kp.nodeId);
    const circuit = setupCircuit(ctx.branded, relayKeys, NOW);
    expect(circuit.hops.length).toBe(1);
    expect(circuit.routeId).toBe(ctx.branded.routeId);
    expect(circuit.hops[0]!.forwardingKey.length).toBe(32);
    expect(circuit.hops[0]!.returnKey.length).toBe(32);
  });

  // 6. Exhaustive: NO non-genuine representation can reach circuit construction.
  test("exhaustive: every non-genuine route representation is rejected before key derivation", () => {
    const ctx = makeGenuineBrandedRoute();
    const relayKeys = makeRelayKeys(ctx.kp.nodeId);
    const nonGenuine: Array<{ label: string; route: any }> = [
      { label: "legacy CommittedRoute", route: createCommittedRoute(ctx.commitment) },
      { label: "plain object", route: { routeId: "x", hops: ctx.branded.hops, expiry: NOW + 3600 } },
      { label: "RouteProposal", route: ctx.proposal },
      { label: "branded copy", route: { ...ctx.branded } },
      { label: "JSON round-trip of branded", route: JSON.parse(JSON.stringify(ctx.branded)) },
    ];
    for (const { label, route } of nonGenuine) {
      expect(isBrandedCommittedRoute(route)).toBe(false);
      expect(() => setupCircuit(route, relayKeys, NOW)).toThrow(
        new RegExp("not a genuine BrandedCommittedRoute|WeakSet membership check failed", "i"),
      );
      // Suppress unused-label lint: label is for diagnostics.
      void label;
    }
  });
});
