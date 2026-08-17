/**
 * ShareNet 2.0 — R-003/R-004: Independent verifyRouteCommitment() tests.
 *
 * Per the R-003/R-004 final reconciliation:
 *
 *   "Add an independent verifyRouteCommitment() path. It must verify from
 *    the serialized commitment and source public key alone. It must not
 *    depend on WeakSet membership."
 *
 * Adversarial tests:
 *   - proposal mutation (hops changed) → reject
 *   - commitment root mutation → reject
 *   - nonce mutation → reject
 *   - acceptance mutation → reject
 *   - route_id mutation → reject
 *   - source signature mutation → reject
 *   - independently decoded commitment (JSON round-trip) → verify succeeds
 *   - genuine commitment → verify succeeds
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
  verifyRouteCommitment,
  computeCommitmentRoot,
  deriveRouteId,
  type RouteCommitment,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";

const NOW = 1786876545;

function makeGenuineCommitment() {
  const kps = [generateNodeKeypair(), generateNodeKeypair()];
  const initiator = generateNodeKeypair();
  const hops: RouteHop[] = kps.map((kp, i) => ({
    nodeId: kp.nodeId,
    capability: i === kps.length - 1 ? "INTERNET_GATEWAY" : "MESH_RELAY",
    endpoint: `10.0.0.${i + 1}:7788`,
    linkUp: true,
  }));
  const proposal: RouteProposal = {
    hops,
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: NOW + 3600,
    initiatorNodeId: initiator.nodeId,
    agreementDigest: bytesToHex(randomBytes(32)),
  };
  const sa = new Map<number, ServiceAgreement>();
  const hpk = new Map<string, Uint8Array>();
  for (let i = 0; i < kps.length; i++) {
    sa.set(i, {
      nodeId: kps[i]!.nodeId, capability: hops[i]!.capability as any,
      requirementDigest: proposal.requirementDigest,
      allocatedBandwidthBps: 1048576, expiry: proposal.expiry, policyVersion: 1,
    });
    hpk.set(kps[i]!.nodeId, kps[i]!.publicKey);
  }
  const acc = kps.map((kp, i) =>
    signRouteAcceptance(proposal, i, hops[i]!, sa.get(i)!, kp.nodeId, kp.secretKey, proposal.expiry),
  );
  const result = createRouteCommitment(proposal, acc, hpk, sa, initiator.secretKey, NOW);
  if (!result.ok) throw new Error("commitment failed");
  return { commitment: result.commitment, initiator, kps, hops, proposal, sa, hpk };
}

describe("R-003/R-004: Independent verifyRouteCommitment() (no WeakSet)", () => {
  test("genuine commitment → verify succeeds (no WeakSet dependency)", () => {
    const ctx = makeGenuineCommitment();
    const result = verifyRouteCommitment(
      ctx.commitment, ctx.initiator.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(true);
  });

  test("independently decoded commitment (JSON round-trip) → verify succeeds", () => {
    const ctx = makeGenuineCommitment();
    // Simulate crossing a process boundary: serialize → deserialize
    // The byte arrays are converted to hex for JSON, then back
    const serialized = JSON.stringify({
      routeId: ctx.commitment.routeId,
      proposal: ctx.commitment.proposal,
      acceptances: ctx.commitment.acceptances.map(a => ({
        ...a,
        acceptanceNonce: bytesToHex(a.acceptanceNonce),
        signature: bytesToHex(a.signature),
      })),
      commitmentRoot: bytesToHex(ctx.commitment.commitmentRoot),
      commitmentNonce: bytesToHex(ctx.commitment.commitmentNonce),
      committerSignature: bytesToHex(ctx.commitment.committerSignature),
      committedAt: ctx.commitment.committedAt,
    });
    const decoded = JSON.parse(serialized);
    // Reconstruct the commitment object (NOT in any WeakSet)
    const decodedCommitment: RouteCommitment = {
      routeId: decoded.routeId,
      proposal: decoded.proposal,
      acceptances: decoded.acceptances.map((a: any) => ({
        ...a,
        acceptanceNonce: new Uint8Array(a.acceptanceNonce.match(/.{2}/g).map((h: string) => parseInt(h, 16))),
        signature: new Uint8Array(a.signature.match(/.{2}/g).map((h: string) => parseInt(h, 16))),
      })),
      commitmentRoot: new Uint8Array(decoded.commitmentRoot.match(/.{2}/g).map((h: string) => parseInt(h, 16))),
      commitmentNonce: new Uint8Array(decoded.commitmentNonce.match(/.{2}/g).map((h: string) => parseInt(h, 16))),
      committerSignature: new Uint8Array(decoded.committerSignature.match(/.{2}/g).map((h: string) => parseInt(h, 16))),
      committedAt: decoded.committedAt,
    };
    // verifyRouteCommitment does NOT use WeakSet — it re-derives everything
    const result = verifyRouteCommitment(
      decodedCommitment, ctx.initiator.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(true);
  });

  test("proposal mutation (hops changed) → reject (commitment_root mismatch)", () => {
    const ctx = makeGenuineCommitment();
    // Mutate the proposal: change a hop's nodeId
    // We can't mutate the frozen commitment, so create a shallow copy with a mutated proposal
    const tamperedCommitment = {
      ...ctx.commitment,
      proposal: {
        ...ctx.commitment.proposal,
        hops: ctx.commitment.proposal.hops.map((h, i) =>
          i === 0 ? { ...h, nodeId: "attacker-node" } : h,
        ),
      },
    } as RouteCommitment;
    const result = verifyRouteCommitment(
      tamperedCommitment, ctx.initiator.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("commitment_root mismatch");
  });

  test("commitment root mutation → reject (recomputed root != carried root)", () => {
    const ctx = makeGenuineCommitment();
    const tamperedRoot = new Uint8Array(ctx.commitment.commitmentRoot);
    tamperedRoot[0] ^= 0x01;
    const tamperedCommitment = {
      ...ctx.commitment,
      commitmentRoot: tamperedRoot,
    } as RouteCommitment;
    const result = verifyRouteCommitment(
      tamperedCommitment, ctx.initiator.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("commitment_root mismatch");
  });

  test("commitment nonce mutation → reject (signature invalid)", () => {
    const ctx = makeGenuineCommitment();
    const tamperedNonce = new Uint8Array(ctx.commitment.commitmentNonce);
    tamperedNonce[0] ^= 0x01;
    const tamperedCommitment = {
      ...ctx.commitment,
      commitmentNonce: tamperedNonce,
    } as RouteCommitment;
    const result = verifyRouteCommitment(
      tamperedCommitment, ctx.initiator.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("acceptance mutation (signature changed) → reject", () => {
    const ctx = makeGenuineCommitment();
    const tamperedSig = new Uint8Array(ctx.commitment.acceptances[0]!.signature);
    tamperedSig[0] ^= 0x01;
    const tamperedAcceptances = ctx.commitment.acceptances.map((a, i) =>
      i === 0 ? { ...a, signature: tamperedSig } : a,
    );
    const tamperedCommitment = {
      ...ctx.commitment,
      acceptances: tamperedAcceptances as any,
    } as RouteCommitment;
    const result = verifyRouteCommitment(
      tamperedCommitment, ctx.initiator.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // Could be either commitment_root mismatch (acceptance leaf changed)
      // or acceptance signature invalid
      expect(result.reason).toMatch(/commitment_root mismatch|signature invalid/);
    }
  });

  test("route_id mutation → reject (route_id != 'route:' + hex(root))", () => {
    const ctx = makeGenuineCommitment();
    const tamperedCommitment = {
      ...ctx.commitment,
      routeId: "route:forged-route-id-that-doesnt-match-the-root",
    } as RouteCommitment;
    const result = verifyRouteCommitment(
      tamperedCommitment, ctx.initiator.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("route_id mismatch");
  });

  test("source signature mutation → reject", () => {
    const ctx = makeGenuineCommitment();
    const tamperedSig = new Uint8Array(ctx.commitment.committerSignature);
    tamperedSig[0] ^= 0x01;
    const tamperedCommitment = {
      ...ctx.commitment,
      committerSignature: tamperedSig,
    } as RouteCommitment;
    const result = verifyRouteCommitment(
      tamperedCommitment, ctx.initiator.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("wrong source public key → reject", () => {
    const ctx = makeGenuineCommitment();
    const stranger = generateNodeKeypair();
    const result = verifyRouteCommitment(
      ctx.commitment, stranger.publicKey, ctx.hpk, ctx.sa, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });
});
