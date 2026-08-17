/**
 * ShareNet 2.0 — R-008 hardening: ACK freshness, replay, and forwarding lifecycle.
 *
 * Per the R-008 hardening requirement:
 *
 *   "Enforce ACK freshness using ackTimestamp, ackExpiry, clock skew, and
 *    a maximum ACK age/TTL."
 *
 * This file proves the four freshness bounds in `processCircuitSetupAck`:
 *   a) ackExpiry > now            (absolute deadline)
 *   b) ackExpiry > ackTimestamp   (sanity: deadline follows creation)
 *   c) ackTimestamp <= now+SKEW    (reject future-dated acks)
 *   d) now - ackTimestamp <= AGE   (reject acks consumed too late — TTL)
 *
 * Plus the forwarding-lifecycle state machine (R-008 hardening): legal
 * transitions are enforced; illegal transitions are rejected; terminal
 * states are recognized.
 *
 * The freshness checks fire BEFORE signature verification, so a mutated
 * ack is rejected on freshness grounds even though its signature no
 * longer matches — this is defense-in-depth: the attacker cannot extend
 * an ack's usable lifetime by mutating its timestamps because (1) the
 * freshness bounds reject the mutation and (2) the signature would
 * invalidate on a genuine re-sign attempt under a different timestamp.
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
  type RouteProposal,
  type RouteHop,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";
import { createBrandedCommittedRoute } from "@reference/transport/validated-types";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  handleCircuitSetup,
  processCircuitSetupAck,
  routeCommitmentDigest,
  transitionForwardingLifecycle,
  isTerminalForwardingLifecycle,
  ACK_MAX_AGE_SECONDS,
  ACK_MAX_CLOCK_SKEW_SECONDS,
  type CircuitSetupRequest,
  type CircuitSetupAck,
  type ForwardingLifecycle,
} from "@reference/circuit/distributed-setup";
import { deriveCircuitId } from "@reference/circuit/circuit";
import { toHex } from "@reference/encoding/cbor";

const NOW = 1786876545;

function setupRoute(numHops = 1) {
  const kps = Array.from({ length: numHops }, () => generateNodeKeypair());
  const initiator = generateNodeKeypair();
  const hops: RouteHop[] = kps.map((kp, i) => ({
    nodeId: kp.nodeId,
    capability: i === kps.length - 1 ? "INTERNET_GATEWAY" : "MESH_RELAY",
    endpoint: `10.0.0.${i + 1}:7788`,
    linkUp: true,
  }));
  const proposal: RouteProposal = {
    routeId: bytesToHex(randomBytes(32)), hops,
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: NOW + 3600, initiatorNodeId: initiator.nodeId,
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
  const branded = createBrandedCommittedRoute(result.commitment);
  return { kps, initiator, hops, proposal, branded, hpk };
}

/**
 * Produce a genuine, signed ack + the shared verification context for hop 0.
 *
 * `ackCreatedAt` controls the ack's `ackTimestamp` (and thus the signature's
 * time field). The ack is GENUINELY signed by the relay at that time, so the
 * signature verifies. This lets boundary/freshness-acceptance tests control
 * the ack's age without invalidating the signature (mutating `ackTimestamp`
 * post-hoc would invalidate the signature — which is itself a defense, but
 * not what the acceptance-boundary tests intend to exercise).
 */
function makeFreshAck(ackCreatedAt: number = NOW) {
  const ctx = setupRoute(1);
  const initSk = randomBytes(32);
  const initPk = x25519.getPublicKey(initSk);
  const circuitId = deriveCircuitId(ctx.branded.routeId, initPk);
  const req: CircuitSetupRequest = {
    route: ctx.branded, hopIndex: 0,
    initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
  };
  const relayResult = handleCircuitSetup(req, ctx.kps[0]!.secretKey, circuitId, ackCreatedAt);
  if (!relayResult.ok) throw new Error("relay setup failed");
  const commitDigestHex = toHex(routeCommitmentDigest(ctx.branded));
  return {
    ctx, initSk, initPk, circuitId,
    ack: relayResult.ack,
    commitDigestHex,
  };
}

describe("R-008 hardening: ACK freshness bounds in processCircuitSetupAck", () => {
  // a) expired: ackExpiry <= now → REJECT
  test("expired ack (ackExpiry <= now) → REJECT", () => {
    const f = makeFreshAck();
    const expiredAck: CircuitSetupAck = { ...f.ack, ackExpiry: NOW - 1 };
    const r = processCircuitSetupAck(
      expiredAck, f.ctx.branded.routeId, f.commitDigestHex, 0,
      f.initPk, f.ctx.kps[0]!.publicKey, f.initSk, f.circuitId, NOW,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("expired");
  });

  // b) malformed: ackExpiry <= ackTimestamp → REJECT
  test("malformed ack (ackExpiry <= ackTimestamp) → REJECT", () => {
    const f = makeFreshAck();
    // Dated slightly in the future so ackExpiry can be > now but < ackTimestamp.
    const futureTs = NOW + (ACK_MAX_CLOCK_SKEW_SECONDS + 10);
    const malformedAck: CircuitSetupAck = {
      ...f.ack, ackTimestamp: futureTs, ackExpiry: futureTs - 1,
    };
    const r = processCircuitSetupAck(
      malformedAck, f.ctx.branded.routeId, f.commitDigestHex, 0,
      f.initPk, f.ctx.kps[0]!.publicKey, f.initSk, f.circuitId, NOW,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("malformed");
  });

  // c) future-skewed: ackTimestamp > now + SKEW → REJECT
  test("future-skewed ack (ackTimestamp > now + SKEW) → REJECT", () => {
    const f = makeFreshAck();
    const skewedAck: CircuitSetupAck = {
      ...f.ack, ackTimestamp: NOW + (ACK_MAX_CLOCK_SKEW_SECONDS + 50),
    };
    const r = processCircuitSetupAck(
      skewedAck, f.ctx.branded.routeId, f.commitDigestHex, 0,
      f.initPk, f.ctx.kps[0]!.publicKey, f.initSk, f.circuitId, NOW,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("future-skewed");
  });

  // d) stale: now - ackTimestamp > AGE → REJECT (max ACK age / TTL)
  test("stale ack (age > ACK_MAX_AGE_SECONDS) → REJECT", () => {
    const f = makeFreshAck();
    const staleAck: CircuitSetupAck = {
      ...f.ack, ackTimestamp: NOW - (ACK_MAX_AGE_SECONDS + 10),
    };
    const r = processCircuitSetupAck(
      staleAck, f.ctx.branded.routeId, f.commitDigestHex, 0,
      f.initPk, f.ctx.kps[0]!.publicKey, f.initSk, f.circuitId, NOW,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("stale");
  });

  // Positive: a fresh ack (age 0, no skew, valid expiry) → ACCEPT
  test("fresh ack (age 0, no skew) → ACCEPT", () => {
    const f = makeFreshAck();
    // ackTimestamp === NOW, ackExpiry === NOW + 3600 → all freshness bounds pass.
    const r = processCircuitSetupAck(
      f.ack, f.ctx.branded.routeId, f.commitDigestHex, 0,
      f.initPk, f.ctx.kps[0]!.publicKey, f.initSk, f.circuitId, NOW,
    );
    expect(r.ok).toBe(true);
  });

  // Boundary: ack exactly at ACK_MAX_AGE_SECONDS old → ACCEPT (<= bound)
  // Uses a genuinely-signed ack created ACK_MAX_AGE_SECONDS in the past so
  // the signature still verifies (mutating the timestamp post-hoc would
  // invalidate the signature — a separate defense tested by the reject cases).
  test("boundary: ack exactly at ACK_MAX_AGE_SECONDS old → ACCEPT (<= bound)", () => {
    const f = makeFreshAck(NOW - ACK_MAX_AGE_SECONDS);
    // ackTimestamp === NOW - ACK_MAX_AGE_SECONDS, ackExpiry === ackTimestamp + 3600.
    // age === ACK_MAX_AGE_SECONDS → `now - ackTimestamp > AGE` is false → accept.
    const r = processCircuitSetupAck(
      f.ack, f.ctx.branded.routeId, f.commitDigestHex, 0,
      f.initPk, f.ctx.kps[0]!.publicKey, f.initSk, f.circuitId, NOW,
    );
    expect(r.ok).toBe(true);
  });

  // Boundary: ack exactly at SKEW in the future → ACCEPT (<= bound)
  // Uses a genuinely-signed ack created SKEW seconds in the future.
  test("boundary: ack exactly at SKEW in the future → ACCEPT (<= bound)", () => {
    const f = makeFreshAck(NOW + ACK_MAX_CLOCK_SKEW_SECONDS);
    // ackTimestamp === NOW + SKEW → `ackTimestamp > now + SKEW` is false → accept.
    const r = processCircuitSetupAck(
      f.ack, f.ctx.branded.routeId, f.commitDigestHex, 0,
      f.initPk, f.ctx.kps[0]!.publicKey, f.initSk, f.circuitId, NOW,
    );
    expect(r.ok).toBe(true);
  });

  // Replay defense: an ack captured for circuit A cannot be replayed for a
  // different circuit (different routeCommitmentDigest) — rejected before
  // freshness even matters.
  test("ack replay across circuits: different routeCommitmentDigest → REJECT", () => {
    const f1 = makeFreshAck();
    const f2 = makeFreshAck(); // different route
    // Try to use ack1's data in circuit 2's context.
    const r = processCircuitSetupAck(
      f1.ack, f2.ctx.branded.routeId, f2.commitDigestHex, 0,
      f2.initPk, f1.ctx.kps[0]!.publicKey, f2.initSk, f2.circuitId, NOW,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      // Either routeId mismatch (if routeIds differ) or digest mismatch.
      expect(r.reason).toMatch(/routeId mismatch|routeCommitmentDigest mismatch/);
    }
  });

  // The freshness constants are published and frozen.
  test("frozen freshness constants are published", () => {
    expect(ACK_MAX_AGE_SECONDS).toBeGreaterThan(0);
    expect(ACK_MAX_CLOCK_SKEW_SECONDS).toBeGreaterThan(0);
    expect(ACK_MAX_AGE_SECONDS).toBeLessThan(3600); // tighter than the 1h absolute expiry
  });
});

describe("R-008 hardening: forwarding lifecycle state machine", () => {
  const legal: Array<{ from: ForwardingLifecycle; to: ForwardingLifecycle }> = [
    { from: "INSTALLED", to: "ACTIVE" },
    { from: "INSTALLED", to: "EXPIRED" },
    { from: "INSTALLED", to: "CLOSED" },
    { from: "ACTIVE", to: "EXPIRED" },
    { from: "ACTIVE", to: "CLOSED" },
  ];
  const illegal: Array<{ from: ForwardingLifecycle; to: ForwardingLifecycle }> = [
    { from: "EXPIRED", to: "ACTIVE" },   // terminal → cannot re-activate
    { from: "CLOSED", to: "ACTIVE" },    // terminal → cannot re-activate
    { from: "EXPIRED", to: "CLOSED" },
    { from: "CLOSED", to: "EXPIRED" },
    { from: "ACTIVE", to: "INSTALLED" }, // cannot regress
  ];

  for (const { from, to } of legal) {
    test(`legal transition ${from} → ${to} → ACCEPT`, () => {
      const r = transitionForwardingLifecycle(from, to);
      expect(r.ok).toBe(true);
    });
  }
  for (const { from, to } of illegal) {
    test(`illegal transition ${from} → ${to} → REJECT`, () => {
      const r = transitionForwardingLifecycle(from, to);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toContain("illegal");
    });
  }

  test("terminal forwarding states are recognized", () => {
    expect(isTerminalForwardingLifecycle("EXPIRED")).toBe(true);
    expect(isTerminalForwardingLifecycle("CLOSED")).toBe(true);
    expect(isTerminalForwardingLifecycle("INSTALLED")).toBe(false);
    expect(isTerminalForwardingLifecycle("ACTIVE")).toBe(false);
  });

  test("relay installs forwarding state as INSTALLED (not ACTIVE)", () => {
    const f = makeFreshAck();
    // handleCircuitSetup already ran in makeFreshAck; re-run to inspect state.
    const req: CircuitSetupRequest = {
      route: f.ctx.branded, hopIndex: 0,
      initiatorX25519PublicKey: f.initPk, setupNonce: randomBytes(16),
    };
    const relayResult = handleCircuitSetup(req, f.ctx.kps[0]!.secretKey, f.circuitId, NOW);
    expect(relayResult.ok).toBe(true);
    if (!relayResult.ok) return;
    expect(relayResult.state.lifecycle).toBe("INSTALLED");
    expect(isTerminalForwardingLifecycle(relayResult.state.lifecycle)).toBe(false);
  });
});
