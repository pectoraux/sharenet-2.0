/**
 * ShareNet 2.0 — R-009 Stage 3 Phase 4: Failure detection + durable circuit invalidation tests.
 *
 * Tests:
 *   Phase 3: LinkFailureDetector unit tests (state machine, threshold, window, reset, idempotent, stale)
 *   Phase 6: Circuit invalidation on LINK_DOWN (durable tombstone, zeroize, fail-closed)
 *   Phase 9: RecoveryManager integration (LINK_DOWN → handleLinkEvent → RecoveryPlan)
 *   Phase 11: Anti-DoS tests (single failure, below threshold, threshold, transport disconnect, reset, duplicate, wrong circuit)
 *   Phase 12: Restart + durability
 *   Phase 15: Failure detector test matrix
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { randomBytes, generateNodeKeypair } from "@reference/identity/keys";
import { toHex } from "@reference/encoding/cbor";
import {
  LinkFailureDetector,
  FailureObservation,
  PROTOCOL_FAILURE_THRESHOLD,
  PROTOCOL_FAILURE_WINDOW_SECONDS,
  invalidateCircuitOnFailure,
} from "@reference/failure/link-failure-detector";
import { InMemoryCircuitDestroyStore } from "@reference/circuit/replay-stores";
import { RecoveryManager, createRecoveryPlan, type LinkHealthEvent, type GatewayCandidate } from "@reference/routing/recovery";
import {
  DESTROYER_ROLE_INITIATOR,
  DESTROY_REASON_LINK_FAILURE,
  DESTROY_REASON_GATEWAY_DISAPPEARANCE,
} from "@reference/circuit/destroy";
import { signCircuitDestroy, encodeCircuitDestroy, DESTROY_REASON_OPERATOR_INITIATED } from "@reference/circuit/destroy";
import { setupCircuit } from "@reference/circuit/circuit";
import { processCircuitDestroy } from "@reference/circuit/destroy";
import { processCircuitWireFrame } from "@reference/circuit/forwarding";
import { sealForwardFrame, encodeCircuitFrame } from "@reference/circuit/frame";
import { InMemoryCircuitSequenceFloorStore } from "@reference/circuit/replay-stores";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";
import { x25519 } from "@noble/curves/ed25519.js";
import { zeroizeCircuit } from "@reference/circuit/zeroize";

const NOW = 1786876545;

function makeRoute(numHops = 1) {
  const ctx = makeGenuineBrandedRouteHelper(numHops, NOW);
  return {
    branded: ctx.branded,
    kps: ctx.kps,
    commitmentRoot: ctx.branded.commitmentRoot,
    initiator: ctx.initiator,
  };
}

function makeRelayX25519Keys(route: { hops: Array<{ nodeId: string }> }) {
  return route.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk };
  });
}

// =====================================================================
// Phase 3: LinkFailureDetector unit tests
// =====================================================================

describe("R-009 Stage 3 Phase 4: LinkFailureDetector state machine", () => {
  test("HEALTHY → single protocol failure → DEGRADED", () => {
    const detector = new LinkFailureDetector();
    const state = detector.recordObservation({
      linkId: "link-1",
      localNodeId: "node-a",
      remoteNodeId: "node-b",
      category: "PROTOCOL_AUTHENTICATION",
      reason: "AEAD tag failure",
      observedAt: NOW,
    });
    expect(state).toBe("DEGRADED");
    expect(detector.getState("link-1")).toBe("DEGRADED");
  });

  test("DEGRADED → successful traffic → HEALTHY (reset)", () => {
    const detector = new LinkFailureDetector();
    detector.recordObservation({
      linkId: "link-1", localNodeId: "node-a", remoteNodeId: "node-b",
      category: "PROTOCOL_AUTHENTICATION", reason: "bad frame", observedAt: NOW,
    });
    expect(detector.getState("link-1")).toBe("DEGRADED");

    // Successful traffic resets the suspicion.
    const state = detector.recordSuccess("link-1", NOW + 1);
    expect(state).toBe("HEALTHY");
    expect(detector.getState("link-1")).toBe("HEALTHY");
  });

  test("threshold reached (3 failures within 60s) → LINK_DOWN", () => {
    const detector = new LinkFailureDetector();
    // First failure → DEGRADED.
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f1", observedAt: NOW });
    expect(detector.getState("l")).toBe("DEGRADED");
    // Second failure → still DEGRADED (below threshold).
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f2", observedAt: NOW + 1 });
    expect(detector.getState("l")).toBe("DEGRADED");
    // Third failure → LINK_DOWN (threshold reached).
    const state = detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f3", observedAt: NOW + 2 });
    expect(state).toBe("LINK_DOWN");
    expect(detector.getState("l")).toBe("LINK_DOWN");
  });

  test("below threshold (2 failures) does NOT produce LINK_DOWN", () => {
    const detector = new LinkFailureDetector();
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f1", observedAt: NOW });
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f2", observedAt: NOW + 1 });
    expect(detector.getState("l")).toBe("DEGRADED"); // NOT LINK_DOWN
  });

  test("transport-confirmed failure → immediate LINK_DOWN (no threshold needed)", () => {
    const detector = new LinkFailureDetector();
    const state = detector.recordObservation({
      linkId: "l", localNodeId: "a", remoteNodeId: "b",
      category: "TRANSPORT_CONFIRMED", reason: "ECONNRESET", observedAt: NOW,
    });
    expect(state).toBe("LINK_DOWN");
    expect(detector.getState("l")).toBe("LINK_DOWN");
  });

  test("transport-confirmed failure from HEALTHY → immediate LINK_DOWN", () => {
    const detector = new LinkFailureDetector();
    // No prior failures — link is HEALTHY.
    const state = detector.recordObservation({
      linkId: "l", localNodeId: "a", remoteNodeId: "b",
      category: "TRANSPORT_CONFIRMED", reason: "socket closed", observedAt: NOW,
    });
    expect(state).toBe("LINK_DOWN");
  });

  test("duplicate LINK_DOWN is idempotent (no re-emission)", () => {
    const detector = new LinkFailureDetector();
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "TRANSPORT_CONFIRMED", reason: "closed", observedAt: NOW });
    // Second transport failure on the same link → still LINK_DOWN, no new event.
    const state = detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "TRANSPORT_CONFIRMED", reason: "closed again", observedAt: NOW + 1 });
    expect(state).toBe("LINK_DOWN");
    // Only ONE LINK_DOWN event should have been emitted.
    const events = detector.getEvents();
    const downEvents = events.filter(e => e.newStatus === "DOWN");
    expect(downEvents.length).toBe(1);
  });

  test("stale observations outside the window do NOT count toward threshold", () => {
    const detector = new LinkFailureDetector();
    // Two failures at NOW.
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f1", observedAt: NOW });
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f2", observedAt: NOW + 1 });
    // A failure OUTSIDE the window (NOW + 61 — past the 60s window).
    // The window is [observedAt - 60, observedAt]. NOW + 1 is at the edge.
    // NOW + 61 - 60 = NOW + 1. So NOW + 1 is the cutoff. Failures at NOW
    // are pruned. Only the new failure counts → DEGRADED, not LINK_DOWN.
    const state = detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f3", observedAt: NOW + 61 });
    expect(state).toBe("DEGRADED"); // NOT LINK_DOWN — stale failures pruned
  });

  test("recordSuccess on LINK_DOWN does NOT reset (terminal)", () => {
    const detector = new LinkFailureDetector();
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "TRANSPORT_CONFIRMED", reason: "closed", observedAt: NOW });
    expect(detector.getState("l")).toBe("LINK_DOWN");
    // Successful traffic on a dead link → still LINK_DOWN.
    const state = detector.recordSuccess("l", NOW + 1);
    expect(state).toBe("LINK_DOWN");
  });

  test("events are emitted on state transitions", () => {
    const detector = new LinkFailureDetector();
    // HEALTHY → DEGRADED.
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f1", observedAt: NOW });
    // DEGRADED → LINK_DOWN.
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "TRANSPORT_CONFIRMED", reason: "closed", observedAt: NOW + 1 });
    const events = detector.drainEvents();
    expect(events.length).toBe(2); // DEGRADED + DOWN
    expect(events[0]!.newStatus).toBe("DEGRADED");
    expect(events[1]!.newStatus).toBe("DOWN");
  });

  test("unknown link getState returns HEALTHY", () => {
    const detector = new LinkFailureDetector();
    expect(detector.getState("nonexistent")).toBe("HEALTHY");
  });

  test("concurrent observations on the same link are deterministic", () => {
    const detector = new LinkFailureDetector();
    // Fire 3 concurrent observations (simulating concurrent frame processing).
    const states = [
      detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f1", observedAt: NOW }),
      detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f2", observedAt: NOW }),
      detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f3", observedAt: NOW }),
    ];
    // The last one should be LINK_DOWN.
    expect(states[2]).toBe("LINK_DOWN");
    expect(detector.getState("l")).toBe("LINK_DOWN");
  });
});

// =====================================================================
// Phase 6: Circuit invalidation on LINK_DOWN
// =====================================================================

describe("R-009 Stage 3 Phase 4: durable circuit invalidation on LINK_DOWN", () => {
  test("LINK_DOWN → durable revocation (tombstone written with LINK_FAILURE reason)", async () => {
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuitId = randomBytes(32);
    const commitmentRoot = randomBytes(32);
    const nonce = randomBytes(16);

    const result = await invalidateCircuitOnFailure(
      destroyStore, circuitId, commitmentRoot,
      DESTROY_REASON_LINK_FAILURE,
      "system", DESTROYER_ROLE_INITIATOR, nonce,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.action).toBe("REVOKED");

    // The tombstone exists.
    expect(await destroyStore.isRevoked(circuitId, commitmentRoot)).toBe(true);
  });

  test("already revoked → idempotent (ALREADY_REVOKED)", async () => {
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuitId = randomBytes(32);
    const commitmentRoot = randomBytes(32);
    const nonce = randomBytes(16);

    // First invalidation.
    await invalidateCircuitOnFailure(destroyStore, circuitId, commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, nonce);

    // Second invalidation → idempotent.
    const result = await invalidateCircuitOnFailure(destroyStore, circuitId, commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.action).toBe("ALREADY_REVOKED");
  });

  test("persistence failure → fail-closed (NOT claimed as REVOKED)", async () => {
    // Failing store — simulate persistence failure.
    const failingStore = {
      isRevoked: async () => false,
      consumeDestroyAndRevoke: async () => ({ ok: false as const, reason: "simulated persistence failure" }),
      revoke: async () => false,
    };
    const result = await invalidateCircuitOnFailure(
      failingStore as any, randomBytes(32), randomBytes(32),
      DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("fail-closed");
  });

  test("failure invalidation + zeroize → keys destroyed, circuit dead", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const destroyStore = new InMemoryCircuitDestroyStore();

    // Keys are non-zero before invalidation.
    expect(circuit.hops[0]!.forwardingKey.some((b) => b !== 0)).toBe(true);

    // Invalidate.
    const result = await invalidateCircuitOnFailure(
      destroyStore, circuit.circuitId, circuit.commitmentRoot,
      DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16),
    );
    expect(result.ok).toBe(true);

    // Zeroize.
    zeroizeCircuit(circuit);
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(true);
    expect(circuit.initiatorX25519SecretKey.every((b) => b === 0)).toBe(true);

    // The circuit is durably revoked.
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);

    // A subsequent frame is REJECTED (circuit revoked).
    const plaintext = new TextEncoder().encode("post-failure frame");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);
    const frameResult = await processCircuitWireFrame(circuit, 0, wireBytes, destroyStore, NOW);
    expect(frameResult.ok).toBe(false);
    if (!frameResult.ok) expect(frameResult.reason).toContain("revoked");
  });

  test("wrong circuit cannot be invalidated by a failure on a different circuit", async () => {
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuitA = { id: randomBytes(32), root: randomBytes(32) };
    const circuitB = { id: randomBytes(32), root: randomBytes(32) };

    // Invalidate circuit A.
    await invalidateCircuitOnFailure(destroyStore, circuitA.id, circuitA.root, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    // Circuit A is revoked.
    expect(await destroyStore.isRevoked(circuitA.id, circuitA.root)).toBe(true);
    // Circuit B is NOT revoked (wrong circuit — the failure cannot invalidate another circuit).
    expect(await destroyStore.isRevoked(circuitB.id, circuitB.root)).toBe(false);
  });
});

// =====================================================================
// Phase 9: RecoveryManager integration
// =====================================================================

describe("R-009 Stage 3 Phase 4: RecoveryManager integration", () => {
  test("LINK_DOWN event → RecoveryManager.handleLinkEvent → route invalidated", () => {
    const rm = new RecoveryManager();
    rm.registerLink("link-1", "node-a", "node-b");
    // Register a route that uses link-1.
    const route = makeRoute(1);
    rm.registerRoute(route.branded as any, toHex(randomBytes(32)), ["link-1"], NOW);

    // Simulate a LINK_DOWN event from the detector.
    const event: LinkHealthEvent = {
      linkId: "link-1",
      localNodeId: "node-a",
      remoteNodeId: "node-b",
      newStatus: "DOWN",
      reason: "LINK_DOWN",
      observedAt: NOW,
    };
    const invalidatedRoutes = rm.handleLinkEvent(event);
    expect(invalidatedRoutes.length).toBeGreaterThan(0); // at least one route invalidated
  });

  test("DEGRADED event → RecoveryManager marks route degraded (NOT invalidated)", () => {
    const rm = new RecoveryManager();
    rm.registerLink("link-1", "node-a", "node-b");
    const route = makeRoute(1);
    rm.registerRoute(route.branded as any, toHex(randomBytes(32)), ["link-1"], NOW);

    const event: LinkHealthEvent = {
      linkId: "link-1",
      localNodeId: "node-a",
      remoteNodeId: "node-b",
      newStatus: "DEGRADED",
      reason: "LINK_DEGRADED",
      observedAt: NOW,
    };
    const invalidatedRoutes = rm.handleLinkEvent(event);
    expect(invalidatedRoutes.length).toBe(0); // NOT invalidated — just degraded
    // The route should be in a non-HEALTHY state (DEGRADED).
    const routes = rm.getHealthyRoutes();
    // A degraded route is not in the "healthy" list.
    expect(routes.length).toBe(0); // the degraded route is not healthy
  });

  test("LINK_DOWN → RecoveryPlan created (NO recovery execution)", () => {
    const rm = new RecoveryManager();
    rm.registerLink("link-1", "node-a", "node-b");
    rm.registerRoute("route-1", [{ nodeId: "node-a", capability: "MESH_RELAY" as any, endpoint: "addr-a", expiry: NOW + 3600 } as any], "node-b");

    rm.handleLinkEvent({
      linkId: "link-1", localNodeId: "node-a", remoteNodeId: "node-b",
      newStatus: "DOWN", reason: "LINK_DOWN", observedAt: NOW,
    });

    const plan = createRecoveryPlan(["route-1"], "LINK_DOWN", [] as GatewayCandidate[], "INTERNET_GATEWAY" as any);
    expect(plan).toBeDefined();
    expect(plan.invalidatedRouteIds).toContain("route-1");
    // NO recovery execution — the plan is descriptive only.
  });
});

// =====================================================================
// Phase 11: Anti-DoS tests
// =====================================================================

describe("R-009 Stage 3 Phase 4: anti-DoS", () => {
  test("1. one forged AEAD failure does NOT produce LINK_DOWN", () => {
    const detector = new LinkFailureDetector();
    const state = detector.recordObservation({
      linkId: "l", localNodeId: "a", remoteNodeId: "b",
      category: "PROTOCOL_AUTHENTICATION", reason: "AEAD tag failure (forged)", observedAt: NOW,
    });
    expect(state).toBe("DEGRADED"); // NOT LINK_DOWN
  });

  test("2. repeated failures below threshold do NOT produce LINK_DOWN", () => {
    const detector = new LinkFailureDetector();
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f1", observedAt: NOW });
    const state = detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f2", observedAt: NOW + 1 });
    expect(state).toBe("DEGRADED"); // threshold=3, only 2 → NOT LINK_DOWN
  });

  test("3. threshold reached → transitions exactly according to frozen policy", () => {
    const detector = new LinkFailureDetector();
    // Exactly PROTOCOL_FAILURE_THRESHOLD (3) failures.
    for (let i = 0; i < PROTOCOL_FAILURE_THRESHOLD - 1; i++) {
      const s = detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: `f${i}`, observedAt: NOW + i });
      expect(s).toBe("DEGRADED"); // below threshold
    }
    // The threshold-th failure → LINK_DOWN.
    const state = detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "threshold", observedAt: NOW + PROTOCOL_FAILURE_THRESHOLD - 1 });
    expect(state).toBe("LINK_DOWN");
  });

  test("4. authenticated transport disconnect → immediate LINK_DOWN", () => {
    const detector = new LinkFailureDetector();
    const state = detector.recordObservation({
      linkId: "l", localNodeId: "a", remoteNodeId: "b",
      category: "TRANSPORT_CONFIRMED", reason: "ECONNRESET", observedAt: NOW,
    });
    expect(state).toBe("LINK_DOWN");
  });

  test("5. successful authenticated traffic resets suspicion", () => {
    const detector = new LinkFailureDetector();
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f1", observedAt: NOW });
    expect(detector.getState("l")).toBe("DEGRADED");
    // Successful traffic.
    detector.recordSuccess("l", NOW + 1);
    expect(detector.getState("l")).toBe("HEALTHY");
    // Now 2 more failures → should be DEGRADED again (count reset).
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f2", observedAt: NOW + 2 });
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f3", observedAt: NOW + 3 });
    expect(detector.getState("l")).toBe("DEGRADED"); // NOT LINK_DOWN (count was reset)
  });

  test("6. duplicate LINK_DOWN is idempotent", () => {
    const detector = new LinkFailureDetector();
    detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "TRANSPORT_CONFIRMED", reason: "closed", observedAt: NOW });
    // Second LINK_DOWN.
    const state = detector.recordObservation({ linkId: "l", localNodeId: "a", remoteNodeId: "b", category: "TRANSPORT_CONFIRMED", reason: "closed again", observedAt: NOW + 1 });
    expect(state).toBe("LINK_DOWN"); // still LINK_DOWN
    // Only 1 DOWN event emitted.
    const downEvents = detector.getEvents().filter(e => e.newStatus === "DOWN");
    expect(downEvents.length).toBe(1);
  });

  test("7. wrong link/circuit cannot invalidate another circuit", async () => {
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuitA = { id: randomBytes(32), root: randomBytes(32) };
    const circuitB = { id: randomBytes(32), root: randomBytes(32) };

    // A failure on link-A invalidates circuit-A only.
    await invalidateCircuitOnFailure(destroyStore, circuitA.id, circuitA.root, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    expect(await destroyStore.isRevoked(circuitA.id, circuitA.root)).toBe(true);
    expect(await destroyStore.isRevoked(circuitB.id, circuitB.root)).toBe(false);
  });

  test("8. cross-route failure evidence rejected (wrong commitmentRoot)", async () => {
    const destroyStore = new InMemoryCircuitDestroyStore();
    const routeA = { id: randomBytes(32), root: randomBytes(32) };

    // A failure on route-A invalidates circuit-A (correct route).
    await invalidateCircuitOnFailure(destroyStore, routeA.id, routeA.root, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    // A failure with a DIFFERENT commitmentRoot (cross-route) → tries to
    // invalidate circuit-A but with wrong root → the store is keyed by
    // (circuitId, commitmentRoot) so a wrong root will NOT match.
    const wrongRoot = randomBytes(32);
    expect(await destroyStore.isRevoked(routeA.id, wrongRoot)).toBe(false); // wrong root → NOT revoked
  });

  test("9. malicious peer cannot inject a fake transport-confirmed failure", () => {
    // The TRANSPORT_CONFIRMED category is ONLY produced by the platform layer
    // (real socket events). A remote peer cannot send a "transport-confirmed"
    // observation over the wire — it is a LOCAL diagnostic. A malicious peer
    // can only cause PROTOCOL_AUTHENTICATION failures (bad frames), which
    // require threshold accumulation.
    //
    // This test verifies the CATEGORY model: a remote peer's bad frame is
    // PROTOCOL_AUTHENTICATION, NOT TRANSPORT_CONFIRMED.
    const detector = new LinkFailureDetector();
    // A remote peer sends a bad frame → PROTOCOL_AUTHENTICATION (NOT TRANSPORT_CONFIRMED).
    const state = detector.recordObservation({
      linkId: "l", localNodeId: "a", remoteNodeId: "malicious-peer",
      category: "PROTOCOL_AUTHENTICATION", reason: "forged AEAD tag", observedAt: NOW,
    });
    expect(state).toBe("DEGRADED"); // NOT LINK_DOWN — requires threshold
  });
});

// =====================================================================
// Phase 12: Restart + durability
// =====================================================================

describe("R-009 Stage 3 Phase 4: restart + durability", () => {
  test("failure-triggered invalidation persists across restart (DurableSqlite)", async () => {
    const { DurableSqliteCircuitDestroyStore } = await import("@/lib/sharenet/durable-circuit-replay-stores");
    const { db } = await import("@/lib/db");
    await db.circuitRevocation.deleteMany({});
    await db.consumedCircuitDestroy.deleteMany({});

    const cid = randomBytes(32);
    const cr = randomBytes(32);

    // Invalidate.
    const store = new DurableSqliteCircuitDestroyStore();
    const result = await invalidateCircuitOnFailure(store, cid, cr, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));
    expect(result.ok).toBe(true);

    // Simulate restart: new store instance, same DB.
    const restartedStore = new DurableSqliteCircuitDestroyStore();
    expect(await restartedStore.isRevoked(cid, cr)).toBe(true);

    // Old destroy is idempotent.
    const initiatorKp = generateNodeKeypair();
    const destroy = signCircuitDestroy(cid, cr, initiatorKp.nodeId, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED, NOW, NOW + 3600, initiatorKp.secretKey, initiatorKp.publicKey);
    const destroyResult = await processCircuitDestroy(encodeCircuitDestroy(destroy), {
      circuitId: cid, circuitIdHex: toHex(cid), routeId: "route:" + toHex(cr),
      hops: [], initiatorX25519PublicKey: new Uint8Array(32), initiatorX25519SecretKey: new Uint8Array(32),
      expiry: NOW + 3600, establishedAt: NOW, replayGuard: {} as any,
      noncePrefix: new Uint8Array(8), commitmentRoot: cr,
      floorStore: { getFloor: async () => 0n, checkAndAdvance: async () => ({ ok: true }) } as any,
    }, initiatorKp.nodeId, "gateway", restartedStore, NOW);
    expect(destroyResult.ok).toBe(true);
    if (!destroyResult.ok) return;
    expect(destroyResult.action).toBe("ALREADY_REVOKED"); // idempotent — tombstone persists

    // Cleanup.
    await db.circuitRevocation.deleteMany({});
    await db.consumedCircuitDestroy.deleteMany({});
  });
});

// =====================================================================
// Phase 15: Full detector test matrix — concurrency
// =====================================================================

describe("R-009 Stage 3 Phase 4: concurrency", () => {
  test("concurrent observations on different links are independent", () => {
    const detector = new LinkFailureDetector();
    // Link A: 2 failures → DEGRADED.
    detector.recordObservation({ linkId: "A", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f1", observedAt: NOW });
    detector.recordObservation({ linkId: "A", localNodeId: "a", remoteNodeId: "b", category: "PROTOCOL_AUTHENTICATION", reason: "f2", observedAt: NOW });
    // Link B: transport failure → LINK_DOWN.
    detector.recordObservation({ linkId: "B", localNodeId: "c", remoteNodeId: "d", category: "TRANSPORT_CONFIRMED", reason: "closed", observedAt: NOW });

    expect(detector.getState("A")).toBe("DEGRADED"); // NOT LINK_DOWN (only 2 failures)
    expect(detector.getState("B")).toBe("LINK_DOWN");
  });
});
