/**
 * ShareNet 2.0 — R-009 Stage 3 Phase 4: PRODUCTION failure-detection integration tests.
 *
 * These tests prove the ACTUAL production chain using the FailureEventDispatcher:
 *
 *   REAL socket/protocol failure
 *       ↓
 *   FailureEventDispatcher.recordObservation() (PRODUCTION — inline dispatch)
 *       ↓
 *   LINK_DOWN
 *       ↓
 *   durable circuit invalidation (INLINE — no manual dispatch)
 *       ↓
 *   zeroize
 *       ↓
 *   RecoveryManager
 *       ↓
 *   RecoveryPlan
 *
 * The tests do NOT directly call dispatchFailureEvents(), invalidateCircuitOnFailure(),
 * or RecoveryManager.handleLinkEvent(). The dispatcher records the observation
 * AND immediately dispatches — the production code path owns the entire chain.
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { createServer } from "node:net";
import { randomBytes } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import { setupCircuit } from "@reference/circuit/circuit";
import { sealForwardFrame, encodeCircuitFrame } from "@reference/circuit/frame";
import { processCircuitWireFrame } from "@reference/circuit/forwarding";
import { LinkFailureDetector as LFD, type CircuitLinkAssociation, FailureEventDispatcher as FED } from "@reference/failure/failure-event-dispatcher";
import { InMemoryCircuitDestroyStore, InMemoryCircuitSequenceFloorStore } from "@reference/circuit/replay-stores";
import { RecoveryManager, createRecoveryPlan, type GatewayCandidate } from "@reference/routing/recovery";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

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

// Helper: create a fully-wired dispatcher (detector + associations + store + RecoveryManager).
function createDispatcher(circuit: any, route: any) {
  const detector = new LFD();
  const destroyStore = new InMemoryCircuitDestroyStore();
  const rm = new RecoveryManager();
  rm.registerLink("link-1", "node-a", "node-b");
  rm.registerRoute(route.branded as any, toHex(circuit.circuitId), ["link-1"], NOW);

  const associations = new Map<string, CircuitLinkAssociation[]>([
    ["link-1", [{ circuitId: circuit.circuitId, commitmentRoot: circuit.commitmentRoot, circuitObj: circuit }]],
  ]);

  const dispatcher = new FED(detector, associations, destroyStore, rm);
  return { dispatcher, detector, destroyStore, rm };
}

// =====================================================================
// AEAD threshold integration — production path via processCircuitWireFrame
// =====================================================================

describe("R-009 Phase 4 PRODUCTION: AEAD threshold via processCircuitWireFrame + dispatcher", () => {
  test("3 tampered frames → DEGRADED → DEGRADED → LINK_DOWN → durable revoke → zeroize → RecoveryPlan (NO manual dispatch)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const { dispatcher, destroyStore, rm } = createDispatcher(circuit, route);

    // Seal a valid frame.
    const plaintext = new TextEncoder().encode("test");
    const sealed = sealForwardFrame(circuit, 1, plaintext);

    // --- Frame 1: tamper → AEAD failure → DEGRADED (via production path) ---
    const tampered1 = { ...sealed, ciphertext: new Uint8Array([...sealed.ciphertext].map((b, i) => i === 0 ? b ^ 0x01 : b)) };
    const result1 = await processCircuitWireFrame(
      circuit, 0, encodeCircuitFrame(tampered1), destroyStore, NOW,
      dispatcher, undefined, "link-1", "node-a", "node-b",
    );
    expect(result1.ok).toBe(false);
    expect(dispatcher.getState("link-1")).toBe("DEGRADED");
    // Circuit is still ACTIVE (no manual dispatch needed — the dispatcher did NOT invalidate yet).
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);

    // --- Frame 2: another tampered frame → still DEGRADED ---
    const tampered2 = { ...sealed, ciphertext: new Uint8Array([...sealed.ciphertext].map((b, i) => i === 1 ? b ^ 0x02 : b)) };
    const result2 = await processCircuitWireFrame(
      circuit, 0, encodeCircuitFrame(tampered2), destroyStore, NOW,
      dispatcher, undefined, "link-1", "node-a", "node-b",
    );
    expect(result2.ok).toBe(false);
    expect(dispatcher.getState("link-1")).toBe("DEGRADED");
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);

    // --- Frame 3: third tampered frame → threshold → LINK_DOWN ---
    // The dispatcher records the observation + IMMEDIATELY dispatches:
    // durable invalidation + zeroize + RecoveryManager — INLINE, no manual call.
    const tampered3 = { ...sealed, ciphertext: new Uint8Array([...sealed.ciphertext].map((b, i) => i === 2 ? b ^ 0x04 : b)) };
    const result3 = await processCircuitWireFrame(
      circuit, 0, encodeCircuitFrame(tampered3), destroyStore, NOW,
      dispatcher, undefined, "link-1", "node-a", "node-b",
    );
    expect(result3.ok).toBe(false);
    expect(dispatcher.getState("link-1")).toBe("LINK_DOWN");

    // The dispatcher ALREADY dispatched — circuit is durably revoked (NO manual dispatchFailureEvents call).
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);

    // Keys were zeroized (the dispatcher did it inline).
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(true);

    // RecoveryManager received the event — route invalidated.
    const invalidatedRoutes = rm.getInvalidatedRoutes();
    expect(invalidatedRoutes.length).toBeGreaterThan(0);

    // RecoveryPlan can be created (NO execution).
    const plan = createRecoveryPlan(
      invalidatedRoutes.map(r => r.routeId),
      "LINK_DOWN",
      [] as GatewayCandidate[],
      "INTERNET_GATEWAY" as any,
    );
    expect(plan.invalidatedRouteIds.length).toBeGreaterThan(0);
  });

  test("1 good frame after DEGRADED → resets suspicion (NO manual dispatch)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const { dispatcher, destroyStore } = createDispatcher(circuit, route);

    // 1 bad frame → DEGRADED.
    const sealed = sealForwardFrame(circuit, 1, new TextEncoder().encode("test"));
    const tampered = { ...sealed, ciphertext: new Uint8Array([...sealed.ciphertext].map((b, i) => i === 0 ? b ^ 0x01 : b)) };
    await processCircuitWireFrame(
      circuit, 0, encodeCircuitFrame(tampered), destroyStore, NOW,
      dispatcher, undefined, "link-1", "node-a", "node-b",
    );
    expect(dispatcher.getState("link-1")).toBe("DEGRADED");

    // 1 good frame → HEALTHY (reset — the dispatcher did it inline).
    const goodResult = await processCircuitWireFrame(
      circuit, 0, encodeCircuitFrame(sealed), destroyStore, NOW,
      dispatcher, undefined, "link-1", "node-a", "node-b",
    );
    expect(goodResult.ok).toBe(true);
    expect(dispatcher.getState("link-1")).toBe("HEALTHY");
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);
  });
});

// =====================================================================
// Real TCP disconnect → dispatcher → LINK_DOWN → durable revoke
// =====================================================================

describe("R-009 Phase 4 PRODUCTION: real TCP disconnect → dispatcher → LINK_DOWN", () => {
  test("real socket failure → TRANSPORT_CONFIRMED → LINK_DOWN → durable revoke (NO manual dispatch)", async () => {
    const { TcpCircuitDestroyTransport } = await import("@/lib/sharenet/circuit-destroy-transport");
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Allocate a port for the "next hop" but DON'T start a server.
    const deadPort = await new Promise<number>((resolve) => {
      const srv = createServer();
      srv.listen(0, "127.0.0.1", () => {
        const addr = srv.address();
        if (addr && typeof addr === "object") {
          const port = addr.port;
          srv.close(() => resolve(port));
        }
      });
    });

    const { dispatcher, destroyStore, rm } = createDispatcher(circuit, route);

    // Create the transport WITH the dispatcher wired in.
    const transport = new TcpCircuitDestroyTransport(
      "node-a", 0, new Map([["node-b", deadPort]]),
      dispatcher, undefined, "link-1", "node-b",
    );

    expect(dispatcher.getState("link-1")).toBe("HEALTHY");

    // Attempt to send — this will fail (connection refused) + the transport's
    // socket error handler will call dispatcher.recordObservation(TRANSPORT_CONFIRMED)
    // → the dispatcher IMMEDIATELY dispatches: durable invalidation + zeroize +
    // RecoveryManager — INLINE, no manual dispatchFailureEvents call.
    const fakeLink = {
      localNodeId: "node-a", remoteNodeId: "node-b",
      linkIdHex: "mock", linkIdBytes: new Uint8Array(32),
      transcriptDigestHex: "mock", localRole: "INITIATOR" as const,
      establishedAt: NOW, expiresAt: NOW + 3600, transcriptVerifiedAt: NOW,
      remoteNode: { nodeId: "node-b" },
    };
    const sendResult = await transport.send({
      localNodeId: "node-a",
      nextHopNodeId: "node-b",
      circuitId: circuit.circuitId,
      commitmentRoot: circuit.commitmentRoot,
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink,
      senderEd25519SecretKey: randomBytes(32),
      senderEd25519PublicKey: randomBytes(32),
    }, new Uint8Array(32));

    expect(sendResult.ok).toBe(false);
    expect(dispatcher.getState("link-1")).toBe("LINK_DOWN");

    // The dispatcher ALREADY dispatched — circuit is durably revoked.
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);

    // Keys were zeroized.
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(true);

    // RecoveryManager received the event.
    const invalidatedRoutes = rm.getInvalidatedRoutes();
    expect(invalidatedRoutes.length).toBeGreaterThan(0);
  });
});

// =====================================================================
// Anti-DoS + idempotency against production paths
// =====================================================================

describe("R-009 Phase 4 PRODUCTION: anti-DoS + idempotency", () => {
  test("wrong link cannot invalidate another circuit (production dispatcher)", async () => {
    const detector = new LFD();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const rm = new RecoveryManager();
    rm.registerLink("link-1", "a", "b");
    rm.registerLink("link-2", "a", "c");

    // Circuit A is on link-1.
    const cidA = randomBytes(32);
    const crA = randomBytes(32);
    const associations = new Map<string, CircuitLinkAssociation[]>([
      ["link-1", [{ circuitId: cidA, commitmentRoot: crA }]],
    ]);
    const dispatcher = new FED(detector, associations, destroyStore, rm);

    // A failure on link-2 (different link) — circuit A should NOT be affected.
    await dispatcher.recordObservation({
      linkId: "link-2", localNodeId: "a", remoteNodeId: "c",
      category: "TRANSPORT_CONFIRMED", reason: "test", observedAt: NOW,
    });

    expect(await destroyStore.isRevoked(cidA, crA)).toBe(false); // still ACTIVE
  });

  test("persistence failure → fail closed (NO manual dispatch)", async () => {
    const failingStore = {
      isRevoked: async () => false,
      consumeDestroyAndRevoke: async () => ({ ok: false as const, reason: "simulated" }),
      revoke: async () => false,
    };
    const detector = new LFD();
    const rm = new RecoveryManager();
    rm.registerLink("link-1", "a", "b");

    const associations = new Map<string, CircuitLinkAssociation[]>([
      ["link-1", [{ circuitId: randomBytes(32), commitmentRoot: randomBytes(32) }]],
    ]);
    const dispatcher = new FED(detector, associations, failingStore as any, rm);

    const result = await dispatcher.recordObservation({
      linkId: "link-1", localNodeId: "a", remoteNodeId: "b",
      category: "TRANSPORT_CONFIRMED", reason: "test", observedAt: NOW,
    });
    expect(result.state).toBe("LINK_DOWN");
    expect(result.invalidatedCircuits.length).toBe(0); // NOT invalidated — fail closed
  });

  test("duplicate LINK_DOWN → exactly one durable transition (NO manual dispatch)", async () => {
    const detector = new LFD();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const rm = new RecoveryManager();
    rm.registerLink("link-1", "a", "b");

    const cid = randomBytes(32);
    const cr = randomBytes(32);
    const associations = new Map<string, CircuitLinkAssociation[]>([
      ["link-1", [{ circuitId: cid, commitmentRoot: cr }]],
    ]);
    const dispatcher = new FED(detector, associations, destroyStore, rm);

    // First LINK_DOWN — dispatched INLINE → circuit revoked.
    const result1 = await dispatcher.recordObservation({
      linkId: "link-1", localNodeId: "a", remoteNodeId: "b",
      category: "TRANSPORT_CONFIRMED", reason: "first", observedAt: NOW,
    });
    expect(result1.invalidatedCircuits.length).toBe(1);
    expect(await destroyStore.isRevoked(cid, cr)).toBe(true);

    // Second LINK_DOWN (duplicate — idempotent).
    const result2 = await dispatcher.recordObservation({
      linkId: "link-1", localNodeId: "a", remoteNodeId: "b",
      category: "TRANSPORT_CONFIRMED", reason: "second", observedAt: NOW + 1,
    });
    expect(result2.invalidatedCircuits.length).toBe(0); // idempotent — no duplicate
  });
});
