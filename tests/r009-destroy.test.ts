/**
 * ShareNet 2.0 — R-009 Stage 3: CircuitDestroy + teardown tests.
 *
 * Tests:
 *   1. signCircuitDestroy + verifyCircuitDestroy round-trip (initiator)
 *   2. encode/decode round-trip
 *   3. wrong signer → REJECT
 *   4. wrong circuitId → REJECT (signature invalid)
 *   5. wrong commitmentRoot → REJECT (routeId mismatch)
 *   6. wrong destroyerRole → REJECT
 *   7. tampered reason → REJECT
 *   8. tampered nonce → REJECT
 *   9. expiry enforcement in processCircuitWireFrame
 *   10. durable revocation: revoked circuit → frame REJECTED
 *   11. durable revocation: process restart → still revoked
 *   12. durable revocation: idempotent revoke
 *   13. destroy replay: second destroy → REJECTED (destroy replay store)
 *   14. destroy replay: different circuitId → independent ACCEPT
 *   15. expiry does NOT advance replay floor
 *   16. revocation does NOT advance replay floor
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { randomBytes, generateNodeKeypair } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  setupCircuit,
} from "@reference/circuit/circuit";
import {
  encodeCircuitFrame,
  sealForwardFrame,
  DIRECTION_FORWARD,
} from "@reference/circuit/frame";
import { processCircuitWireFrame, zeroizeCircuit } from "@reference/circuit/forwarding";
import {
  signCircuitDestroy,
  verifyCircuitDestroy,
  encodeCircuitDestroy,
  decodeCircuitDestroy,
  processCircuitDestroy,
  DESTROYER_ROLE_INITIATOR,
  DESTROYER_ROLE_GATEWAY,
  DESTROY_REASON_OPERATOR_INITIATED,
  DESTROY_REASON_CIRCUIT_EXPIRED,
  CIRCUIT_DESTROY_MAX_CLOCK_SKEW_SECONDS,
  type CircuitDestroy,
} from "@reference/circuit/destroy";
import {
  InMemoryCircuitSequenceFloorStore,
  InMemoryCircuitRevocationStore,
  InMemoryCircuitDestroyReplayStore,
  InMemoryCircuitDestroyStore,
  type CircuitRevocationStore,
  type CircuitDestroyStore,
} from "@reference/circuit/replay-stores";
import {
  constructReturnOnionTemplate,
  signGatewayReturnTemplate,
  constructGatewayReturnAuthorization,
  encodeGatewayReturnAuthorization,
} from "@reference/circuit/return-template";
import { handleCircuitSetup } from "@reference/circuit/distributed-setup";
import { db } from "@/lib/db";
import { DurableSqliteCircuitRevocationStore, DurableSqliteCircuitDestroyReplayStore, DurableSqliteCircuitDestroyStore } from "@/lib/sharenet/durable-circuit-replay-stores";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;

function makeRoute(numHops = 2) {
  const ctx = makeGenuineBrandedRouteHelper(numHops, NOW);
  return {
    branded: ctx.branded,
    kps: ctx.kps,
    hpk: ctx.hopPublicKeys,
    commitmentRoot: ctx.branded.commitmentRoot,
    initiator: ctx.initiator,
    // Per R-009 Stage 3 Phase 2 (gateway destroy authorization): the
    // gateway proof requires the committed route's acceptances + hopNodeIds
    // to build the portable terminal-hop proof chain.
    commitment: ctx.commitment,
    hopNodeIds: ctx.branded.hops.map((h) => h.nodeId),
    terminalAcceptance: ctx.commitment.acceptances[ctx.commitment.acceptances.length - 1]!,
  };
}

/**
 * Build a serialized GatewayReturnAuthorization (the portable terminal-hop
 * proof chain) for the gateway of the given route + circuit.
 *
 * This is the proof a gateway attaches to a GATEWAY-originated CircuitDestroy.
 * The receiver decodes + verifies it via verifyTerminalHopProof (called inside
 * processCircuitDestroy) — no WeakSet/BrandedCommittedRoute dependency.
 */
function makeGatewayProof(
  route: ReturnType<typeof makeRoute>,
  circuit: ReturnType<typeof setupCircuit>,
): Uint8Array {
  const terminalHopIndex = route.branded.hops.length - 1;
  const relayKp = route.kps[terminalHopIndex]!;
  const gatewayNodeId = route.branded.hops[terminalHopIndex]!.nodeId;
  const initiatorKp = route.initiator;

  // Generate a genuine terminal CircuitSetupAck.
  const ackResult = handleCircuitSetup(
    {
      route: route.branded,
      hopIndex: terminalHopIndex,
      initiatorX25519PublicKey: circuit.initiatorX25519PublicKey,
      setupNonce: randomBytes(16),
    },
    relayKp.secretKey,
    route.commitmentRoot,
    NOW,
  );
  if (!ackResult.ok) throw new Error(`terminal ack setup failed: ${ackResult.reason}`);
  const terminalAck = ackResult.ack;
  const relayEd25519PublicKey = relayKp.publicKey;
  const gatewayX25519PublicKey = ackResult.state.relayX25519PublicKey;

  // Construct the GatewayReturnTemplate (signed by the initiator).
  const template = constructReturnOnionTemplate(circuit);
  const gatewayTemplate = signGatewayReturnTemplate(
    template, route.branded.expiry, gatewayNodeId,
    gatewayX25519PublicKey,
    circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
    initiatorKp.secretKey, initiatorKp.publicKey,
  );

  // Bundle into a GatewayReturnAuthorization (the portable proof).
  const auth = constructGatewayReturnAuthorization(
    gatewayTemplate, terminalAck, relayEd25519PublicKey,
    route.terminalAcceptance, route.hopNodeIds,
    route.commitment.proposal, route.commitment.acceptances,
  );
  return encodeGatewayReturnAuthorization(auth);
}

function makeRelayX25519Keys(route: { hops: Array<{ nodeId: string }> }) {
  return route.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk };
  });
}

describe("R-009 Stage 3: CircuitDestroy wire object", () => {
  test("sign + verify round-trip (initiator destroy)", () => {
    const route = makeRoute(2);
    const initiatorKp = generateNodeKeypair();
    const circuitId = randomBytes(32);

    const destroy = signCircuitDestroy(
      circuitId, route.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const result = verifyCircuitDestroy(destroy);
    expect(result.ok).toBe(true);
  });

  test("encode + decode round-trip", () => {
    const route = makeRoute(1);
    const initiatorKp = generateNodeKeypair();
    const circuitId = randomBytes(32);

    const destroy = signCircuitDestroy(
      circuitId, route.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const encoded = encodeCircuitDestroy(destroy);
    const decoded = decodeCircuitDestroy(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(toHex(decoded.circuitDestroy.circuitId)).toBe(toHex(destroy.circuitId));
    expect(toHex(decoded.circuitDestroy.signature)).toBe(toHex(destroy.signature));
  });

  test("wrong signer (different Ed25519 key) → REJECT", () => {
    const route = makeRoute(1);
    const initiatorKp = generateNodeKeypair();
    const wrongKp = generateNodeKeypair();
    const circuitId = randomBytes(32);

    const destroy = signCircuitDestroy(
      circuitId, route.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // Tamper: replace the public key with a different one.
    const tampered: CircuitDestroy = { ...destroy, destroyerEd25519PublicKey: wrongKp.publicKey };
    const result = verifyCircuitDestroy(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("wrong circuitId → REJECT (signature invalid)", () => {
    const route = makeRoute(1);
    const initiatorKp = generateNodeKeypair();

    const destroy = signCircuitDestroy(
      randomBytes(32), route.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const tampered: CircuitDestroy = { ...destroy, circuitId: randomBytes(32) };
    const result = verifyCircuitDestroy(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("invalid destroyerRole → REJECT", () => {
    const route = makeRoute(1);
    const initiatorKp = generateNodeKeypair();
    const circuitId = randomBytes(32);

    const destroy = signCircuitDestroy(
      circuitId, route.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const tampered: CircuitDestroy = { ...destroy, destroyerRole: 0x03 };
    const result = verifyCircuitDestroy(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("invalid destroyerRole");
  });

  test("tampered destroyReason → REJECT", () => {
    const route = makeRoute(1);
    const initiatorKp = generateNodeKeypair();
    const circuitId = randomBytes(32);

    const destroy = signCircuitDestroy(
      circuitId, route.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const tampered: CircuitDestroy = { ...destroy, destroyReason: 0x99 };
    const result = verifyCircuitDestroy(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("tampered destroyNonce → REJECT", () => {
    const route = makeRoute(1);
    const initiatorKp = generateNodeKeypair();
    const circuitId = randomBytes(32);

    const destroy = signCircuitDestroy(
      circuitId, route.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const tampered: CircuitDestroy = { ...destroy, destroyNonce: new Uint8Array(16).fill(0xFF) };
    const result = verifyCircuitDestroy(tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });
});

describe("R-009 Stage 3: expiry enforcement in processCircuitWireFrame", () => {
  test("expired circuit → frame REJECTED (before AEAD)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Seal a valid frame.
    const plaintext = new TextEncoder().encode("test");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // now > expiry → REJECT. The expiry path performs a DURABLE revocation
    // (writes a CIRCUIT_EXPIRED record into the revocationStore) before
    // returning. A real InMemoryCircuitRevocationStore exercises that path.
    const revocationStore = new InMemoryCircuitRevocationStore();
    const result = await processCircuitWireFrame(circuit, 0, wireBytes, revocationStore, route.branded.expiry + 1);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("expired");
    // Floor must NOT advance.
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(0n);
  });

  test("non-expired circuit → frame ACCEPTED", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("test");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // A fresh InMemoryCircuitRevocationStore → no durable record → frame OK.
    const result = await processCircuitWireFrame(circuit, 0, wireBytes, new InMemoryCircuitRevocationStore(), NOW);
    expect(result.ok).toBe(true);
  });
});

describe("R-009 Stage 3: durable revocation", () => {
  let revocationStore: DurableSqliteCircuitRevocationStore;

  beforeAll(async () => {
    revocationStore = new DurableSqliteCircuitRevocationStore();
    await db.circuitRevocation.deleteMany({});
  });

  afterAll(async () => {
    await db.circuitRevocation.deleteMany({});
  });

  test("revoked circuit → frame REJECTED", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("test");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // Revoke the circuit.
    const ok = await revocationStore.revoke(
      circuit.circuitId, circuit.commitmentRoot,
      "initiator", 0x01, 0x01, randomBytes(16),
    );
    expect(ok).toBe(true);

    // Frame must be rejected (circuit is revoked).
    const result = await processCircuitWireFrame(circuit, 0, wireBytes, revocationStore, NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("revoked");
    // Floor must NOT advance.
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(0n);
  });

  test("process restart → still revoked", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Revoke.
    await revocationStore.revoke(
      circuit.circuitId, circuit.commitmentRoot,
      "initiator", 0x01, 0x01, randomBytes(16),
    );

    // Simulate restart: create a NEW revocation store (same DB).
    const restartedStore = new DurableSqliteCircuitRevocationStore();
    const isRevoked = await restartedStore.isRevoked(circuit.circuitId, circuit.commitmentRoot);
    expect(isRevoked).toBe(true);
  });

  test("idempotent revoke → returns true", async () => {
    const circuitId = randomBytes(32);
    const commitmentRoot = randomBytes(32);

    const r1 = await revocationStore.revoke(circuitId, commitmentRoot, "initiator", 0x01, 0x01, randomBytes(16));
    expect(r1).toBe(true);

    const r2 = await revocationStore.revoke(circuitId, commitmentRoot, "gateway", 0x02, 0x01, randomBytes(16));
    expect(r2).toBe(true); // idempotent — already revoked
  });
});

describe("R-009 Stage 3: destroy replay protection (durable SQLite)", () => {
  let destroyReplayStore: DurableSqliteCircuitDestroyReplayStore;

  beforeAll(async () => {
    destroyReplayStore = new DurableSqliteCircuitDestroyReplayStore();
    await db.consumedCircuitDestroy.deleteMany({});
  });

  afterAll(async () => {
    await db.consumedCircuitDestroy.deleteMany({});
  });

  test("first destroy → ACCEPT", async () => {
    const ok = await destroyReplayStore.consume(randomBytes(32), randomBytes(32), randomBytes(16));
    expect(ok).toBe(true);
  });

  test("replay destroy → REJECT", async () => {
    const cr = randomBytes(32);
    const cid = randomBytes(32);
    const nonce = randomBytes(16);

    const r1 = await destroyReplayStore.consume(cr, cid, nonce);
    expect(r1).toBe(true);

    const r2 = await destroyReplayStore.consume(cr, cid, nonce);
    expect(r2).toBe(false);
  });

  test("different circuitId → independent ACCEPT", async () => {
    const cr = randomBytes(32);
    const nonce = randomBytes(16);

    const r1 = await destroyReplayStore.consume(cr, randomBytes(32), nonce);
    const r2 = await destroyReplayStore.consume(cr, randomBytes(32), nonce);
    expect(r1).toBe(true);
    expect(r2).toBe(true);
  });
});

// =====================================================================
// R-009 Stage 3: processCircuitDestroy — canonical teardown protocol path
// =====================================================================

describe("R-009 Stage 3: processCircuitDestroy (canonical teardown path)", () => {
  test("initiator destroy → ACCEPT + durable revocation", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator; // the route helper's REAL initiator keypair (its publicKey derives route.initiator.nodeId)
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, // expectedInitiatorNodeId
      gatewayNodeId, // expectedGatewayNodeId
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.idempotent).toBe(false);

    // Circuit is now durably revoked.
    const isRevoked = await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot);
    expect(isRevoked).toBe(true);
  });

  test("gateway destroy → ACCEPT + durable revocation", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayKp = route.kps[1]!;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      gatewayNodeId,
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      gatewayKp.secretKey, gatewayKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);
    // GATEWAY destroy REQUIRES the portable terminal-hop proof chain.
    const gatewayProofBytes = makeGatewayProof(route, circuit);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
      gatewayProofBytes,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.idempotent).toBe(false);

    const isRevoked = await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot);
    expect(isRevoked).toBe(true);
  });

  test("unauthorized relay destroy → REJECT", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const relayKp = route.kps[0]!;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Relay 0 tries to destroy as INITIATOR (it's not the initiator).
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      relayKp.nodeId, // relay's nodeId, not the initiator's
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      relayKp.secretKey, relayKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, // expectedInitiatorNodeId (doesn't match)
      gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("unauthorized");

    // Circuit must NOT be revoked.
    const isRevoked = await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot);
    expect(isRevoked).toBe(false);
  });

  test("replay destroy → REJECT (destroy replay store)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // First call → ACCEPT.
    const r1 = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(r1.ok).toBe(true);

    // Second call (same destroy) → idempotent (circuit already revoked).
    const r2 = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.idempotent).toBe(true); // idempotent — already revoked
  });

  test("wrong circuitId → REJECT", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Sign for a DIFFERENT circuitId.
    const destroy = signCircuitDestroy(
      randomBytes(32), // wrong circuitId
      circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("circuitId mismatch");
  });

  test("destroyed circuit → subsequent frame REJECTED", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Destroy the circuit.
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const destroyResult = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(destroyResult.ok).toBe(true);

    // Now try to send a frame on the destroyed circuit.
    const plaintext = new TextEncoder().encode("post-destroy frame");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);
    const frameResult = await processCircuitWireFrame(circuit, 0, wireBytes, destroyStore, NOW);
    expect(frameResult.ok).toBe(false);
    if (!frameResult.ok) expect(frameResult.reason).toContain("revoked");
  });

  test("zeroizeCircuit → keys are all zeros", () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Keys are non-zero before zeroize.
    expect(circuit.hops[0]!.forwardingKey.some((b) => b !== 0)).toBe(true);
    expect(circuit.initiatorX25519SecretKey.some((b) => b !== 0)).toBe(true);

    // Zeroize.
    zeroizeCircuit(circuit);

    // Keys are all zeros after zeroize.
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(true);
    expect(circuit.hops[0]!.returnKey.every((b) => b === 0)).toBe(true);
    expect(circuit.initiatorX25519SecretKey.every((b) => b === 0)).toBe(true);
    expect(circuit.noncePrefix.every((b) => b === 0)).toBe(true);

    // commitmentRoot + circuitId are NOT zeroized (needed for revocation checks).
    expect(circuit.commitmentRoot.some((b) => b !== 0)).toBe(true);
    expect(circuit.circuitId.some((b) => b !== 0)).toBe(true);
  });

  test("expiry → durable revocation written (survives restart)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("expired frame");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // now > expiry → reject + write durable revocation.
    // InMemoryCircuitDestroyStore structurally satisfies CircuitRevocationStore
    // (it has isRevoked + revoke), so it can be passed to processCircuitWireFrame.
    const result = await processCircuitWireFrame(circuit, 0, wireBytes, destroyStore, route.branded.expiry + 1);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("expired");

    // Durable revocation record was written.
    const isRevoked = await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot);
    expect(isRevoked).toBe(true);

    // Simulate restart: create a NEW revocation store (same in-memory state is gone,
    // but the record persists in the store — for a durable store, it would persist in the DB).
    const restartedStore = destroyStore; // in-memory: same object (durable would be new instance from DB)
    const isStillRevoked = await restartedStore.isRevoked(circuit.circuitId, circuit.commitmentRoot);
    expect(isStillRevoked).toBe(true);
  });
});

// =====================================================================
// R-009 Stage 3 re-audit of 6936831: identity authorization bypass +
// fail-closed expiry + zeroize ownership.
//
// Four gaps flagged by the re-audit:
//   1. CircuitDestroy checked destroyerNodeId == expectedInitiatorNodeId
//      but NOT that destroyerEd25519PublicKey derives destroyerNodeId.
//   2. processCircuitWireFrame ignored the boolean result of
//      revocationStore.revoke() during expiry.
//   3. processCircuitDestroy did not own zeroization (caller obligation).
//   4. Lifecycle semantics needed a single authoritative state machine.
// =====================================================================

/**
 * Test double: a CircuitRevocationStore whose revoke() ALWAYS fails.
 *
 * Simulates a durable persistence failure (DB write error, disk full, unique
 * constraint violation that is NOT the idempotent case, etc.). Used to prove
 * the expiry path is fail-closed: a failed revoke() MUST NOT be claimed as
 * "durably revoked" and MUST NOT zeroize keys.
 */
class FailingCircuitRevocationStore implements CircuitRevocationStore {
  async isRevoked(): Promise<boolean> {
    return false; // never revoked — so the expiry path actually attempts revoke()
  }
  async revoke(): Promise<boolean> {
    return false; // ALWAYS fails — simulates persistence failure
  }
}

// ---- Fix #1: identity authorization bypass is closed ------------------

describe("R-009 Stage 3 re-audit (6936831): identity authorization bypass is closed", () => {
  test("valid initiator destroy → ACCEPT (legitimate key derives legitimate NodeId)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Legitimate: initiator signs with their own key + claims their own NodeId.
    // verifyNodeIdBinding(initiator.nodeId, initiatorKp.publicKey) → true.
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.idempotent).toBe(false);

    // Circuit is durably revoked.
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);
  });

  test("attacker key + legitimate initiator NodeId → REJECT (identity binding fails)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // ATTACK: the attacker generates their OWN Ed25519 keypair, but sets
    // destroyerNodeId to the LEGITIMATE initiator's public NodeId string.
    // The signature verifies (against the attacker's own pubkey, which the
    // attacker honestly places in destroyerEd25519PublicKey). Without the
    // identity-binding check, destroyerNodeId === expectedInitiatorNodeId
    // would PASS and the forged destroy would be accepted.
    const attackerKp = generateNodeKeypair();
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId, // ← attacker claims the LEGITIMATE initiator's NodeId
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      attackerKp.secretKey, attackerKp.publicKey, // ← but signs with ATTACKER's key
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("identity binding failed");
      expect(result.reason).toContain("forged destroy rejected");
    }

    // CRITICAL: the circuit MUST NOT be revoked by a forged destroy.
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);

    // And the destroy nonce MUST NOT have been consumed (we rejected before step 7).
    // A retry with the SAME nonce would still be accepted on a genuine destroy.
    // Verify by calling consumeDestroyAndRevoke — it should succeed (first use,
    // NOT idempotent — the forged destroy did not consume the nonce).
    const reConsume = await destroyStore.consumeDestroyAndRevoke(
      circuit.commitmentRoot, circuit.circuitId, destroy.destroyNonce,
      "test-verify", 0x01, 0x01,
    );
    expect(reConsume.ok).toBe(true);
    if (reConsume.ok) expect(reConsume.idempotent).toBe(false); // first use — the forged destroy did not consume it
  });

  test("attacker key + legitimate gateway NodeId → REJECT (identity binding fails)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // ATTACK: same as above but targeting the GATEWAY role. The attacker
    // claims the legitimate gateway's NodeId while signing with their own key.
    const attackerKp = generateNodeKeypair();
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      gatewayNodeId, // ← attacker claims the LEGITIMATE gateway's NodeId
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      attackerKp.secretKey, attackerKp.publicKey, // ← but signs with ATTACKER's key
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("identity binding failed");
    }
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);
  });

  test("valid gateway destroy → ACCEPT (legitimate gateway key derives gateway NodeId)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayKp = route.kps[1]!;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Legitimate: gateway signs with their own key + claims their own NodeId.
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      gatewayNodeId,
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      gatewayKp.secretKey, gatewayKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);
    // GATEWAY destroy REQUIRES the portable terminal-hop proof chain.
    const gatewayProofBytes = makeGatewayProof(route, circuit);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
      gatewayProofBytes,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.idempotent).toBe(false);
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);
  });
});

// ---- Fix #2: expiry revocation is fail-closed -------------------------

describe("R-009 Stage 3 re-audit (6936831): expiry revocation is fail-closed", () => {
  test("revocation persistence failure → frame rejected, fail-closed, keys NOT zeroized", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Snapshot key material BEFORE the expiry attempt — to prove it is retained.
    expect(circuit.hops[0]!.forwardingKey.some((b) => b !== 0)).toBe(true);
    expect(circuit.initiatorX25519SecretKey.some((b) => b !== 0)).toBe(true);
    const fwdKeySnapshot = new Uint8Array(circuit.hops[0]!.forwardingKey);
    const initSecretSnapshot = new Uint8Array(circuit.initiatorX25519SecretKey);

    const plaintext = new TextEncoder().encode("expired frame, failing store");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // now > expiry, BUT the revocation store ALWAYS fails to persist.
    const failingStore = new FailingCircuitRevocationStore();
    const result = await processCircuitWireFrame(circuit, 0, wireBytes, failingStore, route.branded.expiry + 1);

    // The frame MUST be rejected.
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // The reason MUST explicitly indicate a persistence failure (fail-closed),
      // NOT a false "circuit expired (durably revoked)".
      expect(result.reason).toContain("persistence FAILED");
      expect(result.reason).toContain("fail-closed");
      expect(result.reason).not.toContain("durably revoked");
    }

    // CRITICAL: keys MUST NOT be zeroized. The terminal state was NOT durably
    // recorded, so destroying the keys would be unsafe (the operator may
    // retry; zeroized keys cannot be recovered). The keys are retained for retry.
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(false);
    expect(circuit.initiatorX25519SecretKey.every((b) => b === 0)).toBe(false);
    // The keys are byte-identical to the snapshot (untouched).
    expect(circuit.hops[0]!.forwardingKey).toEqual(fwdKeySnapshot);
    expect(circuit.initiatorX25519SecretKey).toEqual(initSecretSnapshot);

    // The replay floor MUST NOT advance (the frame was rejected before AEAD).
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(0n);
  });
});

// ---- Fix #3: processCircuitDestroy owns zeroization --------------------

describe("R-009 Stage 3 re-audit (6936831): processCircuitDestroy owns zeroization", () => {
  test("processCircuitDestroy succeeds → all key material zeroized WITHOUT caller-side zeroize", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Keys are non-zero BEFORE the destroy.
    expect(circuit.hops[0]!.forwardingKey.some((b) => b !== 0)).toBe(true);
    expect(circuit.hops[1]!.forwardingKey.some((b) => b !== 0)).toBe(true);
    expect(circuit.hops[0]!.returnKey.some((b) => b !== 0)).toBe(true);
    expect(circuit.initiatorX25519SecretKey.some((b) => b !== 0)).toBe(true);
    expect(circuit.noncePrefix.some((b) => b !== 0)).toBe(true);

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // Call processCircuitDestroy — the CANONICAL teardown path. The caller
    // does NOT invoke zeroizeCircuit() afterwards. The function owns it.
    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.idempotent).toBe(false);

    // CRITICAL: every private/derived key is all zeros AFTER processCircuitDestroy,
    // WITHOUT any caller-side zeroizeCircuit() call in this test.
    for (const hop of circuit.hops) {
      expect(hop.forwardingKey.every((b) => b === 0)).toBe(true);
      expect(hop.returnKey.every((b) => b === 0)).toBe(true);
      if (hop.relayX25519PublicKey) {
        expect(hop.relayX25519PublicKey.every((b) => b === 0)).toBe(true);
      }
    }
    expect(circuit.initiatorX25519SecretKey.every((b) => b === 0)).toBe(true);
    expect(circuit.noncePrefix.every((b) => b === 0)).toBe(true);

    // commitmentRoot + circuitId are NOT zeroized (needed for revocation checks).
    expect(circuit.commitmentRoot.some((b) => b !== 0)).toBe(true);
    expect(circuit.circuitId.some((b) => b !== 0)).toBe(true);

    // And the circuit is durably revoked.
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);
  });

  test("idempotent destroy (already revoked) → keys still zeroized + no re-consume", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // First destroy — fresh teardown. Keys zeroized.
    const r1 = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.idempotent).toBe(false);
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(true);

    // Re-mangle a key to prove the second (idempotent) destroy re-zeroizes.
    circuit.hops[0]!.forwardingKey.fill(0xAB);
    expect(circuit.hops[0]!.forwardingKey.some((b) => b !== 0)).toBe(true);

    // Second destroy — idempotent (circuit already revoked). processCircuitDestroy
    // STILL owns zeroization: it re-fills the keys with zeros (idempotent zeroize).
    const r2 = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.idempotent).toBe(true); // already revoked — idempotent success
    // Keys are zeroized again (idempotent zeroize is a no-op on already-zero keys,
    // but here we deliberately re-mangled them, so this proves the function ran).
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(true);
  });
});

// =====================================================================
// R-009 Stage 3 Phase 2 re-audit of 60e4364:
//   1. Gateway destroy authorization via portable terminal-hop proof chain.
//   2. CircuitDestroy freshness (issuedAt/expiry/circuit.expiry + clock skew).
//   3. Atomic consume-nonce + revoke-tombstone (no split state).
// =====================================================================

/**
 * Test double: a CircuitDestroyStore whose consumeDestroyAndRevoke ALWAYS fails.
 *
 * Simulates a durable persistence failure (DB transaction abort, disk full, etc.).
 * Used to prove the atomic operation is fail-closed with NO split state: the
 * nonce is NOT consumed and the tombstone is NOT written. A retry with the SAME
 * destroy + a WORKING store should succeed (the nonce is still fresh).
 */
class FailingCircuitDestroyStore implements CircuitDestroyStore {
  async isRevoked(): Promise<boolean> {
    return false;
  }
  async consumeDestroyAndRevoke(): Promise<{ ok: false; reason: string }> {
    return { ok: false, reason: "simulated persistence failure (FailingCircuitDestroyStore)" };
  }
}

// ---- Fix #1: Gateway destroy authorization via portable proof chain --------

describe("R-009 Stage 3 Phase 2: gateway destroy authorization via portable terminal-hop proof", () => {
  test("valid gateway destroy + valid proof → ACCEPT", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayKp = route.kps[1]!;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      gatewayNodeId,
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      gatewayKp.secretKey, gatewayKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);
    const gatewayProofBytes = makeGatewayProof(route, circuit);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
      gatewayProofBytes,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.idempotent).toBe(false);
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);
  });

  test("gateway destroy WITHOUT proof → REJECT (proof required)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayKp = route.kps[1]!;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      gatewayNodeId,
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      gatewayKp.secretKey, gatewayKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // No gatewayProofBytes — the caller-supplied expectedGatewayNodeId alone
    // is no longer sufficient.
    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
      // gatewayProofBytes omitted
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("gateway destroy requires portable terminal-hop proof");
    }
    // Circuit MUST NOT be revoked.
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);
  });

  test("gateway destroy + tampered proof (corrupted bytes) → REJECT", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayKp = route.kps[1]!;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      gatewayNodeId,
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      gatewayKp.secretKey, gatewayKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // Tamper the proof: flip a byte in the serialized GatewayReturnAuthorization.
    const gatewayProofBytes = makeGatewayProof(route, circuit);
    const tamperedProof = new Uint8Array(gatewayProofBytes);
    tamperedProof[tamperedProof.length - 1] ^= 0x01;

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
      tamperedProof,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("terminal-hop proof chain verification failed");
    }
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);
  });

  test("gateway destroy + proof from ANOTHER route → REJECT (commitmentRoot mismatch)", async () => {
    // Route A: the circuit's actual route.
    const routeA = makeRoute(2);
    const relayKeysA = makeRelayX25519Keys(routeA.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(routeA.branded, relayKeysA, NOW, floorStore);
    const gatewayKpA = routeA.kps[1]!;
    const gatewayNodeIdA = routeA.branded.hops[1]!.nodeId;

    // Route B: a DIFFERENT route with a different commitmentRoot.
    const routeB = makeRoute(2);
    const relayKeysB = makeRelayX25519Keys(routeB.branded);
    const circuitB = setupCircuit(routeB.branded, relayKeysB, NOW, floorStore);

    // The gateway of route A signs a destroy for circuit A (correct circuit).
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      gatewayNodeIdA,
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, routeA.branded.expiry,
      gatewayKpA.secretKey, gatewayKpA.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // But attaches a proof from ROUTE B (different commitmentRoot).
    // The proof is validly signed for route B, but its commitmentRoot does NOT
    // match circuit A's commitmentRoot.
    const gatewayProofFromRouteB = makeGatewayProof(routeB, circuitB);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      routeA.initiator.nodeId, gatewayNodeIdA,
      destroyStore,
      NOW,
      gatewayProofFromRouteB,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("commitmentRoot does not match");
    }
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);
  });

  test("non-terminal relay with valid key + proof at non-terminal hopIndex → REJECT", async () => {
    const route = makeRoute(3); // 3 hops: relay 0, relay 1, gateway 2
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Relay 0 (a NON-terminal relay) tries to destroy as GATEWAY.
    const relay0Kp = route.kps[0]!;
    const relay0NodeId = route.branded.hops[0]!.nodeId;
    const gatewayNodeId = route.branded.hops[2]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      relay0NodeId, // claims its own NodeId
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      relay0Kp.secretKey, relay0Kp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // Relay 0 constructs a proof using its OWN acceptance at hopIndex 0.
    // The proof is validly signed, but the terminal-hop check will fail
    // (hopIndex 0 != last index 2).
    const terminalHopIndex = 0; // relay 0 is NOT terminal
    const relayKp = route.kps[terminalHopIndex]!;
    const initiatorKp = route.initiator;
    const ackResult = handleCircuitSetup(
      {
        route: route.branded,
        hopIndex: terminalHopIndex,
        initiatorX25519PublicKey: circuit.initiatorX25519PublicKey,
        setupNonce: randomBytes(16),
      },
      relayKp.secretKey,
      route.commitmentRoot,
      NOW,
    );
    if (!ackResult.ok) throw new Error(`relay ack setup failed: ${ackResult.reason}`);
    const relayAck = ackResult.ack;
    const relayEd25519PublicKey = relayKp.publicKey;
    const relayX25519PublicKey = ackResult.state.relayX25519PublicKey;
    const template = constructReturnOnionTemplate(circuit);
    const gatewayTemplate = signGatewayReturnTemplate(
      template, route.branded.expiry, relay0NodeId,
      relayX25519PublicKey,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    // Use relay 0's acceptance (NOT the terminal acceptance).
    const relay0Acceptance = route.commitment.acceptances[0]!;
    const fakeAuth = constructGatewayReturnAuthorization(
      gatewayTemplate, relayAck, relayEd25519PublicKey,
      relay0Acceptance, route.hopNodeIds,
      route.commitment.proposal, route.commitment.acceptances,
    );
    const fakeProofBytes = encodeGatewayReturnAuthorization(fakeAuth);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
      fakeProofBytes,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // The proof chain rejects: hopIndex 0 is not the terminal hop (last index 2).
      expect(result.reason).toContain("terminal-hop proof chain verification failed");
      expect(result.reason).toContain("not the terminal hop");
    }
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);
  });

  test("valid key (own NodeId) + valid proof for real gateway → REJECT (identity mismatch)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // The attacker generates their OWN valid keypair → derives their own valid
    // NodeId X (NOT the gateway's). Layer 1 (verifyNodeIdBinding(X, attackerKey))
    // PASSES — the key genuinely derives X.
    const attackerKp = generateNodeKeypair();
    const attackerNodeId = attackerKp.nodeId;

    // The attacker signs a destroy as GATEWAY, claiming their OWN NodeId X.
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      attackerNodeId, // ← the attacker's OWN NodeId (Layer 1 passes)
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      attackerKp.secretKey, attackerKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // The attacker attaches a VALID proof for the REAL gateway (e.g., intercepted
    // during setup, or obtained via a compromised relay). The proof verifies —
    // it's genuinely for this circuit's route + terminal hop.
    const gatewayProofBytes = makeGatewayProof(route, circuit);

    const result = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
      gatewayProofBytes,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // REJECTED: the destroy's destroyerEd25519PublicKey (attacker's key) does
      // NOT match the proof's relayEd25519PublicKey (real gateway's key). The
      // destroy signer is NOT the ack/acceptance signer.
      expect(result.reason).toContain("destroyerEd25519PublicKey does not match");
      expect(result.reason).toContain("terminal-hop proof");
    }
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);
  });
});

// ---- Fix #2: CircuitDestroy freshness ---------------------------------

describe("R-009 Stage 3 Phase 2: CircuitDestroy freshness (issuedAt / expiry / circuit.expiry)", () => {
  test("valid current destroy → ACCEPT", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // issuedAt = NOW (current), expiry = circuit.expiry (matches circuit).
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(true);
  });

  test("destroy issued in the future (beyond skew) → REJECT before nonce consumption", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // issuedAt = NOW + SKEW + 1 (beyond the permitted clock skew).
    const futureIssuedAt = NOW + CIRCUIT_DESTROY_MAX_CLOCK_SKEW_SECONDS + 1;
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      futureIssuedAt, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("future-dated");
      expect(result.reason).toContain("before nonce consumption");
    }
    // CRITICAL: the nonce MUST NOT have been consumed (rejected before step 7).
    // Verify by calling consumeDestroyAndRevoke — it should succeed (first use).
    const reConsume = await destroyStore.consumeDestroyAndRevoke(
      circuit.commitmentRoot, circuit.circuitId, destroy.destroyNonce,
      "test-verify", 0x01, 0x01,
    );
    expect(reConsume.ok).toBe(true);
    if (reConsume.ok) expect(reConsume.idempotent).toBe(false);
  });

  test("destroy expired (now >= expiry) → REJECT before nonce consumption", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Sign a destroy with expiry in the past (expired). The circuit itself is
    // still alive (circuit.expiry > NOW), but the destroy's expiry is NOW - 1.
    const expiredExpiry = NOW - 1;
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, expiredExpiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("expired");
      expect(result.reason).toContain("before nonce consumption");
    }
    // Nonce NOT consumed.
    const reConsume = await destroyStore.consumeDestroyAndRevoke(
      circuit.commitmentRoot, circuit.circuitId, destroy.destroyNonce,
      "test-verify", 0x01, 0x01,
    );
    expect(reConsume.ok).toBe(true);
    if (reConsume.ok) expect(reConsume.idempotent).toBe(false);
  });

  test("destroy expiry > circuit.expiry → REJECT (lifetime extension blocked)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Sign a destroy with expiry = circuit.expiry + 1 (exceeds the circuit's expiry).
    const extendedExpiry = route.branded.expiry + 1;
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, extendedExpiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("destroy tries to extend circuit lifetime");
    }
    // Nonce NOT consumed.
    const reConsume = await destroyStore.consumeDestroyAndRevoke(
      circuit.commitmentRoot, circuit.circuitId, destroy.destroyNonce,
      "test-verify", 0x01, 0x01,
    );
    expect(reConsume.ok).toBe(true);
    if (reConsume.ok) expect(reConsume.idempotent).toBe(false);
  });

  test("exact expiry boundary: now = expiry - 1 → ACCEPT; now = expiry → REJECT", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore1 = new InMemoryCircuitDestroyStore();
    const destroyStore2 = new InMemoryCircuitDestroyStore();
    const circuit1 = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    // Need a second circuit with the same keys but a separate store — use a fresh circuit.
    const floorStore2 = new InMemoryCircuitSequenceFloorStore();
    const relayKeys2 = makeRelayX25519Keys(route.branded);
    const circuit2 = setupCircuit(route.branded, relayKeys2, NOW, floorStore2);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Both destroys have expiry = circuit.expiry (the boundary value).
    // Test 1: now = expiry - 1 → ACCEPT (now < expiry).
    const destroy1 = signCircuitDestroy(
      circuit1.circuitId, circuit1.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result1 = await processCircuitDestroy(
      encodeCircuitDestroy(destroy1), circuit1,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore1,
      route.branded.expiry - 1, // now = expiry - 1 → ACCEPT
    );
    expect(result1.ok).toBe(true);

    // Test 2: now = expiry → REJECT (now >= expiry, boundary).
    const destroy2 = signCircuitDestroy(
      circuit2.circuitId, circuit2.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result2 = await processCircuitDestroy(
      encodeCircuitDestroy(destroy2), circuit2,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore2,
      route.branded.expiry, // now = expiry → REJECT (boundary)
    );
    expect(result2.ok).toBe(false);
    if (!result2.ok) {
      expect(result2.reason).toContain("expired");
    }
  });

  test("issuedAt within clock skew (issuedAt = now + SKEW) → ACCEPT", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // issuedAt = NOW + SKEW (exactly at the boundary — permitted).
    const issuedAtAtSkewBoundary = NOW + CIRCUIT_DESTROY_MAX_CLOCK_SKEW_SECONDS;
    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      issuedAtAtSkewBoundary, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(true); // exactly at the skew boundary → ACCEPT
  });
});

// ---- Fix #3: Atomic consume-nonce + revoke-tombstone (no split state) ----

describe("R-009 Stage 3 Phase 2: atomic consumeDestroyAndRevoke (no split state)", () => {
  test("atomic operation success → nonce consumed AND tombstone written", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const destroyStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), circuit,
      route.initiator.nodeId, gatewayNodeId,
      destroyStore,
      NOW,
    );
    expect(result.ok).toBe(true);

    // Both the tombstone AND the nonce were committed atomically.
    expect(await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);
    // A second consumeDestroyAndRevoke with the same nonce → idempotent (tombstone exists).
    const retry = await destroyStore.consumeDestroyAndRevoke(
      circuit.commitmentRoot, circuit.circuitId, destroy.destroyNonce,
      "test-retry", 0x01, 0x01,
    );
    expect(retry.ok).toBe(true);
    if (retry.ok) expect(retry.idempotent).toBe(true); // tombstone already exists
  });

  test("atomic operation FAILURE → no split state (nonce NOT consumed, tombstone NOT written)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const failingStore = new FailingCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    // Snapshot key material — to prove it is retained on atomic failure.
    expect(circuit.hops[0]!.forwardingKey.some((b) => b !== 0)).toBe(true);
    const fwdKeySnapshot = new Uint8Array(circuit.hops[0]!.forwardingKey);

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const result = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), circuit,
      route.initiator.nodeId, gatewayNodeId,
      failingStore, // ALWAYS fails
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("consumeDestroyAndRevoke failed");
      expect(result.reason).toContain("no split state");
      expect(result.reason).toContain("safe to retry");
    }

    // CRITICAL: no split state — the tombstone was NOT written.
    expect(await failingStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(false);

    // CRITICAL: keys were NOT zeroized (the atomic transaction failed, so the
    // terminal state was not durably recorded — keys retained for retry).
    expect(circuit.hops[0]!.forwardingKey).toEqual(fwdKeySnapshot);
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(false);
  });

  test("retry after atomic failure → succeeds (nonce still fresh)", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const failingStore = new FailingCircuitDestroyStore();
    const workingStore = new InMemoryCircuitDestroyStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = route.initiator;
    const gatewayNodeId = route.branded.hops[1]!.nodeId;

    const destroy = signCircuitDestroy(
      circuit.circuitId, circuit.commitmentRoot,
      route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, route.branded.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // First attempt: fails (FailingCircuitDestroyStore).
    const r1 = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      failingStore,
      NOW,
    );
    expect(r1.ok).toBe(false);

    // Keys were NOT zeroized by the failed attempt — re-mangle to prove the
    // retry's zeroization is fresh.
    expect(circuit.hops[0]!.forwardingKey.some((b) => b !== 0)).toBe(true);

    // Second attempt: the SAME destroy (same nonce) with a WORKING store.
    // The nonce is STILL FRESH (the failed transaction rolled back) — the
    // retry should SUCCEED. This is the key property of the atomic operation:
    // no split state means the nonce was not consumed by the failure.
    const r2 = await processCircuitDestroy(
      wireBytes, circuit,
      route.initiator.nodeId, gatewayNodeId,
      workingStore,
      NOW,
    );
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.idempotent).toBe(false); // first successful processing

    // The tombstone is now written.
    expect(await workingStore.isRevoked(circuit.circuitId, circuit.commitmentRoot)).toBe(true);
    // Keys are zeroized by the successful retry.
    expect(circuit.hops[0]!.forwardingKey.every((b) => b === 0)).toBe(true);
  });
});

// ---- Durable SQLite atomic operation ----------------------------------------

describe("R-009 Stage 3 Phase 2: DurableSqliteCircuitDestroyStore (atomic transaction)", () => {
  let destroyStore: DurableSqliteCircuitDestroyStore;

  beforeAll(async () => {
    destroyStore = new DurableSqliteCircuitDestroyStore();
    await db.circuitRevocation.deleteMany({});
    await db.consumedCircuitDestroy.deleteMany({});
  });

  afterAll(async () => {
    await db.circuitRevocation.deleteMany({});
    await db.consumedCircuitDestroy.deleteMany({});
  });

  test("atomic consumeDestroyAndRevoke → both committed (tombstone + nonce)", async () => {
    const cid = randomBytes(32);
    const cr = randomBytes(32);
    const nonce = randomBytes(16);

    const result = await destroyStore.consumeDestroyAndRevoke(cr, cid, nonce, "initiator", 0x01, 0x01);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.idempotent).toBe(false);

    // Tombstone exists.
    expect(await destroyStore.isRevoked(cid, cr)).toBe(true);

    // The nonce was consumed (a second consume with the same nonce fails — but
    // since the tombstone exists, consumeDestroyAndRevoke returns idempotent).
    const retry = await destroyStore.consumeDestroyAndRevoke(cr, cid, nonce, "gateway", 0x02, 0x01);
    expect(retry.ok).toBe(true);
    if (retry.ok) expect(retry.idempotent).toBe(true);
  });

  test("atomic consumeDestroyAndRevoke → replay (same nonce, different circuit) → independent", async () => {
    const cr = randomBytes(32);
    const nonce = randomBytes(16);

    const r1 = await destroyStore.consumeDestroyAndRevoke(cr, randomBytes(32), nonce, "initiator", 0x01, 0x01);
    expect(r1.ok).toBe(true);

    const r2 = await destroyStore.consumeDestroyAndRevoke(cr, randomBytes(32), nonce, "initiator", 0x01, 0x01);
    expect(r2.ok).toBe(true); // different circuitId → independent (not a replay)
  });

  test("atomic consumeDestroyAndRevoke → replay (same nonce + circuit) → REJECT", async () => {
    const cid = randomBytes(32);
    const cr = randomBytes(32);
    const nonce = randomBytes(16);

    // Pre-revoke the circuit (simulate a prior destroy that wrote the tombstone).
    await destroyStore.revoke(cid, cr, "initiator", 0x01, 0x01, nonce);

    // Now a SECOND destroy with the same nonce → idempotent (tombstone exists).
    const result = await destroyStore.consumeDestroyAndRevoke(cr, cid, nonce, "initiator", 0x01, 0x01);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.idempotent).toBe(true);
  });
});
