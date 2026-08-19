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
import { processCircuitWireFrame } from "@reference/circuit/forwarding";
import {
  signCircuitDestroy,
  verifyCircuitDestroy,
  encodeCircuitDestroy,
  decodeCircuitDestroy,
  DESTROYER_ROLE_INITIATOR,
  DESTROYER_ROLE_GATEWAY,
  DESTROY_REASON_OPERATOR_INITIATED,
  DESTROY_REASON_CIRCUIT_EXPIRED,
  type CircuitDestroy,
} from "@reference/circuit/destroy";
import {
  InMemoryCircuitSequenceFloorStore,
  InMemoryCircuitRevocationStore,
  InMemoryCircuitDestroyReplayStore,
} from "@reference/circuit/replay-stores";
import { db } from "@/lib/db";
import { DurableSqliteCircuitRevocationStore, DurableSqliteCircuitDestroyReplayStore } from "@/lib/sharenet/durable-circuit-replay-stores";
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
  };
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

    // now > expiry → REJECT.
    const result = await processCircuitWireFrame(circuit, 0, wireBytes, undefined, route.branded.expiry + 1);
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

    const result = await processCircuitWireFrame(circuit, 0, wireBytes, undefined, NOW);
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
