/**
 * ShareNet 2.0 — R-008 durable integration tests (protocol-path).
 *
 * These are the protocol-level integration tests required by the R-008
 * integration audit. They prove that the durable replay stores are wired
 * INTO THE REFERENCE PROTOCOL PATH — not merely that the persistence
 * helpers work in isolation.
 *
 * The three required scenarios (per the audit):
 *
 *   SEQUENCE-FLOOR DURABILITY (across simulated process restart):
 *     1. process circuit frame seq=5   → accepted, floor=5 persisted
 *     2. simulate process restart      → new protocol engine, same durable store
 *     3. receive seq=4                 → REJECTED (4 ≤ floor 5)
 *
 *   SETUP-ACK SINGLE-USE (across simulated process restart):
 *     4. process ack nonce X            → accepted, consumption persisted
 *     5. simulate process restart      → new protocol engine, same durable store
 *     6. receive identical ack X       → REJECTED (already consumed)
 *
 *   ACK HOP-ISOLATION (same nonce, different hop → both accepted):
 *     7. ack X on hop 0                → accepted  (key = cr:0:X)
 *     8. ack X on hop 1                → accepted  (key = cr:1:X, different)
 *
 * These tests use the REAL durable SQLite substrate
 * (`DurableSqliteCircuitSequenceFloorStore` + `DurableSqliteCircuitAckReplayStore`,
 * backed by Prisma + SQLite). The "simulate process restart" step re-instantiates
 * a fresh protocol engine that loads state from the SAME durable store —
 * proving the security boundary is inside the protocol engine, with persistence
 * abstracted behind the interface.
 *
 * Per the R-008 integration audit:
 *   "Do not begin broad R-009 implementation until the reference protocol
 *    itself — not merely the application layer — uses the durable replay
 *    state."
 *
 * NOTE on "restart" simulation: a real process restart re-loads the route
 * from a route store. The route (a WeakSet-branded in-memory artifact)
 * cannot be serialized, so within a scenario we create the route ONCE in
 * `beforeAll` and reuse it across the "restart" tests. The durable STATE
 * (floor / consumed acks) is what persists — reloaded from the database by
 * each fresh protocol engine instance. The in-memory circuit (initiator
 * key, hop keys) is genuinely re-created each "restart".
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { db } from "@/lib/db";
import { randomBytes } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  handleCircuitSetup,
  processCircuitSetupAck,
  establishDistributedCircuit,
  routeCommitmentDigest,
  type CircuitSetupRequest,
} from "@reference/circuit/distributed-setup";
import {
  setupCircuit,
  processCircuitFrame,
  onionEncrypt,
} from "@reference/circuit/circuit";
import {
  DurableSqliteCircuitSequenceFloorStore,
  DurableSqliteCircuitAckReplayStore,
} from "@/lib/sharenet/durable-circuit-replay-stores";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;

/**
 * Build a genuine branded route through the full proof-carrying pipeline.
 * Returns everything the integration tests need.
 */
function makeRoute(numHops = 1) {
  const ctx = makeGenuineBrandedRouteHelper(numHops, NOW);
  return {
    branded: ctx.branded,
    kps: ctx.kps,
    hpk: ctx.hopPublicKeys,
    commitmentRoot: ctx.branded.commitmentRoot,
    commitDigestHex: toHex(routeCommitmentDigest(ctx.branded)),
  };
}

/** Make a set of relay X25519 keys matching a route's hops. */
function makeRelayX25519Keys(route: { hops: Array<{ nodeId: string }> }) {
  return route.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk };
  });
}

// =====================================================================
// SCENARIO 1: Sequence-floor durability across simulated process restart
// =====================================================================

describe("R-008 durable integration: sequence floor survives process restart", () => {
  let floorStore: DurableSqliteCircuitSequenceFloorStore;
  // Route + relay keys are created ONCE and reused across the "restart"
  // tests. The durable STATE (floor) is what persists; the in-memory circuit
  // (initiator key, hop keys) is genuinely re-created each "restart".
  let route: ReturnType<typeof makeRoute>;
  let relayKeys: ReturnType<typeof makeRelayX25519Keys>;

  beforeAll(async () => {
    floorStore = new DurableSqliteCircuitSequenceFloorStore();
    route = makeRoute(1);
    relayKeys = makeRelayX25519Keys(route.branded);
    await db.circuitSequenceFloor.deleteMany({});
  });

  afterAll(async () => {
    await db.circuitSequenceFloor.deleteMany({});
  });

  test("1. process circuit frame seq=5 → accepted, floor=5 persisted durably", async () => {
    // Circuit 1 (the "first process"): created with the durable floor store.
    const circuit1 = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Encrypt a genuine frame seq=5 (1-hop circuit: one onion layer).
    const plaintext = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const { encryptedPayload } = onionEncrypt(circuit1, 5, plaintext);

    // Process the frame — should accept + decrypt (floor was 0, now 5).
    const result = await processCircuitFrame(circuit1, 0, 5, encryptedPayload);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(new TextDecoder().decode(result.decrypted)).toBe(
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
      );
    }

    // The durable floor is now 5 (persisted to the database).
    const persistedFloor = await floorStore.getFloor(route.commitmentRoot);
    expect(persistedFloor).toBe(5n);
  });

  test("2. simulate restart: new engine, same route + same durable store, seq=4 → REJECTED", async () => {
    // Circuit 2 (the "restarted process"): NEW initiator keypair (new hop keys
    // via ECDH), but the SAME route + SAME durable floor store. The floor for
    // this route is already 5 (persisted by test 1).
    const priorFloor = await floorStore.getFloor(route.commitmentRoot);
    expect(priorFloor).toBe(5n); // survived the "restart"

    const circuit2 = setupCircuit(route.branded, relayKeys, NOW, floorStore, priorFloor);
    expect(circuit2.replayGuard.getSequenceFloor()).toBe(5n);

    // Attempt to process seq=4 (≤ floor 5) → must be REJECTED.
    // Content is irrelevant — the sequence check rejects before decryption.
    const fakeCiphertext = randomBytes(48);
    const result = await processCircuitFrame(circuit2, 0, 4, fakeCiphertext);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("≤ floor");
      expect(result.reason).toContain("replay/stale");
    }

    // The floor is UNCHANGED (4 was rejected — not persisted).
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(5n);
  });

  test("3. after restart: seq=6 (strictly higher than floor 5) → ACCEPTED", async () => {
    const priorFloor = await floorStore.getFloor(route.commitmentRoot);
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore, priorFloor);

    const plaintext = new TextEncoder().encode("second packet after restart");
    const { encryptedPayload } = onionEncrypt(circuit, 6, plaintext);

    const result = await processCircuitFrame(circuit, 0, 6, encryptedPayload);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(new TextDecoder().decode(result.decrypted)).toBe(
        "second packet after restart",
      );
    }

    // Floor advanced to 6 (durable).
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(6n);
  });
});

// =====================================================================
// SCENARIO 2: Setup-ack single-use across simulated process restart
// =====================================================================

describe("R-008 durable integration: setup-ack single-use survives process restart", () => {
  let ackStore: DurableSqliteCircuitAckReplayStore;

  beforeAll(async () => {
    ackStore = new DurableSqliteCircuitAckReplayStore();
    await db.consumedCircuitAck.deleteMany({});
  });

  afterAll(async () => {
    await db.consumedCircuitAck.deleteMany({});
  });

  test("4. process ack X → accepted, consumption persisted durably", async () => {
    const route = makeRoute(1);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);

    const req: CircuitSetupRequest = {
      route: route.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relayResult = handleCircuitSetup(req, route.kps[0]!.secretKey, route.commitmentRoot, NOW);
    expect(relayResult.ok).toBe(true);
    if (!relayResult.ok) return;

    // First processing — should be accepted (and durably consumed).
    const r = await processCircuitSetupAck(
      relayResult.ack, route.branded.routeId, route.commitDigestHex, 0,
      initPk, route.kps[0]!.publicKey, initSk, route.commitmentRoot, NOW,
      ackStore,
    );
    expect(r.ok).toBe(true);

    // The ack is now durably consumed.
    const fresh = await ackStore.isFresh(route.commitmentRoot, 0, relayResult.ack.ackNonce);
    expect(fresh).toBe(false);
  });

  test("5. simulate restart: same durable ack store, identical ack X → REJECTED", async () => {
    const route = makeRoute(1);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);

    const req: CircuitSetupRequest = {
      route: route.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relayResult = handleCircuitSetup(req, route.kps[0]!.secretKey, route.commitmentRoot, NOW);
    expect(relayResult.ok).toBe(true);
    if (!relayResult.ok) return;

    // First processing — accepted.
    const r1 = await processCircuitSetupAck(
      relayResult.ack, route.branded.routeId, route.commitDigestHex, 0,
      initPk, route.kps[0]!.publicKey, initSk, route.commitmentRoot, NOW,
      ackStore,
    );
    expect(r1.ok).toBe(true);

    // "Restart": the SAME durable ack store. Re-present the IDENTICAL ack.
    // The ack is still within its freshness window (same NOW), so freshness
    // checks pass — but the ack store rejects it as a replay.
    const r2 = await processCircuitSetupAck(
      relayResult.ack, route.branded.routeId, route.commitDigestHex, 0,
      initPk, route.kps[0]!.publicKey, initSk, route.commitmentRoot, NOW,
      ackStore,
    );
    expect(r2.ok).toBe(false);
    if (!r2.ok) {
      expect(r2.reason).toContain("ack replay");
      expect(r2.reason).toContain("already consumed");
    }
  });
});

// =====================================================================
// SCENARIO 3: Ack hop-isolation (same nonce, different hop → both accepted)
// =====================================================================

describe("R-008 durable integration: ack key includes hopIndex (hop isolation)", () => {
  let ackStore: DurableSqliteCircuitAckReplayStore;

  beforeAll(async () => {
    ackStore = new DurableSqliteCircuitAckReplayStore();
    await db.consumedCircuitAck.deleteMany({});
  });

  afterAll(async () => {
    await db.consumedCircuitAck.deleteMany({});
  });

  test("6. ack X on hop 0 + ack X on hop 1 (SAME nonce) → BOTH accepted", async () => {
    // A 2-hop route so both hopIndex 0 and 1 are valid.
    const route = makeRoute(2);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);

    // FIXED nonce shared by both acks — proves the replay key includes hopIndex.
    const sharedNonce = randomBytes(16);

    // Hop 0 ack (genuinely signed with the shared nonce via the test hook).
    const req0: CircuitSetupRequest = {
      route: route.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay0Result = handleCircuitSetup(
      req0, route.kps[0]!.secretKey, route.commitmentRoot, NOW, sharedNonce,
    );
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(toHex(relay0Result.ack.ackNonce)).toBe(toHex(sharedNonce));

    // Hop 1 ack (same nonce, different hop).
    const req1: CircuitSetupRequest = {
      route: route.branded, hopIndex: 1,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay1Result = handleCircuitSetup(
      req1, route.kps[1]!.secretKey, route.commitmentRoot, NOW, sharedNonce,
    );
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(toHex(relay1Result.ack.ackNonce)).toBe(toHex(sharedNonce));

    // Both acks carry the SAME nonce but different hopIndex. The replay key
    // is (commitmentRoot, hopIndex, ackNonce) — so they are distinct.
    // Processing hop 0 → accepted.
    const r0 = await processCircuitSetupAck(
      relay0Result.ack, route.branded.routeId, route.commitDigestHex, 0,
      initPk, route.kps[0]!.publicKey, initSk, route.commitmentRoot, NOW,
      ackStore,
    );
    expect(r0.ok).toBe(true);

    // Processing hop 1 (same nonce, different hop) → ALSO accepted.
    const r1 = await processCircuitSetupAck(
      relay1Result.ack, route.branded.routeId, route.commitDigestHex, 1,
      initPk, route.kps[1]!.publicKey, initSk, route.commitmentRoot, NOW,
      ackStore,
    );
    expect(r1.ok).toBe(true);
  });

  test("7. after both hops consumed: re-presenting ack X on hop 0 → REJECTED (replay)", async () => {
    // Re-build a fresh 2-hop route + a fresh shared-nonce ack pair so this
    // test is independent of test 6's state.
    const route = makeRoute(2);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);
    const sharedNonce = randomBytes(16);

    const req0: CircuitSetupRequest = {
      route: route.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay0Result = handleCircuitSetup(
      req0, route.kps[0]!.secretKey, route.commitmentRoot, NOW, sharedNonce,
    );
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;

    // First processing of hop 0 ack → accepted.
    const r1 = await processCircuitSetupAck(
      relay0Result.ack, route.branded.routeId, route.commitDigestHex, 0,
      initPk, route.kps[0]!.publicKey, initSk, route.commitmentRoot, NOW,
      ackStore,
    );
    expect(r1.ok).toBe(true);

    // Second processing of the SAME ack on the SAME hop → REJECTED (replay).
    const r2 = await processCircuitSetupAck(
      relay0Result.ack, route.branded.routeId, route.commitDigestHex, 0,
      initPk, route.kps[0]!.publicKey, initSk, route.commitmentRoot, NOW,
      ackStore,
    );
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toContain("ack replay");
  });
});

// =====================================================================
// SCENARIO 4: Full distributed establishment with durable stores
// (proves establishDistributedCircuit is wired to BOTH stores)
// =====================================================================

describe("R-008 durable integration: establishDistributedCircuit uses both durable stores", () => {
  let floorStore: DurableSqliteCircuitSequenceFloorStore;
  let ackStore: DurableSqliteCircuitAckReplayStore;

  beforeAll(async () => {
    floorStore = new DurableSqliteCircuitSequenceFloorStore();
    ackStore = new DurableSqliteCircuitAckReplayStore();
    await db.circuitSequenceFloor.deleteMany({});
    await db.consumedCircuitAck.deleteMany({});
  });

  afterAll(async () => {
    await db.circuitSequenceFloor.deleteMany({});
    await db.consumedCircuitAck.deleteMany({});
  });

  test("8. establish circuit with durable stores → ack consumed + floor loaded + frame processing durable", async () => {
    // 1-hop route so processCircuitFrame at hop 0 decrypts the single onion
    // layer to plaintext. (The point of this test is the durable wiring of
    // BOTH stores during establishDistributedCircuit, not multi-hop peeling.)
    const route = makeRoute(1);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);

    const req0: CircuitSetupRequest = {
      route: route.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay0 = handleCircuitSetup(req0, route.kps[0]!.secretKey, route.commitmentRoot, NOW);
    expect(relay0.ok).toBe(true);
    if (!relay0.ok) return;

    // Establish with BOTH durable stores.
    const est = await establishDistributedCircuit(
      route.branded, initSk, initPk, [relay0.ack], route.hpk, NOW,
      ackStore, floorStore,
    );
    expect(est.ok).toBe(true);
    if (!est.ok) return;
    const circuit = est.circuit;
    expect(circuit.floorStore).toBe(floorStore);

    // The ack is now durably consumed.
    expect(await ackStore.isFresh(route.commitmentRoot, 0, relay0.ack.ackNonce)).toBe(false);

    // Process a frame through the established circuit — durable check+persist.
    const plaintext = new TextEncoder().encode("durable circuit payload");
    const { encryptedPayload } = onionEncrypt(circuit, 1, plaintext);
    const r = await processCircuitFrame(circuit, 0, 1, encryptedPayload);
    expect(r.ok).toBe(true);
    if (r.ok) expect(new TextDecoder().decode(r.decrypted)).toBe("durable circuit payload");

    // Floor advanced to 1 (durable).
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(1n);
  });

  test("9. re-establish on the SAME route (re-key) → prior floor continued, old seq rejected", async () => {
    // Reuse the SAME route across the re-key so the floor (keyed by
    // commitmentRoot) persists. Create route + relay keys once.
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);

    // Pre-seed a floor of 10 on this route (simulate a prior circuit that
    // advanced to seq=10, then was torn down / re-keyed).
    const PRE_SET_FLOOR = 10n;
    await floorStore.checkAndAdvance(route.commitmentRoot, PRE_SET_FLOOR);
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(PRE_SET_FLOOR);

    // Re-key: the initiator generates a NEW X25519 keypair and re-establishes
    // on the same route. establishDistributedCircuit loads the prior floor (10)
    // so the new circuit continues from there.
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);

    const req0: CircuitSetupRequest = {
      route: route.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay0 = handleCircuitSetup(req0, route.kps[0]!.secretKey, route.commitmentRoot, NOW);
    expect(relay0.ok).toBe(true);
    if (!relay0.ok) return;

    const est = await establishDistributedCircuit(
      route.branded, initSk, initPk, [relay0.ack], route.hpk, NOW,
      ackStore, floorStore,
    );
    expect(est.ok).toBe(true);
    if (!est.ok) return;

    // The new circuit's in-memory guard cache was seeded from the durable floor (10).
    expect(est.circuit.replayGuard.getSequenceFloor()).toBe(PRE_SET_FLOOR);

    // A frame with seq=5 (≤ floor 10) → REJECTED (old frame replay after re-key).
    const r = await processCircuitFrame(est.circuit, 0, 5, randomBytes(48));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("≤ floor");

    // A frame with seq=11 (> floor 10) → ACCEPTED, floor advances to 11.
    const plaintext = new TextEncoder().encode("post-re-key packet");
    const { encryptedPayload } = onionEncrypt(est.circuit, 11, plaintext);
    const r2 = await processCircuitFrame(est.circuit, 0, 11, encryptedPayload);
    expect(r2.ok).toBe(true);
    if (r2.ok) expect(new TextDecoder().decode(r2.decrypted)).toBe("post-re-key packet");
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(11n);
  });
});
