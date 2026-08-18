/**
 * ShareNet 2.0 — R-008 durable persistence + ack replay tests.
 *
 * Per the R-008 final hardening directive:
 *
 *   "1. Replace the in-memory SequenceFloorStore with durable persistence.
 *    2. Add setup-ack replay consumption: (commitmentRoot, hopIndex, ackNonce)
 *       must be single-use.
 *    3. Add adversarial tests for:
 *       process restart → old sequence still rejected
 *       same ack twice → second rejected
 *       same ack on different hop → rejected (different key)
 *       fresh distinct ack → accepted"
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { db } from "@/lib/db";
import {
  checkAndUpdateDurableCircuitFloor,
  getDurableCircuitFloor,
  updateDurableCircuitFloor,
  isAckFresh,
  consumeAck,
  purgeOldConsumedAcks,
} from "@/lib/sharenet/circuit-persistence";
import { DIRECTION_FORWARD } from "@reference/circuit/frame";

const ROUTE_A = "a".repeat(64); // commitment_root hex
const ROUTE_B = "b".repeat(64); // different route
const ACK_NONCE_1 = "01" + "02".repeat(15); // 16 bytes hex
const ACK_NONCE_2 = "03" + "04".repeat(15); // different nonce

// R-009 Stage 1: the durable floor namespace is now (commitmentRoot,
// hopIndex, direction) — receiver-local. These tests use hop 0 + FORWARD
// as the canonical receiver context; the "different route has its own
// floor" test additionally varies hopIndex/direction to exercise the
// receiver-local keying.
const HOP_0 = 0;
const HOP_1 = 1;

describe("R-008: Durable circuit sequence-floor persistence", () => {
  beforeAll(async () => {
    // Clean up any prior state
    await db.circuitSequenceFloor.deleteMany({});
    await db.consumedCircuitAck.deleteMany({});
  });

  afterAll(async () => {
    await db.circuitSequenceFloor.deleteMany({});
    await db.consumedCircuitAck.deleteMany({});
  });

  test("fresh route starts at floor 0", async () => {
    const floor = await getDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD);
    expect(floor).toBe(0n);
  });

  test("sequence 1 is accepted on fresh route", async () => {
    const result = await checkAndUpdateDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD, 1n);
    expect(result.ok).toBe(true);
  });

  test("sequence 1 again is rejected (replay) — durable persistence", async () => {
    const result = await checkAndUpdateDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD, 1n);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("replay/stale");
  });

  test("sequence 0 is rejected (lower than floor)", async () => {
    const result = await checkAndUpdateDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD, 0n);
    expect(result.ok).toBe(false);
  });

  test("sequence 5 is accepted (higher than floor)", async () => {
    const result = await checkAndUpdateDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD, 5n);
    expect(result.ok).toBe(true);
  });

  test("sequence 3 is rejected (lower than floor=5) — simulates process restart", async () => {
    // Simulate process restart: re-read the floor from the DB
    const floor = await getDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD);
    expect(floor).toBe(5n); // floor survived (not reset to 0)

    const result = await checkAndUpdateDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD, 3n);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("replay/stale");
  });

  test("different (route, hop, direction) has its own floor", async () => {
    // R-009 Stage 1: the namespace is (commitmentRoot, hopIndex, direction).
    // Different route → independent floor. Also exercise a different
    // (hop, direction) on ROUTE_A to prove the per-receiver keying.
    const floorB = await getDurableCircuitFloor(ROUTE_B, HOP_0, DIRECTION_FORWARD);
    expect(floorB).toBe(0n); // independent floor (different route)

    const result = await checkAndUpdateDurableCircuitFloor(ROUTE_B, HOP_0, DIRECTION_FORWARD, 10n);
    expect(result.ok).toBe(true);

    // ROUTE_A at (hop 0, FORWARD) is unchanged (5n from the prior test).
    const floorA = await getDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD);
    expect(floorA).toBe(5n); // route A unchanged

    // ROUTE_A at a DIFFERENT (hop, direction) is also independent — the
    // receiver-local keying means hop 1's forward floor is its own counter.
    const floorA_hop1 = await getDurableCircuitFloor(ROUTE_A, HOP_1, DIRECTION_FORWARD);
    expect(floorA_hop1).toBe(0n); // different (hop) → fresh floor
    const resultHop1 = await checkAndUpdateDurableCircuitFloor(ROUTE_A, HOP_1, DIRECTION_FORWARD, 7n);
    expect(resultHop1.ok).toBe(true);
  });

  test("updateDurableCircuitFloor directly sets the floor", async () => {
    const ok = await updateDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD, 100n);
    expect(ok).toBe(true);
    const floor = await getDurableCircuitFloor(ROUTE_A, HOP_0, DIRECTION_FORWARD);
    expect(floor).toBe(100n);
  });
});

describe("R-008: Setup-ack single-use consumption", () => {
  beforeAll(async () => {
    await db.consumedCircuitAck.deleteMany({});
  });

  afterAll(async () => {
    await db.consumedCircuitAck.deleteMany({});
  });

  test("fresh ack is accepted (first use)", async () => {
    const fresh = await isAckFresh(ROUTE_A, 0, ACK_NONCE_1);
    expect(fresh).toBe(true);

    const consumed = await consumeAck(ROUTE_A, 0, ACK_NONCE_1);
    expect(consumed).toBe(true); // first use — successfully consumed
  });

  test("same ack twice → second rejected (replay)", async () => {
    const fresh = await isAckFresh(ROUTE_A, 0, ACK_NONCE_1);
    expect(fresh).toBe(false); // already consumed

    const consumed = await consumeAck(ROUTE_A, 0, ACK_NONCE_1);
    expect(consumed).toBe(false); // duplicate — rejected
  });

  test("same ack on different hop → different key, accepted", async () => {
    // Same nonce but different hopIndex — different unique key
    const fresh = await isAckFresh(ROUTE_A, 1, ACK_NONCE_1);
    expect(fresh).toBe(true); // hop 1 hasn't consumed this nonce

    const consumed = await consumeAck(ROUTE_A, 1, ACK_NONCE_1);
    expect(consumed).toBe(true);
  });

  test("same ack on different route → different key, accepted", async () => {
    const fresh = await isAckFresh(ROUTE_B, 0, ACK_NONCE_1);
    expect(fresh).toBe(true); // different route

    const consumed = await consumeAck(ROUTE_B, 0, ACK_NONCE_1);
    expect(consumed).toBe(true);
  });

  test("fresh distinct ack → accepted", async () => {
    const fresh = await isAckFresh(ROUTE_A, 0, ACK_NONCE_2);
    expect(fresh).toBe(true);

    const consumed = await consumeAck(ROUTE_A, 0, ACK_NONCE_2);
    expect(consumed).toBe(true);
  });

  test("purge old consumed acks", async () => {
    // Purge acks older than 0 seconds (all should be purged)
    const count = await purgeOldConsumedAcks(0);
    expect(count).toBeGreaterThan(0);

    // Verify they're gone
    const fresh = await isAckFresh(ROUTE_A, 0, ACK_NONCE_1);
    expect(fresh).toBe(true); // purged — looks fresh again
  });
});
