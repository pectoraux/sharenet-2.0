/**
 * ShareNet 2.0 — R-009 Stage 2: durable gateway authorization replay tests.
 *
 * Tests the DurableSqliteGatewayAuthorizationReplayStore against the real
 * SQLite database. Proves single-use consumption survives process restart.
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { db } from "@/lib/db";
import { DurableSqliteGatewayAuthorizationReplayStore } from "@/lib/sharenet/durable-circuit-replay-stores";
import { randomBytes } from "@reference/identity/keys";

const ROUTE_A = "a".repeat(64);
const ROUTE_B = "b".repeat(64);
const CIRCUIT_A = "c".repeat(64);
const CIRCUIT_B = "d".repeat(64);
const NONCE_1 = "01" + "02".repeat(15);
const NONCE_2 = "03" + "04".repeat(15);

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe("R-009 Stage 2: durable gateway authorization replay (SQLite)", () => {
  let store: DurableSqliteGatewayAuthorizationReplayStore;

  beforeAll(async () => {
    store = new DurableSqliteGatewayAuthorizationReplayStore();
    await db.consumedGatewayAuthorization.deleteMany({});
  });

  afterAll(async () => {
    await db.consumedGatewayAuthorization.deleteMany({});
  });

  test("first authorization → ACCEPT", async () => {
    const ok = await store.consume(hexToBytes(ROUTE_A), hexToBytes(CIRCUIT_A), hexToBytes(NONCE_1));
    expect(ok).toBe(true);
  });

  test("exact replay → REJECT", async () => {
    const ok = await store.consume(hexToBytes(ROUTE_A), hexToBytes(CIRCUIT_A), hexToBytes(NONCE_1));
    expect(ok).toBe(false);
  });

  test("different circuitId → independent ACCEPT", async () => {
    const ok = await store.consume(hexToBytes(ROUTE_A), hexToBytes(CIRCUIT_B), hexToBytes(NONCE_1));
    expect(ok).toBe(true);
  });

  test("different ackNonce → independent ACCEPT", async () => {
    const ok = await store.consume(hexToBytes(ROUTE_A), hexToBytes(CIRCUIT_A), hexToBytes(NONCE_2));
    expect(ok).toBe(true);
  });

  test("different route → independent ACCEPT", async () => {
    const ok = await store.consume(hexToBytes(ROUTE_B), hexToBytes(CIRCUIT_A), hexToBytes(NONCE_1));
    expect(ok).toBe(true);
  });

  test("process restart simulation: new store instance, same DB → replay REJECTED", async () => {
    // Simulate a restart: create a NEW store instance (same DB).
    const restartedStore = new DurableSqliteGatewayAuthorizationReplayStore();
    // The authorization from test 1 was already consumed — the new store should reject it.
    const ok = await restartedStore.consume(hexToBytes(ROUTE_A), hexToBytes(CIRCUIT_A), hexToBytes(NONCE_1));
    expect(ok).toBe(false); // rejected — the DB remembers
  });

  test("concurrent double-consume → exactly one ACCEPT", async () => {
    // Fire two concurrent consume calls with the same key.
    // SQLite serializes writes, so exactly one should succeed.
    const [r1, r2] = await Promise.all([
      store.consume(hexToBytes(ROUTE_B), hexToBytes(CIRCUIT_B), hexToBytes(NONCE_2)),
      store.consume(hexToBytes(ROUTE_B), hexToBytes(CIRCUIT_B), hexToBytes(NONCE_2)),
    ]);
    // Exactly one should be true.
    expect(r1 !== r2).toBe(true); // one true, one false
  });
});
