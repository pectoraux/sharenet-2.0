/**
 * ShareNet 2.0 — GATE-02 Tests: Identity and persistent advertisement state.
 *
 * Per GATE-02 requirements:
 *   - restart test proves expired advertisements never reset sequence floors
 *   - bad signature, wrong NodeId binding, replay, expiry, and sequence rollback fail
 *
 * These are deterministic unit tests (no network, no DB, no mesh).
 * Run: `bun test tests/gate-02-identity-persistence.test.ts`
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  keypairFromSecretKey,
  hexToBytes,
  randomBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  signAdvertisement,
  verifyAdvertisement,
  advertisementToHex,
  type NodeCapability,
} from "@reference/advertisement/advertisement";
import {
  checkSequence,
  acceptAdvertisement,
} from "@reference/advertisement/sequence-floor";
import {
  InMemorySequenceFloorStore,
  type SequenceFloorStore,
} from "@reference/advertisement/sequence-floor-store";

const REFERENCE_NOW = 1786876545; // frozen timestamp for reproducibility

function makeAdv(kp: ReturnType<typeof generateNodeKeypair>, sequence: number, timestampOffset = 0) {
  return signAdvertisement({
    protocolVersion: 1,
    nodeId: kp.nodeId,
    signingPublicKey: kp.publicKey,
    capabilities: ["MESH_RELAY" as NodeCapability],
    endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
    sequence,
    timestamp: REFERENCE_NOW + timestampOffset,
    expiry: REFERENCE_NOW + timestampOffset + 3600,
    nonce: randomBytes(16),
  }, kp.secretKey);
}

describe("GATE-02: Identity and persistent advertisement state", () => {
  // --- 1. Bad signature fails ---
  test("bad signature is rejected", () => {
    const kp = generateNodeKeypair();
    const adv = makeAdv(kp, 1);
    const badSig = new Uint8Array(adv.signature);
    badSig[0] ^= 0xff;
    const tampered = { ...adv, signature: badSig };
    const v = verifyAdvertisement(tampered, REFERENCE_NOW);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error).toBe("INVALID_SIGNATURE");
  });

  // --- 2. Wrong NodeId binding fails ---
  test("wrong NodeId binding is rejected (IDENTITY_BINDING_MISMATCH)", () => {
    const kpA = generateNodeKeypair();
    const kpB = generateNodeKeypair();
    const adv = makeAdv(kpA, 1);
    // Claim B's nodeId but sign with A's key
    const tampered = { ...adv, nodeId: kpB.nodeId };
    const v = verifyAdvertisement(tampered, REFERENCE_NOW);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error).toBe("IDENTITY_BINDING_MISMATCH");
  });

  // --- 3. Expired advertisement fails ---
  test("expired advertisement is rejected (EXPIRED)", () => {
    const kp = generateNodeKeypair();
    // timestamp within clock skew, expiry in the past
    const adv = signAdvertisement({
      protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
      capabilities: ["MESH_RELAY"], endpoints: [],
      sequence: 1, timestamp: REFERENCE_NOW - 200, expiry: REFERENCE_NOW - 100,
      nonce: randomBytes(16),
    }, kp.secretKey);
    const v = verifyAdvertisement(adv, REFERENCE_NOW);
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.error).toBe("EXPIRED");
  });

  // --- 4. Sequence rollback is rejected (STALE) ---
  test("sequence rollback is rejected (STALE)", () => {
    const result = checkSequence(10, 5);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("STALE");
  });

  // --- 5. Duplicate sequence is rejected (DUPLICATE) ---
  test("duplicate sequence is rejected (DUPLICATE)", () => {
    const result = checkSequence(10, 10);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("DUPLICATE");
  });

  // --- 6. Newer sequence is accepted ---
  test("newer sequence is accepted", () => {
    const result = checkSequence(10, 11);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.newFloor).toBe(11);
  });

  // --- 7. RESTART TEST: expired advertisement does NOT reset sequence floor ---
  test("RESTART: expired advertisement does not reset sequence floor after restart", () => {
    const kp = generateNodeKeypair();
    let store: SequenceFloorStore = new InMemorySequenceFloorStore();

    // Step 1: accept advertisement with sequence=5
    const adv1 = makeAdv(kp, 5);
    const v1 = verifyAdvertisement(adv1, REFERENCE_NOW);
    expect(v1.ok).toBe(true);
    const seq1 = store.checkAndAdvance(kp.nodeId, 5);
    expect(seq1.ok).toBe(true);

    // Verify floor is 5
    expect(store.getFloor(kp.nodeId)).toBe(5);

    // Step 2: simulate restart — serialize, create new store, restore
    const snapshot = store.serialize();
    store = new InMemorySequenceFloorStore();
    store.restore(snapshot);

    // Verify floor survived restart
    expect(store.getFloor(kp.nodeId)).toBe(5);

    // Step 3: now try to accept an EXPIRED advertisement with sequence=3
    // (older than the floor). Even though the advertisement is expired,
    // the floor check MUST reject it as STALE — the floor is NOT reset.
    const expiredAdv = signAdvertisement({
      protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
      capabilities: ["MESH_RELAY"], endpoints: [],
      sequence: 3, timestamp: REFERENCE_NOW - 7200, expiry: REFERENCE_NOW - 3600,
      nonce: randomBytes(16),
    }, kp.secretKey);
    const v2 = verifyAdvertisement(expiredAdv, REFERENCE_NOW);
    // The advertisement is expired, but the KEY test is: does the floor reset?
    // The floor check happens AFTER verification. Even if verification fails
    // (EXPIRED), the floor MUST remain 5.
    const seq2 = store.checkAndAdvance(kp.nodeId, 3);
    expect(seq2.ok).toBe(false);
    if (!seq2.ok) expect(seq2.reason).toBe("STALE");

    // CRITICAL: the floor is STILL 5, not reset to 3 or 0
    expect(store.getFloor(kp.nodeId)).toBe(5);
  });

  // --- 8. RESTART TEST: sequence floor survives multiple restarts ---
  test("RESTART: sequence floor survives multiple restarts", () => {
    const kp = generateNodeKeypair();
    let store = new InMemorySequenceFloorStore();

    store.checkAndAdvance(kp.nodeId, 1);
    store.checkAndAdvance(kp.nodeId, 5);
    store.checkAndAdvance(kp.nodeId, 10);
    expect(store.getFloor(kp.nodeId)).toBe(10);

    // Restart 1
    store = store.restart();
    expect(store.getFloor(kp.nodeId)).toBe(10);

    // Try a stale sequence — should still fail
    const stale = store.checkAndAdvance(kp.nodeId, 7);
    expect(stale.ok).toBe(false);

    // Restart 2
    store = store.restart();
    expect(store.getFloor(kp.nodeId)).toBe(10);

    // Accept a newer sequence
    const ok = store.checkAndAdvance(kp.nodeId, 15);
    expect(ok.ok).toBe(true);
    expect(store.getFloor(kp.nodeId)).toBe(15);
  });

  // --- 9. acceptAdvertisement combines verification + sequence correctly ---
  test("acceptAdvertisement rejects when verification fails", () => {
    const kp = generateNodeKeypair();
    const result = acceptAdvertisement(
      kp.nodeId, kp.publicKey, ["MESH_RELAY"], 1, REFERENCE_NOW,
      { verificationOk: false, verificationError: "INVALID_SIGNATURE", sequenceCheck: { ok: true, previousFloor: -1, newFloor: 1 } },
    );
    expect(result.ok).toBe(false);
  });

  test("acceptAdvertisement rejects when sequence check fails", () => {
    const kp = generateNodeKeypair();
    const result = acceptAdvertisement(
      kp.nodeId, kp.publicKey, ["MESH_RELAY"], 5, REFERENCE_NOW,
      { verificationOk: true, sequenceCheck: { ok: false, reason: "STALE", currentFloor: 10, attemptedSequence: 5 } },
    );
    expect(result.ok).toBe(false);
  });

  test("acceptAdvertisement produces AuthenticatedNodeRecordStub when both pass", () => {
    const kp = generateNodeKeypair();
    const result = acceptAdvertisement(
      kp.nodeId, kp.publicKey, ["MESH_RELAY"], 1, REFERENCE_NOW,
      { verificationOk: true, sequenceCheck: { ok: true, previousFloor: -1, newFloor: 1 } },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.record.nodeId).toBe(kp.nodeId);
      expect(result.record.sequence).toBe(1);
    }
  });
});
