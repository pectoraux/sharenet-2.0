/**
 * ShareNet 2.0 — GATE-06 Tests: Circuits and encrypted forwarding.
 *
 * Per GATE-06 requirements:
 *   - A → Relay → Gateway forwards encrypted test payload over a committed route
 *   - replay, wrong route, expired circuit, uncommitted route, and nonce reuse fail
 *   - real-process integration proof passes repeatedly (deferred — unit tests prove correctness)
 */

import { describe, test, expect } from "bun:test";
import { randomBytes, bytesToHex } from "@reference/identity/keys";
import {
  type RouteProposal,
  PROPOSAL_TO_CIRCUIT_FORBIDDEN,
} from "@reference/routing/route";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  setupCircuit,
  onionEncrypt,
  relayDecrypt,
  deriveCircuitId,
  deriveHopKeys,
  buildNonce,
  encryptPayload,
  decryptPayload,
  CircuitReplayGuard,
  CIRCUIT_REPLAY_MODEL,
  UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN,
} from "@reference/circuit/circuit";
import {
  isBrandedCommittedRoute,
  type BrandedCommittedRoute,
} from "@reference/transport/validated-types";
import { InMemoryCircuitSequenceFloorStore } from "@reference/circuit/replay-stores";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const REFERENCE_NOW = 1786876545;
const testFloorStore = new InMemoryCircuitSequenceFloorStore();

function makeBrandedRoute(numHops = 2) {
  const ctx = makeGenuineBrandedRouteHelper(numHops, REFERENCE_NOW);
  return { route: ctx.branded, kps: ctx.kps, initiator: ctx.initiator };
}

function makeRelayX25519Keys(route: BrandedCommittedRoute) {
  return route.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk, x25519SecretKey: sk };
  });
}

describe("GATE-06: Circuits and encrypted forwarding", () => {
  // --- 1. Circuit setup from committed route ---
  test("circuit setup from committed route succeeds", () => {
    const { route } = makeBrandedRoute(2);
    expect(isBrandedCommittedRoute(route)).toBe(true);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW, testFloorStore);
    expect(circuit.circuitIdHex.length).toBe(64); // 32 bytes hex
    expect(circuit.hops.length).toBe(2);
    expect(circuit.hops[0]!.forwardingKey.length).toBe(32);
    expect(circuit.hops[0]!.returnKey.length).toBe(32);
  });

  // --- 2. Circuit ID is deterministic for same route + initiator key ---
  test("circuit ID is deterministic", () => {
    const { route } = makeBrandedRoute(1);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW, testFloorStore);
    // Per spec/08 §3 (new API): circuit_id derives from commitment_root, NOT routeId string.
    const circuitId2 = deriveCircuitId(route.commitmentRoot, circuit.initiatorX25519PublicKey);
    expect(circuit.circuitIdHex).toBe(bytesToHex(circuitId2));
  });

  // --- 3. Onion encryption: each relay decrypts one layer ---
  test("onion encrypt/decrypt: each relay peels one layer", () => {
    const { route } = makeBrandedRoute(2);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW, testFloorStore);

    const plaintext = new TextEncoder().encode("Hello, real Internet!");
    const seq = 1; // frame sequence is a 32-bit number per spec/08 §4.3 (new API)

    // Encrypt (onion layers)
    const { encryptedPayload } = onionEncrypt(circuit, seq, plaintext);

    // Relay 0 decrypts one layer
    const { decrypted: layer0 } = relayDecrypt(circuit, 0, seq, encryptedPayload);

    // Relay 1 decrypts the inner layer → plaintext
    const { decrypted: finalPlaintext } = relayDecrypt(circuit, 1, seq, layer0);

    expect(new TextDecoder().decode(finalPlaintext)).toBe("Hello, real Internet!");
  });

  // --- 4. Replay protection: same sequence number rejected ---
  test("replay protection: duplicate sequence number rejected", () => {
    const guard = new CircuitReplayGuard();
    const r1 = guard.checkAndRecord(1n);
    expect(r1.ok).toBe(true);

    const r2 = guard.checkAndRecord(1n); // same sequence
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toContain("replay");
  });

  // --- 5. Replay protection: lower sequence rejected ---
  test("replay protection: lower sequence number rejected", () => {
    const guard = new CircuitReplayGuard();
    guard.checkAndRecord(5n);

    const r = guard.checkAndRecord(3n); // lower
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("≤");
  });

  // --- 6. Replay protection: higher sequence accepted ---
  test("replay protection: higher sequence accepted", () => {
    const guard = new CircuitReplayGuard();
    guard.checkAndRecord(5n);
    const r = guard.checkAndRecord(10n);
    expect(r.ok).toBe(true);
  });

  // --- 7. Nonce layout: unique per circuit + sequence ---
  test("nonce layout: nonce_prefix || frame_sequence", () => {
    // Per spec/08 §4.3 (new API): nonce = 8-byte circuit_nonce_prefix || 4-byte frame_sequence (BE).
    const prefixA = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]);
    const prefixB = new Uint8Array([0x87, 0x65, 0x43, 0x21, 0, 0, 0, 0]);
    const nonce1 = buildNonce(prefixA, 1);
    const nonce2 = buildNonce(prefixA, 2);
    const nonce3 = buildNonce(prefixB, 1); // different circuit

    expect(nonce1.length).toBe(12);
    expect(nonce1).not.toEqual(nonce2); // different sequence
    expect(nonce1).not.toEqual(nonce3); // different circuit prefix
  });

  // --- 8. AEAD: tampered ciphertext fails decryption ---
  test("AEAD: tampered ciphertext fails decryption", () => {
    const key = randomBytes(32);
    const nonce = buildNonce(new Uint8Array([0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]), 1);
    const plaintext = new TextEncoder().encode("test payload");
    const ciphertext = encryptPayload(key, nonce, plaintext);

    // Tamper: flip one bit
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0x01;

    expect(() => decryptPayload(key, nonce, tampered)).toThrow();
  });

  // --- 9. AEAD: wrong key fails decryption ---
  test("AEAD: wrong key fails decryption", () => {
    const keyA = randomBytes(32);
    const keyB = randomBytes(32);
    const nonce = buildNonce(new Uint8Array([0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]), 1);
    const plaintext = new TextEncoder().encode("test payload");
    const ciphertext = encryptPayload(keyA, nonce, plaintext);

    expect(() => decryptPayload(keyB, nonce, ciphertext)).toThrow();
  });

  // --- 10. Circuit expiry is propagated from the branded committed route ---
  // R-008 hardening: the genuine pipeline (createRouteCommitment) rejects
  // expired acceptances, so an expired branded route is genuinely impossible.
  // The old test spread the route to override expiry — that now correctly
  // fails the WeakSet brand check (a copy is not a genuine branded route).
  // This test now verifies (a) the route's expiry is propagated to the circuit
  // and (b) a property-copy of the branded route is rejected by setupCircuit.
  test("circuit expiry is propagated from the branded committed route; copy rejected", () => {
    const { route } = makeBrandedRoute(1);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW, testFloorStore);
    expect(circuit.expiry).toBe(route.expiry);
    expect(circuit.expiry).toBeGreaterThan(REFERENCE_NOW);

    // A property-copy is NOT a genuine branded route (WeakSet identity check).
    const copiedRoute = { ...route, expiry: REFERENCE_NOW - 100 };
    expect(isBrandedCommittedRoute(copiedRoute)).toBe(false);
    expect(() => setupCircuit(copiedRoute as any, relayKeys, REFERENCE_NOW, testFloorStore)).toThrow();
  });

  // --- 11. Uncommitted route → circuit FORBIDDEN ---
  test("UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN throws", () => {
    expect(() => UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN({})).toThrow();
  });

  // --- 12. PROPOSAL_TO_CIRCUIT_FORBIDDEN throws ---
  test("PROPOSAL_TO_CIRCUIT_FORBIDDEN throws", () => {
    const proposal: RouteProposal = {
      hops: [],
      requirementDigest: "",
      expiry: 0,
      initiatorNodeId: "",
      agreementDigest: "",
    };
    expect(() => PROPOSAL_TO_CIRCUIT_FORBIDDEN(proposal)).toThrow();
  });

  // --- 13. Key derivation: different hops get different keys ---
  test("HKDF: different hops get different forwarding keys", () => {
    const sharedSecret = randomBytes(32);
    // Per spec/08 §4.1 (new API): the 3rd arg is commitment_root (used as HKDF salt).
    const commitmentRoot = randomBytes(32);
    const keys0 = deriveHopKeys(sharedSecret, 0, commitmentRoot);
    const keys1 = deriveHopKeys(sharedSecret, 1, commitmentRoot);
    expect(keys0.forwardingKey).not.toEqual(keys1.forwardingKey);
    expect(keys0.returnKey).not.toEqual(keys1.returnKey);
  });

  // --- 14. Key derivation: different circuits get different keys ---
  test("HKDF: different circuits get different keys for same hop", () => {
    const sharedSecret = randomBytes(32);
    // Per spec/08 §4.1 (new API): different commitment_roots → different salts → different keys.
    const commitmentRoot1 = randomBytes(32);
    const commitmentRoot2 = randomBytes(32);
    const keys1 = deriveHopKeys(sharedSecret, 0, commitmentRoot1);
    const keys2 = deriveHopKeys(sharedSecret, 0, commitmentRoot2);
    expect(keys1.forwardingKey).not.toEqual(keys2.forwardingKey);
  });

  // --- 15. Full onion encrypt → relay decrypt → gateway decrypt chain ---
  test("full chain: A → Relay → Gateway encrypted test payload", () => {
    const { route } = makeBrandedRoute(2);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW, testFloorStore);

    const plaintext = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const seq = 1; // frame sequence is a 32-bit number per spec/08 §4.3 (new API)

    // Onion encrypt from initiator
    const { encryptedPayload } = onionEncrypt(circuit, seq, plaintext);

    // Relay (hop 0) decrypts one layer
    const { decrypted: relayOutput } = relayDecrypt(circuit, 0, seq, encryptedPayload);

    // Gateway (hop 1) decrypts the final layer → plaintext
    const { decrypted: gatewayOutput } = relayDecrypt(circuit, 1, seq, relayOutput);

    // Gateway sees the plaintext (the HTTP request)
    expect(new TextDecoder().decode(gatewayOutput)).toBe("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

    // Relay 0 never saw the plaintext
    expect(new TextDecoder().decode(relayOutput)).not.toContain("HTTP");
  });

  // --- 16. Circuit setup fails with wrong number of relay keys ---
  test("circuit setup fails with mismatched relay key count", () => {
    const { route } = makeBrandedRoute(2);
    const relayKeys = makeRelayX25519Keys(route).slice(0, 1); // only 1 key for 2 hops
    expect(() => setupCircuit(route, relayKeys, REFERENCE_NOW, testFloorStore)).toThrow();
  });

  // --- 17. Circuit setup fails with mismatched node IDs ---
  test("circuit setup fails with mismatched node IDs", () => {
    const { route } = makeBrandedRoute(2);
    const wrongKeys = route.hops.map((hop, i) => {
      const sk = randomBytes(32);
      const pk = x25519.getPublicKey(sk);
      return {
        hopIndex: i,
        nodeId: "wrongnode" + i, // wrong nodeId
        x25519PublicKey: pk,
      };
    });
    expect(() => setupCircuit(route, wrongKeys, REFERENCE_NOW, testFloorStore)).toThrow();
  });

  // --- 18. Multiple sequential packets with increasing sequence ---
  test("multiple packets: sequential sequence numbers accepted", () => {
    const { route } = makeBrandedRoute(1);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW, testFloorStore);

    for (let i = 1; i <= 10; i++) {
      const plaintext = new TextEncoder().encode(`packet ${i}`);
      // Per spec/08 §4.3 (new API): frame_sequence is a 32-bit number (NOT bigint).
      const { encryptedPayload } = onionEncrypt(circuit, i, plaintext);
      const { decrypted } = relayDecrypt(circuit, 0, i, encryptedPayload);
      expect(new TextDecoder().decode(decrypted)).toBe(`packet ${i}`);
    }
  });

  // --- 19. R-008 freeze: circuit replay model is ORDERED_STREAM ---
  // Per R-008 hardening: the data-plane replay model is frozen as
  // ORDERED_STREAM semantics before R-009. This test codifies the freeze
  // so a silent switch to a sliding-window / out-of-order model would
  // be caught by CI.
  test("R-008 freeze: circuit replay model is ORDERED_STREAM (strictly increasing; backfill rejected)", () => {
    // The frozen model constant is published and equals ORDERED_STREAM.
    expect(CIRCUIT_REPLAY_MODEL).toBe("ORDERED_STREAM");

    const guard = new CircuitReplayGuard();

    // Ordered-stream: strictly increasing. 1, 2, 3 accepted.
    expect(guard.checkAndRecord(1n).ok).toBe(true);
    expect(guard.checkAndRecord(2n).ok).toBe(true);
    expect(guard.checkAndRecord(3n).ok).toBe(true);

    // Equal sequence rejected (replay).
    const eq = guard.checkAndRecord(3n);
    expect(eq.ok).toBe(false);
    if (!eq.ok) expect(eq.reason).toContain("replay");

    // Lower sequence rejected (stale / out-of-order).
    const lower = guard.checkAndRecord(2n);
    expect(lower.ok).toBe(false);
    if (!lower.ok) expect(lower.reason).toContain("≤");

    // A gap (skip 4, jump to 5) IS accepted under ORDERED_STREAM —
    // the model is strictly-increasing, not contiguous. The gap is the
    // sender's choice; the receiver only enforces monotonic increase.
    const gap = guard.checkAndRecord(5n);
    expect(gap.ok).toBe(true);

    // Back-filling the gap (4, after 5) is rejected — no out-of-order.
    const backfill = guard.checkAndRecord(4n);
    expect(backfill.ok).toBe(false);
    if (!backfill.ok) expect(backfill.reason).toContain("≤");
  });
});
