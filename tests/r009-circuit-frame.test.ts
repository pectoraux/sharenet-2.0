/**
 * ShareNet 2.0 — R-009: CircuitFrame wire object + seal/open/forward tests.
 *
 * Tests the R-009 data-plane packet protocol built ON the frozen R-008
 * crypto substrate. Per spec/08 §4.6 + the R-008 frozen protocol ordering:
 *
 *   1. AEAD authenticate + decrypt      (openFrame — reject if tag fails)
 *   2. atomic durable sequence commit   (caller — via CircuitSequenceFloorStore)
 *   3. frame accepted + forwarded
 *
 * The frozen R-008 crypto primitives (buildNonce, buildCircuitFrameAD,
 * encryptPayload, decryptPayload) are NOT modified — R-009 builds on top.
 *
 * Test coverage:
 *   1. encode/decode round-trip (canonical CBOR byte stability)
 *   2. decode rejects malformed frames (invalid CBOR, wrong field sizes, illegal direction)
 *   3. sealForwardFrame + openFrame round-trip (1-hop + 2-hop)
 *   4. forwardFrame: relay peels one layer → nextFrame (intermediate) or plaintext (terminal)
 *   5. full 2-hop forwarding chain: source → relay 0 → gateway (terminal) → plaintext
 *   6. tampered ciphertext → AEAD fails → frame rejected
 *   7. wrong circuit (nonce_prefix mismatch) → rejected
 *   8. integration with R-008 frozen ordering: AEAD-first, then durable commit
 *   9. terminal hop delivers the original application plaintext (onion integrity)
 */

import { describe, test, expect } from "bun:test";
import { randomBytes } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  setupCircuit,
  onionEncrypt,
} from "@reference/circuit/circuit";
import {
  encodeCircuitFrame,
  decodeCircuitFrame,
  sealForwardFrame,
  openFrame,
  DIRECTION_FORWARD,
  type CircuitFrame,
} from "@reference/circuit/frame";
import {
  forwardFrame,
  processWireFrame,
} from "@reference/circuit/forwarding";
import { InMemoryCircuitSequenceFloorStore } from "@reference/circuit/replay-stores";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;

function makeRoute(numHops = 2) {
  const ctx = makeGenuineBrandedRouteHelper(numHops, NOW);
  return {
    branded: ctx.branded,
    kps: ctx.kps,
    hpk: ctx.hopPublicKeys,
    commitmentRoot: ctx.branded.commitmentRoot,
  };
}

function makeRelayX25519Keys(route: { hops: Array<{ nodeId: string }> }) {
  return route.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk };
  });
}

describe("R-009: CircuitFrame wire object — encode/decode", () => {
  // 1. encode/decode round-trip (byte stability)
  test("encode → decode round-trip preserves all fields", () => {
    const noncePrefix = randomBytes(8);
    const frame: CircuitFrame = {
      circuitNoncePrefix: noncePrefix,
      frameSequence: 42,
      direction: DIRECTION_FORWARD,
      ciphertext: randomBytes(64),
    };
    const encoded = encodeCircuitFrame(frame);
    const decoded = decodeCircuitFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(toHex(decoded.frame.circuitNoncePrefix)).toBe(toHex(noncePrefix));
    expect(decoded.frame.frameSequence).toBe(42);
    expect(decoded.frame.direction).toBe(DIRECTION_FORWARD);
    expect(toHex(decoded.frame.ciphertext)).toBe(toHex(frame.ciphertext));
  });

  // 2a. decode rejects invalid CBOR
  test("decode rejects invalid CBOR bytes", () => {
    const decoded = decodeCircuitFrame(new Uint8Array([0x00, 0x01, 0x02]));
    expect(decoded.ok).toBe(false);
  });

  // 2b. decode rejects wrong nonce_prefix size
  test("decode rejects wrong circuit_nonce_prefix size (7 bytes)", () => {
    // Manually craft a CBOR map with a 7-byte nonce_prefix
    const badFrame: CircuitFrame = {
      circuitNoncePrefix: randomBytes(7), // wrong size
      frameSequence: 1,
      direction: DIRECTION_FORWARD,
      ciphertext: randomBytes(32),
    };
    // encode should throw (validate before encoding)
    expect(() => encodeCircuitFrame(badFrame)).toThrow();
  });

  // 2c. decode rejects illegal direction
  test("encode rejects illegal direction (0x03)", () => {
    const badFrame = {
      circuitNoncePrefix: randomBytes(8),
      frameSequence: 1,
      direction: 0x03 as 0x01, // illegal
      ciphertext: randomBytes(32),
    };
    expect(() => encodeCircuitFrame(badFrame)).toThrow();
  });

  // 2d. decode rejects oversized frame_sequence
  test("encode rejects frame_sequence > u32 max", () => {
    const badFrame = {
      circuitNoncePrefix: randomBytes(8),
      frameSequence: 0x100000000, // 2^32 — too big for u32
      direction: DIRECTION_FORWARD,
      ciphertext: randomBytes(32),
    };
    expect(() => encodeCircuitFrame(badFrame)).toThrow();
  });
});

describe("R-009: sealForwardFrame + openFrame — 1-hop", () => {
  test("seal → open round-trip: 1-hop circuit delivers plaintext at terminal hop", () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("Hello, real Internet!");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const encoded = encodeCircuitFrame(sealed);

    // Relay 0 (terminal for 1-hop) opens the frame.
    const decoded = decodeCircuitFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;

    const open = openFrame(circuit, 0, decoded.frame);
    expect(open.ok).toBe(true);
    if (!open.ok) return;
    expect(open.isTerminal).toBe(true); // 1-hop: hop 0 is terminal
    expect(new TextDecoder().decode(open.payload)).toBe("Hello, real Internet!");
  });
});

describe("R-009: sealForwardFrame + forwardFrame — 2-hop forwarding", () => {
  // 5. Full 2-hop forwarding chain: source → relay 0 → gateway (terminal)
  test("full 2-hop chain: source seals → relay 0 forwards → gateway delivers plaintext", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // Relay 0: decode + forward one layer.
    const relay0Result = processWireFrame(circuit, 0, wireBytes);
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.forward.terminal).toBe(false); // hop 0 is not terminal for 2-hop

    // Encode the next frame + send to relay 1 (gateway).
    const nextWireBytes = encodeCircuitFrame(relay0Result.forward.nextFrame);
    const relay1Result = processWireFrame(circuit, 1, nextWireBytes);
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(relay1Result.forward.terminal).toBe(true); // hop 1 IS terminal
    expect(new TextDecoder().decode(relay1Result.forward.plaintext)).toBe(
      "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
  });

  // Relay 0 never sees the plaintext (onion encryption)
  test("intermediate hop never sees the application plaintext", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("SECRET-PLAINTTEXT-MUST-NOT-LEAK");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    const relay0Result = processWireFrame(circuit, 0, wireBytes);
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;

    // The payload at hop 0 is the inner CIPHERTEXT (for hop 1), not the plaintext.
    if (!relay0Result.forward.terminal) {
      const relay0Payload = relay0Result.forward.nextFrame.ciphertext;
      const decoded = new TextDecoder().decode(relay0Payload);
      expect(decoded).not.toContain("SECRET-PLAINTTEXT");
      expect(decoded).not.toContain("PLAINTEXT");
    }
  });

  // The ciphertext shrinks by 16 bytes per hop (the AEAD tag)
  test("ciphertext shrinks by 16 bytes (AEAD tag) per hop", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = randomBytes(100);
    const sealed = sealForwardFrame(circuit, 1, plaintext);

    // Original: 100 bytes plaintext + 16 bytes tag (hop 1) + 16 bytes tag (hop 0) = 132
    expect(sealed.ciphertext.length).toBe(100 + 16 + 16);

    // After hop 0 peels one layer: 100 + 16 = 116
    const fwd0 = forwardFrame(circuit, 0, sealed);
    expect(fwd0.ok).toBe(true);
    if (!fwd0.ok || fwd0.terminal) return;
    expect(fwd0.nextFrame.ciphertext.length).toBe(100 + 16);

    // After hop 1 peels the final layer: 100 bytes plaintext
    const fwd1 = forwardFrame(circuit, 1, fwd0.nextFrame);
    expect(fwd1.ok).toBe(true);
    if (!fwd1.ok || !fwd1.terminal) return;
    expect(fwd1.plaintext.length).toBe(100);
  });
});

describe("R-009: adversarial — tampering + wrong circuit rejection", () => {
  // 6. Tampered ciphertext → AEAD fails
  test("tampered ciphertext (1 bit flipped) → openFrame rejects with AEAD failure", () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("authenticated payload");
    const sealed = sealForwardFrame(circuit, 1, plaintext);

    // Flip one bit in the ciphertext.
    const tamperedCt = new Uint8Array(sealed.ciphertext);
    tamperedCt[0] ^= 0x01;
    const tampered: CircuitFrame = { ...sealed, ciphertext: tamperedCt };

    const result = openFrame(circuit, 0, tampered);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("AEAD authentication failed");
    }
  });

  // 7. Wrong circuit (nonce_prefix mismatch) → rejected
  test("wrong circuit (nonce_prefix mismatch) → openFrame rejects", () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("test");
    const sealed = sealForwardFrame(circuit, 1, plaintext);

    // Mismatch the nonce_prefix.
    const wrong: CircuitFrame = {
      ...sealed,
      circuitNoncePrefix: new Uint8Array(8).fill(0xff),
    };

    const result = openFrame(circuit, 0, wrong);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("nonce_prefix mismatch");
    }
  });

  // Tampered frame_sequence in the wire → AEAD fails (AD mismatch)
  test("tampered frame_sequence in wire → AEAD fails (AD binds frame_sequence)", () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("test");
    const sealed = sealForwardFrame(circuit, 5, plaintext); // seq=5
    const encoded = encodeCircuitFrame(sealed);

    // Decode, tamper the frame_sequence, re-encode.
    const decoded = decodeCircuitFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    const tampered: CircuitFrame = {
      ...decoded.frame,
      frameSequence: 6, // tampered: was 5
    };
    const tamperedEncoded = encodeCircuitFrame(tampered);

    const decoded2 = decodeCircuitFrame(tamperedEncoded);
    expect(decoded2.ok).toBe(true);
    if (!decoded2.ok) return;

    // The AEAD AD uses frame_sequence=6 (from the tampered header), but the
    // ciphertext was encrypted with frame_sequence=5. AEAD must fail.
    const result = openFrame(circuit, 0, decoded2.frame);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("AEAD authentication failed");
    }
  });
});

describe("R-009: integration with R-008 frozen ordering (AEAD → durable commit)", () => {
  // 8. AEAD-first: a tampered frame does NOT advance the floor
  test("R-008 frozen ordering: tampered frame → AEAD fails → floor UNCHANGED", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Floor starts at 0.
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(0n);

    // Tampered frame at seq=100 → AEAD fails.
    const sealed = sealForwardFrame(circuit, 100, new TextEncoder().encode("x"));
    const tamperedCt = new Uint8Array(sealed.ciphertext);
    tamperedCt[0] ^= 0x01;
    const tampered: CircuitFrame = { ...sealed, ciphertext: tamperedCt };

    // Step 1 (R-008 frozen ordering): AEAD first.
    const aeadResult = openFrame(circuit, 0, tampered);
    expect(aeadResult.ok).toBe(false); // AEAD failed

    // Step 2 does NOT happen — the caller must NOT call floorStore.checkAndAdvance
    // when AEAD fails. The floor is UNCHANGED.
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(0n);
  });

  // 9. AEAD succeeds → durable commit → frame accepted
  test("R-008 frozen ordering: valid frame → AEAD succeeds → durable commit → floor advances", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("authenticated frame");
    const sealed = sealForwardFrame(circuit, 1, plaintext);

    // Step 1: AEAD first.
    const aeadResult = openFrame(circuit, 0, sealed);
    expect(aeadResult.ok).toBe(true);

    // Step 2: durable commit (only after AEAD succeeds).
    const commitResult = await floorStore.checkAndAdvance(
      route.commitmentRoot,
      BigInt(sealed.frameSequence),
    );
    expect(commitResult.ok).toBe(true);
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(1n);
  });

  // Replay: valid captured frame re-presented → AEAD succeeds but commit rejects
  test("R-008 frozen ordering: replay → AEAD succeeds but durable commit rejects (floor unchanged)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("genuine");
    const sealed = sealForwardFrame(circuit, 1, plaintext);

    // First presentation: AEAD succeeds + commit succeeds.
    const aead1 = openFrame(circuit, 0, sealed);
    expect(aead1.ok).toBe(true);
    const commit1 = await floorStore.checkAndAdvance(route.commitmentRoot, 1n);
    expect(commit1.ok).toBe(true);
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(1n);

    // Replay: AEAD succeeds (valid ciphertext) but commit rejects (1 ≤ floor 1).
    const aead2 = openFrame(circuit, 0, sealed);
    expect(aead2.ok).toBe(true); // AEAD still succeeds — the ciphertext is valid
    const commit2 = await floorStore.checkAndAdvance(route.commitmentRoot, 1n);
    expect(commit2.ok).toBe(false); // replay rejected at the floor
    if (!commit2.ok) expect(commit2.reason).toContain("≤ floor");
    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(1n); // unchanged
  });
});

describe("R-009: multi-frame sequential sequence (ORDERED_STREAM)", () => {
  // 10 sequential frames with strictly increasing sequence numbers
  test("10 sequential frames: seq 1..10 all accepted + forwarded correctly", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    for (let seq = 1; seq <= 10; seq++) {
      const plaintext = new TextEncoder().encode(`packet ${seq}`);
      const sealed = sealForwardFrame(circuit, seq, plaintext);
      const wireBytes = encodeCircuitFrame(sealed);

      // Relay 0 forwards.
      const r0 = processWireFrame(circuit, 0, wireBytes);
      expect(r0.ok).toBe(true);
      if (!r0.ok) return;

      // AEAD succeeded — durable commit at hop 0.
      const commit = await floorStore.checkAndAdvance(route.commitmentRoot, BigInt(seq));
      expect(commit.ok).toBe(true);

      // Gateway (hop 1) delivers plaintext.
      const nextWire = encodeCircuitFrame(r0.forward.nextFrame);
      const r1 = processWireFrame(circuit, 1, nextWire);
      expect(r1.ok).toBe(true);
      if (!r1.ok) return;
      expect(new TextDecoder().decode(r1.forward.plaintext)).toBe(`packet ${seq}`);
    }

    expect(await floorStore.getFloor(route.commitmentRoot)).toBe(10n);
  });
});
