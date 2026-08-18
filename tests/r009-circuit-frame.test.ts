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
import { toHex, canonicalEncode } from "@reference/encoding/cbor";
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
  processCircuitWireFrame,
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
  test("full 2-hop chain: source seals → relay 0 forwards → gateway delivers plaintext", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // Relay 0: decode + AEAD + durable commit + forward (canonical production path).
    // Entry hop commits the floor (commitFloor=true, the default).
    const relay0Result = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.terminal).toBe(false); // hop 0 is not terminal for 2-hop
    expect(relay0Result.committedSequence).toBe(1n);

    // Forward the encoded nextFrame to relay 1 (gateway).
    // Intermediate hop (hopIndex=1): no commit — the protocol derives that
    // only hop 0 is the ingress replay checkpoint (ADR-0019).
    const nextWireBytes = relay0Result.nextWireBytes;
    const relay1Result = await processCircuitWireFrame(circuit, 1, nextWireBytes);
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(relay1Result.terminal).toBe(true); // hop 1 IS terminal
    expect(new TextDecoder().decode(relay1Result.plaintext)).toBe(
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
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(0n);

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
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(0n);
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
      0,
      DIRECTION_FORWARD,
      BigInt(sealed.frameSequence),
    );
    expect(commitResult.ok).toBe(true);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n);
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
    const commit1 = await floorStore.checkAndAdvance(route.commitmentRoot, 0, DIRECTION_FORWARD, 1n);
    expect(commit1.ok).toBe(true);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n);

    // Replay: AEAD succeeds (valid ciphertext) but commit rejects (1 ≤ floor 1).
    const aead2 = openFrame(circuit, 0, sealed);
    expect(aead2.ok).toBe(true); // AEAD still succeeds — the ciphertext is valid
    const commit2 = await floorStore.checkAndAdvance(route.commitmentRoot, 0, DIRECTION_FORWARD, 1n);
    expect(commit2.ok).toBe(false); // replay rejected at the floor
    if (!commit2.ok) expect(commit2.reason).toContain("≤ floor");
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n); // unchanged
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

      // Relay 0 forwards (canonical production path: decode + AEAD + commit + forward).
      // Entry hop commits the floor (commitFloor=true, the default).
      const r0 = await processCircuitWireFrame(circuit, 0, wireBytes);
      expect(r0.ok).toBe(true);
      if (!r0.ok) return;
      expect(r0.committedSequence).toBe(BigInt(seq));

      // Gateway (hop 1) delivers plaintext.
      // Intermediate hop (hopIndex=1): no commit — the protocol derives
      // that only hop 0 is the ingress replay checkpoint (ADR-0019).
      const nextWire = r0.nextWireBytes;
      const r1 = await processCircuitWireFrame(circuit, 1, nextWire);
      expect(r1.ok).toBe(true);
      if (!r1.ok) return;
      expect(new TextDecoder().decode(r1.plaintext)).toBe(`packet ${seq}`);
    }

    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(10n);
  });
});

// =====================================================================
// R-009 Stage 1 hardening: strict canonical CBOR decoding
// (per the re-audit: reject non-canonical encodings, duplicate keys,
//  unknown keys, trailing bytes, sequence-zero)
// =====================================================================

describe("R-009 Stage 1 hardening: strict canonical CBOR decoding", () => {
  // Helper: build a valid CircuitFrame then encode it, to get canonical bytes.
  function makeValidFrame(): CircuitFrame {
    return {
      circuitNoncePrefix: new Uint8Array(8).fill(0xab),
      frameSequence: 1,
      direction: DIRECTION_FORWARD,
      ciphertext: new Uint8Array(32).fill(0xcd),
    };
  }

  test("valid canonical frame decodes successfully", () => {
    const encoded = encodeCircuitFrame(makeValidFrame());
    const decoded = decodeCircuitFrame(encoded);
    expect(decoded.ok).toBe(true);
  });

  test("non-canonical integer encoding (0x1801 instead of 0x01) → REJECT", () => {
    // Build a valid frame, encode, then tamper: replace the canonical 0x01
    // (frame_sequence=1, one byte) with the non-minimal 0x1801 (two bytes).
    // The canonical encoder uses 0x01 for value 1; 0x1801 is non-minimal.
    const valid = encodeCircuitFrame(makeValidFrame());
    // The frame_sequence (value 1) appears as byte 0x01 in the canonical encoding.
    // Find it + replace with 0x18 0x01 (non-minimal 1-byte form).
    const tampered = new Uint8Array(valid.length + 1);
    let inserted = false;
    let j = 0;
    for (let i = 0; i < valid.length; i++) {
      // The frame_sequence key (0x02) is followed by 0x01 (canonical) in the map.
      if (!inserted && valid[i] === 0x02 && i + 1 < valid.length && valid[i + 1] === 0x01) {
        tampered[j++] = 0x02; // key
        tampered[j++] = 0x18; // AI=24 (1-byte follow)
        tampered[j++] = 0x01; // value 1 (non-minimal)
        i++; // skip the original 0x01
        inserted = true;
      } else {
        tampered[j++] = valid[i]!;
      }
    }
    const result = decodeCircuitFrame(tampered.slice(0, j));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("non-canonical");
    }
  });

  test("duplicate key → REJECT", () => {
    // Build a frame with a duplicate key (key 2 appears twice).
    // cborg keeps the last value, so the decoded map has 1 entry for key 2.
    // The round-trip check detects this (re-encoded bytes differ from input).
    const valid = encodeCircuitFrame(makeValidFrame());
    // Insert a duplicate key 2 + value right after the existing key 2 entry.
    // Canonical form: a4 01 48 <8bytes> 02 01 03 01 04 58 <len> <bytes>
    // We insert "02 05" (key 2, value 5) after the existing "02 01".
    // This makes the map have 5 entries (with 2 being a dup), but the
    // map-length prefix still says 4. cborg will decode 4 entries (skipping
    // the 5th), so the round-trip check catches the trailing bytes.
    const dup = new Uint8Array(valid.length + 2);
    let j = 0;
    let inserted = false;
    for (let i = 0; i < valid.length; i++) {
      dup[j++] = valid[i]!;
      // After "02 01" (key 2, value 1), insert "02 05" (dup key 2, value 5).
      if (!inserted && valid[i] === 0x01 && i > 0 && valid[i - 1] === 0x02) {
        dup[j++] = 0x02; // dup key
        dup[j++] = 0x05; // value 5
        inserted = true;
      }
    }
    const result = decodeCircuitFrame(dup.slice(0, j));
    expect(result.ok).toBe(false);
  });

  test("unknown key (key 5) → REJECT", () => {
    // Build a frame with an extra unknown key 5.
    const valid = encodeCircuitFrame(makeValidFrame());
    // The canonical encoding: a4 (map of 4) 01..02..03..04..
    // Replace "a4" with "a5" (map of 5) + append "05 01" (key 5, value 1).
    const withUnknown = new Uint8Array(valid.length + 2);
    withUnknown[0] = 0xa5; // map of 5 (was a4)
    withUnknown.set(valid.slice(1), 1);
    withUnknown[valid.length] = 0x05; // key 5
    withUnknown[valid.length + 1] = 0x01; // value 1
    const result = decodeCircuitFrame(withUnknown);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("unknown CBOR map key 5");
    }
  });

  test("trailing bytes → REJECT", () => {
    // Append trailing bytes after a valid frame.
    const valid = encodeCircuitFrame(makeValidFrame());
    const withTrailing = new Uint8Array(valid.length + 3);
    withTrailing.set(valid, 0);
    withTrailing[valid.length] = 0x01;
    withTrailing[valid.length + 1] = 0x02;
    withTrailing[valid.length + 2] = 0x03;
    const result = decodeCircuitFrame(withTrailing);
    expect(result.ok).toBe(false);
    // Trailing bytes are rejected — either as a CBOR decode error (cborg
    // refuses to consume them) or as a non-canonical round-trip mismatch.
    // Both are valid rejections.
    if (!result.ok) {
      expect(result.reason).toMatch(/non-canonical|CBOR decode failed|too many terminals|trailing/);
    }
  });

  test("sequence zero (frame_sequence=0) → REJECT at wire boundary", () => {
    // Attempt to decode a frame with frame_sequence=0. Per spec/08 §4.3,
    // sequences start at 1. The wire decoder rejects 0 (not deferred to replay).
    // Build the frame manually (encodeCircuitFrame would throw for seq=0).
    const m = new Map<number, unknown>([
      [1, new Uint8Array(8).fill(0xab)], // nonce_prefix
      [2, 0], // frame_sequence = 0 (illegal)
      [3, DIRECTION_FORWARD], // direction
      [4, new Uint8Array(32).fill(0xcd)], // ciphertext
    ]);
    const encoded = canonicalEncode(m);
    const result = decodeCircuitFrame(encoded);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("frame_sequence must be a u32 in [1, 4294967295]");
    }
  });

  test("encode rejects frame_sequence=0 (defense-in-depth)", () => {
    const badFrame: CircuitFrame = {
      circuitNoncePrefix: new Uint8Array(8).fill(0xab),
      frameSequence: 0, // illegal
      direction: DIRECTION_FORWARD,
      ciphertext: new Uint8Array(32).fill(0xcd),
    };
    expect(() => encodeCircuitFrame(badFrame)).toThrow(/frameSequence must be a u32 in \[1/);
  });
});

// =====================================================================
// R-009 Stage 1 hardening: canonical production path owns durable commit
// (per the re-audit: processCircuitWireFrame owns decode → AEAD → commit → forward)
// =====================================================================

describe("R-009 Stage 1 hardening: processCircuitWireFrame owns the full invariant", () => {
  test("production path: valid frame → decode + AEAD + durable commit + forward", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("production path");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // The production path owns the ENTIRE invariant.
    const result = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.terminal).toBe(true); // 1-hop: hop 0 is terminal
    expect(result.committedSequence).toBe(1n);
    expect(new TextDecoder().decode(result.plaintext)).toBe("production path");

    // The floor was durably committed by the production path (not the caller).
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n);
  });

  test("production path: tampered frame → AEAD fails → floor UNCHANGED (no commit)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("tampered");
    const sealed = sealForwardFrame(circuit, 100, plaintext);
    // Flip one bit in the ciphertext.
    const tamperedWire = new Uint8Array(encodeCircuitFrame(sealed));
    // Find the ciphertext region (after the header) + flip a bit.
    // The ciphertext starts after the 4 map header bytes + nonce_prefix (10 bytes) +
    // frame_sequence (2 bytes) + direction (2 bytes) = ~14 bytes in. Flip byte 15.
    tamperedWire[15] ^= 0x01;

    const result = await processCircuitWireFrame(circuit, 0, tamperedWire);
    expect(result.ok).toBe(false);
    // The floor is UNCHANGED — the production path did NOT commit (AEAD failed first).
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(0n);
  });

  test("production path: replay → AEAD succeeds but commit rejects (floor unchanged)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("genuine");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // First presentation: accepted + committed.
    const r1 = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(r1.ok).toBe(true);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n);

    // Replay: AEAD succeeds (valid ciphertext) but the durable commit rejects
    // (1 ≤ floor 1). The production path catches the replay.
    const r2 = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toContain("≤ floor");
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n); // unchanged
  });

  test("production path: non-canonical wire → REJECT at decode (before AEAD)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Non-canonical: trailing bytes appended to a valid frame.
    const sealed = sealForwardFrame(circuit, 1, new TextEncoder().encode("x"));
    const valid = encodeCircuitFrame(sealed);
    const withTrailing = new Uint8Array(valid.length + 1);
    withTrailing.set(valid, 0);
    withTrailing[valid.length] = 0xff; // trailing byte

    const result = await processCircuitWireFrame(circuit, 0, withTrailing);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/non-canonical|CBOR decode failed|too many terminals|trailing/);
    // Floor unchanged — decode rejected before AEAD/commit.
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(0n);
  });
});

// =====================================================================
// R-009 Stage 1 final hardening: protocol-enforced commit ownership
// (per the re-audit: commit ownership derived from protocol state, NOT
//  caller-controlled. hop 0 always commits; hop 1+ never commits; backward
//  rejected by Stage 1 production path.)
// =====================================================================

describe("R-009 Stage 1 final hardening: commit ownership is protocol-enforced (not caller-controlled)", () => {
  // The commitFloor boolean was REMOVED. processCircuitWireFrame now derives
  // commit ownership from protocol semantics:
  //   direction == FORWARD && hopIndex == 0 → COMMIT (ingress checkpoint)
  //   direction == FORWARD && hopIndex > 0  → forward only (no commit)
  //
  // These tests prove the invariant is protocol-enforced: a caller cannot
  // disable the commit at hop 0, nor claim it at hop 1.

  test("hop 0 CANNOT disable the commit — the floor always advances for accepted frames", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("hop 0 must commit");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // hop 0 processes — the floor MUST advance (no way to disable it).
    const r0 = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(r0.ok).toBe(true);
    if (!r0.ok) return;
    expect(r0.committedSequence).toBe(1n);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n); // committed
  });

  test("every hop commits at its OWN receiver-local floor (root, hopIndex, FORWARD)", async () => {
    // R-009 Stage 1 final replay-model correction: the durable floor is keyed
    // by (commitmentRoot, hopIndex, direction) — every receiver commits its
    // own floor. hop 0 commits at (root, 0, FORWARD); hop 1 commits at
    // (root, 1, FORWARD) — independent floors. This catches replays by a
    // malicious upstream relay toward a downstream hop.
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Pre-seed hop 0's floor at 5 (simulate prior traffic at hop 0).
    await floorStore.checkAndAdvance(route.commitmentRoot, 0, DIRECTION_FORWARD, 5n);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(5n);
    // hop 1's floor starts at 0 (no prior traffic at hop 1).
    expect(await floorStore.getFloor(route.commitmentRoot, 1, DIRECTION_FORWARD)).toBe(0n);

    // hop 0 processes a frame at seq=6 — commits at (root, 0, FORWARD) → 6.
    const plaintext = new TextEncoder().encode("seq 6");
    const sealed = sealForwardFrame(circuit, 6, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);
    const r0 = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(r0.ok).toBe(true);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(6n); // hop 0 committed

    // hop 1 processes the forwarded nextFrame — commits at (root, 1, FORWARD) → 6
    // (its OWN floor, independent from hop 0's).
    const r1 = await processCircuitWireFrame(circuit, 1, r0.nextWireBytes);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.terminal).toBe(true); // hop 1 is terminal → delivers plaintext
    // hop 0's floor is STILL 6 (unchanged by hop 1's processing).
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(6n);
    // hop 1's floor advanced to 6 (its own commit).
    expect(await floorStore.getFloor(route.commitmentRoot, 1, DIRECTION_FORWARD)).toBe(6n);
  });

  test("malicious relay replay toward downstream hop → REJECTED by downstream's own floor", async () => {
    // The critical adversarial test: a malicious upstream relay replays an
    // already-valid inner ciphertext toward a downstream hop. The downstream
    // hop's OWN floor catches the replay — even though the AEAD succeeds
    // (the ciphertext is valid). This is why the floor is receiver-local.
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Legitimate frame seq=10: source → hop 0 → hop 1.
    const plaintext = new TextEncoder().encode("legitimate seq 10");
    const sealed = sealForwardFrame(circuit, 10, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // hop 0 processes — commits at (root, 0, FORWARD) → 10.
    const r0 = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(r0.ok).toBe(true);
    if (!r0.ok) return;

    // hop 1 processes the forwarded nextFrame — commits at (root, 1, FORWARD) → 10.
    const r1 = await processCircuitWireFrame(circuit, 1, r0.nextWireBytes);
    expect(r1.ok).toBe(true);
    expect(await floorStore.getFloor(route.commitmentRoot, 1, DIRECTION_FORWARD)).toBe(10n);

    // MALICIOUS RELAY ATTACK: relay 0 replays the SAME nextFrame toward hop 1.
    // The AEAD succeeds (valid ciphertext, same key+nonce → same plaintext),
    // but hop 1's OWN floor catches the replay (10 ≤ floor 10).
    const replayResult = await processCircuitWireFrame(circuit, 1, r0.nextWireBytes);
    expect(replayResult.ok).toBe(false);
    if (!replayResult.ok) expect(replayResult.reason).toContain("≤ floor");
    // hop 1's floor is UNCHANGED (still 10 — the replay did not advance it).
    expect(await floorStore.getFloor(route.commitmentRoot, 1, DIRECTION_FORWARD)).toBe(10n);
  });

  test("replay at hop 0 → rejected by the ingress checkpoint (commit fails)", async () => {
    // The ingress checkpoint at hop 0 catches replays. A replayed frame at
    // hop 0 is rejected by the durable commit — the floor does NOT advance.
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const plaintext = new TextEncoder().encode("genuine");
    const sealed = sealForwardFrame(circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);

    // First presentation at hop 0 → accepted + committed.
    const r1 = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(r1.ok).toBe(true);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n);

    // Replay at hop 0 → AEAD succeeds (valid ciphertext) but the ingress
    // checkpoint's durable commit rejects (1 ≤ floor 1).
    const r2 = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toContain("≤ floor");
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n); // unchanged
  });
});

describe("R-009 Stage 1 final hardening: backward direction rejected by production path", () => {
  // Stage 1 implements FORWARD traffic only. The return-onion protocol
  // (including the replay-floor keying question: per-route vs
  // per-(route, direction)) is Stage 2 work. The Stage 1 production path
  // fails closed on BACKWARD. The generic CircuitFrame decoder still
  // accepts both enum values (0x01 + 0x02) so the wire schema stays
  // compatible with Stage 2.

  test("decode accepts BACKWARD (wire schema compatible with Stage 2)", () => {
    // The decoder recognizes direction=0x02 (BACKWARD) as a valid wire value.
    const m = new Map<number, unknown>([
      [1, new Uint8Array(8).fill(0xab)],
      [2, 1], // frame_sequence
      [3, 0x02], // direction = BACKWARD
      [4, new Uint8Array(32).fill(0xcd)],
    ]);
    const encoded = canonicalEncode(m);
    const decoded = decodeCircuitFrame(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.frame.direction).toBe(0x02);
  });

  test("processCircuitWireFrame REJECTS backward frame (Stage 1 — fail closed)", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // Manually craft a backward frame (valid canonical CBOR, direction=0x02).
    const m = new Map<number, unknown>([
      [1, circuit.noncePrefix],
      [2, 1], // frame_sequence
      [3, 0x02], // direction = BACKWARD (Stage 1 rejects)
      [4, new Uint8Array(32).fill(0xcd)], // dummy ciphertext
    ]);
    const wireBytes = canonicalEncode(m);

    const result = await processCircuitWireFrame(circuit, 0, wireBytes);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("BACKWARD");
      expect(result.reason).toContain("Stage 2");
    }
    // The floor is UNCHANGED — the backward frame never reached AEAD/commit.
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(0n);
  });

  test("processCircuitWireFrame has NO commitFloor parameter (protocol-derived)", () => {
    // The function signature has exactly 3 params (circuit, hopIndex, wireBytes).
    // The commitFloor boolean was REMOVED — commit ownership is derived from
    // protocol state (direction + hopIndex), not caller-supplied.
    expect(processCircuitWireFrame.length).toBe(3);
  });
});
