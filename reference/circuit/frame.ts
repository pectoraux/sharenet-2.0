/**
 * ShareNet 2.0 — CircuitFrame wire object + frame seal/open (R-009).
 *
 * Per spec/08 §4.6 (FROZEN):
 *
 *   CircuitFrame = {
 *       circuit_nonce_prefix:  bstr .size 8,   ; per-circuit prefix (§4.3)
 *       frame_sequence:        uint .size 4,    ; big-endian, starts at 1
 *       direction:             uint .size 1,   ; 0x01 = forward, 0x02 = backward
 *       ciphertext:            bstr,           ; ChaCha20-Poly1305 encrypted payload
 *   }
 *
 *   AD = utf8("SHARENET/CIRCUIT/FRAME/1")
 *      || commitment_root       ; 32 bytes
 *      || frame_sequence        ; 4 bytes big-endian
 *      || direction             ; 1 byte
 *
 * R-009 SCOPE (Stage 1):
 *   - CircuitFrame wire object (canonical CBOR encode/decode per ADR-0004).
 *   - sealForwardFrame: source onion-encrypts a plaintext into a CircuitFrame
 *     (forward direction, 0x01). Encrypts from the outermost hop (last) to
 *     the innermost hop (first), using each hop's forwardingKey.
 *   - openFrame: a relay decodes the wire frame + AEAD-authenticates + decrypts
 *     ONE layer, returning the inner payload (ciphertext for the next hop, or
 *     plaintext if this is the terminal hop).
 *   - forwardFrame: wraps openFrame — a relay peels one layer and produces
 *     the outgoing wire CircuitFrame for the next hop (or delivers the
 *     plaintext if terminal).
 *
 * FROZEN CRYPTO SUBSTRATE (R-008 — MUST NOT be modified):
 *   This module IMPORTS and builds on:
 *     - buildNonce(noncePrefix, frameSequence)         — nonce construction
 *     - buildCircuitFrameAD(commitmentRoot, seq, dir)   — AD construction
 *     - encryptPayload / decryptPayload                 — ChaCha20-Poly1305
 *     - deriveNoncePrefix(commitmentRoot)               — per-circuit prefix
 *   These are the frozen R-008 primitives. R-009 packet semantics are built
 *   ON TOP of them — the crypto substrate is not touched.
 *
 * R-008 FROZEN PROTOCOL ORDERING (data-plane frame acceptance):
 *   1. AEAD authenticate + decrypt      (openFrame — reject if tag fails)
 *   2. atomic durable sequence commit   (caller — via CircuitSequenceFloorStore)
 *   3. frame accepted
 *   openFrame performs step 1. The caller performs step 2 (via the store)
 *   AFTER openFrame succeeds. This ordering is FROZEN per R-008 — an
 *   unauthenticated frame must NOT advance the floor.
 */

import { canonicalEncode, toHex } from "../encoding/cbor";
import {
  buildNonce,
  buildCircuitFrameAD,
  encryptPayload,
  decryptPayload,
  AEAD_NONCE_BYTES,
  type ActiveCircuit,
} from "./circuit";

// -----------------------------------------------------------------------
// Constants (per spec/08 §4.6 — FROZEN)
// -----------------------------------------------------------------------

/** Frame direction: source → gateway (forward traffic). Per spec/08 §4.6. */
export const DIRECTION_FORWARD = 0x01 as const;

/** Frame direction: gateway → source (return traffic). Per spec/08 §4.6. */
export const DIRECTION_BACKWARD = 0x02 as const;

/** All legal direction values (for validation on decode). */
const LEGAL_DIRECTIONS = new Set([DIRECTION_FORWARD, DIRECTION_BACKWARD]);

/** Size of the circuit_nonce_prefix field (bytes). Per spec/08 §4.6. */
export const CIRCUIT_NONCE_PREFIX_BYTES = 8;

/** Size of the frame_sequence field (bytes, big-endian u32). Per spec/08 §4.6. */
export const FRAME_SEQUENCE_BYTES = 4;

/** Size of the direction field (bytes). Per spec/08 §4.6. */
export const DIRECTION_BYTES = 1;

// -----------------------------------------------------------------------
// CircuitFrame wire object (per spec/08 §4.6)
// -----------------------------------------------------------------------

/**
 * The data-plane wire object carrying encrypted application traffic over a
 * circuit.
 *
 * Per spec/08 §4.6: the frame carries the 8-byte circuit_nonce_prefix (in
 * the clear — it is part of the AEAD AD, not the payload), the 4-byte
 * big-endian frame_sequence, the 1-byte direction, and the onion ciphertext.
 *
 * The header fields (nonce_prefix, frame_sequence, direction) are NOT
 * encrypted — they are the AEAD associated data. A receiver authenticates
 * them via the AEAD tag; tampering with any field causes AEAD failure.
 */
export interface CircuitFrame {
  /** Per-circuit nonce prefix (8 bytes, derived from commitment_root). */
  circuitNoncePrefix: Uint8Array;
  /** Per-circuit frame sequence (32-bit, starts at 1, big-endian on wire). */
  frameSequence: number;
  /** Traffic direction: 0x01 = forward (source→gateway), 0x02 = backward. */
  direction: 0x01 | 0x02;
  /** Onion-encrypted payload (N layers deep for an N-hop circuit). */
  ciphertext: Uint8Array;
}

// -----------------------------------------------------------------------
// Canonical CBOR encoding (per ADR-0004 integer-keyed map)
// -----------------------------------------------------------------------

/** CBOR map keys for CircuitFrame (per ADR-0004 canonical encoding). */
const FRAME_KEY_NONCE_PREFIX = 1;
const FRAME_KEY_FRAME_SEQUENCE = 2;
const FRAME_KEY_DIRECTION = 3;
const FRAME_KEY_CIPHERTEXT = 4;

/**
 * Encode a CircuitFrame to canonical CBOR for the wire.
 *
 * Per spec/08 §4.6 + ADR-0004: the frame is a canonical CBOR map with
 * integer keys:
 *   1 → circuit_nonce_prefix (bstr .size 8)
 *   2 → frame_sequence (uint .size 4, big-endian)
 *   3 → direction (uint .size 1)
 *   4 → ciphertext (bstr)
 *
 * The encoding is canonical (deterministic) so the bytes are reproducible
 * across implementations (TS / Python / Rust / Kotlin).
 */
export function encodeCircuitFrame(frame: CircuitFrame): Uint8Array {
  // Validate field sizes before encoding (defense-in-depth).
  if (frame.circuitNoncePrefix.length !== CIRCUIT_NONCE_PREFIX_BYTES) {
    throw new Error(
      `encodeCircuitFrame: circuitNoncePrefix must be ${CIRCUIT_NONCE_PREFIX_BYTES} bytes, got ${frame.circuitNoncePrefix.length}`,
    );
  }
  if (!Number.isInteger(frame.frameSequence) || frame.frameSequence < 0 || frame.frameSequence > 0xffffffff) {
    throw new Error(
      `encodeCircuitFrame: frameSequence must be a u32 (0..4294967295), got ${frame.frameSequence}`,
    );
  }
  if (!LEGAL_DIRECTIONS.has(frame.direction)) {
    throw new Error(
      `encodeCircuitFrame: direction must be 0x01 (forward) or 0x02 (backward), got 0x${frame.direction.toString(16)}`,
    );
  }
  if (!(frame.ciphertext instanceof Uint8Array)) {
    throw new Error("encodeCircuitFrame: ciphertext must be a Uint8Array");
  }

  const m = new Map<number, unknown>([
    [FRAME_KEY_NONCE_PREFIX, frame.circuitNoncePrefix],
    [FRAME_KEY_FRAME_SEQUENCE, frame.frameSequence],
    [FRAME_KEY_DIRECTION, frame.direction],
    [FRAME_KEY_CIPHERTEXT, frame.ciphertext],
  ]);
  return canonicalEncode(m);
}

/**
 * Result of decoding a wire CircuitFrame.
 *
 * - `{ ok: true, frame }`: the wire bytes decoded to a valid CircuitFrame.
 * - `{ ok: false, reason }`: the wire bytes are malformed (invalid CBOR,
 *   wrong field sizes, illegal direction, etc.).
 */
export type DecodeCircuitFrameResult =
  | { ok: true; frame: CircuitFrame }
  | { ok: false; reason: string };

/**
 * Decode a CircuitFrame from canonical CBOR wire bytes + validate all
 * field sizes.
 *
 * Per spec/08 §4.6: validates that:
 *   - circuit_nonce_prefix is exactly 8 bytes
 *   - frame_sequence fits in a u32 (0..4294967295)
 *   - direction is 0x01 or 0x02
 *   - ciphertext is a bstr (any length ≥ 16, since AEAD tag is 16 bytes)
 *
 * Returns `{ ok: false, reason }` for any malformed frame. The caller MUST
 * reject malformed frames before any cryptographic operation (fail-closed).
 */
export function decodeCircuitFrame(bytes: Uint8Array): DecodeCircuitFrameResult {
  // Decode the canonical CBOR map.
  let m: Map<number, unknown>;
  try {
    m = decodeCanonicalMap(bytes);
  } catch (e) {
    return { ok: false, reason: `CBOR decode failed: ${(e as Error).message}` };
  }

  // Extract + validate each field.
  const noncePrefix = m.get(FRAME_KEY_NONCE_PREFIX);
  if (!(noncePrefix instanceof Uint8Array) || noncePrefix.length !== CIRCUIT_NONCE_PREFIX_BYTES) {
    return {
      ok: false,
      reason: `circuit_nonce_prefix must be a bstr of ${CIRCUIT_NONCE_PREFIX_BYTES} bytes`,
    };
  }

  const frameSequence = m.get(FRAME_KEY_FRAME_SEQUENCE);
  if (typeof frameSequence !== "number" || !Number.isInteger(frameSequence) ||
      frameSequence < 0 || frameSequence > 0xffffffff) {
    return { ok: false, reason: "frame_sequence must be a u32 (0..4294967295)" };
  }

  const direction = m.get(FRAME_KEY_DIRECTION);
  if (typeof direction !== "number" || !LEGAL_DIRECTIONS.has(direction as 0x01 | 0x02)) {
    return { ok: false, reason: "direction must be 0x01 (forward) or 0x02 (backward)" };
  }

  const ciphertext = m.get(FRAME_KEY_CIPHERTEXT);
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 16) {
    // AEAD tag is 16 bytes — a valid ciphertext is at least 16 bytes.
    return { ok: false, reason: "ciphertext must be a bstr of at least 16 bytes (AEAD tag)" };
  }

  return {
    ok: true,
    frame: {
      circuitNoncePrefix: noncePrefix,
      frameSequence,
      direction: direction as 0x01 | 0x02,
      ciphertext,
    },
  };
}

/**
 * Minimal canonical CBOR map decoder.
 *
 * Decodes a CBOR map with integer keys (per ADR-0004). This is a focused
 * decoder for the CircuitFrame wire object — it does NOT implement the
 * full CBOR spec. It handles: map with integer keys, bstr (Uint8Array),
 * uint (number), text (string).
 *
 * For the full CBOR spec, see RFC 8949 §4.2.2 (canonical CBOR).
 */
function decodeCanonicalMap(bytes: Uint8Array): Map<number, unknown> {
  if (bytes.length === 0) {
    throw new Error("empty input");
  }
  const view = bytes;
  let offset = 0;

  // Major type 5 (map) with the count in the additional info.
  const firstByte = view[offset]!;
  offset++;
  const majorType = firstByte >> 5;
  const ai = firstByte & 0x1f;

  if (majorType !== 5) {
    throw new Error(`expected CBOR map (major type 5), got major type ${majorType}`);
  }

  let count: number;
  if (ai < 24) {
    count = ai;
  } else if (ai === 24) {
    count = view[offset]!; offset++;
  } else if (ai === 25) {
    count = (view[offset]! << 8) | view[offset + 1]!; offset += 2;
  } else {
    throw new Error(`unsupported CBOR map count AI=${ai}`);
  }

  const m = new Map<number, unknown>();
  for (let i = 0; i < count; i++) {
    // Decode key (must be a uint — ADR-0004 integer-keyed map).
    const keyResult = decodeItem(view, offset);
    if (typeof keyResult.value !== "number") {
      throw new Error(`CBOR map key must be uint, got ${typeof keyResult.value}`);
    }
    offset = keyResult.nextOffset;

    // Decode value.
    const valResult = decodeItem(view, offset);
    offset = valResult.nextOffset;

    m.set(keyResult.value, valResult.value);
  }
  return m;
}

/** Decode a single CBOR item (uint, bstr, or text) starting at `offset`. */
function decodeItem(bytes: Uint8Array, offset: number): { value: unknown; nextOffset: number } {
  if (offset >= bytes.length) {
    throw new Error("unexpected end of CBOR input");
  }
  const firstByte = bytes[offset]!;
  const majorType = firstByte >> 5;
  const ai = firstByte & 0x1f;
  let o = offset + 1;

  // Resolve the argument (additional info).
  let arg: number;
  if (ai < 24) {
    arg = ai;
  } else if (ai === 24) {
    arg = bytes[o]!; o++;
  } else if (ai === 25) {
    arg = (bytes[o]! << 8) | bytes[o + 1]!; o += 2;
  } else if (ai === 26) {
    arg = (bytes[o]! * 0x1000000) + ((bytes[o + 1]! << 16) | (bytes[o + 2]! << 8) | bytes[o + 3]!); o += 4;
  } else {
    throw new Error(`unsupported CBOR AI=${ai}`);
  }

  switch (majorType) {
    case 0: // uint
      return { value: arg, nextOffset: o };
    case 2: { // bstr
      const bstr = bytes.slice(o, o + arg);
      if (bstr.length !== arg) {
        throw new Error(`CBOR bstr claims ${arg} bytes but only ${bstr.length} available`);
      }
      return { value: bstr, nextOffset: o + arg };
    }
    case 3: { // text
      const text = new TextDecoder().decode(bytes.slice(o, o + arg));
      return { value: text, nextOffset: o + arg };
    }
    default:
      throw new Error(`unsupported CBOR major type ${majorType} at offset ${offset}`);
  }
}

// -----------------------------------------------------------------------
// Frame seal (source-side: create the N-layer onion CircuitFrame)
// -----------------------------------------------------------------------

/**
 * Seal a plaintext into a forward CircuitFrame (source → gateway).
 *
 * Per spec/08 §4.1 + §4.6: the source onion-encrypts the plaintext from
 * the OUTERMOST hop (last relay) to the INNERMOST hop (first relay). Each
 * relay decrypts one layer with its forwardingKey.
 *
 * This uses the FROZEN R-008 crypto primitives:
 *   - buildNonce(noncePrefix, frameSequence)         — nonce
 *   - buildCircuitFrameAD(commitmentRoot, seq, dir)  — AD
 *   - encryptPayload(key, nonce, plaintext, ad)       — ChaCha20-Poly1305
 *
 * The resulting CircuitFrame carries the N-layer-deep ciphertext + the
 * circuit_nonce_prefix + frame_sequence + direction (0x01) in the clear
 * (as AEAD AD, authenticated by the tag).
 *
 * @param circuit - the active circuit (carries the per-hop forwardingKeys)
 * @param frameSequence - the 32-bit frame sequence (starts at 1, strictly increasing)
 * @param plaintext - the application payload to send
 * @returns a CircuitFrame ready to encode to wire bytes + send to hop 0
 */
export function sealForwardFrame(
  circuit: ActiveCircuit,
  frameSequence: number,
  plaintext: Uint8Array,
): CircuitFrame {
  if (!Number.isInteger(frameSequence) || frameSequence < 1 || frameSequence > 0xffffffff) {
    throw new Error(
      `sealForwardFrame: frameSequence must be a u32 ≥ 1, got ${frameSequence}`,
    );
  }

  // Per spec/08 §4.6: AD = domain || commitment_root || frame_sequence || direction
  const aad = buildCircuitFrameAD(circuit.commitmentRoot, frameSequence, DIRECTION_FORWARD);

  // Onion-encrypt from the outermost hop (last) to the innermost hop (first).
  // After this loop, `data` is N layers deep — hop 0 peels the outermost layer.
  let data = plaintext;
  for (let i = circuit.hops.length - 1; i >= 0; i--) {
    const hop = circuit.hops[i]!;
    const nonce = buildNonce(circuit.noncePrefix, frameSequence);
    data = encryptPayload(hop.forwardingKey, nonce, data, aad);
  }

  return {
    circuitNoncePrefix: circuit.noncePrefix,
    frameSequence,
    direction: DIRECTION_FORWARD,
    ciphertext: data,
  };
}

// -----------------------------------------------------------------------
// Frame open (relay-side: peel one AEAD layer)
// -----------------------------------------------------------------------

/**
 * Result of opening (peeling) one layer of a CircuitFrame.
 *
 * - `{ ok: true, payload, isTerminal }`:
 *     - `payload` is either the inner ciphertext (to forward to the next hop)
 *       or the application plaintext (if this was the terminal hop).
 *     - `isTerminal` is true if this hop is the last hop (the payload is
 *       plaintext, not a ciphertext to forward).
 * - `{ ok: false, reason }`: AEAD authentication failed (tampered ciphertext,
 *   wrong key, wrong circuit). The caller MUST reject the frame and MUST
 *   NOT advance the durable sequence floor (R-008 frozen ordering).
 */
export type OpenFrameResult =
  | { ok: true; payload: Uint8Array; isTerminal: boolean }
  | { ok: false; reason: string };

/**
 * Open (peel) one AEAD layer of a CircuitFrame at a given hop.
 *
 * Per spec/08 §4.1 + §4.6: the relay decrypts one layer using its
 * forwardingKey (for forward direction) or returnKey (for backward).
 * The AEAD tag authenticates the AD (domain || commitment_root ||
 * frame_sequence || direction), binding the frame to the exact circuit.
 *
 * R-008 FROZEN ORDERING: this function performs ONLY the AEAD step (step 1
 * of the frozen ordering: "AEAD authenticate + decrypt"). The caller is
 * responsible for the durable sequence commit (step 2) AFTER this function
 * returns `{ ok: true }`. An AEAD failure (`{ ok: false }`) MUST NOT
 * advance the floor.
 *
 * @param circuit - the active circuit
 * @param hopIndex - which relay hop is processing this frame
 * @param frame - the decoded CircuitFrame wire object
 */
export function openFrame(
  circuit: ActiveCircuit,
  hopIndex: number,
  frame: CircuitFrame,
): OpenFrameResult {
  const hop = circuit.hops[hopIndex];
  if (!hop) {
    return { ok: false, reason: `no hop at index ${hopIndex}` };
  }

  // Defense-in-depth: verify the frame's nonce_prefix matches the circuit's.
  // (The AEAD AD already binds to commitment_root, so an AEAD failure would
  // catch a cross-circuit frame — this is a fast-path early rejection.)
  if (!bytesEqual(frame.circuitNoncePrefix, circuit.noncePrefix)) {
    return {
      ok: false,
      reason: "circuit_nonce_prefix mismatch (frame does not belong to this circuit)",
    };
  }

  // Select the key based on direction: forwardingKey for forward, returnKey
  // for backward. (Stage 1 primarily exercises forward; backward is defined
  // for completeness but multi-hop backward requires the return-onion
  // template extension — a later R-009 sub-phase.)
  const key = frame.direction === DIRECTION_FORWARD ? hop.forwardingKey : hop.returnKey;

  // Build the nonce + AD using the FROZEN R-008 primitives.
  const nonce = buildNonce(circuit.noncePrefix, frame.frameSequence);
  const aad = buildCircuitFrameAD(circuit.commitmentRoot, frame.frameSequence, frame.direction);

  // AEAD authenticate + decrypt one layer. If the tag does not verify
  // (tampered ciphertext, wrong key, wrong circuit), this throws — the
  // caller MUST treat the frame as rejected and MUST NOT advance the floor.
  let payload: Uint8Array;
  try {
    payload = decryptPayload(key, nonce, frame.ciphertext, aad);
  } catch (e) {
    return { ok: false, reason: `AEAD authentication failed: ${(e as Error).message}` };
  }

  // This hop is terminal if it's the last hop in the route AND the direction
  // is forward (the gateway receives the plaintext). For backward direction,
  // the terminal hop is hop 0 (the source) — but Stage 1 does not fully
  // exercise backward; the isTerminal flag is computed for forward.
  const isTerminal = frame.direction === DIRECTION_FORWARD && hopIndex === circuit.hops.length - 1;

  return { ok: true, payload, isTerminal };
}

/** Constant-time byte equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// Re-export for convenience.
export { toHex };
