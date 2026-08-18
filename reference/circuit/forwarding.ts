/**
 * ShareNet 2.0 — Per-hop circuit frame forwarding (R-009).
 *
 * Per spec/08 §5 (circuit setup) + §4.6 (CircuitFrame): after a circuit is
 * ACTIVE, data-plane frames flow hop-by-hop. Each relay:
 *
 *   1. Receives a wire CircuitFrame from the previous hop.
 *   2. Decodes it (canonical CBOR).
 *   3. AEAD-authenticates + decrypts ONE layer (openFrame — step 1 of the
 *      R-008 frozen ordering).
 *   4. Durable sequence commit (step 2 — the caller's responsibility, via
 *      CircuitSequenceFloorStore. Must happen AFTER AEAD succeeds.)
 *   5. Either:
 *      a. Forwards the inner frame to the next hop (encode + send), OR
 *      b. Delivers the plaintext locally (if this is the terminal hop).
 *
 * This module implements steps 3 + 5 (the relay's forwarding logic). Step 4
 * (durable replay protection) is the caller's responsibility — it wraps
 * around `forwardFrame` using the R-008 frozen ordering.
 *
 * R-008 FROZEN PROTOCOL ORDERING (data-plane):
 *   1. AEAD authenticate + decrypt      (openFrame — inside forwardFrame)
 *   2. atomic durable sequence commit   (caller — via CircuitSequenceFloorStore)
 *   3. frame accepted + forwarded
 *
 * The caller's flow:
 *   ```typescript
 *   const decoded = decodeCircuitFrame(wireBytes);
 *   if (!decoded.ok) return reject(decoded.reason);
 *   const fwd = forwardFrame(circuit, hopIndex, decoded.frame);
 *   if (!fwd.ok) return reject(fwd.reason);  // AEAD failed — floor UNCHANGED
 *   // AEAD succeeded — now commit the durable sequence floor.
 *   const commit = await circuit.floorStore.checkAndAdvance(
 *     circuit.commitmentRoot, BigInt(decoded.frame.frameSequence));
 *   if (!commit.ok) return reject(commit.reason);  // replay/stale — floor UNCHANGED
 *   // Frame accepted — forward or deliver.
 *   if (fwd.terminal) deliverPlaintext(fwd.plaintext);
 *   else sendToNextHop(encodeCircuitFrame(fwd.nextFrame));
 *   ```
 */

import {
  encodeCircuitFrame,
  decodeCircuitFrame,
  openFrame,
  type CircuitFrame,
  type OpenFrameResult,
} from "./frame";
import type { ActiveCircuit } from "./circuit";

// -----------------------------------------------------------------------
// Forwarding result
// -----------------------------------------------------------------------

/**
 * Result of forwarding a CircuitFrame at a relay hop.
 *
 * - `{ ok: true, terminal: true, plaintext }`: this is the terminal hop
 *   (the gateway for forward direction). The payload is the application
 *   plaintext — deliver it locally.
 * - `{ ok: true, terminal: false, nextFrame }`: this is an intermediate
 *   hop. The inner ciphertext has been revealed; encode `nextFrame` and
 *   forward it to the next hop.
 * - `{ ok: false, reason }`: AEAD authentication failed. The caller MUST
 *   reject the frame and MUST NOT advance the durable sequence floor
 *   (R-008 frozen ordering).
 */
export type ForwardFrameResult =
  | { ok: true; terminal: true; plaintext: Uint8Array }
  | { ok: true; terminal: false; nextFrame: CircuitFrame }
  | { ok: false; reason: string };

// -----------------------------------------------------------------------
// forwardFrame — relay peels one layer
// -----------------------------------------------------------------------

/**
 * Forward a CircuitFrame at a relay hop: peel one AEAD layer and produce
 * the outgoing wire frame (or deliver the plaintext if terminal).
 *
 * This is the relay's data-plane processing function. It performs step 1
 * (AEAD authenticate + decrypt) of the R-008 frozen ordering. The caller
 * is responsible for step 2 (durable sequence commit) AFTER this function
 * returns `{ ok: true }`.
 *
 * Per spec/08 §4.1 + §4.6:
 *   - The relay decrypts one layer using its forwardingKey (forward direction)
 *     or returnKey (backward direction).
 *   - The AEAD tag authenticates the frame header (nonce_prefix +
 *     frame_sequence + direction + commitment_root), binding the frame
 *     to the exact circuit.
 *   - If this is the terminal hop (last hop, forward direction), the
 *     decrypted payload is the application plaintext.
 *   - Otherwise, the decrypted payload is the inner ciphertext — wrap it
 *     in a new CircuitFrame with the SAME header (nonce_prefix +
 *     frame_sequence + direction) and forward to the next hop.
 *
 * The outgoing CircuitFrame carries the SAME header as the incoming frame
 * (the header is hop-invariant — only the ciphertext shrinks by 16 bytes
 * per hop, the AEAD tag).
 *
 * @param circuit - the active circuit (carries per-hop keys + noncePrefix)
 * @param hopIndex - which relay hop is processing this frame (0-based)
 * @param frame - the decoded incoming CircuitFrame wire object
 * @returns the forwarding result (see ForwardFrameResult)
 */
export function forwardFrame(
  circuit: ActiveCircuit,
  hopIndex: number,
  frame: CircuitFrame,
): ForwardFrameResult {
  // Step 1 (R-008 frozen ordering): AEAD authenticate + decrypt one layer.
  const openResult: OpenFrameResult = openFrame(circuit, hopIndex, frame);
  if (!openResult.ok) {
    return { ok: false, reason: openResult.reason };
  }

  // Step 5: forward or deliver.
  if (openResult.isTerminal) {
    // Terminal hop — the payload is the application plaintext.
    return { ok: true, terminal: true, plaintext: openResult.payload };
  }

  // Intermediate hop — the payload is the inner ciphertext. Build a new
  // CircuitFrame with the SAME header + the inner ciphertext, for the next hop.
  const nextFrame: CircuitFrame = {
    circuitNoncePrefix: frame.circuitNoncePrefix,
    frameSequence: frame.frameSequence,
    direction: frame.direction,
    ciphertext: openResult.payload,
  };

  return { ok: true, terminal: false, nextFrame };
}

// -----------------------------------------------------------------------
// Full relay processing helper (decode + forward)
// -----------------------------------------------------------------------

/**
 * Result of processing a raw wire frame at a relay: decode + forward.
 *
 * - `{ ok: true, decoded, forward }`: the wire bytes decoded successfully
 *   AND the AEAD layer peeled. The caller must still do the durable
 *   sequence commit (step 2 of the R-008 frozen ordering) before
 *   accepting the frame.
 * - `{ ok: false, reason }`: either the decode failed OR the AEAD failed.
 *   The caller rejects the frame; the floor MUST NOT advance.
 */
export type ProcessWireFrameResult =
  | {
      ok: true;
      decoded: CircuitFrame;
      forward: ForwardFrameResult;
    }
  | { ok: false; reason: string };

/**
 * Process a raw wire CircuitFrame at a relay: decode + forward one layer.
 *
 * This is the full relay entry point for the data plane. It:
 *   1. Decodes the wire bytes (canonical CBOR) → CircuitFrame.
 *   2. Forwards (peels one AEAD layer) → either a nextFrame or terminal plaintext.
 *
 * It does NOT do the durable sequence commit (step 2 of the R-008 frozen
 * ordering) — the caller must do that AFTER this returns `{ ok: true }`,
 * using `circuit.floorStore.checkAndAdvance(circuit.commitmentRoot,
 * BigInt(decoded.frameSequence))`.
 *
 * This separation enforces the R-008 frozen ordering: AEAD first (this
 * function), durable commit second (the caller), accept third.
 *
 * @param circuit - the active circuit
 * @param hopIndex - which relay hop is processing
 * @param wireBytes - the raw CBOR-encoded CircuitFrame bytes from the previous hop
 */
export function processWireFrame(
  circuit: ActiveCircuit,
  hopIndex: number,
  wireBytes: Uint8Array,
): ProcessWireFrameResult {
  // Step 0: decode the wire bytes.
  const decoded = decodeCircuitFrame(wireBytes);
  if (!decoded.ok) {
    return { ok: false, reason: decoded.reason };
  }

  // Step 1 (R-008 frozen ordering): AEAD authenticate + decrypt one layer.
  const forward = forwardFrame(circuit, hopIndex, decoded.frame);
  if (!forward.ok) {
    return { ok: false, reason: forward.reason };
  }

  return { ok: true, decoded: decoded.frame, forward };
}

export { encodeCircuitFrame };
