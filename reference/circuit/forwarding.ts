/**
 * ShareNet 2.0 — Per-hop circuit frame forwarding (R-009).
 *
 * Per spec/08 §5 (circuit setup) + §4.6 (CircuitFrame): after a circuit is
 * ACTIVE, data-plane frames flow hop-by-hop. Each relay:
 *
 *   1. Receives a wire CircuitFrame from the previous hop.
 *   2. Decodes it (strict canonical CBOR — rejects non-canonical encodings,
 *      duplicate keys, unknown keys, trailing bytes per the R-009 Stage 1 audit).
 *   3. AEAD-authenticates + decrypts ONE layer (openFrame — step 1 of the
 *      R-008 frozen ordering).
 *   4. Durable sequence commit (step 2 — via circuit.floorStore.checkAndAdvance.
 *      MUST happen AFTER AEAD succeeds. Fail-closed.)
 *   5. Either:
 *      a. Forwards the inner frame to the next hop (encode + send), OR
 *      b. Delivers the plaintext locally (if this is the terminal hop).
 *
 * CANONICAL PRODUCTION ENTRY POINT (R-009 Stage 1 hardening):
 *
 *   `processCircuitWireFrame()` is the canonical production relay entry point.
 *   It owns the ENTIRE R-008 frozen ordering invariant:
 *
 *     decode → AEAD authenticate → durable sequence commit → forward/deliver
 *
 *   There is no "caller must remember step 2" contract for the production
 *   path. The durable commit happens inside this function, AFTER AEAD
 *   succeeds and BEFORE forwarding. If AEAD fails, the floor is UNCHANGED
 *   (the commit is never reached).
 *
 *   The lower-level `openFrame()` (in frame.ts) is kept as the AEAD-only
 *   primitive for cryptographic testing + the conformance vectors. It does
 *   NOT do the durable commit.
 *
 * R-008 FROZEN PROTOCOL ORDERING (data-plane, enforced here):
 *   1. decode (strict canonical CBOR)
 *   2. AEAD authenticate + decrypt      (openFrame — reject if tag fails)
 *   3. atomic durable sequence commit   (circuit.floorStore.checkAndAdvance)
 *   4. forward / deliver
 *
 *   Steps 2+3 are the R-008 frozen ordering. Step 3 happens ONLY after step 2
 *   succeeds — an unauthenticated frame MUST NOT advance the floor.
 */

import {
  encodeCircuitFrame,
  decodeCircuitFrame,
  openFrame,
  DIRECTION_FORWARD,
  DIRECTION_BACKWARD,
  type CircuitFrame,
  type OpenFrameResult,
} from "./frame";
import type { ActiveCircuit } from "./circuit";
import {
  peelReturnEnvelopeLayer,
  decryptReturnPayload,
  encodeReturnFramePayload,
} from "./return-template";

// -----------------------------------------------------------------------
// Forwarding result (AEAD-only, no durable commit)
// -----------------------------------------------------------------------

/**
 * Result of forwarding a CircuitFrame at a relay hop (AEAD peel only —
 * does NOT include the durable sequence commit).
 *
 * This is the lower-level result used by the conformance vectors + tests.
 * The production path uses `ProcessCircuitWireFrameResult` (below), which
 * includes the durable commit.
 *
 * FORWARD direction:
 * - `{ ok: true, terminal: true, plaintext }`: terminal hop (gateway) — deliver plaintext.
 * - `{ ok: true, terminal: false, nextFrame }`: intermediate hop — forward nextFrame.
 *
 * BACKWARD direction (distributed return-onion template model):
 * - `{ ok: true, terminal: true, plaintext }`: terminal hop (source) — the response
 *   plaintext, decrypted with the K_ret recovered from the envelope.
 * - `{ ok: true, terminal: false, nextFrame }`: intermediate hop — forward the
 *   nextFrame (with inner { sealedPayload, innerEnvelope } ciphertext).
 *
 * - `{ ok: false, reason }`: AEAD authentication failed. Floor MUST NOT advance.
 */
export type ForwardFrameResult =
  | { ok: true; terminal: true; plaintext: Uint8Array }
  | { ok: true; terminal: false; nextFrame: CircuitFrame }
  | { ok: false; reason: string };

/**
 * Result of the CANONICAL PRODUCTION relay entry point (includes durable commit).
 *
 * - `{ ok: true, terminal: true, plaintext }`: terminal hop — plaintext delivered,
 *   floor durably committed.
 * - `{ ok: true, terminal: false, nextWireBytes }`: intermediate hop — encode these
 *   bytes + forward to the next hop. Floor durably committed.
 * - `{ ok: false, reason }`: frame rejected (decode failed, AEAD failed, or
 *   durable commit failed/replay). The floor is UNCHANGED.
 */
export type ProcessCircuitWireFrameResult =
  | { ok: true; terminal: true; plaintext: Uint8Array; committedSequence: bigint }
  | { ok: true; terminal: false; nextWireBytes: Uint8Array; committedSequence: bigint }
  | { ok: false; reason: string };

// -----------------------------------------------------------------------
// forwardFrame — relay peels one AEAD layer (NO durable commit)
// -----------------------------------------------------------------------

/**
 * Forward a CircuitFrame at a relay hop: peel one AEAD layer and produce
 * the outgoing wire frame (or deliver the plaintext if terminal).
 *
 * R-009 Stage 2 UNIFIED WIRE PROTOCOL: the frame direction determines the
 * processing path:
 *
 *   FORWARD  → openFrame() with the hop's forwardingKey (the forward onion:
 *              the ciphertext is N-layer-deep, each layer peeled with
 *              forwardingKey). Terminal hop = hop N-1 (gateway) → plaintext.
 *
 *   BACKWARD → peelReturnEnvelopeLayer() with the hop's returnKey (the
 *              distributed return-onion template model: the ciphertext is
 *              CBOR { sealedPayload, envelopeLayer }. The relay peels its
 *              returnKey from the envelopeLayer, NOT from the frame ciphertext
 *              directly. Terminal hop = hop 0 (source) → recovers K_ret from
 *              the envelope + decrypts the sealedPayload → plaintext).
 *
 * This is the LOWER-LEVEL function: it performs step 1 (AEAD authenticate +
 * decrypt) of the R-008 frozen ordering ONLY. It does NOT do the durable
 * sequence commit (step 2). Use this for:
 *   - Conformance vectors (which test AEAD + forwarding, not durable state)
 *   - Unit tests of the onion peel mechanics
 *
 * For the PRODUCTION relay path, use `processCircuitWireFrame()` instead —
 * it owns the full invariant (decode → AEAD → durable commit → forward).
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
  if (frame.direction === DIRECTION_FORWARD) {
    // FORWARD: the forward onion. openFrame peels one forwardingKey layer.
    const openResult: OpenFrameResult = openFrame(circuit, hopIndex, frame);
    if (!openResult.ok) {
      return { ok: false, reason: openResult.reason };
    }
    if (openResult.isTerminal) {
      return { ok: true, terminal: true, plaintext: openResult.payload };
    }
    // Intermediate forward hop — the payload is the inner onion ciphertext.
    const nextFrame: CircuitFrame = {
      circuitNoncePrefix: frame.circuitNoncePrefix,
      frameSequence: frame.frameSequence,
      direction: frame.direction,
      ciphertext: openResult.payload,
    };
    return { ok: true, terminal: false, nextFrame };
  }

  // BACKWARD: the distributed return-onion template model.
  // The ciphertext is CBOR { sealedPayload, envelopeLayer }.
  // peelReturnEnvelopeLayer peels the hop's returnKey from the envelopeLayer.
  const peelResult = peelReturnEnvelopeLayer(circuit, hopIndex, frame.ciphertext);
  if (!peelResult.ok) {
    return { ok: false, reason: peelResult.reason };
  }

  if (peelResult.isTerminal) {
    // Terminal backward hop (hop 0 = source): recover K_ret + decrypt the sealedPayload.
    if (!peelResult.kRet) {
      return { ok: false, reason: "terminal backward hop: K_ret not recovered" };
    }
    const decResult = decryptReturnPayload(
      peelResult.kRet,
      circuit.noncePrefix,
      circuit.commitmentRoot,
      frame.frameSequence,
      peelResult.innerPayload.sealedPayload,
    );
    if (!decResult.ok) {
      return { ok: false, reason: decResult.reason };
    }
    return { ok: true, terminal: true, plaintext: decResult.plaintext };
  }

  // Intermediate backward hop — re-encode { sealedPayload, innerEnvelope }
  // as the next frame's ciphertext + forward toward the source.
  const nextCiphertext = encodeReturnFramePayload(peelResult.innerPayload);
  const nextFrame: CircuitFrame = {
    circuitNoncePrefix: frame.circuitNoncePrefix,
    frameSequence: frame.frameSequence,
    direction: frame.direction,
    ciphertext: nextCiphertext,
  };
  return { ok: true, terminal: false, nextFrame };
}

// -----------------------------------------------------------------------
// CANONICAL PRODUCTION ENTRY POINT: processCircuitWireFrame
// (decode → AEAD → durable commit → forward — owns the full invariant)
// -----------------------------------------------------------------------

/**
 * Process a raw wire CircuitFrame at a relay: the CANONICAL PRODUCTION
 * entry point that owns the ENTIRE R-008 frozen ordering invariant.
 *
 * R-009 Stage 1 final replay-model correction: the durable floor is keyed by
 * (commitmentRoot, hopIndex, direction) — the RECEIVING SECURITY CONTEXT.
 * EVERY hop commits its own floor. There is no "ingress-only" checkpoint;
 * every receiver on the circuit enforces replay protection. This is critical
 * under ShareNet's threat model (malicious relays): a malicious upstream
 * relay replaying an already-valid inner ciphertext toward a downstream hop
 * is caught by the downstream hop's own floor. See ADR-0019.
 *
 * BACKWARD DIRECTION REJECTION (Stage 1):
 *   Stage 1 implements FORWARD traffic only. The return-onion protocol
 *   (including the replay-floor keying question — though the namespace is
 *   now (root, hop, direction) so forward + backward are independent) is
 *   Stage 2 work. The Stage 1 production path REJECTS backward frames.
 *   The generic CircuitFrame decoder still accepts both enum values (0x01 +
 *   0x02) so the wire schema stays compatible with Stage 2.
 *
 * Pipeline (R-008 frozen ordering + R-009 Stage 1 receiver-local replay):
 *   1. decode (strict canonical CBOR — rejects non-canonical encodings)
 *   2. reject BACKWARD direction (Stage 1 — fail closed until Stage 2)
 *   3. AEAD authenticate + decrypt one layer (openFrame)
 *      → reject if tag fails (floor UNCHANGED — DoS fix from R-008)
 *   4. atomic durable sequence commit at THIS RECEIVER's floor
 *      (circuit.floorStore.checkAndAdvance(root, hopIndex, FORWARD, seq))
 *      → reject if replay/stale (seq ≤ floor) or persistence fails (fail-closed)
 *   5. forward / deliver
 *      → terminal hop: deliver plaintext
 *      → intermediate hop: encode nextFrame → forward bytes to next hop
 *
 * CRITICAL: the durable commit (step 4) happens ONLY after AEAD succeeds
 * (step 3). An unauthenticated/tampered frame is rejected at step 3 and the
 * floor is NEVER touched. This is the DoS fix from R-008 (AEAD-before-commit).
 *
 * @param circuit - the active circuit (carries floorStore + per-hop keys)
 * @param hopIndex - which relay hop is processing (0-based)
 * @param wireBytes - the raw canonical-CBOR-encoded CircuitFrame from the previous hop
 * @returns the processing result (see ProcessCircuitWireFrameResult)
 */
export async function processCircuitWireFrame(
  circuit: ActiveCircuit,
  hopIndex: number,
  wireBytes: Uint8Array,
): Promise<ProcessCircuitWireFrameResult> {
  // Step 1: decode (strict canonical CBOR).
  const decoded = decodeCircuitFrame(wireBytes);
  if (!decoded.ok) {
    return { ok: false, reason: decoded.reason };
  }
  const frame = decoded.frame;

  // Step 2 (R-009 Stage 2): both directions accepted.
  // Stage 1 rejected BACKWARD; Stage 2 lifts that restriction. The return-onion
  // protocol is now implemented (sealReturnFrame). The receiver-local replay
  // floor (commitmentRoot, hopIndex, direction) already handles forward +
  // backward independently (different direction values → different floor rows).
  // The terminal hop for BACKWARD is hop 0 (the source); for FORWARD it's hop N-1
  // (the gateway). openFrame computes isTerminal correctly for both directions.

  // Step 3 (R-008 frozen ordering): AEAD authenticate + decrypt one layer.
  const forward = forwardFrame(circuit, hopIndex, frame);
  if (!forward.ok) {
    // AEAD failed — the floor MUST NOT advance. Do NOT call floorStore.
    return { ok: false, reason: forward.reason };
  }

  // Step 4 (R-009 receiver-local replay): atomic durable sequence commit at
  // THIS RECEIVER's floor, keyed by (commitmentRoot, hopIndex, frame.direction).
  // EVERY hop commits its own floor — for BOTH forward + backward directions.
  // Forward + backward floors are independent (different direction → different
  // floor row per ADR-0019). This catches replays by a malicious relay in
  // either direction. Fail-closed.
  const seq = BigInt(frame.frameSequence);
  const commitResult = await circuit.floorStore.checkAndAdvance(
    circuit.commitmentRoot,
    hopIndex,
    frame.direction,
    seq,
  );
  if (!commitResult.ok) {
    return { ok: false, reason: commitResult.reason };
  }

  // Step 5: forward / deliver. The frame is accepted.
  if (forward.terminal) {
    return { ok: true, terminal: true, plaintext: forward.plaintext, committedSequence: seq };
  }
  // Intermediate hop — encode the nextFrame for the next hop.
  const nextWireBytes = encodeCircuitFrame(forward.nextFrame);
  return { ok: true, terminal: false, nextWireBytes, committedSequence: seq };
}

// -----------------------------------------------------------------------
// Test-only helper: decode + AEAD peel (NO durable commit)
// -----------------------------------------------------------------------

/**
 * Result of decode + forward (AEAD only — NO durable commit).
 *
 * Provided for the conformance vectors + unit tests that need to test the
 * decode + AEAD mechanics without committing durable state. The PRODUCTION
 * path uses `processCircuitWireFrame()` (above), which includes the commit.
 */
export type ProcessWireFrameResult =
  | {
      ok: true;
      decoded: CircuitFrame;
      forward: ForwardFrameResult;
    }
  | { ok: false; reason: string };

/**
 * Decode a wire CircuitFrame + peel one AEAD layer (NO durable commit).
 *
 * TEST-ONLY helper. This function performs steps 1-2 (decode + AEAD) but
 * NOT step 3 (durable commit). It is used by the conformance vectors and
 * unit tests to verify the decode + AEAD mechanics in isolation.
 *
 * WARNING: do NOT use this as a production relay entry point — it does not
 * do the durable sequence commit. Use `processCircuitWireFrame()` instead.
 *
 * @param circuit - the active circuit
 * @param hopIndex - which relay hop is processing
 * @param wireBytes - the raw CBOR-encoded CircuitFrame bytes
 */
export function processWireFrame(
  circuit: ActiveCircuit,
  hopIndex: number,
  wireBytes: Uint8Array,
): ProcessWireFrameResult {
  // Step 1: decode the wire bytes.
  const decoded = decodeCircuitFrame(wireBytes);
  if (!decoded.ok) {
    return { ok: false, reason: decoded.reason };
  }

  // Step 2 (R-008 frozen ordering): AEAD authenticate + decrypt one layer.
  const forward = forwardFrame(circuit, hopIndex, decoded.frame);
  if (!forward.ok) {
    return { ok: false, reason: forward.reason };
  }

  return { ok: true, decoded: decoded.frame, forward };
}

export { encodeCircuitFrame };
