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
  type CircuitFrame,
  type OpenFrameResult,
} from "./frame";
import type { ActiveCircuit } from "./circuit";

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
 * - `{ ok: true, terminal: true, plaintext }`: terminal hop — deliver plaintext.
 * - `{ ok: true, terminal: false, nextFrame }`: intermediate hop — forward nextFrame.
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
 * This is the LOWER-LEVEL function: it performs step 1 (AEAD authenticate +
 * decrypt) of the R-008 frozen ordering ONLY. It does NOT do the durable
 * sequence commit (step 2). Use this for:
 *   - Conformance vectors (which test AEAD + forwarding, not durable state)
 *   - Unit tests of the onion peel mechanics
 *
 * For the PRODUCTION relay path, use `processCircuitWireFrame()` instead —
 * it owns the full invariant (decode → AEAD → durable commit → forward).
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
 *     in a new CircuitFrame with the SAME header + forward to the next hop.
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

  // Forward or deliver.
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
// CANONICAL PRODUCTION ENTRY POINT: processCircuitWireFrame
// (decode → AEAD → durable commit → forward — owns the full invariant)
// -----------------------------------------------------------------------

/**
 * Process a raw wire CircuitFrame at a relay: the CANONICAL PRODUCTION
 * entry point that owns the ENTIRE R-008 frozen ordering invariant.
 *
 * Per the R-009 Stage 1 final hardening: the production wire entry point
 * MUST own the durable commit, AND commit ownership MUST be DERIVED FROM
 * PROTOCOL STATE — not supplied as a caller-controlled boolean.
 *
 * COMMIT OWNERSHIP (R-009 Stage 1 — frozen, single ingress replay checkpoint):
 *
 *   The durable sequence floor is committed exactly ONCE per frame per route,
 *   at the single ingress replay checkpoint. For Stage 1 (forward traffic),
 *   this is derived from protocol semantics:
 *
 *     direction == FORWARD && hopIndex == 0
 *         → COMMIT the durable sequence floor (ingress checkpoint)
 *
 *     direction == FORWARD && hopIndex > 0
 *         → forward only (the floor was already committed at hop 0)
 *
 *   This is NOT caller-controlled. There is no `commitFloor` boolean. The
 *   protocol itself determines commit ownership — a bad integration cannot
 *   accidentally disable the commit (hop 0 always commits) or claim it
 *   at the wrong hop (hop 1 never commits). See ADR-0019.
 *
 * BACKWARD DIRECTION REJECTION (Stage 1):
 *
 *   Stage 1 implements FORWARD traffic only. The backward/return-onion
 *   protocol is Stage 2 work. Until Stage 2 freezes the return-onion
 *   semantics (including the replay-floor keying question: per-route vs
 *   per-(route, direction)), the Stage 1 production path REJECTS backward
 *   frames. The generic CircuitFrame decoder still accepts both enum
 *   values (0x01 + 0x02) so the wire schema stays compatible with Stage 2,
 *   but processCircuitWireFrame() fails closed on BACKWARD.
 *
 * Pipeline (R-008 frozen ordering, Stage 1):
 *   1. decode (strict canonical CBOR — rejects non-canonical encodings)
 *   2. reject BACKWARD direction (Stage 1 — fail closed until Stage 2)
 *   3. AEAD authenticate + decrypt one layer (openFrame)
 *      → reject if tag fails (floor UNCHANGED — DoS fix from R-008)
 *   4. atomic durable sequence commit (circuit.floorStore.checkAndAdvance)
 *      → ONLY at the ingress checkpoint (direction==FORWARD && hopIndex==0)
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

  // Step 2 (R-009 Stage 1): reject BACKWARD direction.
  // Stage 1 implements FORWARD traffic only. The return-onion protocol
  // (including the replay-floor keying question) is Stage 2 work. The
  // production path fails closed on BACKWARD until Stage 2 freezes it.
  if (frame.direction !== DIRECTION_FORWARD) {
    return {
      ok: false,
      reason: "R-009 Stage 1 production path rejects BACKWARD direction (return-onion is Stage 2 work — not yet frozen)",
    };
  }

  // Step 3 (R-008 frozen ordering): AEAD authenticate + decrypt one layer.
  const forward = forwardFrame(circuit, hopIndex, frame);
  if (!forward.ok) {
    // AEAD failed — the floor MUST NOT advance. Do NOT call floorStore.
    return { ok: false, reason: forward.reason };
  }

  // Step 4 (R-009 Stage 1 — frozen ingress replay checkpoint):
  // Commit ownership is DERIVED FROM PROTOCOL STATE, not caller-supplied.
  //   direction == FORWARD && hopIndex == 0  → COMMIT (ingress checkpoint)
  //   direction == FORWARD && hopIndex > 0   → forward only (no commit)
  //
  // This is the single ingress replay checkpoint per route. A frame with
  // frameSequence=N is processed by every hop, but the floor is committed
  // exactly once — at hop 0 (the entry relay). Subsequent hops forward
  // without re-committing (which would be a self-replay).
  //
  // Per ADR-0019: this invariant is protocol-enforced, not caller-enforced.
  const seq = BigInt(frame.frameSequence);
  const isIngressCheckpoint = (hopIndex === 0);
  if (isIngressCheckpoint) {
    const commitResult = await circuit.floorStore.checkAndAdvance(
      circuit.commitmentRoot,
      seq,
    );
    if (!commitResult.ok) {
      // Replay/stale or persistence failure — reject. Floor UNCHANGED.
      return { ok: false, reason: commitResult.reason };
    }
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
