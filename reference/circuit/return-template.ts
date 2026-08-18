/**
 * ShareNet 2.0 — Return-onion template distribution (R-009 Stage 2).
 *
 * Per the re-audit of 4ca7688: the `sealReturnFrame()` function is
 * cryptographically correct but architecturally incomplete — it requires
 * a single process to hold ALL returnKeys. In a real distributed ShareNet
 * circuit, the gateway does NOT have the initiator's private key or the
 * intermediate relays' private keys, so it cannot derive the per-hop
 * returnKeys.
 *
 * This module implements the distributed return-key/template distribution
 * protocol (Model A — layered encrypted return template):
 *
 *   1. The INITIATOR (who holds all returnKeys from the ECDH setup)
 *      constructs a `ReturnOnionTemplate` during `establishDistributedCircuit`:
 *        - Generates a fresh per-circuit return key `K_ret` (32-byte AEAD key).
 *        - Wraps `K_ret` in N nested AEAD layers, one per hop's returnKey:
 *            env_0     = AEAD(returnKey_0, K_ret)
 *            env_1     = AEAD(returnKey_1, env_0)
 *            ...
 *            env_{N-1} = AEAD(returnKey_{N-1}, env_{N-2})
 *        - The template = { circuitId, commitmentRoot, kRet, envelope = env_{N-1} }.
 *
 *   2. The INITIATOR sends the template to the GATEWAY (the terminal hop)
 *      during setup. The gateway holds K_ret (a circuit-scoped key — NOT a
 *      relay key) + the opaque envelope (it cannot decrypt any envelope
 *      layer without the returnKeys).
 *
 *   3. To send a return response, the GATEWAY:
 *        - Seals the response payload with K_ret: sealedPayload = AEAD(K_ret, nonce, payload, AD).
 *        - Constructs a backward CircuitFrame with ciphertext = CBOR { sealedPayload, envelope }.
 *        - Sends to hop N-1.
 *
 *   4. Each RELAY (hop i, from N-1 down to 1):
 *        - Decodes the ciphertext as { sealedPayload, envelopeLayer }.
 *        - Peels its returnKey from the envelopeLayer: innerEnv = AEAD_decrypt(returnKey_i, envelopeLayer).
 *        - Forwards { sealedPayload, innerEnv } to hop i-1.
 *
 *   5. The SOURCE (hop 0):
 *        - Peels the final envelope layer: K_ret = AEAD_decrypt(returnKey_0, envelopeLayer).
 *        - Decrypts the sealedPayload with K_ret → plaintext.
 *        - Delivers.
 *
 * SECURITY PROPERTIES:
 *   - The gateway holds K_ret (circuit-scoped) — NOT the per-hop returnKeys.
 *     It cannot decrypt forward traffic or intermediate returnKey layers.
 *   - Each relay peels only its own returnKey layer (onion property preserved
 *     for key distribution).
 *   - The response payload is sealed once with K_ret. Intermediate relays
 *     see the sealed payload but cannot decrypt it (they don't hold K_ret).
 *   - All material is bound to (commitmentRoot, circuitId, direction=BACKWARD).
 *
 * This is the standard "return onion without the gateway holding all keys"
 * design: the onion is on the KEY DISTRIBUTION (the envelope), and the
 * payload is sealed with a circuit-scoped key that the gateway holds.
 *
 * The existing `sealReturnFrame()` (in frame.ts) remains as a single-process
 * TEST PRIMITIVE (valid when one process holds all returnKeys). The
 * distributed production path uses the template-based functions in this module.
 */

import { randomBytes } from "@noble/hashes/utils.js";
import { canonicalEncode, canonicalDecode, toHex } from "../encoding/cbor";
import {
  buildNonce,
  buildCircuitFrameAD,
  encryptPayload,
  decryptPayload,
  AEAD_KEY_BYTES,
  AEAD_NONCE_BYTES,
  deriveCircuitId,
  deriveNoncePrefix,
  type ActiveCircuit,
} from "./circuit";
import { DIRECTION_BACKWARD } from "./frame";

// -----------------------------------------------------------------------
// Constants (R-009 Stage 2 — return-onion template)
// -----------------------------------------------------------------------

/** Domain tag for return-onion envelope AEAD (binds the envelope to the circuit). */
export const RETURN_ENVELOPE_DOMAIN = "SHARENET/CIRCUIT/RETURN/ENV/1";

/** Domain tag for return payload AEAD (the K_ret-sealed payload). */
export const RETURN_PAYLOAD_DOMAIN = "SHARENET/CIRCUIT/RETURN/PAYLOAD/1";

// -----------------------------------------------------------------------
// ReturnOnionTemplate wire object
// -----------------------------------------------------------------------

/**
 * The return-onion template — distributed by the initiator to the gateway
 * during circuit setup.
 *
 * Contains:
 *   - circuitId: binds the template to the specific circuit instance.
 *   - commitmentRoot: binds to the route (for AD construction).
 *   - kRet: the circuit-scoped return key (held by the gateway; NOT a relay key).
 *   - envelope: the outermost AEAD layer (opaque to the gateway; each relay
 *     peels one returnKey layer).
 *
 * The gateway uses { kRet, envelope } to seal return responses. It does NOT
 * hold any per-hop returnKey.
 */
export interface ReturnOnionTemplate {
  /** The 32-byte CircuitId (binds to the circuit instance). */
  circuitId: Uint8Array;
  /** The 32-byte commitment_root (route identity — for AD + floor keying). */
  commitmentRoot: Uint8Array;
  /** The 64-bit nonce prefix (bound to the circuit instance per ADR-0020). */
  noncePrefix: Uint8Array;
  /** The circuit-scoped return key K_ret (32 bytes). Held by the gateway. */
  kRet: Uint8Array;
  /** The outermost envelope layer (opaque to the gateway). N AEAD layers deep. */
  envelope: Uint8Array;
}

// -----------------------------------------------------------------------
// Template construction (initiator-side, during setup)
// -----------------------------------------------------------------------

/**
 * Construct a ReturnOnionTemplate during circuit setup.
 *
 * The INITIATOR calls this after all relay acks are verified + all returnKeys
 * are derived. The template is then sent to the gateway (the terminal hop).
 *
 * Construction:
 *   1. Generate a fresh K_ret (32-byte AEAD key).
 *   2. Wrap K_ret in N nested AEAD layers (one per hop's returnKey):
 *        env_0     = AEAD(returnKey_0, K_ret)
 *        env_1     = AEAD(returnKey_1, env_0)
 *        ...
 *        env_{N-1} = AEAD(returnKey_{N-1}, env_{N-2})
 *   3. The envelope = env_{N-1} (the outermost layer — for hop N-1).
 *
 * The gateway receives { circuitId, commitmentRoot, noncePrefix, kRet, envelope }.
 * It holds kRet (to seal return payloads) + the opaque envelope (to attach to
 * each return frame). It does NOT hold any per-hop returnKey.
 *
 * @param circuit - the active circuit (carries all per-hop returnKeys)
 * @returns the ReturnOnionTemplate
 */
export function constructReturnOnionTemplate(
  circuit: ActiveCircuit,
  /**
   * TEST-ONLY hook: a fixed K_ret (32 bytes).
   *
   * When provided, the template uses this K_ret instead of a fresh random one.
   * This lets conformance vectors produce deterministic outputs. Production
   * callers MUST leave this undefined so K_ret is fresh + unpredictable.
   */
  kRetForTest?: Uint8Array,
): ReturnOnionTemplate {
  // Generate the circuit-scoped return key K_ret.
  const kRet = kRetForTest ?? randomBytes(AEAD_KEY_BYTES);

  // Wrap K_ret in N nested AEAD layers, from hop 0 (innermost) to hop N-1 (outermost).
  // Each layer is AEAD-encrypted under the hop's returnKey, bound to the circuit.
  let envelope: Uint8Array = kRet;
  for (let i = 0; i < circuit.hops.length; i++) {
    const hop = circuit.hops[i]!;
    const returnKey = hop.returnKey;
    const ad = buildReturnEnvelopeAD(circuit.commitmentRoot, i);
    // Use a fixed nonce for the envelope (the envelope is a one-time setup
    // artifact, not a streaming frame — nonce uniqueness is per-envelope-layer
    // + the AD binds to the hopIndex, so each layer has a distinct AD).
    // Per spec: the envelope nonce = circuit_nonce_prefix || hopIndex (big-endian u32).
    // This is distinct per hop, so no nonce reuse across layers.
    const nonce = buildReturnEnvelopeNonce(circuit.noncePrefix, i);
    envelope = encryptPayload(returnKey, nonce, envelope, ad);
  }

  return {
    circuitId: circuit.circuitId,
    commitmentRoot: circuit.commitmentRoot,
    noncePrefix: circuit.noncePrefix,
    kRet,
    envelope,
  };
}

// -----------------------------------------------------------------------
// Gateway-side: seal a return response using the template
// -----------------------------------------------------------------------

/**
 * The ciphertext payload of a backward frame in the distributed (template-based) model.
 *
 * This is a CBOR pair:
 *   { 1: sealedPayload (bstr), 2: envelopeLayer (bstr) }
 *
 * - sealedPayload: the response sealed with K_ret (single AEAD layer).
 * - envelopeLayer: the remaining return-onion envelope (one layer is peeled
 *   per relay as the frame travels backward toward the source).
 *
 * Each relay decodes this, peels its returnKey from envelopeLayer, keeps
 * sealedPayload, and forwards { sealedPayload, innerEnvelope }.
 */
export interface ReturnFramePayload {
  /** The response payload sealed with K_ret. */
  sealedPayload: Uint8Array;
  /** The remaining envelope layer (opaque to the gateway; each relay peels one). */
  envelopeLayer: Uint8Array;
}

/**
 * Seal a return response using the ReturnOnionTemplate (distributed path).
 *
 * The GATEWAY calls this. It does NOT hold any per-hop returnKey — only K_ret
 * (the circuit-scoped key) + the opaque envelope.
 *
 * The gateway:
 *   1. Seals the response with K_ret: sealedPayload = AEAD(K_ret, nonce, response, AD).
 *   2. Wraps { sealedPayload, envelope } into the backward frame's ciphertext.
 *
 * The resulting CircuitFrame (direction=BACKWARD) has its ciphertext set to
 * the CBOR-encoded { sealedPayload, envelopeLayer } pair. Each relay peels
 * one envelope layer + forwards; the source recovers K_ret + decrypts.
 *
 * @param template - the ReturnOnionTemplate (held by the gateway)
 * @param frameSequence - the 32-bit frame sequence
 * @param plaintext - the response payload to send back to the source
 * @returns the backward frame's ciphertext (CBOR-encoded ReturnFramePayload)
 */
export function sealReturnFrameFromTemplate(
  template: ReturnOnionTemplate,
  frameSequence: number,
  plaintext: Uint8Array,
): Uint8Array {
  if (!Number.isInteger(frameSequence) || frameSequence < 1 || frameSequence > 0xffffffff) {
    throw new Error(
      `sealReturnFrameFromTemplate: frameSequence must be a u32 ≥ 1, got ${frameSequence}`,
    );
  }

  // Seal the response with K_ret (single AEAD layer).
  const nonce = buildNonce(template.noncePrefix, frameSequence);
  const ad = buildReturnPayloadAD(template.commitmentRoot, frameSequence);
  const sealedPayload = encryptPayload(template.kRet, nonce, plaintext, ad);

  // Wrap { sealedPayload, envelope } into the ciphertext (CBOR pair).
  const payload: ReturnFramePayload = {
    sealedPayload,
    envelopeLayer: template.envelope,
  };
  return encodeReturnFramePayload(payload);
}

// -----------------------------------------------------------------------
// Relay-side: peel one envelope layer + forward
// -----------------------------------------------------------------------

/**
 * Result of peeling one return envelope layer at a relay.
 *
 * - `{ ok: true, innerPayload }`: the envelope layer was peeled; `innerPayload`
 *   is the { sealedPayload, innerEnvelope } to forward to the next hop.
 *   If this was the FINAL layer (terminal = the source), `innerPayload.kRet`
 *   is set + `innerPayload.sealedPayload` should be decrypted with it.
 * - `{ ok: false, reason }`: AEAD failed (tampered envelope, wrong returnKey).
 */
export type PeelReturnEnvelopeResult =
  | { ok: true; innerPayload: ReturnFramePayload; isTerminal: boolean; kRet?: Uint8Array }
  | { ok: false; reason: string };

/**
 * Peel one return envelope layer at a relay (backward frame, distributed path).
 *
 * The RELAY calls this. It:
 *   1. Decodes the backward frame's ciphertext as { sealedPayload, envelopeLayer }.
 *   2. Peels its returnKey from the envelopeLayer:
 *        innerEnv = AEAD_decrypt(returnKey_i, envelopeLayer, AD).
 *   3. If the peeled result is 32 bytes, it's K_ret (this is the terminal hop = source).
 *      Otherwise, it's the next envelope layer (forward to hop i-1).
 *   4. Constructs { sealedPayload, innerEnvelope } for the next hop.
 *
 * The sealedPayload is NOT touched by the relay — it only peels the envelope
 * (key distribution). The source (terminal) decrypts the sealedPayload with K_ret.
 *
 * @param circuit - the active circuit (carries the relay's returnKey)
 * @param hopIndex - which relay hop is processing (0-based)
 * @param ciphertext - the backward frame's ciphertext (CBOR-encoded ReturnFramePayload)
 * @returns the peel result
 */
export function peelReturnEnvelopeLayer(
  circuit: ActiveCircuit,
  hopIndex: number,
  ciphertext: Uint8Array,
): PeelReturnEnvelopeResult {
  const hop = circuit.hops[hopIndex];
  if (!hop) {
    return { ok: false, reason: `no hop at index ${hopIndex}` };
  }

  // Decode the ciphertext as { sealedPayload, envelopeLayer }.
  let payload: ReturnFramePayload;
  try {
    payload = decodeReturnFramePayload(ciphertext);
  } catch (e) {
    return { ok: false, reason: `return payload decode failed: ${(e as Error).message}` };
  }

  // Peel the relay's returnKey from the envelopeLayer.
  const returnKey = hop.returnKey;
  const ad = buildReturnEnvelopeAD(circuit.commitmentRoot, hopIndex);
  const nonce = buildReturnEnvelopeNonce(circuit.noncePrefix, hopIndex);

  let peeled: Uint8Array;
  try {
    peeled = decryptPayload(returnKey, nonce, payload.envelopeLayer, ad);
  } catch (e) {
    return { ok: false, reason: `AEAD envelope peel failed: ${(e as Error).message}` };
  }

  // If the peeled result is exactly 32 bytes, it's K_ret — this is the terminal
  // hop (the source). The source uses K_ret to decrypt the sealedPayload.
  const isTerminal = (peeled.length === AEAD_KEY_BYTES);

  if (isTerminal) {
    // Terminal hop (source): return K_ret so the caller can decrypt the sealedPayload.
    return {
      ok: true,
      innerPayload: payload,
      isTerminal: true,
      kRet: peeled,
    };
  }

  // Intermediate hop: forward { sealedPayload, innerEnvelope } to the next hop.
  const innerPayload: ReturnFramePayload = {
    sealedPayload: payload.sealedPayload,
    envelopeLayer: peeled,
  };
  return { ok: true, innerPayload, isTerminal: false };
}

// -----------------------------------------------------------------------
// Source-side: decrypt the return payload with K_ret (terminal hop)
// -----------------------------------------------------------------------

/**
 * Decrypt the return payload with K_ret (terminal hop = source).
 *
 * The SOURCE calls this after `peelReturnEnvelopeLayer` returns `isTerminal=true`
 * + `kRet`. It decrypts the sealedPayload with K_ret to recover the response.
 *
 * @param kRet - the circuit-scoped return key (recovered from the envelope)
 * @param noncePrefix - the circuit nonce prefix
 * @param commitmentRoot - the route commitment root (for AD)
 * @param frameSequence - the frame sequence (for AD + nonce)
 * @param sealedPayload - the sealed response payload
 * @returns the decrypted response plaintext
 */
export function decryptReturnPayload(
  kRet: Uint8Array,
  noncePrefix: Uint8Array,
  commitmentRoot: Uint8Array,
  frameSequence: number,
  sealedPayload: Uint8Array,
): { ok: true; plaintext: Uint8Array } | { ok: false; reason: string } {
  const nonce = buildNonce(noncePrefix, frameSequence);
  const ad = buildReturnPayloadAD(commitmentRoot, frameSequence);
  try {
    const plaintext = decryptPayload(kRet, nonce, sealedPayload, ad);
    return { ok: true, plaintext };
  } catch (e) {
    return { ok: false, reason: `return payload decrypt failed: ${(e as Error).message}` };
  }
}

// -----------------------------------------------------------------------
// AD + nonce construction for the return envelope + payload
// -----------------------------------------------------------------------

/**
 * Build the AEAD AD for a return envelope layer.
 *
 * Binds the envelope to: domain || commitment_root || hopIndex.
 * (The hopIndex distinguishes each layer — no nonce reuse across layers.)
 */
function buildReturnEnvelopeAD(commitmentRoot: Uint8Array, hopIndex: number): Uint8Array {
  const domain = new TextEncoder().encode(RETURN_ENVELOPE_DOMAIN);
  const ad = new Uint8Array(domain.length + 32 + 1);
  ad.set(domain, 0);
  ad.set(commitmentRoot, domain.length);
  ad[domain.length + 32] = hopIndex;
  return ad;
}

/**
 * Build the nonce for a return envelope layer.
 *
 * Per layer: nonce = circuit_nonce_prefix (8 bytes) || hopIndex (4 bytes big-endian).
 * This gives each layer a distinct nonce (no reuse).
 */
function buildReturnEnvelopeNonce(noncePrefix: Uint8Array, hopIndex: number): Uint8Array {
  const nonce = new Uint8Array(AEAD_NONCE_BYTES);
  nonce.set(noncePrefix, 0);
  const dv = new DataView(nonce.buffer);
  dv.setUint32(8, hopIndex, false); // big-endian
  return nonce;
}

/**
 * Build the AEAD AD for the return payload (K_ret-sealed).
 *
 * Binds the payload to: domain || commitment_root || frame_sequence || direction.
 * (Same structure as the forward frame AD, but with the RETURN_PAYLOAD_DOMAIN.)
 */
function buildReturnPayloadAD(commitmentRoot: Uint8Array, frameSequence: number): Uint8Array {
  const domain = new TextEncoder().encode(RETURN_PAYLOAD_DOMAIN);
  const ad = new Uint8Array(domain.length + 32 + 4 + 1);
  ad.set(domain, 0);
  ad.set(commitmentRoot, domain.length);
  const dv = new DataView(ad.buffer, domain.length + 32);
  dv.setUint32(0, frameSequence, false); // big-endian
  ad[domain.length + 32 + 4] = DIRECTION_BACKWARD;
  return ad;
}

// -----------------------------------------------------------------------
// ReturnFramePayload CBOR encode/decode
// -----------------------------------------------------------------------

const RETURN_PAYLOAD_KEY_SEALED = 1;
const RETURN_PAYLOAD_KEY_ENVELOPE = 2;

/**
 * Encode a ReturnFramePayload to canonical CBOR (the backward frame's ciphertext).
 *
 * Used by the gateway to construct the initial backward frame ciphertext, AND
 * by relays to re-encode the inner { sealedPayload, innerEnvelope } pair after
 * peeling one envelope layer (for forwarding to the next hop).
 */
export function encodeReturnFramePayload(payload: ReturnFramePayload): Uint8Array {
  const m = new Map<number, unknown>([
    [RETURN_PAYLOAD_KEY_SEALED, payload.sealedPayload],
    [RETURN_PAYLOAD_KEY_ENVELOPE, payload.envelopeLayer],
  ]);
  return canonicalEncode(m);
}

/**
 * Decode a ReturnFramePayload from canonical CBOR (the backward frame's ciphertext).
 */
function decodeReturnFramePayload(bytes: Uint8Array): ReturnFramePayload {
  // Minimal canonical CBOR decode for the 2-key integer-keyed map.
  let decoded: unknown;
  try {
    decoded = canonicalDecode(bytes);
  } catch (e) {
    throw new Error(`CBOR decode failed: ${(e as Error).message}`);
  }
  if (!(decoded instanceof Map)) {
    throw new Error("ReturnFramePayload must be a CBOR map");
  }
  const m = decoded as Map<number, unknown>;
  const sealed = m.get(RETURN_PAYLOAD_KEY_SEALED);
  const envelope = m.get(RETURN_PAYLOAD_KEY_ENVELOPE);
  if (!(sealed instanceof Uint8Array) || !(envelope instanceof Uint8Array)) {
    throw new Error("ReturnFramePayload missing sealedPayload or envelopeLayer");
  }
  return { sealedPayload: sealed, envelopeLayer: envelope };
}

export { toHex };
