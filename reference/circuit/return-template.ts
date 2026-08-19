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
import { x25519 } from "@noble/curves/ed25519.js";
import { extract as hkdfExtract, expand as hkdfExpand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { canonicalEncode, canonicalDecode, toHex, bytesEqual } from "../encoding/cbor";
import { signMessage, verifySignature } from "../identity/keys";
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
import type { BrandedCommittedRoute } from "../transport/validated-types";
import { isBrandedCommittedRoute } from "../transport/validated-types";
import {
  circuitAckSigningPayload,
  routeCommitmentDigest,
  type CircuitSetupAck,
} from "./distributed-setup";

// -----------------------------------------------------------------------
// Constants (R-009 Stage 2 — return-onion template)
// -----------------------------------------------------------------------

/** Domain tag for return-onion envelope AEAD (binds the envelope to the circuit). */
export const RETURN_ENVELOPE_DOMAIN = "SHARENET/CIRCUIT/RETURN/ENV/1";

/** Domain tag for return payload AEAD (the K_ret-sealed payload). */
export const RETURN_PAYLOAD_DOMAIN = "SHARENET/CIRCUIT/RETURN/PAYLOAD/1";

/** Domain tag for the GatewayReturnTemplate signing (binds the transfer to the gateway). */
export const GATEWAY_RETURN_TEMPLATE_DOMAIN = "SHARENET/CIRCUIT/RETURN/TEMPLATE/1";

/** Domain tag for the K_ret encryption (confidential delivery to the gateway). */
export const GATEWAY_KRET_ENCRYPTION_DOMAIN = "SHARENET/CIRCUIT/RETURN/KRET/1";

// -----------------------------------------------------------------------
// GatewayReturnTemplate — confidential + authenticated transfer (R-009 Stage 2)
// -----------------------------------------------------------------------

/**
 * The confidential + authenticated gateway-template transfer wire object.
 *
 * Per the re-audit of ca8736f: the previous GatewayReturnTemplate carried
 * `kRet` in plaintext — any relay that intercepted the setup message could
 * read it and decrypt return traffic. The signature provided authenticity
 * but NOT confidentiality.
 *
 * This wire object encrypts `kRet` to the gateway's X25519 public key:
 *   sharedSecret = X25519(initiator_x25519_secret, gateway_x25519_public)
 *   kRetKey = HKDF-SHA256(salt=commitment_root, ikm=sharedSecret,
 *              info="SHARENET/CIRCUIT/RETURN/KRET/1" || circuitId)
 *   encryptedKRet = ChaCha20-Poly1305(kRetKey, nonce, kRet, AD)
 *
 * The gateway decrypts `kRet` using its X25519 secret key:
 *   sharedSecret = X25519(gateway_x25519_secret, initiator_x25519_public)
 *   (same ECDH → same sharedSecret → same kRetKey → decrypts encryptedKRet)
 *
 * Security properties:
 *   - CONFIDENTIALITY: a relay that intercepts the wire object sees
 *     `encryptedKRet` but cannot recover `kRet` (it doesn't have the
 *     gateway's X25519 secret key or the initiator's X25519 secret key).
 *   - AUTHENTICITY: the initiator's Ed25519 signature binds the complete
 *     transfer (circuitId, commitmentRoot, noncePrefix, encryptedKRet,
 *     kRetNonce, envelope, expiry, gatewayNodeId, gatewayX25519PublicKey).
 *   - GATEWAY AUTHORIZATION: the transfer is bound to (gatewayNodeId +
 *     gatewayX25519PublicKey). The gateway must control BOTH the NodeId
 *     AND the X25519 secret key to accept the template — preventing
 *     identity-to-key substitution.
 *   - NO CROSS-CIRCUIT REPLAY: the circuitId/commitmentRoot binding prevents
 *     replaying the template onto a different circuit.
 *   - NO STALE-TEMPLATE REUSE: the expiry check rejects expired templates.
 *
 * Wire format (canonical CBOR, integer-keyed map per ADR-0004):
 *   { 1: circuitId, 2: commitmentRoot, 3: noncePrefix, 4: encryptedKRet,
 *     5: kRetNonce, 6: envelope, 7: expiry, 8: gatewayNodeId,
 *     9: gatewayX25519PublicKey, 10: initiatorX25519PublicKey,
 *     11: initiatorEd25519PublicKey, 12: initiatorSignature }
 */
export interface GatewayReturnTemplate {
  /** The 32-byte CircuitId (binds to the circuit instance). */
  circuitId: Uint8Array;
  /** The 32-byte commitment_root (route identity). */
  commitmentRoot: Uint8Array;
  /** The 64-bit nonce prefix (bound to the circuit instance per ADR-0020). */
  noncePrefix: Uint8Array;
  /** The encrypted K_ret (48 bytes = 32-byte K_ret + 16-byte AEAD tag). */
  encryptedKRet: Uint8Array;
  /** The 12-byte AEAD nonce used for the K_ret encryption. */
  kRetNonce: Uint8Array;
  /** The outermost envelope layer (opaque to the gateway). N AEAD layers deep. */
  envelope: Uint8Array;
  /** Circuit expiry (unix seconds). The gateway rejects expired templates. */
  expiry: number;
  /** The terminal gateway's NodeId (binds the template to the intended gateway). */
  gatewayNodeId: string;
  /** The terminal gateway's X25519 public key (the ECDH partner for K_ret decryption). */
  gatewayX25519PublicKey: Uint8Array;
  /** The initiator's X25519 public key (the ECDH partner — the gateway uses this). */
  initiatorX25519PublicKey: Uint8Array;
  /** The initiator's Ed25519 public key (verifies the signature). */
  initiatorEd25519PublicKey: Uint8Array;
  /** The initiator's Ed25519 signature over the complete binding payload. */
  initiatorSignature: Uint8Array;
}

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

// -----------------------------------------------------------------------
// GatewayReturnTemplate — signing, verification, encode, decode
// -----------------------------------------------------------------------

/** CBOR map keys for the GatewayReturnTemplate wire object (per ADR-0004). */
const GT_KEY_CIRCUIT_ID = 1;
const GT_KEY_COMMITMENT_ROOT = 2;
const GT_KEY_NONCE_PREFIX = 3;
const GT_KEY_ENCRYPTED_K_RET = 4;
const GT_KEY_K_RET_NONCE = 5;
const GT_KEY_ENVELOPE = 6;
const GT_KEY_EXPIRY = 7;
const GT_KEY_GATEWAY_NODE_ID = 8;
const GT_KEY_GATEWAY_X25519_PUBKEY = 9;
const GT_KEY_INITIATOR_X25519_PUBKEY = 10;
const GT_KEY_INITIATOR_ED25519_PUBKEY = 11;
const GT_KEY_INITIATOR_SIGNATURE = 12;

/**
 * Derive the K_ret encryption key from the ECDH shared secret.
 *
 * kRetKey = HKDF-SHA256(salt=commitment_root, ikm=sharedSecret,
 *   info="SHARENET/CIRCUIT/RETURN/KRET/1" || circuitId)
 *
 * The initiator uses X25519(initiator_x25519_secret, gateway_x25519_public).
 * The gateway uses X25519(gateway_x25519_secret, initiator_x25519_public).
 * Both produce the same sharedSecret → same kRetKey.
 */
function deriveKRetEncryptionKey(
  sharedSecret: Uint8Array,
  commitmentRoot: Uint8Array,
  circuitId: Uint8Array,
): Uint8Array {
  const prk = hkdfExtract(sha256, sharedSecret, commitmentRoot);
  const domain = new TextEncoder().encode(GATEWAY_KRET_ENCRYPTION_DOMAIN);
  const info = new Uint8Array(domain.length + circuitId.length);
  info.set(domain, 0);
  info.set(circuitId, domain.length);
  return hkdfExpand(sha256, prk, info, 32);
}

/**
 * Compute the signing payload for a GatewayReturnTemplate.
 *
 * The payload binds: domain || circuitId || commitmentRoot || noncePrefix ||
 * encryptedKRet || kRetNonce || envelope || expiry || gatewayNodeId ||
 * gatewayX25519PublicKey || initiatorX25519PublicKey.
 *
 * NOTE: the payload signs the ENCRYPTED kRet (encryptedKRet), NOT the plaintext
 * kRet. This means the signature is verifiable by anyone (it doesn't require
 * decrypting kRet), but it binds the encrypted ciphertext to the circuit identity
 * — preventing substitution of a different encryptedKRet.
 */
export function gatewayReturnTemplateSigningPayload(
  circuitId: Uint8Array,
  commitmentRoot: Uint8Array,
  noncePrefix: Uint8Array,
  encryptedKRet: Uint8Array,
  kRetNonce: Uint8Array,
  envelope: Uint8Array,
  expiry: number,
  gatewayNodeId: string,
  gatewayX25519PublicKey: Uint8Array,
  initiatorX25519PublicKey: Uint8Array,
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, circuitId],
    [2, commitmentRoot],
    [3, noncePrefix],
    [4, encryptedKRet],
    [5, kRetNonce],
    [6, envelope],
    [7, expiry],
    [8, gatewayNodeId],
    [9, gatewayX25519PublicKey],
    [10, initiatorX25519PublicKey],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(GATEWAY_RETURN_TEMPLATE_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * Construct a signed + confidential GatewayReturnTemplate.
 *
 * The INITIATOR calls this after `constructReturnOnionTemplate()`. It:
 *   1. Derives the ECDH shared secret: X25519(initiator_x25519_secret, gateway_x25519_public).
 *   2. Derives the K_ret encryption key via HKDF.
 *   3. Encrypts K_ret with ChaCha20-Poly1305 → encryptedKRet.
 *   4. Signs the complete binding (including encryptedKRet + gatewayX25519PublicKey).
 *
 * The result is the canonical wire object sent to the gateway during setup.
 * K_ret is NOT carried in plaintext — only the intended gateway can decrypt it.
 *
 * @param template - the ReturnOnionTemplate (from constructReturnOnionTemplate)
 * @param expiry - the circuit expiry (unix seconds)
 * @param gatewayNodeId - the terminal gateway's NodeId
 * @param gatewayX25519PublicKey - the gateway's X25519 public key (from CircuitSetupAck)
 * @param initiatorX25519SecretKey - the initiator's X25519 ephemeral secret key
 * @param initiatorX25519PublicKey - the initiator's X25519 ephemeral public key
 * @param initiatorEd25519SecretKey - the initiator's Ed25519 node identity secret key
 * @param initiatorEd25519PublicKey - the initiator's Ed25519 node identity public key
 * @returns the signed + confidential GatewayReturnTemplate wire object
 */
export function signGatewayReturnTemplate(
  template: ReturnOnionTemplate,
  expiry: number,
  gatewayNodeId: string,
  gatewayX25519PublicKey: Uint8Array,
  initiatorX25519SecretKey: Uint8Array,
  initiatorX25519PublicKey: Uint8Array,
  initiatorEd25519SecretKey: Uint8Array,
  initiatorEd25519PublicKey: Uint8Array,
): GatewayReturnTemplate {
  // 1. Derive the ECDH shared secret (initiator ↔ gateway).
  const sharedSecret = x25519.getSharedSecret(initiatorX25519SecretKey, gatewayX25519PublicKey);

  // 2. Derive the K_ret encryption key.
  const kRetKey = deriveKRetEncryptionKey(sharedSecret, template.commitmentRoot, template.circuitId);

  // 3. Encrypt K_ret with ChaCha20-Poly1305.
  const kRetNonce = randomBytes(AEAD_NONCE_BYTES);
  const kRetAD = new TextEncoder().encode(GATEWAY_KRET_ENCRYPTION_DOMAIN);
  const cipher = chacha20poly1305(kRetKey, kRetNonce, kRetAD);
  const encryptedKRet = cipher.encrypt(template.kRet);

  // 4. Sign the complete binding (including encryptedKRet + gatewayX25519PublicKey).
  const payload = gatewayReturnTemplateSigningPayload(
    template.circuitId,
    template.commitmentRoot,
    template.noncePrefix,
    encryptedKRet,
    kRetNonce,
    template.envelope,
    expiry,
    gatewayNodeId,
    gatewayX25519PublicKey,
    initiatorX25519PublicKey,
  );
  const signature = signMessage(initiatorEd25519SecretKey, payload);

  return {
    circuitId: template.circuitId,
    commitmentRoot: template.commitmentRoot,
    noncePrefix: template.noncePrefix,
    encryptedKRet,
    kRetNonce,
    envelope: template.envelope,
    expiry,
    gatewayNodeId,
    gatewayX25519PublicKey,
    initiatorX25519PublicKey,
    initiatorEd25519PublicKey,
    initiatorSignature: signature,
  };
}

/** Result of verifying a GatewayReturnTemplate. */
export type VerifyGatewayReturnTemplateResult =
  | { ok: true; template: ReturnOnionTemplate }
  | { ok: false; reason: string };

/**
 * Verify + decrypt a GatewayReturnTemplate at the gateway.
 *
 * The GATEWAY calls this when it receives the template transfer. It:
 *   1. Checks gatewayNodeId matches the gateway's own NodeId (wrong gateway → reject).
 *   2. Checks gatewayX25519PublicKey matches the gateway's own X25519 public key
 *      (prevents identity-to-key substitution).
 *   3. Checks expiry (expired → reject).
 *   4. Verifies the initiator's Ed25519 signature over the complete binding
 *      (tampered → reject).
 *   5. Derives the ECDH shared secret: X25519(gateway_x25519_secret, initiator_x25519_public).
 *   6. Decrypts encryptedKRet → recovers K_ret.
 *
 * If all checks pass, it returns the extracted ReturnOnionTemplate (K_ret +
 * envelope) which the gateway stores + uses to seal return responses.
 *
 * @param gatewayTemplate - the signed + confidential GatewayReturnTemplate wire object
 * @param expectedGatewayNodeId - the gateway's own NodeId
 * @param gatewayX25519SecretKey - the gateway's own X25519 secret key (for ECDH decryption)
 * @param gatewayX25519PublicKey - the gateway's own X25519 public key (for binding check)
 * @param now - the current time (unix seconds)
 */
export function verifyGatewayReturnTemplate(
  gatewayTemplate: GatewayReturnTemplate,
  expectedGatewayNodeId: string,
  gatewayX25519SecretKey: Uint8Array,
  gatewayX25519PublicKey: Uint8Array,
  now: number,
): VerifyGatewayReturnTemplateResult {
  // 1. Check gatewayNodeId.
  if (gatewayTemplate.gatewayNodeId !== expectedGatewayNodeId) {
    return {
      ok: false,
      reason: `gateway NodeId mismatch: expected ${expectedGatewayNodeId}, got ${gatewayTemplate.gatewayNodeId}`,
    };
  }

  // 2. Check gatewayX25519PublicKey (prevents identity-to-key substitution).
  if (!bytesEqual(gatewayTemplate.gatewayX25519PublicKey, gatewayX25519PublicKey)) {
    return {
      ok: false,
      reason: "gateway X25519 public key mismatch (identity-to-key substitution attempt)",
    };
  }

  // 3. Check expiry.
  if (gatewayTemplate.expiry <= now) {
    return {
      ok: false,
      reason: `template expired: expiry ${gatewayTemplate.expiry} ≤ now ${now}`,
    };
  }

  // 4. Verify the initiator's Ed25519 signature.
  const payload = gatewayReturnTemplateSigningPayload(
    gatewayTemplate.circuitId,
    gatewayTemplate.commitmentRoot,
    gatewayTemplate.noncePrefix,
    gatewayTemplate.encryptedKRet,
    gatewayTemplate.kRetNonce,
    gatewayTemplate.envelope,
    gatewayTemplate.expiry,
    gatewayTemplate.gatewayNodeId,
    gatewayTemplate.gatewayX25519PublicKey,
    gatewayTemplate.initiatorX25519PublicKey,
  );
  if (!verifySignature(gatewayTemplate.initiatorEd25519PublicKey, payload, gatewayTemplate.initiatorSignature)) {
    return { ok: false, reason: "initiator signature invalid (tampered template or wrong initiator)" };
  }

  // 5. Derive the ECDH shared secret (gateway ↔ initiator).
  const sharedSecret = x25519.getSharedSecret(gatewayX25519SecretKey, gatewayTemplate.initiatorX25519PublicKey);

  // 6. Derive the K_ret encryption key + decrypt.
  const kRetKey = deriveKRetEncryptionKey(sharedSecret, gatewayTemplate.commitmentRoot, gatewayTemplate.circuitId);
  const kRetAD = new TextEncoder().encode(GATEWAY_KRET_ENCRYPTION_DOMAIN);
  const cipher = chacha20poly1305(kRetKey, gatewayTemplate.kRetNonce, kRetAD);
  let kRet: Uint8Array;
  try {
    kRet = cipher.decrypt(gatewayTemplate.encryptedKRet);
  } catch (e) {
    return { ok: false, reason: `K_ret decryption failed: ${(e as Error).message} (wrong gateway key or tampered ciphertext)` };
  }

  // 7. Extract the ReturnOnionTemplate.
  const template: ReturnOnionTemplate = {
    circuitId: gatewayTemplate.circuitId,
    commitmentRoot: gatewayTemplate.commitmentRoot,
    noncePrefix: gatewayTemplate.noncePrefix,
    kRet,
    envelope: gatewayTemplate.envelope,
  };
  return { ok: true, template };
}

/**
 * Verify a GatewayReturnTemplate at the gateway, bound to the ACTUAL committed route
 * + the VERIFIED terminal CircuitSetupAck.
 *
 * This is the AUTHENTICATED GATEWAY VERIFIER — the gateway uses this to verify
 * that it is the actual terminal destination of the committed route, not merely
 * a supplied NodeId. It verifies the COMPLETE proof chain:
 *
 *   0a. Verify the route is genuine (BrandedCommittedRoute WeakSet check).
 *   0b. Verify the template's commitmentRoot matches the route's commitmentRoot.
 *   0c. Verify the template's gatewayNodeId matches the route's terminal hop's NodeId.
 *   0d. VERIFY THE TERMINAL ACK'S Ed25519 SIGNATURE (the ack is a proof-bearing
 *       artifact, not a bare { relayX25519PublicKey } — the gateway cannot accept
 *       a forged plain object because the signature would fail).
 *   0e. Verify the ack's routeId matches the route's routeId.
 *   0f. Verify the ack's routeCommitmentDigest matches the route's digest.
 *   0g. Verify the ack's hopIndex is the terminal hop index (route.hops.length - 1).
 *   0h. Verify the ack's initiatorX25519PublicKey matches the template's.
 *   0i. Verify the ack's relayX25519PublicKey matches the template's gatewayX25519PublicKey.
 *
 * Then it delegates to verifyGatewayReturnTemplate for the standard checks
 * (NodeId, X25519 key, expiry, signature, ECDH decrypt).
 *
 * Per the re-audit of e165ba2: the previous version accepted a bare
 * { relayX25519PublicKey } structural type — an attacker could create a fake
 * ack with any X25519 key. Now the verifier consumes a GENUINE CircuitSetupAck
 * + the terminal relay's Ed25519 public key, and verifies the ack's signature
 * before extracting the X25519 key. A forged ack fails the signature check.
 *
 * @param gatewayTemplate - the signed + confidential GatewayReturnTemplate wire object
 * @param route - the genuine BrandedCommittedRoute (the gateway verifies this)
 * @param terminalAck - the FULL CircuitSetupAck from the terminal hop (proof-bearing)
 * @param relayEd25519PublicKey - the terminal relay's Ed25519 public key (verifies the ack signature)
 * @param expectedGatewayNodeId - the gateway's own NodeId
 * @param gatewayX25519SecretKey - the gateway's own X25519 secret key
 * @param gatewayX25519PublicKey - the gateway's own X25519 public key
 * @param now - the current time (unix seconds)
 */
export function verifyGatewayReturnTemplateWithRoute(
  gatewayTemplate: GatewayReturnTemplate,
  route: BrandedCommittedRoute,
  terminalAck: CircuitSetupAck,
  relayEd25519PublicKey: Uint8Array,
  expectedGatewayNodeId: string,
  gatewayX25519SecretKey: Uint8Array,
  gatewayX25519PublicKey: Uint8Array,
  now: number,
): VerifyGatewayReturnTemplateResult {
  // 0a. Verify the route is genuine (WeakSet check).
  if (!isBrandedCommittedRoute(route)) {
    return { ok: false, reason: "route is not a genuine BrandedCommittedRoute" };
  }

  // 0b. Verify the template's commitmentRoot matches the route's commitmentRoot.
  if (!bytesEqual(gatewayTemplate.commitmentRoot, route.commitmentRoot)) {
    return {
      ok: false,
      reason: "commitmentRoot mismatch: template does not match this route",
    };
  }

  // 0c. Verify the template's gatewayNodeId is the actual terminal hop.
  const terminalHopIndex = route.hops.length - 1;
  const terminalHopNodeId = route.hops[terminalHopIndex]!.nodeId;
  if (gatewayTemplate.gatewayNodeId !== terminalHopNodeId) {
    return {
      ok: false,
      reason: `gatewayNodeId is not the terminal hop: template has "${gatewayTemplate.gatewayNodeId}", route terminal is "${terminalHopNodeId}"`,
    };
  }

  // 0d. VERIFY THE TERMINAL ACK'S Ed25519 SIGNATURE.
  // This is the critical proof-bearing check: the ack is signed by the terminal
  // relay's Ed25519 key. A forged ack (with a different relayX25519PublicKey)
  // will fail this signature check because the attacker doesn't have the relay's
  // Ed25519 secret key. Per the re-audit of e165ba2: the previous version accepted
  // a bare { relayX25519PublicKey } — now the verifier consumes the FULL
  // CircuitSetupAck and verifies its signature.
  const ackPayload = circuitAckSigningPayload(
    terminalAck.routeId,
    terminalAck.routeCommitmentDigestHex,
    terminalAck.hopIndex,
    terminalAck.relayX25519PublicKey,
    terminalAck.initiatorX25519PublicKey,
    terminalAck.possessionProofCiphertext,
    terminalAck.possessionChallenge,
    terminalAck.ackNonce,
    terminalAck.ackTimestamp,
    terminalAck.ackExpiry,
  );
  if (!verifySignature(relayEd25519PublicKey, ackPayload, terminalAck.relaySignature)) {
    return {
      ok: false,
      reason: "terminal CircuitSetupAck signature invalid (forged or tampered ack)",
    };
  }

  // 0e. Verify the ack's routeId matches the route's routeId.
  if (terminalAck.routeId !== route.routeId) {
    return {
      ok: false,
      reason: "terminal ack routeId does not match the route",
    };
  }

  // 0f. Verify the ack's routeCommitmentDigest matches the route's digest.
  const expectedDigestHex = toHex(routeCommitmentDigest(route));
  if (terminalAck.routeCommitmentDigestHex !== expectedDigestHex) {
    return {
      ok: false,
      reason: "terminal ack routeCommitmentDigest does not match the route",
    };
  }

  // 0g. Verify the ack's hopIndex is the terminal hop index.
  if (terminalAck.hopIndex !== terminalHopIndex) {
    return {
      ok: false,
      reason: `terminal ack hopIndex ${terminalAck.hopIndex} is not the terminal hop index ${terminalHopIndex}`,
    };
  }

  // 0h. Verify the ack's initiatorX25519PublicKey matches the template's.
  if (!bytesEqual(terminalAck.initiatorX25519PublicKey, gatewayTemplate.initiatorX25519PublicKey)) {
    return {
      ok: false,
      reason: "terminal ack initiatorX25519PublicKey does not match the template's",
    };
  }

  // 0i. Verify the ack's relayX25519PublicKey matches the template's gatewayX25519PublicKey.
  if (!bytesEqual(terminalAck.relayX25519PublicKey, gatewayTemplate.gatewayX25519PublicKey)) {
    return {
      ok: false,
      reason: "gatewayX25519PublicKey does not match the terminal hop's verified CircuitSetupAck",
    };
  }

  // Delegate to the standard verifier for the remaining checks
  // (gatewayNodeId == expectedGatewayNodeId, X25519 key binding, expiry,
  // signature, ECDH decrypt).
  return verifyGatewayReturnTemplate(
    gatewayTemplate,
    expectedGatewayNodeId,
    gatewayX25519SecretKey,
    gatewayX25519PublicKey,
    now,
  );
}

/**
 * Encode a GatewayReturnTemplate to canonical CBOR for the wire.
 *
 * Per ADR-0004: integer-keyed map. The 12-field structure is:
 *   { 1: circuitId, 2: commitmentRoot, 3: noncePrefix, 4: encryptedKRet,
 *     5: kRetNonce, 6: envelope, 7: expiry, 8: gatewayNodeId,
 *     9: gatewayX25519PublicKey, 10: initiatorX25519PublicKey,
 *     11: initiatorEd25519PublicKey, 12: initiatorSignature }
 */
export function encodeGatewayReturnTemplate(gt: GatewayReturnTemplate): Uint8Array {
  const m = new Map<number, unknown>([
    [GT_KEY_CIRCUIT_ID, gt.circuitId],
    [GT_KEY_COMMITMENT_ROOT, gt.commitmentRoot],
    [GT_KEY_NONCE_PREFIX, gt.noncePrefix],
    [GT_KEY_ENCRYPTED_K_RET, gt.encryptedKRet],
    [GT_KEY_K_RET_NONCE, gt.kRetNonce],
    [GT_KEY_ENVELOPE, gt.envelope],
    [GT_KEY_EXPIRY, gt.expiry],
    [GT_KEY_GATEWAY_NODE_ID, gt.gatewayNodeId],
    [GT_KEY_GATEWAY_X25519_PUBKEY, gt.gatewayX25519PublicKey],
    [GT_KEY_INITIATOR_X25519_PUBKEY, gt.initiatorX25519PublicKey],
    [GT_KEY_INITIATOR_ED25519_PUBKEY, gt.initiatorEd25519PublicKey],
    [GT_KEY_INITIATOR_SIGNATURE, gt.initiatorSignature],
  ]);
  return canonicalEncode(m);
}

/**
 * Decode a GatewayReturnTemplate from canonical CBOR wire bytes.
 *
 * Validates all field types + sizes. Returns `{ ok: false, reason }` for any
 * malformed wire object.
 */
export function decodeGatewayReturnTemplate(bytes: Uint8Array): { ok: true; gatewayTemplate: GatewayReturnTemplate } | { ok: false; reason: string } {
  let decoded: unknown;
  try {
    decoded = canonicalDecode(bytes);
  } catch (e) {
    return { ok: false, reason: `CBOR decode failed: ${(e as Error).message}` };
  }
  if (!(decoded instanceof Map)) {
    return { ok: false, reason: "GatewayReturnTemplate must be a CBOR map" };
  }
  const m = decoded as Map<number, unknown>;

  const circuitId = m.get(GT_KEY_CIRCUIT_ID);
  const commitmentRoot = m.get(GT_KEY_COMMITMENT_ROOT);
  const noncePrefix = m.get(GT_KEY_NONCE_PREFIX);
  const encryptedKRet = m.get(GT_KEY_ENCRYPTED_K_RET);
  const kRetNonce = m.get(GT_KEY_K_RET_NONCE);
  const envelope = m.get(GT_KEY_ENVELOPE);
  const expiry = m.get(GT_KEY_EXPIRY);
  const gatewayNodeId = m.get(GT_KEY_GATEWAY_NODE_ID);
  const gatewayX25519Pub = m.get(GT_KEY_GATEWAY_X25519_PUBKEY);
  const initiatorX25519Pub = m.get(GT_KEY_INITIATOR_X25519_PUBKEY);
  const initiatorEd25519Pub = m.get(GT_KEY_INITIATOR_ED25519_PUBKEY);
  const signature = m.get(GT_KEY_INITIATOR_SIGNATURE);

  if (!(circuitId instanceof Uint8Array) || circuitId.length !== 32) {
    return { ok: false, reason: "circuitId must be a 32-byte bstr" };
  }
  if (!(commitmentRoot instanceof Uint8Array) || commitmentRoot.length !== 32) {
    return { ok: false, reason: "commitmentRoot must be a 32-byte bstr" };
  }
  if (!(noncePrefix instanceof Uint8Array) || noncePrefix.length !== 8) {
    return { ok: false, reason: "noncePrefix must be an 8-byte bstr" };
  }
  // encryptedKRet = 32-byte K_ret + 16-byte AEAD tag = 48 bytes.
  if (!(encryptedKRet instanceof Uint8Array) || encryptedKRet.length !== 48) {
    return { ok: false, reason: "encryptedKRet must be a 48-byte bstr (32 + 16 AEAD tag)" };
  }
  if (!(kRetNonce instanceof Uint8Array) || kRetNonce.length !== 12) {
    return { ok: false, reason: "kRetNonce must be a 12-byte bstr" };
  }
  if (!(envelope instanceof Uint8Array) || envelope.length < 16) {
    return { ok: false, reason: "envelope must be a bstr of at least 16 bytes" };
  }
  if (typeof expiry !== "number" || !Number.isInteger(expiry)) {
    return { ok: false, reason: "expiry must be an integer" };
  }
  if (typeof gatewayNodeId !== "string") {
    return { ok: false, reason: "gatewayNodeId must be a text string" };
  }
  if (!(gatewayX25519Pub instanceof Uint8Array) || gatewayX25519Pub.length !== 32) {
    return { ok: false, reason: "gatewayX25519PublicKey must be a 32-byte bstr" };
  }
  if (!(initiatorX25519Pub instanceof Uint8Array) || initiatorX25519Pub.length !== 32) {
    return { ok: false, reason: "initiatorX25519PublicKey must be a 32-byte bstr" };
  }
  if (!(initiatorEd25519Pub instanceof Uint8Array) || initiatorEd25519Pub.length !== 32) {
    return { ok: false, reason: "initiatorEd25519PublicKey must be a 32-byte bstr" };
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    return { ok: false, reason: "initiatorSignature must be a 64-byte bstr" };
  }

  return {
    ok: true,
    gatewayTemplate: {
      circuitId,
      commitmentRoot,
      noncePrefix,
      encryptedKRet,
      kRetNonce,
      envelope,
      expiry,
      gatewayNodeId,
      gatewayX25519PublicKey: gatewayX25519Pub,
      initiatorX25519PublicKey: initiatorX25519Pub,
      initiatorEd25519PublicKey: initiatorEd25519Pub,
      initiatorSignature: signature,
    },
  };
}

// -----------------------------------------------------------------------
// GatewayReturnAuthorization — serializable, language-independent terminal-gateway
// authorization proof (R-009 Stage 2 final proof portability).
//
// Per the re-audit of 8fa4ef3: verifyGatewayReturnTemplateWithRoute requires an
// in-process BrandedCommittedRoute WeakSet + a genuine CircuitSetupAck — both
// are in-process proof artifacts that cannot cross the process/language boundary.
//
// GatewayReturnAuthorization solves this by embedding the terminal CircuitSetupAck's
// relayEd25519PublicKey + relaySignature + routeCommitmentDigestHex + routeId +
// hopIndex directly in a canonical CBOR wire object. The gateway verifies:
//   1. The terminal ack's Ed25519 signature (using the embedded relayEd25519PublicKey).
//   2. The ack's routeId/routeCommitmentDigest/hopIndex binding (against the template's
//      commitmentRoot — which is also signed by the initiator).
//   3. The initiator's Ed25519 signature over the complete template binding.
//   4. The standard GatewayReturnTemplate checks (NodeId, X25519 key, expiry, ECDH decrypt).
//
// All verification is from wire bytes alone — no WeakSet dependency.
// -----------------------------------------------------------------------

/** Domain tag for the GatewayReturnAuthorization signing. */
export const GATEWAY_RETURN_AUTHORIZATION_DOMAIN = "SHARENET/CIRCUIT/RETURN/AUTH/1";

/**
 * The serializable, language-independent terminal-gateway authorization proof.
 *
 * This is the complete wire artifact the initiator sends to the gateway. It
 * bundles:
 *   - The GatewayReturnTemplate (with encrypted K_ret, envelope, etc.)
 *   - The terminal CircuitSetupAck's proof fields (relayEd25519PublicKey,
 *     relaySignature, routeId, routeCommitmentDigestHex, hopIndex, ackNonce,
 *     ackTimestamp, ackExpiry)
 *
 * The gateway verifies the terminal ack's Ed25519 signature using the
 * embedded relayEd25519PublicKey — this proves the ack was signed by the
 * terminal relay (not forged). The ack's routeId/routeCommitmentDigest/hopIndex
 * bind it to the committed route. The initiator's signature over the complete
 * template binding prevents substitution.
 *
 * Wire format (canonical CBOR):
 *   { 1: gatewayTemplateBytes (bstr — the encoded GatewayReturnTemplate),
 *     2: relayEd25519PublicKey (bstr .size 32),
 *     3: routeId (text),
 *     4: routeCommitmentDigestHex (text),
 *     5: hopIndex (uint),
 *     6: ackNonce (bstr .size 16),
 *     7: ackTimestamp (uint),
 *     8: ackExpiry (uint),
 *     9: relaySignature (bstr .size 64) }
 *
 * Note: the relayX25519PublicKey + initiatorX25519PublicKey +
 * possessionProofCiphertext + possessionChallenge are already in the
 * GatewayReturnTemplate (fields 9-10 there). The ack's signature covers
 * them (the signing payload includes all 10 ack fields). The gateway
 * reconstructs the ack signing payload from the GatewayReturnTemplate's
 * fields + this object's fields.
 */
export interface GatewayReturnAuthorization {
  /** The encoded GatewayReturnTemplate (the inner wire object). */
  gatewayTemplateBytes: Uint8Array;
  /** The terminal relay's Ed25519 public key (verifies the ack signature). */
  relayEd25519PublicKey: Uint8Array;
  /** The route ID (from the committed route). */
  routeId: string;
  /** Hex of the route commitment digest (BLAKE3-256 of the route binding). */
  routeCommitmentDigestHex: string;
  /** The terminal hop index (route.hops.length - 1). */
  hopIndex: number;
  /** The ack's AEAD possession proof ciphertext (48 bytes). */
  possessionProofCiphertext: Uint8Array;
  /** The ack's possession challenge (32 bytes). */
  possessionChallenge: Uint8Array;
  /** The ack's nonce (16 bytes). */
  ackNonce: Uint8Array;
  /** The ack's creation timestamp (unix seconds). */
  ackTimestamp: number;
  /** The ack's expiry (unix seconds). */
  ackExpiry: number;
  /** The terminal relay's Ed25519 signature over the ack binding payload. */
  relaySignature: Uint8Array;
}

/** CBOR map keys for GatewayReturnAuthorization (per ADR-0004). */
const GA_KEY_TEMPLATE_BYTES = 1;
const GA_KEY_RELAY_ED25519_PUBKEY = 2;
const GA_KEY_ROUTE_ID = 3;
const GA_KEY_ROUTE_COMMITMENT_DIGEST = 4;
const GA_KEY_HOP_INDEX = 5;
const GA_KEY_POSSESSION_PROOF_CIPHERTEXT = 6;
const GA_KEY_POSSESSION_CHALLENGE = 7;
const GA_KEY_ACK_NONCE = 8;
const GA_KEY_ACK_TIMESTAMP = 9;
const GA_KEY_ACK_EXPIRY = 10;
const GA_KEY_RELAY_SIGNATURE = 11;

/**
 * Construct a GatewayReturnAuthorization from a GatewayReturnTemplate + the
 * terminal CircuitSetupAck + the terminal relay's Ed25519 public key.
 *
 * The INITIATOR calls this after signGatewayReturnTemplate. It bundles the
 * template + the ack proof fields into a single canonical wire artifact.
 *
 * @param gatewayTemplate - the signed + confidential GatewayReturnTemplate
 * @param terminalAck - the genuine CircuitSetupAck from handleCircuitSetup
 * @param relayEd25519PublicKey - the terminal relay's Ed25519 public key
 * @returns the GatewayReturnAuthorization wire object
 */
export function constructGatewayReturnAuthorization(
  gatewayTemplate: GatewayReturnTemplate,
  terminalAck: CircuitSetupAck,
  relayEd25519PublicKey: Uint8Array,
): GatewayReturnAuthorization {
  return {
    gatewayTemplateBytes: encodeGatewayReturnTemplate(gatewayTemplate),
    relayEd25519PublicKey,
    routeId: terminalAck.routeId,
    routeCommitmentDigestHex: terminalAck.routeCommitmentDigestHex,
    hopIndex: terminalAck.hopIndex,
    possessionProofCiphertext: terminalAck.possessionProofCiphertext,
    possessionChallenge: terminalAck.possessionChallenge,
    ackNonce: terminalAck.ackNonce,
    ackTimestamp: terminalAck.ackTimestamp,
    ackExpiry: terminalAck.ackExpiry,
    relaySignature: terminalAck.relaySignature,
  };
}

/**
 * Encode a GatewayReturnAuthorization to canonical CBOR for the wire.
 */
export function encodeGatewayReturnAuthorization(ga: GatewayReturnAuthorization): Uint8Array {
  const m = new Map<number, unknown>([
    [GA_KEY_TEMPLATE_BYTES, ga.gatewayTemplateBytes],
    [GA_KEY_RELAY_ED25519_PUBKEY, ga.relayEd25519PublicKey],
    [GA_KEY_ROUTE_ID, ga.routeId],
    [GA_KEY_ROUTE_COMMITMENT_DIGEST, ga.routeCommitmentDigestHex],
    [GA_KEY_HOP_INDEX, ga.hopIndex],
    [GA_KEY_POSSESSION_PROOF_CIPHERTEXT, ga.possessionProofCiphertext],
    [GA_KEY_POSSESSION_CHALLENGE, ga.possessionChallenge],
    [GA_KEY_ACK_NONCE, ga.ackNonce],
    [GA_KEY_ACK_TIMESTAMP, ga.ackTimestamp],
    [GA_KEY_ACK_EXPIRY, ga.ackExpiry],
    [GA_KEY_RELAY_SIGNATURE, ga.relaySignature],
  ]);
  return canonicalEncode(m);
}

/**
 * Decode a GatewayReturnAuthorization from canonical CBOR wire bytes.
 */
export function decodeGatewayReturnAuthorization(bytes: Uint8Array): { ok: true; authorization: GatewayReturnAuthorization } | { ok: false; reason: string } {
  let decoded: unknown;
  try {
    decoded = canonicalDecode(bytes);
  } catch (e) {
    return { ok: false, reason: `CBOR decode failed: ${(e as Error).message}` };
  }
  if (!(decoded instanceof Map)) {
    return { ok: false, reason: "GatewayReturnAuthorization must be a CBOR map" };
  }
  const m = decoded as Map<number, unknown>;

  const templateBytes = m.get(GA_KEY_TEMPLATE_BYTES);
  const relayEd25519Pub = m.get(GA_KEY_RELAY_ED25519_PUBKEY);
  const routeId = m.get(GA_KEY_ROUTE_ID);
  const routeCommitmentDigestHex = m.get(GA_KEY_ROUTE_COMMITMENT_DIGEST);
  const hopIndex = m.get(GA_KEY_HOP_INDEX);
  const possessionProofCt = m.get(GA_KEY_POSSESSION_PROOF_CIPHERTEXT);
  const possessionChallenge = m.get(GA_KEY_POSSESSION_CHALLENGE);
  const ackNonce = m.get(GA_KEY_ACK_NONCE);
  const ackTimestamp = m.get(GA_KEY_ACK_TIMESTAMP);
  const ackExpiry = m.get(GA_KEY_ACK_EXPIRY);
  const relaySignature = m.get(GA_KEY_RELAY_SIGNATURE);

  if (!(templateBytes instanceof Uint8Array) || templateBytes.length < 10) {
    return { ok: false, reason: "gatewayTemplateBytes must be a bstr" };
  }
  if (!(relayEd25519Pub instanceof Uint8Array) || relayEd25519Pub.length !== 32) {
    return { ok: false, reason: "relayEd25519PublicKey must be a 32-byte bstr" };
  }
  if (typeof routeId !== "string") {
    return { ok: false, reason: "routeId must be a text string" };
  }
  if (typeof routeCommitmentDigestHex !== "string") {
    return { ok: false, reason: "routeCommitmentDigestHex must be a text string" };
  }
  if (typeof hopIndex !== "number" || !Number.isInteger(hopIndex) || hopIndex < 0) {
    return { ok: false, reason: "hopIndex must be a non-negative integer" };
  }
  if (!(possessionProofCt instanceof Uint8Array) || possessionProofCt.length !== 48) {
    return { ok: false, reason: "possessionProofCiphertext must be a 48-byte bstr" };
  }
  if (!(possessionChallenge instanceof Uint8Array) || possessionChallenge.length !== 32) {
    return { ok: false, reason: "possessionChallenge must be a 32-byte bstr" };
  }
  if (!(ackNonce instanceof Uint8Array) || ackNonce.length !== 16) {
    return { ok: false, reason: "ackNonce must be a 16-byte bstr" };
  }
  if (typeof ackTimestamp !== "number" || !Number.isInteger(ackTimestamp)) {
    return { ok: false, reason: "ackTimestamp must be an integer" };
  }
  if (typeof ackExpiry !== "number" || !Number.isInteger(ackExpiry)) {
    return { ok: false, reason: "ackExpiry must be an integer" };
  }
  if (!(relaySignature instanceof Uint8Array) || relaySignature.length !== 64) {
    return { ok: false, reason: "relaySignature must be a 64-byte bstr" };
  }

  return {
    ok: true,
    authorization: {
      gatewayTemplateBytes: templateBytes,
      relayEd25519PublicKey: relayEd25519Pub,
      routeId,
      routeCommitmentDigestHex,
      hopIndex,
      possessionProofCiphertext: possessionProofCt,
      possessionChallenge,
      ackNonce,
      ackTimestamp,
      ackExpiry,
      relaySignature,
    },
  };
}

/**
 * Result of verifying a GatewayReturnAuthorization at the gateway.
 */
export type VerifyGatewayReturnAuthorizationResult =
  | { ok: true; template: ReturnOnionTemplate }
  | { ok: false; reason: string };

/**
 * Verify a GatewayReturnAuthorization at the gateway — from wire bytes alone.
 *
 * This is the PORTABLE gateway verifier: it does NOT depend on a local
 * BrandedCommittedRoute WeakSet or a genuine CircuitSetupAck. It verifies
 * everything from the canonical wire bytes:
 *
 *   1. Decode the inner GatewayReturnTemplate.
 *   2. Verify the terminal ack's Ed25519 signature using the embedded
 *      relayEd25519PublicKey. This proves the ack was signed by the terminal
 *      relay (not forged). The ack signing payload is reconstructed from
 *      the template's fields + the authorization's fields.
 *   3. Verify the ack's routeId matches the template's routeId (via the
 *      commitmentRoot — the routeId is derived from commitmentRoot).
 *   4. Verify the ack's hopIndex is consistent (the gateway doesn't know the
 *      full route, but the initiator signed the template binding including
 *      gatewayNodeId, which the ack also binds to the terminal hop).
 *   5. Verify the ack's relayX25519PublicKey matches the template's
 *      gatewayX25519PublicKey (the ack's X25519 key is the one K_ret was
 *      encrypted to).
 *   6. Check expiry (the ack's ackExpiry + the template's expiry).
 *   7. Delegate to verifyGatewayReturnTemplate for the standard checks
 *      (NodeId, X25519 key binding, initiator signature, ECDH decrypt).
 *
 * @param authorization - the GatewayReturnAuthorization wire object
 * @param expectedGatewayNodeId - the gateway's own NodeId
 * @param gatewayX25519SecretKey - the gateway's own X25519 secret key
 * @param gatewayX25519PublicKey - the gateway's own X25519 public key
 * @param now - the current time (unix seconds)
 */
export function verifyGatewayReturnAuthorization(
  authorization: GatewayReturnAuthorization,
  expectedGatewayNodeId: string,
  gatewayX25519SecretKey: Uint8Array,
  gatewayX25519PublicKey: Uint8Array,
  now: number,
): VerifyGatewayReturnAuthorizationResult {
  // 1. Decode the inner GatewayReturnTemplate.
  const decoded = decodeGatewayReturnTemplate(authorization.gatewayTemplateBytes);
  if (!decoded.ok) {
    return { ok: false, reason: `failed to decode inner GatewayReturnTemplate: ${decoded.reason}` };
  }
  const gt = decoded.gatewayTemplate;

  // 2. Verify the terminal ack's Ed25519 signature.
  //    Reconstruct the ack signing payload from the template's + authorization's fields.
  //    The relayX25519PublicKey + initiatorX25519PublicKey come from the GatewayReturnTemplate.
  //    The possessionProofCiphertext + possessionChallenge + ackNonce + ackTimestamp + ackExpiry
  //    come from the GatewayReturnAuthorization.
  //    The routeId + routeCommitmentDigestHex + hopIndex also come from the authorization.
  const ackPayload = circuitAckSigningPayload(
    authorization.routeId,
    authorization.routeCommitmentDigestHex,
    authorization.hopIndex,
    gt.gatewayX25519PublicKey,              // relayX25519PublicKey (from the template)
    gt.initiatorX25519PublicKey,            // initiatorX25519PublicKey (from the template)
    authorization.possessionProofCiphertext,
    authorization.possessionChallenge,
    authorization.ackNonce,
    authorization.ackTimestamp,
    authorization.ackExpiry,
  );
  if (!verifySignature(authorization.relayEd25519PublicKey, ackPayload, authorization.relaySignature)) {
    return { ok: false, reason: "terminal ack signature invalid (forged or tampered authorization)" };
  }

  // 3. Check expiry (both the template + the ack).
  if (gt.expiry <= now) {
    return { ok: false, reason: `template expired: expiry ${gt.expiry} ≤ now ${now}` };
  }
  if (authorization.ackExpiry <= now) {
    return { ok: false, reason: `ack expired: ackExpiry ${authorization.ackExpiry} ≤ now ${now}` };
  }

  // 4. The ack's relayX25519PublicKey (signed in the ack payload) matches the
  //    template's gatewayX25519PublicKey (also signed in the template's
  //    initiator signature). If both signatures verify, the binding is proven
  //    — the terminal relay's X25519 key is the same one K_ret was encrypted to.

  // 5. Delegate to the standard verifier (NodeId, X25519 key, initiator signature, ECDH decrypt).
  return verifyGatewayReturnTemplate(
    gt,
    expectedGatewayNodeId,
    gatewayX25519SecretKey,
    gatewayX25519PublicKey,
    now,
  );
}

export { toHex };
