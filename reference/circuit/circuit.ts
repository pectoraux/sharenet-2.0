/**
 * ShareNet 2.0 — Circuits and Encrypted Forwarding (GATE-06).
 *
 * Per spec/08-circuits.md and spec/00 §24:
 *
 *   A circuit is created ONLY from a committed route.
 *   Pipeline: CommittedRoute → CircuitSetup → relay acknowledgements →
 *             cryptographic possession proofs → ActiveCircuit
 *
 *   Per spec/00 §31: RouteProposal → ActiveCircuit (without commitment) is FORBIDDEN.
 *
 * Cryptographic design (per GATE-06 requirements):
 *   - X25519 key agreement between initiator and each relay
 *   - HKDF domain-separated key schedule
 *   - AEAD: ChaCha20-Poly1305 (256-bit key, 96-bit nonce, 128-bit tag)
 *   - Nonce layout: 64-bit circuit_nonce_prefix || 32-bit frame_sequence (big-endian)
 *   - Replay protection: per-circuit monotonic frame sequence number, reject duplicates
 *   - Route/circuit binding: circuit_id = BLAKE3-256(commitment_root || initiator_x25519_pubkey)
 *   - Relays never receive application plaintext (onion-layered encryption)
 *
 * Domain tags (FROZEN per spec/14 §4):
 *   SHARENET/CIRCUIT/KEY/1          — HKDF info for key derivation
 *   SHARENET/CIRCUIT/POSSESSION/1   — relay possession proof during setup
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { hkdf as hkdfModule, extract as hkdfExtract, expand as hkdfExpand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { signMessage, verifySignature } from "../identity/keys";
import { canonicalEncode, toHex, fromHex } from "../encoding/cbor";
import { isBrandedCommittedRoute, type BrandedCommittedRoute } from "../transport/validated-types";

// -----------------------------------------------------------------------
// Constants (FROZEN per GATE-06)
// -----------------------------------------------------------------------

export const CIRCUIT_KEY_DOMAIN = "SHARENET/CIRCUIT/KEY/1";
export const CIRCUIT_POSSESSION_DOMAIN = "SHARENET/CIRCUIT/POSSESSION/1";
export const CIRCUIT_ID_DOMAIN = "SHARENET/CIRCUIT/ID/1";

/**
 * Circuit replay model — FROZEN before R-009.
 *
 * Per spec/08 §4.5 and the R-008 hardening: the circuit data-plane replay
 * model is **ORDERED_STREAM** semantics. This is a protocol freeze:
 * R-009 (circuit packet semantics) MUST build on this model and MUST NOT
 * silently switch to a sliding-window / out-of-order acceptance model
 * without an explicit spec amendment.
 *
 * ORDERED_STREAM means:
 *   - frame_sequence is strictly increasing per circuit (starts at 1)
 *   - a receiver rejects any frame whose sequence is <= the highest
 *     sequence already accepted on that circuit
 *   - there is no out-of-order acceptance window (gap tolerance is 0)
 *   - the sequence floor persists across re-key (spec/14 §3)
 *
 * This constant exists so conformance/architecture tests can assert the
 * frozen model rather than reverse-engineering it from the guard.
 */
export const CIRCUIT_REPLAY_MODEL = "ORDERED_STREAM" as const;

/** AEAD key size (256 bits / 32 bytes for ChaCha20-Poly1305). */
export const AEAD_KEY_BYTES = 32;

/** AEAD nonce size (96 bits / 12 bytes for ChaCha20-Poly1305). */
export const AEAD_NONCE_BYTES = 12;

/** AEAD tag size (128 bits / 16 bytes for ChaCha20-Poly1305). */
export const AEAD_TAG_BYTES = 16;

/** X25519 public key size. */
export const X25519_PUBLIC_KEY_BYTES = 32;

/** X25519 secret key size. */
export const X25519_SECRET_KEY_BYTES = 32;

/** Circuit expiration in seconds (1 hour). */
export const CIRCUIT_EXPIRY_SECONDS = 3600;

// -----------------------------------------------------------------------
// Circuit ID derivation
// -----------------------------------------------------------------------

/**
 * Compute the CircuitId from a route commitment.
 *
 * Per spec/08 §3 (FROZEN):
 * circuit_id = BLAKE3-256(
 *   utf8("SHARENET/CIRCUIT/ID/1")
 *   || commitment_root       ; 32 bytes — the raw Merkle root
 *   || initiator_x25519_pub  ; 32 bytes — the source's ephemeral key
 * )
 *
 * This binds the circuit to a specific committed route (via commitment_root)
 * + the initiator's ephemeral X25519 key, preventing circuit ID reuse.
 *
 * NOTE: The input is the raw 32-byte commitment_root, NOT the route_id
 * string (which is "route:" + hex(commitment_root)).
 */
export function deriveCircuitId(
  commitmentRoot: Uint8Array,
  initiatorX25519PublicKey: Uint8Array,
): Uint8Array {
  const h = blake3.create({ dkLen: 32 });
  h.update(new TextEncoder().encode(CIRCUIT_ID_DOMAIN));
  h.update(commitmentRoot);
  h.update(initiatorX25519PublicKey);
  return h.digest();
}

// -----------------------------------------------------------------------
// Key schedule (HKDF)
// -----------------------------------------------------------------------

/**
 * Derive per-hop AEAD keys using HKDF.
 *
 * Per spec/08 §4.1 (FROZEN):
 *   salt = commitment_root (32 bytes — binds keys to the specific route)
 *   ikm  = X25519 shared secret
 *   info = "SHARENET/CIRCUIT/KEY/1" || u8(hop_index)
 *
 * Output is 64 bytes, split into:
 *   - forwardingKey (bytes 0–31): AEAD key for forward traffic
 *   - returnKey (bytes 32–63): AEAD key for return traffic
 */
export function deriveHopKeys(
  sharedSecret: Uint8Array,
  hopIndex: number,
  commitmentRoot: Uint8Array,
): { forwardingKey: Uint8Array; returnKey: Uint8Array } {
  // HKDF extract with commitment_root as salt (per spec/08 §4.1)
  const prk = hkdfExtract(sha256, sharedSecret, commitmentRoot);

  // HKDF expand: forwardingKey (32 bytes) + returnKey (32 bytes) = 64 bytes
  const domain = new TextEncoder().encode(CIRCUIT_KEY_DOMAIN);
  const info = new Uint8Array(domain.length + 1);
  info.set(domain, 0);
  info[domain.length] = hopIndex;

  const expanded = hkdfExpand(sha256, prk, info, 64);
  return {
    forwardingKey: expanded.slice(0, 32),
    returnKey: expanded.slice(32, 64),
  };
}

/**
 * Derive the 64-bit circuit nonce prefix from the commitment root.
 *
 * Per spec/08 §4.3 (FROZEN):
 *   prefix = first 8 bytes of HKDF-SHA256(
 *     salt = commitment_root,
 *     ikm  = "nonce-prefix",
 *     info = "SHARENET/CIRCUIT/NONCE/1"
 *   )
 */
export function deriveNoncePrefix(commitmentRoot: Uint8Array): Uint8Array {
  const prk = hkdfExtract(sha256, new TextEncoder().encode("nonce-prefix"), commitmentRoot);
  const info = new TextEncoder().encode("SHARENET/CIRCUIT/NONCE/1");
  const expanded = hkdfExpand(sha256, prk, info, 8);
  return expanded.slice(0, 8);
}

/**
 * Build a 96-bit AEAD nonce from the circuit nonce prefix and frame sequence.
 *
 * Per spec/08 §4.3 (FROZEN):
 *   nonce = circuit_nonce_prefix (64 bits) || frame_sequence (32 bits, big-endian)
 */
export function buildNonce(noncePrefix: Uint8Array, frameSequence: number): Uint8Array {
  if (noncePrefix.length !== 8) throw new Error("nonce prefix must be 8 bytes");
  const nonce = new Uint8Array(AEAD_NONCE_BYTES);
  nonce.set(noncePrefix, 0);
  const dv = new DataView(nonce.buffer);
  dv.setUint32(8, frameSequence, false); // big-endian 32-bit
  return nonce;
}

/**
 * Build the AEAD associated data (AD) for a circuit frame.
 *
 * Per spec/08 §4.6 (FROZEN):
 *   AD = "SHARENET/CIRCUIT/FRAME/1" || commitment_root (32) || frame_sequence (4 BE) || direction (1)
 */
export function buildCircuitFrameAD(
  commitmentRoot: Uint8Array,
  frameSequence: number,
  direction: 0x01 | 0x02,
): Uint8Array {
  const domain = new TextEncoder().encode("SHARENET/CIRCUIT/FRAME/1");
  const ad = new Uint8Array(domain.length + 32 + 4 + 1);
  ad.set(domain, 0);
  ad.set(commitmentRoot, domain.length);
  const dv = new DataView(ad.buffer, domain.length + 32);
  dv.setUint32(0, frameSequence, false); // big-endian
  ad[domain.length + 32 + 4] = direction;
  return ad;
}

// -----------------------------------------------------------------------
// AEAD encryption/decryption
// -----------------------------------------------------------------------

/**
 * Encrypt a payload using ChaCha20-Poly1305 AEAD.
 *
 * Returns ciphertext || tag (ciphertext length + 16 bytes).
 */
export function encryptPayload(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const cipher = chacha20poly1305(key, nonce, aad);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt a payload using ChaCha20-Poly1305 AEAD.
 *
 * Returns the plaintext, or throws if the tag does not verify.
 */
export function decryptPayload(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const cipher = chacha20poly1305(key, nonce, aad);
  return cipher.decrypt(ciphertext);
}

// -----------------------------------------------------------------------
// Replay protection (per-circuit sequence number tracking)
// -----------------------------------------------------------------------

/**
 * Replay protection for a single circuit.
 *
 * Per GATE-06 and the R-008 hardening freeze: this guard implements the
 * **ORDERED_STREAM** replay model (see `CIRCUIT_REPLAY_MODEL`).
 *
 * Each circuit tracks the highest sequence number seen and rejects
 * any frame whose sequence is `<=` the highest accepted sequence.
 * There is no out-of-order/sliding-window acceptance: gap tolerance
 * is 0. This is the frozen data-plane replay contract that R-009
 * (circuit packet semantics) MUST build on.
 *
 * Per spec/08 §4.5: "Sequence floors persist across circuit re-key events."
 * The `initialFloor` parameter allows a new circuit to continue from the
 * prior floor, preventing replay of old frames after a re-key.
 */
export class CircuitReplayGuard {
  private highestSeq: bigint;

  /**
   * Create a replay guard. If `initialFloor` is provided, the guard starts
   * from that floor (e.g. the previous circuit's highest sequence), ensuring
   * that old frames cannot be replayed after a re-key.
   */
  constructor(initialFloor: bigint = 0n) {
    this.highestSeq = initialFloor;
  }

  /**
   * Check if a sequence number is acceptable (strictly higher than the floor).
   * If acceptable, records it and returns true.
   */
  checkAndRecord(seq: bigint): { ok: true } | { ok: false; reason: string } {
    if (seq <= this.highestSeq) {
      return { ok: false, reason: `sequence ${seq} ≤ floor ${this.highestSeq} (replay/stale)` };
    }
    this.highestSeq = seq;
    return { ok: true };
  }

  getHighestSeq(): bigint {
    return this.highestSeq;
  }

  /**
   * Get the current sequence floor for persistence across re-key.
   * The caller MUST store this and pass it to the next circuit's
   * CircuitReplayGuard constructor.
   */
  getSequenceFloor(): bigint {
    return this.highestSeq;
  }
}

/**
 * A persistent sequence-floor store that survives circuit re-key events.
 *
 * Per spec/08 §4.5: "Sequence floors persist across circuit re-key events;
 * a re-key MUST continue the counter from the prior floor."
 *
 * This store is keyed by commitment_root (the route identity), so a re-key
 * on the same route continues from the prior floor. A different route
 * gets a fresh floor (0).
 */
export class SequenceFloorStore {
  private floors = new Map<string, bigint>(); // commitmentRootHex → floor

  /**
   * Get the current sequence floor for a given commitment_root.
   * Returns 0n if no prior circuit has been established on this route.
   */
  getFloor(commitmentRoot: Uint8Array): bigint {
    const key = toHex(commitmentRoot);
    return this.floors.get(key) ?? 0n;
  }

  /**
   * Update the sequence floor for a given commitment_root.
   * Called when a circuit is torn down or re-keyed.
   */
  setFloor(commitmentRoot: Uint8Array, floor: bigint): void {
    const key = toHex(commitmentRoot);
    this.floors.set(key, floor);
  }

  /**
   * Create a CircuitReplayGuard initialized from the persisted floor.
   * This is the correct way to create a guard for a new circuit on an
   * existing route — it prevents old frames from being replayed.
   */
  createReplayGuard(commitmentRoot: Uint8Array): CircuitReplayGuard {
    return new CircuitReplayGuard(this.getFloor(commitmentRoot));
  }
}

// -----------------------------------------------------------------------
// Circuit types
// -----------------------------------------------------------------------

/**
 * Per-hop key material for a circuit.
 * Each hop has its own forwarding + return keys (derived from X25519 ECDH).
 */
export interface HopKeyMaterial {
  hopIndex: number;
  nodeId: string;
  forwardingKey: Uint8Array;
  returnKey: Uint8Array;
  /** The relay's X25519 public key (for the initiator's records). */
  relayX25519PublicKey: Uint8Array;
}

/**
 * An ActiveCircuit — created ONLY from a CommittedRoute.
 *
 * Per spec/00 §31: RouteProposal → ActiveCircuit (without commitment) is FORBIDDEN.
 * Per spec/08 §3: CircuitSetup → relay acknowledgements → possession proofs → ActiveCircuit.
 */
export interface ActiveCircuit {
  circuitId: Uint8Array;
  circuitIdHex: string;
  routeId: string;
  hops: HopKeyMaterial[];
  initiatorX25519PublicKey: Uint8Array;
  initiatorX25519SecretKey: Uint8Array;
  expiry: number;
  establishedAt: number;
  replayGuard: CircuitReplayGuard;
  /** 64-bit nonce prefix derived from commitment_root (per spec/08 §4.3) */
  noncePrefix: Uint8Array;
  /** The 32-byte commitment_root (for CircuitFrame AD construction per spec/08 §4.6) */
  commitmentRoot: Uint8Array;
}

// -----------------------------------------------------------------------
// Circuit setup (from CommittedRoute)
// -----------------------------------------------------------------------

/**
 * A relay's X25519 keypair for circuit setup.
 * Each relay generates an ephemeral X25519 keypair for this circuit.
 */
export interface RelayCircuitKeys {
  hopIndex: number;
  nodeId: string;
  x25519SecretKey: Uint8Array;
  x25519PublicKey: Uint8Array;
}

/**
 * Set up a circuit from a BrandedCommittedRoute.
 *
 * This is the ONLY function that creates an ActiveCircuit from the
 * single-process (non-distributed) path. It requires a genuine
 * `BrandedCommittedRoute` — the unforgeable proof artifact produced by
 * `createBrandedCommittedRoute`, which itself consumes a genuine
 * `RouteCommitment` from `createRouteCommitment`.
 *
 * Per R-008 hardening (closing the legacy bypass flagged in the
 * trust-boundary audit): the legacy `CommittedRoute` acceptance path is
 * **REMOVED**. Every circuit construction path now requires a genuine
 * branded route. There is no structural-trust fallback.
 *
 * The runtime WeakSet membership check (`isBrandedCommittedRoute`) is
 * the **first** operation. This guarantees:
 *   - a plain object matching the shape is REJECTED (not in the WeakSet)
 *   - a legacy `CommittedRoute` (from `createCommittedRoute`) is REJECTED
 *   - a `RouteProposal` is REJECTED
 *   - a property-copy of a genuine branded route is REJECTED
 *     (`{ ...branded }` is a new object, not in the WeakSet)
 *   - a deserialized branded route is REJECTED
 *
 * Only an object that transited `createBrandedCommittedRoute` is
 * accepted. The TypeScript signature `route: BrandedCommittedRoute` is
 * the compile-time boundary; the WeakSet check is the runtime boundary.
 *
 * The initiator generates an X25519 keypair, performs ECDH with each
 * relay's X25519 public key, and derives per-hop AEAD keys via HKDF.
 */
export function setupCircuit(
  route: BrandedCommittedRoute,
  relayX25519PublicKeys: Array<{ hopIndex: number; nodeId: string; x25519PublicKey: Uint8Array }>,
  now: number,
): ActiveCircuit {
  // R-008 hardening: runtime brand boundary — the FIRST check.
  // This is genuinely unforgeable (WeakSet tracks object identity, not
  // property values). There is no legacy bypass.
  if (!isBrandedCommittedRoute(route)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: setupCircuit rejected — route is not a genuine " +
        "BrandedCommittedRoute (WeakSet membership check failed). Per R-008 " +
        "hardening, every circuit construction path requires a genuine branded " +
        "route produced by createBrandedCommittedRoute (which consumes a genuine " +
        "RouteCommitment from createRouteCommitment). Legacy CommittedRoute, " +
        "RouteProposal, plain objects, property-copies, and deserialized routes " +
        "are all rejected. The legacy structural-trust path has been removed.",
    );
  }

  // Validate: the route must have hops
  if (route.hops.length === 0) {
    throw new Error("cannot setup circuit: route has no hops");
  }

  // Validate: every relayX25519PublicKey must match a hop
  if (relayX25519PublicKeys.length !== route.hops.length) {
    throw new Error(
      `cannot setup circuit: expected ${route.hops.length} relay X25519 keys, got ${relayX25519PublicKeys.length}`,
    );
  }

  // Initiator generates ephemeral X25519 keypair
  const initiatorSecretKey = randomBytes(X25519_SECRET_KEY_BYTES);
  const initiatorPublicKey = x25519.getPublicKey(initiatorSecretKey);

  // Compute CircuitId — uses commitment_root (raw 32 bytes), NOT routeId string
  const circuitId = deriveCircuitId(route.commitmentRoot, initiatorPublicKey);
  const circuitIdHex = toHex(circuitId);

  // Derive the 64-bit nonce prefix from commitment_root (per spec/08 §4.3)
  const noncePrefix = deriveNoncePrefix(route.commitmentRoot);

  // Derive per-hop keys — uses commitment_root as salt (per spec/08 §4.1)
  const hopKeys: HopKeyMaterial[] = [];
  for (let i = 0; i < route.hops.length; i++) {
    const hop = route.hops[i]!;
    const relayKeys = relayX25519PublicKeys[i]!;
    if (relayKeys.hopIndex !== i) {
      throw new Error(`relay key ${i} has wrong hopIndex ${relayKeys.hopIndex}`);
    }
    if (relayKeys.nodeId !== hop.nodeId) {
      throw new Error(`relay key ${i} nodeId ${relayKeys.nodeId} != hop ${hop.nodeId}`);
    }

    // ECDH: initiator's secret key × relay's public key
    const sharedSecret = x25519.getSharedSecret(initiatorSecretKey, relayKeys.x25519PublicKey);
    const keys = deriveHopKeys(sharedSecret, i, route.commitmentRoot);

    hopKeys.push({
      hopIndex: i,
      nodeId: hop.nodeId,
      forwardingKey: keys.forwardingKey,
      returnKey: keys.returnKey,
      relayX25519PublicKey: relayKeys.x25519PublicKey,
    });
  }

  return {
    circuitId,
    circuitIdHex,
    routeId: route.routeId,
    hops: hopKeys,
    initiatorX25519PublicKey: initiatorPublicKey,
    initiatorX25519SecretKey: initiatorSecretKey,
    expiry: route.expiry,
    establishedAt: now,
    replayGuard: new CircuitReplayGuard(),
    noncePrefix,
    commitmentRoot: route.commitmentRoot,
  };
}

// -----------------------------------------------------------------------
// Onion-layered encryption (relays never receive plaintext)
// -----------------------------------------------------------------------

/**
 * Encrypt a payload for multi-hop forwarding using onion encryption.
 *
 * The payload is encrypted layer by layer, starting from the OUTERMOST hop
 * (last relay) and ending with the INNERMOST hop (first relay). Each relay
 * decrypts one layer and forwards the inner ciphertext to the next hop.
 *
 * This ensures relays never receive application plaintext — they only see
 * the encrypted layer they're responsible for.
 */
export function onionEncrypt(
  circuit: ActiveCircuit,
  frameSequence: number,
  plaintext: Uint8Array,
): { encryptedPayload: Uint8Array; aad: Uint8Array } {
  let data = plaintext;
  // Per spec/08 §4.6: AD = "SHARENET/CIRCUIT/FRAME/1" || commitment_root || frame_sequence || direction
  const aad = buildCircuitFrameAD(circuit.commitmentRoot, frameSequence, 0x01);

  // Encrypt from the outermost hop (last) to the innermost hop (first)
  for (let i = circuit.hops.length - 1; i >= 0; i--) {
    const hop = circuit.hops[i]!;
    const nonce = buildNonce(circuit.noncePrefix, frameSequence);
    data = encryptPayload(hop.forwardingKey, nonce, data, aad);
  }

  return { encryptedPayload: data, aad };
}

/**
 * Decrypt one layer of onion encryption (what a relay does).
 *
 * The relay decrypts using its forwarding key, revealing the inner ciphertext
 * (which it forwards to the next hop) or the plaintext (if it's the last hop).
 */
export function relayDecrypt(
  circuit: ActiveCircuit,
  hopIndex: number,
  frameSequence: number,
  ciphertext: Uint8Array,
): { decrypted: Uint8Array; aad: Uint8Array } {
  const hop = circuit.hops[hopIndex];
  if (!hop) throw new Error(`no hop at index ${hopIndex}`);
  const nonce = buildNonce(circuit.noncePrefix, frameSequence);
  const aad = buildCircuitFrameAD(circuit.commitmentRoot, frameSequence, 0x01);
  const decrypted = decryptPayload(hop.forwardingKey, nonce, ciphertext, aad);
  return { decrypted, aad };
}

// -----------------------------------------------------------------------
// Architecture guards
// -----------------------------------------------------------------------

/**
 * Per spec/00 §31: RouteProposal → ActiveCircuit (without commitment) is FORBIDDEN.
 * This is already enforced by PROPOSAL_TO_CIRCUIT_FORBIDDEN in route.ts.
 * setupCircuit requires a CommittedRoute, not a RouteProposal.
 */

/**
 * Per spec/00 §31: uncommitted route → circuit is FORBIDDEN.
 * setupCircuit takes a CommittedRoute (which is only created from RouteCommitment).
 * This function exists as an explicit guard for the architecture test.
 */
export function UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN(route: unknown): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create a circuit from an uncommitted route. ` +
      `Per spec/00 §31 and spec/08 §3, a circuit can ONLY be created from a CommittedRoute ` +
      `(which requires all hops to have signed RouteAcceptance).`,
  );
}

// Re-export for convenience
export { randomBytes, toHex, fromHex };
