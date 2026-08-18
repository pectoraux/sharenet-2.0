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
import type { CircuitSequenceFloorStore } from "./replay-stores";
import { InMemoryCircuitSequenceFloorStore } from "./replay-stores";

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
 * Derive the 64-bit circuit nonce prefix.
 *
 * Per spec/08 §4.3 (FROZEN — R-009 Stage 1 final protocol reconciliation, ADR-0020):
 *
 *   prefix = first 8 bytes of HKDF-SHA256(
 *     salt = commitment_root,
 *     ikm  = initiator_x25519_pub,   ; 32 bytes — binds nonce space to the circuit instance
 *     info = "SHARENET/CIRCUIT/NONCE/1"
 *   )
 *
 * The nonce prefix is bound to the CIRCUIT INSTANCE (commitment_root +
 * initiator ephemeral X25519 public key), not just the route. This is
 * critical for re-key safety:
 *
 *   Per spec/08 §4.7: "a new circuit MUST start from a fresh (eph_priv,
 *   eph_pub) and a new circuit_nonce_prefix."
 *
 * Under the OLD derivation (pre-980ced6), the nonce prefix was bound only
 * to `commitment_root`. A re-key on the same route produced the SAME nonce
 * prefix — contradicting §4.7. Nonce uniqueness across re-key relied solely
 * on the persistent sequence floor.
 *
 * Under this (corrected) derivation, the nonce prefix is bound to the
 * initiator's ephemeral public key, so:
 *
 *   new eph keypair → new CircuitId → new nonce prefix
 *
 * Two circuits on the same route with different ephemeral keys get DIFFERENT
 * nonce prefixes. The persistent receiver-local sequence floor
 * (commitmentRoot, hopIndex, direction) still provides cross-re-key replay
 * protection, but nonce uniqueness is now also guaranteed by construction
 * — matching the normative text.
 *
 * NOTE: the ikm is the raw 32-byte initiator X25519 public key (the same
 * key used in CircuitId derivation), NOT the string "nonce-prefix".
 */
export function deriveNoncePrefix(
  commitmentRoot: Uint8Array,
  initiatorX25519PublicKey: Uint8Array,
): Uint8Array {
  const prk = hkdfExtract(sha256, initiatorX25519PublicKey, commitmentRoot);
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
  /**
   * The durable sequence-floor store backing this circuit's replay
   * protection (R-008 integration fix — final hardening).
   *
   * REQUIRED (non-optional): per the R-008 re-audit, production paths
   * MUST supply a durable store — the type system now enforces this.
   * Test paths supply `InMemoryCircuitSequenceFloorStore` explicitly.
   * There is no in-memory fallback in `processCircuitFrame`.
   *
   * The security boundary lives inside the protocol engine: persistence
   * is abstracted behind `CircuitSequenceFloorStore`. A protocol engineer
   * in Rust/Kotlin implements the same interface against any durable
   * substrate (LMDB, RocksDB, SQLite) and the protocol path uses it.
   */
  floorStore: CircuitSequenceFloorStore;
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
  /**
   * REQUIRED durable sequence-floor store (R-008 final hardening).
   *
   * Per the R-008 re-audit: production paths MUST supply a durable store
   * — the type system now enforces this (no optional, no default). Test
   * paths supply `InMemoryCircuitSequenceFloorStore` explicitly.
   *
   * The protocol core never imports Prisma; the durable SQLite
   * implementation lives in `src/lib/sharenet/` and implements
   * `CircuitSequenceFloorStore`.
   */
  floorStore: CircuitSequenceFloorStore,
  /**
   * Optional initial floor (for re-key continuation per spec/08 §4.5).
   * If `floorStore` is provided, the caller should load the prior floor
   * from the store (async) and pass it here so the in-memory guard cache
   * starts at the right value. If omitted, the guard starts at 0.
   */
  initialFloor?: bigint,
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

  // Derive the 64-bit nonce prefix — bound to the circuit INSTANCE
  // (commitment_root + initiator ephemeral public key) per spec/08 §4.3 +
  // ADR-0020 (R-009 Stage 1 final protocol reconciliation).
  const noncePrefix = deriveNoncePrefix(route.commitmentRoot, initiatorPublicKey);

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
    // Seed the in-memory guard cache from the prior floor (re-key continuation,
    // spec/08 §4.5). The durable store is the source of truth for cross-process
    // durability; this cache is the fast-path for in-process replay checks.
    replayGuard: new CircuitReplayGuard(initialFloor ?? 0n),
    noncePrefix,
    commitmentRoot: route.commitmentRoot,
    floorStore,
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
// Circuit frame processing — atomic check + persist via the floor store
// (R-008 integration fix)
// -----------------------------------------------------------------------

/**
 * Result of processing an inbound circuit frame.
 *
 * - `{ ok: true, decrypted }`: the frame's sequence was accepted (strictly
 *   higher than the floor) AND durably persisted; the payload was decrypted.
 * - `{ ok: false, reason }`: the frame was rejected — replay/stale sequence,
 *   persistence failure (fail-closed), or decryption failure (tampered).
 */
export type ProcessCircuitFrameResult =
  | { ok: true; decrypted: Uint8Array }
  | { ok: false; reason: string };

/**
 * Process an inbound circuit frame with atomic, durable replay protection.
 *
 * This is the protocol-path integration point required by the R-008 audit:
 *
 *   "CircuitReplayGuard must load its floor through the store and persist
 *    every accepted sequence before treating it as accepted. Persistence
 *    failure must fail closed."
 *
 * R-009 Stage 1 final replay-model correction: the durable floor is keyed by
 * (commitmentRoot, hopIndex, direction) — the RECEIVING SECURITY CONTEXT.
 * Every receiver on the circuit commits its own floor. This is critical under
 * ShareNet's threat model (malicious relays): a malicious upstream relay
 * replaying an already-valid inner ciphertext toward a downstream hop is
 * caught by the downstream hop's own floor.
 *
 * The operation is:
 *   1. AEAD authenticate + decrypt (reject if tag fails — floor UNCHANGED).
 *   2. atomically check-and-advance the floor through the store, keyed by
 *      (commitmentRoot, hopIndex, direction). Fail-closed.
 *   3. frame accepted.
 *
 * @param circuit - the active circuit (MUST carry a `floorStore` — required field)
 * @param hopIndex - which relay hop is processing this frame
 * @param frameSequence - the frame's 32-bit sequence number
 * @param direction - 0x01 (forward) or 0x02 (backward) — the frame's direction
 * @param ciphertext - the encrypted frame payload
 */
export async function processCircuitFrame(
  circuit: ActiveCircuit,
  hopIndex: number,
  frameSequence: number,
  direction: number,
  ciphertext: Uint8Array,
): Promise<ProcessCircuitFrameResult> {
  // R-008 FINAL HARDENING — frozen protocol ordering:
  //
  //   1. AEAD authenticate + decrypt      (reject if tag fails — floor UNCHANGED)
  //   2. atomic durable sequence commit   (reject if replay/stale — fail-closed)
  //   3. frame accepted
  //
  // CRITICAL: the durable sequence floor is committed ONLY AFTER the AEAD
  // tag verifies. This prevents the DoS vector flagged in the R-008 re-audit:
  //
  //   "sequence floor can be burned before AEAD authentication"

  // 1. AEAD authenticate + decrypt. If the tag does not verify (tampered
  //    ciphertext, wrong key), reject IMMEDIATELY — the durable floor is
  //    not touched. No DoS vector.
  let decrypted: Uint8Array;
  try {
    const result = relayDecrypt(circuit, hopIndex, frameSequence, ciphertext);
    decrypted = result.decrypted;
  } catch (e) {
    return { ok: false, reason: `decryption failed: ${(e as Error).message}` };
  }

  // 2. AEAD succeeded — now atomically commit the sequence floor through
  //    the durable store, keyed by (commitmentRoot, hopIndex, direction).
  //    This is the R-009 Stage 1 receiver-local replay model: every hop
  //    has its own floor. Fail-closed.
  //
  //    `circuit.floorStore` is guaranteed set (ActiveCircuit.floorStore is
  //    non-optional — construction APIs require it).
  const seq = BigInt(frameSequence);
  const commitResult = await circuit.floorStore.checkAndAdvance(
    circuit.commitmentRoot, hopIndex, direction, seq,
  );
  if (!commitResult.ok) {
    return { ok: false, reason: commitResult.reason };
  }

  // Mirror the accepted floor into the in-memory guard cache so
  // getSequenceFloor() reflects reality for the caller.
  circuit.replayGuard.checkAndRecord(seq);

  return { ok: true, decrypted };
}

/**
 * Load the durable sequence floor for a receiving context and return it.
 *
 * Helper for circuit setup: the caller loads the prior floor (async) for a
 * specific (hop, direction) then passes it to `setupCircuit` as
 * `initialFloor` so the in-memory guard cache starts at the right value.
 * This is the re-key continuation path (spec/08 §4.5), per-receiver.
 *
 * @param floorStore - the durable floor store
 * @param commitmentRoot - the 32-byte route commitment root
 * @param hopIndex - which relay hop is the receiver (0-based)
 * @param direction - 0x01 (forward) or 0x02 (backward)
 */
export async function loadCircuitFloor(
  floorStore: CircuitSequenceFloorStore,
  commitmentRoot: Uint8Array,
  hopIndex: number,
  direction: number,
): Promise<bigint> {
  return floorStore.getFloor(commitmentRoot, hopIndex, direction);
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
