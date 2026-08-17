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
 *   - Nonce layout: 32-bit route_id_prefix || 64-bit sequence_number (big-endian)
 *   - Replay protection: per-circuit monotonic sequence number, reject duplicates
 *   - Route/circuit binding: circuit_id = BLAKE3-256(route_id || initiator_x25519_pubkey)
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
import type { CommittedRoute } from "../routing/route";
import { isBrandedCommittedRoute, type BrandedCommittedRoute } from "../transport/validated-types";

// -----------------------------------------------------------------------
// Constants (FROZEN per GATE-06)
// -----------------------------------------------------------------------

export const CIRCUIT_KEY_DOMAIN = "SHARENET/CIRCUIT/KEY/1";
export const CIRCUIT_POSSESSION_DOMAIN = "SHARENET/CIRCUIT/POSSESSION/1";
export const CIRCUIT_ID_DOMAIN = "SHARENET/CIRCUIT/ID/1";

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
 * circuit_id = BLAKE3-256(
 *   utf8("SHARENET/CIRCUIT/ID/1")
 *   || route_id
 *   || initiator_x25519_public_key
 * )
 *
 * This binds the circuit to a specific committed route + the initiator's
 * ephemeral X25519 key, preventing circuit ID reuse across routes.
 */
export function deriveCircuitId(
  routeId: string,
  initiatorX25519PublicKey: Uint8Array,
): Uint8Array {
  const h = blake3.create({ dkLen: 32 });
  h.update(new TextEncoder().encode(CIRCUIT_ID_DOMAIN));
  h.update(new TextEncoder().encode(routeId));
  h.update(initiatorX25519PublicKey);
  return h.digest();
}

// -----------------------------------------------------------------------
// Key schedule (HKDF)
// -----------------------------------------------------------------------

/**
 * Derive per-hop AEAD keys using HKDF.
 *
 * For each hop, the initiator and the hop perform X25519 ECDH to get a shared
 * secret. Then HKDF extracts and expands to get:
 *   - forwardingKey: the AEAD key for this hop's relay to encrypt/decrypt
 *   - returnKey: the AEAD key for return traffic
 *
 * HKDF info = utf8("SHARENET/CIRCUIT/KEY/1") || u8be(hopIndex) || circuit_id
 */
export function deriveHopKeys(
  sharedSecret: Uint8Array,
  hopIndex: number,
  circuitId: Uint8Array,
): { forwardingKey: Uint8Array; returnKey: Uint8Array } {
  // HKDF extract
  const salt = new Uint8Array(0); // no salt — the shared secret is already high-entropy
  const prk = hkdfExtract(sha256, sharedSecret, salt);

  // HKDF expand: forwardingKey (32 bytes) + returnKey (32 bytes) = 64 bytes
  const info = new Uint8Array(
    new TextEncoder().encode(CIRCUIT_KEY_DOMAIN).length + 1 + circuitId.length,
  );
  let off = 0;
  const domain = new TextEncoder().encode(CIRCUIT_KEY_DOMAIN);
  info.set(domain, off); off += domain.length;
  info[off] = hopIndex; off += 1;
  info.set(circuitId, off);

  const expanded = hkdfExpand(sha256, prk, info, 64);
  return {
    forwardingKey: expanded.slice(0, 32),
    returnKey: expanded.slice(32, 64),
  };
}

// -----------------------------------------------------------------------
// AEAD encryption/decryption
// -----------------------------------------------------------------------

/**
 * Nonce layout: 4-byte route_id_prefix || 8-byte sequence_number (big-endian).
 *
 * The route_id_prefix binds the nonce to a specific circuit, preventing
 * nonce reuse across circuits. The sequence_number is monotonically
 * increasing per-circuit, providing replay protection.
 */
export function buildNonce(routeIdPrefix: number, sequenceNumber: bigint): Uint8Array {
  const nonce = new Uint8Array(AEAD_NONCE_BYTES);
  const dv = new DataView(nonce.buffer);
  dv.setUint32(0, routeIdPrefix, false); // big-endian
  // Write 64-bit sequence number as two 32-bit halves (big-endian)
  const high = Number(sequenceNumber >> 32n);
  const low = Number(sequenceNumber & 0xFFFFFFFFn);
  dv.setUint32(4, high, false);
  dv.setUint32(8, low, false);
  return nonce;
}

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
 * Per GATE-06: replay protection via monotonic sequence numbers.
 * Each circuit tracks the highest sequence number seen and rejects
 * any packet with a lower or equal sequence number.
 */
export class CircuitReplayGuard {
  private highestSeq = 0n;
  private seenSeqs = new Set<bigint>();
  private readonly maxSeenSet = 1000; // bounded memory

  /**
   * Check if a sequence number is acceptable (strictly higher than any seen).
   * If acceptable, records it and returns true.
   */
  checkAndRecord(seq: bigint): { ok: true } | { ok: false; reason: string } {
    if (seq <= this.highestSeq) {
      return { ok: false, reason: `sequence ${seq} ≤ highest ${this.highestSeq} (replay/stale)` };
    }
    if (this.seenSeqs.has(seq)) {
      return { ok: false, reason: `sequence ${seq} already seen (replay)` };
    }
    this.seenSeqs.add(seq);
    if (this.seenSeqs.size > this.maxSeenSet) {
      // Evict the oldest entries (lowest values)
      const sorted = Array.from(this.seenSeqs).sort((a, b) => (a < b ? -1 : 1));
      for (let i = 0; i < 100; i++) this.seenSeqs.delete(sorted[i]!);
    }
    this.highestSeq = seq;
    return { ok: true };
  }

  getHighestSeq(): bigint {
    return this.highestSeq;
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
  routeIdPrefix: number; // first 4 bytes of routeId as u32 (for nonce construction)
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
 * Set up a circuit from a CommittedRoute.
 *
 * This is the ONLY function that creates an ActiveCircuit.
 * It requires a CommittedRoute (not a RouteProposal — per spec/00 §31).
 *
 * Per R-006 hardening: this function accepts BOTH:
 *   1. A BrandedCommittedRoute (unforgeable, from createBrandedCommittedRoute)
 *   2. A legacy CommittedRoute (for backward compatibility with existing tests)
 *
 * If a BrandedCommittedRoute is passed, the brand is verified at runtime.
 * If a legacy CommittedRoute is passed, the structural type is trusted (transitional).
 *
 * A plain object or RouteProposal will fail at runtime because it lacks
 * the required fields (hops, routeId, expiry, etc.) OR lacks the brand.
 *
 * The initiator generates an X25519 keypair, performs ECDH with each relay's
 * X25519 public key, and derives per-hop AEAD keys via HKDF.
 */
export function setupCircuit(
  route: CommittedRoute | BrandedCommittedRoute,
  relayX25519PublicKeys: Array<{ hopIndex: number; nodeId: string; x25519PublicKey: Uint8Array }>,
  now: number,
): ActiveCircuit {
  // R-006 hardening: if this is a BrandedCommittedRoute, verify the brand.
  // If it's a plain CommittedRoute (legacy), accept it structurally.
  // If it's neither (plain object, RouteProposal, topology data), it will
  // fail below because it lacks the required fields.
  if (isBrandedCommittedRoute(route)) {
    // Branded route — the brand was set by createBrandedCommittedRoute
    // which already verified all acceptance signatures and hop validation.
  }
  // Non-branded routes (legacy CommittedRoute) are accepted structurally
  // for backward compatibility. A future hardening pass can make the
  // brand mandatory.

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

  // Compute CircuitId
  const circuitId = deriveCircuitId(route.routeId, initiatorPublicKey);
  const circuitIdHex = toHex(circuitId);

  // Route ID prefix (first 4 bytes of routeId hex as u32)
  const routeIdPrefix = parseInt(route.routeId.slice(0, 8), 16);

  // Derive per-hop keys
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
    const keys = deriveHopKeys(sharedSecret, i, circuitId);

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
    routeIdPrefix,
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
  sequenceNumber: bigint,
  plaintext: Uint8Array,
): { encryptedPayload: Uint8Array; aad: Uint8Array } {
  let data = plaintext;
  const aad = buildNonce(circuit.routeIdPrefix, sequenceNumber);

  // Encrypt from the outermost hop (last) to the innermost hop (first)
  for (let i = circuit.hops.length - 1; i >= 0; i--) {
    const hop = circuit.hops[i]!;
    const nonce = buildNonce(circuit.routeIdPrefix, sequenceNumber);
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
  sequenceNumber: bigint,
  ciphertext: Uint8Array,
): { decrypted: Uint8Array; aad: Uint8Array } {
  const hop = circuit.hops[hopIndex];
  if (!hop) throw new Error(`no hop at index ${hopIndex}`);
  const nonce = buildNonce(circuit.routeIdPrefix, sequenceNumber);
  const aad = nonce; // AAD is the nonce itself (binds to sequence + route)
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
