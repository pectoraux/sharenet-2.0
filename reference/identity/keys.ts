/**
 * ShareNet 2.0 Identity — Ed25519 signing + canonical NodeId derivation.
 *
 * Per spec/02-identity.md §2.1 (canonical Phase 0 scheme, APPROVED by
 * Principal Architect 2026-08-16, ADR-0015 RESOLVED):
 *
 *   NodeIdBytes = BLAKE3-256( utf8("SHARENET/NODEID/1") || Ed25519PublicKey )
 *   NodeIdText  = lowercase, unpadded RFC 4648 base32 of NodeIdBytes
 *
 * Properties:
 *   - Ed25519PublicKey is exactly 32 raw bytes.
 *   - NodeIdBytes is exactly 32 bytes (BLAKE3-256 output).
 *   - NodeIdText is exactly 52 lowercase base32 characters [a-z2-7].
 *   - No "node:" prefix. No hex. No padding.
 *
 * Invariant: NodeIdText == CanonicalNodeId(Ed25519PublicKey).
 * A node MUST NOT be allowed to claim an arbitrary NodeId.
 *
 * This scheme RETIRES the interim BLAKE2b-256 + "node:"-hex derivation.
 * There is NO dual parsing, NO fallback derivation, NO silent migration.
 * The interim test/development NodeIds are retired (see
 * mini-services/node-link/data/README.md).
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/hashes/utils.js";

// Re-export randomBytes so callers can generate nonces / seeds without
// reaching directly into @noble/hashes.
export { randomBytes };

/**
 * Domain-separation tag for NodeId derivation. FROZEN per ADR-0015
 * (Principal-Architect-approved canonical scheme). The tag is the ASCII
 * bytes of "SHARENET/NODEID/1" — 16 bytes, no NUL terminator.
 *
 * Per spec/14-security.md §4, this tag is registered and MUST NOT be
 * reused for any other signature/KDF domain.
 */
export const NODE_ID_DOMAIN_TAG = "SHARENET/NODEID/1";

/** Length of a raw NodeId hash in bytes (BLAKE3-256 output). */
export const NODE_ID_BYTES = 32;

/**
 * Length of the canonical NodeId text form.
 *
 * 32 bytes = 256 bits. base32 encodes 5 bits per character.
 * ceil(256 / 5) = 52 characters. Unpadded (no '=' fill).
 *
 * Validation: 52 chars × 5 bits = 260 bits, so the last 4 bits of the
 * final char are unused and MUST be zero on encode (the base32 alphabet
 * is [a-z2-7]). On decode, those bits MUST be verified to be zero;
 * a non-zero value indicates a malformed or non-canonical NodeId.
 */
export const NODE_ID_TEXT_LENGTH = 52;

/** Length of an Ed25519 public key in bytes. */
export const ED25519_PUBLIC_KEY_BYTES = 32;

/** Length of an Ed25519 secret key in bytes (32-byte seed). */
export const ED25519_SECRET_KEY_BYTES = 32;

/** Length of an Ed25519 signature in bytes. */
export const ED25519_SIGNATURE_BYTES = 64;

/** RFC 4648 base32 alphabet, lowercase (no padding). */
const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

export interface NodeKeypair {
  /** 32-byte raw Ed25519 secret key (seed). NEVER leaves the node. */
  secretKey: Uint8Array;
  /** 32-byte raw Ed25519 public key. */
  publicKey: Uint8Array;
  /** Canonical NodeId text (52 lowercase base32 chars). */
  nodeId: string;
}

/**
 * Derive the canonical NodeId text from a raw Ed25519 public key.
 *
 *   NodeIdBytes = BLAKE3-256( utf8("SHARENET/NODEID/1") || publicKey )
 *   NodeIdText  = base32_lowercase_unpadded( NodeIdBytes )
 *
 * This is the single source of truth. Any code that needs a NodeId MUST
 * call this function. NEVER accept a NodeId as input without re-deriving.
 */
export function deriveNodeId(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(
      `invalid Ed25519 public key length: expected ${ED25519_PUBLIC_KEY_BYTES} bytes, got ${publicKey.length}`,
    );
  }
  const tagBytes = new TextEncoder().encode(NODE_ID_DOMAIN_TAG);
  const input = new Uint8Array(tagBytes.length + publicKey.length);
  input.set(tagBytes, 0);
  input.set(publicKey, tagBytes.length);
  const hash = blake3(input, { dkLen: NODE_ID_BYTES });
  return bytesToBase32(hash);
}

/**
 * Verify that a claimed NodeId matches the canonical derivation from a
 * public key. Per spec/02 §3, a node MUST NOT be allowed to claim an
 * arbitrary NodeId — this guard is the enforcement point.
 *
 * Re-derives and compares in constant time on the decoded bytes.
 */
export function verifyNodeIdBinding(claimedNodeId: string, publicKey: Uint8Array): boolean {
  if (!isValidNodeIdFormat(claimedNodeId)) return false;
  const claimedBytes = base32ToBytes(claimedNodeId);
  const canonicalBytes = blake3(
    concat(new TextEncoder().encode(NODE_ID_DOMAIN_TAG), publicKey),
    { dkLen: NODE_ID_BYTES },
  );
  return constantTimeEqualBytes(claimedBytes, canonicalBytes);
}

/**
 * Assert that a NodeId string is well-formed: exactly 52 lowercase base32
 * characters [a-z2-7], with the trailing 4 bits zero (canonical encoding).
 *
 * Does NOT verify it is bound to any particular key — that requires
 * `verifyNodeIdBinding`.
 *
 * Canonical trailing-bits rule: 32 bytes (256 bits) encoded into 52 base32
 * chars (260 bits) leaves 4 unused bits in the final char. These 4 bits are
 * the LOW 4 bits of the last char's 5-bit value; they MUST be zero. So the
 * last char's value MUST be 0 (`a`) or 16 (`q`) — the 1 meaningful bit
 * occupies the MSB position (bit 4).
 */
export function isValidNodeIdFormat(nodeId: string): boolean {
  if (typeof nodeId !== "string") return false;
  if (nodeId.length !== NODE_ID_TEXT_LENGTH) return false;
  if (!/^[a-z2-7]+$/.test(nodeId)) return false;
  // Verify the trailing 4 bits are zero (canonical encoding of 32 bytes
  // into 52 base32 chars leaves 4 unused bits in the last char).
  const lastChar = nodeId.charCodeAt(NODE_ID_TEXT_LENGTH - 1);
  const lastVal = BASE32_ALPHABET.indexOf(String.fromCharCode(lastChar));
  if (lastVal < 0) return false;
  // The last char encodes 5 bits: 1 meaningful bit (MSB, bit 4) + 4 zero
  // padding bits (bits 0-3). Valid values: 0 (a) or 16 (q).
  return (lastVal & 0x0f) === 0;
}

/** Generate a fresh Ed25519 keypair + derived NodeId. */
export function generateNodeKeypair(): NodeKeypair {
  const secretKey = randomBytes(ED25519_SECRET_KEY_BYTES);
  const publicKey = ed25519.getPublicKey(secretKey);
  const nodeId = deriveNodeId(publicKey);
  return { secretKey, publicKey, nodeId };
}

/** Construct a NodeKeypair from an existing 32-byte secret key (seed). */
export function keypairFromSecretKey(secretKey: Uint8Array): NodeKeypair {
  if (secretKey.length !== ED25519_SECRET_KEY_BYTES) {
    throw new Error(
      `invalid Ed25519 secret key length: expected ${ED25519_SECRET_KEY_BYTES} bytes, got ${secretKey.length}`,
    );
  }
  const publicKey = ed25519.getPublicKey(secretKey);
  const nodeId = deriveNodeId(publicKey);
  return { secretKey, publicKey, nodeId };
}

/**
 * Sign an arbitrary message with an Ed25519 secret key.
 *
 * NOTE: callers MUST apply their own domain-separation prefix to the message
 * before calling this. Signing raw messages without a domain prefix permits
 * cross-protocol signature reuse. See spec/14-security.md §4 for the
 * registered domain-separation strings.
 */
export function signMessage(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

/**
 * Verify an Ed25519 signature. Returns true if the signature is valid for
 * the message under the given public key. Constant-time per @noble/curves.
 */
export function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------
// Internal helpers (also exported for use by golden vectors / debugging)
// ---------------------------------------------------------------------

/** Lowercase hex encoding of a byte array. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

/** Parse a hex string to a byte array. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`invalid hex length: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) throw new Error(`invalid hex byte at offset ${i * 2}`);
    out[i] = b;
  }
  return out;
}

/**
 * Encode bytes as lowercase unpadded RFC 4648 base32.
 *
 * For a 32-byte input this produces exactly 52 characters. The trailing
 * 4 bits of the final 5-bit group are zero (canonical encoding).
 */
export function bytesToBase32(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) {
    buffer = (buffer << 8) | bytes[i]!;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(buffer >> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
  }
  return out;
}

/**
 * Decode a lowercase unpadded RFC 4648 base32 string to bytes.
 *
 * Throws on invalid characters or non-canonical trailing bits.
 * For a 52-char input this produces exactly 32 bytes.
 */
export function base32ToBytes(s: string): Uint8Array {
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    const val = BASE32_ALPHABET.indexOf(String.fromCharCode(ch));
    if (val < 0) throw new Error(`invalid base32 char at offset ${i}: '${s[i]}'`);
    buffer = (buffer << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  // Remaining bits MUST be zero (canonical encoding).
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
    throw new Error("non-canonical base32: trailing bits are non-zero");
  }
  return new Uint8Array(out);
}

/** Constant-time string equality. Length leaks, content does not. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** Constant-time byte equality. Length leaks, content does not. */
function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/** Concatenate two byte arrays. */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
