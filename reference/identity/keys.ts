/**
 * ShareNet 2.0 Identity — Ed25519 signing + NodeId derivation.
 *
 * Per spec/02-identity.md §2.1 and ADR-0003:
 *
 *   NodeId = "node:" + hex(BLAKE2b-256("sharenet-node-id-v1" || Ed25519PublicKey))
 *
 * where Ed25519PublicKey is the 32-byte raw public key. The domain-separation
 * string "sharenet-node-id-v1" is FROZEN FOREVER. Bumping it requires a new
 * NodeId namespace and a coordinated protocol migration.
 *
 * Invariant: NodeId == CanonicalNodeId(Ed25519PublicKey).
 * A node MUST NOT be allowed to claim an arbitrary NodeId.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { blake2b } from "@noble/hashes/blake2.js";
import { randomBytes } from "@noble/hashes/utils.js";

// Re-export randomBytes so callers can generate nonces / seeds without
// reaching directly into @noble/hashes.
export { randomBytes };

/** Domain-separation string for NodeId derivation. FROZEN per ADR-0003. */
export const NODE_ID_DOMAIN = "sharenet-node-id-v1";

/** NodeId string prefix. */
export const NODE_ID_PREFIX = "node:";

/** Length of a raw NodeId hash in bytes (BLAKE2b-256 output). */
export const NODE_ID_HASH_BYTES = 32;

/** Length of the hex-encoded NodeId hash (without the "node:" prefix). */
export const NODE_ID_HASH_HEX_LEN = NODE_ID_HASH_BYTES * 2;

/** Length of an Ed25519 public key in bytes. */
export const ED25519_PUBLIC_KEY_BYTES = 32;

/** Length of an Ed25519 secret key in bytes (32-byte seed expanded). */
export const ED25519_SECRET_KEY_BYTES = 32;

/** Length of an Ed25519 signature in bytes. */
export const ED25519_SIGNATURE_BYTES = 64;

export interface NodeKeypair {
  /** 32-byte raw Ed25519 secret key (seed). */
  secretKey: Uint8Array;
  /** 32-byte raw Ed25519 public key. */
  publicKey: Uint8Array;
  /** Canonical NodeId string derived from the public key. */
  nodeId: string;
}

/**
 * Derive the canonical NodeId from a raw Ed25519 public key.
 *
 *   NodeId = "node:" + hex(BLAKE2b-256("sharenet-node-id-v1" || publicKey))
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
  const domainBytes = new TextEncoder().encode(NODE_ID_DOMAIN);
  const input = new Uint8Array(domainBytes.length + publicKey.length);
  input.set(domainBytes, 0);
  input.set(publicKey, domainBytes.length);
  const hash = blake2b(input, { dkLen: NODE_ID_HASH_BYTES });
  return NODE_ID_PREFIX + bytesToHex(hash);
}

/**
 * Verify that a claimed NodeId matches the canonical derivation from a
 * public key. Per spec/02 §3, a node MUST NOT be allowed to claim an
 * arbitrary NodeId — this guard is the enforcement point.
 */
export function verifyNodeIdBinding(claimedNodeId: string, publicKey: Uint8Array): boolean {
  const canonical = deriveNodeId(publicKey);
  return constantTimeEqual(claimedNodeId, canonical);
}

/**
 * Assert that a NodeId string is well-formed (prefix + 64 hex chars).
 * Does NOT verify it is bound to any particular key — that requires
 * `verifyNodeIdBinding`.
 */
export function isValidNodeIdFormat(nodeId: string): boolean {
  if (!nodeId.startsWith(NODE_ID_PREFIX)) return false;
  const hexPart = nodeId.slice(NODE_ID_PREFIX.length);
  if (hexPart.length !== NODE_ID_HASH_HEX_LEN) return false;
  return /^[0-9a-f]+$/.test(hexPart);
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

/** Constant-time string equality. Length leaks, content does not. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
