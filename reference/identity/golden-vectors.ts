/**
 * ShareNet 2.0 — Canonical NodeId Golden Vectors (BLAKE3 + base32).
 *
 * Per spec/02-identity.md §2.1 (APPROVED canonical scheme, ADR-0015 RESOLVED):
 *
 *   NodeIdBytes = BLAKE3-256( utf8("SHARENET/NODEID/1") || Ed25519PublicKey )
 *   NodeIdText  = lowercase unpadded RFC 4648 base32 of NodeIdBytes
 *
 * These vectors are FROZEN. Any conformant implementation MUST produce
 * these exact bytes for these exact inputs. The interim BLAKE2b-256 +
 * "node:"-hex vectors are RETIRED (see ADR-0015 resolution).
 *
 * The TEST_SEED below is a fixed, published test vector. It MUST NOT be
 * used in production. It exists so that conformance test runners can
 * verify the derivation is byte-stable.
 *
 * These vectors are language-neutral: the same Ed25519 public key +
 * BLAKE3-256 + RFC 4648 base32 in any conformant implementation (Rust,
 * Go, C, Python) MUST produce the identical NodeIdText.
 */

import {
  keypairFromSecretKey,
  deriveNodeId,
  verifyNodeIdBinding,
  isValidNodeIdFormat,
  generateNodeKeypair,
  hexToBytes,
  bytesToHex,
  type NodeKeypair,
} from "./keys";

/**
 * TEST SEED — fixed published vector. Do NOT use in production.
 * Hex: 0000000000000000000000000000000000000000000000000000000000000001
 *
 * Using all-zeros-except-last-byte-1 to make the vector visually obvious
 * in test failures. Conformance test vectors should never use a key that
 * could be confused with a real key.
 */
export const TEST_SEED_HEX =
  "0000000000000000000000000000000000000000000000000000000000000001";

export const TEST_SEED = hexToBytes(TEST_SEED_HEX);

/**
 * Expected Ed25519 public key for the test seed (32 bytes).
 *
 * Computed via @noble/curves v2.3.0 ed25519.getPublicKey(TEST_SEED).
 * FROZEN: any change to this value indicates either a regression in
 * @noble/curves (which would be a security event requiring audit) or a
 * change to the test seed. Both MUST be reviewed.
 */
export const TEST_PUBLIC_KEY_HEX =
  "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";

/**
 * Expected NodeIdBytes (BLAKE3-256 output, 32 bytes) for the test seed.
 *
 * FROZEN: BLAKE3-256("SHARENET/NODEID/1" || TEST_PUBLIC_KEY).
 * Any change indicates a regression in the derivation domain tag
 * (ADR-0015) or the underlying hash library.
 */
export const EXPECTED_NODE_ID_BYTES_HEX =
  "c577f2e11e5b21067ccadc94619259169a61a4fa8d08d628add0c5a5666051d0";

/**
 * Expected NodeIdText (canonical NodeId) for the test seed.
 *
 * FROZEN: lowercase unpadded RFC 4648 base32 of EXPECTED_NODE_ID_BYTES.
 * Exactly 52 characters [a-z2-7]. No "node:" prefix. No hex. No padding.
 *
 * Any change indicates a regression in either the BLAKE3 derivation, the
 * domain tag, or the base32 encoder. This is the single most important
 * stability guarantee in the protocol.
 */
export const EXPECTED_NODE_ID =
  "yv37fyi6lmqqm7gk3skgdeszc2ngdjh2ruenmkfn2dc2kztakhia";

/**
 * Computed-at-load golden keypair. We compute it at module load so that
 * any breaking change in @noble/curves (which would be a security event)
 * surfaces immediately as a failing vector rather than silently.
 */
export const GOLDEN_KEYPAIR: NodeKeypair = keypairFromSecretKey(TEST_SEED);

/**
 * Golden NodeId vector — recomputed at module load from TEST_SEED.
 *
 * MUST equal EXPECTED_NODE_ID. The architecture regression test asserts
 * this at module load and on every test run.
 */
export const GOLDEN_NODE_ID = GOLDEN_KEYPAIR.nodeId;

export interface IdentityVectorResult {
  name: string;
  passed: boolean;
  actual: string;
  expected?: string;
  description: string;
}

/**
 * Run all identity golden vectors. Returns a list of pass/fail results.
 *
 * Vectors checked:
 *   1. TEST_SEED produces a stable public key (recorded in TEST_PUBLIC_KEY_HEX).
 *   2. NodeIdBytes = BLAKE3-256(tag || publicKey) matches EXPECTED_NODE_ID_BYTES_HEX.
 *   3. NodeIdText matches EXPECTED_NODE_ID (the FROZEN base32 vector).
 *   4. NodeId derivation is deterministic (re-deriving yields the same NodeId).
 *   5. NodeId binding verification accepts the correct binding.
 *   6. NodeId binding verification REJECTS an incorrect binding (different key).
 *   7. NodeId format validation accepts canonical NodeIds.
 *   8. NodeId format validation rejects malformed strings (wrong length, wrong
 *      alphabet, non-canonical trailing bits, "node:" prefix, hex).
 */
export function runIdentityGoldenVectors(): IdentityVectorResult[] {
  const results: IdentityVectorResult[] = [];

  // Vector 1: stable public key from seed — MUST match the FROZEN value above.
  const pubHex = bytesToHex(GOLDEN_KEYPAIR.publicKey);
  results.push({
    name: "stable-public-key-from-seed",
    passed: pubHex === TEST_PUBLIC_KEY_HEX,
    actual: pubHex,
    expected: TEST_PUBLIC_KEY_HEX,
    description:
      "Deriving an Ed25519 public key from the fixed test seed MUST produce exactly the " +
      "FROZEN public key hex recorded above. A change indicates a @noble/curves regression " +
      "or a test-seed modification — both require audit.",
  });

  // Vector 1b: NodeIdBytes matches the FROZEN hex.
  // We re-derive the bytes by decoding the NodeIdText (base32 → bytes).
  const nodeIdBytesHex = bytesToHex(decodeBase32(GOLDEN_NODE_ID));
  results.push({
    name: "node-id-bytes-match-frozen",
    passed: nodeIdBytesHex === EXPECTED_NODE_ID_BYTES_HEX,
    actual: nodeIdBytesHex,
    expected: EXPECTED_NODE_ID_BYTES_HEX,
    description:
      "BLAKE3-256(\"SHARENET/NODEID/1\" || TEST_PUBLIC_KEY) MUST equal the FROZEN " +
      "NodeIdBytes hex. A change indicates a derivation regression (ADR-0015).",
  });

  // Vector 2: NodeIdText matches the FROZEN value.
  results.push({
    name: "node-id-text-matches-frozen-vector",
    passed: GOLDEN_NODE_ID === EXPECTED_NODE_ID,
    actual: GOLDEN_NODE_ID,
    expected: EXPECTED_NODE_ID,
    description:
      "The canonical NodeIdText (52 lowercase base32 chars) MUST equal the FROZEN vector. " +
      "A change indicates a regression in BLAKE3, the domain tag, or the base32 encoder.",
  });

  // Vector 3: NodeId derivation is deterministic.
  const derivedAgain = deriveNodeId(GOLDEN_KEYPAIR.publicKey);
  results.push({
    name: "node-id-deterministic",
    passed: derivedAgain === GOLDEN_NODE_ID,
    actual: derivedAgain,
    expected: GOLDEN_NODE_ID,
    description:
      "Calling deriveNodeId twice on the same public key MUST yield the same NodeId.",
  });

  // Vector 4: NodeId binding verification accepts correct binding.
  const bindingOk = verifyNodeIdBinding(GOLDEN_NODE_ID, GOLDEN_KEYPAIR.publicKey);
  results.push({
    name: "node-id-binding-accepts-correct",
    passed: bindingOk === true,
    actual: String(bindingOk),
    expected: "true",
    description:
      "verifyNodeIdBinding must return true when the claimed NodeId is the canonical " +
      "derivation of the given public key.",
  });

  // Vector 5: NodeId binding verification rejects an incorrect binding.
  const otherKeypair = generateNodeKeypair();
  const bindingReject = verifyNodeIdBinding(GOLDEN_NODE_ID, otherKeypair.publicKey);
  results.push({
    name: "node-id-binding-rejects-incorrect",
    passed: bindingReject === false,
    actual: String(bindingReject),
    expected: "false",
    description:
      "verifyNodeIdBinding MUST return false when the claimed NodeId does not match " +
      "the canonical derivation of the (different) public key. This is the core " +
      "spec/02 §3 enforcement: a node cannot claim an arbitrary NodeId.",
  });

  // Vector 6: NodeId format validation accepts canonical NodeIds.
  const formatOk = isValidNodeIdFormat(GOLDEN_NODE_ID);
  results.push({
    name: "node-id-format-accepts-canonical",
    passed: formatOk === true,
    actual: String(formatOk),
    expected: "true",
    description:
      "isValidNodeIdFormat accepts strings of exactly 52 lowercase base32 chars [a-z2-7] " +
      "with canonical (zero) trailing bits.",
  });

  // Vector 7: NodeId format validation rejects malformed strings.
  const malformedExamples = [
    "", // empty
    "a".repeat(51), // too short
    "a".repeat(53), // too long
    "A".repeat(52), // uppercase (not lowercase)
    "1".repeat(52), // '1' is not in base32 alphabet [a-z2-7]
    "0".repeat(52), // '0' is not in base32 alphabet
    "8".repeat(52), // '8' is not in base32 alphabet
    "node:" + "a".repeat(52), // old prefix scheme — MUST be rejected
    "node:" + "0".repeat(64), // old hex scheme — MUST be rejected
  ];
  // A truly non-canonical NodeId: same as GOLDEN but with the last char
  // replaced by one whose low 4 bits are non-zero. 'b' = 1, so 1 & 0x0f = 1 ≠ 0.
  const nonCanonical = GOLDEN_NODE_ID.slice(0, 51) + "b";
  const allMalformedRejected =
    malformedExamples.every((s) => !isValidNodeIdFormat(s)) &&
    !isValidNodeIdFormat(nonCanonical);
  results.push({
    name: "node-id-format-rejects-malformed",
    passed: allMalformedRejected,
    actual: `rejected ${malformedExamples.filter((s) => !isValidNodeIdFormat(s)).length}/${malformedExamples.length} + non-canonical=${!isValidNodeIdFormat(nonCanonical)}`,
    expected: `rejected ${malformedExamples.length}/${malformedExamples.length} + non-canonical=true`,
    description:
      "isValidNodeIdFormat MUST reject: empty, wrong length, uppercase, non-base32 chars, " +
      "old 'node:' prefix scheme, old hex scheme, and non-canonical trailing bits " +
      "(last char low 4 bits non-zero).",
  });

  return results;
}

// Local import to avoid circular dependency at module load.
import { base32ToBytes as decodeBase32 } from "./keys";

/** Re-export keypair for direct use by tests/debugging. */
export { GOLDEN_KEYPAIR as GOLDEN_IDENTITY };
