/**
 * Golden vectors for identity: Ed25519 keypair + NodeId derivation.
 *
 * Per spec/17-conformance.md §2.2, these vectors MUST be reproducible across
 * every ShareNet implementation. The NodeId derivation (spec/02 §2.1, ADR-0003)
 * is FROZEN — any implementation that produces a different NodeId for the
 * same seed is non-conformant.
 *
 * The seed below is a fixed, published test vector. It MUST NOT be used in
 * production. It exists solely so that conformance test runners can verify
 * the derivation is byte-stable.
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
 * Expected NodeId for the test seed.
 *
 * FROZEN: computed once via BLAKE2b-256("sharenet-node-id-v1" || TEST_PUBLIC_KEY).
 * Any change indicates a regression in either the derivation domain string
 * (ADR-0003) or the underlying hash/curve libraries.
 */
export const EXPECTED_NODE_ID =
  "node:824d26d78fa3b39119eaedfa513d98b254d788f8b9c22f428c8a0895bbb5fd2d";

/**
 * Computed-at-load golden keypair. We compute it at module load so that
 * any breaking change in @noble/curves (which would be a security event)
 * surfaces immediately as a failing vector rather than silently.
 */
export const GOLDEN_KEYPAIR: NodeKeypair = keypairFromSecretKey(TEST_SEED);

/**
 * Golden NodeId vector — recomputed at module load from TEST_SEED.
 *
 * The expected hex below is frozen: it was computed once using
 * BLAKE2b-256("sharenet-node-id-v1" || publicKey(TEST_SEED)) and recorded.
 * Any change to this value indicates a derivation regression or a
 * crypto library upgrade that MUST be audited.
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
 *   2. NodeId derivation is deterministic: re-deriving from the same public key
 *      yields the same NodeId.
 *   3. NodeId binding verification accepts the correct binding.
 *   4. NodeId binding verification REJECTS an incorrect binding (different key).
 *   5. NodeId format validation accepts canonical NodeIds.
 *   6. NodeId format validation rejects malformed strings.
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

  // Vector 1b: NodeId derivation MUST match the FROZEN value above.
  results.push({
    name: "node-id-matches-frozen-vector",
    passed: GOLDEN_NODE_ID === EXPECTED_NODE_ID,
    actual: GOLDEN_NODE_ID,
    expected: EXPECTED_NODE_ID,
    description:
      "BLAKE2b-256(\"sharenet-node-id-v1\" || TEST_PUBLIC_KEY) MUST equal the FROZEN NodeId " +
      "hex recorded above. A change indicates a derivation regression (ADR-0003) — this is " +
      "the single most important stability guarantee in the protocol.",
  });

  // Vector 2: NodeId derivation is deterministic
  const derivedAgain = deriveNodeId(GOLDEN_KEYPAIR.publicKey);
  results.push({
    name: "node-id-deterministic",
    passed: derivedAgain === GOLDEN_NODE_ID,
    actual: derivedAgain,
    expected: GOLDEN_NODE_ID,
    description:
      "Calling deriveNodeId twice on the same public key MUST yield the same NodeId.",
  });

  // Vector 3: NodeId binding verification accepts correct binding
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

  // Vector 4: NodeId binding verification rejects an incorrect binding
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

  // Vector 5: NodeId format validation accepts canonical NodeIds
  const formatOk = isValidNodeIdFormat(GOLDEN_NODE_ID);
  results.push({
    name: "node-id-format-accepts-canonical",
    passed: formatOk === true,
    actual: String(formatOk),
    expected: "true",
    description:
      "isValidNodeIdFormat accepts strings of form 'node:' + 64 lowercase hex chars.",
  });

  // Vector 6: NodeId format validation rejects malformed strings
  const malformedExamples = [
    "", // empty
    "node:", // missing hash
    "node:abc", // too short
    "node:ZZZZ0000000000000000000000000000000000000000000000000000000000", // uppercase/non-hex
    "notnode:abcdef0000000000000000000000000000000000000000000000000000000000", // wrong prefix
    "node:abcdef0000000000000000000000000000000000000000000000000000000000extra", // too long
  ];
  const allMalformedRejected = malformedExamples.every((s) => !isValidNodeIdFormat(s));
  results.push({
    name: "node-id-format-rejects-malformed",
    passed: allMalformedRejected,
    actual: `rejected ${malformedExamples.filter((s) => !isValidNodeIdFormat(s)).length}/${malformedExamples.length}`,
    expected: `rejected ${malformedExamples.length}/${malformedExamples.length}`,
    description:
      "isValidNodeIdFormat MUST reject empty strings, wrong prefixes, wrong lengths, " +
      "and non-hex characters.",
  });

  return results;
}

/** Re-export keypair for direct use by tests/debugging. */
export { GOLDEN_KEYPAIR as GOLDEN_IDENTITY };
