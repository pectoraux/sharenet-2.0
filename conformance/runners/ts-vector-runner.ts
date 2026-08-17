/**
 * ShareNet 2.0 — TypeScript Conformance Vector Runner
 *
 * Per GATE-01: reads vectors from conformance/vectors/ files (not runtime-only
 * golden vectors) and verifies each one against the reference implementation.
 *
 * Usage: bun run conformance/runners/ts-vector-runner.ts
 * Exit: 0 if all vectors pass, 1 if any fail.
 */

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  keypairFromSecretKey,
  deriveNodeId,
  verifyNodeIdBinding,
  isValidNodeIdFormat,
  hexToBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  verifyAdvertisement,
  advertisementFromHex,
  type NodeAdvertisement,
} from "@reference/advertisement/advertisement";
import { checkSequence } from "@reference/advertisement/sequence-floor";
import { canonicalEncode, canonicalDecode, isCanonical, toHex, fromHex } from "@reference/encoding/cbor";
import {
  computeTranscriptHash,
  computeLinkIdBytes,
  buildPossessionPayload,
  signPossessionProof,
  verifyPossessionProof,
  decodeMessage,
  POSSESSION_DOMAIN_INITIATOR,
  POSSESSION_DOMAIN_RESPONDER,
  ROLE_INITIATOR,
  ROLE_RESPONDER,
} from "@reference/transport/auth-handshake";

interface VectorResult {
  id: string;
  passed: boolean;
  expected: string;
  actual: string;
}

const vectorsDir = join(process.cwd(), "conformance", "vectors");

function walkJsonFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...walkJsonFiles(full));
    } else if (entry.endsWith(".json")) {
      out.push(full);
    }
  }
  return out;
}

function verifyNodeIdVector(data: any): VectorResult {
  const pubKeyHex = data.input.ed25519PublicKeyHex;
  const expectedNodeId = data.expected.nodeIdText;
  const pubKey = hexToBytes(pubKeyHex);
  const actualNodeId = deriveNodeId(pubKey);
  const passed = actualNodeId === expectedNodeId && isValidNodeIdFormat(actualNodeId);
  return {
    id: data.id,
    passed,
    expected: expectedNodeId,
    actual: passed ? actualNodeId : `mismatch: ${actualNodeId} != ${expectedNodeId}`,
  };
}

function verifyNodeIdFormatVector(data: any): VectorResult {
  const cases = data.cases || [];
  let allOk = true;
  const failures: string[] = [];
  for (const c of cases) {
    const result = isValidNodeIdFormat(c.input);
    if (result !== c.expected) {
      allOk = false;
      failures.push(`${c.input.slice(0, 20)}... expected=${c.expected} got=${result}`);
    }
  }
  return {
    id: data.id,
    passed: allOk,
    expected: `${cases.length} cases all match`,
    actual: allOk ? `${cases.length} cases all match` : `FAILED: ${failures.join("; ")}`,
  };
}

function verifyCborVector(data: any): VectorResult {
  const vectors = data.vectors || [];
  let allOk = true;
  const failures: string[] = [];
  for (const v of vectors) {
    try {
      let input = v.input;
      // Handle byte-string marker
      if (typeof input === "object" && input !== null && "__bytes__" in input) {
        input = hexToBytes(input.__bytes__);
      }
      const encoded = canonicalEncode(input);
      const actualHex = toHex(encoded);
      if (actualHex !== v.expectedHex) {
        allOk = false;
        failures.push(`${v.name}: ${actualHex} != ${v.expectedHex}`);
      }
    } catch (e) {
      allOk = false;
      failures.push(`${v.name}: threw ${(e as Error).message}`);
    }
  }
  return {
    id: data.id,
    passed: allOk,
    expected: `${vectors.length} CBOR vectors match`,
    actual: allOk ? `${vectors.length} CBOR vectors match` : `FAILED: ${failures.join("; ")}`,
  };
}

function verifyAdvVector(data: any): VectorResult {
  const hex = data.input.advertisementHex;
  const referenceNow = data.referenceNow;
  const expectedNodeId = data.input.expectedNodeId;
  const currentFloor = data.input.currentSequenceFloor ?? null;

  try {
    const adv = advertisementFromHex(hex);
    const v = verifyAdvertisement(adv, referenceNow);
    if (data.expected.verificationResult === "ok") {
      if (v.ok) {
        // Also check sequence floor if specified
        if (currentFloor !== null) {
          const seqCheck = checkSequence(currentFloor, adv.sequence);
          if (seqCheck.ok) {
            return { id: data.id, passed: true, expected: "ok", actual: "ok" };
          } else {
            return { id: data.id, passed: false, expected: "ok", actual: `sequence check: ${seqCheck.reason}` };
          }
        }
        return { id: data.id, passed: true, expected: "ok", actual: "ok" };
      } else {
        return { id: data.id, passed: false, expected: "ok", actual: `fail: ${v.error}` };
      }
    } else {
      // Expected fail
      if (!v.ok) {
        // For DECODE_FAILED, the decode itself should throw
        return { id: data.id, passed: v.error === data.expected.errorCode || data.expected.errorCode === "DECODE_FAILED", expected: `fail/${data.expected.errorCode}`, actual: `fail/${v.error}` };
      } else {
        // Verification passed but we expected a fail — check if it's a sequence floor failure
        if (currentFloor !== null && data.expected.errorCode === "STALE") {
          const seqCheck = checkSequence(currentFloor, adv.sequence);
          if (!seqCheck.ok && seqCheck.reason === "STALE") {
            return { id: data.id, passed: true, expected: `fail/STALE`, actual: `verify ok, seq STALE (floor=${currentFloor}, attempted=${adv.sequence})` };
          }
        }
        return { id: data.id, passed: false, expected: `fail/${data.expected.errorCode}`, actual: "ok (unexpected)" };
      }
    }
  } catch (e) {
    if (data.expected.errorCode === "DECODE_FAILED") {
      return { id: data.id, passed: true, expected: "fail/DECODE_FAILED", actual: `decode threw: ${(e as Error).message}` };
    }
    return { id: data.id, passed: false, expected: data.expected.errorCode ?? "ok", actual: `threw: ${(e as Error).message}` };
  }
}

function verifyHandshakeVector(data: any): VectorResult {
  const input = data.input;
  const expected = data.expected;

  // Parse the wire messages
  const initiateBytes = fromHex(input.initiateMessageHex);
  const acceptBytes = fromHex(input.acceptMessageHex);
  const confirmBytes = input.confirmMessageHex ? fromHex(input.confirmMessageHex) : null;

  // Parse keys
  const pubKeyA = hexToBytes(input.initiatorPublicKeyHex);
  const pubKeyB = hexToBytes(input.responderPublicKeyHex);
  const nodeIdA = input.initiatorNodeId;
  const nodeIdB = input.responderNodeId;
  const linkNonceA = hexToBytes(input.linkNonceAHex);
  const linkNonceB = hexToBytes(input.linkNonceBHex);
  const challengeForB = hexToBytes(input.challengeForBHex);
  const challengeForA = hexToBytes(input.challengeForAHex);

  // Compute LinkId bytes (from responder's perspective: local=B, remote=A)
  const linkIdBytes = computeLinkIdBytes(nodeIdB, nodeIdA, linkNonceB, linkNonceA);

  // Compute transcript hashes
  const transcriptHashAfterInitiate = computeTranscriptHash([initiateBytes]);
  const transcriptHashAfterAccept = computeTranscriptHash([initiateBytes, acceptBytes]);

  // Decode Accept message to get proofB
  const acceptMsg = decodeMessage(acceptBytes) as any;
  const proofB = acceptMsg.proofB ? new Uint8Array(acceptMsg.proofB) : new Uint8Array(64);

  // Verify proofB (B signs challengeForB with RESPONDER role)
  const proofBOk = verifyPossessionProof(
    pubKeyB, proofB, POSSESSION_DOMAIN_RESPONDER,
    transcriptHashAfterInitiate, linkIdBytes, challengeForB, ROLE_RESPONDER,
  );

  if (expected.result === "LINK_UP") {
    // Also need to verify proofA
    if (!confirmBytes) {
      return { id: data.id, passed: false, expected: "LINK_UP", actual: "missing confirmMessageHex" };
    }
    const confirmMsg = decodeMessage(confirmBytes) as any;
    const proofA = confirmMsg.proofA ? new Uint8Array(confirmMsg.proofA) : new Uint8Array(64);
    const proofAOk = verifyPossessionProof(
      pubKeyA, proofA, POSSESSION_DOMAIN_INITIATOR,
      transcriptHashAfterAccept, linkIdBytes, challengeForA, ROLE_INITIATOR,
    );
    const passed = proofBOk && proofAOk;
    return {
      id: data.id,
      passed,
      expected: `LINK_UP (proofB=${expected.proofBValid}, proofA=${expected.proofAValid})`,
      actual: `proofB=${proofBOk}, proofA=${proofAOk}`,
    };
  } else {
    // Expected fail
    const passed = !proofBOk;
    return {
      id: data.id,
      passed,
      expected: `fail/${expected.errorCode}`,
      actual: passed ? `proofB invalid (as expected)` : `proofB valid (unexpected — should have failed)`,
    };
  }
}

// Main
const files = walkJsonFiles(vectorsDir);
const results: VectorResult[] = [];

for (const file of files) {
  const data = JSON.parse(readFileSync(file, "utf-8"));
  let result: VectorResult;

  if (data.id?.startsWith("V-NODEID-001")) {
    result = verifyNodeIdVector(data);
  } else if (data.id?.startsWith("V-NODEID-002")) {
    // Binding rejection: verify that the claimed NodeId does NOT match a different key
    const claimedNodeId = data.input.claimedNodeId;
    const diffPubKey = hexToBytes(data.input.differentPublicKeyHex);
    const rejects = !verifyNodeIdBinding(claimedNodeId, diffPubKey);
    result = { id: data.id, passed: rejects, expected: "verifyNodeIdBinding returns false", actual: `returns ${!rejects}` };
  } else if (data.id?.startsWith("V-NODEID-003")) {
    result = verifyNodeIdFormatVector(data);
  } else if (data.id?.startsWith("V-CBOR-")) {
    result = verifyCborVector(data);
  } else if (data.id?.startsWith("V-ADV-")) {
    result = verifyAdvVector(data);
  } else if (data.id?.startsWith("V-LINK-HANDSHAKE-") || data.id?.startsWith("V-LINK-AUTH-")) {
    result = verifyHandshakeVector(data);
  } else {
    result = { id: data.id ?? file, passed: false, expected: "known vector type", actual: "unknown vector type" };
  }

  results.push(result);
}

// Report
console.log("");
console.log("=== TypeScript Conformance Vector Runner ===");
console.log(`Vectors checked: ${results.length}`);
console.log("");

let allPassed = true;
for (const r of results) {
  const status = r.passed ? "PASS" : "FAIL";
  console.log(`  [${status}] ${r.id}`);
  if (!r.passed) {
    console.log(`    expected: ${r.expected}`);
    console.log(`    actual:   ${r.actual}`);
    allPassed = false;
  }
}
console.log("");

const passed = results.filter((r) => r.passed).length;
const failed = results.length - passed;
console.log(`Passed: ${passed}/${results.length}, Failed: ${failed}`);
console.log("");

process.exit(failed > 0 ? 1 : 0);
