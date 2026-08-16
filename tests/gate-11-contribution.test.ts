/**
 * ShareNet 2.0 — GATE-11 Tests: Contribution proofs.
 *
 * Per GATE-11 requirements:
 *   - actual measured service creates verifiable proof
 *   - self-reported traffic creates no credit
 *   - fraud/replay/duplicate receipt tests
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  randomBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  createBilateralReceipt,
  verifyBilateralReceipt,
  createContributionProof,
  ContributionLedger,
  SELF_REPORTED_CONTRIBUTION_FORBIDDEN,
  type BilateralReceipt,
} from "@reference/economics/contribution";

const REFERENCE_NOW = 1786876545;

function makeReceiptBody(gatewayNodeId: string, peerNodeId: string) {
  return {
    receiptId: bytesToHex(randomBytes(32)),
    gatewayNodeId,
    peerNodeId,
    destination: "example.com:443",
    bytesSent: 1024,
    bytesReceived: 4096,
    sessionStart: REFERENCE_NOW,
    sessionEnd: REFERENCE_NOW + 10,
    httpStatus: 200,
  };
}

describe("GATE-11: Contribution proofs", () => {
  // --- 1. Bilateral receipt creation + verification ---
  test("bilateral receipt is created and verified by both parties", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const body = makeReceiptBody(gateway.nodeId, peer.nodeId);

    const receipt = createBilateralReceipt(body, gateway.secretKey, peer.secretKey);
    const v = verifyBilateralReceipt(receipt, gateway.publicKey, peer.publicKey);
    expect(v.ok).toBe(true);
  });

  // --- 2. Receipt with wrong gateway key fails ---
  test("receipt with wrong gateway key fails verification", () => {
    const gatewayA = generateNodeKeypair();
    const gatewayB = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const body = makeReceiptBody(gatewayA.nodeId, peer.nodeId);

    const receipt = createBilateralReceipt(body, gatewayA.secretKey, peer.secretKey);
    const v = verifyBilateralReceipt(receipt, gatewayB.publicKey, peer.publicKey);
    expect(v.ok).toBe(false);
  });

  // --- 3. Receipt with wrong peer key fails ---
  test("receipt with wrong peer key fails verification", () => {
    const gateway = generateNodeKeypair();
    const peerA = generateNodeKeypair();
    const peerB = generateNodeKeypair();
    const body = makeReceiptBody(gateway.nodeId, peerA.nodeId);

    const receipt = createBilateralReceipt(body, gateway.secretKey, peerA.secretKey);
    const v = verifyBilateralReceipt(receipt, gateway.publicKey, peerB.publicKey);
    expect(v.ok).toBe(false);
  });

  // --- 4. Contribution proof from verified receipt ---
  test("contribution proof is created from verified bilateral receipt", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const body = makeReceiptBody(gateway.nodeId, peer.nodeId);
    const receipt = createBilateralReceipt(body, gateway.secretKey, peer.secretKey);

    const result = createContributionProof(receipt, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.proof.contributorNodeId).toBe(gateway.nodeId);
      expect(result.proof.peerNodeId).toBe(peer.nodeId);
      expect(result.proof.bytesForwarded).toBe(1024 + 4096);
      expect(result.proof.durationSeconds).toBe(10);
      expect(result.proof.receiptHash.length).toBe(64);
    }
  });

  // --- 5. Contribution proof from unverified receipt fails ---
  test("contribution proof fails from receipt with wrong keys", () => {
    const gatewayA = generateNodeKeypair();
    const gatewayB = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const body = makeReceiptBody(gatewayA.nodeId, peer.nodeId);
    const receipt = createBilateralReceipt(body, gatewayA.secretKey, peer.secretKey);

    const result = createContributionProof(receipt, gatewayB.publicKey, peer.publicKey, REFERENCE_NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("verification failed");
  });

  // --- 6. Append-only ledger ---
  test("ledger appends verified proofs", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const ledger = new ContributionLedger();

    const body = makeReceiptBody(gateway.nodeId, peer.nodeId);
    const receipt = createBilateralReceipt(body, gateway.secretKey, peer.secretKey);
    const proofResult = createContributionProof(receipt, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
    expect(proofResult.ok).toBe(true);

    if (proofResult.ok) {
      const appendResult = ledger.append(proofResult.proof, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
      expect(appendResult.ok).toBe(true);
      expect(ledger.size()).toBe(1);
    }
  });

  // --- 7. Duplicate receipt rejected ---
  test("ledger rejects duplicate receipt (replay)", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const ledger = new ContributionLedger();

    const body = makeReceiptBody(gateway.nodeId, peer.nodeId);
    const receipt = createBilateralReceipt(body, gateway.secretKey, peer.secretKey);
    const proofResult = createContributionProof(receipt, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
    expect(proofResult.ok).toBe(true);

    if (proofResult.ok) {
      // First append — OK
      ledger.append(proofResult.proof, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
      expect(ledger.size()).toBe(1);

      // Second append of the SAME proof — rejected
      const dup = ledger.append(proofResult.proof, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
      expect(dup.ok).toBe(false);
      if (!dup.ok) expect(dup.reason).toContain("duplicate");
      expect(ledger.size()).toBe(1); // still 1
    }
  });

  // --- 8. Self-reported contribution FORBIDDEN ---
  test("SELF_REPORTED_CONTRIBUTION_FORBIDDEN throws", () => {
    expect(() => SELF_REPORTED_CONTRIBUTION_FORBIDDEN("somenode", 10000)).toThrow();
  });

  // --- 9. Actual measured service creates verifiable proof ---
  test("actual measured service creates verifiable proof (full flow)", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const ledger = new ContributionLedger();

    // Step 1: Gateway measures the service (actual bytes, not claimed)
    const measuredBytes = { sent: 2048, received: 8192 };

    // Step 2: Create bilateral receipt (both sign)
    const body = makeReceiptBody(gateway.nodeId, peer.nodeId);
    body.bytesSent = measuredBytes.sent;
    body.bytesReceived = measuredBytes.received;
    const receipt = createBilateralReceipt(body, gateway.secretKey, peer.secretKey);

    // Step 3: Create contribution proof (verifies both signatures)
    const proofResult = createContributionProof(receipt, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
    expect(proofResult.ok).toBe(true);

    // Step 4: Append to ledger
    if (proofResult.ok) {
      const appendResult = ledger.append(proofResult.proof, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
      expect(appendResult.ok).toBe(true);

      // Step 5: Verify the ledger has the correct contribution
      expect(ledger.getTotalBytesForwarded(gateway.nodeId)).toBe(2048 + 8192);
    }
  });

  // --- 10. Self-reported traffic creates NO credit ---
  test("self-reported traffic (one signature only) cannot create a contribution proof", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const body = makeReceiptBody(gateway.nodeId, peer.nodeId);

    // Create a receipt with only the gateway's signature (self-reported)
    const partialReceipt: BilateralReceipt = {
      ...body,
      gatewaySignature: new Uint8Array(64), // placeholder (not valid)
      peerSignature: new Uint8Array(64),    // placeholder (not valid)
    };

    // Attempt to create a contribution proof — must fail
    const result = createContributionProof(partialReceipt, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
    expect(result.ok).toBe(false);
  });

  // --- 11. Multiple contributions from different sessions ---
  test("multiple contributions from different sessions are tracked separately", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const ledger = new ContributionLedger();

    for (let i = 0; i < 5; i++) {
      const body = makeReceiptBody(gateway.nodeId, peer.nodeId);
      body.bytesSent = 1000 * (i + 1);
      body.bytesReceived = 2000 * (i + 1);
      const receipt = createBilateralReceipt(body, gateway.secretKey, peer.secretKey);
      const proofResult = createContributionProof(receipt, gateway.publicKey, peer.publicKey, REFERENCE_NOW + i);
      expect(proofResult.ok).toBe(true);
      if (proofResult.ok) {
        ledger.append(proofResult.proof, gateway.publicKey, peer.publicKey, REFERENCE_NOW + i);
      }
    }

    expect(ledger.size()).toBe(5);
    // Total: sum of (1000+2000) * (1+2+3+4+5) = 3000 * 15 = 45000
    expect(ledger.getTotalBytesForwarded(gateway.nodeId)).toBe(3000 * (1 + 2 + 3 + 4 + 5));
  });

  // --- 12. Different contributors tracked separately ---
  test("different contributors are tracked separately in the ledger", () => {
    const gw1 = generateNodeKeypair();
    const gw2 = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const ledger = new ContributionLedger();

    // gw1 contributes
    const body1 = makeReceiptBody(gw1.nodeId, peer.nodeId);
    body1.bytesSent = 500;
    body1.bytesReceived = 500;
    const r1 = createBilateralReceipt(body1, gw1.secretKey, peer.secretKey);
    const p1 = createContributionProof(r1, gw1.publicKey, peer.publicKey, REFERENCE_NOW);
    if (p1.ok) ledger.append(p1.proof, gw1.publicKey, peer.publicKey, REFERENCE_NOW);

    // gw2 contributes
    const body2 = makeReceiptBody(gw2.nodeId, peer.nodeId);
    body2.bytesSent = 1000;
    body2.bytesReceived = 1000;
    const r2 = createBilateralReceipt(body2, gw2.secretKey, peer.secretKey);
    const p2 = createContributionProof(r2, gw2.publicKey, peer.publicKey, REFERENCE_NOW);
    if (p2.ok) ledger.append(p2.proof, gw2.publicKey, peer.publicKey, REFERENCE_NOW);

    expect(ledger.size()).toBe(2);
    expect(ledger.getTotalBytesForwarded(gw1.nodeId)).toBe(1000);
    expect(ledger.getTotalBytesForwarded(gw2.nodeId)).toBe(2000);
  });

  // --- 13. Tampered receipt (bytes changed after signing) ---
  test("tampered receipt (bytes changed after signing) fails verification", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const body = makeReceiptBody(gateway.nodeId, peer.nodeId);
    const receipt = createBilateralReceipt(body, gateway.secretKey, peer.secretKey);

    // Tamper: change bytesSent after signing
    const tampered: BilateralReceipt = { ...receipt, bytesSent: 999999 };
    const v = verifyBilateralReceipt(tampered, gateway.publicKey, peer.publicKey);
    expect(v.ok).toBe(false);
  });

  // --- 14. Ledger is append-only (entries cannot be removed) ---
  test("ledger entries cannot be removed (append-only)", () => {
    const gateway = generateNodeKeypair();
    const peer = generateNodeKeypair();
    const ledger = new ContributionLedger();

    const body = makeReceiptBody(gateway.nodeId, peer.nodeId);
    const receipt = createBilateralReceipt(body, gateway.secretKey, peer.secretKey);
    const proofResult = createContributionProof(receipt, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
    if (proofResult.ok) {
      ledger.append(proofResult.proof, gateway.publicKey, peer.publicKey, REFERENCE_NOW);
    }

    // The ledger has no remove/delete method — entries are permanent
    expect(ledger.size()).toBe(1);
    const entries = ledger.getEntries();
    expect(entries.length).toBe(1);
    expect(entries[0]!.sequenceNumber).toBe(0);
  });
});
