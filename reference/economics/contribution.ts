/**
 * ShareNet 2.0 — Contribution Proofs (GATE-11).
 *
 * Per spec/11-contribution.md and GATE-11 requirements:
 *
 *   Gateway session
 *       ↓
 *   actual service measurement
 *       ↓
 *   signed receipt
 *       ↓
 *   ContributionProof
 *       ↓
 *   verification
 *       ↓
 *   ContributionLedger
 *       ↓
 *   Civic Points (GATE-12)
 *
 *   Never credit based solely on "I forwarded 10 GB."
 *   Self-reported traffic creates NO credit.
 *
 *   ContributionProof ≠ CivicPoints (GATE-12).
 *   ContributionProof is the cryptographic attestation of measured service.
 *   CivicPoints are the internal resource accounting derived from proofs.
 *
 * Per spec/00 §2 (Economics):
 *   Contribution ≠ ContributionProof ≠ CivicPoints ≠ Settlement ≠ ExternalCryptocurrency
 */

import { signMessage, verifySignature } from "../identity/keys";
import { blake3 } from "@noble/hashes/blake3.js";
import { canonicalEncode, toHex, fromHex } from "../encoding/cbor";
import type { ServiceMeasurement } from "../gateway/gateway";

// -----------------------------------------------------------------------
// Constants (FROZEN per spec/14 §4)
// -----------------------------------------------------------------------

export const CONTRIBUTION_PROOF_DOMAIN = "SHARENET/CONTRIBUTION/PROOF/1";
export const RECEIPT_DOMAIN = "SHARENET/CONTRIBUTION/RECEIPT/1";

// -----------------------------------------------------------------------
// Bilateral receipt (signed by BOTH gateway and peer)
// -----------------------------------------------------------------------

/**
 * A bilateral receipt is a mutually-signed attestation that a service
 * session occurred. BOTH the gateway AND the peer sign the receipt,
 * making it a bilateral agreement (not just a self-report).
 *
 * Per GATE-11: "signed bilateral receipts."
 * Per spec/11: "Never credit based solely on 'I forwarded 10 GB.'"
 *
 * The receipt contains the ACTUAL measured service (bytes, duration),
 * not a claimed amount. Both parties must agree on the measurement.
 */
export interface BilateralReceipt {
  /** Unique receipt ID (random 32 bytes, hex). */
  receiptId: string;
  /** The gateway's NodeId. */
  gatewayNodeId: string;
  /** The peer's NodeId. */
  peerNodeId: string;
  /** The destination that was accessed. */
  destination: string;
  /** Bytes sent to the destination (measured, not claimed). */
  bytesSent: number;
  /** Bytes received from the destination (measured, not claimed). */
  bytesReceived: number;
  /** Session start (unix seconds). */
  sessionStart: number;
  /** Session end (unix seconds). */
  sessionEnd: number;
  /** HTTP status code of the last response. */
  httpStatus: number;
  /** Gateway's Ed25519 signature over the receipt body. */
  gatewaySignature: Uint8Array;
  /** Peer's Ed25519 signature over the receipt body. */
  peerSignature: Uint8Array;
}

/** Compute the signing payload for a bilateral receipt body (without signatures). */
export function receiptSigningPayload(receipt: Omit<BilateralReceipt, "gatewaySignature" | "peerSignature">): Uint8Array {
  const m = new Map<number, unknown>([
    [1, receipt.receiptId],
    [2, receipt.gatewayNodeId],
    [3, receipt.peerNodeId],
    [4, receipt.destination],
    [5, receipt.bytesSent],
    [6, receipt.bytesReceived],
    [7, receipt.sessionStart],
    [8, receipt.sessionEnd],
    [9, receipt.httpStatus],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(RECEIPT_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * Create a bilateral receipt. BOTH parties must sign.
 *
 * The gateway signs first (it measured the service), then the peer
 * signs (acknowledging the measurement is accurate).
 */
export function createBilateralReceipt(
  body: Omit<BilateralReceipt, "gatewaySignature" | "peerSignature">,
  gatewaySecretKey: Uint8Array,
  peerSecretKey: Uint8Array,
): BilateralReceipt {
  const payload = receiptSigningPayload(body);
  const gatewaySignature = signMessage(gatewaySecretKey, payload);
  const peerSignature = signMessage(peerSecretKey, payload);
  return { ...body, gatewaySignature, peerSignature };
}

/**
 * Verify a bilateral receipt. BOTH signatures must verify.
 *
 * Per GATE-11: "proof verification." A receipt with only one valid
 * signature is NOT a valid bilateral receipt — it's a unilateral claim
 * (which creates NO credit per spec/11).
 */
export function verifyBilateralReceipt(
  receipt: BilateralReceipt,
  gatewayPublicKey: Uint8Array,
  peerPublicKey: Uint8Array,
): { ok: true } | { ok: false; reason: string } {
  const payload = receiptSigningPayload(receipt);

  if (!verifySignature(gatewayPublicKey, payload, receipt.gatewaySignature)) {
    return { ok: false, reason: "gateway signature invalid" };
  }
  if (!verifySignature(peerPublicKey, payload, receipt.peerSignature)) {
    return { ok: false, reason: "peer signature invalid" };
  }
  return { ok: true };
}

// -----------------------------------------------------------------------
// ContributionProof (derived from a verified bilateral receipt)
// -----------------------------------------------------------------------

/**
 * A ContributionProof is the cryptographic attestation of measured service.
 *
 * Per spec/11:
 *   Contribution ≠ ContributionProof
 *
 *   A Contribution is the act of providing service.
 *   A ContributionProof is the cryptographic evidence that the service was provided.
 *
 * Per spec/00 §31 (forbidden):
 *   "self-reported contribution → Civic Points" is FORBIDDEN.
 *   A ContributionProof requires bilateral signatures, not self-reporting.
 *
 * A ContributionProof is created ONLY from a verified bilateral receipt.
 * Self-reported traffic (one signature, or no signature) CANNOT create
 * a ContributionProof.
 */
export interface ContributionProof {
  /** The receipt ID this proof is derived from. */
  receiptId: string;
  /** The contributing node (gateway or relay). */
  contributorNodeId: string;
  /** The benefiting peer. */
  peerNodeId: string;
  /** The service provided (e.g. "INTERNET_GATEWAY"). */
  serviceType: string;
  /** Measured bytes forwarded (sent + received). */
  bytesForwarded: number;
  /** Session duration in seconds. */
  durationSeconds: number;
  /** Hash of the bilateral receipt (for ledger dedup). */
  receiptHash: string;
  /** Gateway signature (from the receipt). */
  gatewaySignature: Uint8Array;
  /** Peer signature (from the receipt). */
  peerSignature: Uint8Array;
  /** Proof creation timestamp. */
  createdAt: number;
}

/**
 * Create a ContributionProof from a verified bilateral receipt.
 *
 * This is the ONLY function that creates a ContributionProof.
 * It requires a receipt where BOTH signatures have been verified.
 * A self-reported receipt (one signature) CANNOT create a proof.
 *
 * Per spec/00 §31: self-reported contribution → Civic Points is FORBIDDEN.
 */
export function createContributionProof(
  receipt: BilateralReceipt,
  gatewayPublicKey: Uint8Array,
  peerPublicKey: Uint8Array,
  now: number,
): { ok: true; proof: ContributionProof } | { ok: false; reason: string } {
  // Verify the receipt first
  const verification = verifyBilateralReceipt(receipt, gatewayPublicKey, peerPublicKey);
  if (!verification.ok) {
    return { ok: false, reason: `receipt verification failed: ${verification.reason}` };
  }

  // Compute receipt hash (for ledger dedup)
  const hashInput = receiptSigningPayload(receipt);
  const receiptHash = toHex(blake3(hashInput, { dkLen: 32 }));

  return {
    ok: true,
    proof: {
      receiptId: receipt.receiptId,
      contributorNodeId: receipt.gatewayNodeId,
      peerNodeId: receipt.peerNodeId,
      serviceType: "INTERNET_GATEWAY",
      bytesForwarded: receipt.bytesSent + receipt.bytesReceived,
      durationSeconds: receipt.sessionEnd - receipt.sessionStart,
      receiptHash,
      gatewaySignature: receipt.gatewaySignature,
      peerSignature: receipt.peerSignature,
      createdAt: now,
    },
  };
}

// -----------------------------------------------------------------------
// ContributionLedger (append-only, hash-chained per spec/11 §4)
// -----------------------------------------------------------------------

export const LEDGER_ENTRY_DOMAIN = "SHARENET/CONTRIBUTION/LEDGER/1";

export interface LedgerEntry {
  sequence: number;           // monotonic ledger-wide counter
  proofHash: string;          // hex of receiptHash from the ContributionProof (wire representation)
  verifiedAt: number;         // when the verifier confirmed the proof
  verifierId: string;         // NodeId of the verifying node
  verifierSignature: Uint8Array; // Ed25519 by verifier over the entry body
  prevHash: string;           // hex of BLAKE3-256(entry_{n-1}); "0"*64 for genesis
  entryHash: string;          // hex of BLAKE3-256(this entry, excl. entryHash)
}

/**
 * Compute the LedgerEntry **signing payload** (what the verifier signs).
 *
 * Per spec/11 §4 (FROZEN): the verifier signature is OVER the entry body
 * EXCLUDING the verifier_signature itself — otherwise the construction is
 * circular. The signing payload includes:
 *   sequence, proof_hash, verified_at, verifier_id, prev_hash
 *
 * payload = domain || canonicalEncode({1: sequence, 2: proofHash,
 *   3: verifiedAt, 4: verifierId, 5: prevHash})
 */
export function ledgerEntrySigningPayload(
  entry: Pick<LedgerEntry, "sequence" | "proofHash" | "verifiedAt" | "verifierId" | "prevHash">,
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, entry.sequence],
    [2, entry.proofHash],
    [3, entry.verifiedAt],
    [4, entry.verifierId],
    [5, entry.prevHash],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(LEDGER_ENTRY_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * Compute the LedgerEntry **hash payload** (what the entryHash is derived from).
 *
 * Per spec/11 §4 (FROZEN): the entry_hash INCLUDES the verifier_signature
 * (so tampering with the signature breaks the hash chain). The hash payload
 * includes:
 *   sequence, proof_hash, verified_at, verifier_id, verifier_signature, prev_hash
 *
 * payload = domain || canonicalEncode({1: sequence, 2: proofHash,
 *   3: verifiedAt, 4: verifierId, 5: verifierSignature, 6: prevHash})
 */
export function ledgerEntryHashPayload(
  entry: Omit<LedgerEntry, "entryHash">,
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, entry.sequence],
    [2, entry.proofHash],
    [3, entry.verifiedAt],
    [4, entry.verifierId],
    [5, entry.verifierSignature],
    [6, entry.prevHash],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(LEDGER_ENTRY_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * Compute the entry hash: BLAKE3-256 of the hash payload (which INCLUDES
 * the verifier_signature but EXCLUDES entryHash itself).
 */
export function computeLedgerEntryHash(entry: Omit<LedgerEntry, "entryHash">): string {
  return toHex(blake3(ledgerEntryHashPayload(entry), { dkLen: 32 }));
}

/**
 * An append-only contribution ledger.
 *
 * Per GATE-11: "append-only contribution ledger."
 *
 * Properties:
 *   - Append-only: entries can NEVER be removed or modified.
 *   - Dedup by receipt hash: the same receipt cannot create two proofs.
 *   - Replay protection: the same proof cannot be appended twice.
 *   - Fraud detection: proofs with invalid signatures are rejected.
 *
 * Per spec/11:
 *   ContributionProof → verification → ContributionLedger → Civic Points
 */
export class ContributionLedger {
  private entries: LedgerEntry[] = [];
  private proofs: Map<string, ContributionProof> = new Map(); // proofHash → proof (internal)
  private seenReceiptHashes = new Set<string>();
  private nextSeq = 0;

  /**
   * Append a verified contribution proof to the ledger.
   *
   * Per spec/11 §4: entries are hash-chained. The verifier signs each
   * entry with its Ed25519 key, and the entry's `prevHash` links to
   * the previous entry's hash. Tampering with any entry breaks the chain.
   *
   * Returns false if:
   *   - The receipt hash was already seen (duplicate/replay)
   */
  append(
    proof: ContributionProof,
    verifierNodeId: string,
    verifierSecretKey: Uint8Array,
    now: number,
  ): { ok: true; sequence: number; entryHash: string } | { ok: false; reason: string } {
    // Dedup: check receipt hash
    if (this.seenReceiptHashes.has(proof.receiptHash)) {
      return { ok: false, reason: `receipt hash ${proof.receiptHash.slice(0, 16)}... already in ledger (duplicate/replay)` };
    }

    const seq = this.nextSeq++;
    const prevHash = this.entries.length > 0
      ? this.entries[this.entries.length - 1]!.entryHash
      : "0".repeat(64); // genesis entry

    // Build the entry body (without verifierSignature or entryHash)
    // for the signing payload. The signing payload EXCLUDES verifierSignature
    // to avoid circularity — the verifier signs over the 5 non-signature fields.
    const signingInput = {
      sequence: seq,
      proofHash: proof.receiptHash,
      verifiedAt: now,
      verifierId: verifierNodeId,
      prevHash,
    };

    // Compute the signing payload and sign it
    const signingPayload = ledgerEntrySigningPayload(signingInput);
    const verifierSignature = signMessage(verifierSecretKey, signingPayload);

    // Build the full entry (with the real signature, without entryHash)
    const entryWithSignature: Omit<LedgerEntry, "entryHash"> = {
      ...signingInput,
      verifierSignature,
    };

    // Compute the entry hash (over the hash payload — INCLUDES verifierSignature)
    const entryHash = computeLedgerEntryHash(entryWithSignature);

    const entry: LedgerEntry = {
      ...entryWithSignature,
      entryHash,
    };

    this.entries.push(entry);
    this.proofs.set(proof.receiptHash, proof);
    this.seenReceiptHashes.add(proof.receiptHash);

    return { ok: true, sequence: seq, entryHash };
  }

  /**
   * Verify the hash chain integrity.
   *
   * Returns false if any entry's prevHash doesn't match the previous
   * entry's entryHash, or if any entry's verifier signature is invalid.
   */
  verifyChain(
    verifierPublicKeys: Map<string, Uint8Array>,
  ): { ok: true } | { ok: false; reason: string } {
    let prevHash = "0".repeat(64); // genesis

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i]!;

      // Check prevHash chain
      if (entry.prevHash !== prevHash) {
        return { ok: false, reason: `chain broken at entry ${i}: prevHash ${entry.prevHash.slice(0, 16)}... != expected ${prevHash.slice(0, 16)}...` };
      }

      // Verify verifier signature (over signing payload — EXCLUDES verifierSignature)
      const signingPayload = ledgerEntrySigningPayload(entry);
      const pubKey = verifierPublicKeys.get(entry.verifierId);
      if (!pubKey) {
        return { ok: false, reason: `entry ${i}: no public key for verifier ${entry.verifierId}` };
      }
      if (!verifySignature(pubKey, signingPayload, entry.verifierSignature)) {
        return { ok: false, reason: `entry ${i}: verifier signature invalid` };
      }

      // Verify entryHash (over hash payload — INCLUDES verifierSignature)
      const entryWithoutHash: Omit<LedgerEntry, "entryHash"> = {
        sequence: entry.sequence,
        proofHash: entry.proofHash,
        verifiedAt: entry.verifiedAt,
        verifierId: entry.verifierId,
        verifierSignature: entry.verifierSignature,
        prevHash: entry.prevHash,
      };
      const recomputedHash = computeLedgerEntryHash(entryWithoutHash);
      if (recomputedHash !== entry.entryHash) {
        return { ok: false, reason: `entry ${i}: entryHash ${entry.entryHash.slice(0, 16)}... != recomputed ${recomputedHash.slice(0, 16)}...` };
      }

      prevHash = entry.entryHash;
    }

    return { ok: true };
  }

  /** Get all ledger entries (read-only). */
  getEntries(): readonly LedgerEntry[] {
    return this.entries;
  }

  /** Get entries for a specific contributor (looks up proof internally). */
  getEntriesByContributor(contributorNodeId: string): readonly LedgerEntry[] {
    return this.entries.filter((e) => {
      const proof = this.proofs.get(e.proofHash);
      return proof?.contributorNodeId === contributorNodeId;
    });
  }

  /** Total bytes forwarded by a contributor (looks up proof internally). */
  getTotalBytesForwarded(contributorNodeId: string): number {
    return this.entries
      .filter((e) => {
        const proof = this.proofs.get(e.proofHash);
        return proof?.contributorNodeId === contributorNodeId;
      })
      .reduce((sum, e) => {
        const proof = this.proofs.get(e.proofHash);
        return sum + (proof?.bytesForwarded ?? 0);
      }, 0);
  }

  /** Total entries in the ledger. */
  size(): number {
    return this.entries.length;
  }

  /** True if a receipt hash has been seen. */
  hasReceiptHash(hash: string): boolean {
    return this.seenReceiptHashes.has(hash);
  }
}

// -----------------------------------------------------------------------
// Architecture guard: self-reported traffic creates no credit
// -----------------------------------------------------------------------

/**
 * Per spec/00 §31 and spec/11:
 *   "self-reported contribution → Civic Points" is FORBIDDEN.
 *
 * This guard throws if any code attempts to create a ContributionProof
 * or ledger entry from self-reported traffic (without bilateral signatures).
 */
export function SELF_REPORTED_CONTRIBUTION_FORBIDDEN(nodeId: string, claimedBytes: number): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: node ${nodeId} attempted to self-report ${claimedBytes} bytes ` +
      `of contribution. Per spec/00 §31 and spec/11, self-reported traffic creates NO credit. ` +
      `A ContributionProof requires a BILATERAL receipt signed by BOTH the gateway AND the peer. ` +
      `The contribution must be MEASURED (by the gateway) and ACKNOWLEDGED (by the peer), not claimed.`,
  );
}
