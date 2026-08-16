/**
 * Persistent Sequence Floor — replay protection for node advertisements.
 *
 * Per spec/14 §3, spec/03 §5.5, and ADR-0006:
 *
 *   For an incoming advertisement with sequence number n:
 *     n < current_floor => stale  (reject, log)
 *     n == current_floor => duplicate (reject, log)
 *     n > current_floor => accept, update floor
 *
 *   Expiration MUST NOT reset the sequence floor.
 *   A tombstone keeps the floor even after the advertisement expires,
 *   so an attacker cannot replay an old (re-signed-freshly) advertisement
 *   after the legitimate node went silent.
 *
 *   Wraparound protection: the floor is a 64-bit unsigned integer stored
 *   as a SQLite INTEGER (8-byte). Sequence numbers MUST strictly increase.
 *
 * This module provides a storage-agnostic interface. The Prisma-backed
 * implementation lives in src/lib/sequence-floor.ts.
 */

import type { AdvertisementVerificationError } from "./advertisement";

/** Result of an acceptance check against the sequence floor. */
export type SequenceCheckResult =
  | { ok: true; previousFloor: number; newFloor: number }
  | { ok: false; reason: "STALE" | "DUPLICATE"; currentFloor: number; attemptedSequence: number };

/**
 * Pure-function core of the sequence check. Storage layers call this after
 * loading the current floor to decide whether to accept the new advertisement.
 *
 * Per ADR-0006 the check is monotonic-only. There is no "within window"
 * allowance: any n <= floor is rejected. This is the strictest policy and
 * the only one that is replay-safe.
 */
export function checkSequence(
  currentFloor: number | null,
  attemptedSequence: number,
): SequenceCheckResult {
  if (attemptedSequence < 0 || !Number.isSafeInteger(attemptedSequence)) {
    // Wraparound / overflow / fractional — reject.
    return {
      ok: false,
      reason: "STALE",
      currentFloor: currentFloor ?? -1,
      attemptedSequence,
    };
  }
  if (currentFloor === null) {
    // First-seen for this node — accept.
    return { ok: true, previousFloor: -1, newFloor: attemptedSequence };
  }
  if (attemptedSequence < currentFloor) {
    return { ok: false, reason: "STALE", currentFloor, attemptedSequence };
  }
  if (attemptedSequence === currentFloor) {
    return { ok: false, reason: "DUPLICATE", currentFloor, attemptedSequence };
  }
  // attemptedSequence > currentFloor — accept
  return { ok: true, previousFloor: currentFloor, newFloor: attemptedSequence };
}

/**
 * The acceptance decision combines cryptographic verification (verifyAdvertisement)
 * with the sequence-floor check. Per spec/03 §5 + ADR-0007, the ONLY legal
 * pipeline from a wire advertisement to an AuthenticatedNodeRecord is:
 *
 *   NodeAdvertisement
 *      ↓ verifyAdvertisement (signature, binding, timestamps, expiry, canonical)
 *   VerifiedNodeAdvertisement
 *      ↓ acceptAdvertisement (sequence floor, acceptance policy)
 *   AuthenticatedNodeRecord
 *
 * Forbidden: RemoteNodeHint → AuthenticatedNodeRecord (spec/06 §3, architecture test #7).
 */
export interface AcceptanceInput {
  verificationOk: boolean;
  verificationError?: AdvertisementVerificationError;
  sequenceCheck: SequenceCheckResult;
}

export type AcceptanceResult =
  | { ok: true; record: AuthenticatedNodeRecordStub }
  | { ok: false; reason: string };

/**
 * Stub for the AuthenticatedNodeRecord. The full record (with link state,
 * observed metrics, etc.) is built later in the pipeline. This minimal stub
 * exists so the acceptance function can return a typed record rather than
 * an untyped object.
 */
export interface AuthenticatedNodeRecordStub {
  nodeId: string;
  publicKeyHex: string;
  capabilities: readonly string[];
  acceptedAt: number;
  sequence: number;
  verifiedAt: number;
}

/**
 * Combine verification + sequence-check results into an accept/reject decision.
 * Returns an AuthenticatedNodeRecordStub on success.
 *
 * This is the SINGLE function that constructs an AuthenticatedNodeRecord from
 * a verified advertisement. All other code paths MUST go through this function.
 * The architecture regression test #7 asserts that no RemoteNodeHint constructor
 * returns an AuthenticatedNodeRecord.
 */
export function acceptAdvertisement(
  nodeId: string,
  publicKey: Uint8Array,
  capabilities: readonly string[],
  sequence: number,
  verifiedAt: number,
  input: AcceptanceInput,
): AcceptanceResult {
  if (!input.verificationOk) {
    return { ok: false, reason: `verification failed: ${input.verificationError ?? "unknown"}` };
  }
  if (!input.sequenceCheck.ok) {
    return {
      ok: false,
      reason: `sequence rejected: ${input.sequenceCheck.reason} (floor=${input.sequenceCheck.currentFloor}, attempted=${input.sequenceCheck.attemptedSequence})`,
    };
  }
  return {
    ok: true,
    record: {
      nodeId,
      publicKeyHex: bytesToHexCompat(publicKey),
      capabilities,
      acceptedAt: Math.floor(Date.now() / 1000),
      sequence,
      verifiedAt,
    },
  };
}

/** Internal hex helper (avoid circular import with keys.ts). */
function bytesToHexCompat(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}
