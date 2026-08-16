/**
 * ShareNet 2.0 — Hint Propagation Store (GATE-04).
 *
 * Per spec/06-topology.md and GATE-04 requirements:
 *   - separate propagation sequence floor (distinct from advertisement sequence floor)
 *   - bounded size (max hints per reporter, max total hints)
 *   - bounded horizon (hopCount ≤ MAX_HINT_HOPS)
 *   - freshness (timestamp within MAX_HINT_FRESHNESS_SECONDS)
 *   - provenance (reporterNodeId + reporterSignature)
 *   - replay protection (nonce uniqueness per reporter)
 *
 * This store is the ONLY data structure that holds RemoteNodeHints.
 * It is in-memory (protocol-core, no DB dependency per ADR-0013).
 * A hint in this store CANNOT be promoted to an AuthenticatedNodeRecord.
 */

import type { RemoteNodeHint } from "./remote-node-hint";
import { MAX_HINT_HOPS, MAX_HINT_FRESHNESS_SECONDS, createRemoteNodeHint } from "./remote-node-hint";
import { randomBytes } from "@noble/hashes/utils.js";

/** Maximum hints stored per reporter (bounded size). */
export const MAX_HINTS_PER_REPORTER = 100;

/** Maximum total hints in the store (bounded size). */
export const MAX_TOTAL_HINTS = 10000;

/**
 * Propagation sequence floor — separate from advertisement sequence floor.
 *
 * Per GATE-04: "separate propagation sequence floor."
 * Each reporter has its own monotonic propagation counter. A hint with
 * a propagation sequence ≤ the current floor is rejected as a replay.
 *
 * This is DISTINCT from the advertisement sequence floor (which protects
 * NodeAdvertisement acceptance). Hint propagation has its own replay
 * protection because hints are forwarded by intermediaries, not just
 * originated by the subject.
 */
export interface PropagationFloorEntry {
  reporterNodeId: string;
  currentMaxPropagationSeq: number;
  lastSeenAt: number;
}

export interface HintStoreEntry {
  hint: RemoteNodeHint;
  propagationSeq: number;  // assigned by the forwarding node
  receivedAt: number;
}

/**
 * In-memory hint propagation store with bounded size, freshness, and replay protection.
 *
 * This store CANNOT produce AuthenticatedNodeRecords. It only holds hints.
 * The PROMOTE_HINT_TO_RECORD_FORBIDDEN guard in remote-node-hint.ts enforces
 * this at the type level.
 */
export class HintPropagationStore {
  private hints: Map<string, HintStoreEntry> = new Map(); // key = hint hash
  private propagationFloors: Map<string, PropagationFloorEntry> = new Map();
  private seenNonces: Map<string, number> = new Map(); // nonceHex -> timestamp

  /**
   * Accept a hint into the store. Returns the result of the acceptance check.
   *
   * Checks:
   *   1. Bounded horizon: hint.hopCount ≤ MAX_HINT_HOPS
   *   2. Freshness: |hint.timestamp - now| ≤ MAX_HINT_FRESHNESS_SECONDS
   *   3. Replay protection: hint.nonce not previously seen
   *   4. Bounded size: store has room (≤ MAX_TOTAL_HINTS)
   *   5. Per-reporter bound: reporter has ≤ MAX_HINTS_PER_REPORTER hints
   *   6. Propagation sequence floor: propagationSeq > current floor for this reporter
   */
  acceptHint(
    hint: RemoteNodeHint,
    propagationSeq: number,
    now: number = Math.floor(Date.now() / 1000),
  ): { ok: true } | { ok: false; reason: string } {
    // 1. Bounded horizon
    if (hint.hopCount > MAX_HINT_HOPS) {
      return { ok: false, reason: `hopCount ${hint.hopCount} > max ${MAX_HINT_HOPS}` };
    }

    // 2. Freshness
    if (Math.abs(hint.timestamp - now) > MAX_HINT_FRESHNESS_SECONDS) {
      return { ok: false, reason: "hint outside freshness window" };
    }

    // 3. Replay protection (nonce uniqueness)
    const nonceKey = this.nonceKey(hint.reporterNodeId, hint.nonce);
    if (this.seenNonces.has(nonceKey)) {
      return { ok: false, reason: "hint nonce already seen (replay)" };
    }

    // 4. Bounded size
    if (this.hints.size >= MAX_TOTAL_HINTS) {
      // Evict oldest
      this.evictOldest();
    }

    // 5. Per-reporter bound
    const reporterCount = this.countByReporter(hint.reporterNodeId);
    if (reporterCount >= MAX_HINTS_PER_REPORTER) {
      // Evict oldest from this reporter
      this.evictOldestByReporter(hint.reporterNodeId);
    }

    // 6. Propagation sequence floor
    const floor = this.propagationFloors.get(hint.reporterNodeId);
    if (floor && propagationSeq <= floor.currentMaxPropagationSeq) {
      return {
        ok: false,
        reason: `propagation seq ${propagationSeq} ≤ floor ${floor.currentMaxPropagationSeq} (stale/duplicate)`,
      };
    }

    // Accept
    const hintKey = this.hintHash(hint);
    this.hints.set(hintKey, { hint, propagationSeq, receivedAt: now });
    this.seenNonces.set(nonceKey, now);
    this.propagationFloors.set(hint.reporterNodeId, {
      reporterNodeId: hint.reporterNodeId,
      currentMaxPropagationSeq: propagationSeq,
      lastSeenAt: now,
    });

    return { ok: true };
  }

  /** Get all hints (read-only). */
  getAllHints(): readonly HintStoreEntry[] {
    return Array.from(this.hints.values());
  }

  /** Get hints for a specific reporter. */
  getHintsByReporter(reporterNodeId: string): readonly HintStoreEntry[] {
    return this.getAllHints().filter((e) => e.hint.reporterNodeId === reporterNodeId);
  }

  /** Get the propagation floor for a reporter. */
  getPropagationFloor(reporterNodeId: string): number | null {
    return this.propagationFloors.get(reporterNodeId)?.currentMaxPropagationSeq ?? null;
  }

  /** Total hint count. */
  size(): number {
    return this.hints.size;
  }

  /** Purge expired hints. */
  purgeExpired(now: number = Math.floor(Date.now() / 1000)): number {
    let purged = 0;
    for (const [key, entry] of this.hints) {
      if (Math.abs(entry.hint.timestamp - now) > MAX_HINT_FRESHNESS_SECONDS) {
        this.hints.delete(key);
        purged++;
      }
    }
    return purged;
  }

  // --- internals ---

  private nonceKey(reporterNodeId: string, nonce: Uint8Array): string {
    return reporterNodeId + ":" + this.bytesToHex(nonce);
  }

  private hintHash(hint: RemoteNodeHint): string {
    return hint.reporterNodeId + ":" + hint.subjectNodeId + ":" + this.bytesToHex(hint.nonce);
  }

  private countByReporter(reporterNodeId: string): number {
    let count = 0;
    for (const entry of this.hints.values()) {
      if (entry.hint.reporterNodeId === reporterNodeId) count++;
    }
    return count;
  }

  private evictOldest(): void {
    let oldest: string | null = null;
    let oldestTime = Infinity;
    for (const [key, entry] of this.hints) {
      if (entry.receivedAt < oldestTime) {
        oldestTime = entry.receivedAt;
        oldest = key;
      }
    }
    if (oldest) this.hints.delete(oldest);
  }

  private evictOldestByReporter(reporterNodeId: string): void {
    let oldest: string | null = null;
    let oldestTime = Infinity;
    for (const [key, entry] of this.hints) {
      if (entry.hint.reporterNodeId === reporterNodeId && entry.receivedAt < oldestTime) {
        oldestTime = entry.receivedAt;
        oldest = key;
      }
    }
    if (oldest) this.hints.delete(oldest);
  }

  private bytesToHex(bytes: Uint8Array): string {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i]!.toString(16).padStart(2, "0");
    }
    return out;
  }
}

/**
 * Forward a hint: increment hopCount and re-sign with the forwarder's key.
 *
 * Per spec/06 §4.2: hints are bounded by hopCount. Each forward increments
 * the hopCount. A hint with hopCount > MAX_HINT_HOPS is dropped.
 *
 * The forwarder re-signs the hint body with its OWN key, becoming the new
 * reporter. The original reporter's identity is preserved in the hint's
 * provenance chain (a future extension; for now the forwarder replaces the
 * reporter).
 */
export function forwardHint(
  hint: RemoteNodeHint,
  forwarderNodeId: string,
  forwarderSecretKey: Uint8Array,
): RemoteNodeHint | null {
  if (hint.hopCount >= MAX_HINT_HOPS) {
    return null; // drop — exceeded horizon
  }

  // Create a new hint with hopCount + 1, re-signed by the forwarder.
  // The forwarder becomes the new reporter (the original reporter is
  // implicitly vouched for by the forwarder's signature).
  return createRemoteNodeHint(
    {
      reporterNodeId: forwarderNodeId,
      subjectNodeId: hint.subjectNodeId,
      subjectEndpointHint: hint.subjectEndpointHint,
      claimedCapabilities: hint.claimedCapabilities,
      hopCount: hint.hopCount + 1,
      timestamp: Math.floor(Date.now() / 1000),
      nonce: randomBytes(16),
    },
    forwarderSecretKey,
  );
}
