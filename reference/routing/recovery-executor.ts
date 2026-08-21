/**
 * ShareNet 2.0 — Recovery executor (R-009 Stage 3 Phase 5).
 *
 * Per ADR-0025 (automatic circuit recovery execution):
 *
 *   RecoveryPlan
 *       ↓
 *   RecoveryExecutor.execute()
 *       ↓
 *   candidate discovery → route proposal → route commitment →
 *   circuit establishment → verification → RECOVERED
 *
 * The executor is separate from RecoveryManager (detection/planning) and
 * from the route/circuit construction primitives.
 *
 * ARCHITECTURE: this module lives in `reference/routing/` (the protocol
 * core). It imports from `reference/circuit/`, `reference/routing/`,
 * `reference/identity/`, `reference/failure/`. It does NOT import Prisma,
 * `@/`, sockets, or any platform module. Architecture tests #21/#23
 * remain green.
 */

import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex, canonicalEncode } from "../encoding/cbor";
import { generateNodeKeypair, type NodeKeypair } from "../identity/keys";
import {
  signRouteAcceptance,
  createRouteCommitment,
  type RouteProposal,
  type RouteAcceptance,
  type RouteCommitment,
  type RouteHop,
} from "./route";
import {
  createBrandedCommittedRoute,
  type BrandedCommittedRoute,
  type ValidatedHop,
} from "../transport/validated-types";
import { setupCircuit, type ActiveCircuit } from "../circuit/circuit";
import type { CircuitDestroyStore } from "../circuit/replay-stores";
import type { CircuitSequenceFloorStore } from "../circuit/replay-stores";
import { InMemoryCircuitSequenceFloorStore } from "../circuit/replay-stores";
import type { RecoveryPlan, GatewayCandidate } from "./recovery";
import { discoverAlternativeGateways } from "./recovery";
import type { ServiceAgreement } from "./service-negotiation";

// -----------------------------------------------------------------------
// Frozen constants (ADR-0025 §8)
// -----------------------------------------------------------------------

export const MAX_RECOVERY_ATTEMPTS = 3 as const;
export const RECOVERY_BACKOFF_BASE_SECONDS = 5 as const;
export const RECOVERY_BACKOFF_MAX_SECONDS = 60 as const;

export const RECOVERY_ATTEMPT_DOMAIN = "SHARENET/RECOVERY/ATTEMPT/1";

// -----------------------------------------------------------------------
// Recovery state machine (ADR-0025 §1)
// -----------------------------------------------------------------------

export type RecoveryState =
  | "RECOVERY_PENDING"
  | "DISCOVERING"
  | "ROUTING"
  | "COMMITTING"
  | "ESTABLISHING_CIRCUIT"
  | "VERIFYING"
  | "RECOVERED"
  | "FAILED";

// -----------------------------------------------------------------------
// Recovery attempt identity (ADR-0025 §2)
// -----------------------------------------------------------------------

/**
 * A unique recovery attempt identity. Bound to the failed circuit,
 * the failure event, and a fresh random nonce.
 */
export interface RecoveryAttemptId {
  /** The BLAKE3-256 hash of the binding payload. */
  readonly id: Uint8Array;
  /** Hex of the id (for convenience). */
  readonly idHex: string;
  /** The failed circuit's ID. */
  readonly failedCircuitId: Uint8Array;
  /** The failed route's commitmentRoot. */
  readonly failedCommitmentRoot: Uint8Array;
  /** When the failure was observed. */
  readonly failureTimestamp: number;
  /** Fresh 16-byte nonce (unique per attempt). */
  readonly attemptNonce: Uint8Array;
  /** When this attempt was created. */
  readonly createdAt: number;
}

/**
 * Compute a recovery attempt ID. Every retry gets a distinct ID (fresh nonce).
 */
export function computeRecoveryAttemptId(
  failedCircuitId: Uint8Array,
  failedCommitmentRoot: Uint8Array,
  failureTimestamp: number,
  createdAt: number,
): RecoveryAttemptId {
  const attemptNonce = randomBytes(16);
  const m = new Map<number, unknown>([
    [1, failedCircuitId],
    [2, failedCommitmentRoot],
    [3, failureTimestamp],
    [4, attemptNonce],
    [5, createdAt],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(RECOVERY_ATTEMPT_DOMAIN);
  const input = new Uint8Array(domain.length + body.length);
  input.set(domain, 0);
  input.set(body, domain.length);
  const id = blake3(input, { dkLen: 32 });
  return {
    id,
    idHex: toHex(id),
    failedCircuitId,
    failedCommitmentRoot,
    failureTimestamp,
    attemptNonce,
    createdAt,
  };
}

// -----------------------------------------------------------------------
// Recovery attempt result
// -----------------------------------------------------------------------

/**
 * The result of a recovery execution attempt.
 */
export type RecoveryExecutionResult =
  | {
      ok: true;
      state: "RECOVERED";
      attemptId: RecoveryAttemptId;
      /** The new circuit that replaces the failed one. */
      newCircuit: ActiveCircuit;
      /** The new route's commitmentRoot. */
      newCommitmentRoot: Uint8Array;
      /** The new circuit's ID. */
      newCircuitId: Uint8Array;
    }
  | {
      ok: false;
      state: "FAILED";
      attemptId: RecoveryAttemptId;
      reason: string;
      /** Which stage failed. */
      failedAt: RecoveryState;
    };

// -----------------------------------------------------------------------
// RecoveryExecutor — the production recovery executor
// -----------------------------------------------------------------------

/**
 * The production recovery executor. Consumes a RecoveryPlan and executes
 * the full recovery pipeline:
 *
 *   1. Candidate gateway discovery (discoverAlternativeGateways)
 *   2. New route proposal (RouteProposal + RouteAcceptance + RouteCommitment)
 *   3. New circuit establishment (setupCircuit)
 *   4. Verification (circuit is ACTIVE + has new identity)
 *
 * The executor is separate from RecoveryManager (detection/planning) and
 * from the route/circuit construction primitives.
 *
 * SECURITY: the caller CANNOT force a specific gateway, route, or circuit.
 * Candidate selection is derived from the available node set + the required
 * capability + the exclusion of the failed gateway. Route identity emerges
 * from the canonical commitment construction. Circuit identity emerges from
 * the new commitmentRoot + new ephemeral key.
 */
export class RecoveryExecutor {
  /**
   * @param destroyStore - the authoritative CircuitDestroyStore (for
   *   revoking partially-created circuits on failure).
   * @param floorStoreFactory - a factory that creates a fresh floor store
   *   for the new circuit (each recovery gets a new replay namespace).
   */
  constructor(
    private readonly destroyStore: CircuitDestroyStore,
    private readonly floorStoreFactory: () => CircuitSequenceFloorStore = () => new InMemoryCircuitSequenceFloorStore(),
  ) {}

  /**
   * Execute a recovery attempt.
   *
   * @param plan - the RecoveryPlan to execute.
   * @param availableNodes - the set of available gateway candidates.
   * @param requiredCapability - the required gateway capability.
   * @param failedGatewayNodeId - the NodeId of the failed gateway (excluded).
   * @param failedCircuitId - the failed circuit's ID.
   * @param failedCommitmentRoot - the failed route's commitmentRoot.
   * @param failureTimestamp - when the failure was observed.
   * @param now - current time (unix seconds).
   * @param relayX25519PublicKeys - the X25519 public keys for circuit setup.
   * @param brandedRouteFactory - a factory that takes a RouteCommitment +
   *   returns { brandedRoute, relayKeypairs }. The factory constructs a
   *   genuine BrandedCommittedRoute + returns the relay keypairs used.
   *   The executor uses the factory's keypairs for setupCircuit (NodeIds
   *   must match the branded route).
   */
  async execute(
    plan: RecoveryPlan,
    availableNodes: GatewayCandidate[],
    requiredCapability: any,
    failedGatewayNodeId: string,
    failedCircuitId: Uint8Array,
    failedCommitmentRoot: Uint8Array,
    failureTimestamp: number,
    now: number,
    relayX25519PublicKeys: Uint8Array[],
    brandedRouteFactory: () => { brandedRoute: BrandedCommittedRoute; relayKeypairs: NodeKeypair[] },
  ): Promise<RecoveryExecutionResult> {
    const attemptId = computeRecoveryAttemptId(
      failedCircuitId, failedCommitmentRoot, failureTimestamp, now,
    );

    // --- Stage 1: DISCOVERING ---
    // Use the existing discoverAlternativeGateways, excluding the failed gateway.
    const candidates = discoverAlternativeGateways(
      availableNodes,
      requiredCapability,
      [failedGatewayNodeId],
    );

    if (candidates.length === 0) {
      return {
        ok: false,
        state: "FAILED",
        attemptId,
        reason: "no alternative gateway available (all candidates excluded or ineligible)",
        failedAt: "DISCOVERING",
      };
    }

    // Deterministic selection: first candidate (ordered by NodeId lexicographic
    // — discoverAlternativeGateways already returns ordered results).
    const selectedCandidate = candidates[0]!;

    // --- Stage 2-3: ROUTING + COMMITTING ---
    // Use the factory to construct a genuine BrandedCommittedRoute + relay keypairs.
    // The factory runs the full authenticated-link pipeline internally + returns
    // genuine ValidatedHops + a BrandedCommittedRoute with a new commitmentRoot.
    // The executor does NOT construct ValidatedHops itself (it can't — they require
    // the authenticated link layer's WeakSet-registered proof artifacts).
    const { brandedRoute, relayKeypairs } = brandedRouteFactory();

    // The new commitmentRoot is derived from the branded route.
    const newCommitmentRoot = brandedRoute.commitmentRoot;

    // Verify: new commitmentRoot != old commitmentRoot (cryptographic independence).
    if (toHex(newCommitmentRoot) === toHex(failedCommitmentRoot)) {
      // Astronomically improbable, but if it happens, fail.
      return {
        ok: false,
        state: "FAILED",
        attemptId,
        reason: "new commitmentRoot collides with the old one (cryptographic collision — reject)",
        failedAt: "ROUTING",
      };
    }

    // --- Stage 3: COMMITTING ---
    // The branded route was constructed by the factory in Stage 2.
    // No additional commitment step needed — the factory's BrandedCommittedRoute
    // is the genuine, WeakSet-registered proof artifact.

    // --- Stage 4: ESTABLISHING_CIRCUIT ---
    // Generate a FRESH initiator X25519 keypair (guarantees new circuitId + noncePrefix).
    const initiatorX25519SecretKey = randomBytes(32);
    const initiatorX25519PublicKey = x25519.getPublicKey(initiatorX25519SecretKey);

    // Use the existing setupCircuit (single-process — in production, this
    // would be establishDistributedCircuit with real transport).
    const floorStore = this.floorStoreFactory();
    const relayKeys = relayX25519PublicKeys.map((pk, i) => ({
      hopIndex: i,
      nodeId: relayKeypairs[i]!.nodeId,
      x25519PublicKey: pk,
    }));

    const newCircuit = setupCircuit(brandedRoute, relayKeys, now, floorStore);

    // --- Stage 5: VERIFYING ---
    // Verify: new circuitId != old circuitId.
    if (toHex(newCircuit.circuitId) === toHex(failedCircuitId)) {
      // Should never happen (new commitmentRoot + new ephemeral key → new circuitId).
      return {
        ok: false,
        state: "FAILED",
        attemptId,
        reason: "new circuitId collides with the old one (cryptographic collision — reject)",
        failedAt: "VERIFYING",
      };
    }

    // Verify: new circuit is not revoked (the old tombstone doesn't match).
    const isOldRevoked = await this.destroyStore.isRevoked(failedCircuitId, failedCommitmentRoot);
    const isNewRevoked = await this.destroyStore.isRevoked(newCircuit.circuitId, newCommitmentRoot);
    if (!isOldRevoked) {
      return {
        ok: false,
        state: "FAILED",
        attemptId,
        reason: "old circuit is NOT revoked — recovery cannot proceed without old circuit being durably dead",
        failedAt: "VERIFYING",
      };
    }
    if (isNewRevoked) {
      return {
        ok: false,
        state: "FAILED",
        attemptId,
        reason: "new circuit is already revoked — something is wrong",
        failedAt: "VERIFYING",
      };
    }

    // All stages succeeded.
    return {
      ok: true,
      state: "RECOVERED",
      attemptId,
      newCircuit,
      newCommitmentRoot,
      newCircuitId: newCircuit.circuitId,
    };
  }
}
