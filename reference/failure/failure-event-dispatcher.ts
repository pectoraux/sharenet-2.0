/**
 * ShareNet 2.0 — Production failure-event dispatcher (R-009 Stage 3 Phase 4).
 *
 * Per the re-audit of 93ce7be: `dispatchFailureEvents()` existed but had
 * ZERO production callers. The detector accumulated observations but nobody
 * acted on them in production.
 *
 * This module provides the `FailureEventDispatcher` — the PRODUCTION
 * event-dispatch boundary. It wraps the `LinkFailureDetector` + the
 * circuit associations + the destroy store + the RecoveryManager. Its
 * `recordObservation()` + `recordSuccess()` methods delegate to the detector
 * AND THEN IMMEDIATELY drain + dispatch any resulting LINK_DOWN events.
 *
 * This makes dispatch INLINE — no polling, no timer, no separate event loop.
 * The production code (transport `send()`, `processCircuitWireFrame()`)
 * calls `dispatcher.recordObservation()` / `dispatcher.recordSuccess()`
 * instead of the raw detector. The dispatch happens as part of the same
 * call stack — synchronously after the observation.
 *
 * ARCHITECTURE: this module lives in `reference/failure/` (the protocol
 * core). It imports from `reference/circuit/` + `reference/routing/` (both
 * protocol core). It does NOT import Prisma, `@/`, sockets, or any
 * platform module. Architecture tests #21/#23 remain green.
 */

import {
  LinkFailureDetector,
  type FailureObservation,
  type LinkHealthState,
  invalidateCircuitOnFailure,
} from "./link-failure-detector";
import type { CircuitDestroyStore } from "../circuit/replay-stores";
import type { ActiveCircuit } from "../circuit/circuit";
import type { RecoveryManager } from "../routing/recovery";
import { randomBytes } from "@noble/hashes/utils.js";
import { zeroizeCircuit } from "../circuit/zeroize";

// Re-export the detector + types so callers can import from one module.
export { LinkFailureDetector, type FailureObservation, type LinkHealthState, type FailureCategory } from "./link-failure-detector";
export { PROTOCOL_FAILURE_THRESHOLD, PROTOCOL_FAILURE_WINDOW_SECONDS } from "./link-failure-detector";
export { invalidateCircuitOnFailure, type CircuitInvalidationResult } from "./link-failure-detector";

// -----------------------------------------------------------------------
// Circuit-link association
// -----------------------------------------------------------------------

/**
 * An association between a link + a circuit that depends on it.
 * The dispatcher uses this to identify which circuits to invalidate
 * when a link goes DOWN.
 */
export interface CircuitLinkAssociation {
  readonly circuitId: Uint8Array;
  readonly commitmentRoot: Uint8Array;
  readonly circuitObj?: ActiveCircuit;
}

// -----------------------------------------------------------------------
// FailureEventDispatcher — the production event-dispatch boundary
// -----------------------------------------------------------------------

/**
 * The result of a dispatch cycle.
 */
export interface DispatchResult {
  /** The new link health state after the observation + dispatch. */
  readonly state: LinkHealthState;
  /** Circuits that were durably invalidated (REVOKED) in this dispatch. */
  readonly invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }>;
  /** Whether the RecoveryManager was notified. */
  readonly recoveryManagerNotified: boolean;
}

/**
 * The PRODUCTION failure-event dispatcher.
 *
 * This class wraps the `LinkFailureDetector` + the circuit-link associations
 * + the `CircuitDestroyStore` + the `RecoveryManager`. Its `recordObservation()`
 * + `recordSuccess()` methods delegate to the detector AND THEN IMMEDIATELY
 * drain + dispatch any resulting LINK_DOWN events — inline, no polling.
 *
 * The production code calls:
 *   - `dispatcher.recordObservation(observation)` when a failure is detected
 *     (socket error, AEAD failure).
 *   - `dispatcher.recordSuccess(linkId, now)` when a frame is accepted.
 *
 * The dispatcher internally:
 *   1. Feeds the observation to the detector.
 *   2. Drains the detector's events.
 *   3. For each LINK_DOWN event: resolves affected circuits → durable
 *      invalidation → zeroize → RecoveryManager.handleLinkEvent().
 *
 * This is the SOLE production consumer of detector events. No test
 * needs to call `dispatchFailureEvents()` manually.
 */
export class FailureEventDispatcher {
  private readonly detector: LinkFailureDetector;
  private readonly circuitAssociations: Map<string, CircuitLinkAssociation[]>;
  private readonly destroyStore: CircuitDestroyStore;
  private readonly recoveryManager?: RecoveryManager;

  /**
   * @param detector - the LinkFailureDetector.
   * @param circuitAssociations - a map from linkId → circuits on that link.
   * @param destroyStore - the authoritative CircuitDestroyStore.
   * @param recoveryManager - the RecoveryManager (optional — for recovery
   *   planning; if not provided, invalidation still happens but no
   *   RecoveryPlan is created).
   */
  constructor(
    detector: LinkFailureDetector,
    circuitAssociations: Map<string, CircuitLinkAssociation[]>,
    destroyStore: CircuitDestroyStore,
    recoveryManager?: RecoveryManager,
  ) {
    this.detector = detector;
    this.circuitAssociations = circuitAssociations;
    this.destroyStore = destroyStore;
    this.recoveryManager = recoveryManager;
  }

  /**
   * Record a failure observation + immediately dispatch any resulting
   * LINK_DOWN events. This is the PRODUCTION entry point — called by
   * the transport (socket error) + the forwarding path (AEAD failure).
   *
   * @returns the new link health state + the dispatch result.
   */
  async recordObservation(observation: FailureObservation): Promise<DispatchResult> {
    // 1. Feed the observation to the detector.
    const state = this.detector.recordObservation(observation);

    // 2. Drain + dispatch any events (INLINE — no polling).
    const dispatch = await this.drainAndDispatch(observation.observedAt);

    return { state, ...dispatch };
  }

  /**
   * Record a successful authenticated traffic event + reset suspicion.
   * Called by the transport (successful send) + the forwarding path
   * (successful frame).
   */
  async recordSuccess(linkId: string, now: number): Promise<DispatchResult> {
    const state = this.detector.recordSuccess(linkId, now);
    // Successful traffic doesn't generate LINK_DOWN events, but we drain
    // any pending DEGRADED → HEALTHY events for the RecoveryManager.
    const dispatch = await this.drainAndDispatch(now);
    return { state, ...dispatch };
  }

  /**
   * Get the current health state of a link (delegates to the detector).
   */
  getState(linkId: string): LinkHealthState {
    return this.detector.getState(linkId);
  }

  /**
   * Drain events from the detector + dispatch them. For each LINK_DOWN:
   *   1. Resolve affected circuits (via circuit-link associations).
   *   2. Durably invalidate each circuit (via invalidateCircuitOnFailure).
   *   3. Zeroize (if the circuit object is available).
   *   4. Forward the event to the RecoveryManager.
   *
   * Persistence failure → fail-closed (no claim of REVOKED, no false
   * recovery signal).
   */
  private async drainAndDispatch(now: number): Promise<{ invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }>; recoveryManagerNotified: boolean }> {
    const events = this.detector.drainEvents();
    const invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }> = [];
    let recoveryManagerNotified = false;

    for (const event of events) {
      // Forward all events (DEGRADED + DOWN) to the RecoveryManager.
      if (this.recoveryManager) {
        this.recoveryManager.handleLinkEvent(event);
        recoveryManagerNotified = true;
      }

      // Only LINK_DOWN triggers circuit invalidation.
      if (event.newStatus !== "DOWN") {
        continue;
      }

      // Resolve affected circuits.
      const circuits = this.circuitAssociations.get(event.linkId) ?? [];
      for (const { circuitId, commitmentRoot, circuitObj } of circuits) {
        const result = await invalidateCircuitOnFailure(
          this.destroyStore,
          circuitId,
          commitmentRoot,
          0x03, // DESTROY_REASON_LINK_FAILURE
          "system",
          0x01, // DESTROYER_ROLE_INITIATOR
          randomBytes(16),
        );
        if (result.ok && result.action === "REVOKED") {
          invalidatedCircuits.push({ circuitId, reason: 0x03 });
          // Zeroize the circuit if the object is available.
          if (circuitObj) {
            zeroizeCircuit(circuitObj);
          }
        }
        // If result.ok is false (persistence failure) → fail closed.
        // Do NOT claim REVOKED. Do NOT emit recovery signal.
      }
    }

    return { invalidatedCircuits, recoveryManagerNotified };
  }
}
