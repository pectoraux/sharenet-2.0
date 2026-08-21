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
import type { RecoveryManager, GatewayCandidate, LinkHealthEvent } from "../routing/recovery";
import { createRecoveryPlan } from "../routing/recovery";
import type { RecoveryExecutor, AuthenticatedTopologyProvider, RecoveryExecutionResult } from "../routing/recovery-executor";
import type { NodeCapability } from "../routing/service-negotiation";
import { randomBytes } from "@noble/hashes/utils.js";
import { zeroizeCircuit } from "../circuit/zeroize";
import { deriveRouteId } from "../routing/route";

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
// Recovery outcome — the OBSERVABLE result of a recovery attempt
// -----------------------------------------------------------------------

/**
 * The observable outcome of a single recovery attempt, bound to the failed
 * circuit that triggered it.
 *
 * This is the AUTHORITATIVE recovery result contract. The dispatcher MUST
 * populate exactly one `kind` per recovery attempt. Nothing is silently
 * swallowed.
 *
 *   RECOVERED       — the new circuit is ACTIVE with a fresh cryptographic
 *                     identity. The old tombstone remains REVOKED.
 *   FAILED          — the executor returned a typed failure (no candidate,
 *                     route verification failed, old circuit not revoked,
 *                     identity collision, etc.). `failedAt` identifies the
 *                     recovery stage.
 *   EXECUTION_ERROR — the executor THREW an exception. The error message is
 *                     captured (not swallowed). This is distinct from FAILED
 *                     because it indicates a runtime fault, not a protocol
 *                     rejection.
 */
export type RecoveryOutcome =
  | {
      readonly kind: "RECOVERED";
      readonly failedCircuitId: Uint8Array;
      readonly newCircuitId: Uint8Array;
      readonly newCommitmentRoot: Uint8Array;
      readonly attemptIdHex: string;
    }
  | {
      readonly kind: "FAILED";
      readonly failedCircuitId: Uint8Array;
      readonly attemptIdHex: string;
      readonly reason: string;
      readonly failedAt: string;
    }
  | {
      readonly kind: "EXECUTION_ERROR";
      readonly failedCircuitId: Uint8Array;
      readonly errorMessage: string;
    };

// -----------------------------------------------------------------------
// FailureEventDispatcher — the production event-dispatch boundary
// -----------------------------------------------------------------------

/**
 * The result of a dispatch cycle.
 *
 * `recoveryOutcomes` is the OBSERVABLE contract for recovery: every recovery
 * attempt triggered by this dispatch produces exactly one entry. The caller
 * can inspect success, failure, and execution errors without inspecting
 * dispatcher internals. Nothing is silently swallowed.
 */
export interface DispatchResult {
  /** The new link health state after the observation + dispatch. */
  readonly state: LinkHealthState;
  /** Circuits that were durably invalidated (REVOKED) in this dispatch. */
  readonly invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }>;
  /** Whether the RecoveryManager was notified. */
  readonly recoveryManagerNotified: boolean;
  /**
   * The observable recovery outcomes for this dispatch. One entry per
   * recovery attempt. Empty when no recovery was attempted (no executor
   * wired, or no circuits were durably revoked).
   */
  readonly recoveryOutcomes: readonly RecoveryOutcome[];
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
  private readonly recoveryExecutor?: RecoveryExecutor;
  private readonly authenticatedTopologyProvider?: AuthenticatedTopologyProvider;
  private readonly gatewayCandidates?: GatewayCandidate[];
  private readonly requiredCapability?: NodeCapability;
  private readonly relayX25519PublicKeys?: Uint8Array[];

  /**
   * Re-entrancy guard. While the dispatch loop is running, any new
   * observations (e.g. from a recovery execution that triggers a transport
   * failure) are ENQUEUED into `pendingObservations`. The dispatch loop
   * drains the queue iteratively — NOT recursively. There is exactly ONE
   * dispatch owner at a time; when it finishes, if the queue is non-empty,
   * it continues draining in the same call stack (no new stack frame per
   * queued observation).
   *
   * This is a BOUNDED queue/drain mechanism:
   *   - No recursive `drainAndDispatch()` calls (the prior implementation
   *     recursively called itself in the finally block — unbounded).
   *   - No `setTimeout` polling, no interval polling.
   *   - No unbounded promise chaining.
   *   - No fire-and-forget recovery (recovery execution is awaited).
   *   - No swallowed errors.
   *
   * Per Subtask 1 §8: the frozen ordering (invalidation → zeroize →
   * recovery signal) is preserved. Re-entrant observations are queued —
   * not nested.
   */
  private dispatching = false;
  private readonly pendingObservations: FailureObservation[] = [];
  /**
   * BOUND on the number of queued re-entrant observations. If exceeded,
   * further re-entrant observations are REJECTED (the dispatcher is
   * overloaded — fail-closed to prevent unbounded queue growth). This is
   * a defensive DoS guard, not a protocol limit.
   */
  private static readonly MAX_QUEUED_OBSERVATIONS = 256;

  /**
   * @param detector - the LinkFailureDetector.
   * @param circuitAssociations - a map from linkId → circuits on that link.
   * @param destroyStore - the authoritative CircuitDestroyStore.
   * @param recoveryManager - OPTIONAL: the RecoveryManager. When absent,
   *   invalidation still happens but no recovery is planned or executed.
   * @param recoveryExecutor - OPTIONAL: the RecoveryExecutor. When provided,
   *   the dispatcher AUTOMATICALLY triggers recovery after durable invalidation
   *   + zeroize. REQUIRE: authenticatedTopologyProvider MUST also be provided
   *   (fail-closed if absent).
   * @param authenticatedTopologyProvider - REQUIRED when recoveryExecutor is
   *   provided. This is the AUTHENTICATED boundary for constructing replacement
   *   routes. If recoveryExecutor is provided but this is absent, the
   *   constructor THROWS (fail-closed — no recovery without authenticated
   *   topology capability).
   * @param gatewayCandidates - gateway candidates for recovery.
   * @param requiredCapability - the required gateway capability (typed).
   * @param relayX25519PublicKeys - relay X25519 public keys for circuit setup.
   */
  constructor(
    detector: LinkFailureDetector,
    circuitAssociations: Map<string, CircuitLinkAssociation[]>,
    destroyStore: CircuitDestroyStore,
    recoveryManager?: RecoveryManager,
    recoveryExecutor?: RecoveryExecutor,
    authenticatedTopologyProvider?: AuthenticatedTopologyProvider,
    gatewayCandidates?: GatewayCandidate[],
    requiredCapability?: NodeCapability,
    relayX25519PublicKeys?: Uint8Array[],
  ) {
    this.detector = detector;
    this.circuitAssociations = circuitAssociations;
    this.destroyStore = destroyStore;
    this.recoveryManager = recoveryManager;
    this.recoveryExecutor = recoveryExecutor;
    this.authenticatedTopologyProvider = authenticatedTopologyProvider;
    this.gatewayCandidates = gatewayCandidates;
    this.requiredCapability = requiredCapability;
    this.relayX25519PublicKeys = relayX25519PublicKeys;

    // FAIL-CLOSED: if recovery execution is enabled, the authenticated topology
    // capability MUST be present. No fallback, no `any`, no optional bypass.
    if (recoveryExecutor && !authenticatedTopologyProvider) {
      throw new Error(
        "ARCHITECTURE VIOLATION: FailureEventDispatcher constructed with recoveryExecutor " +
        "but without authenticatedTopologyProvider. Automatic recovery requires a genuine " +
        "authenticated topology capability — no fallback is permitted."
      );
    }
    if (recoveryExecutor && !requiredCapability) {
      throw new Error(
        "ARCHITECTURE VIOLATION: FailureEventDispatcher constructed with recoveryExecutor " +
        "but without requiredCapability. The required gateway capability must be explicitly " +
        "specified — no `any` default is permitted."
      );
    }
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

    // 2. If we are already dispatching (re-entrant call from inside a recovery
    //    execution), ENQUEUE the observation. The current dispatch owner will
    //    drain it iteratively — NOT recursively. The caller gets a minimal
    //    DispatchResult (the observation was accepted; its effects will be
    //    processed by the current dispatch cycle).
    if (this.dispatching) {
      if (this.pendingObservations.length >= FailureEventDispatcher.MAX_QUEUED_OBSERVATIONS) {
        // Fail-closed: the queue is full. The dispatcher is overloaded.
        // Drop the observation + return a result indicating overload.
        // (This is a defensive DoS guard; in normal operation the queue
        // never exceeds a handful of entries.)
        return {
          state,
          invalidatedCircuits: [],
          recoveryManagerNotified: false,
          recoveryOutcomes: [{
            kind: "EXECUTION_ERROR",
            failedCircuitId: observation.circuitId ?? new Uint8Array(0),
            errorMessage: "dispatcher queue full — re-entrant observation dropped (MAX_QUEUED_OBSERVATIONS exceeded)",
          }],
        };
      }
      this.pendingObservations.push(observation);
      return {
        state,
        invalidatedCircuits: [],
        recoveryManagerNotified: false,
        recoveryOutcomes: [],
      };
    }

    // 3. This caller is the dispatch owner. Run the bounded drain loop.
    //    The loop processes the current events + any re-entrant observations
    //    enqueued during processing — iteratively, not recursively.
    const dispatch = await this.runDispatchLoop(observation.observedAt);

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
    // Re-entrancy guard: recordSuccess is not expected to re-enter, but
    // we apply the same guard for safety.
    if (this.dispatching) {
      return {
        state,
        invalidatedCircuits: [],
        recoveryManagerNotified: false,
        recoveryOutcomes: [],
      };
    }
    const dispatch = await this.runDispatchLoop(now);
    return { state, ...dispatch };
  }

  /**
   * Get the current health state of a link (delegates to the detector).
   */
  getState(linkId: string): LinkHealthState {
    return this.detector.getState(linkId);
  }

  /**
   * The BOUNDED dispatch loop. This is the SOLE dispatch owner. It:
   *   1. Sets the `dispatching` guard.
   *   2. Processes the current batch of detector events.
   *   3. Drains the `pendingObservations` queue ITERATIVELY (NOT recursively):
   *      while the queue is non-empty, feed each queued observation to the
   *      detector + process the resulting events. This is a `while` loop,
   *      not a recursive call.
   *   4. Clears the `dispatching` guard + returns.
   *
   * This is BOUNDED: the loop terminates when the queue is empty. Each
   * iteration processes exactly one observation's worth of events. The
   * queue cannot grow unboundedly because:
   *   - Each re-entrant observation is one queue entry.
   *   - `recordObservation()` enqueues at most one entry per call.
   *   - The MAX_QUEUED_OBSERVATIONS guard rejects excess entries.
   *
   * Ordering is CRITICAL (ADR-0025 §6):
   *   durable invalidation → zeroize → recovery signal.
   * RecoveryManager MUST NOT observe a circuit as eligible for recovery
   * before the old circuit has durably entered terminal state + its secrets
   * have been zeroized. Persistence failure → fail-closed (no recovery).
   */
  private async runDispatchLoop(now: number): Promise<{ invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }>; recoveryManagerNotified: boolean; recoveryOutcomes: RecoveryOutcome[] }> {
    this.dispatching = true;
    const recoveryOutcomes: RecoveryOutcome[] = [];
    const invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }> = [];
    let recoveryManagerNotified = false;

    try {
      // Process the initial batch of detector events (from the observation
      // that triggered this dispatch cycle).
      await this.processEventsBatch(now, invalidatedCircuits, recoveryOutcomes, () => recoveryManagerNotified, (v: boolean) => { recoveryManagerNotified = recoveryManagerNotified || v; });

      // Iteratively drain the re-entrant observation queue. NO RECURSION.
      // Each iteration: take one observation from the queue, feed it to the
      // detector, process the resulting events. Continue until the queue
      // is empty. This is a `while` loop — the dispatch owner remains the
      // same call stack frame throughout.
      let safetyCounter = 0;
      while (this.pendingObservations.length > 0) {
        // Defensive bound: if we've processed more iterations than
        // MAX_QUEUED_OBSERVATIONS, something is generating observations
        // faster than we can drain them. Break to prevent an infinite loop.
        // (The MAX_QUEUED_OBSERVATIONS cap on enqueue also bounds this.)
        if (safetyCounter++ > FailureEventDispatcher.MAX_QUEUED_OBSERVATIONS) {
          break;
        }
        const obs = this.pendingObservations.shift()!;
        this.detector.recordObservation(obs);
        await this.processEventsBatch(
          now,
          invalidatedCircuits,
          recoveryOutcomes,
          () => recoveryManagerNotified,
          (v: boolean) => { recoveryManagerNotified = recoveryManagerNotified || v; },
        );
      }
    } finally {
      this.dispatching = false;
    }

    return { invalidatedCircuits, recoveryManagerNotified, recoveryOutcomes };
  }

  /**
   * Process one batch of detector events. For each LINK_DOWN:
   *   1. Resolve affected circuits (via circuit-link associations).
   *   2. Durably invalidate each circuit (via invalidateCircuitOnFailure).
   *   3. Zeroize (if the circuit object is available).
   *   4. ONLY THEN forward the event to the RecoveryManager + trigger recovery.
   *
   * This method does NOT loop. It processes exactly the events currently
   * in the detector's drain queue. Re-entrant observations enqueued during
   * processing are handled by the caller's `while` loop in `runDispatchLoop`.
   */
  private async processEventsBatch(
    now: number,
    invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }>,
    recoveryOutcomes: RecoveryOutcome[],
    getNotified: () => boolean,
    setNotified: (v: boolean) => void,
  ): Promise<void> {
    const events = this.detector.drainEvents();

    for (const event of events) {
      // Only LINK_DOWN triggers circuit invalidation + recovery.
      if (event.newStatus !== "DOWN") {
        // Forward DEGRADED events to RecoveryManager (no invalidation).
        if (this.recoveryManager) {
          this.recoveryManager.handleLinkEvent(event);
          setNotified(true);
        }
        continue;
      }

      // --- Step 1: Durable invalidation ---
      const circuits = this.circuitAssociations.get(event.linkId) ?? [];
      const successfullyRevoked: Array<{ circuitId: Uint8Array; commitmentRoot: Uint8Array }> = [];
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
        if (result.ok && (result.action === "REVOKED" || result.action === "ALREADY_REVOKED")) {
          successfullyRevoked.push({ circuitId, commitmentRoot });
          // --- Step 2: Zeroize (AFTER durable tombstone confirmed) ---
          if (circuitObj) {
            zeroizeCircuit(circuitObj);
          }
          if (result.action === "REVOKED") {
            invalidatedCircuits.push({ circuitId, reason: 0x03 });
          }
        }
        // Persistence failure → fail closed. Do NOT claim REVOKED. Do NOT zeroize.
        // Do NOT emit recovery signal for this circuit.
      }

      // --- Step 3: Recovery signal (AFTER durable invalidation + zeroize) ---
      // Only notify RecoveryManager if ALL affected circuits were durably revoked.
      if (successfullyRevoked.length === circuits.length && this.recoveryManager) {
        this.recoveryManager.handleLinkEvent(event);
        setNotified(true);
        // --- Step 4: Trigger circuit-specific recovery execution ---
        // Recovery is bound to EACH exact failed circuit — NOT the entire
        // invalidated-route set. Each circuit gets its own RecoveryPlan
        // identifying its own failedCircuitId + failedCommitmentRoot.
        if (this.recoveryExecutor && this.authenticatedTopologyProvider && this.requiredCapability) {
          for (const { circuitId, commitmentRoot } of successfullyRevoked) {
            // Create a CIRCUIT-SPECIFIC RecoveryPlan for THIS exact failed circuit.
            // The plan uses the failed circuit's routeId — derived via the
            // CANONICAL deriveRouteId(commitmentRoot) function. NOT an inline
            // string reconstruction (avoids drift from the frozen derivation).
            const failedRouteId = deriveRouteId(commitmentRoot);
            const plan = createRecoveryPlan(
              [failedRouteId], // circuit-specific — only THIS circuit's route
              "LINK_DOWN",
              this.gatewayCandidates ?? [],
              this.requiredCapability,
              [event.remoteNodeId], // exclude the failed gateway
            );
            // AWAIT recovery execution — do NOT fire-and-forget.
            // The result is OBSERVABLE via recoveryOutcomes (not swallowed).
            // Durable state persistence is Subtask 2; for now, the outcome
            // is returned synchronously in the DispatchResult.
            const outcome = await this.executeRecoverySafely(
              plan,
              circuitId,
              commitmentRoot,
              event,
              now,
            );
            recoveryOutcomes.push(outcome);
          }
        }
      }
    }
  }

  /**
   * Execute a single recovery attempt + translate the result into an
   * OBSERVABLE RecoveryOutcome. Executor exceptions are caught + translated
   * to EXECUTION_ERROR (not silently swallowed). Typed failures are
   * translated to FAILED. Success is translated to RECOVERED.
   *
   * This is the SOLE boundary between the executor + the dispatch result.
   * No recovery result is ever discarded.
   */
  private async executeRecoverySafely(
    plan: import("../routing/recovery").RecoveryPlan,
    circuitId: Uint8Array,
    commitmentRoot: Uint8Array,
    event: LinkHealthEvent,
    now: number,
  ): Promise<RecoveryOutcome> {
    // We must cast away the optionality for the executor/provider/capability
    // because TypeScript cannot narrow through the closure. The caller
    // (drainAndDispatch) already verified all three are present.
    const executor = this.recoveryExecutor!;
    const provider = this.authenticatedTopologyProvider!;
    const capability = this.requiredCapability!;
    try {
      const result: RecoveryExecutionResult = await executor.execute(
        plan,
        this.gatewayCandidates ?? [],
        capability,
        event.remoteNodeId,
        circuitId,
        commitmentRoot,
        event.observedAt,
        now,
        this.relayX25519PublicKeys ?? [],
        provider,
      );
      if (result.ok) {
        return {
          kind: "RECOVERED",
          failedCircuitId: circuitId,
          newCircuitId: result.newCircuitId,
          newCommitmentRoot: result.newCommitmentRoot,
          attemptIdHex: result.attemptId.idHex,
        };
      }
      return {
        kind: "FAILED",
        failedCircuitId: circuitId,
        attemptIdHex: result.attemptId.idHex,
        reason: result.reason,
        failedAt: result.failedAt,
      };
    } catch (e) {
      // Executor threw — OBSERVABLE (not swallowed). Distinct from FAILED
      // because this is a runtime fault, not a protocol rejection.
      return {
        kind: "EXECUTION_ERROR",
        failedCircuitId: circuitId,
        errorMessage: e instanceof Error ? e.message : String(e),
      };
    }
  }
}
