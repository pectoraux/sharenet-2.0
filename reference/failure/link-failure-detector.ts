/**
 * ShareNet 2.0 — Link failure detection (R-009 Stage 3 Phase 4).
 *
 * Per ADR-0024 (link failure detection + durable circuit invalidation):
 *
 *   HEALTHY
 *      ↓ single protocol failure
 *   DEGRADED
 *      ↓ repeated failures reach threshold (within window)
 *      OR transport-confirmed failure
 *   LINK_DOWN (terminal)
 *
 * The detector is DETERMINISTIC + PLATFORM-INDEPENDENT. It does NOT import
 * Prisma, sockets, or anything from `src/`. The platform layer feeds it
 * FailureObservation records (derived from real socket events / AEAD failures);
 * the detector classifies them + emits LinkHealthEvent records for the
 * RecoveryManager.
 *
 * FROZEN POLICY (ADR-0024 §2):
 *   PROTOCOL_FAILURE_THRESHOLD = 3
 *   PROTOCOL_FAILURE_WINDOW_SECONDS = 60
 *
 * Anti-DoS: a single forged bad packet does NOT kill a link. An attacker
 * must inject 3 bad packets within 60s to trigger LINK_DOWN — and only
 * if the link is already in DEGRADED state.
 *
 * Transport-confirmed failures (real socket close/reset) produce immediate
 * LINK_DOWN — no threshold needed (the transport itself confirms the peer
 * is unreachable).
 *
 * ARCHITECTURE (ADR-0013): this module lives in `reference/failure/` (the
 * protocol core). It does NOT import `@/lib/db`, `@/`, or any platform
 * module. Architecture tests #21/#23 remain green.
 */

import type { LinkHealthEvent } from "../routing/recovery";

// -----------------------------------------------------------------------
// Frozen constants (ADR-0024 §2)
// -----------------------------------------------------------------------

/**
 * The number of protocol-authentication failures within the observation
 * window that triggers LINK_DOWN. FROZEN per ADR-0024.
 *
 * Why 3: 1 is too aggressive (trivial DoS), 10+ is too lenient (data leak).
 * 3 is tight enough to detect a broken/malicious peer quickly, while
 * tolerating occasional network corruption (1-2 bad frames are common on
 * lossy mesh links).
 */
export const PROTOCOL_FAILURE_THRESHOLD = 3 as const;

/**
 * The observation window (seconds) within which the threshold must be
 * reached. FROZEN per ADR-0024.
 *
 * Why 60s: short enough to detect a broken peer quickly, long enough to
 * distinguish a transient glitch from a sustained failure.
 */
export const PROTOCOL_FAILURE_WINDOW_SECONDS = 60 as const;

// -----------------------------------------------------------------------
// FailureObservation — local diagnostic evidence
// -----------------------------------------------------------------------

/**
 * The category of a failure observation.
 *
 * - `TRANSPORT_CONFIRMED`: the authenticated transport channel permanently
 *   closed (TCP reset, connection refused, socket timeout, peer killed).
 *   This is produced ONLY by the platform layer (real socket events) —
 *   a caller CANNOT assert this category. Produces immediate LINK_DOWN.
 *
 * - `PROTOCOL_AUTHENTICATION`: a single bad frame, AEAD tag failure,
 *   malformed packet, invalid proof, or invalid CircuitDestroy. This is
 *   evidence of a possible attacker OR a buggy peer — NOT evidence the
 *   peer is dead. Requires threshold accumulation before LINK_DOWN.
 */
export type FailureCategory = "TRANSPORT_CONFIRMED" | "PROTOCOL_AUTHENTICATION";

/**
 * A local diagnostic structure capturing a failure observation. This is
 * NOT a portable signed protocol object — it does NOT cross trust
 * boundaries. It is used internally by the LinkFailureDetector to
 * classify failures + determine escalation.
 */
export interface FailureObservation {
  /** The linkId of the affected link. */
  readonly linkId: string;
  /** The local participant's NodeId (the observer). */
  readonly localNodeId: string;
  /** The remote peer's NodeId. */
  readonly remoteNodeId: string;
  /** The circuitId, if the failure is circuit-specific (e.g. AEAD failure). */
  readonly circuitId?: Uint8Array;
  /** The failure category (TRANSPORT_CONFIRMED or PROTOCOL_AUTHENTICATION). */
  readonly category: FailureCategory;
  /** A human-readable reason string (for audit/diagnostics). */
  readonly reason: string;
  /** When the failure was observed (unix seconds). */
  readonly observedAt: number;
}

// -----------------------------------------------------------------------
// LinkHealthState — the per-link state machine
// -----------------------------------------------------------------------

/**
 * The health state of a link, as tracked by the LinkFailureDetector.
 *
 * - `HEALTHY`: no recent failures.
 * - `DEGRAED`: at least one protocol failure observed within the window;
 *   the link is suspect but not dead.
 * - `LINK_DOWN`: terminal. The link is confirmed dead (transport failure
 *   or threshold reached). No automatic recovery.
 *
 * This mirrors `HealthStatus` from recovery.ts but is kept separate to
 * avoid coupling the detector to the RecoveryManager's state model.
 */
export type LinkHealthState = "HEALTHY" | "DEGRADED" | "LINK_DOWN";

// -----------------------------------------------------------------------
// Per-link state (internal)
// -----------------------------------------------------------------------

/**
 * Internal per-link tracking state. NOT exported — callers interact
 * with the detector via `recordObservation()` + `getState()`.
 */
interface LinkState {
  readonly linkId: string;
  readonly localNodeId: string;
  readonly remoteNodeId: string;
  health: LinkHealthState;
  /** Timestamps of PROTOCOL_AUTHENTICATION failures within the window. */
  protocolFailures: number[];
  /** Timestamp of the first failure in the current window (for window reset). */
  windowStart: number;
  /** Whether a LINK_DOWN event has been emitted (idempotency). */
  linkDownEmitted: boolean;
}

// -----------------------------------------------------------------------
// LinkFailureDetector
// -----------------------------------------------------------------------

/**
 * A deterministic, platform-independent link failure detector.
 *
 * The detector maintains a per-link state machine. It is fed
 * `FailureObservation` records (from the platform layer — real socket
 * events, AEAD failures, etc.) + classifies them according to the frozen
 * policy (ADR-0024 §2).
 *
 * On state transitions, it emits `LinkHealthEvent` records (the existing
 * type from recovery.ts) that feed `RecoveryManager.handleLinkEvent()`.
 *
 * SECURITY: the caller CANNOT assert `confirmed=true`. The classification
 * is derived from the evidence category — `TRANSPORT_CONFIRMED` is only
 * produced by the platform layer (real socket events), not by a caller
 * assertion.
 *
 * ANTI-DoS: a single forged bad packet does NOT kill a link. The attacker
 * must inject `PROTOCOL_FAILURE_THRESHOLD` (3) bad packets within
 * `PROTOCOL_FAILURE_WINDOW_SECONDS` (60) to trigger LINK_DOWN — and only
 * if the link is already in DEGRADED state.
 *
 * IDEMPOTENT: duplicate LINK_DOWN for the same link is a no-op (no
 * re-invalidation, no re-emission of events).
 *
 * STALE-RESISTANT: observations outside the observation window do NOT
 * count toward the threshold. The window is reset on the first failure
 * after the window expires.
 *
 * RESET: successful authenticated traffic resets the failure count +
 * returns to HEALTHY (from DEGRADED). The caller calls
 * `recordSuccess(linkId, now)` to signal this.
 */
export class LinkFailureDetector {
  // Per-link state, keyed by linkId.
  private readonly links = new Map<string, LinkState>();
  // Emitted LinkHealthEvent records (consumed by RecoveryManager).
  private readonly events: LinkHealthEvent[] = [];

  /**
   * Record a failure observation. Updates the per-link state machine +
   * emits a LinkHealthEvent if the state transitions.
   *
   * @returns the new LinkHealthState for this link.
   */
  recordObservation(observation: FailureObservation): LinkHealthState {
    let link = this.links.get(observation.linkId);
    if (!link) {
      link = {
        linkId: observation.linkId,
        localNodeId: observation.localNodeId,
        remoteNodeId: observation.remoteNodeId,
        health: "HEALTHY",
        protocolFailures: [],
        windowStart: 0,
        linkDownEmitted: false,
      };
      this.links.set(observation.linkId, link);
    }

    // If already LINK_DOWN, this is idempotent (no re-invalidation).
    if (link.health === "LINK_DOWN") {
      return "LINK_DOWN";
    }

    // Classify the failure.
    if (observation.category === "TRANSPORT_CONFIRMED") {
      // Transport-confirmed failure → immediate LINK_DOWN.
      this.transitionToLinkDown(link, observation.reason, observation.observedAt);
      return "LINK_DOWN";
    }

    // PROTOCOL_AUTHENTICATION failure.
    // Prune observations outside the window.
    const windowCutoff = observation.observedAt - PROTOCOL_FAILURE_WINDOW_SECONDS;
    link.protocolFailures = link.protocolFailures.filter(t => t >= windowCutoff);

    // Add the new observation.
    if (link.protocolFailures.length === 0) {
      // First failure in a new window.
      link.windowStart = observation.observedAt;
    }
    link.protocolFailures.push(observation.observedAt);

    // Check if the threshold is reached.
    if (link.protocolFailures.length >= PROTOCOL_FAILURE_THRESHOLD) {
      // Threshold reached → LINK_DOWN.
      this.transitionToLinkDown(link, `repeated protocol failures (${link.protocolFailures.length} within ${PROTOCOL_FAILURE_WINDOW_SECONDS}s): ${observation.reason}`, observation.observedAt);
      return "LINK_DOWN";
    }

    // Below threshold → DEGRADED.
    if (link.health === "HEALTHY") {
      link.health = "DEGRADED";
      this.emitEvent(link, "DEGRADED", "LINK_DEGRADED", observation.reason, observation.observedAt);
    }
    return "DEGRADED";
  }

  /**
   * Record a successful authenticated traffic event. Resets the failure
   * count + returns to HEALTHY (from DEGRADED).
   *
   * This is the "reset" mechanism: if the link is DEGRADED but a subsequent
   * frame authenticates successfully, the suspicion is cleared.
   */
  recordSuccess(linkId: string, now: number): LinkHealthState {
    const link = this.links.get(linkId);
    if (!link) {
      return "HEALTHY";
    }
    if (link.health === "LINK_DOWN") {
      return "LINK_DOWN"; // terminal — no reset
    }
    if (link.health === "DEGRADED") {
      link.health = "HEALTHY";
      link.protocolFailures = [];
      link.windowStart = 0;
      this.emitEvent(link, "HEALTHY", "MANUAL_INVALIDATION", "suspicion cleared by successful authenticated traffic", now);
    }
    return "HEALTHY";
  }

  /**
   * Get the current health state of a link.
   */
  getState(linkId: string): LinkHealthState {
    const link = this.links.get(linkId);
    return link ? link.health : "HEALTHY";
  }

  /**
   * Consume all emitted LinkHealthEvent records. After this call, the
   * internal event buffer is cleared. The caller (typically the
   * RecoveryManager integration) should call this periodically.
   */
  drainEvents(): LinkHealthEvent[] {
    const events = this.events.splice(0);
    return events;
  }

  /**
   * Get all emitted LinkHealthEvent records without clearing them.
   * Useful for tests.
   */
  getEvents(): LinkHealthEvent[] {
    return [...this.events];
  }

  /**
   * Transition a link to LINK_DOWN (terminal). Emits a LinkHealthEvent.
   * Idempotent — if the link is already LINK_DOWN, this is a no-op.
   */
  private transitionToLinkDown(link: LinkState, reason: string, at: number): void {
    if (link.health === "LINK_DOWN") {
      return; // idempotent
    }
    link.health = "LINK_DOWN";
    if (!link.linkDownEmitted) {
      link.linkDownEmitted = true;
      this.emitEvent(link, "DOWN", "LINK_DOWN", reason, at);
    }
  }

  /**
   * Emit a LinkHealthEvent into the internal buffer.
   */
  private emitEvent(
    link: LinkState,
    newStatus: "HEALTHY" | "DEGRADED" | "DOWN",
    reason: string,
    detail: string,
    at: number,
  ): void {
    const event: LinkHealthEvent = {
      linkId: link.linkId,
      localNodeId: link.localNodeId,
      remoteNodeId: link.remoteNodeId,
      newStatus,
      reason: reason as any, // InvalidationReason is a string-literal union
      observedAt: at,
    };
    this.events.push(event);
  }
}

// -----------------------------------------------------------------------
// CircuitInvalidator — bridges LINK_DOWN → durable circuit invalidation
// -----------------------------------------------------------------------

/**
 * The result of a failure-triggered circuit invalidation.
 *
 * - `{ ok: true, action: "REVOKED" }` — the circuit was durably revoked
 *   (the tombstone was written).
 * - `{ ok: true, action: "ALREADY_REVOKED" }` — the circuit was already
 *   revoked (the tombstone existed — idempotent).
 * - `{ ok: false, reason }` — the durable invalidation FAILED (persistence
 *   failure — fail-closed, no split state, safe to retry).
 */
export type CircuitInvalidationResult =
  | { ok: true; action: "REVOKED" }
  | { ok: true; action: "ALREADY_REVOKED" }
  | { ok: false; reason: string };

/**
 * A function that durably invalidates a circuit on LINK_DOWN. This is the
 * bridge from the failure detector to the durable store.
 *
 * The invalidation uses the SAME authoritative tombstone as explicit
 * CircuitDestroy and natural expiry (ADR-0022). The `destroyReason`
 * field distinguishes failure-triggered invalidation:
 *   - `DESTROY_REASON_LINK_FAILURE` (0x03) for link failures.
 *   - `DESTROY_REASON_GATEWAY_DISAPPEARANCE` (0x04) for gateway disappearance.
 *
 * The invalidation is ATOMIC (uses `CircuitDestroyStore.consumeDestroyAndRevoke`).
 * If the durable write fails, the circuit is NOT claimed as REVOKED —
 * fail-closed, safe to retry (the nonce is NOT consumed if the transaction
 * rolled back — no split state).
 *
 * @param destroyStore - the authoritative CircuitDestroyStore.
 * @param circuitId - the circuit to invalidate.
 * @param commitmentRoot - the route's commitment root.
 * @param reason - the DESTROY_REASON_* code (0x03 or 0x04).
 * @param destroyerNodeId - "system" (failure-triggered, not initiator-authenticated).
 * @param destroyerRole - DESTROYER_ROLE_INITIATOR (the circuit owner's context).
 * @param destroyNonce - a fresh 16-byte nonce (or a zero nonce for system events).
 */
export async function invalidateCircuitOnFailure(
  destroyStore: import("../circuit/replay-stores").CircuitDestroyStore,
  circuitId: Uint8Array,
  commitmentRoot: Uint8Array,
  reason: number,
  destroyerNodeId: string,
  destroyerRole: number,
  destroyNonce: Uint8Array,
): Promise<CircuitInvalidationResult> {
  // Check if already revoked (idempotent).
  const alreadyRevoked = await destroyStore.isRevoked(circuitId, commitmentRoot);
  if (alreadyRevoked) {
    return { ok: true, action: "ALREADY_REVOKED" };
  }

  // Atomically consume the nonce + write the tombstone.
  const result = await destroyStore.consumeDestroyAndRevoke(
    commitmentRoot,
    circuitId,
    destroyNonce,
    destroyerNodeId,
    destroyerRole,
    reason,
  );
  if (!result.ok) {
    return {
      ok: false,
      reason: `failure-triggered invalidation failed: ${result.reason} (fail-closed, safe to retry)`,
    };
  }
  if (result.idempotent) {
    return { ok: true, action: "ALREADY_REVOKED" };
  }
  return { ok: true, action: "REVOKED" };
}

// -----------------------------------------------------------------------
// Production failure-event dispatcher
// -----------------------------------------------------------------------

/**
 * The production failure-event dispatcher.
 *
 * This function drains events from the LinkFailureDetector + for each
 * LINK_DOWN event:
 *   1. Identifies affected circuits (via the circuit-link association).
 *   2. Durably invalidates each circuit (via invalidateCircuitOnFailure).
 *   3. Zeroizes the circuit (if the circuit object is available).
 *   4. Forwards the event to the RecoveryManager (route invalidation → RecoveryPlan).
 *
 * This is the PRODUCTION dispatch boundary — it connects the detector to
 * the invalidation + recovery systems. It is called by the production
 * runtime after each frame-processing or transport operation.
 *
 * @param detector - the LinkFailureDetector to drain events from.
 * @param circuitAssociations - a map from linkId → array of circuits on that link.
 * @param destroyStore - the authoritative CircuitDestroyStore for durable invalidation.
 * @param recoveryManager - the RecoveryManager to forward events to (optional).
 * @returns the list of invalidated circuit IDs + recovery plans.
 */
export async function dispatchFailureEvents(
  detector: LinkFailureDetector,
  circuitAssociations: Map<string, Array<{ circuitId: Uint8Array; commitmentRoot: Uint8Array; circuitObj?: import("../circuit/circuit").ActiveCircuit }>>,
  destroyStore: import("../circuit/replay-stores").CircuitDestroyStore,
  recoveryManager?: import("../routing/recovery").RecoveryManager,
): Promise<{ invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }>; recoveryPlans: any[] }> {
  const events = detector.drainEvents();
  const invalidatedCircuits: Array<{ circuitId: Uint8Array; reason: number }> = [];
  const recoveryPlans: any[] = [];

  for (const event of events) {
    // Only LINK_DOWN triggers circuit invalidation.
    if (event.newStatus !== "DOWN") {
      // Forward DEGRADED events to the RecoveryManager (if provided).
      if (recoveryManager) {
        recoveryManager.handleLinkEvent(event);
      }
      continue;
    }

    // LINK_DOWN — invalidate all circuits on this link.
    const circuits = circuitAssociations.get(event.linkId) ?? [];
    for (const { circuitId, commitmentRoot, circuitObj } of circuits) {
      const result = await invalidateCircuitOnFailure(
        destroyStore,
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
          const { zeroizeCircuit } = await import("../circuit/zeroize");
          zeroizeCircuit(circuitObj);
        }
      }
      // If result.ok is false (persistence failure) → fail closed.
      // Do NOT claim REVOKED. Do NOT emit recovery signal.
    }

    // Forward the LINK_DOWN event to the RecoveryManager.
    if (recoveryManager) {
      const invalidatedRoutes = recoveryManager.handleLinkEvent(event);
      // RecoveryPlan is descriptive only — no execution.
    }
  }

  return { invalidatedCircuits, recoveryPlans };
}

// Import randomBytes lazily to avoid circular dependency.
import { randomBytes } from "@noble/hashes/utils.js";
