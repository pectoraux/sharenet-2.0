/**
 * ShareNet 2.0 — Re-exports from the failure-event-dispatcher for convenience.
 *
 * This file re-exports the FailureEventDispatcher + its types + the
 * LinkFailureDetector so tests can import from a single module.
 */

export { FailureEventDispatcher, type CircuitLinkAssociation, type DispatchResult } from "./failure-event-dispatcher";
export { LinkFailureDetector, type FailureObservation, type LinkHealthState, type FailureCategory } from "./link-failure-detector";
export { PROTOCOL_FAILURE_THRESHOLD, PROTOCOL_FAILURE_WINDOW_SECONDS } from "./link-failure-detector";
export { invalidateCircuitOnFailure, type CircuitInvalidationResult } from "./link-failure-detector";
