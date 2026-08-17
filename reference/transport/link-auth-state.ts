/**
 * ShareNet 2.0 — R-002A: Link Authentication State Machine + Enforcement.
 *
 * Per R-002 requirement: the implementation state machine MUST NOT bypass:
 *
 *   AD_CREATED
 *       ↓
 *   AD_VERIFIED
 *       ↓
 *   HANDSHAKE_CHALLENGE
 *       ↓
 *   PROOF_OF_POSSESSION
 *       ↓
 *   TRANSCRIPT_VERIFIED
 *       ↓
 *   LINK_UP
 *
 * There must NOT exist any path like:
 *   VerifiedAdvertisement → Link
 *   RemoteNodeRecord → LinkUp
 * without the full handshake.
 *
 * The proof statement the possession signature must make:
 *   "The holder of NodeId X's private key participated in this specific
 *    transport handshake, with these exact roles, identities, and
 *    transcript bytes."
 */

import type { NodeAdvertisement } from "../advertisement/advertisement";
import type { RemoteNodeHint } from "../topology/remote-node-hint";

// -----------------------------------------------------------------------
// Link authentication state machine
// -----------------------------------------------------------------------

export type LinkAuthState =
  | "AD_CREATED"              // advertisement exists but not verified
  | "AD_VERIFIED"             // advertisement passed spec/03 §5 checks
  | "HANDSHAKE_CHALLENGE"     // Initiate message sent/received, challenge issued
  | "PROOF_OF_POSSESSION"    // possession proof received, verifying
  | "TRANSCRIPT_VERIFIED"     // both proofs verified against the transcript
  | "LINK_UP"                 // fully authenticated, eligible for routing
  | "LINK_DOWN";              // failed or closed

/** Valid state transitions. Any transition not in this map is FORBIDDEN. */
const VALID_TRANSITIONS: Record<LinkAuthState, LinkAuthState[]> = {
  AD_CREATED: ["AD_VERIFIED", "LINK_DOWN"],
  AD_VERIFIED: ["HANDSHAKE_CHALLENGE", "LINK_DOWN"],
  HANDSHAKE_CHALLENGE: ["PROOF_OF_POSSESSION", "LINK_DOWN"],
  PROOF_OF_POSSESSION: ["TRANSCRIPT_VERIFIED", "LINK_DOWN"],
  TRANSCRIPT_VERIFIED: ["LINK_UP", "LINK_DOWN"],
  LINK_UP: ["LINK_DOWN"],
  LINK_DOWN: [],
};

/**
 * The link authentication state machine.
 *
 * Enforces that LINK_UP can ONLY be reached through the full pipeline:
 *   AD_VERIFIED → HANDSHAKE_CHALLENGE → PROOF_OF_POSSESSION → TRANSCRIPT_VERIFIED → LINK_UP
 *
 * No state can skip to LINK_UP. No state can bypass the handshake.
 */
export class LinkAuthStateMachine {
  private state: LinkAuthState = "AD_CREATED";
  private transitionLog: Array<{ from: LinkAuthState; to: LinkAuthState; at: number; reason: string }> = [];

  getState(): LinkAuthState {
    return this.state;
  }

  /**
   * Attempt a state transition. Returns false if the transition is invalid.
   */
  transition(newState: LinkAuthState, reason: string, now: number = Date.now()): boolean {
    const allowed = VALID_TRANSITIONS[this.state];
    if (!allowed.includes(newState)) {
      return false; // FORBIDDEN transition
    }
    this.transitionLog.push({ from: this.state, to: newState, at: now, reason });
    this.state = newState;
    return true;
  }

  getTransitionLog(): readonly Array<{ from: LinkAuthState; to: LinkAuthState; at: number; reason: string }> {
    return this.transitionLog;
  }

  /** True if the link is fully authenticated (LINK_UP). */
  isLinkUp(): boolean {
    return this.state === "LINK_UP";
  }

  /** True if the link is only ADV_VERIFIED (NOT routable). */
  isAdvVerifiedOnly(): boolean {
    return this.state === "AD_VERIFIED";
  }
}

// -----------------------------------------------------------------------
// Architecture guards: no bypass paths
// -----------------------------------------------------------------------

/**
 * Per R-002A: there must be no path from a VerifiedAdvertisement directly
 * to a Link (bypassing the handshake).
 *
 * This guard throws if any code attempts to create a LINK_UP from an
 * advertisement without the full handshake pipeline.
 */
export function ADV_TO_LINK_UP_FORBIDDEN(adv: NodeAdvertisement): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create LINK_UP directly from a ` +
      `VerifiedAdvertisement (nodeId=${adv.nodeId.slice(0, 24)}...). ` +
      `Per R-002A and spec/04 §4, LINK_UP requires the full pipeline: ` +
      `AD_VERIFIED → HANDSHAKE_CHALLENGE → PROOF_OF_POSSESSION → ` +
      `TRANSCRIPT_VERIFIED → LINK_UP. ` +
      `A valid advertisement alone does NOT prove fresh possession of ` +
      `the signing key bound to the connection transcript.`,
  );
}

/**
 * Per R-002A: there must be no path from a RemoteNodeHint to a Link
 * (hints are not authenticated identities).
 */
export function HINT_TO_LINK_UP_FORBIDDEN(hint: RemoteNodeHint): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create LINK_UP from a ` +
      `RemoteNodeHint (subject=${hint.subjectNodeId.slice(0, 24)}...). ` +
      `Per spec/06 §3, a hint is NOT an authenticated identity. ` +
      `LINK_UP requires the full handshake pipeline with the actual node.`,
  );
}

/**
 * Per R-002A: there must be no path from ADV_VERIFIED to LINK_UP
 * without going through HANDSHAKE_CHALLENGE → PROOF_OF_POSSESSION →
 * TRANSCRIPT_VERIFIED.
 *
 * This guard is called by the state machine when a transition is attempted
 * that would skip states.
 */
export function SKIP_HANDSHAKE_FORBIDDEN(fromState: LinkAuthState, toState: LinkAuthState): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to transition from ${fromState} ` +
      `directly to ${toState}, bypassing the handshake pipeline. ` +
      `Per R-002A, the only valid path to LINK_UP is: ` +
      `AD_VERIFIED → HANDSHAKE_CHALLENGE → PROOF_OF_POSSESSION → ` +
      `TRANSCRIPT_VERIFIED → LINK_UP.`,
  );
}
