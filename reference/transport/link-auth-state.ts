/**
 * ShareNet 2.0 — R-002A: Link Authentication State Machine (evidence-carrying).
 *
 * Per R-002-P1 hardening v5 (final R-002 closure): the state machine no
 * longer accepts arbitrary `(newState, reason)` transitions. Each
 * security-sensitive transition now CONSUMES a genuine proof artifact
 * (WeakSet-registered):
 *
 *   AD_CREATED
 *       ↓  advanceToAdVerified(verifiedAdvertisement)
 *   AD_VERIFIED
 *       ↓  advanceToHandshakeChallenge(challenge)
 *   HANDSHAKE_CHALLENGE
 *       ↓  advanceToProofOfPossession(consumedChallenge)
 *   PROOF_OF_POSSESSION
 *       ↓  advanceToTranscriptVerified(verifiedTranscript)
 *   TRANSCRIPT_VERIFIED
 *       ↓  advanceToLinkUp(authenticatedLink)
 *   LINK_UP
 *
 * A caller CANNOT reach LINK_UP by supplying state names — the only way
 * to LINK_UP is `advanceToLinkUp(authenticatedLink)`, which requires a
 * genuine `AuthenticatedLink` (WeakSet-verified, itself consuming a
 * genuine `VerifiedTranscript` + `AuthenticatedNodeRecord`).
 *
 * The generic `transition(newState, reason)` API is REMOVED for
 * security-sensitive states. The only remaining generic transitions are
 * `LINK_DOWN` (teardown, always allowed) and `AD_VERIFIED→LINK_DOWN` etc.
 *
 * This unifies the two meanings of LINK_UP: the state machine's LINK_UP
 * and the AuthenticatedLink proof artifact are now the same thing — there
 * is exactly one semantic meaning of LINK_UP: a genuine authenticated-link
 * proof exists.
 */

import type { NodeAdvertisement } from "../advertisement/advertisement";
import type { RemoteNodeHint } from "../topology/remote-node-hint";
import type { VerifiedNodeAdvertisement } from "../advertisement/advertisement";
import { isVerifiedNodeAdvertisement } from "../advertisement/advertisement";
import type { ConsumedChallenge, VerifiedTranscript, AuthenticatedLink } from "./authenticated-link";
import { isConsumedChallenge, isVerifiedTranscript, isAuthenticatedLink } from "./authenticated-link";

// -----------------------------------------------------------------------
// Link authentication state machine
// -----------------------------------------------------------------------

export type LinkAuthState =
  | "AD_CREATED"              // advertisement exists but not verified
  | "AD_VERIFIED"             // advertisement passed spec/03 §5 checks
  | "HANDSHAKE_CHALLENGE"     // Initiate message sent/received, challenge issued
  | "PROOF_OF_POSSESSION"     // possession proof received, verifying
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

/** Internal transition log entry. */
interface TransitionLogEntry {
  from: LinkAuthState;
  to: LinkAuthState;
  at: number;
  reason: string;
}

/**
 * The link authentication state machine (evidence-carrying).
 *
 * Per R-002-P1 hardening v5: security-sensitive transitions now require
 * genuine proof artifacts. The generic `transition(newState, reason)`
 * API is REMOVED for security-sensitive states — a caller cannot walk
 * to LINK_UP by supplying state names.
 *
 * The only way to LINK_UP is `advanceToLinkUp(authenticatedLink)`, which
 * requires a genuine `AuthenticatedLink` (WeakSet-verified).
 */
export class LinkAuthStateMachine {
  private state: LinkAuthState = "AD_CREATED";
  private transitionLog: TransitionLogEntry[] = [];
  /** The genuine AuthenticatedLink, set when advanceToLinkUp succeeds. */
  private authenticatedLink: AuthenticatedLink | null = null;
  /** The genuine VerifiedTranscript, set when advanceToTranscriptVerified succeeds. */
  private verifiedTranscript: VerifiedTranscript | null = null;
  /** The genuine ConsumedChallenge, set when advanceToProofOfPossession succeeds. */
  private consumedChallenge: ConsumedChallenge | null = null;
  /** The genuine VerifiedNodeAdvertisement, set when advanceToAdVerified succeeds. */
  private verifiedAdvertisement: VerifiedNodeAdvertisement | null = null;

  getState(): LinkAuthState {
    return this.state;
  }

  /**
   * Transition to AD_VERIFIED.
   * Requires a genuine VerifiedNodeAdvertisement (WeakSet-verified).
   */
  advanceToAdVerified(verified: VerifiedNodeAdvertisement, now: number = Date.now()): boolean {
    if (!isVerifiedNodeAdvertisement(verified)) {
      throw new Error(
        "ARCHITECTURE VIOLATION: advanceToAdVerified rejected — " +
          "verifiedAdvertisement is not a genuine VerifiedNodeAdvertisement " +
          "(WeakSet membership check failed). Per R-002-P1 hardening v5, " +
          "the state machine requires genuine proof artifacts for " +
          "security-sensitive transitions. A plain object or a copy " +
          "cannot advance the state to AD_VERIFIED.",
      );
    }
    if (!this.tryTransition("AD_VERIFIED", "advertisement verified", now)) return false;
    this.verifiedAdvertisement = verified;
    return true;
  }

  /**
   * Transition to HANDSHAKE_CHALLENGE.
   * Requires the raw challenge bytes (registered separately in the ChallengeCache).
   * This state records that a challenge was issued; the proof-of-possession
   * transition consumes a ConsumedChallenge from the cache.
   */
  advanceToHandshakeChallenge(challenge: Uint8Array, now: number = Date.now()): boolean {
    // Basic structural check — the challenge is 32 bytes.
    if (!(challenge instanceof Uint8Array) || challenge.length !== 32) {
      throw new Error(
        "ARCHITECTURE VIOLATION: advanceToHandshakeChallenge rejected — " +
          "challenge must be a 32-byte Uint8Array. The challenge is " +
          "issued here and registered in the ChallengeCache; it will be " +
          "consumed (as a ConsumedChallenge) at the PROOF_OF_POSSESSION step.",
      );
    }
    return this.tryTransition("HANDSHAKE_CHALLENGE", "challenge issued", now);
  }

  /**
   * Transition to PROOF_OF_POSSESSION.
   * Requires a genuine ConsumedChallenge (WeakSet-verified) — proves the
   * challenge was registered by the local verifier, unexpired, and single-use.
   */
  advanceToProofOfPossession(consumedChallenge: ConsumedChallenge, now: number = Date.now()): boolean {
    if (!isConsumedChallenge(consumedChallenge)) {
      throw new Error(
        "ARCHITECTURE VIOLATION: advanceToProofOfPossession rejected — " +
          "consumedChallenge is not a genuine ConsumedChallenge (WeakSet " +
          "membership check failed). Per R-002-P1 hardening v5, the proof " +
          "of possession requires a challenge that was registered, " +
          "unexpired, and single-use (consumed from the ChallengeCache). " +
          "A plain object or a copy cannot advance the state to " +
          "PROOF_OF_POSSESSION.",
      );
    }
    if (!this.tryTransition("PROOF_OF_POSSESSION", "proof of possession verified", now)) return false;
    this.consumedChallenge = consumedChallenge;
    return true;
  }

  /**
   * Transition to TRANSCRIPT_VERIFIED.
   * Requires a genuine VerifiedTranscript (WeakSet-verified) — proves both
   * possession proofs were verified, NodeId binding holds, and the LinkId
   * was recomputed from decoded wire bytes.
   */
  advanceToTranscriptVerified(transcript: VerifiedTranscript, now: number = Date.now()): boolean {
    if (!isVerifiedTranscript(transcript)) {
      throw new Error(
        "ARCHITECTURE VIOLATION: advanceToTranscriptVerified rejected — " +
          "transcript is not a genuine VerifiedTranscript (WeakSet " +
          "membership check failed). Per R-002-P1 hardening v5, the " +
          "transcript-verified state requires a genuine VerifiedTranscript " +
          "produced by createVerifiedTranscript (which verifies both " +
          "possession proofs, NodeId binding, and recomputes the LinkId " +
          "from decoded wire bytes). A plain object or a copy cannot " +
          "advance the state to TRANSCRIPT_VERIFIED.",
      );
    }
    if (!this.tryTransition("TRANSCRIPT_VERIFIED", "transcript verified", now)) return false;
    this.verifiedTranscript = transcript;
    return true;
  }

  /**
   * Transition to LINK_UP.
   * Requires a genuine AuthenticatedLink (WeakSet-verified) — proves the
   * full pipeline: verified advertisement → authenticated node → verified
   * transcript → authenticated link, with freshness, lifetime bounds, and
   * replay protection.
   *
   * This is the ONLY way to reach LINK_UP. There is no generic
   * `transition("LINK_UP", reason)` — a caller cannot walk the state
   * machine to LINK_UP by supplying state names.
   */
  advanceToLinkUp(link: AuthenticatedLink, now: number = Date.now()): boolean {
    if (!isAuthenticatedLink(link)) {
      throw new Error(
        "ARCHITECTURE VIOLATION: advanceToLinkUp rejected — " +
          "link is not a genuine AuthenticatedLink (WeakSet membership " +
          "check failed). Per R-002-P1 hardening v5, LINK_UP requires a " +
          "genuine AuthenticatedLink produced by createAuthenticatedLink " +
          "(which consumes a genuine AuthenticatedNodeRecord + genuine " +
          "VerifiedTranscript, verifies freshness, lifetime, and the " +
          "directional LinkId). The generic transition(newState, reason) " +
          "API has been REMOVED for LINK_UP — there is exactly one " +
          "semantic meaning of LINK_UP: a genuine authenticated-link " +
          "proof exists.",
      );
    }
    if (!this.tryTransition("LINK_UP", "fully authenticated", now)) return false;
    this.authenticatedLink = link;
    return true;
  }

  /**
   * Transition to LINK_DOWN (teardown). Always allowed from any non-terminal state.
   * Does not require proof artifacts — teardown is operator-initiated.
   */
  goToLinkDown(reason: string, now: number = Date.now()): boolean {
    return this.tryTransition("LINK_DOWN", reason, now);
  }

  /**
   * Returns the genuine AuthenticatedLink if the state is LINK_UP, else null.
   * This lets callers verify that LINK_UP genuinely means a proof artifact exists.
   */
  getAuthenticatedLink(): AuthenticatedLink | null {
    return this.state === "LINK_UP" ? this.authenticatedLink : null;
  }

  /**
   * Returns the genuine VerifiedTranscript if the state is TRANSCRIPT_VERIFIED
   * or LINK_UP, else null.
   */
  getVerifiedTranscript(): VerifiedTranscript | null {
    return (this.state === "TRANSCRIPT_VERIFIED" || this.state === "LINK_UP")
      ? this.verifiedTranscript
      : null;
  }

  getTransitionLog(): readonly TransitionLogEntry[] {
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

  /**
   * Internal: attempt a state transition. Validates against the transition table.
   * This is NOT public — callers must use the evidence-carrying advance* methods.
   */
  private tryTransition(newState: LinkAuthState, reason: string, now: number): boolean {
    const allowed = VALID_TRANSITIONS[this.state];
    if (!allowed.includes(newState)) {
      return false; // FORBIDDEN transition
    }
    this.transitionLog.push({ from: this.state, to: newState, at: now, reason });
    this.state = newState;
    return true;
  }
}

// -----------------------------------------------------------------------
// Architecture guards: no bypass paths (preserved for backward compat)
// -----------------------------------------------------------------------

/**
 * Per R-002A: there must be no path from a VerifiedAdvertisement directly
 * to a Link (bypassing the handshake).
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
 * Per R-002A: there must be no path from a RemoteNodeHint to a Link.
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
 * without going through the full handshake pipeline.
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
