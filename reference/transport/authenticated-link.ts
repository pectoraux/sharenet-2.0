/**
 * ShareNet 2.0 — R-002-P1: AuthenticatedLink proof artifact (hardened v3).
 *
 * Per the R-002-P1 hardening audit v3, this version closes the final two
 * semantic gaps:
 *
 *   1. WIRE/MESSAGE BINDING: createVerifiedTranscript now derives ALL
 *      trusted inputs (advertisements, nonces, challenges, proofB,
 *      NodeIds, public keys) by DECODING the Initiate and Accept wire
 *      messages — no duplicate caller-supplied fields. The only
 *      non-wire input is proofA (from the Confirm message), because
 *      that is the message that completes the transcript.
 *
 *   2. USE-TIME FRESHNESS: createValidatedHop now takes `now` and
 *      enforces link.expiresAt > now. A stale AuthenticatedLink cannot
 *      produce a ValidatedHop.
 *
 *   3. FRESHNESS PROVENANCE: createAuthenticatedLink enforces that the
 *      link is established within a bounded window of the transcript's
 *      verification time (establishedAt within [vt.verifiedAt - SKEW,
 *      vt.verifiedAt + MAX_TRANSCRIPT_AGE]). This makes freshness an
 *      explicit verified constraint, not a caller-side convention.
 *
 * The trust chain:
 *
 *   VerifiedNodeAdvertisement (WeakSet)
 *       ↓
 *   AuthenticatedNodeRecord (WeakSet)
 *       ↓
 *   VerifiedTranscript (WeakSet)        — derived from decoded wire bytes
 *                                        + NodeId binding verified
 *                                        + LinkId recomputed
 *                                        + both possession proofs verified
 *       ↓
 *   AuthenticatedLink (WeakSet)          — freshness-bound to transcript
 *                                          + lifetime-enforced + symmetric
 *       ↓
 *   ValidatedHop (WeakSet)               — consumes the genuine link
 *                                          + use-time freshness check
 */

import { toHex } from "../encoding/cbor";
import {
  verifyPossessionProof,
  computeTranscriptHash,
  computeLinkIdBytes,
  decodeMessage,
  POSSESSION_DOMAIN_INITIATOR,
  POSSESSION_DOMAIN_RESPONDER,
  ROLE_INITIATOR,
  ROLE_RESPONDER,
  MSG_KIND,
  type InitiateMessage,
  type AcceptMessage,
} from "./auth-handshake";
import {
  verifyAdvertisement,
  advertisementFromHex,
  type NodeAdvertisement,
} from "../advertisement/advertisement";
import { verifyNodeIdBinding } from "../identity/keys";
import type { AuthenticatedNodeRecord } from "./validated-types";
import { isAuthenticatedNodeRecord } from "./validated-types";

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------

/** Maximum authenticated-link lifetime (1 hour, matching advertisement TTL). */
export const LINK_MAX_LIFETIME_SECONDS = 3600;

/** Maximum clock skew between transcript verification and link establishment. */
export const LINK_CLOCK_SKEW_SECONDS = 60;

/** A VerifiedTranscript must be consumed (turned into an AuthenticatedLink) within this time. */
export const MAX_TRANSCRIPT_AGE_SECONDS = 300; // 5 minutes

// -----------------------------------------------------------------------
// Private WeakSet registries (genuinely unforgeable)
// -----------------------------------------------------------------------

const verifiedTranscriptRegistry = new WeakSet<object>();
const authenticatedLinkRegistry = new WeakSet<object>();

// -----------------------------------------------------------------------
// VerifiedTranscript — derived from decoded wire bytes
// -----------------------------------------------------------------------

/**
 * A VerifiedTranscript is the proof that a 3-message handshake completed,
 * derived ENTIRELY from the decoded wire messages (not from duplicate
 * caller-supplied fields).
 *
 * Per ADR-0016 RESOLVED + R-002-P1 hardening v3:
 *   - The Initiate and Accept wire bytes are decoded to extract:
 *     advertisements, nonces, challenges, proofB.
 *   - The advertisements are verified (signature + NodeId binding + freshness).
 *   - The NodeIds and public keys come FROM the verified advertisements —
 *     never from the caller.
 *   - The directional LinkId is RECOMPUTED from the decoded nonces + NodeIds.
 *   - Both possession proofs are verified against the decoded challenges.
 *
 * The only non-wire input is `proofA` (from the Confirm message), because
 * the Confirm message is what completes the transcript and is not part of
 * the Initiate/Accept bytes.
 *
 * createVerifiedTranscript() verifies ALL of the above before registering.
 * If any check fails, no artifact is produced.
 */
export interface VerifiedTranscript {
  /** The final transcript digest = hash(Initiate, Accept). */
  readonly transcriptDigestHex: string;
  /** The recomputed directional LinkId (derived from decoded nonces). */
  readonly linkIdHex: string;
  readonly linkIdBytes: Uint8Array;
  readonly initiatorNodeId: string;
  readonly responderNodeId: string;
  readonly initiatorNonce: Uint8Array;
  readonly responderNonce: Uint8Array;
  readonly verifiedAt: number;
}

/**
 * The ONLY function that creates a VerifiedTranscript.
 *
 * Takes the raw wire bytes of the Initiate, Accept, and Confirm messages
 * (or just Initiate + Accept + proofA). Derives ALL trusted inputs by
 * decoding the wire messages — no duplicate caller-supplied fields.
 *
 * Verification steps:
 *   1. Decode Initiate → advAHex, nonceA, challengeForB
 *   2. Decode Accept → advBHex, nonceB, challengeForA, proofB
 *   3. Decode advAHex → NodeAdvertisement A → verify (signature + NodeId + freshness)
 *   4. Decode advBHex → NodeAdvertisement B → verify (signature + NodeId + freshness)
 *   5. VerifyNodeIdBinding for both (defense-in-depth — verifyAdvertisement already does this)
 *   6. Recompute linkIdBytes = computeLinkIdBytes(nodeIdA, nodeIdB, nonceA, nonceB)
 *   7. Verify proofB over hash(Initiate), linkIdBytes, challengeForB, RESPONDER
 *   8. Verify proofA over hash(Initiate, Accept), linkIdBytes, challengeForA, INITIATOR
 *
 * If ANY step fails, throws — no artifact is produced.
 */
export function createVerifiedTranscript(params: {
  initiateBytes: Uint8Array;
  acceptBytes: Uint8Array;
  /** A's possession proof from the Confirm message (the one non-wire input). */
  proofA: Uint8Array;
  /** Verification time (unix seconds) — used for advertisement freshness. */
  verifiedAt: number;
}): VerifiedTranscript {
  // 1. Decode the Initiate message.
  let initiate: InitiateMessage;
  try {
    initiate = decodeMessage(params.initiateBytes) as InitiateMessage;
    if (initiate.kind !== MSG_KIND.INITIATE) {
      throw new Error(`expected INITIATE, got kind ${initiate.kind}`);
    }
  } catch (e) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        `failed to decode Initiate message: ${(e as Error).message}. ` +
        "The transcript must be derived from genuine wire bytes, not " +
        "caller-supplied duplicate fields.",
    );
  }

  // 2. Decode the Accept message.
  let accept: AcceptMessage;
  try {
    accept = decodeMessage(params.acceptBytes) as AcceptMessage;
    if (accept.kind !== MSG_KIND.ACCEPT) {
      throw new Error(`expected ACCEPT, got kind ${accept.kind}`);
    }
  } catch (e) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        `failed to decode Accept message: ${(e as Error).message}. ` +
        "The transcript must be derived from genuine wire bytes, not " +
        "caller-supplied duplicate fields.",
    );
  }

  // 3. Decode + verify A's advertisement (from the Initiate message).
  let advA: NodeAdvertisement;
  try {
    advA = advertisementFromHex(initiate.advertisementHex);
  } catch (e) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        `failed to decode initiator advertisement from Initiate: ${(e as Error).message}.`,
    );
  }
  const vA = verifyAdvertisement(advA, params.verifiedAt);
  if (!vA.ok) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        `initiator advertisement verification failed: ${vA.detail}. ` +
        "The advertisement carried in the Initiate wire message MUST " +
        "pass full spec/03 §5 verification (signature + NodeId binding + " +
        "freshness).",
    );
  }

  // 4. Decode + verify B's advertisement (from the Accept message).
  let advB: NodeAdvertisement;
  try {
    advB = advertisementFromHex(accept.advertisementHex);
  } catch (e) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        `failed to decode responder advertisement from Accept: ${(e as Error).message}.`,
    );
  }
  const vB = verifyAdvertisement(advB, params.verifiedAt);
  if (!vB.ok) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        `responder advertisement verification failed: ${vB.detail}. ` +
        "The advertisement carried in the Accept wire message MUST " +
        "pass full spec/03 §5 verification (signature + NodeId binding + " +
        "freshness).",
    );
  }

  // 5. Defense-in-depth: verifyNodeIdBinding for both parties.
  //    verifyAdvertisement already does this, but we re-check here to be
  //    explicit about the identity invariant.
  if (!verifyNodeIdBinding(advA.nodeId, advA.signingPublicKey)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        "initiator NodeId does not match the canonical derivation of " +
        "the initiator public key from the Initiate wire message.",
    );
  }
  if (!verifyNodeIdBinding(advB.nodeId, advB.signingPublicKey)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        "responder NodeId does not match the canonical derivation of " +
        "the responder public key from the Accept wire message.",
    );
  }

  // 6. Recompute the directional LinkId from the DECODED nonces + NodeIds.
  const initiatorNonce = initiate.linkNonceA;
  const responderNonce = accept.linkNonceB;
  const initiatorNodeId = advA.nodeId;
  const responderNodeId = advB.nodeId;
  const linkIdBytes = computeLinkIdBytes(
    initiatorNodeId,
    responderNodeId,
    initiatorNonce,
    responderNonce,
  );

  // 7. Compute the two transcript hashes.
  const responderTranscriptHash = computeTranscriptHash([params.initiateBytes]);
  const initiatorTranscriptHash = computeTranscriptHash([params.initiateBytes, params.acceptBytes]);

  // 8. Verify the responder's (B's) possession proof (decoded from Accept).
  const challengeForB = initiate.challengeForB; // from the wire
  const proofB = accept.proofB; // from the wire
  const proofBOk = verifyPossessionProof(
    advB.signingPublicKey,
    proofB,
    POSSESSION_DOMAIN_RESPONDER,
    responderTranscriptHash,
    linkIdBytes,
    challengeForB,
    ROLE_RESPONDER,
  );
  if (!proofBOk) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        "responder's possession proof (decoded from the Accept wire " +
        "message) did not verify. B must sign the challenge from the " +
        "Initiate message, bound to hash(Initiate) and the directional " +
        "LinkId, with role RESPONDER.",
    );
  }

  // 9. Verify the initiator's (A's) possession proof (the one non-wire input).
  const challengeForA = accept.challengeForA; // from the wire
  const proofAOk = verifyPossessionProof(
    advA.signingPublicKey,
    params.proofA,
    POSSESSION_DOMAIN_INITIATOR,
    initiatorTranscriptHash,
    linkIdBytes,
    challengeForA,
    ROLE_INITIATOR,
  );
  if (!proofAOk) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createVerifiedTranscript rejected — " +
        "initiator's possession proof did not verify. A must sign the " +
        "challenge from the Accept message, bound to hash(Initiate, Accept) " +
        "and the directional LinkId, with role INITIATOR.",
    );
  }

  // All checks verified — register the genuine artifact.
  const transcript: VerifiedTranscript = {
    transcriptDigestHex: toHex(initiatorTranscriptHash),
    linkIdHex: toHex(linkIdBytes),
    linkIdBytes,
    initiatorNodeId,
    responderNodeId,
    initiatorNonce,
    responderNonce,
    verifiedAt: params.verifiedAt,
  };
  verifiedTranscriptRegistry.add(transcript);
  return transcript;
}

/**
 * Runtime check: is this object a genuine VerifiedTranscript
 * produced by createVerifiedTranscript()?
 */
export function isVerifiedTranscript(obj: unknown): obj is VerifiedTranscript {
  return typeof obj === "object" && obj !== null && verifiedTranscriptRegistry.has(obj);
}

// -----------------------------------------------------------------------
// AuthenticatedLink — freshness-bound to transcript + lifetime-enforced
// -----------------------------------------------------------------------

/**
 * An AuthenticatedLink is the proof that a directed link to a specific
 * authenticated node completed the 3-message handshake, AND that the
 * link was established within a bounded freshness window of the
 * transcript verification.
 *
 * Per R-002-P1 hardening v3:
 *   - The link is freshness-bound to the transcript: establishedAt must
 *     be within [vt.verifiedAt - SKEW, vt.verifiedAt + MAX_TRANSCRIPT_AGE].
 *   - Lifetime invariants: expiresAt > establishedAt, bounded by
 *     LINK_MAX_LIFETIME_SECONDS.
 *   - Symmetric: works for both initiator and responder sides.
 */
export interface AuthenticatedLink {
  readonly localNodeId: string;
  readonly remoteNodeId: string;
  readonly remoteNode: AuthenticatedNodeRecord;
  readonly linkIdHex: string;
  readonly linkIdBytes: Uint8Array;
  readonly transcriptDigestHex: string;
  readonly localRole: "INITIATOR" | "RESPONDER";
  readonly establishedAt: number;
  readonly expiresAt: number;
  /** When the underlying transcript was verified. */
  readonly transcriptVerifiedAt: number;
}

/**
 * The ONLY function that creates an AuthenticatedLink.
 *
 * Consumes a genuine AuthenticatedNodeRecord + genuine VerifiedTranscript.
 * Verifies:
 *   - remoteNode is genuine (WeakSet)
 *   - verifiedTranscript is genuine (WeakSet)
 *   - transcript remote participant matches remoteNode (symmetric)
 *   - LinkId recomputed and compared (defense-in-depth)
 *   - Freshness: establishedAt within [vt.verifiedAt - SKEW, vt.verifiedAt + MAX_AGE]
 *   - Lifetime: expiresAt > establishedAt, bounded by LINK_MAX_LIFETIME_SECONDS
 */
export function createAuthenticatedLink(params: {
  localNodeId: string;
  remoteNode: AuthenticatedNodeRecord;
  verifiedTranscript: VerifiedTranscript;
  establishedAt: number;
  expiresAt: number;
}): AuthenticatedLink {
  // 1. Verify the remoteNode is a genuine AuthenticatedNodeRecord.
  if (!isAuthenticatedNodeRecord(params.remoteNode)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        "remoteNode is not a genuine AuthenticatedNodeRecord (WeakSet " +
        "membership check failed).",
    );
  }

  // 2. Verify the verifiedTranscript is genuine.
  if (!isVerifiedTranscript(params.verifiedTranscript)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        "verifiedTranscript is not a genuine VerifiedTranscript (WeakSet " +
        "membership check failed).",
    );
  }

  // 3. Resolve the remote participant — SYMMETRIC.
  const { initiatorNodeId, responderNodeId } = params.verifiedTranscript;
  let remoteFromTranscript: string;
  let localRole: "INITIATOR" | "RESPONDER";
  if (initiatorNodeId === params.localNodeId) {
    remoteFromTranscript = responderNodeId;
    localRole = "INITIATOR";
  } else if (responderNodeId === params.localNodeId) {
    remoteFromTranscript = initiatorNodeId;
    localRole = "RESPONDER";
  } else {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        `localNodeId (${params.localNodeId}) is neither the initiator ` +
        `(${initiatorNodeId}) nor the responder (${responderNodeId}) of ` +
        "the verified transcript.",
    );
  }

  // 4. The transcript's remote node must match the authenticated node.
  if (remoteFromTranscript !== params.remoteNode.nodeId) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        `the transcript's remote node (${remoteFromTranscript}) does not ` +
        `match the AuthenticatedNodeRecord's nodeId (${params.remoteNode.nodeId}).`,
    );
  }

  // 5. Recompute the directional LinkId (defense-in-depth).
  const expectedLinkId = computeLinkIdBytes(
    initiatorNodeId,
    responderNodeId,
    params.verifiedTranscript.initiatorNonce,
    params.verifiedTranscript.responderNonce,
  );
  if (!constantTimeEqual(expectedLinkId, params.verifiedTranscript.linkIdBytes)) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        "the verified transcript's linkIdBytes do not match the recomputed " +
        "directional LinkId.",
    );
  }

  // 6. FRESHNESS PROVENANCE (R-002-P1 hardening v3 issue #3):
  //    The link must be established within a bounded window of the
  //    transcript's verification time. This makes freshness an explicit
  //    verified constraint, not a caller-side convention.
  const vtAge = params.establishedAt - params.verifiedTranscript.verifiedAt;
  if (vtAge > MAX_TRANSCRIPT_AGE_SECONDS) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        `link established ${vtAge}s after transcript verification, ` +
        `exceeding the maximum freshness window (${MAX_TRANSCRIPT_AGE_SECONDS}s). ` +
        "A VerifiedTranscript must be consumed (turned into an " +
        "AuthenticatedLink) promptly — a stale transcript cannot " +
        "produce a fresh link.",
    );
  }
  if (vtAge < -LINK_CLOCK_SKEW_SECONDS) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        `link established ${-vtAge}s BEFORE transcript verification, ` +
        `exceeding clock skew tolerance (${LINK_CLOCK_SKEW_SECONDS}s). ` +
        "The link cannot be established before the transcript was verified.",
    );
  }

  // 7. Lifetime invariants.
  if (params.expiresAt <= params.establishedAt) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        `expiresAt (${params.expiresAt}) must be strictly greater than ` +
        `establishedAt (${params.establishedAt}).`,
    );
  }
  const lifetime = params.expiresAt - params.establishedAt;
  if (lifetime > LINK_MAX_LIFETIME_SECONDS) {
    throw new Error(
      "ARCHITECTURE VIOLATION: createAuthenticatedLink rejected — " +
        `link lifetime (${lifetime}s) exceeds the maximum ` +
        `(${LINK_MAX_LIFETIME_SECONDS}s).`,
    );
  }

  const link: AuthenticatedLink = {
    localNodeId: params.localNodeId,
    remoteNodeId: params.remoteNode.nodeId,
    remoteNode: params.remoteNode,
    linkIdHex: params.verifiedTranscript.linkIdHex,
    linkIdBytes: params.verifiedTranscript.linkIdBytes,
    transcriptDigestHex: params.verifiedTranscript.transcriptDigestHex,
    localRole,
    establishedAt: params.establishedAt,
    expiresAt: params.expiresAt,
    transcriptVerifiedAt: params.verifiedTranscript.verifiedAt,
  };
  authenticatedLinkRegistry.add(link);
  return link;
}

/**
 * Runtime check: is this object a genuine AuthenticatedLink
 * produced by createAuthenticatedLink()?
 */
export function isAuthenticatedLink(obj: unknown): obj is AuthenticatedLink {
  return typeof obj === "object" && obj !== null && authenticatedLinkRegistry.has(obj);
}

/**
 * Check if an AuthenticatedLink is fresh (not expired) at the given time.
 * This is the USE-TIME freshness check — enforced by createValidatedHop.
 */
export function isLinkFresh(link: AuthenticatedLink, now: number): boolean {
  return link.expiresAt > now;
}

// -----------------------------------------------------------------------
// Internal helper
// -----------------------------------------------------------------------

/** Constant-time byte comparison. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
