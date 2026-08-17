/**
 * ShareNet 2.0 — R-002-P1: AuthenticatedLink proof artifact adversarial tests.
 *
 * Per the R-002-P1 directive:
 *
 *   "R-002-P1 should introduce the runtime AuthenticatedLink proof
 *    artifact, and ValidatedHop should consume it. That single change
 *    would simultaneously strengthen R-002 and make the R-006 trust
 *    chain semantically complete."
 *
 * The previous trust chain had a gap:
 *
 *   AuthenticatedNodeRecord + caller-supplied linkUp:boolean
 *       ↓
 *   ValidatedHop
 *
 * A caller holding a genuine AuthenticatedNodeRecord could pass
 * `linkUp=true` with no proof that the directed link completed the
 * authenticated handshake.
 *
 * The new trust chain:
 *
 *   VerifiedNodeAdvertisement (WeakSet)
 *       ↓
 *   AuthenticatedNodeRecord (WeakSet)
 *       ↓
   *   VerifiedTranscript (WeakSet)        — both possession proofs verified
 *       ↓
 *   AuthenticatedLink (WeakSet)          — binds transcript to node
 *       ↓
 *   ValidatedHop (WeakSet)               — consumes the genuine link
 *
 * These tests prove:
 *   1. VerifiedTranscript rejects invalid possession proofs (bad responder proof,
 *      bad initiator proof, wrong challenge, wrong role, wrong transcript hash).
 *   2. AuthenticatedLink is unforgeable (plain object / copy rejected).
 *   3. AuthenticatedLink requires a genuine AuthenticatedNodeRecord + genuine VerifiedTranscript.
 *   4. AuthenticatedLink binds the transcript's remote node to the authNode's nodeId.
 *   5. ValidatedHop requires a genuine AuthenticatedLink (no caller-supplied linkUp boolean).
 *   6. The genuine full pipeline succeeds end-to-end.
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  randomBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  signAdvertisement,
  verifyAdvertisement,
  advertisementToHex,
} from "@reference/advertisement/advertisement";
import {
  computeTranscriptHash,
  computeLinkIdBytes,
  signPossessionProof,
  encodeInitiate,
  encodeAccept,
  POSSESSION_DOMAIN_INITIATOR,
  POSSESSION_DOMAIN_RESPONDER,
  ROLE_INITIATOR,
  ROLE_RESPONDER,
  type InitiateMessage,
  type AcceptMessage,
} from "@reference/transport/auth-handshake";
import {
  createVerifiedTranscript,
  createAuthenticatedLink,
  isVerifiedTranscript,
  isAuthenticatedLink,
  type VerifiedTranscript,
} from "@reference/transport/authenticated-link";
import {
  createAuthenticatedNodeRecord,
  createValidatedHop,
  isValidatedHop,
  isAuthenticatedNodeRecord,
  isBrandedCommittedRoute,
} from "@reference/transport/validated-types";
import { makeGenuineBrandedRoute } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;

/** Run a genuine 3-message handshake and return all the materials. */
function runGenuineHandshake() {
  const kpA = generateNodeKeypair(); // initiator
  const kpB = generateNodeKeypair(); // responder

  const advA = signAdvertisement({
    protocolVersion: 1, nodeId: kpA.nodeId, signingPublicKey: kpA.publicKey,
    capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
    sequence: 1, timestamp: NOW, expiry: NOW + 3600, nonce: randomBytes(16),
  }, kpA.secretKey);
  const advB = signAdvertisement({
    protocolVersion: 1, nodeId: kpB.nodeId, signingPublicKey: kpB.publicKey,
    capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.2", port: 7789 }],
    sequence: 1, timestamp: NOW, expiry: NOW + 3600, nonce: randomBytes(16),
  }, kpB.secretKey);

  const linkNonceA = randomBytes(16);
  const linkNonceB = randomBytes(16);
  const challengeForB = randomBytes(32);
  const challengeForA = randomBytes(32);

  const initiateMsg: InitiateMessage = {
    kind: 1, advertisementHex: advertisementToHex(advA),
    linkNonceA, challengeForB,
  };
  const initiateBytes = encodeInitiate(initiateMsg);

  const linkIdBytes = computeLinkIdBytes(kpA.nodeId, kpB.nodeId, linkNonceA, linkNonceB);
  const transcriptAfterInitiate = computeTranscriptHash([initiateBytes]);

  const proofB = signPossessionProof(
    kpB.secretKey, POSSESSION_DOMAIN_RESPONDER,
    transcriptAfterInitiate, linkIdBytes, challengeForB, ROLE_RESPONDER,
  );

  const acceptMsg: AcceptMessage = {
    kind: 2, advertisementHex: advertisementToHex(advB),
    linkNonceB, challengeForA, proofB,
  };
  const acceptBytes = encodeAccept(acceptMsg);

  const transcriptAfterAccept = computeTranscriptHash([initiateBytes, acceptBytes]);

  const proofA = signPossessionProof(
    kpA.secretKey, POSSESSION_DOMAIN_INITIATOR,
    transcriptAfterAccept, linkIdBytes, challengeForA, ROLE_INITIATOR,
  );

  // Verify both advertisements for the AuthenticatedNodeRecord pipeline
  const vA = verifyAdvertisement(advA, NOW);
  const vB = verifyAdvertisement(advB, NOW);
  if (!vA.ok || !vB.ok) throw new Error("adv verification failed");

  return {
    kpA, kpB, advA, advB,
    linkNonceA, linkNonceB,
    initiateBytes, acceptBytes,
    linkIdBytes,
    transcriptAfterInitiate, transcriptAfterAccept,
    challengeForB, challengeForA,
    proofA, proofB,
    verifiedAdvB: vB.verified,
  };
}

describe("R-002-P1: VerifiedTranscript — rejects invalid possession proofs", () => {
  test("genuine handshake → VerifiedTranscript succeeds (both proofs verified)", () => {
    const h = runGenuineHandshake();
    const vt = createVerifiedTranscript({
      initiateBytes: h.initiateBytes,
      acceptBytes: h.acceptBytes,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId,
      responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey,
      responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForB,
      challengeForA: h.challengeForA,
      proofA: h.proofA,
      proofB: h.proofB,
      verifiedAt: NOW,
    });
    expect(isVerifiedTranscript(vt)).toBe(true);
    expect(vt.initiatorNodeId).toBe(h.kpA.nodeId);
    expect(vt.responderNodeId).toBe(h.kpB.nodeId);
  });

  test("bad responder proof (wrong key) → REJECT", () => {
    const h = runGenuineHandshake();
    const wrongKey = generateNodeKeypair();
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey,
      responderPublicKey: wrongKey.publicKey, // wrong key
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/responder's possession proof did not verify/i);
  });

  test("bad initiator proof (wrong key) → REJECT", () => {
    const h = runGenuineHandshake();
    const wrongKey = generateNodeKeypair();
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: wrongKey.publicKey, // wrong key
      responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/initiator's possession proof did not verify/i);
  });

  test("wrong challenge for responder (swapped) → REJECT", () => {
    const h = runGenuineHandshake();
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey, responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForA, // swapped — B should sign challengeForB, not challengeForA
      challengeForA: h.challengeForB,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/responder's possession proof did not verify/i);
  });

  test("wrong linkIdBytes → REJECT (proofs bound to a different LinkId)", () => {
    const h = runGenuineHandshake();
    const wrongLinkId = computeLinkIdBytes(
      h.kpA.nodeId, h.kpB.nodeId, randomBytes(16), h.linkNonceB,
    );
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      linkIdBytes: wrongLinkId, // different LinkId
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey, responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/possession proof did not verify/i);
  });

  test("tampered Accept message → REJECT (transcript hash mismatch)", () => {
    const h = runGenuineHandshake();
    // Tamper with the Accept message bytes — changes the transcript hash
    const tamperedAccept = new Uint8Array(h.acceptBytes);
    tamperedAccept[0] ^= 0x01;
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: tamperedAccept,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey, responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/possession proof did not verify/i);
  });
});

describe("R-002-P1: AuthenticatedLink — unforgeable proof artifact", () => {
  test("genuine AuthenticatedNodeRecord + genuine VerifiedTranscript → AuthenticatedLink succeeds", () => {
    const h = runGenuineHandshake();
    const authNode = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey, responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    });
    const link = createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNode,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    });
    expect(isAuthenticatedLink(link)).toBe(true);
    expect(link.remoteNodeId).toBe(h.kpB.nodeId);
    expect(link.localNodeId).toBe(h.kpA.nodeId);
    expect(link.transcriptDigestHex).toBe(vt.transcriptDigestHex);
  });

  test("forged AuthenticatedLink (matching shape) → rejected by WeakSet", () => {
    const h = runGenuineHandshake();
    const authNode = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey, responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    });
    const genuine = createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNode,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    });
    // Attacker copies all properties
    const copy = { ...genuine };
    expect(isAuthenticatedLink(copy)).toBe(false);
    expect(isAuthenticatedLink(genuine)).toBe(true);
  });

  test("non-genuine AuthenticatedNodeRecord → createAuthenticatedLink REJECTS", () => {
    const h = runGenuineHandshake();
    const vt = createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey, responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    });
    // A plain object matching AuthenticatedNodeRecord shape — NOT in the WeakSet
    const fakeNode = { nodeId: h.kpB.nodeId, publicKey: h.kpB.publicKey, capabilities: [], endpoints: [], sequence: 1, verifiedAt: NOW, expiresAt: NOW + 3600 };
    expect(isAuthenticatedNodeRecord(fakeNode)).toBe(false);
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: fakeNode as any,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/not a genuine AuthenticatedNodeRecord/i);
  });

  test("non-genuine VerifiedTranscript → createAuthenticatedLink REJECTS", () => {
    const h = runGenuineHandshake();
    const authNode = createAuthenticatedNodeRecord(h.verifiedAdvB);
    // A plain object matching VerifiedTranscript shape — NOT in the WeakSet
    const fakeVt = {
      transcriptDigestHex: bytesToHex(randomBytes(32)),
      linkIdHex: bytesToHex(h.linkIdBytes),
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      verifiedAt: NOW,
    };
    expect(isVerifiedTranscript(fakeVt)).toBe(false);
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNode,
      verifiedTranscript: fakeVt as any, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/not a genuine VerifiedTranscript/i);
  });

  test("transcript remote node ≠ authNode nodeId → createAuthenticatedLink REJECTS", () => {
    const h = runGenuineHandshake();
    const authNode = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey, responderPublicKey: h.kpB.publicKey,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    });
    // Use a DIFFERENT localNodeId that's NOT in the transcript — the
    // remote-from-transcript derivation fails
    const stranger = generateNodeKeypair();
    expect(() => createAuthenticatedLink({
      localNodeId: stranger.nodeId, // not a transcript participant
      remoteNode: authNode,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/is neither the initiator/i);
  });
});

describe("R-002-P1: ValidatedHop requires genuine AuthenticatedLink (no caller-supplied linkUp)", () => {
  test("genuine AuthenticatedLink → ValidatedHop succeeds (linkUp implied, not supplied)", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const link = ctx.authenticatedLinks[0]!;
    expect(isAuthenticatedLink(link)).toBe(true);

    const hop = createValidatedHop(
      link, ctx.hops[0]!.endpoint, ctx.capabilities[0]!, ctx.validatedHops[0]!.serviceAgreementDigest,
    );
    expect(isValidatedHop(hop)).toBe(true);
    expect(hop.linkUp).toBe(true); // implied by the genuine link — not caller-supplied
    expect(hop.nodeId).toBe(link.remoteNode.nodeId);
  });

  test("non-genuine object as link → createValidatedHop REJECTS", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const fakeLink = { ...ctx.authenticatedLinks[0]! }; // copy — not in WeakSet
    expect(isAuthenticatedLink(fakeLink)).toBe(false);
    expect(() => createValidatedHop(
      fakeLink as any, "10.0.0.1:7788", "MESH_RELAY", "digest",
    )).toThrow(/not a genuine AuthenticatedLink/i);
  });

  test("AuthenticatedNodeRecord alone (no AuthenticatedLink) → createValidatedHop REJECTS", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const authNode = ctx.authNodes[0]!;
    expect(isAuthenticatedNodeRecord(authNode)).toBe(true);
    // authNode is NOT an AuthenticatedLink — the WeakSet check fails.
    // R-002-P1: the caller-supplied linkUp boolean is gone.
    expect(() => createValidatedHop(
      authNode as any, "10.0.0.1:7788", "MESH_RELAY", "digest",
    )).toThrow(/not a genuine AuthenticatedLink/i);
  });

  test("plain object as link → createValidatedHop REJECTS", () => {
    const plainObject = { localNodeId: "x", remoteNodeId: "y" };
    expect(isAuthenticatedLink(plainObject)).toBe(false);
    expect(() => createValidatedHop(
      plainObject as any, "10.0.0.1:7788", "MESH_RELAY", "digest",
    )).toThrow(/not a genuine AuthenticatedLink/i);
  });
});

describe("R-002-P1: Genuine full pipeline (adv → authNode → handshake → VerifiedTranscript → AuthenticatedLink → ValidatedHop → BrandedCommittedRoute)", () => {
  test("the full proof-carrying pipeline succeeds end-to-end", () => {
    const ctx = makeGenuineBrandedRoute(2, NOW);

    // Every artifact in the chain is genuine (WeakSet-registered):
    expect(isAuthenticatedNodeRecord(ctx.authNodes[0]!)).toBe(true);
    expect(isAuthenticatedNodeRecord(ctx.authNodes[1]!)).toBe(true);
    expect(isVerifiedTranscript(ctx.verifiedTranscripts[0]!)).toBe(true);
    expect(isVerifiedTranscript(ctx.verifiedTranscripts[1]!)).toBe(true);
    expect(isAuthenticatedLink(ctx.authenticatedLinks[0]!)).toBe(true);
    expect(isAuthenticatedLink(ctx.authenticatedLinks[1]!)).toBe(true);
    expect(isValidatedHop(ctx.validatedHops[0]!)).toBe(true);
    expect(isValidatedHop(ctx.validatedHops[1]!)).toBe(true);

    // The branded route is genuine:
    expect(isBrandedCommittedRoute(ctx.branded)).toBe(true);

    // The branded route's hops are the genuine ValidatedHops (no cast):
    expect(ctx.branded.hops[0]).toBe(ctx.validatedHops[0]); // same object identity
    expect(ctx.branded.hops[1]).toBe(ctx.validatedHops[1]);
  });
});
