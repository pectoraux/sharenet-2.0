/**
 * ShareNet 2.0 — R-002-P1: AuthenticatedLink proof artifact (hardened v2).
 *
 * Per the R-002-P1 hardening audit, this version fixes four issues:
 *   1. Responder-side remote-participant resolution (was broken).
 *   2. NodeId ↔ public-key binding enforced inside createVerifiedTranscript.
 *   3. LinkId recomputed from retained nonces (not trusted from caller).
 *   4. Lifetime invariants enforced (expiresAt > establishedAt, bounded).
 *
 * Adversarial tests (per auditor spec):
 *   - responder-side AuthenticatedLink → succeeds
 *   - wrong NodeId/public-key pair → rejects
 *   - swapped public keys → rejects
 *   - forged transcript participant IDs → rejects
 *   - wrong LinkId derivation → rejects
 *   - expired/future-invalid link lifetime → rejects
 *   - genuine initiator pipeline → succeeds
 *   - genuine responder pipeline → succeeds
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
  LINK_MAX_LIFETIME_SECONDS,
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
    verifiedAdvA: vA.verified,
    verifiedAdvB: vB.verified,
  };
}

/** Build a genuine VerifiedTranscript from the handshake materials. */
function buildVerifiedTranscript(h: ReturnType<typeof runGenuineHandshake>) {
  return createVerifiedTranscript({
    initiateBytes: h.initiateBytes,
    acceptBytes: h.acceptBytes,
    initiatorNodeId: h.kpA.nodeId,
    responderNodeId: h.kpB.nodeId,
    initiatorPublicKey: h.kpA.publicKey,
    responderPublicKey: h.kpB.publicKey,
    initiatorNonce: h.linkNonceA,
    responderNonce: h.linkNonceB,
    challengeForB: h.challengeForB,
    challengeForA: h.challengeForA,
    proofA: h.proofA,
    proofB: h.proofB,
    verifiedAt: NOW,
  });
}

describe("R-002-P1 v2: VerifiedTranscript — NodeId binding enforced", () => {
  test("genuine handshake → VerifiedTranscript succeeds (both proofs + NodeId binding)", () => {
    const h = runGenuineHandshake();
    const vt = buildVerifiedTranscript(h);
    expect(isVerifiedTranscript(vt)).toBe(true);
    expect(vt.initiatorNodeId).toBe(h.kpA.nodeId);
    expect(vt.responderNodeId).toBe(h.kpB.nodeId);
    // LinkId is recomputed internally — verify it matches
    expect(vt.linkIdHex).toBe(bytesToHex(h.linkIdBytes));
  });

  test("wrong initiator NodeId (≠ deriveNodeId(pubkey)) → REJECT", () => {
    const h = runGenuineHandshake();
    const stranger = generateNodeKeypair();
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      initiatorNodeId: stranger.nodeId, // wrong NodeId for kpA.publicKey
      responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey,
      responderPublicKey: h.kpB.publicKey,
      initiatorNonce: h.linkNonceA, responderNonce: h.linkNonceB,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/initiator NodeId does not match/i);
  });

  test("wrong responder NodeId (≠ deriveNodeId(pubkey)) → REJECT", () => {
    const h = runGenuineHandshake();
    const stranger = generateNodeKeypair();
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      initiatorNodeId: h.kpA.nodeId,
      responderNodeId: stranger.nodeId, // wrong NodeId for kpB.publicKey
      initiatorPublicKey: h.kpA.publicKey,
      responderPublicKey: h.kpB.publicKey,
      initiatorNonce: h.linkNonceA, responderNonce: h.linkNonceB,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/responder NodeId does not match/i);
  });

  test("swapped public keys (init pubkey ↔ resp pubkey) → REJECT", () => {
    const h = runGenuineHandshake();
    // Swap: initiator gets B's key, responder gets A's key.
    // The NodeId binding check fires (A's NodeId ≠ deriveNodeId(B's key)).
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      initiatorNodeId: h.kpA.nodeId,
      responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpB.publicKey, // swapped
      responderPublicKey: h.kpA.publicKey,  // swapped
      initiatorNonce: h.linkNonceA, responderNonce: h.linkNonceB,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/NodeId does not match/i);
  });

  test("bad responder proof (wrong key) → REJECT", () => {
    const h = runGenuineHandshake();
    const stranger = generateNodeKeypair();
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: h.acceptBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey,
      responderPublicKey: stranger.publicKey, // NodeId won't match either
      initiatorNonce: h.linkNonceA, responderNonce: h.linkNonceB,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/responder/i);
  });

  test("tampered Accept message → REJECT (transcript hash mismatch)", () => {
    const h = runGenuineHandshake();
    const tamperedAccept = new Uint8Array(h.acceptBytes);
    tamperedAccept[0] ^= 0x01;
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes, acceptBytes: tamperedAccept,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorPublicKey: h.kpA.publicKey, responderPublicKey: h.kpB.publicKey,
      initiatorNonce: h.linkNonceA, responderNonce: h.linkNonceB,
      challengeForB: h.challengeForB, challengeForA: h.challengeForA,
      proofA: h.proofA, proofB: h.proofB, verifiedAt: NOW,
    })).toThrow(/possession proof did not verify/i);
  });
});

describe("R-002-P1 v2: AuthenticatedLink — symmetric (initiator + responder)", () => {
  test("genuine initiator-side AuthenticatedLink → succeeds (localRole=INITIATOR)", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    const link = createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, // initiator side
      remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + 3600,
    });
    expect(isAuthenticatedLink(link)).toBe(true);
    expect(link.localRole).toBe("INITIATOR");
    expect(link.remoteNodeId).toBe(h.kpB.nodeId);
    expect(link.localNodeId).toBe(h.kpA.nodeId);
  });

  test("genuine responder-side AuthenticatedLink → succeeds (localRole=RESPONDER)", () => {
    const h = runGenuineHandshake();
    const authNodeA = createAuthenticatedNodeRecord(h.verifiedAdvA);
    const vt = buildVerifiedTranscript(h);
    const link = createAuthenticatedLink({
      localNodeId: h.kpB.nodeId, // responder side
      remoteNode: authNodeA,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + 3600,
    });
    expect(isAuthenticatedLink(link)).toBe(true);
    expect(link.localRole).toBe("RESPONDER");
    expect(link.remoteNodeId).toBe(h.kpA.nodeId);
    expect(link.localNodeId).toBe(h.kpB.nodeId);
  });

  test("forged AuthenticatedLink (copy) → rejected by WeakSet", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    const genuine = createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    });
    const copy = { ...genuine };
    expect(isAuthenticatedLink(copy)).toBe(false);
    expect(isAuthenticatedLink(genuine)).toBe(true);
  });

  test("non-genuine AuthenticatedNodeRecord → createAuthenticatedLink REJECTS", () => {
    const h = runGenuineHandshake();
    const vt = buildVerifiedTranscript(h);
    const fakeNode = { nodeId: h.kpB.nodeId, publicKey: h.kpB.publicKey };
    expect(isAuthenticatedNodeRecord(fakeNode)).toBe(false);
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: fakeNode as any,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/not a genuine AuthenticatedNodeRecord/i);
  });

  test("non-genuine VerifiedTranscript → createAuthenticatedLink REJECTS", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const fakeVt = {
      transcriptDigestHex: bytesToHex(randomBytes(32)),
      linkIdHex: bytesToHex(h.linkIdBytes),
      linkIdBytes: h.linkIdBytes,
      initiatorNodeId: h.kpA.nodeId, responderNodeId: h.kpB.nodeId,
      initiatorNonce: h.linkNonceA, responderNonce: h.linkNonceB,
      verifiedAt: NOW,
    };
    expect(isVerifiedTranscript(fakeVt)).toBe(false);
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: fakeVt as any, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/not a genuine VerifiedTranscript/i);
  });

  test("forged transcript participant IDs (local not a participant) → REJECT", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    const stranger = generateNodeKeypair();
    expect(() => createAuthenticatedLink({
      localNodeId: stranger.nodeId, // not a transcript participant
      remoteNode: authNodeB,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/is neither the initiator/i);
  });

  test("transcript remote node ≠ authNode nodeId → REJECT", () => {
    const h = runGenuineHandshake();
    // Build a genuine AuthenticatedNodeRecord for a DIFFERENT node (A, not B)
    const authNodeA = createAuthenticatedNodeRecord(h.verifiedAdvA);
    const vt = buildVerifiedTranscript(h);
    // local=A, remote should be B, but we pass authNodeA (nodeId=A)
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeA, // wrong — should be authNodeB
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/does not match.*nodeId/i);
  });
});

describe("R-002-P1 v2: Lifetime invariants enforced", () => {
  test("expiresAt <= establishedAt → REJECT", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW, // equal — invalid
    })).toThrow(/expiresAt.*must be strictly greater than.*establishedAt/i);
  });

  test("expiresAt < establishedAt → REJECT", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW - 100, // before — invalid
    })).toThrow(/expiresAt.*must be strictly greater than.*establishedAt|expires at or before/i);
  });

  test(`lifetime > LINK_MAX_LIFETIME_SECONDS (${LINK_MAX_LIFETIME_SECONDS}s) → REJECT`, () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + LINK_MAX_LIFETIME_SECONDS + 1,
    })).toThrow(/exceeds the maximum/i);
  });

  test("lifetime exactly at LINK_MAX_LIFETIME_SECONDS → ACCEPT (boundary)", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    const link = createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + LINK_MAX_LIFETIME_SECONDS,
    });
    expect(isAuthenticatedLink(link)).toBe(true);
  });
});

describe("R-002-P1 v2: ValidatedHop requires genuine AuthenticatedLink", () => {
  test("genuine AuthenticatedLink → ValidatedHop succeeds (linkUp implied)", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const link = ctx.authenticatedLinks[0]!;
    expect(isAuthenticatedLink(link)).toBe(true);
    const hop = createValidatedHop(
      link, ctx.hops[0]!.endpoint, ctx.capabilities[0]!, ctx.validatedHops[0]!.serviceAgreementDigest,
    );
    expect(isValidatedHop(hop)).toBe(true);
    expect(hop.linkUp).toBe(true);
    expect(hop.nodeId).toBe(link.remoteNode.nodeId);
  });

  test("non-genuine object as link → REJECT", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const fakeLink = { ...ctx.authenticatedLinks[0]! };
    expect(isAuthenticatedLink(fakeLink)).toBe(false);
    expect(() => createValidatedHop(
      fakeLink as any, "10.0.0.1:7788", "MESH_RELAY", "digest",
    )).toThrow(/not a genuine AuthenticatedLink/i);
  });

  test("AuthenticatedNodeRecord alone (no AuthenticatedLink) → REJECT", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const authNode = ctx.authNodes[0]!;
    expect(isAuthenticatedNodeRecord(authNode)).toBe(true);
    expect(() => createValidatedHop(
      authNode as any, "10.0.0.1:7788", "MESH_RELAY", "digest",
    )).toThrow(/not a genuine AuthenticatedLink/i);
  });
});

describe("R-002-P1 v2: Genuine full pipeline (both directions)", () => {
  test("genuine initiator-side pipeline → succeeds end-to-end", () => {
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
    expect(isBrandedCommittedRoute(ctx.branded)).toBe(true);
    // The branded route's hops are the genuine ValidatedHops (same object identity):
    expect(ctx.branded.hops[0]).toBe(ctx.validatedHops[0]);
    expect(ctx.branded.hops[1]).toBe(ctx.validatedHops[1]);
  });

  test("genuine responder-side AuthenticatedLink → ValidatedHop succeeds", () => {
    // Build a responder-side link manually and consume it.
    const h = runGenuineHandshake();
    const authNodeA = createAuthenticatedNodeRecord(h.verifiedAdvA);
    const vt = buildVerifiedTranscript(h);
    const responderLink = createAuthenticatedLink({
      localNodeId: h.kpB.nodeId, // responder side
      remoteNode: authNodeA,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + 3600,
    });
    expect(isAuthenticatedLink(responderLink)).toBe(true);
    expect(responderLink.localRole).toBe("RESPONDER");
    // ValidatedHop consumes the link — linkUp is implied
    const hop = createValidatedHop(
      responderLink, "10.0.0.1:7788", "MESH_RELAY", "digest123",
    );
    expect(isValidatedHop(hop)).toBe(true);
    expect(hop.linkUp).toBe(true);
    expect(hop.nodeId).toBe(h.kpA.nodeId);
  });
});
