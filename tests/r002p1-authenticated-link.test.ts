/**
 * ShareNet 2.0 — R-002-P1: AuthenticatedLink proof artifact (hardened v3).
 *
 * Per the R-002-P1 hardening audit v3, this version closes the final
 * two semantic gaps:
 *
 *   1. WIRE/MESSAGE BINDING: createVerifiedTranscript now derives ALL
 *      trusted inputs from decoded Initiate/Accept wire bytes. The only
 *      non-wire input is proofA (from the Confirm message).
 *   2. USE-TIME FRESHNESS: createValidatedHop now takes `now` and
 *      enforces link.expiresAt > now.
 *   3. FRESHNESS PROVENANCE: createAuthenticatedLink enforces that the
 *      link is established within a bounded window of the transcript's
 *      verification time.
 *
 * Adversarial tests (per auditor spec):
 *   - wire nonce tampered → reject (LinkId changes, proofs fail)
 *   - wire challenge tampered → reject (proofs fail)
 *   - wire proof tampered → reject
 *   - stale AuthenticatedLink → cannot create ValidatedHop
 *   - replayed handshake evidence → reject (stale transcript age)
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
  isLinkFresh,
  LINK_MAX_LIFETIME_SECONDS,
  MAX_TRANSCRIPT_AGE_SECONDS,
  LINK_CLOCK_SKEW_SECONDS,
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

/** Build a genuine VerifiedTranscript from the handshake materials (v3 API). */
function buildVerifiedTranscript(h: ReturnType<typeof runGenuineHandshake>) {
  return createVerifiedTranscript({
    initiateBytes: h.initiateBytes,
    acceptBytes: h.acceptBytes,
    proofA: h.proofA,
    verifiedAt: NOW,
  });
}

describe("R-002-P1 v3: VerifiedTranscript — wire/message binding", () => {
  test("genuine handshake → VerifiedTranscript succeeds (all inputs from wire)", () => {
    const h = runGenuineHandshake();
    const vt = buildVerifiedTranscript(h);
    expect(isVerifiedTranscript(vt)).toBe(true);
    expect(vt.initiatorNodeId).toBe(h.kpA.nodeId);
    expect(vt.responderNodeId).toBe(h.kpB.nodeId);
    expect(vt.linkIdHex).toBe(bytesToHex(h.linkIdBytes));
    // Nonces are derived from the decoded wire messages
    expect(vt.initiatorNonce).toEqual(h.linkNonceA);
    expect(vt.responderNonce).toEqual(h.linkNonceB);
  });

  test("tampered Initiate wire bytes (nonce changed) → REJECT (proofs fail)", () => {
    const h = runGenuineHandshake();
    // Tamper with the Initiate bytes — changes the decoded nonce AND the transcript hash
    const tamperedInitiate = new Uint8Array(h.initiateBytes);
    tamperedInitiate[10] ^= 0x01;
    expect(() => createVerifiedTranscript({
      initiateBytes: tamperedInitiate,
      acceptBytes: h.acceptBytes,
      proofA: h.proofA,
      verifiedAt: NOW,
    })).toThrow();
  });

  test("tampered Accept wire bytes (challenge changed) → REJECT", () => {
    const h = runGenuineHandshake();
    const tamperedAccept = new Uint8Array(h.acceptBytes);
    tamperedAccept[5] ^= 0x01;
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes,
      acceptBytes: tamperedAccept,
      proofA: h.proofA,
      verifiedAt: NOW,
    })).toThrow();
  });

  test("wrong proofA (mismatched) → REJECT", () => {
    const h = runGenuineHandshake();
    // Use a proofA from a DIFFERENT handshake
    const h2 = runGenuineHandshake();
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes,
      acceptBytes: h.acceptBytes,
      proofA: h2.proofA, // wrong proof
      verifiedAt: NOW,
    })).toThrow(/initiator's possession proof did not verify/i);
  });

  test("wrong proofB (from different handshake's Accept) → REJECT", () => {
    const h = runGenuineHandshake();
    const h2 = runGenuineHandshake();
    // Use h2's Accept bytes (different proofB, different nonces)
    expect(() => createVerifiedTranscript({
      initiateBytes: h.initiateBytes,
      acceptBytes: h2.acceptBytes, // different Accept → different proofB/nonces
      proofA: h.proofA,
      verifiedAt: NOW,
    })).toThrow();
  });

  test("expired advertisement in Initiate → REJECT (adv freshness verified)", () => {
    // Build a handshake with an already-expired advertisement
    const kpA = generateNodeKeypair();
    const kpB = generateNodeKeypair();
    const expiredAdv = signAdvertisement({
      protocolVersion: 1, nodeId: kpA.nodeId, signingPublicKey: kpA.publicKey,
      capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
      sequence: 1, timestamp: NOW - 7200, expiry: NOW - 3600, // expired
      nonce: randomBytes(16),
    }, kpA.secretKey);
    const advB = signAdvertisement({
      protocolVersion: 1, nodeId: kpB.nodeId, signingPublicKey: kpB.publicKey,
      capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.2", port: 7789 }],
      sequence: 1, timestamp: NOW, expiry: NOW + 3600, nonce: randomBytes(16),
    }, kpB.secretKey);

    const initiateMsg: InitiateMessage = {
      kind: 1, advertisementHex: advertisementToHex(expiredAdv),
      linkNonceA: randomBytes(16), challengeForB: randomBytes(32),
    };
    const initiateBytes = encodeInitiate(initiateMsg);
    const acceptMsg: AcceptMessage = {
      kind: 2, advertisementHex: advertisementToHex(advB),
      linkNonceB: randomBytes(16), challengeForA: randomBytes(32), proofB: new Uint8Array(64),
    };
    const acceptBytes = encodeAccept(acceptMsg);

    expect(() => createVerifiedTranscript({
      initiateBytes, acceptBytes, proofA: new Uint8Array(64), verifiedAt: NOW,
    })).toThrow(/advertisement verification failed/i);
  });
});

describe("R-002-P1 v3: AuthenticatedLink — freshness provenance + symmetry", () => {
  test("genuine initiator-side AuthenticatedLink → succeeds (localRole=INITIATOR)", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    const link = createAuthenticatedLink({
      localNodeId: h.kpA.nodeId,
      remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + 3600,
    });
    expect(isAuthenticatedLink(link)).toBe(true);
    expect(link.localRole).toBe("INITIATOR");
    expect(link.transcriptVerifiedAt).toBe(NOW);
  });

  test("genuine responder-side AuthenticatedLink → succeeds (localRole=RESPONDER)", () => {
    const h = runGenuineHandshake();
    const authNodeA = createAuthenticatedNodeRecord(h.verifiedAdvA);
    const vt = buildVerifiedTranscript(h);
    const link = createAuthenticatedLink({
      localNodeId: h.kpB.nodeId,
      remoteNode: authNodeA,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + 3600,
    });
    expect(isAuthenticatedLink(link)).toBe(true);
    expect(link.localRole).toBe("RESPONDER");
  });

  test("stale transcript (establishedAt > verifiedAt + MAX_TRANSCRIPT_AGE) → REJECT", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    // Try to establish the link long after the transcript was verified
    const staleEstablishedAt = NOW + MAX_TRANSCRIPT_AGE_SECONDS + 1;
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: staleEstablishedAt, expiresAt: staleEstablishedAt + 3600,
    })).toThrow(/exceeding the maximum freshness window/i);
  });

  test("future-dated establishment (establishedAt < verifiedAt - SKEW) → REJECT", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    const futureEstablishedAt = NOW - LINK_CLOCK_SKEW_SECONDS - 1;
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: futureEstablishedAt, expiresAt: futureEstablishedAt + 3600,
    })).toThrow(/clock skew tolerance/i);
  });

  test("boundary: establishedAt exactly at MAX_TRANSCRIPT_AGE → ACCEPT", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    const boundaryEstablishedAt = NOW + MAX_TRANSCRIPT_AGE_SECONDS;
    const link = createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: boundaryEstablishedAt, expiresAt: boundaryEstablishedAt + 3600,
    });
    expect(isAuthenticatedLink(link)).toBe(true);
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

  test("non-genuine AuthenticatedNodeRecord → REJECT", () => {
    const h = runGenuineHandshake();
    const vt = buildVerifiedTranscript(h);
    const fakeNode = { nodeId: h.kpB.nodeId, publicKey: h.kpB.publicKey };
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: fakeNode as any,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/not a genuine AuthenticatedNodeRecord/i);
  });

  test("local not a transcript participant → REJECT", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    const stranger = generateNodeKeypair();
    expect(() => createAuthenticatedLink({
      localNodeId: stranger.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt, establishedAt: NOW, expiresAt: NOW + 3600,
    })).toThrow(/is neither the initiator/i);
  });

  test("lifetime > LINK_MAX_LIFETIME → REJECT", () => {
    const h = runGenuineHandshake();
    const authNodeB = createAuthenticatedNodeRecord(h.verifiedAdvB);
    const vt = buildVerifiedTranscript(h);
    expect(() => createAuthenticatedLink({
      localNodeId: h.kpA.nodeId, remoteNode: authNodeB,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + LINK_MAX_LIFETIME_SECONDS + 1,
    })).toThrow(/exceeds the maximum/i);
  });
});

describe("R-002-P1 v3: ValidatedHop — use-time freshness enforced", () => {
  test("genuine fresh AuthenticatedLink → ValidatedHop succeeds", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const link = ctx.authenticatedLinks[0]!;
    const hop = createValidatedHop(
      link, ctx.hops[0]!.endpoint, ctx.capabilities[0]!,
      ctx.validatedHops[0]!.serviceAgreementDigest, NOW,
    );
    expect(isValidatedHop(hop)).toBe(true);
    expect(hop.linkUp).toBe(true);
  });

  test("stale AuthenticatedLink (expiresAt <= now) → cannot create ValidatedHop", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const link = ctx.authenticatedLinks[0]!;
    // The link expires at NOW + 3600. Use a `now` that's past the expiry.
    const staleNow = link.expiresAt + 1;
    expect(() => createValidatedHop(
      link, ctx.hops[0]!.endpoint, ctx.capabilities[0]!,
      ctx.validatedHops[0]!.serviceAgreementDigest, staleNow,
    )).toThrow(/expired/i);
  });

  test("boundary: now exactly == expiresAt → REJECT (strictly greater required)", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const link = ctx.authenticatedLinks[0]!;
    const boundaryNow = link.expiresAt; // exactly at expiry
    expect(() => createValidatedHop(
      link, ctx.hops[0]!.endpoint, ctx.capabilities[0]!,
      ctx.validatedHops[0]!.serviceAgreementDigest, boundaryNow,
    )).toThrow(/expired/i);
  });

  test("isLinkFresh helper: fresh → true, stale → false", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const link = ctx.authenticatedLinks[0]!;
    expect(isLinkFresh(link, NOW)).toBe(true);
    expect(isLinkFresh(link, link.expiresAt)).toBe(false);
    expect(isLinkFresh(link, link.expiresAt + 1)).toBe(false);
  });

  test("non-genuine object as link → REJECT", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const fakeLink = { ...ctx.authenticatedLinks[0]! };
    expect(isAuthenticatedLink(fakeLink)).toBe(false);
    expect(() => createValidatedHop(
      fakeLink as any, "10.0.0.1:7788", "MESH_RELAY", "digest", NOW,
    )).toThrow(/not a genuine AuthenticatedLink/i);
  });

  test("AuthenticatedNodeRecord alone → REJECT", () => {
    const ctx = makeGenuineBrandedRoute(1, NOW);
    const authNode = ctx.authNodes[0]!;
    expect(() => createValidatedHop(
      authNode as any, "10.0.0.1:7788", "MESH_RELAY", "digest", NOW,
    )).toThrow(/not a genuine AuthenticatedLink/i);
  });
});

describe("R-002-P1 v3: Genuine full pipeline (both directions)", () => {
  test("genuine initiator-side pipeline → succeeds end-to-end", () => {
    const ctx = makeGenuineBrandedRoute(2, NOW);
    expect(isAuthenticatedNodeRecord(ctx.authNodes[0]!)).toBe(true);
    expect(isAuthenticatedNodeRecord(ctx.authNodes[1]!)).toBe(true);
    expect(isVerifiedTranscript(ctx.verifiedTranscripts[0]!)).toBe(true);
    expect(isVerifiedTranscript(ctx.verifiedTranscripts[1]!)).toBe(true);
    expect(isAuthenticatedLink(ctx.authenticatedLinks[0]!)).toBe(true);
    expect(isAuthenticatedLink(ctx.authenticatedLinks[1]!)).toBe(true);
    expect(isValidatedHop(ctx.validatedHops[0]!)).toBe(true);
    expect(isValidatedHop(ctx.validatedHops[1]!)).toBe(true);
    expect(isBrandedCommittedRoute(ctx.branded)).toBe(true);
    // Same object identity — no cast
    expect(ctx.branded.hops[0]).toBe(ctx.validatedHops[0]);
    expect(ctx.branded.hops[1]).toBe(ctx.validatedHops[1]);
  });

  test("genuine responder-side AuthenticatedLink → ValidatedHop succeeds", () => {
    const h = runGenuineHandshake();
    const authNodeA = createAuthenticatedNodeRecord(h.verifiedAdvA);
    const vt = buildVerifiedTranscript(h);
    const responderLink = createAuthenticatedLink({
      localNodeId: h.kpB.nodeId,
      remoteNode: authNodeA,
      verifiedTranscript: vt,
      establishedAt: NOW, expiresAt: NOW + 3600,
    });
    expect(isAuthenticatedLink(responderLink)).toBe(true);
    expect(responderLink.localRole).toBe("RESPONDER");
    const hop = createValidatedHop(
      responderLink, "10.0.0.1:7788", "MESH_RELAY", "digest123", NOW,
    );
    expect(isValidatedHop(hop)).toBe(true);
    expect(hop.nodeId).toBe(h.kpA.nodeId);
  });
});
