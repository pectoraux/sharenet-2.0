/**
 * ShareNet 2.0 — Route Objects (R-003: repaired acceptance binding).
 *
 * Per R-003 requirement, RouteAcceptance now cryptographically binds:
 *   proposal_digest (the exact route being accepted)
 *   hop_index (which hop this acceptance is for)
 *   hop_digest (the exact hop descriptor — nodeId, capability, endpoint, linkUp)
 *   service_digest (the exact service agreement terms)
 *   acceptor_node_id (who is accepting)
 *   acceptance_nonce (fresh per-acceptance nonce)
 *   expiry (when the acceptance expires)
 *
 * The acceptance signature proves:
 *   "Node X, occupying hop N, accepts this exact route proposal, this exact
 *    role, and these exact negotiated service terms until this expiry."
 *
 * Per R-003: immutable canonical artifacts. Digests are computed once
 * and carried explicitly. Verification compares the carried digest.
 * No TOCTOU — the verifier does not recompute digests from mutable objects.
 *
 * Per R-004 (merged into R-003E): createRouteCommitment MUST verify every
 * acceptance signature before issuing a CommittedRoute.
 *
 * Per spec/00 §31: topology/Dijkstra → route is FORBIDDEN.
 * Per spec/00 §31: RouteProposal → ActiveCircuit (without commitment) is FORBIDDEN.
 */

import { signMessage, verifySignature, type NodeCapability } from "../identity/keys";
import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { canonicalEncode, toHex } from "../encoding/cbor";
import { proposalDigest, hopDigest, serviceDigest } from "./digests";
import type { ServiceAgreement } from "./service-negotiation";
import { registerRouteCommitment } from "../transport/validated-types";

// Re-export ServiceAgreement type for convenience
export type { ServiceAgreement } from "./service-negotiation";

// -----------------------------------------------------------------------
// Domain tags (FROZEN per spec/14 §4 + ADR-0017)
// -----------------------------------------------------------------------

export const ROUTE_PROPOSAL_DOMAIN = "SHARENET/ROUTE/PROPOSAL/1";
export const ROUTE_ACCEPTANCE_DOMAIN = "SHARENET/ROUTE/ACCEPTANCE/1";
export const ROUTE_COMMITMENT_DOMAIN = "SHARENET/ROUTE/COMMITMENT/1";

// -----------------------------------------------------------------------
// Hop (a single hop in a route)
// -----------------------------------------------------------------------

export interface RouteHop {
  nodeId: string;
  capability: NodeCapability;
  endpoint: string;
  linkUp: boolean;
  serviceAgreement?: ServiceAgreement;
}

// -----------------------------------------------------------------------
// RouteProposal
// -----------------------------------------------------------------------

export interface RouteProposal {
  routeId: string;
  hops: RouteHop[];
  requirementDigest: string;
  expiry: number;
  initiatorNodeId: string;
  agreementDigest: string;
}

export function routeProposalSigningPayload(proposal: RouteProposal): Uint8Array {
  const m = new Map<number, unknown>([
    [1, proposal.routeId],
    [2, proposal.hops.map((h) => h.nodeId)],
    [3, proposal.requirementDigest],
    [4, proposal.expiry],
    [5, proposal.initiatorNodeId],
    [6, proposal.agreementDigest],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(ROUTE_PROPOSAL_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

export function createRouteProposal(
  proposal: RouteProposal,
  initiatorSecretKey: Uint8Array,
): SignedRouteProposal {
  const payload = routeProposalSigningPayload(proposal);
  const signature = signMessage(initiatorSecretKey, payload);
  return { proposal, initiatorSignature: signature };
}

export interface SignedRouteProposal {
  proposal: RouteProposal;
  initiatorSignature: Uint8Array;
}

// -----------------------------------------------------------------------
// RouteAcceptance (R-003C: fully bound)
// -----------------------------------------------------------------------

/**
 * A RouteAcceptance is a hop's signed agreement to participate in the route.
 *
 * Per R-003: the acceptance MUST bind:
 *   - proposal_digest: the exact route proposal being accepted
 *   - hop_index: which hop this acceptance is for
 *   - hop_digest: the exact hop descriptor (nodeId, capability, endpoint, linkUp)
 *   - service_digest: the exact service agreement terms
 *   - acceptor_node_id: who is accepting
 *   - acceptance_nonce: fresh per-acceptance nonce (16 bytes)
 *   - expiry: when the acceptance expires
 *
 * The acceptance signature proves:
 *   "Node X, occupying hop N, accepts this exact route proposal, this exact
 *    role, and these exact negotiated service terms until this expiry."
 *
 * Mutating ANY of these fields invalidates the signature.
 */
export interface RouteAcceptance {
  proposalDigestHex: string;     // BLAKE3-256 of the canonical RouteProposal
  hopIndex: number;              // which hop this acceptance is for
  hopDigestHex: string;           // BLAKE3-256 of the canonical HopDescriptor
  serviceDigestHex: string;      // BLAKE3-256 of the canonical ServiceAgreement
  acceptorNodeId: string;        // who is accepting
  acceptanceNonce: Uint8Array;    // 16 random bytes (fresh per acceptance)
  expiry: number;                // unix seconds
  signature: Uint8Array;          // Ed25519 by acceptor over the payload
}

/**
 * Compute the signing payload for a RouteAcceptance.
 *
 * payload = domain || proposal_digest || hop_index || hop_digest || service_digest || acceptor_node_id || nonce || expiry
 */
export function routeAcceptanceSigningPayload(
  proposalDigestBytes: Uint8Array,
  hopIndex: number,
  hopDigestBytes: Uint8Array,
  serviceDigestBytes: Uint8Array,
  acceptorNodeId: string,
  acceptanceNonce: Uint8Array,
  expiry: number,
): Uint8Array {
  const domain = new TextEncoder().encode(ROUTE_ACCEPTANCE_DOMAIN);
  const acceptorBytes = new TextEncoder().encode(acceptorNodeId);
  const hopIndexBuf = new Uint8Array(4);
  new DataView(hopIndexBuf.buffer).setUint32(0, hopIndex, false);
  const expiryBuf = new Uint8Array(8);
  const expiryView = new DataView(expiryBuf.buffer);
  expiryView.setUint32(0, Math.floor(expiry / 0x100000000), false);
  expiryView.setUint32(4, expiry & 0xFFFFFFFF, false);

  const totalLen = domain.length + 32 + 4 + 32 + 32 + acceptorBytes.length + 16 + 8;
  const out = new Uint8Array(totalLen);
  let off = 0;
  out.set(domain, off); off += domain.length;
  out.set(proposalDigestBytes, off); off += 32;
  out.set(hopIndexBuf, off); off += 4;
  out.set(hopDigestBytes, off); off += 32;
  out.set(serviceDigestBytes, off); off += 32;
  out.set(acceptorBytes, off); off += acceptorBytes.length;
  out.set(acceptanceNonce, off); off += 16;
  out.set(expiryBuf, off);
  return out;
}

/**
 * Sign a RouteAcceptance. The acceptor signs over:
 *   proposal_digest + hop_index + hop_digest + service_digest + acceptor_node_id + nonce + expiry
 *
 * The digests are computed from the immutable canonical CBOR of the
 * RouteProposal and HopDescriptor. They are carried as fixed 32-byte
 * values in the acceptance — no TOCTOU.
 */
export function signRouteAcceptance(
  proposal: RouteProposal,
  hopIndex: number,
  hop: RouteHop,
  serviceAgreement: ServiceAgreement,
  acceptorNodeId: string,
  acceptorSecretKey: Uint8Array,
  expiry: number,
): RouteAcceptance {
  const proposalDigestBytes = proposalDigest(proposal);
  const hopDigestBytes = hopDigest(hop);
  const serviceDigestBytes = serviceDigest(serviceAgreement);
  const nonce = randomBytes(16);

  const payload = routeAcceptanceSigningPayload(
    proposalDigestBytes, hopIndex, hopDigestBytes, serviceDigestBytes,
    acceptorNodeId, nonce, expiry,
  );
  const signature = signMessage(acceptorSecretKey, payload);

  return {
    proposalDigestHex: toHex(proposalDigestBytes),
    hopIndex,
    hopDigestHex: toHex(hopDigestBytes),
    serviceDigestHex: toHex(serviceDigestBytes),
    acceptorNodeId,
    acceptanceNonce: nonce,
    expiry,
    signature,
  };
}

/**
 * Verify a RouteAcceptance signature against the acceptor's public key.
 *
 * Per R-003D: cryptographic acceptance verification.
 * The verification uses the CARRIED digests (proposalDigestHex, hopDigestHex,
 * serviceDigestHex) — it does NOT recompute them from mutable objects.
 * This prevents TOCTOU: the digests were frozen at signing time and are
 * compared as-is.
 */
export function verifyRouteAcceptance(
  acceptance: RouteAcceptance,
  acceptorPublicKey: Uint8Array,
): boolean {
  const proposalDigestBytes = fromHexCompat(acceptance.proposalDigestHex);
  const hopDigestBytes = fromHexCompat(acceptance.hopDigestHex);
  const serviceDigestBytes = fromHexCompat(acceptance.serviceDigestHex);

  const payload = routeAcceptanceSigningPayload(
    proposalDigestBytes, acceptance.hopIndex, hopDigestBytes, serviceDigestBytes,
    acceptance.acceptorNodeId, acceptance.acceptanceNonce, acceptance.expiry,
  );
  return verifySignature(acceptorPublicKey, payload, acceptance.signature);
}

/**
 * Verify that a RouteAcceptance matches the expected proposal and hop.
 * Compares the CARRIED digests against freshly-computed ones from the
 * immutable canonical objects. This is the binding check — it ensures
 * the acceptance was signed over EXACTLY this proposal + hop + service.
 *
 * Per R-003D test requirement:
 *   modify proposal → digest mismatch → FAIL
 *   modify hop → digest mismatch → FAIL
 *   modify service agreement → digest mismatch → FAIL
 */
export function verifyAcceptanceBinding(
  acceptance: RouteAcceptance,
  proposal: RouteProposal,
  hopIndex: number,
  hop: RouteHop,
  serviceAgreement: ServiceAgreement,
): { ok: true } | { ok: false; reason: string } {
  if (acceptance.hopIndex !== hopIndex) {
    return { ok: false, reason: `hopIndex mismatch: expected ${hopIndex}, got ${acceptance.hopIndex}` };
  }

  const expectedProposalDigest = toHex(proposalDigest(proposal));
  if (acceptance.proposalDigestHex !== expectedProposalDigest) {
    return { ok: false, reason: `proposal digest mismatch: expected ${expectedProposalDigest.slice(0, 16)}..., got ${acceptance.proposalDigestHex.slice(0, 16)}...` };
  }

  const expectedHopDigest = toHex(hopDigest(hop));
  if (acceptance.hopDigestHex !== expectedHopDigest) {
    return { ok: false, reason: `hop digest mismatch: expected ${expectedHopDigest.slice(0, 16)}..., got ${acceptance.hopDigestHex.slice(0, 16)}...` };
  }

  const expectedServiceDigest = toHex(serviceDigest(serviceAgreement));
  if (acceptance.serviceDigestHex !== expectedServiceDigest) {
    return { ok: false, reason: `service digest mismatch: expected ${expectedServiceDigest.slice(0, 16)}..., got ${acceptance.serviceDigestHex.slice(0, 16)}...` };
  }

  return { ok: true };
}

// -----------------------------------------------------------------------
// Commitment Root (R-003/R-004 canonical commitment model)
// -----------------------------------------------------------------------

/**
 * Compute the canonical commitment_root over a proposal + ordered acceptances
 * + commitment_nonce.
 *
 * Per spec/07 §5.3:
 *   commitment_root = BLAKE3-256(
 *     proposal_digest       (32 bytes — BLAKE3 of canonical RouteProposal)
 *     || acceptance_root   (32 bytes — BLAKE3 of ordered acceptance signatures)
 *     || commitment_nonce  (16 bytes — fresh per commitment)
 *   )
 *
 * The commitment_root IS the route's canonical identity. route_id is derived
 * from it: route_id = toHex(commitment_root). This prevents two different
 * route contents from sharing the same route_id merely because they share a
 * caller-chosen proposal identifier.
 */
export function computeCommitmentRoot(
  proposal: RouteProposal,
  acceptances: RouteAcceptance[],
  commitmentNonce: Uint8Array,
): Uint8Array {
  // 1. proposal_digest (already computed by proposalDigest())
  const proposalDigestBytes = proposalDigest(proposal);

  // 2. acceptance_root = BLAKE3(ordered(acceptance signatures))
  //    Each acceptance's signature is the canonical representation of the
  //    acceptor's signed agreement. The ordered concatenation of these
  //    signatures binds every participant's acceptance into the root.
  const h = blake3.create({ dkLen: 32 });
  for (const acc of acceptances) {
    h.update(acc.signature);
  }
  const acceptanceRoot = h.digest();

  // 3. commitment_root = BLAKE3(proposal_digest || acceptance_root || commitment_nonce)
  const rootHash = blake3(
    new Uint8Array([
      ...proposalDigestBytes,
      ...acceptanceRoot,
      ...commitmentNonce,
    ]),
    { dkLen: 32 },
  );
  return rootHash;
}

/**
 * Derive the canonical route_id from a commitment_root.
 * Per spec/07 §5.4: route_id = toHex(commitment_root).
 */
export function deriveRouteId(commitmentRoot: Uint8Array): string {
  return toHex(commitmentRoot);
}

// -----------------------------------------------------------------------
// RouteCommitment (R-003E/R-004: verifies signatures + canonical commitment_root)
// -----------------------------------------------------------------------

export interface RouteCommitment {
  /**
   * The canonical route identity — DERIVED from commitmentRoot.
   * Per R-003/R-004: route_id = toHex(commitment_root).
   * This is NOT the proposal's routeId; it is the cryptographic commitment
   * to the exact accepted route.
   */
  routeId: string;
  proposal: RouteProposal;
  acceptances: RouteAcceptance[];
  /**
   * The canonical commitment_root (32 bytes).
   * Per spec/07 §5.3: BLAKE3-256(proposal_digest || acceptance_root || commitment_nonce).
   */
  commitmentRoot: Uint8Array;
  /**
   * Fresh per-commitment nonce (16 bytes). Included in the commitment_root
   * derivation to ensure each commitment is unique even with identical
   * proposal + acceptances.
   */
  commitmentNonce: Uint8Array;
  committerSignature: Uint8Array;
  committedAt: number;
}

/**
 * Acceptance verification result (for R-004).
 */
export interface AcceptanceVerificationResult {
  hopIndex: number;
  signatureValid: boolean;
  bindingValid: boolean;
  reason?: string;
}

/**
 * Create a RouteCommitment from a proposal + all acceptances.
 *
 * Per R-003E/R-004: this function MUST verify every acceptance signature
 * AND every acceptance binding before issuing a CommittedRoute.
 *
 * The only legal pipeline:
 *   for each hop:
 *     resolve authentic public key
 *     ↓
 *   verify RouteAcceptance signature
 *     ↓
 *   validate acceptance against proposal digest
 *     ↓
 *   validate hop binding
 *     ↓
 *   validate service agreement binding
 *     ↓
 *   validate expiry
 *     ↓
 *   commit
 */
export function createRouteCommitment(
  proposal: RouteProposal,
  acceptances: RouteAcceptance[],
  hopPublicKeys: Map<string, Uint8Array>, // nodeId → public key
  serviceAgreements: Map<number, ServiceAgreement>, // hopIndex → agreement
  committerSecretKey: Uint8Array,
  now: number,
): { ok: true; commitment: RouteCommitment; verificationResults: AcceptanceVerificationResult[] } | { ok: false; reason: string; verificationResults: AcceptanceVerificationResult[] } {
  // 1. Check every hop has an acceptance
  if (acceptances.length !== proposal.hops.length) {
    return {
      ok: false,
      reason: `expected ${proposal.hops.length} acceptances, got ${acceptances.length}`,
      verificationResults: [],
    };
  }

  const verificationResults: AcceptanceVerificationResult[] = [];

  // 2. Verify each acceptance
  for (let i = 0; i < proposal.hops.length; i++) {
    const hop = proposal.hops[i]!;
    const acc = acceptances[i]!;
    const result: AcceptanceVerificationResult = {
      hopIndex: i,
      signatureValid: false,
      bindingValid: false,
    };

    // 2a. Check hopIndex
    if (acc.hopIndex !== i) {
      result.reason = `acceptance ${i} has wrong hopIndex ${acc.hopIndex}`;
      verificationResults.push(result);
      return { ok: false, reason: result.reason, verificationResults };
    }

    // 2b. Check acceptorNodeId matches hop
    if (acc.acceptorNodeId !== hop.nodeId) {
      result.reason = `acceptance ${i} acceptor ${acc.acceptorNodeId} != hop ${hop.nodeId}`;
      verificationResults.push(result);
      return { ok: false, reason: result.reason, verificationResults };
    }

    // 2c. Check expiry
    if (acc.expiry <= now) {
      result.reason = `acceptance ${i} expired`;
      verificationResults.push(result);
      return { ok: false, reason: result.reason, verificationResults };
    }

    // 2d. Resolve public key
    const pubKey = hopPublicKeys.get(hop.nodeId);
    if (!pubKey) {
      result.reason = `no public key for hop ${i} (${hop.nodeId})`;
      verificationResults.push(result);
      return { ok: false, reason: result.reason, verificationResults };
    }

    // 2e. Verify signature (R-004: mandatory)
    const sigOk = verifyRouteAcceptance(acc, pubKey);
    result.signatureValid = sigOk;
    if (!sigOk) {
      result.reason = `acceptance ${i} signature invalid`;
      verificationResults.push(result);
      return { ok: false, reason: result.reason, verificationResults };
    }

    // 2f. Verify binding (R-003D: the acceptance was signed over EXACTLY this proposal + hop)
    const serviceAgreement = serviceAgreements.get(i);
    if (!serviceAgreement) {
      result.reason = `no service agreement for hop ${i}`;
      verificationResults.push(result);
      return { ok: false, reason: result.reason, verificationResults };
    }

    const bindingResult = verifyAcceptanceBinding(acc, proposal, i, hop, serviceAgreement);
    result.bindingValid = bindingResult.ok;
    if (!bindingResult.ok) {
      result.reason = bindingResult.reason;
      verificationResults.push(result);
      return { ok: false, reason: result.reason, verificationResults };
    }

    // 2g. Check no hop is ADV_VERIFIED-only (all must be LINK_UP)
    if (!hop.linkUp) {
      result.reason = `hop ${i} (${hop.nodeId}) is not LINK_UP`;
      verificationResults.push(result);
      return { ok: false, reason: result.reason, verificationResults };
    }

    verificationResults.push(result);
  }

  // 3. All verifications passed — compute the canonical commitment_root.
  // Per R-003/R-004: the commitment_root IS the route's canonical identity.
  // It binds the proposal + all ordered acceptances + a fresh commitment_nonce.
  const commitmentNonce = randomBytes(16);
  const commitmentRoot = computeCommitmentRoot(proposal, acceptances, commitmentNonce);
  const routeId = deriveRouteId(commitmentRoot);

  // 4. Sign the commitment_root (NOT the proposal's routeId or acceptance signatures).
  // Per spec/07 §5.3: the source signs over the commitment_root, which transitively
  // binds the proposal + all acceptances + the commitment_nonce.
  const payload = routeCommitmentSigningPayload(commitmentRoot, commitmentNonce);
  const signature = signMessage(committerSecretKey, payload);

  const commitment: RouteCommitment = {
    routeId,
    proposal,
    acceptances,
    commitmentRoot,
    commitmentNonce,
    committerSignature: signature,
    committedAt: now,
  };

  // R-006H3: Register the genuine RouteCommitment in the private WeakSet.
  // This allows isRouteCommitment() to verify it was produced through
  // this function (which verified all signatures + bindings).
  registerRouteCommitment(commitment);

  return {
    ok: true,
    commitment,
    verificationResults,
  };
}

/**
 * Compute the signing payload for a RouteCommitment.
 *
 * Per R-003/R-004: the committer signs over the commitment_root +
 * commitment_nonce. This transitively binds:
 *   - the proposal (via proposal_digest in commitment_root)
 *   - all ordered acceptances (via acceptance_root in commitment_root)
 *   - the commitment_nonce (fresh per commitment)
 *
 * payload = domain || commitment_root (32 bytes) || commitment_nonce (16 bytes)
 */
function routeCommitmentSigningPayload(
  commitmentRoot: Uint8Array,
  commitmentNonce: Uint8Array,
): Uint8Array {
  const domain = new TextEncoder().encode(ROUTE_COMMITMENT_DOMAIN);
  const out = new Uint8Array(domain.length + 32 + 16);
  out.set(domain, 0);
  out.set(commitmentRoot, domain.length);
  out.set(commitmentNonce, domain.length + 32);
  return out;
}

// -----------------------------------------------------------------------
// CommittedRoute
// -----------------------------------------------------------------------

export interface CommittedRoute {
  /** The canonical route identity — DERIVED from commitment_root. */
  routeId: string;
  hops: RouteHop[];
  expiry: number;
  initiatorNodeId: string;
  agreementDigest: string;
  committedAt: number;
  /**
   * The canonical commitment_root (32 bytes).
   * Per R-003/R-004: this is the cryptographic anchor binding the exact
   * accepted route. Carried through to the circuit layer.
   */
  commitmentRoot: Uint8Array;
}

export function createCommittedRoute(commitment: RouteCommitment): CommittedRoute {
  return {
    routeId: commitment.routeId,
    hops: commitment.proposal.hops,
    expiry: commitment.proposal.expiry,
    initiatorNodeId: commitment.proposal.initiatorNodeId,
    agreementDigest: commitment.proposal.agreementDigest,
    committedAt: commitment.committedAt,
    commitmentRoot: commitment.commitmentRoot,
  };
}

// -----------------------------------------------------------------------
// Architecture guards
// -----------------------------------------------------------------------

export function TOPOLOGY_TO_ROUTE_FORBIDDEN(topologyData: unknown): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create a CommittedRoute from topology/Dijkstra ` +
      `output without the full RouteProposal → RouteAcceptance → RouteCommitment pipeline. ` +
      `Per spec/00 §31 and spec/07, topology output is discovery metadata only — ` +
      `it is NOT an executable route. Each hop MUST independently accept the route.`,
  );
}

export function PROPOSAL_TO_CIRCUIT_FORBIDDEN(proposal: RouteProposal): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create a circuit from RouteProposal ` +
      `(routeId=${proposal.routeId}) without a RouteCommitment. ` +
      `Per spec/00 §31, a circuit can ONLY be created from a CommittedRoute.`,
  );
}

// -----------------------------------------------------------------------
// Internal helper
// -----------------------------------------------------------------------

function fromHexCompat(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error(`invalid hex length: ${hex.length}`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) throw new Error(`invalid hex byte at offset ${i * 2}`);
    out[i] = b;
  }
  return out;
}
