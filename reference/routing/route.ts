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
  /**
   * Per R-003/R-004 final reconciliation: routeId is REMOVED from the
   * canonical proposal. The only route identity is the commitment_root
   * (derived from proposal + acceptances + nonce). A caller-chosen
   * pre-ID must NOT influence the final route_id.
   */
  hops: RouteHop[];
  requirementDigest: string;
  expiry: number;
  initiatorNodeId: string;
  agreementDigest: string;
}

export function routeProposalSigningPayload(proposal: RouteProposal): Uint8Array {
  const m = new Map<number, unknown>([
    [1, proposal.hops.map((h) => h.nodeId)],
    [2, proposal.requirementDigest],
    [3, proposal.expiry],
    [4, proposal.initiatorNodeId],
    [5, proposal.agreementDigest],
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
  return { proposal, signature };
}

/**
 * The canonical signed wire object carrying a RouteProposal and its source
 * signature.
 *
 * Per spec/schemas/routing-schemas.json (FROZEN):
 *   SignedRouteProposal = { proposal: RouteProposal, signature: bstr .size 64 }
 *
 * The signature is over the proposal signing payload (domain ||
 * canonicalEncode(proposal_fields)), NOT over a routeId.
 */
export interface SignedRouteProposal {
  proposal: RouteProposal;
  signature: Uint8Array;
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
// Commitment Root — Canonical Merkle Construction (FROZEN per spec/07 §5.3.1)
// -----------------------------------------------------------------------

/** Domain tag for the Merkle commitment construction (FROZEN). */
export const MERKLE_COMMITMENT_DOMAIN = "SHARENET/ROUTE/COMMITMENT/MERKLE/1";

/** Leaf-type byte: proposal (0x00). */
const LEAF_TYPE_PROPOSAL = 0x00;
/** Leaf-type byte: acceptance (0x01). */
const LEAF_TYPE_ACCEPTANCE = 0x01;
/** Node-type byte: internal/parent (0x02). */
const NODE_TYPE_INTERNAL = 0x02;

/**
 * Canonical CBOR encoding of a RouteProposal for the Merkle leaf.
 * Uses integer-keyed map per ADR-0004.
 */
function canonicalEncodeProposal(proposal: RouteProposal): Uint8Array {
  // Per R-003/R-004 final reconciliation: routeId is NOT included.
  // The Merkle leaf binds only the semantically-significant fields.
  const m = new Map<number, unknown>([
    [1, proposal.hops.map((h) => h.nodeId)],
    [2, proposal.hops.map((h) => h.capability)],
    [3, proposal.hops.map((h) => h.endpoint)],
    [4, proposal.hops.map((h) => h.linkUp)],
    [5, proposal.requirementDigest],
    [6, proposal.expiry],
    [7, proposal.initiatorNodeId],
    [8, proposal.agreementDigest],
  ]);
  return canonicalEncode(m);
}

/**
 * Canonical CBOR encoding of a RouteAcceptance for the Merkle leaf.
 * Uses integer-keyed map per ADR-0004.
 */
function canonicalEncodeAcceptance(acc: RouteAcceptance): Uint8Array {
  const m = new Map<number, unknown>([
    [1, acc.proposalDigestHex],
    [2, acc.hopIndex],
    [3, acc.hopDigestHex],
    [4, acc.serviceDigestHex],
    [5, acc.acceptorNodeId],
    [6, acc.acceptanceNonce],
    [7, acc.expiry],
    [8, acc.signature],
  ]);
  return canonicalEncode(m);
}

/**
 * Compute a Merkle leaf for the proposal.
 *
 * proposal_leaf = BLAKE3-256(
 *   utf8(MERKLE_COMMITMENT_DOMAIN) || u8(0x00) || canonicalEncode(RouteProposal)
 * )
 */
function computeProposalLeaf(proposal: RouteProposal): Uint8Array {
  const domain = new TextEncoder().encode(MERKLE_COMMITMENT_DOMAIN);
  const body = canonicalEncodeProposal(proposal);
  const input = new Uint8Array(domain.length + 1 + body.length);
  input.set(domain, 0);
  input[domain.length] = LEAF_TYPE_PROPOSAL;
  input.set(body, domain.length + 1);
  return blake3(input, { dkLen: 32 });
}

/**
 * Compute a Merkle leaf for an acceptance.
 *
 * acceptance_leaf_i = BLAKE3-256(
 *   utf8(MERKLE_COMMITMENT_DOMAIN) || u8(0x01) || u32be(i) || canonicalEncode(RouteAcceptance_i)
 * )
 */
function computeAcceptanceLeaf(acc: RouteAcceptance, hopIndex: number): Uint8Array {
  const domain = new TextEncoder().encode(MERKLE_COMMITMENT_DOMAIN);
  const body = canonicalEncodeAcceptance(acc);
  const indexBuf = new Uint8Array(4);
  new DataView(indexBuf.buffer).setUint32(0, hopIndex, false); // big-endian
  const input = new Uint8Array(domain.length + 1 + 4 + body.length);
  input.set(domain, 0);
  input[domain.length] = LEAF_TYPE_ACCEPTANCE;
  input.set(indexBuf, domain.length + 1);
  input.set(body, domain.length + 1 + 4);
  return blake3(input, { dkLen: 32 });
}

/**
 * Compute a Merkle parent from two children.
 *
 * parent = BLAKE3-256(
 *   utf8(MERKLE_COMMITMENT_DOMAIN) || u8(0x02) || left (32 bytes) || right (32 bytes)
 * )
 */
function computeParent(left: Uint8Array, right: Uint8Array): Uint8Array {
  const domain = new TextEncoder().encode(MERKLE_COMMITMENT_DOMAIN);
  const input = new Uint8Array(domain.length + 1 + 32 + 32);
  input.set(domain, 0);
  input[domain.length] = NODE_TYPE_INTERNAL;
  input.set(left, domain.length + 1);
  input.set(right, domain.length + 1 + 32);
  return blake3(input, { dkLen: 32 });
}

/**
 * Compute the canonical commitment_root via a Merkle tree.
 *
 * Per spec/07 §5.3.1 (FROZEN):
 *
 *   Leaves: [proposal_leaf, acceptance_leaf_0, acceptance_leaf_1, ...]
 *   Odd-node handling: duplicate the last node (standard "duplicate last").
 *   Single leaf: that leaf IS the root (no duplication).
 *
 * The commitment_nonce is NOT part of the Merkle tree — it is included
 * only in the source signature payload (see routeCommitmentSigningPayload).
 *
 * The commitment_root is the canonical cryptographic identity of the
 * accepted route.
 */
export function computeCommitmentRoot(
  proposal: RouteProposal,
  acceptances: RouteAcceptance[],
): Uint8Array {
  // 1. Build the leaf level.
  const leaves: Uint8Array[] = [computeProposalLeaf(proposal)];
  for (let i = 0; i < acceptances.length; i++) {
    leaves.push(computeAcceptanceLeaf(acceptances[i]!, i));
  }

  // 2. Build the tree bottom-up.
  let level = leaves;
  while (level.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = i + 1 < level.length ? level[i + 1]! : left; // duplicate last if odd
      nextLevel.push(computeParent(left, right));
    }
    level = nextLevel;
  }

  // 3. The single remaining node is the root.
  return level[0]!;
}

// -----------------------------------------------------------------------
// Merkle inclusion proof (R-009 Stage 2: portable gateway authorization)
// -----------------------------------------------------------------------

/**
 * A Merkle inclusion proof element.
 * Each element is a sibling hash + whether it's the left or right sibling.
 */
export interface MerkleProofElement {
  /** The sibling hash (32 bytes). */
  sibling: Uint8Array;
  /** Whether the sibling is on the left (true) or right (false). */
  isLeft: boolean;
}

/**
 * Generate a Merkle inclusion proof for a specific acceptance leaf.
 *
 * The proof is a list of (sibling, isLeft) elements from the leaf to the root.
 * The verifier recomputes the root by hashing the leaf with each sibling in order.
 *
 * @param proposal - the route proposal (for the proposal leaf)
 * @param acceptances - all acceptances (for the acceptance leaves)
 * @param hopIndex - which acceptance to generate the proof for
 * @returns the Merkle proof elements + the computed commitmentRoot
 */
export function generateMerkleInclusionProof(
  proposal: RouteProposal,
  acceptances: RouteAcceptance[],
  hopIndex: number,
): { proof: MerkleProofElement[]; commitmentRoot: Uint8Array } {
  // 1. Build the leaf level.
  const leaves: Uint8Array[] = [computeProposalLeaf(proposal)];
  for (let i = 0; i < acceptances.length; i++) {
    leaves.push(computeAcceptanceLeaf(acceptances[i]!, i));
  }

  // The target leaf is at index hopIndex + 1 (leaf 0 is the proposal).
  const targetIndex = hopIndex + 1;
  const proof: MerkleProofElement[] = [];

  // 2. Build the tree, recording siblings.
  let level = leaves;
  let currentIndex = targetIndex;
  while (level.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i]!;
      const right = i + 1 < level.length ? level[i + 1]! : left; // duplicate last if odd
      nextLevel.push(computeParent(left, right));

      // If the current node is at this pair, record the sibling.
      if (i === currentIndex || i + 1 === currentIndex) {
        if (currentIndex === i) {
          // Current is left, sibling is right.
          proof.push({ sibling: right, isLeft: false });
        } else {
          // Current is right, sibling is left.
          proof.push({ sibling: left, isLeft: true });
        }
      }
    }
    currentIndex = Math.floor(currentIndex / 2);
    level = nextLevel;
  }

  return { proof, commitmentRoot: level[0]! };
}

/**
 * Verify a Merkle inclusion proof.
 *
 * Recomputes the root from the leaf + the proof elements, then compares
 * against the expected commitmentRoot.
 *
 * @param leaf - the acceptance leaf hash (32 bytes)
 * @param proof - the Merkle proof elements
 * @param expectedCommitmentRoot - the expected commitment_root (32 bytes)
 * @returns true if the proof is valid (the leaf is included in the Merkle tree)
 */
export function verifyMerkleInclusionProof(
  leaf: Uint8Array,
  proof: MerkleProofElement[],
  expectedCommitmentRoot: Uint8Array,
): boolean {
  let hash = leaf;
  for (const element of proof) {
    if (element.isLeft) {
      // Sibling is on the left: parent = computeParent(sibling, hash)
      hash = computeParent(element.sibling, hash);
    } else {
      // Sibling is on the right: parent = computeParent(hash, sibling)
      hash = computeParent(hash, element.sibling);
    }
  }
  // Constant-time comparison with the expected root.
  if (hash.length !== expectedCommitmentRoot.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash[i]! ^ expectedCommitmentRoot[i]!;
  return diff === 0;
}

/**
 * Compute the acceptance leaf hash for a given acceptance + hopIndex.
 * Exported so the gateway verifier can compute it from the authorization fields.
 */
export function computeAcceptanceLeafForVerification(
  acceptance: RouteAcceptance,
  hopIndex: number,
): Uint8Array {
  return computeAcceptanceLeaf(acceptance, hopIndex);
}

/**
 * Derive the canonical route_id from a commitment_root.
 *
 * Per spec/07 §5.4 (FROZEN): route_id = "route:" + lowercase_hex(commitment_root).
 * The "route:" prefix distinguishes route identifiers from other hex-encoded
 * identifiers in the ShareNet ecosystem.
 */
export function deriveRouteId(commitmentRoot: Uint8Array): string {
  return "route:" + toHex(commitmentRoot);
}

// -----------------------------------------------------------------------
// Immutability helpers
// -----------------------------------------------------------------------

/**
 * Create a defensive copy of a Uint8Array.
 * The copy is NOT frozen here — deepFreeze handles freezing.
 * The copy ensures the caller cannot hold a reference to the internal buffer.
 */
function frozenCopy(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

/**
 * Deep-freeze an object and all its nested properties.
 * Used for RouteCommitment, CommittedRoute, and BrandedCommittedRoute.
 *
 * Note: TypedArrays (Uint8Array) are NOT frozen directly because
 * Object.freeze on a TypedArray throws in some runtimes (Bun). Instead,
 * byte arrays are defensive copies — the caller cannot hold a reference
 * to the internal buffer. The frozen outer object prevents replacing
 * the property reference.
 */
function deepFreeze<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") return obj;
  if (Object.isFrozen(obj)) return obj; // already frozen — skip
  // Skip TypedArrays (can't freeze in Bun; defensive copies suffice)
  if (obj instanceof Uint8Array) return obj;
  // Freeze arrays
  if (Array.isArray(obj)) {
    for (const item of obj) deepFreeze(item);
    return Object.freeze(obj) as T;
  }
  // Freeze plain objects
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    deepFreeze((obj as Record<string, unknown>)[key]);
  }
  return Object.freeze(obj) as T;
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
   * Per spec/07 §5.3.1 (FROZEN): Merkle root over
   * [proposal_leaf, acceptance_leaf_0, acceptance_leaf_1, ...].
   * Does NOT depend on commitmentNonce — the nonce is in the signature only.
   */
  commitmentRoot: Uint8Array;
  /**
   * Fresh per-commitment nonce (16 bytes). NOT part of the Merkle tree;
   * included only in the source signature payload to ensure each
   * commitment signature is unique.
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
  // Per spec/07 §5.3.1 (FROZEN): the commitment_root is a Merkle root over
  // [proposal_leaf, acceptance_leaf_0, ...]. It does NOT depend on the
  // commitment_nonce (the nonce is in the signature only).
  const commitmentRoot = computeCommitmentRoot(proposal, acceptances);
  const routeId = deriveRouteId(commitmentRoot);

  // 4. Generate the commitment_nonce + sign over commitment_root + nonce.
  // Per spec/07 §5.3.2: the source signs over the commitment_root and
  // commitment_nonce to ensure each commitment signature is unique.
  const commitmentNonce = randomBytes(16);
  const payload = routeCommitmentSigningPayload(commitmentRoot, commitmentNonce);
  const signature = signMessage(committerSecretKey, payload);

  // 5. Build the immutable commitment artifact.
  // Per R-003/R-004 hardening: the commitment is FROZEN — all byte arrays
  // are defensive copies and the entire object tree is deep-frozen.
  // This prevents post-registration mutation that would invalidate the
  // WeakSet trust guarantee.
  const commitment: RouteCommitment = deepFreeze({
    routeId,
    proposal: deepFreeze({ ...proposal, hops: Object.freeze(proposal.hops.map(h => deepFreeze({ ...h }))) }),
    acceptances: Object.freeze(acceptances.map(a => deepFreeze({
      ...a,
      acceptanceNonce: frozenCopy(a.acceptanceNonce),
      signature: frozenCopy(a.signature),
    }))) as unknown as RouteAcceptance[],
    commitmentRoot: frozenCopy(commitmentRoot),
    commitmentNonce: frozenCopy(commitmentNonce),
    committerSignature: frozenCopy(signature),
    committedAt: now,
  });

  // R-006H3: Register the genuine RouteCommitment in the private WeakSet.
  // This allows isRouteCommitment() to verify it was produced through
  // this function (which verified all signatures + bindings).
  // The object is FROZEN — post-registration mutation is impossible.
  registerRouteCommitment(commitment);

  return {
    ok: true,
    commitment,
    verificationResults,
  };
}

// -----------------------------------------------------------------------
// Independent verification (no WeakSet dependency)
// -----------------------------------------------------------------------

/**
 * Independently verify a RouteCommitment from the serialized commitment
 * and the source's public key alone.
 *
 * Per R-003/R-004 final reconciliation: this function does NOT depend on
 * WeakSet membership. It re-derives the commitment_root from the proposal +
 * acceptances, verifies the source signature over (commitment_root ||
 * commitment_nonce), and verifies that the route_id matches
 * "route:" + hex(commitment_root).
 *
 * It also verifies every acceptance signature + binding (same as
 * createRouteCommitment) to ensure the acceptances are genuine.
 *
 * This is the language-independent verification path — any implementation
 * (Rust, Go, C) can use this logic without WeakSet support.
 *
 * @returns { ok: true } if all checks pass, { ok: false, reason } otherwise.
 */
export function verifyRouteCommitment(
  commitment: RouteCommitment,
  sourcePublicKey: Uint8Array,
  hopPublicKeys: Map<string, Uint8Array>,
  serviceAgreements: Map<number, ServiceAgreement>,
  now: number,
): { ok: true } | { ok: false; reason: string } {
  // 1. Recompute the commitment_root from proposal + acceptances.
  const expectedRoot = computeCommitmentRoot(commitment.proposal, commitment.acceptances);
  if (!constantTimeEqual(expectedRoot, commitment.commitmentRoot)) {
    return { ok: false, reason: "commitment_root mismatch: recomputed root does not match the carried commitment_root" };
  }

  // 2. Verify the route_id matches "route:" + hex(commitment_root).
  const expectedRouteId = deriveRouteId(commitment.commitmentRoot);
  if (commitment.routeId !== expectedRouteId) {
    return { ok: false, reason: `route_id mismatch: expected ${expectedRouteId}, got ${commitment.routeId}` };
  }

  // 3. Verify the source signature over (commitment_root || commitment_nonce).
  const payload = routeCommitmentSigningPayload(commitment.commitmentRoot, commitment.commitmentNonce);
  if (!verifySignature(sourcePublicKey, payload, commitment.committerSignature)) {
    return { ok: false, reason: "source signature invalid over commitment_root + commitment_nonce" };
  }

  // 4. Verify every acceptance signature + binding (same as createRouteCommitment).
  for (let i = 0; i < commitment.proposal.hops.length; i++) {
    const hop = commitment.proposal.hops[i]!;
    const acc = commitment.acceptances[i];
    if (!acc) {
      return { ok: false, reason: `missing acceptance for hop ${i}` };
    }
    if (acc.hopIndex !== i) {
      return { ok: false, reason: `acceptance ${i} has wrong hopIndex ${acc.hopIndex}` };
    }
    if (acc.acceptorNodeId !== hop.nodeId) {
      return { ok: false, reason: `acceptance ${i} acceptor ${acc.acceptorNodeId} != hop ${hop.nodeId}` };
    }
    if (acc.expiry <= now) {
      return { ok: false, reason: `acceptance ${i} expired` };
    }
    const pubKey = hopPublicKeys.get(hop.nodeId);
    if (!pubKey) {
      return { ok: false, reason: `no public key for hop ${i} (${hop.nodeId})` };
    }
    if (!verifyRouteAcceptance(acc, pubKey)) {
      return { ok: false, reason: `acceptance ${i} signature invalid` };
    }
    const sa = serviceAgreements.get(i);
    if (!sa) {
      return { ok: false, reason: `no service agreement for hop ${i}` };
    }
    const binding = verifyAcceptanceBinding(acc, commitment.proposal, i, hop, sa);
    if (!binding.ok) {
      return { ok: false, reason: binding.reason };
    }
    if (!hop.linkUp) {
      return { ok: false, reason: `hop ${i} (${hop.nodeId}) is not LINK_UP` };
    }
  }

  return { ok: true };
}

/** Constant-time byte comparison. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
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
  return deepFreeze({
    routeId: commitment.routeId,
    hops: commitment.proposal.hops,
    expiry: commitment.proposal.expiry,
    initiatorNodeId: commitment.proposal.initiatorNodeId,
    agreementDigest: commitment.proposal.agreementDigest,
    committedAt: commitment.committedAt,
    commitmentRoot: frozenCopy(commitment.commitmentRoot),
  });
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
      `(hops=${proposal.hops.length}) without a RouteCommitment. ` +
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
