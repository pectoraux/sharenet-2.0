/**
 * ShareNet 2.0 — R-003: Canonical Digests for Route Objects.
 *
 * Per R-003B requirement: immutable canonical artifacts.
 * No TOCTOU — digests are computed once and carried explicitly.
 *
 *   RouteProposal → canonical encode → hash → proposal_digest
 *   HopDescriptor → canonical encode → hash → hop_digest
 *   ServiceAgreement → canonical encode → hash → service_digest
 *
 * These digests are IMMUTABLE. They are computed from the canonical CBOR
 * of the object and carried as fixed 32-byte values. Verification compares
 * the carried digest, never recomputes from a potentially-mutated object.
 *
 * Per ADR-0017: all hashing uses BLAKE3-256.
 */

import { blake3 } from "@noble/hashes/blake3.js";
import { canonicalEncode } from "../encoding/cbor";
import { toHex } from "../encoding/cbor";
import type { RouteHop, RouteProposal } from "./route";

// -----------------------------------------------------------------------
// Digest computation
// -----------------------------------------------------------------------

/** Compute BLAKE3-256 of canonical CBOR. Returns 32 bytes. */
export function digest(data: unknown): Uint8Array {
  const encoded = canonicalEncode(data);
  return blake3(encoded, { dkLen: 32 });
}

/** Compute the digest of a RouteProposal (immutable canonical artifact). */
export function proposalDigest(proposal: RouteProposal): Uint8Array {
  // Encode only the semantically-significant fields (not the routeId itself,
  // which is a random identifier — the digest binds the HOPS and TERMS).
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
  return digest(m);
}

/** Compute the digest of a single hop descriptor (immutable canonical artifact). */
export function hopDigest(hop: RouteHop): Uint8Array {
  const m = new Map<number, unknown>([
    [1, hop.nodeId],
    [2, hop.capability],
    [3, hop.endpoint],
    [4, hop.linkUp],
  ]);
  return digest(m);
}

/** Compute the digest of a service agreement (immutable canonical artifact). */
export function serviceDigest(agreement: {
  nodeId: string;
  capability: string;
  allocatedBandwidthBps: number;
  expiry: number;
  policyVersion: number;
}): Uint8Array {
  const m = new Map<number, unknown>([
    [1, agreement.nodeId],
    [2, agreement.capability],
    [3, agreement.allocatedBandwidthBps],
    [4, agreement.expiry],
    [5, agreement.policyVersion],
  ]);
  return digest(m);
}

/** Convert digest bytes to hex string for storage/display. */
export function digestToHex(d: Uint8Array): string {
  return toHex(d);
}
