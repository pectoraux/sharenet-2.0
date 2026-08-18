/**
 * ShareNet 2.0 — Path Validation (spec/07-routing.md §4).
 *
 * A PathValidationResult is a per-link measurement produced by sending
 * a probe over a Link and receiving an authenticated acknowledgement.
 *
 * It is NOT a route. It is per-link metadata that informs next-hop
 * selection (step 4 of the routing pipeline, spec/07 §2).
 */

import { signMessage, verifySignature, type NodeKeypair } from "../identity/keys";
import { blake3 } from "@noble/hashes/blake3.js";
import { canonicalEncode, toHex } from "../encoding/cbor";

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------

export const PATH_VALIDATION_DOMAIN = "SHARENET/PATH/VALIDATION/1";

// -----------------------------------------------------------------------
// PathValidationResult
// -----------------------------------------------------------------------

export interface PathValidationBody {
  sourceNodeId: string;
  nextHopNodeId: string;
  destinationNodeId: string;
  measuredRttMs: number;
  measuredLossPct: number;
  validUntil: number;
}

export interface PathValidationResult extends PathValidationBody {
  signature: Uint8Array;
}

/**
 * Compute the canonical CBOR encoding of the body fields (keys 1–6).
 */
export function encodePathValidationBody(body: PathValidationBody): Uint8Array {
  const m = new Map<number, unknown>([
    [1, body.sourceNodeId],
    [2, body.nextHopNodeId],
    [3, body.destinationNodeId],
    [4, body.measuredRttMs],
    [5, body.measuredLossPct],
    [6, body.validUntil],
  ]);
  return canonicalEncode(m);
}

/**
 * Compute the signing payload: domain || canonical body.
 */
export function pathValidationSigningPayload(body: PathValidationBody): Uint8Array {
  const domain = new TextEncoder().encode(PATH_VALIDATION_DOMAIN);
  const bodyBytes = encodePathValidationBody(body);
  const out = new Uint8Array(domain.length + bodyBytes.length);
  out.set(domain, 0);
  out.set(bodyBytes, domain.length);
  return out;
}

/**
 * Create a signed PathValidationResult.
 */
export function createPathValidationResult(
  body: PathValidationBody,
  sourceSecretKey: Uint8Array,
): PathValidationResult {
  const payload = pathValidationSigningPayload(body);
  const signature = signMessage(sourceSecretKey, payload);
  return { ...body, signature };
}

/**
 * Verify a PathValidationResult signature.
 */
export function verifyPathValidationResult(
  result: PathValidationResult,
  sourcePublicKey: Uint8Array,
): boolean {
  const body: PathValidationBody = {
    sourceNodeId: result.sourceNodeId,
    nextHopNodeId: result.nextHopNodeId,
    destinationNodeId: result.destinationNodeId,
    measuredRttMs: result.measuredRttMs,
    measuredLossPct: result.measuredLossPct,
    validUntil: result.validUntil,
  };
  const payload = pathValidationSigningPayload(body);
  return verifySignature(sourcePublicKey, payload, result.signature);
}

/**
 * Full wire encoding: canonical CBOR map with keys 1–7 (body + signature).
 */
export function encodePathValidationWire(result: PathValidationResult): Uint8Array {
  const m = new Map<number, unknown>([
    [1, result.sourceNodeId],
    [2, result.nextHopNodeId],
    [3, result.destinationNodeId],
    [4, result.measuredRttMs],
    [5, result.measuredLossPct],
    [6, result.validUntil],
    [7, result.signature],
  ]);
  return canonicalEncode(m);
}
