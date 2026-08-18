/**
 * RemoteNodeHint — distinct type that MUST NOT be promotable to AuthenticatedNodeRecord.
 *
 * Per spec/06-topology.md and ADR-0007:
 *
 *   A RemoteNodeHint means: "another node CLAIMS that this node exists or has
 *   some property." It is NOT an authenticated identity.
 *
 *   The pipeline `RemoteNodeHint → AuthenticatedNodeRecord` MUST be impossible.
 *   Architecture regression test #7 (spec/17 §3) asserts this at the type level.
 *
 *   Bounded propagation: hints carry the reporter's NodeId and a signature
 *   over the hint body. Hints are valid for at most MAX_HINT_HOPS hops from
 *   their origin (spec/06 §4.2). Freshness window is MAX_HINT_FRESHNESS.
 */

import { signMessage, verifySignature, isValidNodeIdFormat } from "../identity/keys";
import { canonicalEncode, canonicalDecode, toHex, fromHex } from "../encoding/cbor";

/** Domain-separation tag for hint signatures. FROZEN per spec/14 §4 + ADR-0017. */
export const HINT_SIGNATURE_DOMAIN = "SHARENET/HINT/1";

/** Maximum hint propagation hops (spec/06 §4.2). */
export const MAX_HINT_HOPS = 3;

/** Hint freshness window in seconds (spec/06 §4.3). */
export const MAX_HINT_FRESHNESS_SECONDS = 3600;

/**
 * A RemoteNodeHint. NEVER construct an AuthenticatedNodeRecord from this type.
 *
 * The `__brand` field is a TypeScript phantom type marker that prevents
 * accidental assignment of a hint to a record slot. It is erased at runtime.
 */
export interface RemoteNodeHint {
  readonly __brand: "RemoteNodeHint";
  readonly reporterNodeId: string;
  readonly subjectNodeId: string;
  readonly subjectEndpointHint: string;
  readonly claimedCapabilities: readonly string[];
  readonly hopCount: number;
  readonly timestamp: number;
  readonly nonce: Uint8Array;
  readonly reporterSignature: Uint8Array;
}

/** Body that gets signed by the reporter. */
export interface HintBody {
  reporterNodeId: string;
  subjectNodeId: string;
  subjectEndpointHint: string;
  claimedCapabilities: readonly string[];
  hopCount: number;
  timestamp: number;
  nonce: Uint8Array;
}

/** Encode a hint body to canonical CBOR (integer-keyed map per ADR-0004). */
export function encodeHintBody(body: HintBody): Uint8Array {
  const map = new Map<number, unknown>();
  map.set(1, body.reporterNodeId);
  map.set(2, body.subjectNodeId);
  map.set(3, body.subjectEndpointHint);
  map.set(4, [...body.claimedCapabilities]);
  map.set(5, body.hopCount);
  map.set(6, body.timestamp);
  map.set(7, body.nonce);
  return canonicalEncode(map);
}

/** Compute the bytes-to-be-signed for a hint body (with domain separation). */
export function hintSigningPayload(body: HintBody): Uint8Array {
  const bodyBytes = encodeHintBody(body);
  const domain = new TextEncoder().encode(HINT_SIGNATURE_DOMAIN);
  const payload = new Uint8Array(domain.length + bodyBytes.length);
  payload.set(domain, 0);
  payload.set(bodyBytes, domain.length);
  return payload;
}

/**
 * Create a signed RemoteNodeHint.
 *
 * NOTE: Creating a hint does NOT authenticate the subject. It only authenticates
 * the REPORTER's claim. The hint is a rumor, cryptographically attributable to
 * its reporter.
 */
export function createRemoteNodeHint(
  body: HintBody,
  reporterSecretKey: Uint8Array,
): RemoteNodeHint {
  if (!isValidNodeIdFormat(body.reporterNodeId)) {
    throw new Error("refusing to create hint: reporterNodeId malformed");
  }
  if (!isValidNodeIdFormat(body.subjectNodeId)) {
    throw new Error("refusing to create hint: subjectNodeId malformed");
  }
  if (body.hopCount < 0 || body.hopCount > MAX_HINT_HOPS) {
    throw new Error(`hint hopCount out of range [0, ${MAX_HINT_HOPS}]`);
  }
  if (body.nonce.length !== 16) {
    throw new Error("hint nonce MUST be 16 bytes");
  }
  const payload = hintSigningPayload(body);
  const signature = signMessage(reporterSecretKey, payload);
  return {
    __brand: "RemoteNodeHint",
    reporterNodeId: body.reporterNodeId,
    subjectNodeId: body.subjectNodeId,
    subjectEndpointHint: body.subjectEndpointHint,
    claimedCapabilities: body.claimedCapabilities,
    hopCount: body.hopCount,
    timestamp: body.timestamp,
    nonce: body.nonce,
    reporterSignature: signature,
  };
}

/**
 * Verify a RemoteNodeHint cryptographically.
 *
 * Verifying a hint does NOT promote it to an AuthenticatedNodeRecord. It only
 * confirms that the reporter signed the claimed body. The hint remains a hint.
 */
export function verifyRemoteNodeHint(
  hint: RemoteNodeHint,
  reporterPublicKey: Uint8Array,
  now: number = Math.floor(Date.now() / 1000),
): { ok: true } | { ok: false; reason: string } {
  if (hint.__brand !== "RemoteNodeHint") {
    return { ok: false, reason: "not a RemoteNodeHint (brand mismatch)" };
  }
  if (hint.hopCount > MAX_HINT_HOPS) {
    return { ok: false, reason: `hopCount ${hint.hopCount} exceeds max ${MAX_HINT_HOPS}` };
  }
  if (Math.abs(hint.timestamp - now) > MAX_HINT_FRESHNESS_SECONDS) {
    return { ok: false, reason: "hint outside freshness window" };
  }
  if (hint.nonce.length !== 16) {
    return { ok: false, reason: "nonce not 16 bytes" };
  }
  const body: HintBody = {
    reporterNodeId: hint.reporterNodeId,
    subjectNodeId: hint.subjectNodeId,
    subjectEndpointHint: hint.subjectEndpointHint,
    claimedCapabilities: hint.claimedCapabilities,
    hopCount: hint.hopCount,
    timestamp: hint.timestamp,
    nonce: hint.nonce,
  };
  const payload = hintSigningPayload(body);
  if (!verifySignature(reporterPublicKey, payload, hint.reporterSignature)) {
    return { ok: false, reason: "reporter signature invalid" };
  }
  return { ok: true };
}

/**
 * ARCHITECTURE GUARD — explicit rejection of hint-to-record promotion.
 *
 * Per spec/06 §3 and ADR-0007, there MUST be no function that takes a
 * RemoteNodeHint and returns an AuthenticatedNodeRecord. This function
 * exists solely so the architecture regression test can call it and
 * assert that it THROWS. Any future code that attempts to add such a
 * path will need to remove this guard, which is a visible review signal.
 */
export function PROMOTE_HINT_TO_RECORD_FORBIDDEN(hint: RemoteNodeHint): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to promote RemoteNodeHint to AuthenticatedNodeRecord. ` +
      `Hint subject=${hint.subjectNodeId} reporter=${hint.reporterNodeId}. ` +
      `This is forbidden by spec/06 §3 and ADR-0007. ` +
      `The subject MUST advertise itself; hints are not authoritative.`,
  );
}

/** Serialize a hint to hex for transport. */
export function hintToHex(hint: RemoteNodeHint): string {
  const map = new Map<number, unknown>();
  map.set(1, hint.reporterNodeId);
  map.set(2, hint.subjectNodeId);
  map.set(3, hint.subjectEndpointHint);
  map.set(4, [...hint.claimedCapabilities]);
  map.set(5, hint.hopCount);
  map.set(6, hint.timestamp);
  map.set(7, hint.nonce);
  map.set(8, hint.reporterSignature);
  return toHex(canonicalEncode(map));
}

/** Deserialize a hint from hex. */
export function hintFromHex(hex: string): RemoteNodeHint {
  const map = canonicalDecode<Map<number, unknown>>(fromHex(hex));
  if (!(map instanceof Map)) throw new Error("hint bytes did not decode to a map");
  return {
    __brand: "RemoteNodeHint",
    reporterNodeId: map.get(1) as string,
    subjectNodeId: map.get(2) as string,
    subjectEndpointHint: map.get(3) as string,
    claimedCapabilities: (map.get(4) as string[]).slice(),
    hopCount: map.get(5) as number,
    timestamp: map.get(6) as number,
    nonce: new Uint8Array(map.get(7) as number[]),
    reporterSignature: new Uint8Array(map.get(8) as number[]),
  };
}
