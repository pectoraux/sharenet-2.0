/**
 * ShareNet 2.0 — Peer Handshake Protocol.
 *
 * Per spec/04 §3.2 the link creation pipeline is:
 *
 *   advertisement → candidate endpoint → transport connection →
 *   peer authentication → LinkUp
 *
 * This module defines the WIRE FORMAT of the handshake that runs over a
 * real transport connection (TCP socket, WebSocket, etc.).
 *
 * Handshake flow (two messages, no round-trip-of-round-trips):
 *
 *   Initiator (A)                          Responder (B)
 *   -----------                            -------------
 *   1. SEND InitiateMessage                 →
 *        { myNodeId, myPublicKey, myCapabilities,
 *          myNonce, myEndpoints, myAdvertisementSig,
 *          timestamp, expiry, sequence }
 *                                          2. VERIFY A's advertisement
 *                                                (signature, binding, expiry, canonical)
 *                                             IF FAIL → close socket, no LinkUp
 *                                             IF OK  → SEND AcceptMessage
 *        ←                                  { myNodeId, myPublicKey, myCapabilities,
 *                                            myNonce, myEndpoints, myAdvertisementSig,
 *                                            timestamp, expiry, sequence }
 *   3. VERIFY B's advertisement
 *        IF FAIL → close socket, no LinkUp
 *        IF OK  → LINK_UP (both sides)
 *
 * The handshake is MINIMAL for Phase 3. It establishes:
 *   - mutual advertisement verification (both sides prove their NodeId)
 *   - exchange of nonces (for LinkId derivation)
 *   - exchange of capabilities (for service negotiation later)
 *
 * It does NOT establish a session key (that's Phase 6 circuits via X25519).
 * It does NOT encrypt subsequent traffic (Phase 6 AEAD).
 * Phase 3 proves: two real processes, real socket, mutual auth, directed LinkUp.
 *
 * Wire format = length-prefixed canonical CBOR:
 *   [ 4 bytes big-endian length ] [ canonical CBOR message ]
 *
 * The message discriminates by an integer "kind" field:
 *   1 = InitiateMessage
 *   2 = AcceptMessage
 *   3 = RejectMessage (with reason)
 */

import { canonicalEncode, canonicalDecode, toHex, fromHex } from "../encoding/cbor";
import { verifySignature, type NodeCapability } from "../identity/keys";
import {
  type NodeAdvertisement,
  verifyAdvertisement,
  advertisementToHex,
  advertisementFromHex,
  signAdvertisement,
} from "../advertisement/advertisement";

/** Discriminator for handshake message kinds. */
export const HANDSHAKE_KIND = {
  INITIATE: 1,
  ACCEPT: 2,
  REJECT: 3,
} as const;

/** Maximum handshake message size (to prevent memory bombs). */
export const MAX_HANDSHAKE_MESSAGE_BYTES = 64 * 1024;

/** A canonical-CBOR handshake message carrying an advertisement. */
export interface HandshakeMessage {
  kind: typeof HANDSHAKE_KIND[keyof typeof HANDSHAKE_KIND];
  /** The sender's full signed advertisement (proves NodeId binding). */
  advertisement: NodeAdvertisement;
}

/** A reject message — sent when verification fails. */
export interface RejectMessage {
  kind: typeof HANDSHAKE_KIND.REJECT;
  reason: string;
  /** The expected NodeId the receiver wanted (for debugging). */
  expectedNodeId?: string;
  /** The NodeId the sender actually saw. */
  receivedNodeId: string;
}

/** Encode a HandshakeMessage to length-prefixed wire bytes. */
export function encodeHandshakeMessage(msg: HandshakeMessage | RejectMessage): Uint8Array {
  const body =
    msg.kind === HANDSHAKE_KIND.REJECT
      ? canonicalEncode(
          new Map<number, unknown>([
            [1, (msg as RejectMessage).kind],
            [2, (msg as RejectMessage).reason],
            [3, (msg as RejectMessage).expectedNodeId ?? null],
            [4, (msg as RejectMessage).receivedNodeId],
          ]),
        )
      : canonicalEncode(
          new Map<number, unknown>([
            [1, (msg as HandshakeMessage).kind],
            [2, advertisementToHex((msg as HandshakeMessage).advertisement)],
          ]),
        );
  const len = body.length;
  if (len > MAX_HANDSHAKE_MESSAGE_BYTES) {
    throw new Error(`handshake message too large: ${len} > ${MAX_HANDSHAKE_MESSAGE_BYTES}`);
  }
  const out = new Uint8Array(4 + len);
  new DataView(out.buffer).setUint32(0, len, false); // big-endian
  out.set(body, 4);
  return out;
}

/** Decode a HandshakeMessage from wire bytes (after reading the length prefix). */
export function decodeHandshakeBody(body: Uint8Array): HandshakeMessage | RejectMessage {
  const map = canonicalDecode<Map<number, unknown>>(body);
  if (!(map instanceof Map)) throw new Error("handshake body is not a CBOR map");
  const kind = map.get(1) as number;
  if (kind === HANDSHAKE_KIND.REJECT) {
    return {
      kind,
      reason: map.get(2) as string,
      expectedNodeId: (map.get(3) as string | null) ?? undefined,
      receivedNodeId: map.get(4) as string,
    };
  }
  if (kind === HANDSHAKE_KIND.INITIATE || kind === HANDSHAKE_KIND.ACCEPT) {
    const advHex = map.get(2) as string;
    const adv = advertisementFromHex(advHex);
    return { kind, advertisement: adv };
  }
  throw new Error(`unknown handshake message kind: ${kind}`);
}

/** Read a 4-byte big-endian length prefix from a buffer at the given offset. */
export function readLengthPrefix(buf: Uint8Array, offset: number): number {
  if (buf.length < offset + 4) throw new Error("buffer too short for length prefix");
  return new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, false);
}

/** Result of one side's handshake verification. */
export type HandshakeVerificationResult =
  | { ok: true; advertisement: NodeAdvertisement; verifiedAt: number }
  | { ok: false; reason: string; code: string };

/**
 * Verify a peer's handshake advertisement.
 *
 * This is the SPEC/04 §3.2 "peer authentication" step. It runs the full
 * spec/03 §5 advertisement verification (signature, identity binding,
 * timestamp, expiry, canonical encoding).
 *
 * Optionally also checks that the peer's NodeId matches an expected value
 * (when the initiator dialed a known endpoint that advertised a specific NodeId).
 */
export function verifyPeerHandshake(
  msg: HandshakeMessage,
  expectedNodeId?: string,
  now: number = Math.floor(Date.now() / 1000),
): HandshakeVerificationResult {
  const adv = msg.advertisement;
  const v = verifyAdvertisement(adv, now);
  if (!v.ok) {
    return { ok: false, reason: v.detail, code: v.error };
  }
  if (expectedNodeId && adv.nodeId !== expectedNodeId) {
    return {
      ok: false,
      reason: `peer NodeId mismatch: expected ${expectedNodeId}, got ${adv.nodeId}`,
      code: "NODE_ID_MISMATCH",
    };
  }
  return { ok: true, advertisement: adv, verifiedAt: now };
}

/**
 * Build a HandshakeMessage from a local advertisement.
 * The advertisement MUST already be signed (use signAdvertisement first).
 */
export function buildHandshakeMessage(
  kind: typeof HANDSHAKE_KIND.INITIATE | typeof HANDSHAKE_KIND.ACCEPT,
  advertisement: NodeAdvertisement,
): HandshakeMessage {
  return { kind, advertisement };
}

/** Build a reject message. */
export function buildRejectMessage(
  reason: string,
  receivedNodeId: string,
  expectedNodeId?: string,
): RejectMessage {
  return { kind: HANDSHAKE_KIND.REJECT, reason, receivedNodeId, expectedNodeId };
}

// Re-export so callers don't need to reach into the advertisement module directly.
export { signAdvertisement, advertisementToHex, advertisementFromHex, verifyAdvertisement, verifySignature };
export type { NodeAdvertisement, NodeCapability };
export { toHex, fromHex };
