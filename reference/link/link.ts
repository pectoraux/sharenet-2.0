/**
 * ShareNet 2.0 — Directed Links.
 *
 * Per spec/04-links.md:
 *
 *   Links are DIRECTED. A → B does NOT imply B → A.
 *   A link is created ONLY through an actual authenticated transport
 *   connection (advertisement → candidate endpoint → transport connection →
 *   peer authentication → LinkUp).
 *
 *   An advertised endpoint is NOT equivalent to a usable link.
 *
 * State machine (spec/04 §4, corrected 2026-08-16):
 *
 *   LINK_PENDING   — transport connection initiated, handshake in progress
 *       ↓ advertisement verification success (current two-message exchange)
 *   ADV_VERIFIED   — advertisements verified; NOT yet authenticated (replay-vulnerable)
 *                    NOT eligible for routing. NOT an executable LINK_UP record.
 *       ↓ future: ADR-0016 challenge-response possession proof (NOT YET IMPLEMENTED)
 *   LINK_UP        — authenticated (fresh key possession proven), eligible for routing
 *                    **Not yet implemented** — gated on ADR-0016.
 *       ↓ transport close OR peer NodeId mismatch OR expiry
 *   LINK_DOWN      — no longer usable
 *
 * Per the corrective milestone (2026-08-16, requirement 3):
 *   The current two-message exchange establishes ADV_VERIFIED, NOT LINK_UP.
 *   It must not create an executable LINK_UP record or qualify as the
 *   Phase 3 milestone. The only truthful term is
 *   "advertisement-verification exchange."
 *
 * LinkId derivation (FROZEN per ADR-0014 — see below):
 *
 *   LinkId = "link:" + hex(BLAKE2b-256("sharenet-link-id-v1"
 *                                     ‖ localNodeId
 *                                     ‖ remoteNodeId
 *                                     ‖ localNonce
 *                                     ‖ remoteNonce))
 *
 * The nonces bind the LinkId to a specific handshake instance, preventing
 * LinkId reuse across reconnects. The ordering (local, remote) makes the
 * link direction explicit in the ID itself.
 */

import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/hashes/utils.js";

/** Domain-separation tag for LinkId derivation. FROZEN per ADR-0014 + ADR-0017. */
export const LINK_ID_DOMAIN = "SHARENET/LINK/ID/1";

/** LinkId string prefix. */
export const LINK_ID_PREFIX = "link:";

/** Length of the LinkId hash (BLAKE2b-256). */
export const LINK_ID_HASH_BYTES = 32;

/** Length of the handshake nonce (16 bytes). */
export const LINK_NONCE_BYTES = 16;

/** Link state machine. spec/04 §4 (corrected 2026-08-16). */
export type LinkState = "LINK_PENDING" | "ADV_VERIFIED" | "LINK_UP" | "LINK_DOWN";

/**
 * Derive a LinkId from the two endpoints + their handshake nonces.
 *
 * The local/remote ordering encodes the link DIRECTION. A link from A→B
 * has a different LinkId than a link from B→A, even if both use the same
 * nonces — because the local/remote roles are swapped.
 *
 * This is the single source of truth for LinkId. Callers MUST NOT construct
 * a LinkId by any other means.
 */
export function deriveLinkId(
  localNodeId: string,
  remoteNodeId: string,
  localNonce: Uint8Array,
  remoteNonce: Uint8Array,
): string {
  if (localNonce.length !== LINK_NONCE_BYTES) {
    throw new Error(`localNonce must be ${LINK_NONCE_BYTES} bytes`);
  }
  if (remoteNonce.length !== LINK_NONCE_BYTES) {
    throw new Error(`remoteNonce must be ${LINK_NONCE_BYTES} bytes`);
  }
  const domain = new TextEncoder().encode(LINK_ID_DOMAIN);
  const local = new TextEncoder().encode(localNodeId);
  const remote = new TextEncoder().encode(remoteNodeId);
  const input = new Uint8Array(
    domain.length + local.length + remote.length + localNonce.length + remoteNonce.length,
  );
  let off = 0;
  input.set(domain, off); off += domain.length;
  input.set(local, off); off += local.length;
  input.set(remote, off); off += remote.length;
  input.set(localNonce, off); off += localNonce.length;
  input.set(remoteNonce, off);
  const hash = blake3(input, { dkLen: LINK_ID_HASH_BYTES });
  return LINK_ID_PREFIX + bytesToHex(hash);
}

/** Generate a fresh 16-byte handshake nonce. */
export function generateLinkNonce(): Uint8Array {
  return randomBytes(LINK_NONCE_BYTES);
}

/** A directed link record. Per spec/04, links are directed. */
export interface DirectedLink {
  /** Canonical LinkId (directional). */
  linkId: string;
  /** The local node's NodeId (the link originates here). */
  localNodeId: string;
  /** The remote node's NodeId (the link points to this node). */
  remoteNodeId: string;
  /** Local nonce used in the handshake. */
  localNonce: Uint8Array;
  /** Remote nonce received in the handshake. */
  remoteNonce: Uint8Array;
  /** The remote node's verified public key (32 bytes). */
  remotePublicKey: Uint8Array;
  /** The remote node's advertised capabilities. */
  remoteCapabilities: readonly string[];
  /** The remote endpoint we connected to (host:port). */
  remoteEndpoint: string;
  /** Current state. */
  state: LinkState;
  /** Unix ms when the link entered its current state. */
  stateChangedAt: number;
  /** Unix ms when the link was created. */
  createdAt: number;
  /** Optional: observed RTT in ms (populated by transport layer). */
  observedRttMs?: number;
}

/** Event emitted when a link transitions state. spec/04 §4 (corrected). */
export type LinkEvent =
  | { type: "LINK_PENDING"; linkId: string; localNodeId: string; remoteEndpoint: string; at: number }
  | { type: "ADV_VERIFIED"; linkId: string; remoteNodeId: string; at: number }
  | { type: "LINK_UP"; linkId: string; remoteNodeId: string; at: number }  // reserved for ADR-0016
  | { type: "LINK_DOWN"; linkId: string; reason: string; at: number };

/** True iff linkId is well-formed (prefix + 64 hex). */
export function isValidLinkIdFormat(linkId: string): boolean {
  if (!linkId.startsWith(LINK_ID_PREFIX)) return false;
  const hex = linkId.slice(LINK_ID_PREFIX.length);
  if (hex.length !== LINK_ID_HASH_BYTES * 2) return false;
  return /^[0-9a-f]+$/.test(hex);
}

/**
 * ARCHITECTURE GUARD (spec/04 §2).
 *
 * An advertised endpoint is NOT equivalent to a usable link. A link is
 * created ONLY through an authenticated transport connection. This function
 * exists so the architecture regression test can call it and assert it
 * throws — any code that tries to construct a DirectedLink from a bare
 * endpoint (without a verified handshake) is forbidden.
 */
export function CREATE_LINK_FROM_ENDPOINT_FORBIDDEN(endpoint: string): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: attempted to create a DirectedLink from a bare endpoint ` +
      `(${endpoint}) without an authenticated transport handshake. ` +
      `Per spec/04 §2, an advertised endpoint is NOT equivalent to a usable link. ` +
      `The full pipeline (advertisement → endpoint → transport connection → peer ` +
      `authentication → LinkUp) MUST be executed.`,
  );
}

// ---- internal hex helper (avoids circular import with identity/keys.ts) ----

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}
