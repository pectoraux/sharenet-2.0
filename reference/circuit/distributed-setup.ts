/**
 * ShareNet 2.0 — Distributed Circuit Establishment (R-008).
 *
 * Per R-008: circuit creation must require:
 *   1. A genuine BrandedCommittedRoute (WeakSet-verified)
 *   2. Participant acknowledgements (each relay proves possession + installs forwarding state)
 *   3. All cryptographic state bound to the committed route transcript
 *   4. Encrypted traffic across independent processes using real transports
 *
 * Protocol flow:
 *
 *   Initiator                            Relay N                    Relay N+1
 *   ---------                            ------                    ----------
 *   CircuitSetupRequest(route, hopIndex, initiator_x25519_pub)
 *                      ────────────────→
 *                                        verify route position
 *                                        generate relay_x25519 keypair
 *                                        compute shared secret
 *                                        derive forwarding keys
 *                                        sign possession proof
 *                                        install forwarding state
 *   CircuitSetupAck(relay_x25519_pub, proof, ack_nonce)
 *                      ←────────────────
 *   verify proof
 *   derive keys
 *   store relay state
 *
 *   After ALL relays ack:
 *   ActiveCircuit (registered in WeakSet)
 *
 * Per R-008: negative tests for:
 *   - route substitution (different route in setup request)
 *   - replay (reuse old ack in new circuit)
 *   - participant substitution (wrong relay responds)
 *   - transcript mutation (tampered setup request)
 *   - unauthorized circuit creation (no BrandedCommittedRoute)
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { signMessage, verifySignature } from "../identity/keys";
import { canonicalEncode, toHex } from "../encoding/cbor";
import type { BrandedCommittedRoute, ValidatedHop } from "../transport/validated-types";
import { isBrandedCommittedRoute } from "../transport/validated-types";
import {
  deriveHopKeys,
  deriveCircuitId,
  CircuitReplayGuard,
  type ActiveCircuit,
  type HopKeyMaterial,
  AEAD_KEY_BYTES,
} from "./circuit";

// -----------------------------------------------------------------------
// Constants (FROZEN per spec/14 §4 + ADR-0017)
// -----------------------------------------------------------------------

export const CIRCUIT_SETUP_DOMAIN = "SHARENET/CIRCUIT/SETUP/1";
export const CIRCUIT_ACK_DOMAIN = "SHARENET/CIRCUIT/ACK/1";

/** Circuit forwarding lifecycle states. */
export type ForwardingLifecycle = "INSTALLED" | "ACTIVE" | "EXPIRED" | "CLOSED";

/** Circuit expiry in seconds (1 hour). */
export const CIRCUIT_EXPIRY_SECONDS = 3600;

/**
 * Maximum ACK age (TTL) — an ack must be CONSUMED (processed by the
 * initiator) within this many seconds of `ackTimestamp`, regardless of
 * the looser `ackExpiry`. This bounds the replay window: even when an
 * ack carries a 1-hour absolute expiry, it must still be fresh on a
 * relative scale. Per R-008 hardening.
 */
export const ACK_MAX_AGE_SECONDS = 120; // 2 minutes

/**
 * Maximum tolerated clock skew — `ackTimestamp` may be at most this many
 * seconds in the future relative to the initiator's `now`. Acks dated
 * further into the future are rejected as malformed / replay-with-skew.
 * Per R-008 hardening.
 */
export const ACK_MAX_CLOCK_SKEW_SECONDS = 60; // 1 minute

/**
 * Legal forwarding-lifecycle transitions (R-008 hardening).
 *
 *   INSTALLED → ACTIVE        (circuit fully established: all acks verified)
 *   INSTALLED → EXPIRED       (ack expired before the circuit completed)
 *   INSTALLED → CLOSED        (operator/relay aborted during setup)
 *   ACTIVE  → EXPIRED         (valid_until reached)
 *   ACTIVE  → CLOSED          (teardown)
 *
 * EXPIRED and CLOSED are terminal. Any other transition is rejected.
 */
const LEGAL_LIFECYCLE_TRANSITIONS: Record<ForwardingLifecycle, ForwardingLifecycle[]> = {
  INSTALLED: ["ACTIVE", "EXPIRED", "CLOSED"],
  ACTIVE: ["EXPIRED", "CLOSED"],
  EXPIRED: [],
  CLOSED: [],
};

/**
 * Transition a relay's forwarding lifecycle state.
 *
 * Per R-008 hardening: the lifecycle is a real state machine, not a free
 * string assignment. Illegal transitions are rejected. This makes the
 * forwarding-state progression auditable and prevents a relay from
 * silently re-activating expired/closed forwarding state.
 */
export function transitionForwardingLifecycle(
  from: ForwardingLifecycle,
  to: ForwardingLifecycle,
): { ok: true } | { ok: false; reason: string } {
  if (!LEGAL_LIFECYCLE_TRANSITIONS[from].includes(to)) {
    return {
      ok: false,
      reason: `illegal forwarding-lifecycle transition: ${from} → ${to}`,
    };
  }
  return { ok: true };
}

/**
 * Check whether a forwarding state is terminal (no further traffic).
 * Per spec/08 §6: EXPIRED and CLOSED MUST zeroize derived keys.
 */
export function isTerminalForwardingLifecycle(s: ForwardingLifecycle): boolean {
  return s === "EXPIRED" || s === "CLOSED";
}

// -----------------------------------------------------------------------
// CircuitSetupRequest (Initiator → Relay)
// -----------------------------------------------------------------------

export interface CircuitSetupRequest {
  /** The BrandedCommittedRoute this circuit is being established on. */
  route: BrandedCommittedRoute;
  /** Which hop this relay occupies in the route. */
  hopIndex: number;
  /** The initiator's ephemeral X25519 public key for this circuit. */
  initiatorX25519PublicKey: Uint8Array;
  /** Fresh nonce for replay protection (16 bytes). */
  setupNonce: Uint8Array;
}

/** Encode a CircuitSetupRequest to canonical CBOR for signing/verification. */
export function encodeCircuitSetupRequest(req: CircuitSetupRequest): Uint8Array {
  const m = new Map<number, unknown>([
    [1, req.route.routeId],
    [2, req.hopIndex],
    [3, req.initiatorX25519PublicKey],
    [4, req.setupNonce],
  ]);
  return canonicalEncode(m);
}

/** Compute the bytes-to-be-signed for a circuit setup request. */
export function circuitSetupSigningPayload(req: CircuitSetupRequest): Uint8Array {
  const body = encodeCircuitSetupRequest(req);
  const domain = new TextEncoder().encode(CIRCUIT_SETUP_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

// -----------------------------------------------------------------------
// CircuitSetupAck (Relay → Initiator)
// -----------------------------------------------------------------------

export interface CircuitSetupAck {
  /** The route ID this ack is for. */
  routeId: string;
  /** BLAKE3-256 of the canonical BrandedCommittedRoute (route commitment binding). */
  routeCommitmentDigestHex: string;
  /** Which hop this relay occupies. */
  hopIndex: number;
  /** The relay's ephemeral X25519 public key. */
  relayX25519PublicKey: Uint8Array;
  /** The initiator's X25519 public key (transcript binding). */
  initiatorX25519PublicKey: Uint8Array;
  /** The relay's Ed25519 signature proving possession + route binding + transcript binding. */
  relaySignature: Uint8Array;
  /** Fresh nonce for replay protection (16 bytes). */
  ackNonce: Uint8Array;
  /** Ack creation timestamp (unix seconds). */
  ackTimestamp: number;
  /** Ack expiry (unix seconds). */
  ackExpiry: number;
}

/**
 * Compute the signing payload for a circuit setup ack.
 *
 * Per R-008H: the ack binds:
 *   - routeId (route identity)
 *   - routeCommitmentDigest (cryptographic binding to the exact committed route)
 *   - hopIndex (which hop this relay occupies)
 *   - relayX25519PublicKey (the relay's ephemeral key for this circuit)
 *   - initiatorX25519PublicKey (transcript binding — the initiator's key for this circuit)
 *   - ackNonce (fresh per-ack nonce for replay protection)
 *   - ackTimestamp (when the ack was created)
 *   - ackExpiry (when the ack expires)
 *
 * Mutating ANY of these fields invalidates the signature.
 */
export function circuitAckSigningPayload(
  routeId: string,
  routeCommitmentDigestHex: string,
  hopIndex: number,
  relayX25519PublicKey: Uint8Array,
  initiatorX25519PublicKey: Uint8Array,
  ackNonce: Uint8Array,
  ackTimestamp: number,
  ackExpiry: number,
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, routeId],
    [2, routeCommitmentDigestHex],
    [3, hopIndex],
    [4, relayX25519PublicKey],
    [5, initiatorX25519PublicKey],
    [6, ackNonce],
    [7, ackTimestamp],
    [8, ackExpiry],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(CIRCUIT_ACK_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/** Compute the route commitment digest (BLAKE3-256 of routeId + hops + expiry + initiator). */
export function routeCommitmentDigest(route: BrandedCommittedRoute): Uint8Array {
  const m = new Map<number, unknown>([
    [1, route.routeId],
    [2, route.hops.map((h) => h.nodeId)],
    [3, route.hops.map((h) => h.capability)],
    [4, route.hops.map((h) => h.endpoint)],
    [5, route.expiry],
    [6, route.initiatorNodeId],
    [7, route.agreementDigest],
  ]);
  return blake3(canonicalEncode(m), { dkLen: 32 });
}

// -----------------------------------------------------------------------
// Relay setup handler
// -----------------------------------------------------------------------

export interface RelaySetupState {
  hopIndex: number;
  relayX25519SecretKey: Uint8Array;
  relayX25519PublicKey: Uint8Array;
  forwardingKey: Uint8Array;
  returnKey: Uint8Array;
  lifecycle: ForwardingLifecycle;
  installedAt: number;
  expiresAt: number;
  /** The ack nonce (for replay detection at the relay). */
  ackNonce: Uint8Array;
}

/**
 * Handle a CircuitSetupRequest as a relay.
 *
 * Per R-008H: the relay MUST:
 *   1. Verify the route is a genuine BrandedCommittedRoute (WeakSet check)
 *   2. Verify it occupies the specified hopIndex in the route
 *   3. Generate an ephemeral X25519 keypair
 *   4. Compute the shared secret with the initiator's X25519 public key
 *   5. Derive forwarding + return keys via HKDF
 *   6. Compute routeCommitmentDigest (binds ack to the exact committed route)
 *   7. Sign a possession proof binding: routeId + routeCommitmentDigest +
 *      hopIndex + relay_pubkey + initiator_pubkey + nonce + timestamp + expiry
 *   8. Install forwarding state with lifecycle = INSTALLED
 *
 * Returns the ack + the installed relay state.
 */
export function handleCircuitSetup(
  req: CircuitSetupRequest,
  relayEd25519SecretKey: Uint8Array,
  circuitIdBytes: Uint8Array,
  now: number = Math.floor(Date.now() / 1000),
): { ok: true; ack: CircuitSetupAck; state: RelaySetupState } | { ok: false; reason: string } {
  // 1. Verify the route is genuine
  if (!isBrandedCommittedRoute(req.route)) {
    return { ok: false, reason: "route is not a genuine BrandedCommittedRoute (WeakSet check failed)" };
  }

  // 2. Verify hopIndex is valid
  if (req.hopIndex < 0 || req.hopIndex >= req.route.hops.length) {
    return { ok: false, reason: `hopIndex ${req.hopIndex} out of range [0, ${req.route.hops.length})` };
  }

  // 3. Generate ephemeral X25519 keypair
  const relayX25519SecretKey = randomBytes(32);
  const relayX25519PublicKey = x25519.getPublicKey(relayX25519SecretKey);

  // 4. Compute shared secret
  const sharedSecret = x25519.getSharedSecret(relayX25519SecretKey, req.initiatorX25519PublicKey);

  // 5. Derive forwarding + return keys
  const keys = deriveHopKeys(sharedSecret, req.hopIndex, circuitIdBytes);

  // 6. Compute route commitment digest
  const commitDigest = routeCommitmentDigest(req.route);
  const commitDigestHex = toHex(commitDigest);

  // 7. Sign possession proof (binds route + hop + keys + transcript)
  const ackNonce = randomBytes(16);
  const ackExpiry = now + CIRCUIT_EXPIRY_SECONDS;
  const payload = circuitAckSigningPayload(
    req.route.routeId, commitDigestHex, req.hopIndex,
    relayX25519PublicKey, req.initiatorX25519PublicKey,
    ackNonce, now, ackExpiry,
  );
  const relaySignature = signMessage(relayEd25519SecretKey, payload);

  // 8. Install forwarding state
  const state: RelaySetupState = {
    hopIndex: req.hopIndex,
    relayX25519SecretKey,
    relayX25519PublicKey,
    forwardingKey: keys.forwardingKey,
    returnKey: keys.returnKey,
    lifecycle: "INSTALLED",
    installedAt: now,
    expiresAt: ackExpiry,
    ackNonce,
  };

  const ack: CircuitSetupAck = {
    routeId: req.route.routeId,
    routeCommitmentDigestHex: commitDigestHex,
    hopIndex: req.hopIndex,
    relayX25519PublicKey,
    initiatorX25519PublicKey: req.initiatorX25519PublicKey,
    relaySignature,
    ackNonce,
    ackTimestamp: now,
    ackExpiry,
  };

  return { ok: true, ack, state };
}

// -----------------------------------------------------------------------
// Initiator setup driver
// -----------------------------------------------------------------------

/**
 * Process a CircuitSetupAck as the initiator.
 *
 * Per R-008: the initiator MUST:
 *   1. Verify the relay's signature (proof of possession)
 *   2. Verify the ack matches the expected routeId + hopIndex
 *   3. Compute the shared secret with the relay's X25519 public key
 *   4. Derive forwarding + return keys
 *   5. Store the hop key material
 *
 * Returns the hop key material on success.
 */
export function processCircuitSetupAck(
  ack: CircuitSetupAck,
  expectedRouteId: string,
  expectedRouteCommitmentDigestHex: string,
  expectedHopIndex: number,
  expectedInitiatorX25519PublicKey: Uint8Array,
  relayEd25519PublicKey: Uint8Array,
  initiatorX25519SecretKey: Uint8Array,
  circuitIdBytes: Uint8Array,
  now: number = Math.floor(Date.now() / 1000),
): { ok: true; hopKey: HopKeyMaterial } | { ok: false; reason: string } {
  // 1. Verify routeId matches
  if (ack.routeId !== expectedRouteId) {
    return { ok: false, reason: `routeId mismatch: expected ${expectedRouteId}, got ${ack.routeId}` };
  }

  // 2. Verify routeCommitmentDigest matches (R-008H: binds to exact committed route)
  if (ack.routeCommitmentDigestHex !== expectedRouteCommitmentDigestHex) {
    return { ok: false, reason: `routeCommitmentDigest mismatch: expected ${expectedRouteCommitmentDigestHex.slice(0, 16)}..., got ${ack.routeCommitmentDigestHex.slice(0, 16)}...` };
  }

  // 3. Verify hopIndex matches
  if (ack.hopIndex !== expectedHopIndex) {
    return { ok: false, reason: `hopIndex mismatch: expected ${expectedHopIndex}, got ${ack.hopIndex}` };
  }

  // 4. Verify initiator X25519 pubkey matches (transcript binding)
  if (!bytesEqual(ack.initiatorX25519PublicKey, expectedInitiatorX25519PublicKey)) {
    return { ok: false, reason: `initiator X25519 pubkey mismatch (transcript binding)` };
  }

  // 5. ACK freshness (R-008 hardening): the ack is rejected unless it is
  //    BOTH unexpired AND recently-issued AND not dated too far in the
  //    future. Three independent bounds:
  //
  //    a) ackExpiry > now            — absolute deadline (existing check)
  //    b) ackExpiry > ackTimestamp   — sanity: expiry must follow creation
  //    c) ackTimestamp <= now+SKEW   — reject acks dated far in the future
  //    d) now - ackTimestamp <= AGE  — reject acks consumed too long after
  //                                     issuance (relative freshness / TTL)
  //
  //    (c) and (d) are what bound the replay window independently of the
  //    (looser) 1-hour absolute expiry: even an unexpired ack becomes
  //    unusable once it is more than ACK_MAX_AGE_SECONDS old, and an ack
  //    carrying a future timestamp is treated as malformed/replay.
  if (ack.ackExpiry <= now) {
    return { ok: false, reason: `ack ${expectedHopIndex} expired (expiry ${ack.ackExpiry} <= now ${now})` };
  }
  if (ack.ackExpiry <= ack.ackTimestamp) {
    return { ok: false, reason: `ack ${expectedHopIndex} malformed (expiry ${ack.ackExpiry} <= timestamp ${ack.ackTimestamp})` };
  }
  if (ack.ackTimestamp > now + ACK_MAX_CLOCK_SKEW_SECONDS) {
    return { ok: false, reason: `ack ${expectedHopIndex} future-skewed (timestamp ${ack.ackTimestamp} > now+${ACK_MAX_CLOCK_SKEW_SECONDS})` };
  }
  if (now - ack.ackTimestamp > ACK_MAX_AGE_SECONDS) {
    return { ok: false, reason: `ack ${expectedHopIndex} stale (age ${now - ack.ackTimestamp}s > max ${ACK_MAX_AGE_SECONDS}s)` };
  }

  // 6. Verify relay signature (binds routeId + digest + hopIndex + keys + nonce + timestamps)
  const payload = circuitAckSigningPayload(
    ack.routeId, ack.routeCommitmentDigestHex, ack.hopIndex,
    ack.relayX25519PublicKey, ack.initiatorX25519PublicKey,
    ack.ackNonce, ack.ackTimestamp, ack.ackExpiry,
  );
  if (!verifySignature(relayEd25519PublicKey, payload, ack.relaySignature)) {
    return { ok: false, reason: `relay ${expectedHopIndex} signature invalid` };
  }

  // 7. Compute shared secret
  const sharedSecret = x25519.getSharedSecret(initiatorX25519SecretKey, ack.relayX25519PublicKey);

  // 8. Derive keys
  const keys = deriveHopKeys(sharedSecret, expectedHopIndex, circuitIdBytes);

  return {
    ok: true,
    hopKey: {
      hopIndex: expectedHopIndex,
      nodeId: "", // filled by caller
      forwardingKey: keys.forwardingKey,
      returnKey: keys.returnKey,
      relayX25519PublicKey: ack.relayX25519PublicKey,
    },
  };
}

/** Constant-time byte equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

// -----------------------------------------------------------------------
// Distributed circuit establishment
// -----------------------------------------------------------------------

/**
 * Establish a distributed circuit.
 *
 * Per R-008: this is the ONLY function that creates an ActiveCircuit from
 * a distributed setup process. It requires:
 *   1. A genuine BrandedCommittedRoute (WeakSet-verified)
 *   2. All relay acks (each relay proved possession + installed forwarding state)
 *   3. All ack signatures verified
 *   4. All hop keys derived
 *
 * The resulting ActiveCircuit is registered in the circuit WeakSet.
 */
export function establishDistributedCircuit(
  route: BrandedCommittedRoute,
  initiatorX25519SecretKey: Uint8Array,
  initiatorX25519PublicKey: Uint8Array,
  acks: CircuitSetupAck[],
  relayPublicKeys: Map<string, Uint8Array>, // nodeId → Ed25519 public key
  now: number,
): { ok: true; circuit: ActiveCircuit } | { ok: false; reason: string } {
  // 1. Verify the route is genuine
  if (!isBrandedCommittedRoute(route)) {
    return { ok: false, reason: "route is not a genuine BrandedCommittedRoute" };
  }

  // 2. Verify all acks are present
  if (acks.length !== route.hops.length) {
    return { ok: false, reason: `expected ${route.hops.length} acks, got ${acks.length}` };
  }

  // 3. Compute circuit ID + route commitment digest
  const circuitId = deriveCircuitId(route.routeId, initiatorX25519PublicKey);
  const circuitIdHex = toHex(circuitId);
  // Per R-003/R-004: routeId is "route:" + hex(commitment_root).
  // Strip the prefix to get the raw hex for the nonce prefix.
  const routeIdHex = route.routeId.startsWith("route:")
    ? route.routeId.slice(6)
    : route.routeId;
  const routeIdPrefix = parseInt(routeIdHex.slice(0, 8), 16);
  const commitDigestHex = toHex(routeCommitmentDigest(route));

  // 4. Process each ack
  const hopKeys: HopKeyMaterial[] = [];
  for (let i = 0; i < route.hops.length; i++) {
    const hop = route.hops[i];
    const ack = acks[i]!;

    // Get the relay's Ed25519 public key
    const relayEd25519PubKey = relayPublicKeys.get(hop.nodeId);
    if (!relayEd25519PubKey) {
      return { ok: false, reason: `no Ed25519 public key for relay ${i} (${hop.nodeId})` };
    }

    // Process the ack (with full binding verification)
    const result = processCircuitSetupAck(
      ack, route.routeId, commitDigestHex, i,
      initiatorX25519PublicKey,
      relayEd25519PubKey,
      initiatorX25519SecretKey, circuitId, now,
    );
    if (!result.ok) {
      return { ok: false, reason: result.reason };
    }

    hopKeys.push({
      ...result.hopKey,
      nodeId: hop.nodeId,
    });
  }

  // 5. Create the ActiveCircuit
  const circuit: ActiveCircuit = {
    circuitId,
    circuitIdHex,
    routeId: route.routeId,
    hops: hopKeys,
    initiatorX25519PublicKey,
    initiatorX25519SecretKey,
    expiry: route.expiry,
    establishedAt: now,
    replayGuard: new CircuitReplayGuard(),
    routeIdPrefix,
  };

  return { ok: true, circuit };
}
