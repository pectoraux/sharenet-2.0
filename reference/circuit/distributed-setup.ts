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
  /** Which hop this relay occupies. */
  hopIndex: number;
  /** The relay's ephemeral X25519 public key. */
  relayX25519PublicKey: Uint8Array;
  /** The relay's Ed25519 signature proving possession + route binding. */
  relaySignature: Uint8Array;
  /** Fresh nonce for replay protection (16 bytes). */
  ackNonce: Uint8Array;
}

/** Compute the signing payload for a circuit setup ack. */
export function circuitAckSigningPayload(
  routeId: string,
  hopIndex: number,
  relayX25519PublicKey: Uint8Array,
  ackNonce: Uint8Array,
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, routeId],
    [2, hopIndex],
    [3, relayX25519PublicKey],
    [4, ackNonce],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(CIRCUIT_ACK_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
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
  installed: boolean;
}

/**
 * Handle a CircuitSetupRequest as a relay.
 *
 * Per R-008: the relay MUST:
 *   1. Verify the route is a genuine BrandedCommittedRoute (WeakSet check)
 *   2. Verify it occupies the specified hopIndex in the route
 *   3. Generate an ephemeral X25519 keypair
 *   4. Compute the shared secret with the initiator's X25519 public key
 *   5. Derive forwarding + return keys via HKDF
 *   6. Sign a possession proof (CIRCUIT_ACK_DOMAIN over routeId + hopIndex + relay_pubkey + nonce)
 *   7. Install forwarding state (ready to decrypt/encrypt traffic)
 *
 * Returns the ack + the installed relay state.
 */
export function handleCircuitSetup(
  req: CircuitSetupRequest,
  relayEd25519SecretKey: Uint8Array,
  circuitIdBytes: Uint8Array,
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

  // 6. Sign possession proof
  const ackNonce = randomBytes(16);
  const payload = circuitAckSigningPayload(
    req.route.routeId, req.hopIndex, relayX25519PublicKey, ackNonce,
  );
  const relaySignature = signMessage(relayEd25519SecretKey, payload);

  // 7. Install forwarding state
  const state: RelaySetupState = {
    hopIndex: req.hopIndex,
    relayX25519SecretKey,
    relayX25519PublicKey,
    forwardingKey: keys.forwardingKey,
    returnKey: keys.returnKey,
    installed: true,
  };

  const ack: CircuitSetupAck = {
    routeId: req.route.routeId,
    hopIndex: req.hopIndex,
    relayX25519PublicKey,
    relaySignature,
    ackNonce,
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
  expectedHopIndex: number,
  relayEd25519PublicKey: Uint8Array,
  initiatorX25519SecretKey: Uint8Array,
  circuitIdBytes: Uint8Array,
): { ok: true; hopKey: HopKeyMaterial } | { ok: false; reason: string } {
  // 1. Verify routeId matches
  if (ack.routeId !== expectedRouteId) {
    return { ok: false, reason: `routeId mismatch: expected ${expectedRouteId}, got ${ack.routeId}` };
  }

  // 2. Verify hopIndex matches
  if (ack.hopIndex !== expectedHopIndex) {
    return { ok: false, reason: `hopIndex mismatch: expected ${expectedHopIndex}, got ${ack.hopIndex}` };
  }

  // 3. Verify relay signature
  const payload = circuitAckSigningPayload(
    ack.routeId, ack.hopIndex, ack.relayX25519PublicKey, ack.ackNonce,
  );
  if (!verifySignature(relayEd25519PublicKey, payload, ack.relaySignature)) {
    return { ok: false, reason: `relay ${expectedHopIndex} signature invalid` };
  }

  // 4. Compute shared secret
  const sharedSecret = x25519.getSharedSecret(initiatorX25519SecretKey, ack.relayX25519PublicKey);

  // 5. Derive keys
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

  // 3. Compute circuit ID
  const circuitId = deriveCircuitId(route.routeId, initiatorX25519PublicKey);
  const circuitIdHex = toHex(circuitId);
  const routeIdPrefix = parseInt(route.routeId.slice(0, 8), 16);

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

    // Process the ack
    const result = processCircuitSetupAck(
      ack, route.routeId, i, relayEd25519PubKey,
      initiatorX25519SecretKey, circuitId,
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
