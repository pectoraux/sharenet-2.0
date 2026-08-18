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
  deriveNoncePrefix,
  encryptPayload,
  decryptPayload,
  buildNonce,
  buildCircuitFrameAD,
  CircuitReplayGuard,
  CIRCUIT_POSSESSION_DOMAIN,
  type ActiveCircuit,
  type HopKeyMaterial,
  AEAD_KEY_BYTES,
} from "./circuit";
import type { CircuitAckReplayStore, CircuitSequenceFloorStore } from "./replay-stores";

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
  /** The relay's Ed25519 signature authenticating the ack. */
  relaySignature: Uint8Array;
  /**
   * AEAD-authenticated possession proof: the relay encrypts a fixed
   * challenge nonce using the derived forwardingKey, proving it holds
   * the AEAD key from X25519 ECDH + HKDF. This is NOT just an identity
   * signature — it is cryptographic proof of key possession.
   */
  possessionProofCiphertext: Uint8Array;
  /** The challenge nonce that was encrypted for the possession proof. */
  possessionChallenge: Uint8Array;
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
 * Per R-008: the ack binds:
 *   - routeId (route identity)
 *   - routeCommitmentDigest (cryptographic binding to the exact committed route)
 *   - hopIndex (which hop this relay occupies)
 *   - relayX25519PublicKey (the relay's ephemeral key for this circuit)
 *   - initiatorX25519PublicKey (transcript binding — the initiator's key for this circuit)
 *   - possessionProofCiphertext (the AEAD-encrypted possession proof)
 *   - possessionChallenge (the challenge that was encrypted)
 *   - ackNonce (fresh per-ack nonce for replay protection)
 *   - ackTimestamp (when the ack was created)
 *   - ackExpiry (when the ack expires)
 *
 * The Ed25519 signature authenticates the ack's identity binding.
 * The possession proof (AEAD ciphertext) separately proves the relay
 * holds the derived forwarding key. Both are required for a valid ack.
 */
export function circuitAckSigningPayload(
  routeId: string,
  routeCommitmentDigestHex: string,
  hopIndex: number,
  relayX25519PublicKey: Uint8Array,
  initiatorX25519PublicKey: Uint8Array,
  possessionProofCiphertext: Uint8Array,
  possessionChallenge: Uint8Array,
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
    [6, possessionProofCiphertext],
    [7, possessionChallenge],
    [8, ackNonce],
    [9, ackTimestamp],
    [10, ackExpiry],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(CIRCUIT_ACK_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * Generate the AEAD possession proof.
 *
 * The relay encrypts a fresh challenge nonce using the derived
 * forwardingKey. The initiator decrypts it using the same key
 * (derived from the shared X25519 secret) to verify the relay
 * actually holds the AEAD key — not just the Ed25519 identity key.
 *
 * This proves: "I derived the same key you will derive from our
 * shared X25519 secret + commitment_root."
 */
export function generatePossessionProof(
  forwardingKey: Uint8Array,
  noncePrefix: Uint8Array,
  commitmentRoot: Uint8Array,
  hopIndex: number,
): { ciphertext: Uint8Array; challenge: Uint8Array } {
  const challenge = randomBytes(32);
  const nonce = buildNonce(noncePrefix, 0); // frame_sequence=0 for setup proof
  const aad = buildCircuitFrameAD(commitmentRoot, 0, 0x01);
  const ciphertext = encryptPayload(forwardingKey, nonce, challenge, aad);
  return { ciphertext, challenge };
}

/**
 * Verify the AEAD possession proof.
 *
 * The initiator decrypts the proof ciphertext using the derived
 * forwardingKey and checks that the decrypted challenge matches
 * the one carried in the ack. If decryption fails (wrong key) or
 * the challenge doesn't match, the proof is invalid.
 */
export function verifyPossessionProof(
  forwardingKey: Uint8Array,
  noncePrefix: Uint8Array,
  commitmentRoot: Uint8Array,
  ciphertext: Uint8Array,
  expectedChallenge: Uint8Array,
): boolean {
  try {
    const nonce = buildNonce(noncePrefix, 0);
    const aad = buildCircuitFrameAD(commitmentRoot, 0, 0x01);
    const decrypted = decryptPayload(forwardingKey, nonce, ciphertext, aad);
    // Constant-time comparison
    if (decrypted.length !== expectedChallenge.length) return false;
    let diff = 0;
    for (let i = 0; i < decrypted.length; i++) {
      diff |= decrypted[i]! ^ expectedChallenge[i]!;
    }
    return diff === 0;
  } catch {
    return false; // AEAD decryption failed (wrong key)
  }
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
  commitmentRoot: Uint8Array,
  now: number = Math.floor(Date.now() / 1000),
  /**
   * TEST-ONLY hook: a fixed ack nonce (16 bytes).
   *
   * When provided, the ack is signed with this nonce instead of a fresh
   * random one. This lets integration tests craft acks that share a nonce
   * across different hops to prove the ack-replay key
   * `(commitmentRoot, hopIndex, ackNonce)` includes the hop index.
   *
   * Production callers MUST leave this undefined so the nonce is fresh
   * and unpredictable. A nonce reused across two genuine acks on the
   * SAME hop would be a replay; this hook is only for crafting acks on
   * DIFFERENT hops to prove hop isolation.
   */
  ackNonceForTest?: Uint8Array,
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

  // 5. Derive forwarding + return keys (commitment_root used as HKDF salt per spec/08 §4.1)
  const keys = deriveHopKeys(sharedSecret, req.hopIndex, commitmentRoot);

  // 6. Derive nonce prefix for AEAD operations
  const noncePrefix = deriveNoncePrefix(commitmentRoot);

  // 7. Generate AEAD possession proof — proves the relay holds the forwardingKey
  const possession = generatePossessionProof(
    keys.forwardingKey, noncePrefix, commitmentRoot, req.hopIndex,
  );

  // 8. Compute route commitment digest
  const commitDigest = routeCommitmentDigest(req.route);
  const commitDigestHex = toHex(commitDigest);

  // 9. Sign the ack (binds route + hop + keys + possession proof + transcript).
  //    The ack nonce is fresh random unless the test-only `ackNonceForTest`
  //    hook is provided (used to prove hop-isolation in the ack-replay key).
  const ackNonce = ackNonceForTest ?? randomBytes(16);
  const ackExpiry = now + CIRCUIT_EXPIRY_SECONDS;
  const payload = circuitAckSigningPayload(
    req.route.routeId, commitDigestHex, req.hopIndex,
    relayX25519PublicKey, req.initiatorX25519PublicKey,
    possession.ciphertext, possession.challenge,
    ackNonce, now, ackExpiry,
  );
  const relaySignature = signMessage(relayEd25519SecretKey, payload);

  // 10. Install forwarding state
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
    possessionProofCiphertext: possession.ciphertext,
    possessionChallenge: possession.challenge,
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
 * Per the R-008 integration audit: the initiator MUST ALSO atomically
 * consume `(commitmentRoot, hopIndex, ackNonce)` through a
 * `CircuitAckReplayStore` BEFORE returning success. An identical, still-fresh
 * ack presented a second time is rejected as a replay. This consumption
 * survives process restart when a durable store is supplied.
 *
 * The consumption happens AFTER all cryptographic verification (so invalid
 * acks do not consume nonce space) but BEFORE returning success (so a
 * duplicate is caught). Fail-closed: if the persistence operation cannot
 * complete, the ack is rejected.
 *
 * Returns the hop key material on success.
 */
export async function processCircuitSetupAck(
  ack: CircuitSetupAck,
  expectedRouteId: string,
  expectedRouteCommitmentDigestHex: string,
  expectedHopIndex: number,
  expectedInitiatorX25519PublicKey: Uint8Array,
  relayEd25519PublicKey: Uint8Array,
  initiatorX25519SecretKey: Uint8Array,
  commitmentRoot: Uint8Array,
  now: number = Math.floor(Date.now() / 1000),
  /**
   * REQUIRED ack replay store (R-008 final hardening).
   *
   * Per the R-008 re-audit: production paths MUST supply a durable store
   * — the type system now enforces this (no default). Test paths supply
   * `InMemoryCircuitAckReplayStore` explicitly.
   *
   * The ack is atomically consumed through this store BEFORE success is
   * returned. A replayed ack (same commitmentRoot + hopIndex + ackNonce)
   * is rejected. Fail-closed.
   */
  ackStore: CircuitAckReplayStore,
): Promise<{ ok: true; hopKey: HopKeyMaterial } | { ok: false; reason: string }> {
  // 1. Verify routeId matches
  if (ack.routeId !== expectedRouteId) {
    return { ok: false, reason: `routeId mismatch: expected ${expectedRouteId}, got ${ack.routeId}` };
  }

  // 2. Verify routeCommitmentDigest matches
  if (ack.routeCommitmentDigestHex !== expectedRouteCommitmentDigestHex) {
    return { ok: false, reason: `routeCommitmentDigest mismatch` };
  }

  // 3. Verify hopIndex matches
  if (ack.hopIndex !== expectedHopIndex) {
    return { ok: false, reason: `hopIndex mismatch: expected ${expectedHopIndex}, got ${ack.hopIndex}` };
  }

  // 4. Verify initiator X25519 pubkey matches (transcript binding)
  if (!bytesEqual(ack.initiatorX25519PublicKey, expectedInitiatorX25519PublicKey)) {
    return { ok: false, reason: `initiator X25519 pubkey mismatch (transcript binding)` };
  }

  // 5. ACK freshness (R-008 hardening)
  if (ack.ackExpiry <= now) {
    return { ok: false, reason: `ack ${expectedHopIndex} expired` };
  }
  if (ack.ackExpiry <= ack.ackTimestamp) {
    return { ok: false, reason: `ack ${expectedHopIndex} malformed` };
  }
  if (ack.ackTimestamp > now + ACK_MAX_CLOCK_SKEW_SECONDS) {
    return { ok: false, reason: `ack ${expectedHopIndex} future-skewed` };
  }
  if (now - ack.ackTimestamp > ACK_MAX_AGE_SECONDS) {
    return { ok: false, reason: `ack ${expectedHopIndex} stale` };
  }

  // 6. Verify relay Ed25519 signature (authenticates the ack's identity binding)
  const payload = circuitAckSigningPayload(
    ack.routeId, ack.routeCommitmentDigestHex, ack.hopIndex,
    ack.relayX25519PublicKey, ack.initiatorX25519PublicKey,
    ack.possessionProofCiphertext, ack.possessionChallenge,
    ack.ackNonce, ack.ackTimestamp, ack.ackExpiry,
  );
  if (!verifySignature(relayEd25519PublicKey, payload, ack.relaySignature)) {
    return { ok: false, reason: `relay ${expectedHopIndex} signature invalid` };
  }

  // 7. Compute shared secret
  const sharedSecret = x25519.getSharedSecret(initiatorX25519SecretKey, ack.relayX25519PublicKey);

  // 8. Derive keys (commitment_root used as HKDF salt per spec/08 §4.1)
  const keys = deriveHopKeys(sharedSecret, expectedHopIndex, commitmentRoot);

  // 9. Verify AEAD possession proof — proves the relay holds the derived forwardingKey.
  //    This is NOT just an identity signature. The relay encrypted a challenge
  //    using the derived key; the initiator decrypts it to verify key possession.
  const noncePrefix = deriveNoncePrefix(commitmentRoot);
  const possessionValid = verifyPossessionProof(
    keys.forwardingKey, noncePrefix, commitmentRoot,
    ack.possessionProofCiphertext, ack.possessionChallenge,
  );
  if (!possessionValid) {
    return { ok: false, reason: `relay ${expectedHopIndex} AEAD possession proof invalid (wrong key or tampered)` };
  }

  // 10. Atomically consume the ack through the replay store (R-008 integration).
  //     This happens AFTER all cryptographic verification (so invalid acks do
  //     not consume nonce space) but BEFORE returning success (so a duplicate
  //     is caught). The consumption key is (commitmentRoot, hopIndex, ackNonce).
  //     Fail-closed: if the ack was already consumed (replay) OR the persistence
  //     operation cannot complete, the ack is rejected.
  //
  //     When a durable store is supplied, this consumption survives process
  //     restart — a replayed ack after restart is still rejected.
  const consumed = await ackStore.consume(commitmentRoot, expectedHopIndex, ack.ackNonce);
  if (!consumed) {
    return {
      ok: false,
      reason: `relay ${expectedHopIndex} ack replay: (commitmentRoot, hopIndex, ackNonce) already consumed or persistence failed (fail-closed)`,
    };
  }

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
 * Per the R-008 integration audit: this function ALSO:
 *   5. Atomically consumes each ack through the `CircuitAckReplayStore`
 *      (via `processCircuitSetupAck`) — replayed acks are rejected.
 *   6. Loads the prior sequence floor from the `CircuitSequenceFloorStore`
 *      (if supplied) so a re-key on the same route continues from the
 *      prior floor (spec/08 §4.5), and attaches the store to the
 *      `ActiveCircuit` so `processCircuitFrame` does durable check+persist.
 *
 * The resulting ActiveCircuit is registered in the circuit WeakSet.
 */
export async function establishDistributedCircuit(
  route: BrandedCommittedRoute,
  initiatorX25519SecretKey: Uint8Array,
  initiatorX25519PublicKey: Uint8Array,
  acks: CircuitSetupAck[],
  relayPublicKeys: Map<string, Uint8Array>, // nodeId → Ed25519 public key
  now: number,
  /**
   * REQUIRED ack replay store (R-008 final hardening). No default — the
   * type system enforces that a store is supplied. Test paths pass
   * `InMemoryCircuitAckReplayStore`; production paths pass
   * `DurableSqliteCircuitAckReplayStore`.
   */
  ackStore: CircuitAckReplayStore,
  /**
   * REQUIRED durable sequence-floor store (R-008 final hardening). No
   * optional — the type system enforces that a store is supplied. The
   * prior floor for this route is loaded (re-key continuation, spec/08
   * §4.5) and the store is attached to the ActiveCircuit so
   * `processCircuitFrame` does atomic durable AEAD→commit ordering.
   */
  floorStore: CircuitSequenceFloorStore,
): Promise<{ ok: true; circuit: ActiveCircuit } | { ok: false; reason: string }> {
  // 1. Verify the route is genuine
  if (!isBrandedCommittedRoute(route)) {
    return { ok: false, reason: "route is not a genuine BrandedCommittedRoute" };
  }

  // 2. Verify all acks are present
  if (acks.length !== route.hops.length) {
    return { ok: false, reason: `expected ${route.hops.length} acks, got ${acks.length}` };
  }

  // 3. Compute circuit ID + nonce prefix from commitment_root
  //    Per spec/08 §3 + §4.3: circuit_id and nonce_prefix both bind to the
  //    raw 32-byte commitment_root (NOT the routeId string).
  const circuitId = deriveCircuitId(route.commitmentRoot, initiatorX25519PublicKey);
  const circuitIdHex = toHex(circuitId);
  const noncePrefix = deriveNoncePrefix(route.commitmentRoot);
  const commitDigestHex = toHex(routeCommitmentDigest(route));

  // 3b. R-009 Stage 1 final replay-model correction: the durable floor is now
  //     keyed by (commitmentRoot, hopIndex, direction) — receiver-local, not
  //     route-shared. Each hop loads its OWN floor when it processes frames
  //     (via processCircuitWireFrame → floorStore.checkAndAdvance). The
  //     initiator's circuit (created here) is used to SEAL frames, not to
  //     receive them — so there is no single "initialFloor" to load here.
  //     The floorStore is attached to the ActiveCircuit so that any relay
  //     processing path can consult it. The in-memory replayGuard cache is
  //     seeded at 0 (it's just a fast-path mirror; the store is the source of
  //     truth).
  //
  //     Per spec/08 §4.5: re-key continuation holds PER RECEIVER — a re-key
  //     on the same (route, hop, direction) continues from that receiver's
  //     prior floor, which the store persists.

  // 4. Process each ack (async — each ack is atomically consumed through
  //    the ackStore before being accepted).
  const hopKeys: HopKeyMaterial[] = [];
  for (let i = 0; i < route.hops.length; i++) {
    const hop = route.hops[i];
    const ack = acks[i]!;

    // Get the relay's Ed25519 public key
    const relayEd25519PubKey = relayPublicKeys.get(hop.nodeId);
    if (!relayEd25519PubKey) {
      return { ok: false, reason: `no Ed25519 public key for relay ${i} (${hop.nodeId})` };
    }

    // Process the ack (with full binding verification + ack store consumption).
    // Pass the route's commitment_root as the HKDF salt for key derivation.
    const result = await processCircuitSetupAck(
      ack, route.routeId, commitDigestHex, i,
      initiatorX25519PublicKey,
      relayEd25519PubKey,
      initiatorX25519SecretKey, route.commitmentRoot, now,
      ackStore,
    );
    if (!result.ok) {
      return { ok: false, reason: result.reason };
    }

    hopKeys.push({
      ...result.hopKey,
      nodeId: hop.nodeId,
    });
  }

  // 5. Create the ActiveCircuit — attach the floorStore so processCircuitWireFrame
  //    does durable check+persist at each receiver (keyed by (root, hopIndex, direction)).
  const circuit: ActiveCircuit = {
    circuitId,
    circuitIdHex,
    routeId: route.routeId,
    hops: hopKeys,
    initiatorX25519PublicKey,
    initiatorX25519SecretKey,
    expiry: route.expiry,
    establishedAt: now,
    // The in-memory replayGuard is a fast-path cache mirror; the floorStore
    // is the source of truth. Seeded at 0 — each receiver loads its own floor.
    replayGuard: new CircuitReplayGuard(),
    noncePrefix,
    commitmentRoot: route.commitmentRoot,
    floorStore,
  };

  return { ok: true, circuit };
}
