/**
 * ShareNet 2.0 — CircuitDestroy wire object + teardown protocol (R-009 Stage 3).
 *
 * Per spec/08 §6.5a + ADR-0022:
 *
 *   CircuitDestroy is the authenticated wire object for explicit circuit
 *   teardown. Authorized originators: the initiator (source) and the
 *   gateway (terminal hop). Relays cannot originate but can propagate.
 *
 * The destroy is:
 *   - Signed by the destroyer's Ed25519 key (portable, no WeakSet).
 *   - Bound to the circuit instance (circuitId + commitmentRoot + routeId).
 *   - Replay-protected via destroyNonce (durable, separate namespace).
 *   - Idempotent: a destroy received after revocation is safe (no-op).
 *
 * The authorization model:
 *   - INITIATOR: proves identity via Ed25519 signature. The destroyerNodeId
 *     must match the route's initiatorNodeId.
 *   - GATEWAY: proves terminal-hop membership via the portable proof chain
 *     (RouteAcceptance signature + Merkle inclusion proof + routeId derivation),
 *     reusing the Stage 2 model.
 *
 * This module defines ONLY the wire object + signing/verification.
 * The durable revocation store + destroy replay store + production
 * integration are in separate modules.
 */

import { randomBytes } from "@noble/hashes/utils.js";
import { canonicalEncode, canonicalDecode, toHex, fromHex } from "../encoding/cbor";
import { signMessage, verifySignature, verifyNodeIdBinding } from "../identity/keys";
import type { CircuitDestroyStore } from "./replay-stores";
import type { ActiveCircuit } from "./circuit";
import { zeroizeCircuit } from "./zeroize";
import { verifyTerminalHopProof, decodeGatewayReturnAuthorization } from "./return-template";

// -----------------------------------------------------------------------
// Constants (R-009 Stage 3 — CircuitDestroy)
// -----------------------------------------------------------------------

/** Domain tag for CircuitDestroy signing (FROZEN per ADR-0022). */
export const CIRCUIT_DESTROY_DOMAIN = "SHARENET/CIRCUIT/DESTROY/1";

/** Destroy originator roles. */
export const DESTROYER_ROLE_INITIATOR = 0x01 as const;
export const DESTROYER_ROLE_GATEWAY = 0x02 as const;

/** Destroy reason codes. */
export const DESTROY_REASON_OPERATOR_INITIATED = 0x01 as const;
export const DESTROY_REASON_CIRCUIT_EXPIRED = 0x02 as const;
export const DESTROY_REASON_LINK_FAILURE = 0x03 as const;
export const DESTROY_REASON_GATEWAY_DISAPPEARANCE = 0x04 as const;
export const DESTROY_REASON_PROTOCOL_VIOLATION = 0x05 as const;

/**
 * Maximum permitted clock skew for CircuitDestroy freshness (FROZEN per
 * ADR-0022 §12 + spec/08 §6.5b).
 *
 * The destroyer's clock (which produced `issuedAt`) may be ahead of the
 * receiver's clock (`now`) by up to this many seconds. A destroy with
 * `issuedAt > now + SKEW` is rejected as "future-dated" — this prevents an
 * attacker who compromises the destroyer's key from pre-signing destroys
 * with arbitrary future timestamps (which could be used to confuse audit
 * trails or to attempt to destroy a circuit before it was established).
 *
 * This skew applies ONLY to the `issuedAt` check. The `expiry` checks are
 * strict (no skew): `now >= expiry` → reject (the destroy is stale), and
 * `expiry > circuit.expiry` → reject (the destroy tries to extend the
 * circuit's lifetime).
 *
 * Value: 300 seconds (5 minutes). This is generous for a delay-tolerant
 * network with potentially drifted mesh-node clocks, while still being
 * tight enough to prevent meaningful future-dated forgery.
 */
export const CIRCUIT_DESTROY_MAX_CLOCK_SKEW_SECONDS = 300 as const;

// -----------------------------------------------------------------------
// CircuitDestroy wire object
// -----------------------------------------------------------------------

/**
 * The authenticated CircuitDestroy wire object.
 *
 * Per spec/08 §6.5a + ADR-0022. Canonical CBOR (integer-keyed map).
 */
export interface CircuitDestroy {
  /** The 32-byte CircuitId (binds to the circuit instance). */
  circuitId: Uint8Array;
  /** The 32-byte commitment_root (route identity). */
  commitmentRoot: Uint8Array;
  /** The route ID (derived from commitmentRoot: "route:" + hex). */
  routeId: string;
  /** The NodeId of the destroyer. */
  destroyerNodeId: string;
  /** The destroyer's role: 0x01 = initiator, 0x02 = gateway. */
  destroyerRole: number;
  /** The destroy reason code (enumerated). */
  destroyReason: number;
  /** Fresh 16-byte nonce for replay protection. */
  destroyNonce: Uint8Array;
  /** When the destroy was issued (unix seconds). */
  issuedAt: number;
  /** The circuit's expiry (for lifetime binding). */
  expiry: number;
  /** The destroyer's Ed25519 public key (verifies the signature). */
  destroyerEd25519PublicKey: Uint8Array;
  /** The destroyer's Ed25519 signature over the binding payload. */
  signature: Uint8Array;
}

// -----------------------------------------------------------------------
// CBOR map keys (per ADR-0004)
// -----------------------------------------------------------------------

const CD_KEY_CIRCUIT_ID = 1;
const CD_KEY_COMMITMENT_ROOT = 2;
const CD_KEY_ROUTE_ID = 3;
const CD_KEY_DESTROYER_NODE_ID = 4;
const CD_KEY_DESTROYER_ROLE = 5;
const CD_KEY_DESTROY_REASON = 6;
const CD_KEY_DESTROY_NONCE = 7;
const CD_KEY_ISSUED_AT = 8;
const CD_KEY_EXPIRY = 9;
const CD_KEY_DESTROYER_ED25519_PUBKEY = 10;
const CD_KEY_SIGNATURE = 11;

// -----------------------------------------------------------------------
// Signing payload construction
// -----------------------------------------------------------------------

/**
 * Compute the signing payload for a CircuitDestroy.
 *
 * The payload binds: domain || circuitId || commitmentRoot || routeId ||
 * destroyerNodeId || destroyerRole || destroyReason || destroyNonce ||
 * issuedAt || expiry.
 *
 * The signature is verified by anyone who has the destroyerEd25519PublicKey
 * — no WeakSet or in-process proof required.
 */
export function circuitDestroySigningPayload(
  circuitId: Uint8Array,
  commitmentRoot: Uint8Array,
  routeId: string,
  destroyerNodeId: string,
  destroyerRole: number,
  destroyReason: number,
  destroyNonce: Uint8Array,
  issuedAt: number,
  expiry: number,
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, circuitId],
    [2, commitmentRoot],
    [3, routeId],
    [4, destroyerNodeId],
    [5, destroyerRole],
    [6, destroyReason],
    [7, destroyNonce],
    [8, issuedAt],
    [9, expiry],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(CIRCUIT_DESTROY_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

// -----------------------------------------------------------------------
// Sign + verify
// -----------------------------------------------------------------------

/**
 * Sign a CircuitDestroy.
 *
 * The DESTROYER calls this to create the authenticated wire object.
 *
 * @param circuitId - 32-byte circuit ID
 * @param commitmentRoot - 32-byte route commitment root
 * @param destroyerNodeId - the destroyer's NodeId
 * @param destroyerRole - 0x01 (initiator) or 0x02 (gateway)
 * @param destroyReason - enumerated reason code
 * @param issuedAt - unix seconds
 * @param expiry - circuit expiry (unix seconds)
 * @param destroyerEd25519SecretKey - the destroyer's Ed25519 secret key
 * @param destroyerEd25519PublicKey - the destroyer's Ed25519 public key
 * @returns the signed CircuitDestroy wire object
 */
export function signCircuitDestroy(
  circuitId: Uint8Array,
  commitmentRoot: Uint8Array,
  destroyerNodeId: string,
  destroyerRole: number,
  destroyReason: number,
  issuedAt: number,
  expiry: number,
  destroyerEd25519SecretKey: Uint8Array,
  destroyerEd25519PublicKey: Uint8Array,
): CircuitDestroy {
  const routeId = "route:" + toHex(commitmentRoot);
  const destroyNonce = randomBytes(16);
  const payload = circuitDestroySigningPayload(
    circuitId, commitmentRoot, routeId,
    destroyerNodeId, destroyerRole, destroyReason,
    destroyNonce, issuedAt, expiry,
  );
  const signature = signMessage(destroyerEd25519SecretKey, payload);
  return {
    circuitId,
    commitmentRoot,
    routeId,
    destroyerNodeId,
    destroyerRole,
    destroyReason,
    destroyNonce,
    issuedAt,
    expiry,
    destroyerEd25519PublicKey,
    signature,
  };
}

/** Result of verifying a CircuitDestroy. */
export type VerifyCircuitDestroyResult =
  | { ok: true; circuitDestroy: CircuitDestroy }
  | { ok: false; reason: string };

/**
 * Verify a CircuitDestroy wire object — from wire bytes alone.
 *
 * This is the PORTABLE verifier. It verifies:
 *   1. The Ed25519 signature (authenticates the destroyer).
 *   2. The routeId derivation (routeId = "route:" + hex(commitmentRoot)).
 *   3. The destroyerRole is valid (0x01 or 0x02).
 *   4. Semantic validity: issuedAt <= expiry (a destroy issued after it
 *      expired is nonsensical — rejected at the structural level).
 *   5. The expiry binding (the destroy's expiry matches the circuit's).
 *
 * Authorization checks (is the destroyer the actual initiator/gateway?)
 * are performed separately by the caller using the circuit context
 * (portable proof chain for gateway, initiatorNodeId match for initiator).
 *
 * @param destroy - the CircuitDestroy wire object
 */
export function verifyCircuitDestroy(
  destroy: CircuitDestroy,
): VerifyCircuitDestroyResult {
  // 1. Verify destroyerRole is valid.
  if (destroy.destroyerRole !== DESTROYER_ROLE_INITIATOR &&
      destroy.destroyerRole !== DESTROYER_ROLE_GATEWAY) {
    return { ok: false, reason: `invalid destroyerRole: ${destroy.destroyerRole}` };
  }

  // 2. Verify routeId derivation.
  const expectedRouteId = "route:" + toHex(destroy.commitmentRoot);
  if (destroy.routeId !== expectedRouteId) {
    return { ok: false, reason: `routeId mismatch: expected "${expectedRouteId}", got "${destroy.routeId}"` };
  }

  // 3. SEMANTIC VALIDITY (R-009 Stage 3 Phase 2 final hardening):
  //    issuedAt <= expiry. A destroy with issuedAt > expiry is nonsensical
  //    (it was issued after it expired). This is a structural check — it
  //    catches a malformed destroy at the portable verifier level, before
  //    the signature check. An attacker cannot construct a validly-signed
  //    destroy with issuedAt > expiry because issuedAt + expiry are both
  //    covered by the signature; the check rejects a destroy that was
  //    correctly signed but semantically invalid (e.g., a buggy destroyer
  //    that set issuedAt = expiry + 1 by mistake).
  if (destroy.issuedAt > destroy.expiry) {
    return {
      ok: false,
      reason: `semantic invalidity: issuedAt ${destroy.issuedAt} > expiry ${destroy.expiry} (a destroy cannot be issued after it expired)`,
    };
  }

  // 4. Verify the Ed25519 signature.
  const payload = circuitDestroySigningPayload(
    destroy.circuitId,
    destroy.commitmentRoot,
    destroy.routeId,
    destroy.destroyerNodeId,
    destroy.destroyerRole,
    destroy.destroyReason,
    destroy.destroyNonce,
    destroy.issuedAt,
    destroy.expiry,
  );
  if (!verifySignature(destroy.destroyerEd25519PublicKey, payload, destroy.signature)) {
    return { ok: false, reason: "destroyer signature invalid (forged or tampered destroy)" };
  }

  return { ok: true, circuitDestroy: destroy };
}

// -----------------------------------------------------------------------
// Encode + decode (canonical CBOR)
// -----------------------------------------------------------------------

/**
 * Encode a CircuitDestroy to canonical CBOR for the wire.
 */
export function encodeCircuitDestroy(cd: CircuitDestroy): Uint8Array {
  const m = new Map<number, unknown>([
    [CD_KEY_CIRCUIT_ID, cd.circuitId],
    [CD_KEY_COMMITMENT_ROOT, cd.commitmentRoot],
    [CD_KEY_ROUTE_ID, cd.routeId],
    [CD_KEY_DESTROYER_NODE_ID, cd.destroyerNodeId],
    [CD_KEY_DESTROYER_ROLE, cd.destroyerRole],
    [CD_KEY_DESTROY_REASON, cd.destroyReason],
    [CD_KEY_DESTROY_NONCE, cd.destroyNonce],
    [CD_KEY_ISSUED_AT, cd.issuedAt],
    [CD_KEY_EXPIRY, cd.expiry],
    [CD_KEY_DESTROYER_ED25519_PUBKEY, cd.destroyerEd25519PublicKey],
    [CD_KEY_SIGNATURE, cd.signature],
  ]);
  return canonicalEncode(m);
}

/**
 * Decode a CircuitDestroy from canonical CBOR wire bytes.
 */
export function decodeCircuitDestroy(bytes: Uint8Array): { ok: true; circuitDestroy: CircuitDestroy } | { ok: false; reason: string } {
  let decoded: unknown;
  try {
    decoded = canonicalDecode(bytes);
  } catch (e) {
    return { ok: false, reason: `CBOR decode failed: ${(e as Error).message}` };
  }
  if (!(decoded instanceof Map)) {
    return { ok: false, reason: "CircuitDestroy must be a CBOR map" };
  }
  const m = decoded as Map<number, unknown>;

  const circuitId = m.get(CD_KEY_CIRCUIT_ID);
  const commitmentRoot = m.get(CD_KEY_COMMITMENT_ROOT);
  const routeId = m.get(CD_KEY_ROUTE_ID);
  const destroyerNodeId = m.get(CD_KEY_DESTROYER_NODE_ID);
  const destroyerRole = m.get(CD_KEY_DESTROYER_ROLE);
  const destroyReason = m.get(CD_KEY_DESTROY_REASON);
  const destroyNonce = m.get(CD_KEY_DESTROY_NONCE);
  const issuedAt = m.get(CD_KEY_ISSUED_AT);
  const expiry = m.get(CD_KEY_EXPIRY);
  const destroyerPubKey = m.get(CD_KEY_DESTROYER_ED25519_PUBKEY);
  const signature = m.get(CD_KEY_SIGNATURE);

  if (!(circuitId instanceof Uint8Array) || circuitId.length !== 32) {
    return { ok: false, reason: "circuitId must be a 32-byte bstr" };
  }
  if (!(commitmentRoot instanceof Uint8Array) || commitmentRoot.length !== 32) {
    return { ok: false, reason: "commitmentRoot must be a 32-byte bstr" };
  }
  if (typeof routeId !== "string") {
    return { ok: false, reason: "routeId must be a text string" };
  }
  if (typeof destroyerNodeId !== "string") {
    return { ok: false, reason: "destroyerNodeId must be a text string" };
  }
  if (typeof destroyerRole !== "number" || !Number.isInteger(destroyerRole)) {
    return { ok: false, reason: "destroyerRole must be an integer" };
  }
  if (typeof destroyReason !== "number" || !Number.isInteger(destroyReason)) {
    return { ok: false, reason: "destroyReason must be an integer" };
  }
  if (!(destroyNonce instanceof Uint8Array) || destroyNonce.length !== 16) {
    return { ok: false, reason: "destroyNonce must be a 16-byte bstr" };
  }
  if (typeof issuedAt !== "number" || !Number.isInteger(issuedAt)) {
    return { ok: false, reason: "issuedAt must be an integer" };
  }
  if (typeof expiry !== "number" || !Number.isInteger(expiry)) {
    return { ok: false, reason: "expiry must be an integer" };
  }
  if (!(destroyerPubKey instanceof Uint8Array) || destroyerPubKey.length !== 32) {
    return { ok: false, reason: "destroyerEd25519PublicKey must be a 32-byte bstr" };
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    return { ok: false, reason: "signature must be a 64-byte bstr" };
  }

  return {
    ok: true,
    circuitDestroy: {
      circuitId,
      commitmentRoot,
      routeId,
      destroyerNodeId,
      destroyerRole,
      destroyReason,
      destroyNonce,
      issuedAt,
      expiry,
      destroyerEd25519PublicKey: destroyerPubKey,
      signature,
    },
  };
}

// -----------------------------------------------------------------------
// processCircuitDestroy — the canonical teardown protocol path (R-009 Stage 3)
// -----------------------------------------------------------------------

/** Result of processing a CircuitDestroy. */
export type ProcessCircuitDestroyResult =
  | { ok: true; idempotent: boolean; circuitDestroy: CircuitDestroy }
  | { ok: false; reason: string };

/**
 * Process a CircuitDestroy at a participant (initiator, relay, or gateway).
 *
 * This is the CANONICAL TEARDOWN PROTOCOL PATH. Per ADR-0022 (amended per the
 * re-audit of 60e4364 — R-009 Stage 3 Phase 2):
 *
 *   1. Decode the wire bytes.
 *   2. Verify the CircuitDestroy (signature + routeId + role) — portable verifier.
 *   3. Verify the circuit binding (circuitId + commitmentRoot match the
 *      local circuit context).
 *   4. FRESHNESS CHECKS (before nonce consumption — a validly signed but
 *      expired/future-dated destroy MUST be rejected before consuming the nonce):
 *      a. issuedAt <= now + SKEW (not future-dated beyond clock skew).
 *      b. now < expiry (not expired — strict: now >= expiry → reject).
 *      c. expiry <= circuit.expiry (destroy's expiry does not exceed the
 *         circuit's actual expiry — prevents lifetime extension via destroy).
 *   5. Verify destroyer authorization (TWO-LAYER identity + role model):
 *      a. verifyNodeIdBinding(destroyerNodeId, destroyerEd25519PublicKey) —
 *         Layer 1: the claimed NodeId MUST derive from the claimed public key.
 *      b. INITIATOR (Layer 2): destroyerNodeId must match the circuit's
 *         initiatorNodeId (expectedInitiatorNodeId — from the authenticated
 *         committed route, verified during setup).
 *      c. GATEWAY (Layer 2): the portable terminal-hop proof chain MUST be
 *         provided (gatewayProofBytes) AND MUST verify — the terminal
 *         RouteAcceptance signature → Merkle inclusion → commitmentRoot →
 *         terminal hop identity → terminal CircuitSetupAck signature →
 *         terminal gateway X25519/Node identity binding. The proof's
 *         relayEd25519PublicKey MUST equal the destroy's
 *         destroyerEd25519PublicKey (the destroy signer IS the ack/acceptance
 *         signer). The proof's terminalNodeId MUST equal the destroy's
 *         destroyerNodeId. expectedGatewayNodeId is checked as a redundant
 *         defense-in-depth (the caller's local route knowledge must agree).
 *
 *         This replaces the previous caller-supplied-only check
 *         (destroyerNodeId === expectedGatewayNodeId) which was insufficient
 *         because expectedGatewayNodeId is a string parameter with no
 *         cryptographic binding to the actual terminal hop. The proof chain
 *         is the SOLE authority for gateway authorization — it works from
 *         serialized protocol artifacts alone (no WeakSet/BrandedCommittedRoute).
 *   6. Check durable revocation (if already revoked → idempotent success +
 *      zeroize, since the tombstone is authoritative and the circuit is dead).
 *   7. ATOMICALLY consume the destroy nonce + write the durable revocation
 *      tombstone (single transaction — both succeed or both fail, no split
 *      security state). Fail-closed.
 *   8. Zeroize circuit key material (best-effort) — OWNED by this function.
 *      The caller is NOT responsible for calling zeroizeCircuit().
 *   9. Return the CircuitDestroy for propagation (unchanged — no re-signing).
 *
 * @param wireBytes - the raw canonical-CBOR-encoded CircuitDestroy bytes
 * @param circuit - the local ActiveCircuit (for binding + authorization)
 * @param expectedInitiatorNodeId - the circuit's initiator NodeId (for INITIATOR auth)
 * @param expectedGatewayNodeId - the terminal hop's NodeId (redundant defense-in-depth
 *   for GATEWAY auth; the primary authority is the gatewayProofBytes proof chain)
 * @param destroyStore - REQUIRED atomic CircuitDestroyStore (consumes nonce +
 *   writes tombstone in a single transaction, no split state)
 * @param now - current time (unix seconds)
 * @param gatewayProofBytes - OPTIONAL: serialized GatewayReturnAuthorization
 *   CBOR bytes. REQUIRED when destroyerRole === GATEWAY (proves the destroyer
 *   is the genuine terminal hop via the portable proof chain). IGNORED when
 *   destroyerRole === INITIATOR.
 */
export async function processCircuitDestroy(
  wireBytes: Uint8Array,
  circuit: ActiveCircuit,
  expectedInitiatorNodeId: string,
  expectedGatewayNodeId: string,
  destroyStore: CircuitDestroyStore,
  now: number,
  gatewayProofBytes?: Uint8Array,
): Promise<ProcessCircuitDestroyResult> {
  // 1. Decode.
  const decoded = decodeCircuitDestroy(wireBytes);
  if (!decoded.ok) {
    return { ok: false, reason: decoded.reason };
  }
  const destroy = decoded.circuitDestroy;

  // 2. Verify the CircuitDestroy (signature + routeId + role).
  const verifyResult = verifyCircuitDestroy(destroy);
  if (!verifyResult.ok) {
    return { ok: false, reason: verifyResult.reason };
  }

  // 3. Verify circuit binding.
  if (!bytesEqual(destroy.circuitId, circuit.circuitId)) {
    return { ok: false, reason: "circuitId mismatch: destroy does not match this circuit" };
  }
  if (!bytesEqual(destroy.commitmentRoot, circuit.commitmentRoot)) {
    return { ok: false, reason: "commitmentRoot mismatch: destroy does not match this circuit" };
  }

  // 4. FRESHNESS CHECKS (R-009 Stage 3 Phase 2 — before nonce consumption).
  //    A validly signed but expired/future-dated destroy MUST be rejected
  //    BEFORE consuming the nonce (so the nonce remains fresh for a valid
  //    retry with a non-expired destroy).
  //
  // 4a. issuedAt must not be too far in the future (clock skew permitted).
  if (destroy.issuedAt > now + CIRCUIT_DESTROY_MAX_CLOCK_SKEW_SECONDS) {
    return {
      ok: false,
      reason: `destroy freshness: issuedAt ${destroy.issuedAt} > now ${now} + skew ${CIRCUIT_DESTROY_MAX_CLOCK_SKEW_SECONDS} (future-dated destroy rejected before nonce consumption)`,
    };
  }
  // 4b. The destroy must not have expired (now < expiry, strict).
  //     Boundary: now == expiry → REJECT (consistent with circuit expiry's
  //     `circuit.expiry <= now` convention in processCircuitWireFrame).
  if (now >= destroy.expiry) {
    return {
      ok: false,
      reason: `destroy freshness: now ${now} >= expiry ${destroy.expiry} (expired destroy rejected before nonce consumption)`,
    };
  }
  // 4c. The destroy's expiry must not exceed the circuit's actual expiry
  //     (prevents an attacker from extending the circuit's lifetime via a
  //     destroy with a later expiry — the destroy is evidence of the circuit's
  //     lifetime, and it MUST NOT contradict the circuit's established expiry).
  if (destroy.expiry > circuit.expiry) {
    return {
      ok: false,
      reason: `destroy freshness: destroy expiry ${destroy.expiry} > circuit.expiry ${circuit.expiry} (destroy tries to extend circuit lifetime — rejected)`,
    };
  }

  // 5. Verify destroyer authorization (TWO-LAYER identity + role model).

  // 5a. IDENTITY BINDING (Layer 1 — closes the identity authorization bypass).
  if (!verifyNodeIdBinding(destroy.destroyerNodeId, destroy.destroyerEd25519PublicKey)) {
    return {
      ok: false,
      reason: "unauthorized: destroyerEd25519PublicKey does not derive destroyerNodeId (identity binding failed) — forged destroy rejected",
    };
  }

  // 5b. ROLE AUTHORIZATION (Layer 2).
  if (destroy.destroyerRole === DESTROYER_ROLE_INITIATOR) {
    // INITIATOR: the destroyerNodeId must match the circuit's initiatorNodeId.
    // expectedInitiatorNodeId comes from the authenticated committed route
    // (verified during setup). The Layer 1 check proves the destroy's key
    // derives the claimed NodeId; this check proves the claimed NodeId IS the
    // circuit's initiator.
    if (destroy.destroyerNodeId !== expectedInitiatorNodeId) {
      return {
        ok: false,
        reason: `unauthorized: destroyerNodeId "${destroy.destroyerNodeId}" is not the circuit initiator "${expectedInitiatorNodeId}"`,
      };
    }
  } else if (destroy.destroyerRole === DESTROYER_ROLE_GATEWAY) {
    // GATEWAY: the portable terminal-hop proof chain MUST verify.
    // This replaces the previous caller-supplied-only check
    // (destroyerNodeId === expectedGatewayNodeId) which was insufficient
    // because expectedGatewayNodeId is a string parameter with no
    // cryptographic binding to the actual terminal hop.
    //
    // The proof chain (a serialized GatewayReturnAuthorization) verifies:
    //   - terminal RouteAcceptance signature (by relayEd25519PublicKey)
    //   - Merkle inclusion (acceptance is in commitmentRoot)
    //   - commitmentRoot matches circuit.commitmentRoot (proof is for THIS route)
    //   - terminal hop identity (hopIndex == last, hopNodeIds[hopIndex] == terminalNodeId)
    //   - terminal CircuitSetupAck signature (by relayEd25519PublicKey)
    //   - ack freshness (ackExpiry > now — defense-in-depth)
    // All from serialized protocol artifacts — NO WeakSet/BrandedCommittedRoute.
    if (!gatewayProofBytes) {
      return {
        ok: false,
        reason: "unauthorized: gateway destroy requires portable terminal-hop proof (gatewayProofBytes) — caller-supplied expectedGatewayNodeId alone is insufficient",
      };
    }
    const proofDecoded = decodeGatewayReturnAuthorization(gatewayProofBytes);
    if (!proofDecoded.ok) {
      return { ok: false, reason: `unauthorized: failed to decode gateway proof: ${proofDecoded.reason}` };
    }
    const proofResult = verifyTerminalHopProof(
      proofDecoded.authorization,
      circuit.commitmentRoot,
      now,
    );
    if (!proofResult.ok) {
      return {
        ok: false,
        reason: `unauthorized: gateway terminal-hop proof chain verification failed: ${proofResult.reason}`,
      };
    }
    // The destroy's destroyerEd25519PublicKey MUST be the SAME key that signed
    // the terminal ack + acceptance. This proves the destroy was signed by
    // the genuine terminal hop (the relay that acked + accepted the route),
    // not an attacker who merely learned the gateway's NodeId string.
    if (!bytesEqual(destroy.destroyerEd25519PublicKey, proofResult.relayEd25519PublicKey)) {
      return {
        ok: false,
        reason: "unauthorized: destroyerEd25519PublicKey does not match the terminal-hop proof's relayEd25519PublicKey (the destroy signer is NOT the ack/acceptance signer)",
      };
    }
    // The destroy's destroyerNodeId MUST match the proof's terminalNodeId.
    // (This is implied by Layer 1 + the pubkey match, but check explicitly
    // for defense-in-depth + a clear error message.)
    if (destroy.destroyerNodeId !== proofResult.terminalNodeId) {
      return {
        ok: false,
        reason: `unauthorized: destroyerNodeId "${destroy.destroyerNodeId}" does not match the terminal-hop proof's terminalNodeId "${proofResult.terminalNodeId}"`,
      };
    }
    // Redundant defense-in-depth: the caller's expectedGatewayNodeId must agree
    // with the proof's terminalNodeId. If they disagree, something is wrong
    // (either the proof is forged or the caller's route is wrong) — reject.
    if (destroy.destroyerNodeId !== expectedGatewayNodeId) {
      return {
        ok: false,
        reason: `unauthorized: destroyerNodeId "${destroy.destroyerNodeId}" matches the proof but not the caller's expectedGatewayNodeId "${expectedGatewayNodeId}" (defense-in-depth: caller's route knowledge disagrees with the proof)`,
      };
    }
  } else {
    return { ok: false, reason: `unauthorized: invalid destroyerRole ${destroy.destroyerRole}` };
  }

  // 6. Check durable revocation (idempotent).
  const alreadyRevoked = await destroyStore.isRevoked(circuit.circuitId, circuit.commitmentRoot);
  if (alreadyRevoked) {
    // Idempotent: the circuit is already revoked. The durable tombstone is
    // the authoritative terminal-state record (per ADR-0022 §5 + spec/08
    // §6.3): if it exists, the circuit is CIRCUIT_REVOKED regardless of any
    // local transient state. Return success without re-consuming the nonce
    // or re-writing the revocation. Zeroize is idempotent (re-filling zeros
    // is a no-op if keys were already zeroized by the prior destroy).
    zeroizeCircuit(circuit);
    return { ok: true, idempotent: true, circuitDestroy: destroy };
  }

  // 7. ATOMICALLY consume the destroy nonce + write the durable revocation
  //    tombstone (single transaction — no split security state).
  //    Per the re-audit of 60e4364 (Phase 2): the previous design used two
  //    separate operations (consume + revoke) that could leave a SPLIT state
  //    if one succeeded and the other failed. The atomic operation ensures
  //    both succeed or both fail. Fail-closed: if the transaction fails,
  //    NEITHER the nonce is consumed NOR the tombstone is written — the
  //    operator can safely retry with the SAME destroy (the nonce is still fresh).
  const atomicResult = await destroyStore.consumeDestroyAndRevoke(
    circuit.commitmentRoot,
    circuit.circuitId,
    destroy.destroyNonce,
    destroy.destroyerNodeId,
    destroy.destroyerRole,
    destroy.destroyReason,
  );
  if (!atomicResult.ok) {
    // Transaction failed — fail closed. NO split state: the nonce was NOT
    // consumed (the transaction rolled back). The operator can retry with the
    // SAME destroy (the nonce is still fresh).
    return {
      ok: false,
      reason: `atomic consumeDestroyAndRevoke failed: ${atomicResult.reason} (fail-closed, no split state — nonce NOT consumed, tombstone NOT written, safe to retry)`,
    };
  }

  // 8. Zeroize circuit key material (best-effort) — OWNED by processCircuitDestroy.
  // The tombstone is confirmed persisted (step 7's atomic transaction committed),
  // so it is safe to destroy the keys.
  zeroizeCircuit(circuit);

  // 9. Return the CircuitDestroy for propagation (unchanged).
  return { ok: true, idempotent: atomicResult.idempotent, circuitDestroy: destroy };
}

/** Constant-time byte equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export { toHex, fromHex };
