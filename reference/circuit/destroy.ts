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
import { signMessage, verifySignature } from "../identity/keys";
import type { CircuitRevocationStore, CircuitDestroyReplayStore } from "./replay-stores";
import type { ActiveCircuit } from "./circuit";

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
 *   4. The expiry binding (the destroy's expiry matches the circuit's).
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

  // 3. Verify the Ed25519 signature.
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
 * This is the CANONICAL TEARDOWN PROTOCOL PATH. Per ADR-0022:
 *
 *   1. Decode the wire bytes.
 *   2. Verify the CircuitDestroy (signature + routeId + role).
 *   3. Verify the circuit binding (circuitId + commitmentRoot match the
 *      local circuit context).
 *   4. Verify destroyer authorization:
 *      - INITIATOR: destroyerNodeId must match the circuit's initiatorNodeId.
 *      - GATEWAY: destroyerNodeId must match the terminal hop's nodeId.
 *   5. Check durable revocation (if already revoked → idempotent success).
 *   6. Consume the destroy nonce (durable, fail-closed).
 *   7. Write the durable revocation record.
 *   8. Zeroize circuit key material (best-effort).
 *   9. Return the CircuitDestroy for propagation (unchanged — no re-signing).
 *
 * @param wireBytes - the raw canonical-CBOR-encoded CircuitDestroy bytes
 * @param circuit - the local ActiveCircuit (for binding + authorization)
 * @param expectedInitiatorNodeId - the circuit's initiator NodeId (for INITIATOR auth)
 * @param expectedGatewayNodeId - the terminal hop's NodeId (for GATEWAY auth)
 * @param revocationStore - REQUIRED durable revocation store
 * @param destroyReplayStore - REQUIRED durable destroy replay store
 * @param now - current time (unix seconds)
 */
export async function processCircuitDestroy(
  wireBytes: Uint8Array,
  circuit: ActiveCircuit,
  expectedInitiatorNodeId: string,
  expectedGatewayNodeId: string,
  revocationStore: CircuitRevocationStore,
  destroyReplayStore: CircuitDestroyReplayStore,
  now: number,
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

  // 4. Verify destroyer authorization.
  if (destroy.destroyerRole === DESTROYER_ROLE_INITIATOR) {
    if (destroy.destroyerNodeId !== expectedInitiatorNodeId) {
      return {
        ok: false,
        reason: `unauthorized: destroyerNodeId "${destroy.destroyerNodeId}" is not the circuit initiator "${expectedInitiatorNodeId}"`,
      };
    }
  } else if (destroy.destroyerRole === DESTROYER_ROLE_GATEWAY) {
    if (destroy.destroyerNodeId !== expectedGatewayNodeId) {
      return {
        ok: false,
        reason: `unauthorized: destroyerNodeId "${destroy.destroyerNodeId}" is not the terminal gateway "${expectedGatewayNodeId}"`,
      };
    }
  } else {
    return { ok: false, reason: `unauthorized: invalid destroyerRole ${destroy.destroyerRole}` };
  }

  // 5. Check durable revocation (idempotent).
  const alreadyRevoked = await revocationStore.isRevoked(circuit.circuitId, circuit.commitmentRoot);
  if (alreadyRevoked) {
    // Idempotent: the circuit is already revoked. Return success without
    // re-consuming the nonce or re-writing the revocation.
    return { ok: true, idempotent: true, circuitDestroy: destroy };
  }

  // 6. Consume the destroy nonce (durable, fail-closed).
  const consumed = await destroyReplayStore.consume(
    circuit.commitmentRoot,
    circuit.circuitId,
    destroy.destroyNonce,
  );
  if (!consumed) {
    return {
      ok: false,
      reason: "destroy replay: (commitmentRoot, circuitId, destroyNonce) already consumed or persistence failed (fail-closed)",
    };
  }

  // 7. Write the durable revocation record.
  const revoked = await revocationStore.revoke(
    circuit.circuitId,
    circuit.commitmentRoot,
    destroy.destroyerNodeId,
    destroy.destroyerRole,
    destroy.destroyReason,
    destroy.destroyNonce,
  );
  if (!revoked) {
    return {
      ok: false,
      reason: "failed to write durable revocation record (persistence failure, fail-closed)",
    };
  }

  // 8. Zeroize circuit key material (best-effort).
  // The caller is responsible for calling zeroizeCircuit(circuit) from forwarding.ts.
  // We don't import it here to avoid a circular dependency — the caller does it.

  // 9. Return the CircuitDestroy for propagation (unchanged).
  return { ok: true, idempotent: false, circuitDestroy: destroy };
}

/** Constant-time byte equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export { toHex, fromHex };
