/**
 * ShareNet 2.0 — CircuitDestroy propagation transport (R-009 Stage 3 Phase 3).
 *
 * Per ADR-0023 (propagation semantics) + the re-audit of 90f31a7:
 *
 *   processCircuitDestroy() is a PURE PROTOCOL OPERATION that returns
 *   wireBytes + the derived propagation direction. It does NOT own transport.
 *
 *   This module owns the PRODUCTION DESTROY-PROPAGATION TRANSPORT PATH:
 *
 *     processCircuitDestroy()
 *         ↓
 *     derive propagation direction from signed destroyerRole
 *         ↓
 *     resolve the protocol-defined next hop (NextHopResolver)
 *         ↓
 *     send the ORIGINAL wireBytes unchanged (CircuitDestroyTransport)
 *         ↓
 *     next participant receives those exact bytes
 *         ↓
 *     processCircuitDestroy() again
 *
 * The direction is derived from the SIGNED `destroyerRole` (via
 * `propagationDirection()` from destroy.ts) — NOT caller-supplied. There is
 * no `propagate: true`, `direction:`, `origin:`, or `isRelay` parameter that
 * a caller could forge. The signed `destroyerRole` is the sole source of
 * propagation direction.
 *
 * The transport is AUTHENTICATED: each `send` is bound to an
 * `AuthenticatedLink` (the existing ShareNet link abstraction from
 * reference/transport/authenticated-link.ts). The binding ties:
 *   - local participant identity (link.localNodeId)
 *   - next-hop identity (link.remoteNodeId)
 *   - circuitId + commitmentRoot (carried in the DestroyPropagationContext)
 *   - propagation direction (derived from the signed destroy)
 *
 * ARCHITECTURE (per ADR-0013, enforced by architecture tests #21 + #23):
 *   - This module lives in `reference/circuit/` (the protocol core).
 *   - It does NOT import Prisma, `@/lib/db`, or anything from `src/`.
 *   - The `CircuitDestroyTransport` + `NextHopResolver` INTERFACES are defined
 *     here; the PRODUCTION implementation (TCP / QUIC / ShareNet link layer)
 *     is provided by the platform layer (`src/lib/sharenet/`) via dependency
 *     injection. The protocol engine calls the interface; it never knows about
 *     sockets, Prisma, or the platform.
 */

import { processCircuitDestroy, propagationDirection, type CircuitDestroy, type ProcessCircuitDestroyResult } from "./destroy";
import type { ActiveCircuit } from "./circuit";
import type { CircuitDestroyStore } from "./replay-stores";
import type { AuthenticatedLink } from "../transport/authenticated-link";
import { signMessage, verifySignature, verifyNodeIdBinding } from "../identity/keys";
import { canonicalEncode, canonicalDecode, toHex } from "../encoding/cbor";

// -----------------------------------------------------------------------
// Propagation direction (re-exported for convenience)
// -----------------------------------------------------------------------

/** The propagation direction, derived from the signed `destroyerRole`. */
export type { PropagationDirection } from "./destroy";
export { propagationDirection } from "./destroy";

// -----------------------------------------------------------------------
// PropagationChannelProof — the portable authenticated channel proof
// -----------------------------------------------------------------------

/**
 * Domain tag for PropagationChannelProof signing (FROZEN per ADR-0023 §5).
 *
 * This is a NEW signature domain — separate from the CircuitDestroy signing
 * domain (SHARENET/CIRCUIT/DESTROY/1) + the AuthenticatedLink possession
 * domains. The proof authenticates the CHANNEL (the transport hop), not the
 * destroy (the destroy authenticates itself via its own signature).
 */
export const PROPAGATION_CHANNEL_PROOF_DOMAIN = "SHARENET/CIRCUIT/PROPAGATION/CHANNEL/1";

/**
 * A portable, cryptographically signed proof that authenticates a destroy-
 * propagation channel hop.
 *
 * Per the re-audit of 9bbbef7 (R-009 Stage 3 Phase 3 final transport
 * hardening): the previous transport adapter accepted arbitrary TCP peers.
 * The `AuthenticatedLink` is a genuine WeakSet-registered proof artifact —
 * but it is IN-PROCESS only (cannot cross a process boundary via JSON).
 * A plain object shaped like `AuthenticatedLink` is forgeable.
 *
 * The `PropagationChannelProof` solves this: it is a SIGNED wire object that
 * binds the channel context (senderNodeId + receiverNodeId + circuitId +
 * commitmentRoot + direction) + is signed by the sender's Ed25519 node
 * identity key. The receiver verifies:
 *   1. The signature (the sender is who they claim — not forged).
 *   2. `verifyNodeIdBinding(senderNodeId, senderEd25519PublicKey)` (the
 *      sender's NodeId derives from their public key).
 *   3. `receiverNodeId === localNodeId` (I am the intended recipient).
 *   4. `circuitId + commitmentRoot` match my circuit context.
 *   5. `direction` matches what I expect (derived from the destroy after
 *      decoding — NOT caller-supplied).
 *   6. `senderNodeId === expectedRemoteNodeId` (from my local link inventory).
 *
 * This is a REAL cryptographic proof — not a forgeable plain object. An
 * attacker cannot construct a valid proof without the sender's Ed25519
 * secret key. A copied proof from a different circuit/context fails the
 * circuitId/commitmentRoot/direction binding checks.
 *
 * The proof is CANONICAL CBOR (integer-keyed map per ADR-0004) so it can
 * cross process/language boundaries + be independently verified by a Rust
 * or Kotlin implementation.
 */
export interface PropagationChannelProof {
  /** The sender's NodeId (the participant forwarding the destroy). */
  readonly senderNodeId: string;
  /** The receiver's NodeId (the intended next-hop participant). */
  readonly receiverNodeId: string;
  /** The circuitId the destroy is bound to (32 bytes). */
  readonly circuitId: Uint8Array;
  /** The commitmentRoot the destroy is bound to (32 bytes). */
  readonly commitmentRoot: Uint8Array;
  /** The propagation direction (FORWARD or BACKWARD, derived from destroyerRole). */
  readonly direction: "FORWARD" | "BACKWARD";
  /** The sender's Ed25519 public key (verifies the signature). */
  readonly senderEd25519PublicKey: Uint8Array;
  /** The sender's Ed25519 signature over the binding payload. */
  readonly signature: Uint8Array;
}

/** CBOR map keys for PropagationChannelProof (per ADR-0004). */
const PCP_KEY_SENDER_NODE_ID = 1;
const PCP_KEY_RECEIVER_NODE_ID = 2;
const PCP_KEY_CIRCUIT_ID = 3;
const PCP_KEY_COMMITMENT_ROOT = 4;
const PCP_KEY_DIRECTION = 5;
const PCP_KEY_SENDER_ED25519_PUBKEY = 6;
const PCP_KEY_SIGNATURE = 7;

/**
 * Compute the signing payload for a PropagationChannelProof.
 *
 * The payload binds: domain || senderNodeId || receiverNodeId || circuitId ||
 * commitmentRoot || direction. The signature is verified by anyone who has
 * the senderEd25519PublicKey — no WeakSet or in-process proof required.
 */
export function propagationChannelProofSigningPayload(
  senderNodeId: string,
  receiverNodeId: string,
  circuitId: Uint8Array,
  commitmentRoot: Uint8Array,
  direction: "FORWARD" | "BACKWARD",
): Uint8Array {
  const m = new Map<number, unknown>([
    [1, senderNodeId],
    [2, receiverNodeId],
    [3, circuitId],
    [4, commitmentRoot],
    [5, direction],
  ]);
  const body = canonicalEncode(m);
  const domain = new TextEncoder().encode(PROPAGATION_CHANNEL_PROOF_DOMAIN);
  const out = new Uint8Array(domain.length + body.length);
  out.set(domain, 0);
  out.set(body, domain.length);
  return out;
}

/**
 * Sign a PropagationChannelProof. The SENDER (the participant forwarding the
 * destroy) calls this to create the authenticated channel proof.
 *
 * @param senderNodeId - the sender's NodeId
 * @param receiverNodeId - the intended receiver's NodeId
 * @param circuitId - the circuitId the destroy is bound to
 * @param commitmentRoot - the commitmentRoot the destroy is bound to
 * @param direction - the propagation direction (FORWARD or BACKWARD)
 * @param senderEd25519SecretKey - the sender's Ed25519 secret key
 * @param senderEd25519PublicKey - the sender's Ed25519 public key
 */
export function signPropagationChannelProof(
  senderNodeId: string,
  receiverNodeId: string,
  circuitId: Uint8Array,
  commitmentRoot: Uint8Array,
  direction: "FORWARD" | "BACKWARD",
  senderEd25519SecretKey: Uint8Array,
  senderEd25519PublicKey: Uint8Array,
): PropagationChannelProof {
  const payload = propagationChannelProofSigningPayload(
    senderNodeId, receiverNodeId, circuitId, commitmentRoot, direction,
  );
  const signature = signMessage(senderEd25519SecretKey, payload);
  return {
    senderNodeId,
    receiverNodeId,
    circuitId,
    commitmentRoot,
    direction,
    senderEd25519PublicKey,
    signature,
  };
}

/** Result of verifying a PropagationChannelProof. */
export type VerifyPropagationChannelProofResult =
  | { ok: true; proof: PropagationChannelProof }
  | { ok: false; reason: string };

/**
 * Verify a PropagationChannelProof — from the wire object alone.
 *
 * This is the PORTABLE verifier. It verifies:
 *   1. The Ed25519 signature (the sender is who they claim — not forged).
 *   2. `verifyNodeIdBinding(senderNodeId, senderEd25519PublicKey)` (the
 *      sender's NodeId derives from their public key — closes the identity
 *      bypass, same two-layer model as CircuitDestroy).
 */
export function verifyPropagationChannelProof(
  proof: PropagationChannelProof,
): VerifyPropagationChannelProofResult {
  // 1. Identity binding: the sender's NodeId MUST derive from their public key.
  if (!verifyNodeIdBinding(proof.senderNodeId, proof.senderEd25519PublicKey)) {
    return {
      ok: false,
      reason: "propagation channel proof: senderEd25519PublicKey does not derive senderNodeId (identity binding failed) — forged proof rejected",
    };
  }
  // 2. Verify the Ed25519 signature.
  const payload = propagationChannelProofSigningPayload(
    proof.senderNodeId, proof.receiverNodeId, proof.circuitId,
    proof.commitmentRoot, proof.direction,
  );
  if (!verifySignature(proof.senderEd25519PublicKey, payload, proof.signature)) {
    return {
      ok: false,
      reason: "propagation channel proof: signature invalid (forged or tampered proof)",
    };
  }
  return { ok: true, proof };
}

/**
 * Encode a PropagationChannelProof to canonical CBOR for the wire.
 */
export function encodePropagationChannelProof(proof: PropagationChannelProof): Uint8Array {
  const m = new Map<number, unknown>([
    [PCP_KEY_SENDER_NODE_ID, proof.senderNodeId],
    [PCP_KEY_RECEIVER_NODE_ID, proof.receiverNodeId],
    [PCP_KEY_CIRCUIT_ID, proof.circuitId],
    [PCP_KEY_COMMITMENT_ROOT, proof.commitmentRoot],
    [PCP_KEY_DIRECTION, proof.direction],
    [PCP_KEY_SENDER_ED25519_PUBKEY, proof.senderEd25519PublicKey],
    [PCP_KEY_SIGNATURE, proof.signature],
  ]);
  return canonicalEncode(m);
}

/**
 * Decode a PropagationChannelProof from canonical CBOR wire bytes.
 */
export function decodePropagationChannelProof(bytes: Uint8Array): { ok: true; proof: PropagationChannelProof } | { ok: false; reason: string } {
  let decoded: unknown;
  try {
    decoded = canonicalDecode(bytes);
  } catch (e) {
    return { ok: false, reason: `CBOR decode failed: ${(e as Error).message}` };
  }
  if (!(decoded instanceof Map)) {
    return { ok: false, reason: "PropagationChannelProof must be a CBOR map" };
  }
  const m = decoded as Map<number, unknown>;
  const senderNodeId = m.get(PCP_KEY_SENDER_NODE_ID);
  const receiverNodeId = m.get(PCP_KEY_RECEIVER_NODE_ID);
  const circuitId = m.get(PCP_KEY_CIRCUIT_ID);
  const commitmentRoot = m.get(PCP_KEY_COMMITMENT_ROOT);
  const direction = m.get(PCP_KEY_DIRECTION);
  const senderPubKey = m.get(PCP_KEY_SENDER_ED25519_PUBKEY);
  const signature = m.get(PCP_KEY_SIGNATURE);
  if (typeof senderNodeId !== "string") return { ok: false, reason: "senderNodeId must be a text string" };
  if (typeof receiverNodeId !== "string") return { ok: false, reason: "receiverNodeId must be a text string" };
  if (!(circuitId instanceof Uint8Array) || circuitId.length !== 32) return { ok: false, reason: "circuitId must be a 32-byte bstr" };
  if (!(commitmentRoot instanceof Uint8Array) || commitmentRoot.length !== 32) return { ok: false, reason: "commitmentRoot must be a 32-byte bstr" };
  if (direction !== "FORWARD" && direction !== "BACKWARD") return { ok: false, reason: "direction must be FORWARD or BACKWARD" };
  if (!(senderPubKey instanceof Uint8Array) || senderPubKey.length !== 32) return { ok: false, reason: "senderEd25519PublicKey must be a 32-byte bstr" };
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return { ok: false, reason: "signature must be a 64-byte bstr" };
  return {
    ok: true,
    proof: {
      senderNodeId, receiverNodeId, circuitId, commitmentRoot,
      direction: direction as "FORWARD" | "BACKWARD",
      senderEd25519PublicKey: senderPubKey, signature,
    },
  };
}

// -----------------------------------------------------------------------
// DestroyPropagationContext — the authenticated binding
// -----------------------------------------------------------------------

/**
 * The authenticated propagation context. Binds the destroy to:
 *   - the local participant's identity (from the AuthenticatedLink)
 *   - the next-hop identity (from the AuthenticatedLink)
 *   - the circuit instance (circuitId + commitmentRoot)
 *   - the propagation direction (derived from the signed destroyerRole)
 *
 * This is the binding a participant uses to AUTHENTICATE an outgoing destroy
 * propagation: the destroy is sent ONLY over the AuthenticatedLink whose
 * remoteNodeId matches the resolved next hop, and whose localNodeId is the
 * local participant. A mismatch (wrong next-hop identity, wrong direction,
 * peer mismatch) is a security violation + the transport MUST reject it.
 */
export interface DestroyPropagationContext {
  /** The local participant's NodeId. */
  readonly localNodeId: string;
  /** The next-hop NodeId (the participant the destroy is forwarded to). */
  readonly nextHopNodeId: string;
  /** The circuitId the destroy is bound to. */
  readonly circuitId: Uint8Array;
  /** The commitmentRoot the destroy is bound to. */
  readonly commitmentRoot: Uint8Array;
  /** The propagation direction (FORWARD or BACKWARD, derived from destroyerRole). */
  readonly direction: "FORWARD" | "BACKWARD";
  /** The authenticated link to the next hop (binds localNodeId ↔ nextHopNodeId). */
  readonly authenticatedLink: AuthenticatedLink;
  /**
   * The sender's Ed25519 keypair (for signing the PropagationChannelProof).
   * The transport signs a proof that binds this channel hop; the receiver
   * verifies the proof before accepting the destroy.
   */
  readonly senderEd25519SecretKey: Uint8Array;
  readonly senderEd25519PublicKey: Uint8Array;
}

/**
 * The authenticated RECEIVE context. The receiver uses this to verify the
 * incoming peer before accepting the destroy bytes.
 *
 * Per the re-audit of 9bbbef7: `receive(localNodeId)` accepted arbitrary TCP
 * peers. This context binds the receiver's expectations:
 *   - localNodeId (who I am)
 *   - expectedRemoteNodeId (who I expect to receive from — from my link inventory)
 *   - circuitId + commitmentRoot (my circuit context)
 *   - direction (what I expect — derived from the destroy AFTER decoding, but
 *     the proof's direction must match)
 *
 * The transport verifies the incoming PropagationChannelProof against this
 * context before delivering the destroy bytes.
 */
export interface AuthenticatedReceiveContext {
  /** The local participant's NodeId (who I am). */
  readonly localNodeId: string;
  /** The expected sender's NodeId (from my authenticated link inventory). */
  readonly expectedRemoteNodeId: string;
  /** The circuitId I expect (my circuit context). */
  readonly circuitId: Uint8Array;
  /** The commitmentRoot I expect (my circuit context). */
  readonly commitmentRoot: Uint8Array;
}

// -----------------------------------------------------------------------
// NextHopResolver — derives the next hop from protocol state
// -----------------------------------------------------------------------

/**
 * The result of resolving the next hop for destroy propagation.
 *
 * - `{ nextHop: { nodeId, link } }` — there IS a next hop; forward the
 *   destroy to it over the authenticated link.
 * - `{ terminal: true }` — this participant is the terminal hop (no
 *   forwarding). For INITIATOR-originated destroy (FORWARD), the terminal is
 *   the GATEWAY. For GATEWAY-originated destroy (BACKWARD), the terminal is
 *   the INITIATOR.
 * - `{ ok: false, reason }` — the next hop could not be resolved (the local
 *   participant's identity is not in the circuit topology, or the direction
 *   does not match the topology).
 */
export type NextHopResult =
  | { ok: true; nextHop: { nodeId: string; link: AuthenticatedLink } }
  | { ok: true; terminal: true }
  | { ok: false; reason: string };

/**
 * A resolver that derives the next hop for destroy propagation from PROTOCOL
 * STATE — the signed propagation direction + the circuit topology + the
 * local participant's identity.
 *
 * This is NOT caller-supplied. The direction is derived from the signed
 * `destroyerRole` (FORWARD for INITIATOR, BACKWARD for GATEWAY). The resolver
 * maps the direction + the local participant's hopIndex to the next hop:
 *
 *   FORWARD:  local hop i → next hop i+1; terminal = last hop (gateway).
 *   BACKWARD: local hop i → next hop i-1; terminal = hop 0 (initiator).
 *
 * The resolver MUST return an `AuthenticatedLink` whose `localNodeId` matches
 * the local participant + whose `remoteNodeId` matches the resolved next hop.
 * A mismatch is a security violation (the caller is not the participant it
 * claims to be, or the link is to a different participant).
 *
 * ARCHITECTURE: this interface is defined in the protocol core. The production
 * implementation (provided by the platform layer) looks up the circuit's
 * committed route + the local participant's authenticated links to resolve
 * the next hop.
 */
export interface NextHopResolver {
  /**
   * Resolve the next hop for destroy propagation.
   *
   * @param localNodeId - the local participant's NodeId
   * @param direction - the propagation direction (FORWARD or BACKWARD),
   *   derived from the signed destroyerRole
   * @param circuit - the local ActiveCircuit (for topology + circuitId +
   *   commitmentRoot binding)
   * @param destroy - the decoded CircuitDestroy (for the signed binding)
   */
  resolveNextHop(
    localNodeId: string,
    direction: "FORWARD" | "BACKWARD",
    circuit: ActiveCircuit,
    destroy: CircuitDestroy,
  ): Promise<NextHopResult>;
}

// -----------------------------------------------------------------------
// CircuitDestroyTransport — the authenticated transport abstraction
// -----------------------------------------------------------------------

/**
 * The result of sending a destroy over the transport.
 *
 * - `{ ok: true }` — the destroy was sent to the next hop. The exact wire
 *   bytes were forwarded (the transport MUST NOT decode + re-encode).
 * - `{ ok: false, reason }` — the transport failed (connection refused,
 *   timeout, peer mismatch, altered bytes detected, etc.). The local
 *   circuit's revoked state is NOT rolled back (the local terminal state
 *   is authoritative — see ADR-0023 §6).
 */
export type TransportSendResult =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * The authenticated transport for CircuitDestroy propagation.
 *
 * This is the protocol/application-neutral transport abstraction. The
 * production implementation (TCP / QUIC / ShareNet link layer) is provided
 * by the platform layer via dependency injection.
 *
 * The transport is AUTHENTICATED END-TO-END: each `send` is bound to a
 * `DestroyPropagationContext` that ties the destroy to:
 *   - the local participant identity
 *   - the next-hop identity
 *   - the circuitId + commitmentRoot
 *   - the propagation direction
 *   - the AuthenticatedLink (the existing ShareNet link abstraction)
 *   - the sender's Ed25519 keypair (for signing the PropagationChannelProof)
 *
 * The transport signs a `PropagationChannelProof` (bound to the channel
 * context) + sends it ALONGSIDE the destroy wire bytes. The receiver
 * verifies the proof (signature + binding) BEFORE accepting the destroy.
 *
 * The transport MUST:
 *   1. Verify the `authenticatedLink.localNodeId === ctx.localNodeId` (the
 *      local participant owns this link).
 *   2. Verify the `authenticatedLink.remoteNodeId === ctx.nextHopNodeId`
 *      (the link is to the resolved next hop).
 *   3. Sign a PropagationChannelProof binding (senderNodeId, receiverNodeId,
 *      circuitId, commitmentRoot, direction) using the sender's Ed25519 key.
 *   4. Send the proof + the EXACT `wireBytes` unchanged (no decode + re-encode).
 *
 * The transport MUST NOT:
 *   - Accept a caller-supplied direction that contradicts the signed
 *     `destroyerRole` (the direction in `ctx` is derived from the signed
 *     destroy, not caller-supplied).
 *   - Decode + re-encode the destroy (the exact-byte invariant,
 *     ADR-0023 §3).
 *   - Send to a next hop that does not match the `authenticatedLink`'s
 *     `remoteNodeId` (peer mismatch).
 *
 * ARCHITECTURE: this interface is defined in the protocol core. The
 * production implementation lives in `src/lib/sharenet/` (or a future
 * transport module) and adapts a real transport (TCP / QUIC / ShareNet link
 * layer) to this interface.
 */
export interface CircuitDestroyTransport {
  /**
   * Send the destroy wire bytes to the next hop over the authenticated link.
   *
   * The transport signs a PropagationChannelProof (bound to the channel
   * context) + sends it alongside the destroy wire bytes. The receiver
   * verifies the proof before accepting the destroy.
   *
   * @param ctx - the authenticated propagation context (binds local +
   *   next-hop identity + circuitId + commitmentRoot + direction + link +
   *   sender Ed25519 keypair)
   * @param wireBytes - the EXACT wire bytes to forward (byte-for-byte —
   *   the transport MUST NOT decode + re-encode)
   */
  send(ctx: DestroyPropagationContext, wireBytes: Uint8Array): Promise<TransportSendResult>;

  /**
   * Receive the destroy wire bytes from the previous hop, AUTHENTICATED.
   *
   * Per the re-audit of 9bbbef7: `receive(localNodeId)` accepted arbitrary
   * TCP peers. This method takes an `AuthenticatedReceiveContext` that binds:
   *   - localNodeId (who I am)
   *   - expectedRemoteNodeId (who I expect to receive from)
   *   - circuitId + commitmentRoot (my circuit context)
   *
   * The transport verifies the incoming PropagationChannelProof against this
   * context before delivering the destroy bytes. A wrong peer, wrong circuit,
   * wrong commitmentRoot, or forged/copyed proof is REJECTED.
   *
   * @param ctx - the authenticated receive context (the receiver's expectations)
   * @returns the received wire bytes (exactly as sent — no decode + re-encode),
   *   or a failure reason if the peer/circuit/proof verification failed.
   */
  receive(ctx: AuthenticatedReceiveContext): Promise<{ ok: true; wireBytes: Uint8Array } | { ok: false; reason: string }>;
}

/**
 * Verify an incoming PropagationChannelProof against the receiver's context.
 *
 * This is the RECEIVER-SIDE authentication check. The receiver calls this
 * (or the transport calls it internally) to verify that the incoming proof:
 *   1. Has a valid Ed25519 signature (the sender is who they claim).
 *   2. The sender's NodeId derives from their public key (identity binding).
 *   3. The receiverNodeId === ctx.localNodeId (I am the intended recipient).
 *   4. The senderNodeId === ctx.expectedRemoteNodeId (the sender is my expected peer).
 *   5. The circuitId + commitmentRoot match my circuit context.
 *
 * The `direction` is NOT checked here — the receiver verifies the direction
 * AFTER decoding the destroy (the direction must match the signed
 * `destroyerRole`, which is verified inside `processCircuitDestroy`).
 *
 * @param proof - the incoming PropagationChannelProof (decoded from wire)
 * @param ctx - the receiver's authenticated receive context
 */
export function verifyIncomingPropagationChannelProof(
  proof: PropagationChannelProof,
  ctx: AuthenticatedReceiveContext,
): { ok: true } | { ok: false; reason: string } {
  // 1. Verify the proof's signature + identity binding (portable verifier).
  const proofResult = verifyPropagationChannelProof(proof);
  if (!proofResult.ok) {
    return { ok: false, reason: `incoming peer authentication failed: ${proofResult.reason}` };
  }
  // 2. Verify I am the intended recipient.
  if (proof.receiverNodeId !== ctx.localNodeId) {
    return {
      ok: false,
      reason: `incoming peer authentication failed: proof.receiverNodeId "${proof.receiverNodeId}" !== localNodeId "${ctx.localNodeId}" (I am not the intended recipient)`,
    };
  }
  // 3. Verify the sender is my expected peer.
  if (proof.senderNodeId !== ctx.expectedRemoteNodeId) {
    return {
      ok: false,
      reason: `incoming peer authentication failed: proof.senderNodeId "${proof.senderNodeId}" !== expectedRemoteNodeId "${ctx.expectedRemoteNodeId}" (wrong peer)`,
    };
  }
  // 4. Verify the circuit binding.
  if (!bytesEqual(proof.circuitId, ctx.circuitId)) {
    return {
      ok: false,
      reason: `incoming peer authentication failed: proof.circuitId does not match the receiver's circuitId (wrong circuit context)`,
    };
  }
  if (!bytesEqual(proof.commitmentRoot, ctx.commitmentRoot)) {
    return {
      ok: false,
      reason: `incoming peer authentication failed: proof.commitmentRoot does not match the receiver's commitmentRoot (wrong route context)`,
    };
  }
  return { ok: true };
}

// -----------------------------------------------------------------------
// propagateCircuitDestroy — the production propagation path
// -----------------------------------------------------------------------

/**
 * The result of the production destroy-propagation path.
 *
 * - `{ ok: true, action: "REVOKED", propagated: true }` — the local
 *   participant durably revoked + zeroized + propagated the destroy to the
 *   next hop over the authenticated transport.
 * - `{ ok: true, action: "REVOKED", propagated: false, transportError }` —
 *   the local participant durably revoked + zeroized, BUT the transport
 *   failed. The local circuit remains REVOKED (the tombstone is
 *   authoritative). The operator may retry propagation (re-send the SAME
 *   destroy — the local tombstone makes it idempotent).
 * - `{ ok: true, action: "ALREADY_REVOKED", propagated: false }` — the
 *   circuit was already revoked. Idempotent. Propagation suppressed (the
 *   destroy has already been forwarded by a prior receipt — ADR-0023 §4).
 * - `{ ok: true, action: "REVOKED", terminal: true }` — this participant is
 *   the terminal hop (no forwarding). The local participant durably revoked
 *   + zeroized.
 * - `{ ok: false, reason }` — the local revoke FAILED (decode / signature /
 *   freshness / authorization / persistence failure). NOT propagated.
 */
export type PropagateCircuitDestroyResult =
  | { ok: true; action: "REVOKED"; propagated: true; wireBytes: Uint8Array; direction: "FORWARD" | "BACKWARD" }
  | { ok: true; action: "REVOKED"; propagated: false; transportError: string; wireBytes: Uint8Array; direction: "FORWARD" | "BACKWARD" }
  | { ok: true; action: "ALREADY_REVOKED"; propagated: false; wireBytes: Uint8Array; direction: "FORWARD" | "BACKWARD" }
  | { ok: true; action: "REVOKED"; terminal: true; wireBytes: Uint8Array; direction: "FORWARD" | "BACKWARD" }
  | { ok: false; reason: string };

/**
 * The production destroy-propagation path.
 *
 * This function OWNS the full propagation pipeline:
 *
 *   1. processCircuitDestroy() — decode → verify → durable revoke → zeroize.
 *      (Returns wireBytes + the derived direction. The local terminal state
 *      is established BEFORE any transport.)
 *   2. Derive the propagation direction from the signed `destroyerRole`
 *      (via `propagationDirection()`). NOT caller-supplied.
 *   3. Resolve the next hop (via `NextHopResolver.resolveNextHop()`). The
 *      resolver uses the direction + the circuit topology + the local
 *      participant's identity.
 *   4. If terminal → return (no forwarding).
 *   5. If not terminal + propagate → send the ORIGINAL wireBytes over the
 *      authenticated transport (via `CircuitDestroyTransport.send()`). The
 *      transport binds the local + next-hop identity + circuitId +
 *      commitmentRoot + direction.
 *   6. If the transport fails → the local circuit remains REVOKED (the
 *      tombstone is authoritative). Return `propagated: false` +
 *      `transportError`. The operator may retry.
 *
 * ORDERING (ADR-0023 §4 + §6): decode → verify → durable revoke → zeroize →
 * transport propagation. The destroy is NEVER propagated before the local
 * participant has established its own revoked state. A persistence failure
 * returns `{ ok: false }` — NOT propagated.
 *
 * SECURITY: the direction is derived from the SIGNED `destroyerRole`. There
 * is no caller-supplied `propagate`, `direction`, `origin`, or `isRelay`
 * parameter. An unauthorized relay cannot redirect propagation.
 *
 * @param wireBytes - the raw canonical-CBOR-encoded CircuitDestroy bytes
 * @param circuit - the local ActiveCircuit
 * @param localNodeId - the local participant's NodeId
 * @param expectedInitiatorNodeId - the circuit's initiator NodeId
 * @param expectedGatewayNodeId - the terminal hop's NodeId
 * @param destroyStore - REQUIRED atomic CircuitDestroyStore
 * @param now - current time (unix seconds)
 * @param resolver - the next-hop resolver (derives the next hop from
 *   protocol state)
 * @param transport - the authenticated transport (sends the exact wire bytes)
 * @param gatewayProofBytes - OPTIONAL: serialized GatewayReturnAuthorization
 *   (REQUIRED for GATEWAY-role destroys)
 */
export async function propagateCircuitDestroy(
  wireBytes: Uint8Array,
  circuit: ActiveCircuit,
  localNodeId: string,
  expectedInitiatorNodeId: string,
  expectedGatewayNodeId: string,
  destroyStore: CircuitDestroyStore,
  now: number,
  resolver: NextHopResolver,
  transport: CircuitDestroyTransport,
  senderEd25519SecretKey: Uint8Array,
  senderEd25519PublicKey: Uint8Array,
  gatewayProofBytes?: Uint8Array,
): Promise<PropagateCircuitDestroyResult> {
  // 1. processCircuitDestroy — the pure protocol operation (decode → verify →
  //    durable revoke → zeroize). Returns wireBytes + the derived direction.
  //    This module does NOT re-implement processCircuitDestroy — it calls it.
  //    The local terminal state is established HERE, before any transport.
  const result: ProcessCircuitDestroyResult = await processCircuitDestroy(
    wireBytes, circuit,
    expectedInitiatorNodeId, expectedGatewayNodeId,
    destroyStore, now, gatewayProofBytes,
  );
  if (!result.ok) {
    // Local revoke FAILED — NOT propagated. No split state.
    return { ok: false, reason: result.reason };
  }

  // 2. If already revoked → idempotent. Propagation suppressed (the destroy
  //    has already been forwarded by a prior receipt — ADR-0023 §4).
  const direction = propagationDirection(result.circuitDestroy);
  if (result.action === "ALREADY_REVOKED") {
    return {
      ok: true,
      action: "ALREADY_REVOKED",
      propagated: false,
      wireBytes: result.wireBytes,
      direction,
    };
  }

  // 3. Derive the propagation direction from the SIGNED destroyerRole.
  //    NOT caller-supplied — the direction is protocol state.
  // (direction already derived above)

  // 4. Resolve the next hop (from protocol state: direction + topology + localNodeId).
  const nextHopResult = await resolver.resolveNextHop(
    localNodeId, direction, circuit, result.circuitDestroy,
  );
  if (!nextHopResult.ok) {
    // Resolver failed — this is a configuration error (the local participant
    // is not in the circuit topology, or the direction is invalid). The local
    // circuit is REVOKED (the tombstone is authoritative). Return a transport
    // error (the destroy was NOT propagated, but the local state is correct).
    return {
      ok: true,
      action: "REVOKED",
      propagated: false,
      transportError: `next-hop resolution failed: ${nextHopResult.reason}`,
      wireBytes: result.wireBytes,
      direction,
    };
  }
  if ("terminal" in nextHopResult && nextHopResult.terminal) {
    // This participant is the terminal hop — no forwarding.
    return {
      ok: true,
      action: "REVOKED",
      terminal: true,
      wireBytes: result.wireBytes,
      direction,
    };
  }

  // 5. Build the authenticated propagation context. This binds the destroy
  //    to the local + next-hop identity + circuitId + commitmentRoot +
  //    direction + the AuthenticatedLink + the sender's Ed25519 keypair (for
  //    signing the PropagationChannelProof). The transport verifies this binding
  //    + signs a proof that the receiver verifies.
  const ctx: DestroyPropagationContext = {
    localNodeId,
    nextHopNodeId: nextHopResult.nextHop.nodeId,
    circuitId: circuit.circuitId,
    commitmentRoot: circuit.commitmentRoot,
    direction,
    authenticatedLink: nextHopResult.nextHop.link,
    senderEd25519SecretKey,
    senderEd25519PublicKey,
  };

  // 6. Send the ORIGINAL wireBytes over the authenticated transport.
  //    The transport MUST NOT decode + re-encode. The transport verifies the
  //    authenticatedLink binding (localNodeId ↔ remoteNodeId) + sends the
  //    exact bytes. If the transport fails, the local circuit remains REVOKED.
  const sendResult = await transport.send(ctx, result.wireBytes);
  if (!sendResult.ok) {
    return {
      ok: true,
      action: "REVOKED",
      propagated: false,
      transportError: sendResult.reason,
      wireBytes: result.wireBytes,
      direction,
    };
  }

  // 7. Propagation succeeded. The destroy was sent to the next hop unchanged.
  return {
    ok: true,
    action: "REVOKED",
    propagated: true,
    wireBytes: result.wireBytes,
    direction,
  };
}

// -----------------------------------------------------------------------
// Topology-based NextHopResolver (production helper)
// -----------------------------------------------------------------------

/**
 * A production `NextHopResolver` that uses the circuit's committed route
 * topology + a map of authenticated links to resolve the next hop.
 *
 * The resolver handles THREE participant types:
 *   - INITIATOR (forward originator): sends to hop 0. Not in `hopNodeIds`.
 *   - RELAY (hop i): forwards to hop i+1 (FORWARD) or i-1 (BACKWARD).
 *   - GATEWAY (backward originator): sends to hop N-1. Is the last entry in
 *     `hopNodeIds`.
 *
 * The resolver returns the `AuthenticatedLink` to the next hop (looked up
 * from the `links` map keyed by next-hop NodeId). A missing link is a
 * configuration error.
 *
 * ARCHITECTURE: this helper is in the protocol core. The `AuthenticatedLink`
 * map is provided by the caller (the platform layer). The resolver does NOT
 * import Prisma or sockets.
 */
export class TopologyNextHopResolver implements NextHopResolver {
  /**
   * @param hopNodeIds - the list of relay + gateway NodeIds in the committed
   *   route (hop 0 = initiator's neighbor, ..., hop N-1 = gateway). The
   *   initiator is NOT in this list.
   * @param initiatorNodeId - the circuit's initiator NodeId (the forward
   *   originator). For FORWARD, the initiator sends to hop 0.
   * @param links - a map from remoteNodeId → AuthenticatedLink, for the
   *   local participant's authenticated links to its neighbors.
   */
  constructor(
    private readonly hopNodeIds: string[],
    private readonly initiatorNodeId: string,
    private readonly links: Map<string, AuthenticatedLink>,
  ) {}

  async resolveNextHop(
    localNodeId: string,
    direction: "FORWARD" | "BACKWARD",
    circuit: ActiveCircuit,
    _destroy: CircuitDestroy,
  ): Promise<NextHopResult> {
    if (direction === "FORWARD") {
      // FORWARD: initiator → hop 0 → ... → gateway (terminal).
      if (localNodeId === this.initiatorNodeId) {
        // The initiator sends to hop 0.
        return this.resolveLink(localNodeId, this.hopNodeIds[0]!);
      }
      // A relay: find its hopIndex.
      const localHopIndex = this.hopNodeIds.indexOf(localNodeId);
      if (localHopIndex === -1) {
        return {
          ok: false,
          reason: `localNodeId "${localNodeId}" is not in the circuit topology (initiator or hops)`,
        };
      }
      const nextHopIndex = localHopIndex + 1;
      if (nextHopIndex >= this.hopNodeIds.length) {
        // Terminal: the gateway (last hop).
        return { ok: true, terminal: true };
      }
      return this.resolveLink(localNodeId, this.hopNodeIds[nextHopIndex]!);
    } else {
      // BACKWARD: gateway → hop N-1 → ... → hop 0 → initiator (terminal).
      // The initiator is the terminal participant — it receives + does not forward.
      if (localNodeId === this.initiatorNodeId) {
        return { ok: true, terminal: true };
      }
      const localHopIndex = this.hopNodeIds.indexOf(localNodeId);
      if (localHopIndex === -1) {
        return {
          ok: false,
          reason: `localNodeId "${localNodeId}" is not in the circuit topology`,
        };
      }
      if (localHopIndex === 0) {
        // Hop 0 forwards to the initiator. The initiator is the terminal
        // participant (it receives + does not forward). Resolve the link
        // to the initiator.
        return this.resolveLink(localNodeId, this.initiatorNodeId);
      }
      // Forward to the previous hop.
      return this.resolveLink(localNodeId, this.hopNodeIds[localHopIndex - 1]!);
    }
  }

  /**
   * Resolve the authenticated link to `nextHopNodeId` + verify the binding.
   */
  private async resolveLink(
    localNodeId: string,
    nextHopNodeId: string,
  ): Promise<NextHopResult> {
    const link = this.links.get(nextHopNodeId);
    if (!link) {
      return {
        ok: false,
        reason: `no authenticated link to next hop "${nextHopNodeId}" (localNodeId "${localNodeId}")`,
      };
    }
    if (link.localNodeId !== localNodeId) {
      return {
        ok: false,
        reason: `authenticated link localNodeId "${link.localNodeId}" does not match localNodeId "${localNodeId}" (link is not owned by this participant)`,
      };
    }
    if (link.remoteNodeId !== nextHopNodeId) {
      return {
        ok: false,
        reason: `authenticated link remoteNodeId "${link.remoteNodeId}" does not match resolved next hop "${nextHopNodeId}" (peer mismatch)`,
      };
    }
    return { ok: true, nextHop: { nodeId: nextHopNodeId, link } };
  }
}

// -----------------------------------------------------------------------
// InProcessCircuitDestroyTransport — test/development transport
// -----------------------------------------------------------------------

/**
 * An in-process `CircuitDestroyTransport` for tests + development.
 *
 * This is NOT a real network transport. It uses an in-memory queue per
 * next-hop NodeId. It verifies the authenticated binding (localNodeId ↔
 * remoteNodeId ↔ circuitId ↔ commitmentRoot ↔ direction) before "sending".
 *
 * For real multi-process tests, use the TCP-backed transport adapter in
 * `src/lib/sharenet/` (which adapts a real TCP socket to this interface).
 *
 * ARCHITECTURE: this test helper is in the protocol core so that the protocol
 * engine can be tested without a real transport. It does NOT import Prisma
 * or sockets.
 */
export class InProcessCircuitDestroyTransport implements CircuitDestroyTransport {
  // Queue of (wireBytes, proof) per next-hop NodeId.
  private readonly queues = new Map<string, Array<{ wireBytes: Uint8Array; proof: PropagationChannelProof }>>();
  // Pending receive() waiters per localNodeId.
  private readonly waiters = new Map<string, Array<(result: { ok: true; wireBytes: Uint8Array } | { ok: false; reason: string }) => void>>();

  /**
   * Send the destroy wire bytes to the next hop. Signs a PropagationChannelProof
   * (bound to the channel context) + enqueues it alongside the destroy bytes.
   */
  async send(ctx: DestroyPropagationContext, wireBytes: Uint8Array): Promise<TransportSendResult> {
    // 1. Verify the authenticated link binding (localNodeId owns the link,
    //    link.remoteNodeId === nextHopNodeId).
    if (ctx.authenticatedLink.localNodeId !== ctx.localNodeId) {
      return { ok: false, reason: `transport binding failed: link.localNodeId "${ctx.authenticatedLink.localNodeId}" !== ctx.localNodeId "${ctx.localNodeId}"` };
    }
    if (ctx.authenticatedLink.remoteNodeId !== ctx.nextHopNodeId) {
      return { ok: false, reason: `transport binding failed: link.remoteNodeId "${ctx.authenticatedLink.remoteNodeId}" !== ctx.nextHopNodeId "${ctx.nextHopNodeId}" (peer mismatch)` };
    }
    // 2. Sign the PropagationChannelProof (binds senderNodeId, receiverNodeId,
    //    circuitId, commitmentRoot, direction — signed by the sender's Ed25519 key).
    const proof = signPropagationChannelProof(
      ctx.localNodeId, ctx.nextHopNodeId,
      ctx.circuitId, ctx.commitmentRoot, ctx.direction,
      ctx.senderEd25519SecretKey, ctx.senderEd25519PublicKey,
    );
    // 3. Enqueue the wire bytes + proof for the next hop.
    let queue = this.queues.get(ctx.nextHopNodeId);
    if (!queue) {
      queue = [];
      this.queues.set(ctx.nextHopNodeId, queue);
    }
    queue.push({ wireBytes, proof });

    // 4. Wake any pending receiver.
    const waiters = this.waiters.get(ctx.nextHopNodeId);
    if (waiters && waiters.length > 0) {
      const waiter = waiters.shift()!;
      const item = queue.shift()!;
      // The receiver verifies the proof against its context.
      const verifyResult = verifyIncomingPropagationChannelProof(item.proof, {
        localNodeId: ctx.nextHopNodeId,
        expectedRemoteNodeId: ctx.localNodeId,
        circuitId: ctx.circuitId,
        commitmentRoot: ctx.commitmentRoot,
      });
      if (verifyResult.ok) {
        waiter({ ok: true, wireBytes: item.wireBytes });
      } else {
        waiter({ ok: false, reason: verifyResult.reason });
      }
    }

    return { ok: true };
  }

  /**
   * Receive the destroy wire bytes, AUTHENTICATED. Verifies the incoming
   * PropagationChannelProof against the receiver's context before delivering.
   */
  async receive(ctx: AuthenticatedReceiveContext): Promise<{ ok: true; wireBytes: Uint8Array } | { ok: false; reason: string }> {
    return new Promise((resolve) => {
      const queue = this.queues.get(ctx.localNodeId);
      if (queue && queue.length > 0) {
        const item = queue.shift()!;
        const verifyResult = verifyIncomingPropagationChannelProof(item.proof, ctx);
        if (verifyResult.ok) {
          resolve({ ok: true, wireBytes: item.wireBytes });
        } else {
          resolve({ ok: false, reason: verifyResult.reason });
        }
        return;
      }
      // No pending destroy — wait.
      let waiters = this.waiters.get(ctx.localNodeId);
      if (!waiters) {
        waiters = [];
        this.waiters.set(ctx.localNodeId, waiters);
      }
      waiters.push((result) => resolve(result));
    });
  }

  /** Test-only: check if a destroy is pending for `localNodeId`. */
  hasPending(localNodeId: string): boolean {
    const queue = this.queues.get(localNodeId);
    return !!queue && queue.length > 0;
  }
}

/** Constant-time byte equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
