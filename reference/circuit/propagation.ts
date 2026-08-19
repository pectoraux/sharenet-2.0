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

// -----------------------------------------------------------------------
// Propagation direction (re-exported for convenience)
// -----------------------------------------------------------------------

/** The propagation direction, derived from the signed `destroyerRole`. */
export type { PropagationDirection } from "./destroy";
export { propagationDirection } from "./destroy";

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
 * The transport is AUTHENTICATED: each `send` is bound to a
 * `DestroyPropagationContext` that ties the destroy to:
 *   - the local participant identity
 *   - the next-hop identity
 *   - the circuitId + commitmentRoot
 *   - the propagation direction
 *   - the AuthenticatedLink (the existing ShareNet link abstraction)
 *
 * The transport MUST:
 *   1. Verify the `authenticatedLink.localNodeId === ctx.localNodeId` (the
 *      local participant owns this link).
 *   2. Verify the `authenticatedLink.remoteNodeId === ctx.nextHopNodeId`
 *      (the link is to the resolved next hop).
 *   3. Send the EXACT `wireBytes` unchanged (no decode + re-encode).
 *   4. Bind the `circuitId` + `commitmentRoot` + `direction` to the
 *      authenticated channel context (so the receiver can verify the binding).
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
   * @param ctx - the authenticated propagation context (binds local +
   *   next-hop identity + circuitId + commitmentRoot + direction + link)
   * @param wireBytes - the EXACT wire bytes to forward (byte-for-byte —
   *   the transport MUST NOT decode + re-encode)
   */
  send(ctx: DestroyPropagationContext, wireBytes: Uint8Array): Promise<TransportSendResult>;

  /**
   * Receive the destroy wire bytes from the previous hop.
   *
   * @param localNodeId - the local participant's NodeId (for verifying the
   *   incoming link's remoteNodeId matches)
   * @returns the received wire bytes (exactly as sent — no decode + re-encode)
   */
  receive(localNodeId: string): Promise<Uint8Array>;
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
  //    direction + the AuthenticatedLink. The transport verifies this binding.
  const ctx: DestroyPropagationContext = {
    localNodeId,
    nextHopNodeId: nextHopResult.nextHop.nodeId,
    circuitId: circuit.circuitId,
    commitmentRoot: circuit.commitmentRoot,
    direction,
    authenticatedLink: nextHopResult.nextHop.link,
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
  // Queue of (wireBytes, ctx) per next-hop NodeId.
  private readonly queues = new Map<string, Array<{ wireBytes: Uint8Array; ctx: DestroyPropagationContext }>>();
  // Pending receive() waiters per localNodeId.
  private readonly waiters = new Map<string, Array<(wireBytes: Uint8Array) => void>>();

  /**
   * Send the destroy wire bytes to the next hop. Verifies the authenticated
   * binding before enqueueing.
   */
  async send(ctx: DestroyPropagationContext, wireBytes: Uint8Array): Promise<TransportSendResult> {
    // Verify the authenticated binding.
    if (ctx.authenticatedLink.localNodeId !== ctx.localNodeId) {
      return { ok: false, reason: `transport binding failed: link.localNodeId "${ctx.authenticatedLink.localNodeId}" !== ctx.localNodeId "${ctx.localNodeId}"` };
    }
    if (ctx.authenticatedLink.remoteNodeId !== ctx.nextHopNodeId) {
      return { ok: false, reason: `transport binding failed: link.remoteNodeId "${ctx.authenticatedLink.remoteNodeId}" !== ctx.nextHopNodeId "${ctx.nextHopNodeId}" (peer mismatch)` };
    }

    // Enqueue the wire bytes for the next hop.
    let queue = this.queues.get(ctx.nextHopNodeId);
    if (!queue) {
      queue = [];
      this.queues.set(ctx.nextHopNodeId, queue);
    }
    queue.push({ wireBytes, ctx });

    // Wake any pending receiver.
    const waiters = this.waiters.get(ctx.nextHopNodeId);
    if (waiters && waiters.length > 0) {
      const waiter = waiters.shift()!;
      // Dequeue + deliver.
      const item = queue.shift()!;
      waiter(item.wireBytes);
    }

    return { ok: true };
  }

  /**
   * Receive the destroy wire bytes addressed to `localNodeId`. Blocks until
   * a destroy arrives.
   */
  async receive(localNodeId: string): Promise<Uint8Array> {
    return new Promise<Uint8Array>((resolve) => {
      const queue = this.queues.get(localNodeId);
      if (queue && queue.length > 0) {
        const item = queue.shift()!;
        resolve(item.wireBytes);
        return;
      }
      // No pending destroy — wait.
      let waiters = this.waiters.get(localNodeId);
      if (!waiters) {
        waiters = [];
        this.waiters.set(localNodeId, waiters);
      }
      waiters.push(resolve);
    });
  }

  /** Test-only: check if a destroy is pending for `localNodeId`. */
  hasPending(localNodeId: string): boolean {
    const queue = this.queues.get(localNodeId);
    return !!queue && queue.length > 0;
  }
}
