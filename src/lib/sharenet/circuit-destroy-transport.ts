/**
 * ShareNet 2.0 — TCP-backed CircuitDestroyTransport adapter (R-009 Stage 3 Phase 3).
 *
 * This is the PRODUCTION-EQUIVALENT transport adapter that implements the
 * protocol-core `CircuitDestroyTransport` interface (from
 * `reference/circuit/propagation.ts`) using a real TCP socket.
 *
 * ARCHITECTURE (per ADR-0013):
 *   - The INTERFACE (`CircuitDestroyTransport`) lives in the protocol core
 *     (`reference/circuit/propagation.ts`). The protocol engine calls the
 *     interface; it never knows about sockets.
 *   - The IMPLEMENTATION (this file) lives in the platform layer
 *     (`src/lib/sharenet/`). It adapts a real TCP socket to the interface.
 *     This file MAY import `node:net`, Prisma, etc. (it's the platform layer).
 *
 * The transport is AUTHENTICATED: each `send` is bound to a
 * `DestroyPropagationContext` that ties the destroy to:
 *   - the local participant identity (from the AuthenticatedLink)
 *   - the next-hop identity (from the AuthenticatedLink)
 *   - the circuitId + commitmentRoot
 *   - the propagation direction (derived from the signed destroyerRole)
 *
 * The transport verifies the authenticated binding before sending:
 *   1. `link.localNodeId === ctx.localNodeId` (the local participant owns this link).
 *   2. `link.remoteNodeId === ctx.nextHopNodeId` (the link is to the resolved next hop).
 *
 * Wire protocol on each TCP socket (length-prefixed framing):
 *   [4 bytes big-endian length][length bytes destroy wire]
 *
 * The transport sends the EXACT wire bytes — no decode + re-encode (the
 * exact-byte invariant, ADR-0023 §3).
 */

import { createServer, connect as netConnect, type Server, type Socket } from "node:net";
import {
  signPropagationChannelProof,
  encodePropagationChannelProof,
  decodePropagationChannelProof,
  verifyAndProduceAuthenticatedDestroy,
  type CircuitDestroyTransport,
  type DestroyPropagationContext,
  type AuthenticatedReceiveContext,
  type ReceiveAuthenticatedCircuitDestroyResult,
  type TransportSendResult,
} from "@reference/circuit/propagation";
import type { LinkFailureDetector, FailureObservation } from "@reference/failure/link-failure-detector";
import type { FailureEventDispatcher } from "@reference/failure/failure-event-dispatcher";

/**
 * A TCP-backed CircuitDestroyTransport. Each participant runs a TCP server
 * (listens on a port) + sends to the next hop via a TCP client connection.
 *
 * The `nextHopPort` is looked up by `nextHopNodeId` via the
 * `peerPortRegistry` (a map from NodeId → port). This simulates the
 * authenticated peer discovery (in a real deployment, the registry would
 * be the ShareNet link layer's peer address table).
 */
export class TcpCircuitDestroyTransport implements CircuitDestroyTransport {
  private server: Server | null = null;
  private pendingReceiver: { resolve: (r: ReceiveAuthenticatedCircuitDestroyResult) => void; ctx: AuthenticatedReceiveContext } | null = null;
  private readonly receivedQueue: Array<{ proofBytes: Uint8Array; wireBytes: Uint8Array }> = [];

  /**
   * @param localNodeId - the local participant's NodeId
   * @param listenPort - the port this participant listens on
   * @param peerPortRegistry - a map from peer NodeId → TCP port
   * @param failureDispatcher - OPTIONAL: when provided, socket errors during
   *   `send()` are recorded as TRANSPORT_CONFIRMED observations (immediate
   *   LINK_DOWN) + the dispatcher IMMEDIATELY drains + dispatches the event
   *   (durable invalidation + zeroize + RecoveryManager notification —
   *   INLINE, no polling). Successful sends call `recordSuccess()` (reset
   *   DEGRADED → HEALTHY). Only authenticated sends reach this point.
   * @param failureDetector - DEPRECATED: use failureDispatcher instead.
   *   Kept for backward compatibility. If failureDispatcher is not provided
   *   but failureDetector is, falls back to raw detector (no dispatch).
   * @param linkId - the linkId for failure observations
   * @param remoteNodeId - the remote peer's NodeId for failure observations
   */
  constructor(
    private readonly localNodeId: string,
    private readonly listenPort: number,
    private readonly peerPortRegistry: Map<string, number>,
    private readonly failureDispatcher?: FailureEventDispatcher,
    private readonly failureDetector?: LinkFailureDetector,
    private readonly linkId?: string,
    private readonly remoteNodeId?: string,
  ) {}

  /**
   * Start the TCP server (listen on `listenPort`). Returns when the server
   * is listening. The caller MUST call `stop()` to close the server.
   */
  async start(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.server = createServer((socket) => {
        this.handleIncoming(socket);
      });
      this.server.on("error", reject);
      this.server.listen(this.listenPort, "127.0.0.1", () => resolve());
    });
  }

  /**
   * Stop the TCP server.
   */
  async stop(): Promise<void> {
    return new Promise<void>((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
        this.server = null;
      } else {
        resolve();
      }
    });
  }

  /**
   * Send the destroy wire bytes to the next hop over TCP. Signs a
   * PropagationChannelProof + sends it alongside the destroy wire bytes.
   * The receiver verifies the proof before accepting the destroy.
   */
  async send(ctx: DestroyPropagationContext, wireBytes: Uint8Array): Promise<TransportSendResult> {
    // 1. Verify the authenticated link binding.
    if (ctx.authenticatedLink.localNodeId !== ctx.localNodeId) {
      return {
        ok: false,
        reason: `transport binding failed: link.localNodeId "${ctx.authenticatedLink.localNodeId}" !== ctx.localNodeId "${ctx.localNodeId}"`,
      };
    }
    if (ctx.authenticatedLink.remoteNodeId !== ctx.nextHopNodeId) {
      return {
        ok: false,
        reason: `transport binding failed: link.remoteNodeId "${ctx.authenticatedLink.remoteNodeId}" !== ctx.nextHopNodeId "${ctx.nextHopNodeId}" (peer mismatch)`,
      };
    }

    // 2. Sign the PropagationChannelProof (binds the channel context + the
    //    destroyDigest — the EXACT destroy bytes being propagated).
    const proof = signPropagationChannelProof(
      ctx.localNodeId, ctx.nextHopNodeId,
      ctx.circuitId, ctx.commitmentRoot, ctx.direction,
      wireBytes, // hash the EXACT bytes being sent
      ctx.senderEd25519SecretKey, ctx.senderEd25519PublicKey,
    );
    const proofBytes = encodePropagationChannelProof(proof);

    // 3. Look up the next hop's port.
    const port = this.peerPortRegistry.get(ctx.nextHopNodeId);
    if (port === undefined) {
      return {
        ok: false,
        reason: `no known port for next-hop NodeId "${ctx.nextHopNodeId}" (peer not in registry)`,
      };
    }

    // 4. Connect + send the proof + the EXACT wire bytes.
    //    Wire protocol: [4 bytes proof len][proof bytes][4 bytes destroy len][destroy bytes]
    return new Promise<TransportSendResult>((resolve) => {
      const sock = netConnect(port, "127.0.0.1", () => {
        const proofLenBuf = Buffer.alloc(4);
        proofLenBuf.writeUInt32BE(proofBytes.length, 0);
        sock.write(proofLenBuf);
        sock.write(Buffer.from(proofBytes));
        const destroyLenBuf = Buffer.alloc(4);
        destroyLenBuf.writeUInt32BE(wireBytes.length, 0);
        sock.write(destroyLenBuf);
        sock.write(Buffer.from(wireBytes));
        // Wait for the write to flush, then close.
        setTimeout(() => {
          sock.end();
          // PRODUCTION SUCCESS WIRING: a successful authenticated send
          // resets the link's suspicion (DEGRADED → HEALTHY) + dispatches
          // any pending events INLINE.
          if (this.failureDispatcher && this.linkId) {
            this.failureDispatcher.recordSuccess(this.linkId, Math.floor(Date.now() / 1000));
          } else if (this.failureDetector && this.linkId) {
            this.failureDetector.recordSuccess(this.linkId, Math.floor(Date.now() / 1000));
          }
          resolve({ ok: true });
        }, 50);
      });
      sock.on("error", (err) => {
        // PRODUCTION FAILURE WIRING: a socket error on an AUTHENTICATED
        // send (verified link binding at step 1) is a TRANSPORT_CONFIRMED
        // failure. Feed it to the dispatcher → immediate LINK_DOWN +
        // INLINE dispatch (durable invalidation + zeroize + RecoveryManager).
        // Only authenticated sends reach this point.
        if (this.failureDispatcher && this.linkId && this.remoteNodeId) {
          this.failureDispatcher.recordObservation({
            linkId: this.linkId,
            localNodeId: this.localNodeId,
            remoteNodeId: this.remoteNodeId,
            circuitId: ctx.circuitId,
            category: "TRANSPORT_CONFIRMED",
            reason: `TCP send to ${ctx.nextHopNodeId}:${port} failed: ${err.message}`,
            observedAt: Math.floor(Date.now() / 1000),
          });
        } else if (this.failureDetector && this.linkId && this.remoteNodeId) {
          // Fallback to raw detector (no dispatch) for backward compat.
          this.failureDetector.recordObservation({
            linkId: this.linkId,
            localNodeId: this.localNodeId,
            remoteNodeId: this.remoteNodeId,
            circuitId: ctx.circuitId,
            category: "TRANSPORT_CONFIRMED",
            reason: `TCP send to ${ctx.nextHopNodeId}:${port} failed: ${err.message}`,
            observedAt: Math.floor(Date.now() / 1000),
          });
        }
        resolve({ ok: false, reason: `TCP send to ${ctx.nextHopNodeId}:${port} failed: ${err.message}` });
      });
    });
  }

  /**
   * Receive the destroy wire bytes, AUTHENTICATED. Verifies the incoming
   * PropagationChannelProof against the receiver's context before delivering.
   * Blocks until a destroy arrives. The caller MUST have called `start()`.
   */
  async receive(ctx: AuthenticatedReceiveContext): Promise<ReceiveAuthenticatedCircuitDestroyResult> {
    if (ctx.localNodeId !== this.localNodeId) {
      throw new Error(`receive() called with localNodeId "${ctx.localNodeId}" but transport is for "${this.localNodeId}"`);
    }
    // If a destroy is already queued, run the full verification pipeline + deliver.
    if (this.receivedQueue.length > 0) {
      const item = this.receivedQueue.shift()!;
      const proofDecoded = decodePropagationChannelProof(item.proofBytes);
      if (!proofDecoded.ok) {
        return { ok: false, reason: `received proof decode failed: ${proofDecoded.reason}` };
      }
      // The transport OWNS the full verification: proof + digest + decode +
      // verify + direction. No public API returns {proof, wireBytes} before
      // direction is checked.
      return verifyAndProduceAuthenticatedDestroy(proofDecoded.proof, ctx, item.wireBytes);
    }
    // No queued destroy — wait for one. Store the ctx so handleIncoming
    // can run the full verification when it arrives.
    return new Promise((resolve) => {
      this.pendingReceiver = { resolve, ctx };
    });
  }

  /**
   * Handle an incoming TCP connection. Reads the proof + the wire bytes,
   * runs the FULL verification pipeline (proof + digest + decode + verify +
   * direction), and resolves the pending receiver (if any), or buffers them
   * for later.
   */
  private handleIncoming(socket: Socket): void {
    readProofAndWire(socket).then(({ proofBytes, wireBytes }) => {
      if (this.pendingReceiver) {
        const { resolve, ctx } = this.pendingReceiver;
        this.pendingReceiver = null;
        // Decode + run the FULL verification pipeline (proof + digest +
        // decode + verify + direction). The transport OWNS this — no public
        // API can bypass it.
        const proofDecoded = decodePropagationChannelProof(proofBytes);
        if (!proofDecoded.ok) {
          resolve({ ok: false, reason: `received proof decode failed: ${proofDecoded.reason}` });
        } else {
          resolve(verifyAndProduceAuthenticatedDestroy(proofDecoded.proof, ctx, wireBytes));
        }
      } else {
        // No receiver waiting — buffer the proof + wire bytes.
        this.receivedQueue.push({ proofBytes, wireBytes });
      }
      socket.end();
    }).catch(() => {
      // Ignore read errors (the connection was dropped).
    });
  }
}

/**
 * Read the PropagationChannelProof + the destroy wire bytes from a TCP socket.
 *
 * Wire protocol:
 *   [4 bytes big-endian proof length][proof bytes]
 *   [4 bytes big-endian destroy length][destroy bytes]
 */
function readProofAndWire(socket: Socket): Promise<{ proofBytes: Uint8Array; wireBytes: Uint8Array }> {
  return new Promise((resolve, reject) => {
    let phase: "proof-len" | "proof" | "destroy-len" | "destroy" = "proof-len";
    let lenBuf = Buffer.alloc(0);
    let payload = Buffer.alloc(0);
    let expected = 0;
    let proofBytes: Uint8Array | null = null;
    socket.on("data", (chunk: Buffer) => {
      let buf = chunk;
      while (buf.length > 0) {
        if (phase === "proof-len" || phase === "destroy-len") {
          const needed = 4 - lenBuf.length;
          const take = Math.min(needed, buf.length);
          lenBuf = Buffer.concat([lenBuf, buf.subarray(0, take)]);
          buf = buf.subarray(take);
          if (lenBuf.length === 4) {
            expected = lenBuf.readUInt32BE(0);
            payload = Buffer.alloc(0);
            phase = phase === "proof-len" ? "proof" : "destroy";
            if (expected === 0 && phase === "proof") {
              // Empty proof — shouldn't happen, but handle.
              proofBytes = new Uint8Array(0);
              phase = "destroy-len";
              lenBuf = Buffer.alloc(0);
            }
          }
        } else {
          const remaining = expected - payload.length;
          payload = Buffer.concat([payload, buf.subarray(0, Math.min(remaining, buf.length))]);
          buf = buf.subarray(Math.min(remaining, buf.length));
          if (payload.length === expected) {
            if (phase === "proof") {
              proofBytes = new Uint8Array(payload);
              phase = "destroy-len";
              lenBuf = Buffer.alloc(0);
              payload = Buffer.alloc(0);
            } else {
              // destroy complete
              resolve({ proofBytes: proofBytes!, wireBytes: new Uint8Array(payload) });
              return;
            }
          }
        }
      }
    });
    socket.on("error", reject);
  });
}
