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
import type {
  CircuitDestroyTransport,
  DestroyPropagationContext,
  TransportSendResult,
} from "@reference/circuit/propagation";

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
  private pendingReceiver: ((wireBytes: Uint8Array) => void) | null = null;
  // Queue of received wire bytes (in case a destroy arrives before receive()
  // is called — the destroy is buffered until a receiver waits).
  private readonly receivedQueue: Uint8Array[] = [];

  /**
   * @param localNodeId - the local participant's NodeId
   * @param listenPort - the port this participant listens on (its TCP server)
   * @param peerPortRegistry - a map from peer NodeId → TCP port (for sending)
   */
  constructor(
    private readonly localNodeId: string,
    private readonly listenPort: number,
    private readonly peerPortRegistry: Map<string, number>,
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
   * Send the destroy wire bytes to the next hop over TCP. Verifies the
   * authenticated binding before sending.
   */
  async send(ctx: DestroyPropagationContext, wireBytes: Uint8Array): Promise<TransportSendResult> {
    // 1. Verify the authenticated binding.
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

    // 2. Look up the next hop's port.
    const port = this.peerPortRegistry.get(ctx.nextHopNodeId);
    if (port === undefined) {
      return {
        ok: false,
        reason: `no known port for next-hop NodeId "${ctx.nextHopNodeId}" (peer not in registry)`,
      };
    }

    // 3. Connect + send the EXACT wire bytes (length-prefixed framing).
    return new Promise<TransportSendResult>((resolve) => {
      const sock = netConnect(port, "127.0.0.1", () => {
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(wireBytes.length, 0);
        sock.write(lenBuf);
        sock.write(Buffer.from(wireBytes));
        // Wait for the write to flush, then close.
        setTimeout(() => {
          sock.end();
          resolve({ ok: true });
        }, 50);
      });
      sock.on("error", (err) => {
        resolve({ ok: false, reason: `TCP send to ${ctx.nextHopNodeId}:${port} failed: ${err.message}` });
      });
    });
  }

  /**
   * Receive the destroy wire bytes addressed to `localNodeId`. Blocks until
   * a destroy arrives over the TCP server. The caller MUST have called
   * `start()` first.
   *
   * If a destroy arrives BEFORE `receive()` is called, it is buffered in
   * `receivedQueue` + delivered when `receive()` is next called.
   */
  async receive(localNodeId: string): Promise<Uint8Array> {
    if (localNodeId !== this.localNodeId) {
      throw new Error(`receive() called with localNodeId "${localNodeId}" but transport is for "${this.localNodeId}"`);
    }
    // If a destroy is already queued, deliver it immediately.
    if (this.receivedQueue.length > 0) {
      return this.receivedQueue.shift()!;
    }
    return new Promise<Uint8Array>((resolve) => {
      this.pendingReceiver = resolve;
    });
  }

  /**
   * Handle an incoming TCP connection. Reads the length-prefixed wire bytes
   * + delivers them to the pending receiver (if any), or buffers them in
   * `receivedQueue` (if no receiver is waiting yet).
   */
  private handleIncoming(socket: Socket): void {
    readWire(socket).then((wireBytes) => {
      if (this.pendingReceiver) {
        const receiver = this.pendingReceiver;
        this.pendingReceiver = null;
        receiver(wireBytes);
      } else {
        // No receiver waiting — buffer the destroy.
        this.receivedQueue.push(wireBytes);
      }
      socket.end();
    }).catch(() => {
      // Ignore read errors (the connection was dropped).
    });
  }
}

/**
 * Read length-prefixed wire bytes from a TCP socket.
 *
 * Wire protocol: [4 bytes big-endian length][length bytes destroy wire]
 */
function readWire(socket: Socket): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    let lenBuf: Buffer | null = null;
    let payload = Buffer.alloc(0);
    let expected = 0;
    socket.on("data", (chunk: Buffer) => {
      let buf = chunk;
      while (buf.length > 0) {
        if (!lenBuf) {
          lenBuf = buf.subarray(0, 4);
          buf = buf.subarray(4);
          expected = lenBuf.readUInt32BE(0);
        } else {
          const remaining = expected - payload.length;
          payload = Buffer.concat([payload, buf.subarray(0, Math.min(remaining, buf.length))]);
          buf = buf.subarray(Math.min(remaining, buf.length));
          if (payload.length === expected) {
            resolve(new Uint8Array(payload));
            return;
          }
        }
      }
    });
    socket.on("error", reject);
  });
}
