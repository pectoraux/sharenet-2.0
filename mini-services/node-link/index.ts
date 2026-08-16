/**
 * ShareNet 2.0 — Node-Link Mini-Service (Phase 3).
 *
 * Per spec/00 §37 (second major deliverable):
 *   "real independent processes → authenticated directed network links.
 *    No simulator. No global in-memory graph. No fake transport."
 *
 * This is a REAL Bun process that:
 *   1. Loads (or generates) an Ed25519 keypair + NodeId.
 *   2. Listens on a TCP socket for the ShareNet wire protocol (handshake).
 *   3. Exposes a small HTTP control API for the dashboard to query/steer it.
 *   4. Can DIAL OUT to another node's TCP socket and run the handshake as initiator.
 *   5. Maintains a directed link registry (in-memory, per-process — NOT shared).
 *
 * This is NOT a Next.js route. It is a separate process with its own port.
 * The dashboard talks to it via /api/sharenet/mesh/*?XTransformPort=<port>.
 *
 * Usage:
 *   NODE_NAME=node-a NODE_PORT=3001 WIRE_PORT=7788 bun run dev
 *
 * Environment:
 *   NODE_NAME   — human label for logs (default: "node")
 *   NODE_PORT   — HTTP control API port (default: 3001)
 *   WIRE_PORT   — TCP socket for the ShareNet handshake (default: 7788)
 *   PERSIST_DIR — where to store the keypair (default: ./data)
 */

import { createServer, Socket, type Server } from "node:net";
import * as net from "node:net";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Import the ShareNet protocol core (relative paths — no Next.js alias here).
// These are pure functions with zero HTTP/DB dependencies (ADR-0013 Layer 3).
import { generateNodeKeypair, keypairFromSecretKey, bytesToHex, hexToBytes, randomBytes, type NodeKeypair } from "../../reference/identity/keys.ts";
import { signAdvertisement, type NodeAdvertisement, type NodeCapability, type NodeEndpoint } from "../../reference/advertisement/advertisement.ts";
import {
  buildHandshakeMessage,
  encodeHandshakeMessage,
  decodeHandshakeBody,
  readLengthPrefix,
  verifyPeerHandshake,
  HANDSHAKE_KIND,
  type HandshakeMessage,
} from "../../reference/transport/handshake.ts";
import {
  deriveLinkId,
  generateLinkNonce,
  type DirectedLink,
  type LinkEvent,
} from "../../reference/link/link.ts";

// ---------- Configuration ----------

const NODE_NAME = process.env.NODE_NAME ?? "node";
const NODE_PORT = parseInt(process.env.NODE_PORT ?? "3001", 10);
const WIRE_PORT = parseInt(process.env.WIRE_PORT ?? "7788", 10);
const PERSIST_DIR = process.env.PERSIST_DIR ?? join(process.cwd(), "mini-services", "node-link", "data", NODE_NAME);
const KEYPAIR_FILE = join(PERSIST_DIR, `${NODE_NAME}-keypair.json`);

// ---------- Node identity (load or generate) ----------

async function loadOrCreateKeypair(): Promise<NodeKeypair> {
  await mkdir(PERSIST_DIR, { recursive: true }).catch(() => {});
  if (existsSync(KEYPAIR_FILE)) {
    try {
      const data = JSON.parse(await readFile(KEYPAIR_FILE, "utf-8"));
      const secretKey = hexToBytes(data.secretKeyHex);
      return keypairFromSecretKey(secretKey);
    } catch {
      // fall through to generation
    }
  }
  const kp = generateNodeKeypair();
  await writeFile(KEYPAIR_FILE, JSON.stringify({
    nodeId: kp.nodeId,
    publicKeyHex: bytesToHex(kp.publicKey),
    secretKeyHex: bytesToHex(kp.secretKey),
  }, null, 2));
  console.log(`[${NODE_NAME}] generated new keypair, saved to ${KEYPAIR_FILE}`);
  return kp;
}

const keypair = await loadOrCreateKeypair();
console.log(`[${NODE_NAME}] NodeId: ${keypair.nodeId}`);
console.log(`[${NODE_NAME}] Public key: ${bytesToHex(keypair.publicKey)}`);

// ---------- Advertisement (re-signed every 24h, sequence increments on restart) ----------

let sequenceCounter = 1;
let currentAdvertisement: NodeAdvertisement | null = null;

function buildAdvertisement(endpoints: NodeEndpoint[], capabilities: NodeCapability[]): NodeAdvertisement {
  const now = Math.floor(Date.now() / 1000);
  const adv = signAdvertisement({
    protocolVersion: 1,
    nodeId: keypair.nodeId,
    signingPublicKey: keypair.publicKey,
    capabilities,
    endpoints,
    sequence: sequenceCounter,
    timestamp: now,
    expiry: now + 86400, // 24h
    nonce: randomBytes(16),
  }, keypair.secretKey);
  currentAdvertisement = adv;
  return adv;
}

// Initial advertisement: advertise the WIRE_PORT on localhost.
buildAdvertisement(
  [{ type: "tcp", address: "127.0.0.1", port: WIRE_PORT }],
  ["MESH_RELAY", "DISCOVERY"],
);

// ---------- Directed link registry (in-memory, per-process) ----------

const links = new Map<string, DirectedLink>();
const linkEvents: LinkEvent[] = [];

function recordLinkEvent(ev: LinkEvent) {
  linkEvents.push(ev);
  if (linkEvents.length > 100) linkEvents.shift();
  console.log(`[${NODE_NAME}] link event: ${ev.type} ${ev.linkId.slice(0, 20)}...${"remoteNodeId" in ev ? " peer=" + ev.remoteNodeId.slice(0, 20) + "..." : ""}`);
}

function getOrCreatePendingLink(localNonce: Uint8Array, remoteEndpoint: string): { linkId: string } {
  // Pending links use a temporary LinkId based on local nonce + remote endpoint
  // (we don't know the remote NodeId yet). Once the handshake completes we
  // REPLACE this with the real directional LinkId.
  // For simplicity in Phase 3 we just track pending sockets separately.
  return { linkId: "pending" };
}

// ---------- Wire protocol: length-prefixed canonical CBOR ----------

const RECV_BUFFERS = new WeakMap<Socket, { buf: Buffer; }>();

function handleSocketData(socket: Socket, data: Buffer, isInitiator: boolean, remoteExpectedNodeId?: string) {
  let state = RECV_BUFFERS.get(socket) ?? { buf: Buffer.alloc(0) };
  state.buf = Buffer.concat([state.buf, data]);
  RECV_BUFFERS.set(socket, state);

  // Try to parse complete messages.
  while (state.buf.length >= 4) {
    const len = state.buf.readUInt32BE(0);
    if (state.buf.length < 4 + len) break; // wait for more data
    const body = state.buf.slice(4, 4 + len);
    state.buf = state.buf.slice(4 + len);

    let msg: HandshakeMessage;
    try {
      msg = decodeHandshakeBody(new Uint8Array(body)) as HandshakeMessage;
    } catch (e) {
      console.error(`[${NODE_NAME}] decode error:`, (e as Error).message);
      socket.destroy();
      return;
    }
    handleHandshakeMessage(socket, msg, isInitiator, remoteExpectedNodeId);
  }
}

function handleHandshakeMessage(socket: Socket, msg: HandshakeMessage, isInitiator: boolean, remoteExpectedNodeId?: string) {
  if (msg.kind === HANDSHAKE_KIND.INITIATE) {
    // We are the responder. Verify the initiator's advertisement.
    const v = verifyPeerHandshake(msg, remoteExpectedNodeId);
    if (!v.ok) {
      console.error(`[${NODE_NAME}] initiator verification failed: ${v.reason}`);
      socket.destroy();
      return;
    }
    // Send back our AcceptMessage with our advertisement.
    const acceptMsg = buildHandshakeMessage(HANDSHAKE_KIND.ACCEPT, currentAdvertisement!);
    socket.write(Buffer.from(encodeHandshakeMessage(acceptMsg)));
    // LinkUp (responder side)
    establishLinkUp(socket, v.advertisement, false);
  } else if (msg.kind === HANDSHAKE_KIND.ACCEPT) {
    // We are the initiator. Verify the responder's advertisement.
    const v = verifyPeerHandshake(msg, remoteExpectedNodeId);
    if (!v.ok) {
      console.error(`[${NODE_NAME}] responder verification failed: ${v.reason}`);
      socket.destroy();
      return;
    }
    // LinkUp (initiator side)
    establishLinkUp(socket, v.advertisement, true);
  }
}

// Track per-socket local nonces (initiator side)
const socketLocalNonces = new WeakMap<Socket, Uint8Array>();

function establishLinkUp(socket: Socket, remoteAdv: NodeAdvertisement, isInitiator: boolean) {
  // Determine local + remote nonces. We need a fresh local nonce for this link.
  // The initiator generates its nonce BEFORE sending InitiateMessage; the responder
  // generates its nonce BEFORE sending AcceptMessage.
  const localNonce = socketLocalNonces.get(socket) ?? generateLinkNonce();
  // Extract remote nonce from the advertisement's nonce field (reusing the adv nonce
  // as the link nonce — a real implementation would send a separate nonce field,
  // but for Phase 3 we piggyback on the advertisement nonce which is already 16 bytes).
  const remoteNonce = remoteAdv.nonce;

  const linkId = deriveLinkId(keypair.nodeId, remoteAdv.nodeId, localNonce, remoteNonce);
  const remoteEndpoint = `${remoteAdv.endpoints[0]?.address ?? "unknown"}:${remoteAdv.endpoints[0]?.port ?? 0}`;
  const link: DirectedLink = {
    linkId,
    localNodeId: keypair.nodeId,
    remoteNodeId: remoteAdv.nodeId,
    localNonce,
    remoteNonce,
    remotePublicKey: remoteAdv.signingPublicKey,
    remoteCapabilities: remoteAdv.capabilities,
    remoteEndpoint,
    state: "LINK_UP",
    stateChangedAt: Date.now(),
    createdAt: Date.now(),
  };
  links.set(linkId, link);
  recordLinkEvent({ type: "LINK_UP", linkId, remoteNodeId: remoteAdv.nodeId, at: Date.now() });

  socket.on("close", () => {
    if (links.has(linkId)) {
      const l = links.get(linkId)!;
      l.state = "LINK_DOWN";
      l.stateChangedAt = Date.now();
      recordLinkEvent({ type: "LINK_DOWN", linkId, reason: "socket closed", at: Date.now() });
    }
  });
  socket.on("error", (err) => {
    console.error(`[${NODE_NAME}] socket error on ${linkId.slice(0, 20)}...:`, err.message);
  });
}

// ---------- TCP wire server (accepts incoming handshakes) ----------

const wireServer = createServer((socket) => {
  socket.setNoDelay(true);
  socket.on("data", (data) => handleSocketData(socket, data, false));
  socket.on("error", () => { /* ignore */ });
});

wireServer.listen(WIRE_PORT, "127.0.0.1", () => {
  console.log(`[${NODE_NAME}] wire server listening on 127.0.0.1:${WIRE_PORT}`);
});

// ---------- Dial out (initiator) ----------

async function dialOut(host: string, port: number, expectedNodeId?: string): Promise<{ ok: boolean; linkId?: string; reason?: string }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setNoDelay(true);
    socket.setKeepAlive(true, 30000); // TCP keepalive so the link stays UP
    const localNonce = generateLinkNonce();
    socketLocalNonces.set(socket, localNonce);
    // Keep a strong reference so the socket isn't GC'd after the promise resolves.
    activeSockets.add(socket);
    socket.on("close", () => { activeSockets.delete(socket); });

    const onConnect = () => {
      // Send InitiateMessage with our advertisement.
      const initiate = buildHandshakeMessage(HANDSHAKE_KIND.INITIATE, currentAdvertisement!);
      socket.write(Buffer.from(encodeHandshakeMessage(initiate)));
      // Record a pending link event.
      recordLinkEvent({
        type: "LINK_PENDING",
        linkId: "pending-" + Date.now(),
        localNodeId: keypair.nodeId,
        remoteEndpoint: `${host}:${port}`,
        at: Date.now(),
      });
    };

    let resolved = false;
    const onData = (data: Buffer) => {
      handleSocketData(socket, data, true, expectedNodeId);
      // Check if a link was established in this turn.
      for (const [lid, link] of links.entries()) {
        if (link.remoteEndpoint === `${host}:${port}` && link.state === "LINK_UP") {
          if (!resolved) {
            resolved = true;
            socket.setTimeout(0); // clear the handshake timeout — link is UP
            socket.removeListener("data", onData);
            resolve({ ok: true, linkId: lid });
          }
          return;
        }
      }
    };

    const onError = (err: Error) => {
      activeSockets.delete(socket);
      if (!resolved) { resolved = true; resolve({ ok: false, reason: err.message }); }
    };

    const onTimeout = () => {
      if (!resolved) { resolved = true; resolve({ ok: false, reason: "handshake timeout (10s)" }); }
      socket.destroy();
      activeSockets.delete(socket);
    };

    socket.once("connect", onConnect);
    socket.on("data", onData);
    socket.once("error", onError);
    socket.setTimeout(10000, onTimeout);

    socket.connect(port, host);
  });
}

/** Active sockets — kept alive so links stay LINK_UP after the dial promise resolves. */
const activeSockets = new Set<Socket>();

// ---------- HTTP control API ----------

const httpServer = createHttpServer(async (req: IncomingMessage, res: ServerResponse) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url ?? "/", `http://localhost:${NODE_PORT}`);

  // GET /status — node identity + current advertisement
  if (req.method === "GET" && url.pathname === "/status") {
    res.writeHead(200);
    res.end(JSON.stringify({
      ok: true,
      node: {
        name: NODE_NAME,
        nodeId: keypair.nodeId,
        publicKeyHex: bytesToHex(keypair.publicKey),
        wirePort: WIRE_PORT,
        controlPort: NODE_PORT,
      },
      advertisement: currentAdvertisement ? {
        nodeId: currentAdvertisement.nodeId,
        capabilities: currentAdvertisement.capabilities,
        endpoints: currentAdvertisement.endpoints,
        sequence: currentAdvertisement.sequence,
        timestamp: currentAdvertisement.timestamp,
        expiry: currentAdvertisement.expiry,
      } : null,
    }));
    return;
  }

  // GET /links — current directed links
  if (req.method === "GET" && url.pathname === "/links") {
    res.writeHead(200);
    res.end(JSON.stringify({
      ok: true,
      count: links.size,
      links: Array.from(links.values()).map((l) => ({
        linkId: l.linkId,
        localNodeId: l.localNodeId,
        remoteNodeId: l.remoteNodeId,
        remoteEndpoint: l.remoteEndpoint,
        remoteCapabilities: l.remoteCapabilities,
        state: l.state,
        createdAt: l.createdAt,
        stateChangedAt: l.stateChangedAt,
      })),
      events: linkEvents.slice(-20).map((e) => ({ ...e, linkId: e.linkId.slice(0, 40) })),
    }));
    return;
  }

  // POST /dial — dial out to another node
  if (req.method === "POST" && url.pathname === "/dial") {
    const body = await readBody(req);
    let parsed: { host?: string; port?: number; expectedNodeId?: string };
    try { parsed = JSON.parse(body); } catch { res.writeHead(400); res.end(JSON.stringify({ ok: false, error: "invalid JSON" })); return; }
    const host = parsed.host ?? "127.0.0.1";
    const port = parsed.port ?? 7788;
    const expectedNodeId = parsed.expectedNodeId;
    res.writeHead(200);
    const result = await dialOut(host, port, expectedNodeId);
    res.end(JSON.stringify({ ok: result.ok, linkId: result.linkId, reason: result.reason, dialed: { host, port } }));
    return;
  }

  // POST /refresh-advertisement — increment sequence + re-sign
  if (req.method === "POST" && url.pathname === "/refresh-advertisement") {
    sequenceCounter++;
    buildAdvertisement(
      [{ type: "tcp", address: "127.0.0.1", port: WIRE_PORT }],
      ["MESH_RELAY", "DISCOVERY"],
    );
    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, sequence: sequenceCounter, nodeId: keypair.nodeId }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ ok: false, error: "not found" }));
});

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => resolve(body));
  });
}

httpServer.listen(NODE_PORT, "127.0.0.1", () => {
  console.log(`[${NODE_NAME}] HTTP control API listening on 127.0.0.1:${NODE_PORT}`);
  console.log(`[${NODE_NAME}] ready. Endpoints: GET /status, GET /links, POST /dial, POST /refresh-advertisement`);
});

// ---------- Graceful shutdown ----------

process.on("SIGTERM", () => {
  console.log(`[${NODE_NAME}] SIGTERM received, shutting down`);
  wireServer.close();
  httpServer.close();
  process.exit(0);
});
process.on("SIGINT", () => process.exit(0));
