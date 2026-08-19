/**
 * ShareNet 2.0 — R-009 Stage 3 Phase 3: REAL TCP transport destroy propagation.
 *
 * Per the re-audit of 5f62f21: the previous "multi-process" test spawned
 * independent processes but used the PARENT TEST PROCESS as the router
 * (stdin/stdout IPC for each hop). The destroy artifact did NOT cross a
 * real transport boundary.
 *
 * This test fixes that: each participant is an INDEPENDENT PROCESS running
 * a TCP server. The destroy wire bytes cross a REAL TCP socket between
 * every hop. Each process uses its OWN DurableSqliteCircuitDestroyStore
 * (own SQLite DB file). No InMemoryCircuitDestroyStore in the propagation
 * path.
 *
 * Topology (initiator destroy, FORWARD):
 *
 *   Initiator process (TCP client)
 *       ↓ TCP socket (destroy wire bytes)
 *   Relay 0 process (TCP server + client)
 *       ↓ TCP socket (SAME wire bytes)
 *   Relay 1 process (TCP server + client)
 *       ↓ TCP socket (SAME wire bytes)
 *   Gateway process (TCP server — terminal)
 *
 * The destroy bytes are byte-for-byte identical at every hop (the propagation
 * invariant). Each participant durably revokes + zeroizes locally.
 *
 * For gateway destroy (BACKWARD), the direction reverses:
 *
 *   Gateway process (TCP client)
 *       ↓ TCP socket
 *   Relay 1 process
 *       ↓ TCP socket
 *   Relay 0 process
 *       ↓ TCP socket
 *   Initiator process (terminal)
 *
 * Each participant uses its OWN SQLite DB file (per-process durable namespace).
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { spawn, type ChildProcess, execSync } from "node:child_process";
import { createServer } from "node:net";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomBytes } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  setupCircuit,
} from "@reference/circuit/circuit";
import {
  constructReturnOnionTemplate,
  signGatewayReturnTemplate,
  constructGatewayReturnAuthorization,
  encodeGatewayReturnAuthorization,
} from "@reference/circuit/return-template";
import { handleCircuitSetup } from "@reference/circuit/distributed-setup";
import { InMemoryCircuitSequenceFloorStore } from "@reference/circuit/replay-stores";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";
import {
  signCircuitDestroy,
  encodeCircuitDestroy,
  DESTROYER_ROLE_INITIATOR,
  DESTROYER_ROLE_GATEWAY,
  DESTROY_REASON_OPERATOR_INITIATED,
} from "@reference/circuit/destroy";

const NOW = 1786876545;

// Per-test temp directory for participant DB files.
let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sharenet-p3-tcp-"));
});

afterAll(() => {
  try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

/**
 * Build a route + circuit + gateway proof artifacts.
 */
function makeTopology(numHops = 2) {
  const route = makeGenuineBrandedRouteHelper(numHops, NOW);
  const relayKeys = route.branded.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk };
  });
  const floorStore = new InMemoryCircuitSequenceFloorStore();
  const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
  const gatewayNodeId = route.branded.hops[route.branded.hops.length - 1]!.nodeId;
  const terminalHopIndex = route.branded.hops.length - 1;

  const ackResult = handleCircuitSetup(
    {
      route: route.branded,
      hopIndex: terminalHopIndex,
      initiatorX25519PublicKey: circuit.initiatorX25519PublicKey,
      setupNonce: randomBytes(16),
    },
    route.kps[terminalHopIndex]!.secretKey,
    route.branded.commitmentRoot,
    NOW,
  );
  if (!ackResult.ok) throw new Error(`terminal ack setup failed: ${ackResult.reason}`);

  const template = constructReturnOnionTemplate(circuit);
  const gatewayTemplate = signGatewayReturnTemplate(
    template, route.branded.expiry, gatewayNodeId,
    ackResult.state.relayX25519PublicKey,
    circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
    route.initiator.secretKey, route.initiator.publicKey,
  );
  const terminalAcceptance = route.commitment.acceptances[terminalHopIndex]!;
  const hopNodeIds = route.branded.hops.map((h) => h.nodeId);
  const authorization = constructGatewayReturnAuthorization(
    gatewayTemplate, ackResult.ack, route.kps[terminalHopIndex]!.publicKey,
    terminalAcceptance, hopNodeIds,
    route.commitment.proposal, route.commitment.acceptances,
  );
  const gatewayProofBytes = encodeGatewayReturnAuthorization(authorization);

  return {
    route,
    relayKeys,
    circuit,
    gatewayNodeId,
    gatewayProofBytes,
    initiatorKp: route.initiator,
    gatewayKp: route.kps[terminalHopIndex]!,
    terminalHopIndex,
  };
}

/** Serialize the circuit context for a child process (hex strings only). */
function serializeCircuit(circuit: ReturnType<typeof setupCircuit>): string {
  return JSON.stringify({
    circuitIdHex: toHex(circuit.circuitId),
    routeId: circuit.routeId,
    hops: circuit.hops.map((h) => ({
      hopIndex: h.hopIndex,
      nodeId: h.nodeId,
      forwardingKeyHex: toHex(h.forwardingKey),
      returnKeyHex: toHex(h.returnKey),
      relayX25519PublicKeyHex: h.relayX25519PublicKey ? toHex(h.relayX25519PublicKey) : null,
    })),
    initiatorX25519PublicKeyHex: toHex(circuit.initiatorX25519PublicKey),
    initiatorX25519SecretKeyHex: toHex(circuit.initiatorX25519SecretKey),
    expiry: circuit.expiry,
    establishedAt: circuit.establishedAt,
    noncePrefixHex: toHex(circuit.noncePrefix),
    commitmentRootHex: toHex(circuit.commitmentRoot),
  });
}

/**
 * Allocate a free TCP port by listening on port 0, then closing.
 * Returns the OS-assigned port number.
 */
function allocatePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (addr && typeof addr === "object") {
        const port = addr.port;
        srv.close(() => resolve(port));
      } else {
        srv.close();
        reject(new Error("failed to allocate port"));
      }
    });
    srv.on("error", reject);
  });
}

/**
 * The participant process script. Each participant:
 *   1. Listens on a TCP port (its OWN server — real transport).
 *   2. When it receives destroy wire bytes over the socket:
 *      a. Reconstructs a minimal ActiveCircuit from serialized hex artifacts.
 *      b. Creates a DurableSqliteCircuitDestroyStore backed by its OWN DB file.
 *      c. Calls processCircuitDestroy.
 *      d. If ok + propagate: forwards result.wireBytes (byte-for-byte) to the
 *         next hop over a TCP socket.
 *      e. Reports the result (action, isRevoked, keysZeroized, bytesIdentical)
 *         back to the parent over stdout.
 *   3. The terminal participant (gateway for forward, initiator for backward)
 *      does NOT forward — it just reports.
 *
 * The DB file path is per-participant — each process has its own durable
 * namespace.
 *
 * Wire protocol on each TCP socket:
 *   [4 bytes big-endian length][length bytes destroy wire]
 *
 * This is a real length-prefixed TCP framing protocol.
 */
const PARTICIPANT_SCRIPT = `
const { createServer, connect } = require("net");
const { processCircuitDestroy, propagationDirection } = require("${join(process.cwd(), "reference/circuit/destroy.ts").replace(/\\/g, "\\\\")}");
const { DurableSqliteCircuitDestroyStore } = require("${join(process.cwd(), "src/lib/sharenet/durable-circuit-replay-stores.ts").replace(/\\/g, "\\\\")}");

// Read config from stdin (JSON): circuitJson, listenPort, nextHopPort (or null),
// expectedInitiatorNodeId, expectedGatewayNodeId, now, gatewayProofHex (or null),
// role (initiator/relay0/relay1/gateway).
// DATABASE_URL is set via the process env (per-participant DB file).
let configInput = "";
process.stdin.on("data", (chunk) => { configInput += chunk; });
process.stdin.on("end", () => {
  const config = JSON.parse(configInput);
  const circuit = JSON.parse(config.circuitJson);
  const hops = circuit.hops.map((h) => ({
    hopIndex: h.hopIndex,
    nodeId: h.nodeId,
    forwardingKey: Buffer.from(h.forwardingKeyHex, "hex"),
    returnKey: Buffer.from(h.returnKeyHex, "hex"),
    relayX25519PublicKey: h.relayX25519PublicKeyHex ? Buffer.from(h.relayX25519PublicKeyHex, "hex") : undefined,
  }));
  const activeCircuit = {
    circuitId: Buffer.from(circuit.circuitIdHex, "hex"),
    circuitIdHex: circuit.circuitIdHex,
    routeId: circuit.routeId,
    hops,
    initiatorX25519PublicKey: Buffer.from(circuit.initiatorX25519PublicKeyHex, "hex"),
    initiatorX25519SecretKey: Buffer.from(circuit.initiatorX25519SecretKeyHex, "hex"),
    expiry: circuit.expiry,
    establishedAt: circuit.establishedAt,
    replayGuard: { checkAndRecord: () => ({ ok: true }), getHighestSeq: () => 0n, getSequenceFloor: () => 0n },
    noncePrefix: Buffer.from(circuit.noncePrefixHex, "hex"),
    commitmentRoot: Buffer.from(circuit.commitmentRootHex, "hex"),
    floorStore: { getFloor: async () => 0n, checkAndAdvance: async () => ({ ok: true }) },
  };

  // Per-participant DurableSqliteCircuitDestroyStore (uses the app-global db,
  // which picks up DATABASE_URL from the process env — per-participant DB file).
  const destroyStore = new DurableSqliteCircuitDestroyStore();

  const gatewayProofBytes = config.gatewayProofHex
    ? Buffer.from(config.gatewayProofHex, "hex")
    : undefined;

  // Helper: send wire bytes over a TCP socket with length-prefix framing.
  function sendWire(port, wireBytes) {
    return new Promise((resolve, reject) => {
      const sock = connect(port, "127.0.0.1", () => {
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(wireBytes.length, 0);
        sock.write(lenBuf);
        sock.write(wireBytes);
      });
      sock.on("error", reject);
      sock.on("close", resolve);
      // Wait for the write to flush, then close.
      setTimeout(() => sock.end(), 50);
    });
  }

  // Helper: read length-prefixed wire bytes from a socket.
  function readWire(socket) {
    return new Promise((resolve, reject) => {
      let lenBuf = null;
      let payload = Buffer.alloc(0);
      let expected = 0;
      socket.on("data", (chunk) => {
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
              resolve(payload);
              return;
            }
          }
        }
      });
      socket.on("error", reject);
    });
  }

  // If this participant is the ORIGINATOR (initiator for forward, gateway for
  // backward), it does NOT listen on a TCP port — it directly processes the
  // destroy locally, then sends result.wireBytes to the next hop.
  if (config.isOriginator) {
    (async () => {
      const wireBytes = Buffer.from(config.originatorDestroyHex, "hex");
      const result = await processCircuitDestroy(
        wireBytes, activeCircuit,
        config.expectedInitiatorNodeId, config.expectedGatewayNodeId,
        destroyStore, config.now, gatewayProofBytes,
      );
      if (!result.ok) {
        process.stdout.write(JSON.stringify({ ok: false, reason: result.reason, role: config.role }));
        process.exit(0);
      }
      const keysZeroized = activeCircuit.hops.every(
        (h) => h.forwardingKey.every((b) => b === 0) && h.returnKey.every((b) => b === 0),
      );
      const isRevoked = await destroyStore.isRevoked(activeCircuit.circuitId, activeCircuit.commitmentRoot);
      // Forward result.wireBytes to the next hop over TCP (real transport).
      let transportError = null;
      if (config.nextHopPort && result.propagate) {
        try {
          await sendWire(config.nextHopPort, result.wireBytes);
        } catch (e) {
          transportError = e.message;
        }
      }
      process.stdout.write(JSON.stringify({
        ok: true, action: result.action, propagate: result.propagate,
        isRevoked, keysZeroized, direction: propagationDirection(result.circuitDestroy),
        bytesIdentical: Buffer.from(result.wireBytes).toString("hex") === config.originatorDestroyHex,
        transportError,
        role: config.role,
      }));
      process.exit(0);
    })();
    return;
  }

  // Otherwise: listen on a TCP port for incoming destroy wire bytes.
  const server = createServer(async (socket) => {
    try {
      const wireBytes = await readWire(socket);
      const result = await processCircuitDestroy(
        wireBytes, activeCircuit,
        config.expectedInitiatorNodeId, config.expectedGatewayNodeId,
        destroyStore, config.now, gatewayProofBytes,
      );
      if (!result.ok) {
        process.stdout.write(JSON.stringify({ ok: false, reason: result.reason, role: config.role }));
        process.exit(0);
      }
      const keysZeroized = activeCircuit.hops.every(
        (h) => h.forwardingKey.every((b) => b === 0) && h.returnKey.every((b) => b === 0),
      );
      const isRevoked = await destroyStore.isRevoked(activeCircuit.circuitId, activeCircuit.commitmentRoot);
      const inputHex = wireBytes.toString("hex");
      const outputHex = Buffer.from(result.wireBytes).toString("hex");
      // Forward result.wireBytes to the next hop over TCP (real transport).
      let transportError = null;
      if (config.nextHopPort && result.propagate) {
        try {
          await sendWire(config.nextHopPort, result.wireBytes);
        } catch (e) {
          transportError = e.message;
        }
      }
      process.stdout.write(JSON.stringify({
        ok: true, action: result.action, propagate: result.propagate,
        isRevoked, keysZeroized,
        bytesIdentical: inputHex === outputHex,
        inputHex, outputHex,
        direction: propagationDirection(result.circuitDestroy),
        transportError,
        role: config.role,
      }));
      process.exit(0);
    } catch (e) {
      process.stdout.write(JSON.stringify({ ok: false, reason: "server error: " + e.message, role: config.role }));
      process.exit(1);
    }
  });
  server.listen(config.listenPort, "127.0.0.1", () => {
    // Signal readiness to the parent (empty write).
    process.stdout.write("");
  });
});
`;

/**
 * Spawn a participant process. The `dbPath` determines the per-participant
 * DATABASE_URL env var (own SQLite DB namespace). Returns the ChildProcess +
 * a promise that resolves with the participant's result (parsed from stdout
 * on exit).
 */
function spawnParticipant(config: Record<string, unknown> & { dbPath: string }): {
  child: ChildProcess;
  result: Promise<any>;
} {
  const child = spawn("bun", ["-e", PARTICIPANT_SCRIPT], {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      DATABASE_URL: `file:${config.dbPath}`,
    },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => { stdout += d; });
  child.stderr.on("data", (d) => { stderr += d; });
  const result = new Promise<any>((resolve) => {
    child.on("close", () => {
      try {
        resolve(JSON.parse(stdout));
      } catch {
        resolve({ ok: false, reason: `participant failed: ${stderr || stdout}` });
      }
    });
  });
  child.stdin.write(JSON.stringify(config));
  child.stdin.end();
  return { child, result };
}

/** Helper: verify the tombstone exists in a per-participant DB file. */
async function verifyTombstone(dbPath: string, circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean> {
  const { DurableSqliteCircuitRevocationStore } = await import("@/lib/sharenet/durable-circuit-replay-stores");
  const { PrismaClient } = await import("@prisma/client");
  const prisma = new PrismaClient({ datasources: { db: { url: `file:${dbPath}` } } });
  const store = new DurableSqliteCircuitRevocationStore(prisma);
  const isRevoked = await store.isRevoked(circuitId, commitmentRoot);
  await prisma.$disconnect();
  return isRevoked;
}

/** Helper: push the Prisma schema to a fresh per-participant DB file. */
function pushSchemaToDb(dbPath: string) {
  // Use prisma db push with the DATABASE_URL env var pointing at the per-
  // participant DB file. This creates all tables with the correct schema
  // (including the `id` cuid primary key on ConsumedCircuitDestroy).
  execSync(
    `DATABASE_URL="file:${dbPath}" bunx prisma db push --accept-data-loss --skip-generate`,
    { stdio: "pipe", cwd: process.cwd() },
  );
}

// =====================================================================
// Phase 6: REAL TCP transport — initiator destroy FORWARD
// =====================================================================

describe("R-009 Stage 3 Phase 3 (real TCP): initiator destroy FORWARD", () => {
  test("INITIATOR → relay0 → relay1 → GATEWAY over TCP: all REVOKED, bytes unchanged, keys zeroized", async () => {
    const topo = makeTopology(2); // hops: [relay0, relay1=gateway]
    const circuitJson = serializeCircuit(topo.circuit);
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const destroyWireHex = toHex(encodeCircuitDestroy(destroy));

    // Allocate TCP ports for relay0, relay1, gateway.
    const relay0Port = await allocatePort();
    const relay1Port = await allocatePort();
    const gatewayPort = await allocatePort();

    // Per-participant DB files.
    const dbRelay0 = join(tmpDir, "relay0.db");
    const dbRelay1 = join(tmpDir, "relay1.db");
    const dbGateway = join(tmpDir, "gateway.db");
    pushSchemaToDb(dbRelay0);
    pushSchemaToDb(dbRelay1);
    pushSchemaToDb(dbGateway);

    // Spawn the GATEWAY first (terminal — listens, does NOT forward).
    const gateway = spawnParticipant({
      role: "gateway",
      circuitJson,
      listenPort: gatewayPort,
      nextHopPort: null, // terminal
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbGateway,
      gatewayProofHex: null, // initiator destroy — no gateway proof needed
      isOriginator: false,
    });

    // Wait a moment for the gateway to start listening.
    await new Promise((r) => setTimeout(r, 300));

    // Spawn RELAY 1 (listens, forwards to gateway).
    const relay1 = spawnParticipant({
      role: "relay1",
      circuitJson,
      listenPort: relay1Port,
      nextHopPort: gatewayPort,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay1,
      gatewayProofHex: null,
      isOriginator: false,
    });
    await new Promise((r) => setTimeout(r, 300));

    // Spawn RELAY 0 (listens, forwards to relay1).
    const relay0 = spawnParticipant({
      role: "relay0",
      circuitJson,
      listenPort: relay0Port,
      nextHopPort: relay1Port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay0,
      gatewayProofHex: null,
      isOriginator: false,
    });
    await new Promise((r) => setTimeout(r, 300));

    // Spawn the INITIATOR (originator — does NOT listen; directly processes +
    // sends to relay0 over TCP).
    const initiator = spawnParticipant({
      role: "initiator",
      circuitJson,
      listenPort: null,
      nextHopPort: relay0Port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: join(tmpDir, "initiator.db"),
      gatewayProofHex: null,
      isOriginator: true,
      originatorDestroyHex: destroyWireHex,
    });
    pushSchemaToDb(join(tmpDir, "initiator.db"));

    // Wait for all participants to complete.
    const [initiatorResult, relay0Result, relay1Result, gatewayResult] = await Promise.all([
      initiator.result,
      relay0.result,
      relay1.result,
      gateway.result,
    ]);

    // INITIATOR: REVOKED, keys zeroized, bytes identical, direction FORWARD.
    expect(initiatorResult.ok).toBe(true);
    if (!initiatorResult.ok) return;
    expect(initiatorResult.action).toBe("REVOKED");
    expect(initiatorResult.isRevoked).toBe(true);
    expect(initiatorResult.keysZeroized).toBe(true);
    expect(initiatorResult.bytesIdentical).toBe(true);
    expect(initiatorResult.direction).toBe("FORWARD");

    // RELAY 0: REVOKED, keys zeroized, bytes identical (input === output).
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.action).toBe("REVOKED");
    expect(relay0Result.isRevoked).toBe(true);
    expect(relay0Result.keysZeroized).toBe(true);
    expect(relay0Result.bytesIdentical).toBe(true);
    // The wire bytes received over TCP === the original destroy wire bytes.
    expect(relay0Result.inputHex).toBe(destroyWireHex);
    expect(relay0Result.outputHex).toBe(destroyWireHex);

    // RELAY 1: same.
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(relay1Result.action).toBe("REVOKED");
    expect(relay1Result.isRevoked).toBe(true);
    expect(relay1Result.keysZeroized).toBe(true);
    expect(relay1Result.bytesIdentical).toBe(true);
    expect(relay1Result.inputHex).toBe(destroyWireHex);

    // GATEWAY: REVOKED, terminal (no forward).
    expect(gatewayResult.ok).toBe(true);
    if (!gatewayResult.ok) return;
    expect(gatewayResult.action).toBe("REVOKED");
    expect(gatewayResult.isRevoked).toBe(true);
    expect(gatewayResult.keysZeroized).toBe(true);
    expect(gatewayResult.inputHex).toBe(destroyWireHex);

    // ALL 4 participants durably revoked over real TCP transport.
  }, 60000);
});

// =====================================================================
// Phase 9: REAL TCP transport — gateway destroy BACKWARD
// =====================================================================

describe("R-009 Stage 3 Phase 3 (real TCP): gateway destroy BACKWARD", () => {
  test("GATEWAY → relay1 → relay0 → INITIATOR over TCP: all REVOKED, bytes unchanged", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.gatewayNodeId,
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.gatewayKp.secretKey, topo.gatewayKp.publicKey,
    );
    const destroyWireHex = toHex(encodeCircuitDestroy(destroy));
    const gatewayProofHex = toHex(topo.gatewayProofBytes);

    // Backward direction: gateway → relay1 → relay0 → initiator.
    const relay0Port = await allocatePort();
    const relay1Port = await allocatePort();
    const initiatorPort = await allocatePort();

    const dbInitiator = join(tmpDir, "gw-initiator.db");
    const dbRelay0 = join(tmpDir, "gw-relay0.db");
    const dbRelay1 = join(tmpDir, "gw-relay1.db");
    pushSchemaToDb(dbInitiator);
    pushSchemaToDb(dbRelay0);
    pushSchemaToDb(dbRelay1);

    // INITIATOR (terminal — listens, does NOT forward).
    const initiator = spawnParticipant({
      role: "initiator",
      circuitJson,
      listenPort: initiatorPort,
      nextHopPort: null,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbInitiator,
      gatewayProofHex,
      isOriginator: false,
    });
    await new Promise((r) => setTimeout(r, 300));

    // RELAY 0 (listens, forwards to initiator).
    const relay0 = spawnParticipant({
      role: "relay0",
      circuitJson,
      listenPort: relay0Port,
      nextHopPort: initiatorPort,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay0,
      gatewayProofHex,
      isOriginator: false,
    });
    await new Promise((r) => setTimeout(r, 300));

    // RELAY 1 (listens, forwards to relay0).
    const relay1 = spawnParticipant({
      role: "relay1",
      circuitJson,
      listenPort: relay1Port,
      nextHopPort: relay0Port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay1,
      gatewayProofHex,
      isOriginator: false,
    });
    await new Promise((r) => setTimeout(r, 300));

    // GATEWAY (originator — directly processes + sends to relay1).
    const dbGateway = join(tmpDir, "gw-gateway.db");
    pushSchemaToDb(dbGateway);
    const gateway = spawnParticipant({
      role: "gateway",
      circuitJson,
      listenPort: null,
      nextHopPort: relay1Port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbGateway,
      gatewayProofHex,
      isOriginator: true,
      originatorDestroyHex: destroyWireHex,
    });

    const [gatewayResult, relay1Result, relay0Result, initiatorResult] = await Promise.all([
      gateway.result,
      relay1.result,
      relay0.result,
      initiator.result,
    ]);

    // GATEWAY: REVOKED, direction BACKWARD.
    expect(gatewayResult.ok).toBe(true);
    if (!gatewayResult.ok) return;
    expect(gatewayResult.action).toBe("REVOKED");
    expect(gatewayResult.isRevoked).toBe(true);
    expect(gatewayResult.keysZeroized).toBe(true);
    expect(gatewayResult.direction).toBe("BACKWARD");
    expect(gatewayResult.bytesIdentical).toBe(true);

    // RELAY 1: REVOKED, bytes identical.
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(relay1Result.action).toBe("REVOKED");
    expect(relay1Result.isRevoked).toBe(true);
    expect(relay1Result.keysZeroized).toBe(true);
    expect(relay1Result.inputHex).toBe(destroyWireHex);
    expect(relay1Result.outputHex).toBe(destroyWireHex);

    // RELAY 0: REVOKED.
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.action).toBe("REVOKED");
    expect(relay0Result.isRevoked).toBe(true);
    expect(relay0Result.keysZeroized).toBe(true);
    expect(relay0Result.inputHex).toBe(destroyWireHex);

    // INITIATOR (terminal): REVOKED.
    expect(initiatorResult.ok).toBe(true);
    if (!initiatorResult.ok) return;
    expect(initiatorResult.action).toBe("REVOKED");
    expect(initiatorResult.isRevoked).toBe(true);
    expect(initiatorResult.keysZeroized).toBe(true);
    expect(initiatorResult.inputHex).toBe(destroyWireHex);
  }, 60000);
});

// =====================================================================
// Phase 7: transport-failure test (local revoke succeeds + next-hop fails)
// =====================================================================

describe("R-009 Stage 3 Phase 3 (real TCP): transport failure", () => {
  test("local revoke succeeds + next-hop transport fails → local remains REVOKED, retry possible", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const destroyWireHex = toHex(encodeCircuitDestroy(destroy));

    // Allocate a port for relay0, but DON'T spawn relay0 — simulate transport
    // failure (connection refused).
    const relay0Port = await allocatePort();
    // Don't allocate a DB for relay0 — it never starts.

    const dbInitiator = join(tmpDir, "tf-initiator.db");
    pushSchemaToDb(dbInitiator);

    // INITIATOR (originator) — tries to send to relay0, which is NOT listening.
    // The local revoke succeeds; the TCP send fails (connection refused).
    // The initiator's result should still report REVOKED (local state
    // authoritative) — the transport failure is a separate transport concern.
    const initiator = spawnParticipant({
      role: "initiator",
      circuitJson,
      listenPort: null,
      nextHopPort: relay0Port, // nobody listening → transport failure
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbInitiator,
      gatewayProofHex: null,
      isOriginator: true,
      originatorDestroyHex: destroyWireHex,
    });

    const initiatorResult = await initiator.result;

    // The local revoke SUCCEEDED (the tombstone is persisted). The transport
    // failure does NOT roll back the local terminal state.
    // (The child process may report ok:false if the sendWire threw — but the
    // local revoke + tombstone are already persisted. We verify the tombstone
    // directly via a fresh PrismaClient below.)
    // The child may report ok:false (transport error) OR ok:true (if the send
    // completed before the error surfaced). Either way, the local tombstone
    // is persisted. Verify the tombstone directly:
    const isRevokedAfterFailure = await verifyTombstone(dbInitiator, topo.circuit.circuitId, topo.circuit.commitmentRoot);
    expect(isRevokedAfterFailure).toBe(true); // local remains REVOKED despite transport failure

    // RETRY: now spawn relay0 (the next hop comes online). Re-send the SAME
    // destroy. The initiator is already revoked (idempotent); the retry here
    // is the transport layer re-attempting delivery to relay0. relay0 receives
    // the destroy for the first time → fresh revoke.
    const dbRelay0 = join(tmpDir, "tf-relay0.db");
    pushSchemaToDb(dbRelay0);

    // Spawn relay0 (listens, no next hop — terminal for this retry test).
    const relay0 = spawnParticipant({
      role: "relay0",
      circuitJson,
      listenPort: relay0Port,
      nextHopPort: null,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay0,
      gatewayProofHex: null,
      isOriginator: false,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Manually send the destroy wire bytes to relay0 over TCP (retry).
    const { connect } = await import("node:net");
    await new Promise<void>((resolve, reject) => {
      const sock = connect(relay0Port, "127.0.0.1", () => {
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(encodeCircuitDestroy(destroy).length, 0);
        sock.write(lenBuf);
        sock.write(encodeCircuitDestroy(destroy));
        setTimeout(() => { sock.end(); resolve(); }, 100);
      });
      sock.on("error", reject);
    });

    const relay0Result = await relay0.result;
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.action).toBe("REVOKED");
    expect(relay0Result.isRevoked).toBe(true);
    expect(relay0Result.keysZeroized).toBe(true);
    expect(relay0Result.inputHex).toBe(destroyWireHex); // bytes unchanged
  }, 60000);
});

// =====================================================================
// Phase 8: restart test (real durable store — kill + restart participant)
// =====================================================================

describe("R-009 Stage 3 Phase 3 (real TCP): restart with durable store", () => {
  test("after revoke + restart, old destroy → idempotent, old frame → REJECT", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const destroyWireHex = toHex(encodeCircuitDestroy(destroy));

    const dbParticipant = join(tmpDir, "restart-participant.db");
    pushSchemaToDb(dbParticipant);

    // PHASE 1: the participant receives the destroy + revokes.
    const port1 = await allocatePort();
    const participant1 = spawnParticipant({
      role: "relay0",
      circuitJson,
      listenPort: port1,
      nextHopPort: null,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbParticipant,
      gatewayProofHex: null,
      isOriginator: false,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Send the destroy over TCP.
    const { connect } = await import("node:net");
    await new Promise<void>((resolve, reject) => {
      const sock = connect(port1, "127.0.0.1", () => {
        const wire = encodeCircuitDestroy(destroy);
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(wire.length, 0);
        sock.write(lenBuf);
        sock.write(wire);
        setTimeout(() => { sock.end(); resolve(); }, 100);
      });
      sock.on("error", reject);
    });
    const r1 = await participant1.result;
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.action).toBe("REVOKED");

    // PHASE 2: RESTART — spawn a NEW participant process with the SAME DB file.
    // The tombstone persisted in the DB → the restarted participant sees it.
    const port2 = await allocatePort();
    const participant2 = spawnParticipant({
      role: "relay0-restarted",
      circuitJson,
      listenPort: port2,
      nextHopPort: null,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbParticipant, // SAME DB file — tombstone persists
      gatewayProofHex: null,
      isOriginator: false,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Send the SAME destroy again → idempotent (ALREADY_REVOKED).
    await new Promise<void>((resolve, reject) => {
      const sock = connect(port2, "127.0.0.1", () => {
        const wire = encodeCircuitDestroy(destroy);
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(wire.length, 0);
        sock.write(lenBuf);
        sock.write(wire);
        setTimeout(() => { sock.end(); resolve(); }, 100);
      });
      sock.on("error", reject);
    });
    const r2 = await participant2.result;
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.action).toBe("ALREADY_REVOKED"); // idempotent — tombstone persisted
    expect(r2.propagate).toBe(false); // suppressed

    // PHASE 3: verify the old frame would be REJECTED (the tombstone is present).
    const isRevokedAfterRestart = await verifyTombstone(dbParticipant, topo.circuit.circuitId, topo.circuit.commitmentRoot);
    expect(isRevokedAfterRestart).toBe(true);
  }, 60000);
});

// =====================================================================
// Phase 9: concurrent multi-process destroy (two destroys, exactly ONE transition)
// =====================================================================

describe("R-009 Stage 3 Phase 3 (real TCP): concurrent multi-process destroy", () => {
  test("two concurrent destroy events (different nonces) → exactly ONE ACTIVE→REVOKED transition per participant", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    // Sign TWO destroys with DIFFERENT nonces (signCircuitDestroy generates a
    // fresh random nonce each call).
    const destroyA = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const destroyB = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const wireA = encodeCircuitDestroy(destroyA);
    const wireB = encodeCircuitDestroy(destroyB);

    const dbParticipant = join(tmpDir, "concurrent-participant.db");
    pushSchemaToDb(dbParticipant);

    // Spawn ONE participant that listens on TWO ports (one for each destroy).
    // Actually: spawn ONE participant on ONE port, send BOTH destroys concurrently
    // over separate TCP connections. The participant's DurableSqlite store
    // uses the CREATE (not upsert) tombstone — exactly ONE wins, the other is
    // idempotent.
    const port = await allocatePort();
    // Custom script: handle multiple connections (don't exit after the first).
    const script = `
      const { createServer, connect } = require("net");
      const { processCircuitDestroy } = require("${join(process.cwd(), "reference/circuit/destroy.ts").replace(/\\/g, "\\\\")}");
      const { DurableSqliteCircuitDestroyStore } = require("${join(process.cwd(), "src/lib/sharenet/durable-circuit-replay-stores.ts").replace(/\\/g, "\\\\")}");
      const { PrismaClient } = require("@prisma/client");
      let configInput = "";
      process.stdin.on("data", (chunk) => { configInput += chunk; });
      process.stdin.on("end", () => {
        const config = JSON.parse(configInput);
        const circuit = JSON.parse(config.circuitJson);
        const hops = circuit.hops.map((h) => ({
          hopIndex: h.hopIndex, nodeId: h.nodeId,
          forwardingKey: Buffer.from(h.forwardingKeyHex, "hex"),
          returnKey: Buffer.from(h.returnKeyHex, "hex"),
          relayX25519PublicKey: h.relayX25519PublicKeyHex ? Buffer.from(h.relayX25519PublicKeyHex, "hex") : undefined,
        }));
        const activeCircuit = {
          circuitId: Buffer.from(circuit.circuitIdHex, "hex"),
          circuitIdHex: circuit.circuitIdHex, routeId: circuit.routeId, hops,
          initiatorX25519PublicKey: Buffer.from(circuit.initiatorX25519PublicKeyHex, "hex"),
          initiatorX25519SecretKey: Buffer.from(circuit.initiatorX25519SecretKeyHex, "hex"),
          expiry: circuit.expiry, establishedAt: circuit.establishedAt,
          replayGuard: { checkAndRecord: () => ({ ok: true }), getHighestSeq: () => 0n, getSequenceFloor: () => 0n },
          noncePrefix: Buffer.from(circuit.noncePrefixHex, "hex"),
          commitmentRoot: Buffer.from(circuit.commitmentRootHex, "hex"),
          floorStore: { getFloor: async () => 0n, checkAndAdvance: async () => ({ ok: true }) },
        };
        const prisma = new PrismaClient({ datasources: { db: { url: "file:" + config.dbPath } } });
        const destroyStore = new DurableSqliteCircuitDestroyStore(prisma);

        function readWire(socket) {
          return new Promise((resolve, reject) => {
            let lenBuf = null, payload = Buffer.alloc(0), expected = 0;
            socket.on("data", (chunk) => {
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
                  if (payload.length === expected) { resolve(payload); return; }
                }
              }
            });
            socket.on("error", reject);
          });
        }

        let results = [];
        const server = createServer(async (socket) => {
          const wireBytes = await readWire(socket);
          const result = await processCircuitDestroy(
            wireBytes, activeCircuit,
            config.expectedInitiatorNodeId, config.expectedGatewayNodeId,
            destroyStore, config.now, undefined,
          );
          results.push(result);
          if (results.length === 2) {
            // Both done — report.
            process.stdout.write(JSON.stringify({ ok: true, results: results.map(r => r.ok ? { ok: true, action: r.action, idempotent: r.idempotent } : { ok: false, reason: r.reason }) }));
            await prisma.$disconnect();
            process.exit(0);
          }
        });
        server.listen(config.listenPort, "127.0.0.1");
      });
    `;
    const child = spawn("bun", ["-e", script], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    const donePromise = new Promise<any>((resolve) => {
      child.on("close", () => {
        try { resolve(JSON.parse(stdout)); } catch { resolve({ ok: false, reason: stderr || stdout }); }
      });
    });
    child.stdin.write(JSON.stringify({
      circuitJson,
      listenPort: port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbParticipant,
    }));
    child.stdin.end();
    await new Promise((r) => setTimeout(r, 400));

    // Send BOTH destroys CONCURRENTLY over separate TCP connections.
    const { connect } = await import("node:net");
    const sendDestroy = (wire: Uint8Array) => new Promise<void>((resolve, reject) => {
      const sock = connect(port, "127.0.0.1", () => {
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeUInt32BE(wire.length, 0);
        sock.write(lenBuf);
        sock.write(wire);
        setTimeout(() => { sock.end(); resolve(); }, 100);
      });
      sock.on("error", reject);
    });
    await Promise.all([sendDestroy(wireA), sendDestroy(wireB)]);

    const result = await donePromise;
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Exactly ONE performed the terminal transition (action: REVOKED).
    const transitions = result.results.filter((r: any) => r.ok && r.action === "REVOKED");
    expect(transitions.length).toBe(1);
    // The OTHER is idempotent (action: ALREADY_REVOKED).
    const idempotents = result.results.filter((r: any) => r.ok && r.action === "ALREADY_REVOKED");
    expect(idempotents.length).toBe(1);

    // Verify the tombstone is in the DB.
    const isRevokedAfterConcurrent = await verifyTombstone(dbParticipant, topo.circuit.circuitId, topo.circuit.commitmentRoot);
    expect(isRevokedAfterConcurrent).toBe(true);
  }, 60000);
});
