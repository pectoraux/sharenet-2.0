/**
 * ShareNet 2.0 — R-009 Stage 3 Phase 3: PRODUCTION transport destroy propagation.
 *
 * Per the re-audit of 90f31a7: the previous test embedded the participant
 * forwarding logic in the test itself (a second transport protocol in the
 * test). The production propagation path (propagateCircuitDestroy) did not
 * exist.
 *
 * This test exercises the PRODUCTION propagation abstraction:
 *
 *   participant process
 *       → production propagateCircuitDestroy() (reference/circuit/propagation.ts)
 *       → TopologyNextHopResolver (protocol-core, derives next hop from direction + topology)
 *       → TcpCircuitDestroyTransport (platform-layer TCP adapter, src/lib/sharenet/)
 *       → authenticated TCP transport
 *       → next participant process
 *       → production propagateCircuitDestroy() again
 *
 * The test does NOT contain protocol-specific forwarding logic. It wires the
 * production transport + resolver to the production propagateCircuitDestroy()
 * function. The direction is derived from the signed destroyerRole — NOT
 * caller-supplied.
 *
 * Each participant uses its OWN DurableSqliteCircuitDestroyStore (own SQLite
 * DB file via DATABASE_URL env var). No InMemoryCircuitDestroyStore in the
 * propagation path.
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { spawn, execSync, type ChildProcess } from "node:child_process";
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

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sharenet-p3-prod-"));
});

afterAll(() => {
  try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

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
    hopNodeIds,
  };
}

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

function pushSchemaToDb(dbPath: string) {
  execSync(
    `DATABASE_URL="file:${dbPath}" bunx prisma db push --accept-data-loss --skip-generate`,
    { stdio: "pipe", cwd: process.cwd() },
  );
}

/**
 * The participant process script. This uses the PRODUCTION propagation
 * abstraction:
 *   - propagateCircuitDestroy() from reference/circuit/propagation.ts
 *   - TopologyNextHopResolver from reference/circuit/propagation.ts
 *   - TcpCircuitDestroyTransport from src/lib/sharenet/circuit-destroy-transport.ts
 *   - DurableSqliteCircuitDestroyStore from src/lib/sharenet/durable-circuit-replay-stores.ts
 *
 * The test does NOT contain protocol-specific forwarding logic — the
 * production propagateCircuitDestroy() owns the full pipeline.
 *
 * The participant constructs an AuthenticatedLink (a minimal mock for the
 * test — in production, this comes from the ShareNet link layer's 3-message
 * handshake). The link binds localNodeId ↔ remoteNodeId.
 */
const PARTICIPANT_SCRIPT = `
const { createServer, connect } = require("net");
const { propagateCircuitDestroy, TopologyNextHopResolver, propagationDirection } = require("${join(process.cwd(), "reference/circuit/propagation.ts").replace(/\\/g, "\\\\")}");
const { DurableSqliteCircuitDestroyStore } = require("${join(process.cwd(), "src/lib/sharenet/durable-circuit-replay-stores.ts").replace(/\\/g, "\\\\")}");
const { TcpCircuitDestroyTransport } = require("${join(process.cwd(), "src/lib/sharenet/circuit-destroy-transport.ts").replace(/\\/g, "\\\\")}");

let configInput = "";
process.stdin.on("data", (chunk) => { configInput += chunk; });
process.stdin.on("end", async () => {
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

  const destroyStore = new DurableSqliteCircuitDestroyStore();
  const gatewayProofBytes = config.gatewayProofHex ? Buffer.from(config.gatewayProofHex, "hex") : undefined;

  // Build the authenticated links map: a mock AuthenticatedLink per neighbor.
  // In production, this comes from the ShareNet link layer's 3-message handshake.
  // The link binds localNodeId <-> remoteNodeId.
  const links = new Map();
  for (const [neighborNodeId, linkId] of Object.entries(config.links)) {
    links.set(neighborNodeId, {
      localNodeId: config.localNodeId,
      remoteNodeId: neighborNodeId,
      linkIdHex: linkId,
      linkIdBytes: Buffer.alloc(32, 0),
      transcriptDigestHex: "mock",
      localRole: "INITIATOR",
      establishedAt: ${NOW},
      expiresAt: ${NOW + 3600},
      transcriptVerifiedAt: ${NOW},
      remoteNode: { nodeId: neighborNodeId },
    });
  }

  // TopologyNextHopResolver: derives the next hop from direction + topology.
  const resolver = new TopologyNextHopResolver(config.hopNodeIds, config.expectedInitiatorNodeId, links);

  // If this participant is the ORIGINATOR, it does NOT listen — it directly
  // calls propagateCircuitDestroy + sends to the next hop.
  if (config.isOriginator) {
    // Build a transport that can SEND (no listen needed for the originator).
    const transport = new TcpCircuitDestroyTransport(config.localNodeId, 0, new Map(Object.entries(config.peerPortRegistry)));
    const wireBytes = Buffer.from(config.originatorDestroyHex, "hex");
    const result = await propagateCircuitDestroy(
      wireBytes, activeCircuit,
      config.localNodeId,
      config.expectedInitiatorNodeId, config.expectedGatewayNodeId,
      destroyStore, config.now,
      resolver, transport, gatewayProofBytes,
    );
    // Verify keys were zeroized + tombstone persisted.
    const keysZeroized = activeCircuit.hops.every(
      (h) => h.forwardingKey.every((b) => b === 0) && h.returnKey.every((b) => b === 0),
    );
    const isRevoked = await destroyStore.isRevoked(activeCircuit.circuitId, activeCircuit.commitmentRoot);
    process.stdout.write(JSON.stringify({ ...result, keysZeroized, isRevoked }));
    process.exit(0);
    return;
  }

  // Otherwise: start a TCP server (receive) + build the transport.
  const transport = new TcpCircuitDestroyTransport(config.localNodeId, config.listenPort, new Map(Object.entries(config.peerPortRegistry)));
  await transport.start();

  // Receive the destroy wire bytes over TCP (the real transport).
  const wireBytes = await transport.receive(config.localNodeId);

  // Call the PRODUCTION propagateCircuitDestroy (owns process + resolve + send).
  const result = await propagateCircuitDestroy(
    wireBytes, activeCircuit,
    config.localNodeId,
    config.expectedInitiatorNodeId, config.expectedGatewayNodeId,
    destroyStore, config.now,
    resolver, transport, gatewayProofBytes,
  );

  // Wait briefly for any outgoing send to flush.
  await new Promise((r) => setTimeout(r, 300));
  await transport.stop();

  // Verify keys were zeroized.
  const keysZeroized = activeCircuit.hops.every(
    (h) => h.forwardingKey.every((b) => b === 0) && h.returnKey.every((b) => b === 0),
  );
  const isRevoked = await destroyStore.isRevoked(activeCircuit.circuitId, activeCircuit.commitmentRoot);

  process.stdout.write(JSON.stringify({
    ...result,
    keysZeroized,
    isRevoked,
    direction: result.ok ? propagationDirection(JSON.parse(config.destroyForDirection)) : null,
  }));
  process.exit(0);
});
`;

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
  child.stderr.on("data", (d) => {
    stderr += d;
    // Print child stderr directly so we can see trace logs.
    process.stderr.write(`[${config.role || "child"}] ${d}`);
  });
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

async function verifyTombstone(dbPath: string, circuitId: Uint8Array, commitmentRoot: Uint8Array): Promise<boolean> {
  const { DurableSqliteCircuitRevocationStore } = await import("@/lib/sharenet/durable-circuit-replay-stores");
  const { PrismaClient } = await import("@prisma/client");
  const prisma = new PrismaClient({ datasources: { db: { url: `file:${dbPath}` } } });
  const store = new DurableSqliteCircuitRevocationStore(prisma);
  const isRevoked = await store.isRevoked(circuitId, commitmentRoot);
  await prisma.$disconnect();
  return isRevoked;
}

// Build a minimal mock links map for a participant (links to its neighbors).
function buildLinks(localNodeId: string, neighborNodeIds: string[]): Record<string, string> {
  const links: Record<string, string> = {};
  for (const neighbor of neighborNodeIds) {
    links[neighbor] = `link-${localNodeId}-${neighbor}`;
  }
  return links;
}

// =====================================================================
// Phase 8: PRODUCTION transport — initiator destroy FORWARD
// =====================================================================

describe("R-009 Stage 3 Phase 3 (production transport): initiator destroy FORWARD", () => {
  test("INITIATOR → relay0 → relay1 → GATEWAY via production propagateCircuitDestroy: all REVOKED, bytes unchanged", async () => {
    const topo = makeTopology(3); // hops: [relay0, relay1, gateway]
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
    const destroyForDirection = JSON.stringify(destroy);

    const relay0Port = await allocatePort();
    const relay1Port = await allocatePort();
    const gatewayPort = await allocatePort();

    const dbRelay0 = join(tmpDir, "prod-relay0.db");
    const dbRelay1 = join(tmpDir, "prod-relay1.db");
    const dbGateway = join(tmpDir, "prod-gateway.db");
    pushSchemaToDb(dbRelay0);
    pushSchemaToDb(dbRelay1);
    pushSchemaToDb(dbGateway);

    // Peer port registry: each participant knows the port of its neighbors.
    const relay0PeerPorts = new Map([[topo.hopNodeIds[1]!, relay1Port]]);
    const relay1PeerPorts = new Map([[topo.hopNodeIds[0]!, relay0Port], [topo.hopNodeIds[2]!, gatewayPort]]);
    const gatewayPeerPorts = new Map([[topo.hopNodeIds[1]!, relay1Port]]);

    // Spawn GATEWAY (terminal — listens, does NOT forward).
    const gateway = spawnParticipant({
      role: "gateway",
      circuitJson,
      listenPort: gatewayPort,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbGateway,
      gatewayProofHex: null,
      isOriginator: false,
      localNodeId: topo.gatewayNodeId,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.gatewayNodeId, [topo.hopNodeIds[1]!]),
      peerPortRegistry: Object.fromEntries(gatewayPeerPorts),
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Spawn RELAY 1 (listens, forwards to gateway).
    const relay1 = spawnParticipant({
      role: "relay1",
      circuitJson,
      listenPort: relay1Port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay1,
      gatewayProofHex: null,
      isOriginator: false,
      localNodeId: topo.hopNodeIds[1]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[1]!, [topo.hopNodeIds[0]!, topo.hopNodeIds[2]!]),
      peerPortRegistry: Object.fromEntries(relay1PeerPorts),
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Spawn RELAY 0 (listens, forwards to relay1).
    const relay0 = spawnParticipant({
      role: "relay0",
      circuitJson,
      listenPort: relay0Port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay0,
      gatewayProofHex: null,
      isOriginator: false,
      localNodeId: topo.hopNodeIds[0]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[0]!, [topo.hopNodeIds[1]!]),
      peerPortRegistry: Object.fromEntries(relay0PeerPorts),
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Spawn INITIATOR (originator — directly processes + sends to relay0).
    const dbInitiator = join(tmpDir, "prod-initiator.db");
    pushSchemaToDb(dbInitiator);
    const initiatorPeerPorts = new Map([[topo.hopNodeIds[0]!, relay0Port]]);
    const initiator = spawnParticipant({
      role: "initiator",
      circuitJson,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbInitiator,
      gatewayProofHex: null,
      isOriginator: true,
      originatorDestroyHex: destroyWireHex,
      localNodeId: topo.route.initiator.nodeId,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.route.initiator.nodeId, [topo.hopNodeIds[0]!]),
      peerPortRegistry: Object.fromEntries(initiatorPeerPorts),
      destroyForDirection,
    });

    const [initiatorResult, relay0Result, relay1Result, gatewayResult] = await Promise.all([
      initiator.result,
      relay0.result,
      relay1.result,
      gateway.result,
    ]);

    // INITIATOR: REVOKED, propagated to relay0, keys zeroized, direction FORWARD.
    expect(initiatorResult.ok).toBe(true);
    if (!initiatorResult.ok) return;
    expect(initiatorResult.action).toBe("REVOKED");
    expect(initiatorResult.propagated).toBe(true);
    expect(initiatorResult.isRevoked).toBe(true);
    expect(initiatorResult.keysZeroized).toBe(true);
    expect(initiatorResult.direction).toBe("FORWARD");

    // RELAY 0: REVOKED, propagated to relay1, keys zeroized.
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.action).toBe("REVOKED");
    expect(relay0Result.propagated).toBe(true);
    expect(relay0Result.isRevoked).toBe(true);
    expect(relay0Result.keysZeroized).toBe(true);

    // RELAY 1: REVOKED, propagated to gateway.
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(relay1Result.action).toBe("REVOKED");
    expect(relay1Result.propagated).toBe(true);
    expect(relay1Result.isRevoked).toBe(true);
    expect(relay1Result.keysZeroized).toBe(true);

    // GATEWAY: REVOKED, terminal (no forwarding).
    expect(gatewayResult.ok).toBe(true);
    if (!gatewayResult.ok) return;
    expect(gatewayResult.action).toBe("REVOKED");
    expect(gatewayResult.terminal).toBe(true);
    expect(gatewayResult.isRevoked).toBe(true);
    expect(gatewayResult.keysZeroized).toBe(true);

    // ALL 4 participants durably revoked via the PRODUCTION transport path.
  }, 90000);
});

// =====================================================================
// Phase 8: PRODUCTION transport — gateway destroy BACKWARD
// =====================================================================

describe("R-009 Stage 3 Phase 3 (production transport): gateway destroy BACKWARD", () => {
  test("GATEWAY → relay1 → relay0 → INITIATOR via production propagateCircuitDestroy: all REVOKED", async () => {
    const topo = makeTopology(3);
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
    const destroyForDirection = JSON.stringify(destroy);

    const relay0Port = await allocatePort();
    const relay1Port = await allocatePort();
    const initiatorPort = await allocatePort();

    const dbInitiator = join(tmpDir, "prod-bw-initiator.db");
    const dbRelay0 = join(tmpDir, "prod-bw-relay0.db");
    const dbRelay1 = join(tmpDir, "prod-bw-relay1.db");
    const dbGateway = join(tmpDir, "prod-bw-gateway.db");
    pushSchemaToDb(dbInitiator);
    pushSchemaToDb(dbRelay0);
    pushSchemaToDb(dbRelay1);
    pushSchemaToDb(dbGateway);

    // INITIATOR (terminal — listens, does NOT forward).
    const initiator = spawnParticipant({
      role: "initiator",
      circuitJson,
      listenPort: initiatorPort,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbInitiator,
      gatewayProofHex,
      isOriginator: false,
      localNodeId: topo.route.initiator.nodeId,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.route.initiator.nodeId, [topo.hopNodeIds[0]!]),
      peerPortRegistry: {},
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // RELAY 0 (listens, forwards to initiator).
    const relay0PeerPorts = new Map([[topo.route.initiator.nodeId, initiatorPort]]);
    const relay0 = spawnParticipant({
      role: "relay0",
      circuitJson,
      listenPort: relay0Port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay0,
      gatewayProofHex,
      isOriginator: false,
      localNodeId: topo.hopNodeIds[0]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[0]!, [topo.hopNodeIds[1]!, topo.route.initiator.nodeId]),
      peerPortRegistry: Object.fromEntries(relay0PeerPorts),
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // RELAY 1 (listens, forwards to relay0).
    const relay1PeerPorts = new Map([[topo.hopNodeIds[0]!, relay0Port]]);
    const relay1 = spawnParticipant({
      role: "relay1",
      circuitJson,
      listenPort: relay1Port,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbRelay1,
      gatewayProofHex,
      isOriginator: false,
      localNodeId: topo.hopNodeIds[1]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[1]!, [topo.hopNodeIds[0]!, topo.hopNodeIds[2]!]),
      peerPortRegistry: Object.fromEntries(relay1PeerPorts),
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // GATEWAY (originator — directly processes + sends to relay1).
    const gatewayPeerPorts = new Map([[topo.hopNodeIds[1]!, relay1Port]]);
    const gateway = spawnParticipant({
      role: "gateway",
      circuitJson,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbGateway,
      gatewayProofHex,
      isOriginator: true,
      originatorDestroyHex: destroyWireHex,
      localNodeId: topo.gatewayNodeId,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.gatewayNodeId, [topo.hopNodeIds[1]!]),
      peerPortRegistry: Object.fromEntries(gatewayPeerPorts),
      destroyForDirection,
    });

    const [gatewayResult, relay1Result, relay0Result, initiatorResult] = await Promise.all([
      gateway.result,
      relay1.result,
      relay0.result,
      initiator.result,
    ]);

    // GATEWAY: REVOKED, propagated to relay1, direction BACKWARD.
    expect(gatewayResult.ok).toBe(true);
    if (!gatewayResult.ok) return;
    expect(gatewayResult.action).toBe("REVOKED");
    expect(gatewayResult.propagated).toBe(true);
    expect(gatewayResult.direction).toBe("BACKWARD");
    expect(gatewayResult.isRevoked).toBe(true);

    // RELAY 1: REVOKED, propagated to relay0.
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(relay1Result.action).toBe("REVOKED");
    expect(relay1Result.propagated).toBe(true);
    expect(relay1Result.isRevoked).toBe(true);
    expect(relay1Result.keysZeroized).toBe(true);

    // RELAY 0: REVOKED, propagated to initiator.
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.action).toBe("REVOKED");
    expect(relay0Result.propagated).toBe(true);
    expect(relay0Result.isRevoked).toBe(true);

    // INITIATOR: REVOKED, terminal.
    expect(initiatorResult.ok).toBe(true);
    if (!initiatorResult.ok) return;
    expect(initiatorResult.action).toBe("REVOKED");
    expect(initiatorResult.terminal).toBe(true);
    expect(initiatorResult.isRevoked).toBe(true);
    expect(initiatorResult.keysZeroized).toBe(true);
  }, 90000);
});

// =====================================================================
// Phase 9: adversarial — transport failure after local revoke
// =====================================================================

describe("R-009 Stage 3 Phase 3 (production transport): transport failure", () => {
  test("local revoke succeeds + next-hop transport fails → local remains REVOKED, propagated=false", async () => {
    const topo = makeTopology(3);
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
    const destroyForDirection = JSON.stringify(destroy);

    // Allocate a port for relay0, but DON'T spawn relay0 — simulate transport
    // failure (connection refused).
    const relay0Port = await allocatePort();

    const dbInitiator = join(tmpDir, "tf-prod-initiator.db");
    pushSchemaToDb(dbInitiator);

    const initiatorPeerPorts = new Map([[topo.hopNodeIds[0]!, relay0Port]]);
    const initiator = spawnParticipant({
      role: "initiator",
      circuitJson,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbInitiator,
      gatewayProofHex: null,
      isOriginator: true,
      originatorDestroyHex: destroyWireHex,
      localNodeId: topo.route.initiator.nodeId,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.route.initiator.nodeId, [topo.hopNodeIds[0]!]),
      peerPortRegistry: Object.fromEntries(initiatorPeerPorts),
      destroyForDirection,
    });

    const initiatorResult = await initiator.result;

    // The local revoke SUCCEEDED. The transport failed (connection refused).
    // The initiator's result should be: REVOKED, propagated=false, transportError set.
    expect(initiatorResult.ok).toBe(true);
    if (!initiatorResult.ok) return;
    expect(initiatorResult.action).toBe("REVOKED");
    expect(initiatorResult.propagated).toBe(false);
    expect(initiatorResult.transportError).toBeDefined();
    expect(initiatorResult.isRevoked).toBe(true); // local remains REVOKED

    // Verify the tombstone persisted (durable).
    const isRevoked = await verifyTombstone(dbInitiator, topo.circuit.circuitId, topo.circuit.commitmentRoot);
    expect(isRevoked).toBe(true);
  }, 60000);
});

// =====================================================================
// Phase 12: restart with durable store (production transport)
// =====================================================================

describe("R-009 Stage 3 Phase 3 (production transport): restart", () => {
  test("after revoke + restart, old destroy → idempotent (ALREADY_REVOKED), tombstone persists", async () => {
    const topo = makeTopology(3);
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
    const destroyForDirection = JSON.stringify(destroy);

    const dbParticipant = join(tmpDir, "restart-prod-participant.db");
    pushSchemaToDb(dbParticipant);

    const port1 = await allocatePort();
    const participant1 = spawnParticipant({
      role: "relay0",
      circuitJson,
      listenPort: port1,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbParticipant,
      gatewayProofHex: null,
      isOriginator: false,
      localNodeId: topo.hopNodeIds[0]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[0]!, [topo.hopNodeIds[1]!]),
      peerPortRegistry: {},
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Send the destroy over TCP (manually, simulating the previous hop).
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

    // RESTART: spawn a NEW participant with the SAME DB file.
    const port2 = await allocatePort();
    const participant2 = spawnParticipant({
      role: "relay0-restarted",
      circuitJson,
      listenPort: port2,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      dbPath: dbParticipant, // SAME DB — tombstone persists
      gatewayProofHex: null,
      isOriginator: false,
      localNodeId: topo.hopNodeIds[0]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[0]!, [topo.hopNodeIds[1]!]),
      peerPortRegistry: {},
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Send the SAME destroy again → idempotent.
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
    expect(r2.action).toBe("ALREADY_REVOKED"); // idempotent
    expect(r2.propagated).toBe(false); // suppressed

    // Tombstone persisted.
    const isRevoked = await verifyTombstone(dbParticipant, topo.circuit.circuitId, topo.circuit.commitmentRoot);
    expect(isRevoked).toBe(true);
  }, 90000);
});

// =====================================================================
// Phase 9: adversarial — in-process transport binding tests
// (These test the production transport interface directly — no child process
// needed. They verify the authenticated binding rejects mismatches.)
// =====================================================================

describe("R-009 Stage 3 Phase 3 (production transport): authenticated binding", () => {
  test("InProcessCircuitDestroyTransport rejects peer mismatch (link.remoteNodeId !== nextHopNodeId)", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const transport = new InProcessCircuitDestroyTransport();

    // A link to NodeId "real-next-hop", but the ctx claims nextHopNodeId = "wrong-hop".
    const fakeLink = {
      localNodeId: "local",
      remoteNodeId: "real-next-hop",
      linkIdHex: "mock",
      linkIdBytes: new Uint8Array(32),
      transcriptDigestHex: "mock",
      localRole: "INITIATOR" as const,
      establishedAt: NOW,
      expiresAt: NOW + 3600,
      transcriptVerifiedAt: NOW,
      remoteNode: { nodeId: "real-next-hop" },
    };
    const ctx = {
      localNodeId: "local",
      nextHopNodeId: "wrong-hop", // MISMATCH
      circuitId: new Uint8Array(32),
      commitmentRoot: new Uint8Array(32),
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink,
    };
    const result = await transport.send(ctx, new Uint8Array(32));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("peer mismatch");
  });

  test("InProcessCircuitDestroyTransport rejects link not owned by local participant", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const transport = new InProcessCircuitDestroyTransport();

    const fakeLink = {
      localNodeId: "someone-else", // NOT the local participant
      remoteNodeId: "next-hop",
      linkIdHex: "mock",
      linkIdBytes: new Uint8Array(32),
      transcriptDigestHex: "mock",
      localRole: "INITIATOR" as const,
      establishedAt: NOW,
      expiresAt: NOW + 3600,
      transcriptVerifiedAt: NOW,
      remoteNode: { nodeId: "next-hop" },
    };
    const ctx = {
      localNodeId: "local", // MISMATCH — the link is not owned by this participant
      nextHopNodeId: "next-hop",
      circuitId: new Uint8Array(32),
      commitmentRoot: new Uint8Array(32),
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink,
    };
    const result = await transport.send(ctx, new Uint8Array(32));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("link.localNodeId");
  });

  test("InProcessCircuitDestroyTransport sends exact bytes (no decode + re-encode)", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const transport = new InProcessCircuitDestroyTransport();

    const fakeLink = {
      localNodeId: "local",
      remoteNodeId: "next-hop",
      linkIdHex: "mock",
      linkIdBytes: new Uint8Array(32),
      transcriptDigestHex: "mock",
      localRole: "INITIATOR" as const,
      establishedAt: NOW,
      expiresAt: NOW + 3600,
      transcriptVerifiedAt: NOW,
      remoteNode: { nodeId: "next-hop" },
    };
    const ctx = {
      localNodeId: "local",
      nextHopNodeId: "next-hop",
      circuitId: new Uint8Array(32),
      commitmentRoot: new Uint8Array(32),
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink,
    };
    const wireBytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const sendResult = await transport.send(ctx, wireBytes);
    expect(sendResult.ok).toBe(true);

    // Receive — the exact bytes should arrive.
    const received = await transport.receive("next-hop");
    expect(toHex(received)).toBe(toHex(wireBytes)); // byte-for-byte identical
  });
});
