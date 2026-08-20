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
import { signPropagationChannelProof, encodePropagationChannelProof } from "@reference/circuit/propagation";

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
const { propagateCircuitDestroy, receiveAuthenticatedCircuitDestroy, TopologyNextHopResolver, propagationDirection } = require("${join(process.cwd(), "reference/circuit/propagation.ts").replace(/\\/g, "\\\\")}");
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

  // The DurableSqliteCircuitDestroyStore uses the app-global db (which reads
  // DATABASE_URL from the env). In the child process, the "@/lib/db" alias
  // does NOT resolve via bun -e — so we construct a PrismaClient directly
  // + pass it to the store constructor.
  const { PrismaClient } = require("@prisma/client");
  const prisma = new PrismaClient();
  const destroyStore = new DurableSqliteCircuitDestroyStore(prisma);
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
    const senderSk = Buffer.from(config.senderEd25519SecretKeyHex, "hex");
    const senderPk = Buffer.from(config.senderEd25519PublicKeyHex, "hex");
    const result = await propagateCircuitDestroy(
      wireBytes, activeCircuit,
      config.localNodeId,
      config.expectedInitiatorNodeId, config.expectedGatewayNodeId,
      destroyStore, config.now,
      resolver, transport,
      senderSk, senderPk,
      gatewayProofBytes,
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

  // CANONICAL PRODUCTION RECEIVE: receiveAuthenticatedCircuitDestroy owns
  // the FULL receive pipeline:
  //   transport.receive() → proof+digest verification → decode → verify
  //   CircuitDestroy → derive direction from signed destroyerRole → verify
  //   proof.direction === derived direction → return authenticated destroy.
  // The caller CANNOT obtain an authenticated destroy while direction
  // remains unchecked — this function owns the direction check.
  const receiveResult = await receiveAuthenticatedCircuitDestroy(transport, {
    localNodeId: config.localNodeId,
    expectedRemoteNodeId: config.expectedRemoteNodeId,
    circuitId: activeCircuit.circuitId,
    commitmentRoot: activeCircuit.commitmentRoot,
  });
  if (!receiveResult.ok) {
    process.stdout.write(JSON.stringify({ ok: false, reason: "receive authentication failed: " + receiveResult.reason }));
    await transport.stop();
    process.exit(0);
    return;
  }
  const wireBytes = receiveResult.wireBytes;

  // Call the PRODUCTION propagateCircuitDestroy (owns process + resolve + send).
  const senderSk = Buffer.from(config.senderEd25519SecretKeyHex, "hex");
  const senderPk = Buffer.from(config.senderEd25519PublicKeyHex, "hex");
  const result = await propagateCircuitDestroy(
    wireBytes, activeCircuit,
    config.localNodeId,
    config.expectedInitiatorNodeId, config.expectedGatewayNodeId,
    destroyStore, config.now,
    resolver, transport,
    senderSk, senderPk,
    gatewayProofBytes,
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
      expectedRemoteNodeId: topo.hopNodeIds[1]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.gatewayNodeId, [topo.hopNodeIds[1]!]),
      peerPortRegistry: Object.fromEntries(gatewayPeerPorts),
      senderEd25519SecretKeyHex: toHex(topo.gatewayKp.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.gatewayKp.publicKey),
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
      expectedRemoteNodeId: topo.hopNodeIds[0]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[1]!, [topo.hopNodeIds[0]!, topo.hopNodeIds[2]!]),
      peerPortRegistry: Object.fromEntries(relay1PeerPorts),
      senderEd25519SecretKeyHex: toHex(topo.route.kps[1]!.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.route.kps[1]!.publicKey),
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
      expectedRemoteNodeId: topo.route.initiator.nodeId,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[0]!, [topo.hopNodeIds[1]!]),
      peerPortRegistry: Object.fromEntries(relay0PeerPorts),
      senderEd25519SecretKeyHex: toHex(topo.route.kps[0]!.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.route.kps[0]!.publicKey),
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
      expectedRemoteNodeId: topo.route.initiator.nodeId, // placeholder — originator does not receive
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.route.initiator.nodeId, [topo.hopNodeIds[0]!]),
      peerPortRegistry: Object.fromEntries(initiatorPeerPorts),
      senderEd25519SecretKeyHex: toHex(topo.initiatorKp.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.initiatorKp.publicKey),
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
      expectedRemoteNodeId: topo.hopNodeIds[0]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.route.initiator.nodeId, [topo.hopNodeIds[0]!]),
      peerPortRegistry: {},
      senderEd25519SecretKeyHex: toHex(topo.initiatorKp.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.initiatorKp.publicKey),
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
      expectedRemoteNodeId: topo.hopNodeIds[1]!,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[0]!, [topo.hopNodeIds[1]!, topo.route.initiator.nodeId]),
      peerPortRegistry: Object.fromEntries(relay0PeerPorts),
      senderEd25519SecretKeyHex: toHex(topo.route.kps[0]!.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.route.kps[0]!.publicKey),
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
      expectedRemoteNodeId: topo.gatewayNodeId,
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[1]!, [topo.hopNodeIds[0]!, topo.hopNodeIds[2]!]),
      peerPortRegistry: Object.fromEntries(relay1PeerPorts),
      senderEd25519SecretKeyHex: toHex(topo.route.kps[1]!.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.route.kps[1]!.publicKey),
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
      expectedRemoteNodeId: topo.gatewayNodeId, // placeholder — originator does not receive
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.gatewayNodeId, [topo.hopNodeIds[1]!]),
      peerPortRegistry: Object.fromEntries(gatewayPeerPorts),
      senderEd25519SecretKeyHex: toHex(topo.gatewayKp.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.gatewayKp.publicKey),
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
      expectedRemoteNodeId: topo.route.initiator.nodeId, // placeholder — originator does not receive
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.route.initiator.nodeId, [topo.hopNodeIds[0]!]),
      peerPortRegistry: Object.fromEntries(initiatorPeerPorts),
      senderEd25519SecretKeyHex: toHex(topo.initiatorKp.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.initiatorKp.publicKey),
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
      expectedRemoteNodeId: topo.route.initiator.nodeId, // initiator sends to relay0
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[0]!, [topo.hopNodeIds[1]!]),
      peerPortRegistry: {},
      senderEd25519SecretKeyHex: toHex(topo.route.kps[0]!.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.route.kps[0]!.publicKey),
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Build the PropagationChannelProof (signed by the initiator — the
    // previous hop in the FORWARD direction) + the destroy wire bytes in
    // the production wire format: [4 bytes proof len][proof]
    // [4 bytes destroy len][destroy]. The receiver (relay0) verifies the
    // proof against its expectedRemoteNodeId + circuit context before
    // delivering the destroy to propagateCircuitDestroy().
    const { connect } = await import("node:net");
    const buildProofAndWireBytes = (): Buffer => {
      const wireBytes = Buffer.from(encodeCircuitDestroy(destroy));
      const proof = signPropagationChannelProof(
        topo.route.initiator.nodeId, // senderNodeId (the previous hop)
        topo.hopNodeIds[0]!, // receiverNodeId (relay0)
        topo.circuit.circuitId, topo.circuit.commitmentRoot, "FORWARD",
        wireBytes, // hash the EXACT destroy bytes
        topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
      );
      const proofBytes = Buffer.from(encodePropagationChannelProof(proof));
      const proofLenBuf = Buffer.alloc(4);
      proofLenBuf.writeUInt32BE(proofBytes.length, 0);
      const destroyLenBuf = Buffer.alloc(4);
      destroyLenBuf.writeUInt32BE(wireBytes.length, 0);
      return Buffer.concat([proofLenBuf, proofBytes, destroyLenBuf, wireBytes]);
    };
    const proofAndWireBytes = buildProofAndWireBytes();

    // Send the destroy over TCP (manually, simulating the previous hop).
    await new Promise<void>((resolve, reject) => {
      const sock = connect(port1, "127.0.0.1", () => {
        sock.write(proofAndWireBytes);
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
      expectedRemoteNodeId: topo.route.initiator.nodeId, // initiator sends to relay0
      hopNodeIds: topo.hopNodeIds,
      links: buildLinks(topo.hopNodeIds[0]!, [topo.hopNodeIds[1]!]),
      peerPortRegistry: {},
      senderEd25519SecretKeyHex: toHex(topo.route.kps[0]!.secretKey),
      senderEd25519PublicKeyHex: toHex(topo.route.kps[0]!.publicKey),
      destroyForDirection,
    });
    await new Promise((r) => setTimeout(r, 400));

    // Send the SAME destroy again → idempotent. Reuse the same proof bytes
    // (the proof is signed by the initiator and is valid for the same
    // circuit + direction context).
    await new Promise<void>((resolve, reject) => {
      const sock = connect(port2, "127.0.0.1", () => {
        sock.write(proofAndWireBytes);
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
  // Helper: generate a real Ed25519 keypair for the test sender.
  async function makeSenderKey() {
    const { generateNodeKeypair } = await import("@reference/identity/keys");
    return generateNodeKeypair();
  }

  // Helper: build a fake AuthenticatedLink (plain object — NOT a genuine
  // WeakSet-registered link). The transport verifies the link binding by
  // field value (localNodeId, remoteNodeId), NOT by WeakSet membership.
  // The cryptographic authentication comes from the PropagationChannelProof
  // (signed by the sender's Ed25519 key), not from the link object itself.
  function fakeLink(localNodeId: string, remoteNodeId: string) {
    return {
      localNodeId, remoteNodeId,
      linkIdHex: "mock", linkIdBytes: new Uint8Array(32),
      transcriptDigestHex: "mock", localRole: "INITIATOR" as const,
      establishedAt: NOW, expiresAt: NOW + 3600, transcriptVerifiedAt: NOW,
      remoteNode: { nodeId: remoteNodeId },
    };
  }

  test("InProcessCircuitDestroyTransport rejects peer mismatch (link.remoteNodeId !== nextHopNodeId)", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const transport = new InProcessCircuitDestroyTransport();
    const senderKp = await makeSenderKey();

    // A link to NodeId "real-next-hop", but the ctx claims nextHopNodeId = "wrong-hop".
    const ctx = {
      localNodeId: "local",
      nextHopNodeId: "wrong-hop", // MISMATCH
      circuitId: new Uint8Array(32),
      commitmentRoot: new Uint8Array(32),
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink("local", "real-next-hop"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    };
    const result = await transport.send(ctx, new Uint8Array(32));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("peer mismatch");
  });

  test("InProcessCircuitDestroyTransport rejects link not owned by local participant", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const transport = new InProcessCircuitDestroyTransport();
    const senderKp = await makeSenderKey();

    const ctx = {
      localNodeId: "local", // MISMATCH — the link is owned by "someone-else"
      nextHopNodeId: "next-hop",
      circuitId: new Uint8Array(32),
      commitmentRoot: new Uint8Array(32),
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink("someone-else", "next-hop"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    };
    const result = await transport.send(ctx, new Uint8Array(32));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("link.localNodeId");
  });

  test("InProcessCircuitDestroyTransport sends exact bytes + receiver authenticates (correct peer + correct circuit)", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const transport = new InProcessCircuitDestroyTransport();
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;

    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);
    // Sign a REAL CircuitDestroy (the transport now decodes + verifies it).
    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);
    const ctx = {
      localNodeId: senderNodeId,
      nextHopNodeId: "receiver",
      circuitId, commitmentRoot,
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    };
    const sendResult = await transport.send(ctx, wireBytes);
    expect(sendResult.ok).toBe(true);

    // Receive — the transport OWNS the full verification (proof + digest +
    // decode + verify + direction). Correct peer + correct circuit + correct
    // direction → ACCEPT.
    const received = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(received.ok).toBe(true);
    if (!received.ok) return;
    expect(toHex(received.wireBytes)).toBe(toHex(wireBytes)); // byte-for-byte identical
    expect(received.direction).toBe("FORWARD");
  });

  test("receiver REJECTS wrong peer (senderNodeId !== expectedRemoteNodeId)", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const transport = new InProcessCircuitDestroyTransport();
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;

    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);
    const ctx = {
      localNodeId: senderNodeId,
      nextHopNodeId: "receiver",
      circuitId, commitmentRoot,
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    };
    await transport.send(ctx, new Uint8Array(32));

    // Receiver expects a DIFFERENT peer → REJECT.
    const received = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: "wrong-peer", // MISMATCH
      circuitId, commitmentRoot,
    });
    expect(received.ok).toBe(false);
    if (!received.ok) expect(received.reason).toContain("wrong peer");
  });

  test("receiver REJECTS wrong circuit context (circuitId mismatch)", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const transport = new InProcessCircuitDestroyTransport();
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;

    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);
    const ctx = {
      localNodeId: senderNodeId,
      nextHopNodeId: "receiver",
      circuitId, commitmentRoot,
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    };
    await transport.send(ctx, new Uint8Array(32));

    // Receiver expects a DIFFERENT circuitId → REJECT.
    const received = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId: new Uint8Array(32).fill(0xff), // MISMATCH
      commitmentRoot,
    });
    expect(received.ok).toBe(false);
    if (!received.ok) expect(received.reason).toContain("wrong circuit context");
  });

  test("receiver REJECTS wrong commitmentRoot (route mismatch)", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const transport = new InProcessCircuitDestroyTransport();
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;

    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);
    const ctx = {
      localNodeId: senderNodeId,
      nextHopNodeId: "receiver",
      circuitId, commitmentRoot,
      direction: "FORWARD" as const,
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    };
    await transport.send(ctx, new Uint8Array(32));

    // Receiver expects a DIFFERENT commitmentRoot → REJECT.
    const received = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId,
      commitmentRoot: new Uint8Array(32).fill(0xff), // MISMATCH
    });
    expect(received.ok).toBe(false);
    if (!received.ok) expect(received.reason).toContain("wrong route context");
  });

  test("receiver REJECTS forged PropagationChannelProof (wrong signature)", async () => {
    const { InProcessCircuitDestroyTransport, signPropagationChannelProof, verifyPropagationChannelProof } = await import("@reference/circuit/propagation");
    const senderKp = await makeSenderKey();
    const attackerKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;

    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);
    const fakeWireBytes = new Uint8Array([1, 2, 3, 4, 5]);

    // FORGE: sign the proof with the ATTACKER's key, but claim the sender's NodeId.
    // The verifyNodeIdBinding check catches this (attacker's key doesn't derive
    // the sender's NodeId).
    const forgedProof = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "FORWARD",
      fakeWireBytes,
      attackerKp.secretKey, attackerKp.publicKey, // attacker's key
    );
    const result = verifyPropagationChannelProof(forgedProof);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("identity binding failed");
  });

  test("receiver REJECTS copied PropagationChannelProof from a different circuit", async () => {
    const { signPropagationChannelProof, verifyIncomingPropagationChannelProof } = await import("@reference/circuit/propagation");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;

    // A proof for circuit A.
    const circuitAId = new Uint8Array(32).fill(0xab);
    const commitmentRootA = new Uint8Array(32).fill(0xcd);
    const wireBytesA = new Uint8Array([1, 2, 3, 4, 5]);
    const proofA = signPropagationChannelProof(
      senderNodeId, "receiver", circuitAId, commitmentRootA, "FORWARD",
      wireBytesA,
      senderKp.secretKey, senderKp.publicKey,
    );

    // The receiver expects circuit B → the proof from circuit A is a "copied"
    // proof. The circuitId binding check catches this.
    const circuitBId = new Uint8Array(32).fill(0xff);
    const commitmentRootB = new Uint8Array(32).fill(0xee);
    const result = verifyIncomingPropagationChannelProof(proofA, {
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId: circuitBId, // MISMATCH — expects circuit B
      commitmentRoot: commitmentRootB,
    }, wireBytesA);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("wrong circuit context");
  });

  // ---- destroyDigest adversarial tests (Fix #1) ----

  test("receiver REJECTS destroy substitution (proof for destroy A, different destroy B delivered)", async () => {
    const { signPropagationChannelProof, verifyIncomingPropagationChannelProof } = await import("@reference/circuit/propagation");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    // Proof signed over destroy A's bytes.
    const wireBytesA = new Uint8Array([1, 2, 3, 4, 5]);
    const proofA = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "FORWARD",
      wireBytesA, senderKp.secretKey, senderKp.publicKey,
    );

    // But deliver destroy B's bytes → the destroyDigest check catches this.
    const wireBytesB = new Uint8Array([9, 8, 7, 6, 5]);
    const result = verifyIncomingPropagationChannelProof(proofA, {
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    }, wireBytesB); // DIFFERENT bytes → digest mismatch
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("destroy substitution detected");
  });

  test("receiver REJECTS destroy byte mutation (one byte flipped)", async () => {
    const { signPropagationChannelProof, verifyIncomingPropagationChannelProof } = await import("@reference/circuit/propagation");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    const wireBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const proof = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "FORWARD",
      wireBytes, senderKp.secretKey, senderKp.publicKey,
    );

    // Flip one byte → the digest changes → mismatch.
    const mutatedWireBytes = new Uint8Array([...wireBytes]);
    mutatedWireBytes[0] ^= 0x01;
    const result = verifyIncomingPropagationChannelProof(proof, {
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    }, mutatedWireBytes);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("destroy substitution detected");
  });

  test("receiver REJECTS destroyDigest mutation (proof's digest does not match the bytes)", async () => {
    const { signPropagationChannelProof, verifyPropagationChannelProof, computeDestroyDigest } = await import("@reference/circuit/propagation");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    const wireBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const proof = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "FORWARD",
      wireBytes, senderKp.secretKey, senderKp.publicKey,
    );

    // Tamper the destroyDigest → the signature check catches this (the digest
    // is covered by the signature).
    const tamperedProof = { ...proof, destroyDigest: new Uint8Array(32).fill(0xff) };
    const result = verifyPropagationChannelProof(tamperedProof);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("receiver REJECTS proof signature mutation", async () => {
    const { signPropagationChannelProof, verifyPropagationChannelProof } = await import("@reference/circuit/propagation");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);
    const wireBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const proof = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "FORWARD",
      wireBytes, senderKp.secretKey, senderKp.publicKey,
    );

    // Flip a byte in the signature → invalid.
    const tamperedProof = { ...proof, signature: new Uint8Array([...proof.signature]) };
    tamperedProof.signature[0] ^= 0x01;
    const result = verifyPropagationChannelProof(tamperedProof);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  // ---- direction adversarial tests (Fix #2) ----

  test("receiver REJECTS opposite proof direction (BACKWARD proof for FORWARD destroy)", async () => {
    const { signPropagationChannelProof, verifyPropagationDirection } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    // Sign an INITIATOR destroy (direction = FORWARD) + sign a BACKWARD proof.
    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600,
      senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);
    const proof = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "BACKWARD", // WRONG direction
      wireBytes, senderKp.secretKey, senderKp.publicKey,
    );

    // The direction check: proof.direction (BACKWARD) !== derived (FORWARD).
    const result = verifyPropagationDirection(proof, destroy);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });

  test("receiver ACCEPTS correct direction (FORWARD proof for FORWARD destroy)", async () => {
    const { signPropagationChannelProof, verifyPropagationDirection } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600,
      senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);
    const proof = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "FORWARD", // CORRECT
      wireBytes, senderKp.secretKey, senderKp.publicKey,
    );
    const result = verifyPropagationDirection(proof, destroy);
    expect(result.ok).toBe(true);
  });

  test("receiver REJECTS mutated proof direction (FORWARD proof, BACKWARD destroy)", async () => {
    const { signPropagationChannelProof, verifyPropagationDirection } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, DESTROYER_ROLE_GATEWAY, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    // Sign a GATEWAY destroy (direction = BACKWARD).
    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_GATEWAY, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600,
      senderKp.secretKey, senderKp.publicKey,
    );

    // Mutate the proof's direction to FORWARD (contradicts the signed destroy).
    const proof = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "FORWARD", // WRONG
      new Uint8Array([1, 2, 3]), senderKp.secretKey, senderKp.publicKey,
    );

    // The direction check: proof.direction (FORWARD) !== derived (BACKWARD).
    const result = verifyPropagationDirection(proof, destroy);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });

  // ---- PRODUCTION receiveAuthenticatedCircuitDestroy direction tests ----
  // These tests prove the PRODUCTION receive function (not the test) enforces
  // direction. The test does NOT call verifyPropagationDirection directly.

  test("PRODUCTION receiveAuthenticatedCircuitDestroy ACCEPTS correct FORWARD direction", async () => {
    const { InProcessCircuitDestroyTransport, signPropagationChannelProof, receiveAuthenticatedCircuitDestroy } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // Send via the InProcess transport (signs the proof with FORWARD direction).
    const transport = new InProcessCircuitDestroyTransport();
    const sendResult = await transport.send({
      localNodeId: senderNodeId,
      nextHopNodeId: "receiver",
      circuitId, commitmentRoot,
      direction: "FORWARD",
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);
    expect(sendResult.ok).toBe(true);

    // PRODUCTION receive — owns direction verification internally.
    const result = await receiveAuthenticatedCircuitDestroy(transport, {
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.direction).toBe("FORWARD");
  });

  test("PRODUCTION receiveAuthenticatedCircuitDestroy REJECTS BACKWARD proof + FORWARD destroy", async () => {
    const { InProcessCircuitDestroyTransport, signPropagationChannelProof, receiveAuthenticatedCircuitDestroy } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    // Sign an INITIATOR destroy (direction = FORWARD).
    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // But send with a BACKWARD proof (contradicts the FORWARD destroy).
    // Manually construct the proof with the WRONG direction.
    const transport = new InProcessCircuitDestroyTransport();
    const proof = signPropagationChannelProof(
      senderNodeId, "receiver", circuitId, commitmentRoot, "BACKWARD", // WRONG
      wireBytes, senderKp.secretKey, senderKp.publicKey,
    );
    // Manually enqueue (bypass send which would use the ctx.direction).
    // Access the private queue via the send method with a different ctx,
    // then manually overwrite... Actually, the InProcess send uses ctx.direction.
    // To inject a wrong-direction proof, we need to call send with direction="BACKWARD"
    // but the wireBytes are for a FORWARD destroy. The transport doesn't verify
    // direction on send (only on receive). So:
    const sendResult = await transport.send({
      localNodeId: senderNodeId,
      nextHopNodeId: "receiver",
      circuitId, commitmentRoot,
      direction: "BACKWARD" as any, // WRONG — contradicts the destroy
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);
    expect(sendResult.ok).toBe(true);

    // PRODUCTION receive — the direction mismatch is caught HERE (not by the test).
    const result = await receiveAuthenticatedCircuitDestroy(transport, {
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });

  test("PRODUCTION receiveAuthenticatedCircuitDestroy REJECTS FORWARD proof + BACKWARD destroy", async () => {
    const { InProcessCircuitDestroyTransport, signPropagationChannelProof, receiveAuthenticatedCircuitDestroy } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_GATEWAY, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    // Sign a GATEWAY destroy (direction = BACKWARD).
    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_GATEWAY, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // Send with a FORWARD proof (contradicts the BACKWARD destroy).
    const transport = new InProcessCircuitDestroyTransport();
    const sendResult = await transport.send({
      localNodeId: senderNodeId,
      nextHopNodeId: "receiver",
      circuitId, commitmentRoot,
      direction: "FORWARD" as any, // WRONG
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);
    expect(sendResult.ok).toBe(true);

    // PRODUCTION receive rejects.
    const result = await receiveAuthenticatedCircuitDestroy(transport, {
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });

  test("PRODUCTION receiveAuthenticatedCircuitDestroy REJECTS same-circuit opposite-direction proof", async () => {
    // Same circuit (same circuitId + commitmentRoot), but the proof's direction
    // contradicts the destroy's direction. This is a targeted attack: an
    // attacker with a valid proof for the BACKWARD direction tries to attach it
    // to a FORWARD destroy (or vice versa).
    const { InProcessCircuitDestroyTransport, receiveAuthenticatedCircuitDestroy } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    // FORWARD destroy.
    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    // Send with BACKWARD direction (same circuit, opposite direction).
    const transport = new InProcessCircuitDestroyTransport();
    const sendResult = await transport.send({
      localNodeId: senderNodeId,
      nextHopNodeId: "receiver",
      circuitId, commitmentRoot,
      direction: "BACKWARD" as any,
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);
    expect(sendResult.ok).toBe(true);

    // PRODUCTION receive rejects — same circuit, but the direction contradicts
    // the signed destroyerRole.
    const result = await receiveAuthenticatedCircuitDestroy(transport, {
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });

  // ---- REGRESSION: transport.receive() DIRECTLY enforces direction ----
  // These tests invoke transport.receive() DIRECTLY — NOT via
  // receiveAuthenticatedCircuitDestroy(). They prove the LOWEST public
  // production receive boundary itself rejects direction mismatch.

  test("REGRESSION transport.receive() DIRECTLY ACCEPTS correct FORWARD direction", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const transport = new InProcessCircuitDestroyTransport();
    await transport.send({
      localNodeId: senderNodeId, nextHopNodeId: "receiver",
      circuitId, commitmentRoot, direction: "FORWARD",
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);

    // Call transport.receive() DIRECTLY — NOT receiveAuthenticatedCircuitDestroy().
    const result = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.direction).toBe("FORWARD");
  });

  test("REGRESSION transport.receive() DIRECTLY REJECTS BACKWARD proof + FORWARD destroy", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const transport = new InProcessCircuitDestroyTransport();
    await transport.send({
      localNodeId: senderNodeId, nextHopNodeId: "receiver",
      circuitId, commitmentRoot, direction: "BACKWARD" as any, // WRONG
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);

    // Call transport.receive() DIRECTLY — the direction mismatch is caught
    // INSIDE receive(), not by a caller-side check.
    const result = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });

  test("REGRESSION transport.receive() DIRECTLY REJECTS FORWARD proof + BACKWARD destroy", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_GATEWAY, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_GATEWAY, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const transport = new InProcessCircuitDestroyTransport();
    await transport.send({
      localNodeId: senderNodeId, nextHopNodeId: "receiver",
      circuitId, commitmentRoot, direction: "FORWARD" as any, // WRONG
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);

    // Call transport.receive() DIRECTLY — direction mismatch caught inside.
    const result = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });

  test("REGRESSION transport.receive() DIRECTLY REJECTS same-circuit opposite direction", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const transport = new InProcessCircuitDestroyTransport();
    await transport.send({
      localNodeId: senderNodeId, nextHopNodeId: "receiver",
      circuitId, commitmentRoot, direction: "BACKWARD" as any, // opposite
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);

    // Call transport.receive() DIRECTLY.
    const result = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });

  test("REGRESSION transport.receive() DIRECTLY REJECTS mutated proof.direction", async () => {
    const { InProcessCircuitDestroyTransport } = await import("@reference/circuit/propagation");
    const { signCircuitDestroy, encodeCircuitDestroy, DESTROYER_ROLE_GATEWAY, DESTROY_REASON_OPERATOR_INITIATED } = await import("@reference/circuit/destroy");
    const senderKp = await makeSenderKey();
    const senderNodeId = senderKp.nodeId;
    const circuitId = new Uint8Array(32).fill(0xab);
    const commitmentRoot = new Uint8Array(32).fill(0xcd);

    // GATEWAY destroy (direction = BACKWARD).
    const destroy = signCircuitDestroy(
      circuitId, commitmentRoot, senderNodeId,
      DESTROYER_ROLE_GATEWAY, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, NOW + 3600, senderKp.secretKey, senderKp.publicKey,
    );
    const wireBytes = encodeCircuitDestroy(destroy);

    const transport = new InProcessCircuitDestroyTransport();
    // Send with FORWARD direction (mutated — contradicts the BACKWARD destroy).
    await transport.send({
      localNodeId: senderNodeId, nextHopNodeId: "receiver",
      circuitId, commitmentRoot, direction: "FORWARD" as any, // mutated
      authenticatedLink: fakeLink(senderNodeId, "receiver"),
      senderEd25519SecretKey: senderKp.secretKey,
      senderEd25519PublicKey: senderKp.publicKey,
    }, wireBytes);

    // Call transport.receive() DIRECTLY — catches the mutated direction.
    const result = await transport.receive({
      localNodeId: "receiver",
      expectedRemoteNodeId: senderNodeId,
      circuitId, commitmentRoot,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("direction mismatch");
  });
});
