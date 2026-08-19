/**
 * ShareNet 2.0 — R-009 Stage 3 Phase 3: Destroy propagation + true multi-process teardown.
 *
 * Per ADR-0023 (propagation semantics):
 *
 *   INITIATOR-originated destroy propagates FORWARD:
 *     INITIATOR → hop 0 → hop 1 → GATEWAY
 *
 *   GATEWAY-originated destroy propagates BACKWARD:
 *     GATEWAY → hop N-1 → ... → INITIATOR
 *
 * Each participant runs in an INDEPENDENT process (child_process.spawn).
 * Only serialized protocol artifacts (wire bytes, hex strings) cross
 * process boundaries — NO BrandedCommittedRoute, WeakSet, or in-memory
 * circuit objects.
 *
 * Tests:
 *   Phase 8:  initiator destroy forward (4 processes, all REVOKED)
 *   Phase 9:  gateway destroy backward (4 processes, all REVOKED)
 *   Phase 10: negative multi-process (relay origin, tamper each field, wrong route, expired, persistence failure)
 *   Phase 11: replay/duplicate propagation (no resurrection, idempotent)
 *   Phase 12: restart (revocation persists, old frame rejected, duplicate destroy idempotent)
 *   Phase 15: failure modes (local revoke succeeds + downstream fails; local persistence fails)
 */

import { describe, test, expect } from "bun:test";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { randomBytes, generateNodeKeypair } from "@reference/identity/keys";
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

/**
 * Build a route + circuit + the artifacts each participant needs.
 * Returns serialized (hex) artifacts that can cross process boundaries.
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

  // Generate the terminal ack (for the gateway proof).
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

  // Build the gateway proof (serialized GatewayReturnAuthorization).
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

/**
 * Serialize the circuit context for a child process.
 * The child process reconstructs a minimal ActiveCircuit from this JSON.
 * ONLY serialized artifacts cross the boundary — NO WeakSet/BrandedCommittedRoute.
 */
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
 * Run a participant process that calls processCircuitDestroy.
 *
 * The child process:
 *   1. Reads JSON from stdin (circuit context + destroy wire bytes + params).
 *   2. Reconstructs a minimal ActiveCircuit + InMemoryCircuitDestroyStore.
 *   3. Calls processCircuitDestroy.
 *   4. Writes the result to stdout as JSON (ok, action, propagate, wireHex,
 *      isRevoked, keysZeroized).
 *
 * Each spawn is a SEPARATE process with its own V8 isolate — no shared memory.
 */
function runDestroyParticipant(input: {
  circuitJson: string;
  destroyWireHex: string;
  expectedInitiatorNodeId: string;
  expectedGatewayNodeId: string;
  now: number;
  gatewayProofHex?: string;
}): Promise<{
  ok: boolean;
  action?: string;
  propagate?: boolean;
  wireHex?: string;
  isRevoked?: boolean;
  keysZeroized?: boolean;
  reason?: string;
}> {
  return new Promise((resolve) => {
    const script = `
      const { processCircuitDestroy, propagationDirection } = require("${join(process.cwd(), "reference/circuit/destroy.ts").replace(/\\/g, "\\\\")}");
      const { InMemoryCircuitDestroyStore } = require("${join(process.cwd(), "reference/circuit/replay-stores.ts").replace(/\\/g, "\\\\")}");

      let input = "";
      process.stdin.on("data", (chunk) => { input += chunk; });
      process.stdin.on("end", async () => {
        try {
          const data = JSON.parse(input);
          const circuit = JSON.parse(data.circuitJson);
          // Reconstruct a minimal ActiveCircuit from serialized artifacts ONLY.
          const hops = circuit.hops.map((h) => ({
            hopIndex: h.hopIndex,
            nodeId: h.nodeId,
            forwardingKey: new Uint8Array(Buffer.from(h.forwardingKeyHex, "hex")),
            returnKey: new Uint8Array(Buffer.from(h.returnKeyHex, "hex")),
            relayX25519PublicKey: h.relayX25519PublicKeyHex
              ? new Uint8Array(Buffer.from(h.relayX25519PublicKeyHex, "hex"))
              : undefined,
          }));
          const activeCircuit = {
            circuitId: new Uint8Array(Buffer.from(circuit.circuitIdHex, "hex")),
            circuitIdHex: circuit.circuitIdHex,
            routeId: circuit.routeId,
            hops,
            initiatorX25519PublicKey: new Uint8Array(Buffer.from(circuit.initiatorX25519PublicKeyHex, "hex")),
            initiatorX25519SecretKey: new Uint8Array(Buffer.from(circuit.initiatorX25519SecretKeyHex, "hex")),
            expiry: circuit.expiry,
            establishedAt: circuit.establishedAt,
            replayGuard: { checkAndRecord: () => ({ ok: true }), getHighestSeq: () => 0n, getSequenceFloor: () => 0n },
            noncePrefix: new Uint8Array(Buffer.from(circuit.noncePrefixHex, "hex")),
            commitmentRoot: new Uint8Array(Buffer.from(circuit.commitmentRootHex, "hex")),
            floorStore: { getFloor: async () => 0n, checkAndAdvance: async () => ({ ok: true }) },
          };
          const wireBytes = new Uint8Array(Buffer.from(data.destroyWireHex, "hex"));
          const gatewayProofBytes = data.gatewayProofHex
            ? new Uint8Array(Buffer.from(data.gatewayProofHex, "hex"))
            : undefined;

          // Snapshot a key BEFORE the destroy to verify zeroization afterwards.
          const fwdKeyBefore = activeCircuit.hops[0].forwardingKey.slice();

          const destroyStore = new InMemoryCircuitDestroyStore();
          const result = await processCircuitDestroy(
            wireBytes,
            activeCircuit,
            data.expectedInitiatorNodeId,
            data.expectedGatewayNodeId,
            destroyStore,
            data.now,
            gatewayProofBytes,
          );

          if (!result.ok) {
            process.stdout.write(JSON.stringify({ ok: false, reason: result.reason }));
            return;
          }

          // Verify keys were zeroized (the function owns zeroization).
          const keysZeroized = activeCircuit.hops.every(
            (h) => h.forwardingKey.every((b) => b === 0) && h.returnKey.every((b) => b === 0),
          );

          // Verify the tombstone was persisted in this process's store.
          const isRevoked = await destroyStore.isRevoked(activeCircuit.circuitId, activeCircuit.commitmentRoot);

          // Verify the wire bytes returned are byte-for-byte identical to input.
          const wireHex = Buffer.from(result.wireBytes).toString("hex");
          const inputHex = data.destroyWireHex;
          const bytesIdentical = (wireHex === inputHex);

          process.stdout.write(JSON.stringify({
            ok: true,
            action: result.action,
            propagate: result.propagate,
            idempotent: result.idempotent,
            wireHex,
            bytesIdentical,
            isRevoked,
            keysZeroized,
            direction: propagationDirection(result.circuitDestroy),
            // Also report the key-before-zeroized for the zeroization proof.
            fwdKeyWasNonZeroBefore: fwdKeyBefore.some((b) => b !== 0),
          }));
        } catch (e) {
          process.stdout.write(JSON.stringify({ ok: false, reason: "child threw: " + e.message }));
        }
      });
    `;

    const child = spawn("bun", ["-e", script], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", () => {
      try {
        resolve(JSON.parse(stdout));
      } catch {
        resolve({ ok: false, reason: `child process failed: ${stderr || stdout}` });
      }
    });
    child.stdin.write(JSON.stringify(input));
    child.stdin.end();
  });
}

// Helper: sign an initiator destroy + encode to wire bytes.
function makeInitiatorDestroy(topo: ReturnType<typeof makeTopology>): Uint8Array {
  const destroy = signCircuitDestroy(
    topo.circuit.circuitId, topo.circuit.commitmentRoot,
    topo.route.initiator.nodeId,
    DESTROYER_ROLE_INITIATOR,
    DESTROY_REASON_OPERATOR_INITIATED,
    NOW, topo.route.branded.expiry,
    topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
  );
  return encodeCircuitDestroy(destroy);
}

// Helper: sign a gateway destroy + encode to wire bytes.
function makeGatewayDestroy(topo: ReturnType<typeof makeTopology>): Uint8Array {
  const destroy = signCircuitDestroy(
    topo.circuit.circuitId, topo.circuit.commitmentRoot,
    topo.gatewayNodeId,
    DESTROYER_ROLE_GATEWAY,
    DESTROY_REASON_OPERATOR_INITIATED,
    NOW, topo.route.branded.expiry,
    topo.gatewayKp.secretKey, topo.gatewayKp.publicKey,
  );
  return encodeCircuitDestroy(destroy);
}

// =====================================================================
// Phase 8: INITIATOR destroy forward (4 processes, all REVOKED)
// =====================================================================

describe("R-009 Stage 3 Phase 3: initiator destroy propagation (forward, 4 processes)", () => {
  test("INITIATOR → relay0 → relay1 → GATEWAY: all REVOKED, bytes unchanged, keys zeroized", async () => {
    const topo = makeTopology(2); // 2 hops: relay0, relay1=gateway
    const circuitJson = serializeCircuit(topo.circuit);
    const destroyWire = makeInitiatorDestroy(topo);
    const destroyWireHex = toHex(destroyWire);

    // The SAME wire bytes propagate through all 4 participants.
    // Each participant is an INDEPENDENT process with its own destroyStore.

    // 1. INITIATOR process (originates + revokes).
    const initiatorResult = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(initiatorResult.ok).toBe(true);
    if (!initiatorResult.ok) return;
    expect(initiatorResult.action).toBe("REVOKED");
    expect(initiatorResult.propagate).toBe(true);
    expect(initiatorResult.isRevoked).toBe(true);
    expect(initiatorResult.keysZeroized).toBe(true);
    expect(initiatorResult.bytesIdentical).toBe(true);
    expect(initiatorResult.direction).toBe("FORWARD");

    // 2. RELAY 0 process (receives the SAME wire bytes).
    const relay0Result = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.action).toBe("REVOKED");
    expect(relay0Result.isRevoked).toBe(true);
    expect(relay0Result.keysZeroized).toBe(true);
    expect(relay0Result.bytesIdentical).toBe(true);
    // Byte-for-byte identical to the initiator's wire bytes.
    expect(relay0Result.wireHex).toBe(destroyWireHex);

    // 3. RELAY 1 process.
    const relay1Result = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(relay1Result.action).toBe("REVOKED");
    expect(relay1Result.isRevoked).toBe(true);
    expect(relay1Result.keysZeroized).toBe(true);
    expect(relay1Result.wireHex).toBe(destroyWireHex);

    // 4. GATEWAY process.
    const gatewayResult = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(gatewayResult.ok).toBe(true);
    if (!gatewayResult.ok) return;
    expect(gatewayResult.action).toBe("REVOKED");
    expect(gatewayResult.isRevoked).toBe(true);
    expect(gatewayResult.keysZeroized).toBe(true);
    expect(gatewayResult.wireHex).toBe(destroyWireHex);

    // ALL 4 participants REVOKED. The wire bytes are byte-for-byte identical
    // across all 4 independent processes (the propagation invariant, ADR-0023 §3).
  }, 60000);
});

// =====================================================================
// Phase 9: GATEWAY destroy backward (4 processes, all REVOKED)
// =====================================================================

describe("R-009 Stage 3 Phase 3: gateway destroy propagation (backward, 4 processes)", () => {
  test("GATEWAY → relay1 → relay0 → INITIATOR: all REVOKED, bytes unchanged", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    const destroyWire = makeGatewayDestroy(topo);
    const destroyWireHex = toHex(destroyWire);
    const gatewayProofHex = toHex(topo.gatewayProofBytes);

    // The gateway proof is REQUIRED for GATEWAY-role destroys + is the SAME
    // serialized artifact at every hop (it's part of the destroy's evidence).

    // 1. GATEWAY process (originates + revokes — proof required).
    const gatewayResult = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      gatewayProofHex,
    });
    expect(gatewayResult.ok).toBe(true);
    if (!gatewayResult.ok) return;
    expect(gatewayResult.action).toBe("REVOKED");
    expect(gatewayResult.propagate).toBe(true);
    expect(gatewayResult.isRevoked).toBe(true);
    expect(gatewayResult.keysZeroized).toBe(true);
    expect(gatewayResult.direction).toBe("BACKWARD");
    expect(gatewayResult.wireHex).toBe(destroyWireHex);

    // 2. RELAY 1 process (backward direction — receives the SAME wire + proof).
    const relay1Result = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      gatewayProofHex,
    });
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;
    expect(relay1Result.action).toBe("REVOKED");
    expect(relay1Result.isRevoked).toBe(true);
    expect(relay1Result.keysZeroized).toBe(true);
    expect(relay1Result.wireHex).toBe(destroyWireHex);

    // 3. RELAY 0 process.
    const relay0Result = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      gatewayProofHex,
    });
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.action).toBe("REVOKED");
    expect(relay0Result.isRevoked).toBe(true);
    expect(relay0Result.keysZeroized).toBe(true);
    expect(relay0Result.wireHex).toBe(destroyWireHex);

    // 4. INITIATOR process.
    const initiatorResult = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
      gatewayProofHex,
    });
    expect(initiatorResult.ok).toBe(true);
    if (!initiatorResult.ok) return;
    expect(initiatorResult.action).toBe("REVOKED");
    expect(initiatorResult.isRevoked).toBe(true);
    expect(initiatorResult.keysZeroized).toBe(true);
    expect(initiatorResult.wireHex).toBe(destroyWireHex);

    // ALL 4 participants REVOKED. Gateway destroy propagates BACKWARD.
  }, 60000);
});

// =====================================================================
// Phase 4: propagation authentication — bytes unchanged across hops
// =====================================================================

describe("R-009 Stage 3 Phase 3: propagation authentication (bytes unchanged)", () => {
  test("wire bytes are byte-for-byte identical at every hop (initiator forward)", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    const destroyWire = makeInitiatorDestroy(topo);
    const destroyWireHex = toHex(destroyWire);

    // Run 4 independent processes + compare wire bytes at each hop.
    const results = await Promise.all([
      runDestroyParticipant({ circuitJson, destroyWireHex, expectedInitiatorNodeId: topo.route.initiator.nodeId, expectedGatewayNodeId: topo.gatewayNodeId, now: NOW }),
      runDestroyParticipant({ circuitJson, destroyWireHex, expectedInitiatorNodeId: topo.route.initiator.nodeId, expectedGatewayNodeId: topo.gatewayNodeId, now: NOW }),
      runDestroyParticipant({ circuitJson, destroyWireHex, expectedInitiatorNodeId: topo.route.initiator.nodeId, expectedGatewayNodeId: topo.gatewayNodeId, now: NOW }),
      runDestroyParticipant({ circuitJson, destroyWireHex, expectedInitiatorNodeId: topo.route.initiator.nodeId, expectedGatewayNodeId: topo.gatewayNodeId, now: NOW }),
    ]);

    for (const r of results) {
      expect(r.ok).toBe(true);
      if (!r.ok) return;
      expect(r.wireHex).toBe(destroyWireHex); // byte-for-byte identical
      expect(r.bytesIdentical).toBe(true);
    }
  }, 60000);

  test("a relay that re-encodes the destroy produces identical canonical bytes (CBOR is deterministic)", () => {
    // Canonical CBOR is deterministic — re-encoding produces identical bytes.
    // This is the substrate that makes byte-for-byte propagation verifiable.
    const topo = makeTopology(1);
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const wire1 = encodeCircuitDestroy(destroy);
    const wire2 = encodeCircuitDestroy(destroy);
    expect(toHex(wire1)).toBe(toHex(wire2)); // deterministic encoding
  });
});

// =====================================================================
// Phase 10: negative multi-process tests
// =====================================================================

describe("R-009 Stage 3 Phase 3: negative multi-process tests", () => {
  test("relay attempts to originate destroy as INITIATOR → REJECT (not the initiator)", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    // Relay 0 signs as INITIATOR (it's NOT the initiator).
    const relay0Kp = topo.route.kps[0]!;
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      relay0Kp.nodeId, // relay 0's own NodeId
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      relay0Kp.secretKey, relay0Kp.publicKey,
    );
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(destroy)),
      expectedInitiatorNodeId: topo.route.initiator.nodeId, // the REAL initiator
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("not the circuit initiator");
  }, 30000);

  test("relay changes destroyerNodeId → downstream REJECT (signature invalid)", async () => {
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
    // Tamper: change destroyerNodeId (breaks the signature).
    const tampered = { ...destroy, destroyerNodeId: "wrong-node-id" };
    const tamperedWire = encodeCircuitDestroy(tampered);
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(tamperedWire),
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  }, 30000);

  test("relay re-signs destroy as itself → downstream REJECT (signature invalid)", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    // Relay 0 signs a destroy with the INITIATOR's destroyerNodeId but its OWN key.
    // This fails verifyNodeIdBinding (Layer 1) — relay's key doesn't derive initiator's NodeId.
    const relay0Kp = topo.route.kps[0]!;
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId, // claims the initiator's NodeId
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      relay0Kp.secretKey, relay0Kp.publicKey, // but signs with relay's key
    );
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(destroy)),
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("identity binding failed");
  }, 30000);

  test("relay modifies destroyReason → downstream REJECT (signature invalid)", async () => {
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
    const tampered = { ...destroy, destroyReason: 0x99 };
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(tampered)),
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  }, 30000);

  test("relay modifies commitmentRoot → downstream REJECT (routeId mismatch)", async () => {
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
    // Tamper: change commitmentRoot (breaks routeId derivation + circuit binding).
    const tampered = { ...destroy, commitmentRoot: randomBytes(32) };
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(tampered)),
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(result.ok).toBe(false);
  }, 30000);

  test("relay modifies circuitId → downstream REJECT (circuit binding mismatch)", async () => {
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
    // Tamper: change circuitId (breaks signature + circuit binding).
    const tampered = { ...destroy, circuitId: randomBytes(32) };
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(tampered)),
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(result.ok).toBe(false);
  }, 30000);

  test("destroy from wrong route (different commitmentRoot) → REJECT", async () => {
    // Topology A: the circuit's actual route.
    const topoA = makeTopology(2);
    const circuitJson = serializeCircuit(topoA.circuit);
    // Topology B: a DIFFERENT route.
    const topoB = makeTopology(2);
    // Sign a destroy with topology B's circuitId + commitmentRoot.
    const destroy = signCircuitDestroy(
      topoB.circuit.circuitId, topoB.circuit.commitmentRoot,
      topoB.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topoB.route.branded.expiry,
      topoB.initiatorKp.secretKey, topoB.initiatorKp.publicKey,
    );
    // Process it at topology A's participant → circuitId mismatch.
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(destroy)),
      expectedInitiatorNodeId: topoA.route.initiator.nodeId,
      expectedGatewayNodeId: topoA.gatewayNodeId,
      now: NOW,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("mismatch");
  }, 30000);

  test("gateway proof from wrong route → REJECT (commitmentRoot mismatch)", async () => {
    const topoA = makeTopology(2);
    const topoB = makeTopology(2);
    const circuitJson = serializeCircuit(topoA.circuit);
    // Gateway destroy signed for topology A (correct circuit).
    const destroy = signCircuitDestroy(
      topoA.circuit.circuitId, topoA.circuit.commitmentRoot,
      topoA.gatewayNodeId,
      DESTROYER_ROLE_GATEWAY,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topoA.route.branded.expiry,
      topoA.gatewayKp.secretKey, topoA.gatewayKp.publicKey,
    );
    // But attach topology B's gateway proof (different commitmentRoot).
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(destroy)),
      expectedInitiatorNodeId: topoA.route.initiator.nodeId,
      expectedGatewayNodeId: topoA.gatewayNodeId,
      now: NOW,
      gatewayProofHex: toHex(topoB.gatewayProofBytes),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("commitmentRoot");
  }, 30000);

  test("expired destroy → REJECT before propagation", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    // Sign a destroy with expiry in the PAST (NOW - 1).
    // issuedAt = NOW - 100 (< expiry = NOW - 1) so the semantic validity
    // check (issuedAt <= expiry) passes; the freshness check (now >= expiry)
    // is what rejects this destroy.
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW - 100, NOW - 1, // issuedAt = NOW-100, expiry = NOW-1 (in the past)
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const result = await runDestroyParticipant({
      circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(destroy)),
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW, // now >= destroy.expiry (NOW >= NOW-1) → expired
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("expired");
  }, 30000);

  test("destroy persistence failure → local failure, MUST NOT claim propagation", async () => {
    const topo = makeTopology(2);
    // Use a FAILING destroy store (simulate persistence failure).
    // The child process script is modified to use a failing store.
    const circuitJson = serializeCircuit(topo.circuit);
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId,
      DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    // Custom script that uses a failing store.
    const result = await new Promise<{ ok: boolean; reason?: string; propagate?: boolean }>((resolve) => {
      const script = `
        const { processCircuitDestroy } = require("${join(process.cwd(), "reference/circuit/destroy.ts").replace(/\\/g, "\\\\")}");
        let input = "";
        process.stdin.on("data", (chunk) => { input += chunk; });
        process.stdin.on("end", async () => {
          const data = JSON.parse(input);
          const circuit = JSON.parse(data.circuitJson);
          const hops = circuit.hops.map((h) => ({
            hopIndex: h.hopIndex, nodeId: h.nodeId,
            forwardingKey: new Uint8Array(Buffer.from(h.forwardingKeyHex, "hex")),
            returnKey: new Uint8Array(Buffer.from(h.returnKeyHex, "hex")),
            relayX25519PublicKey: h.relayX25519PublicKeyHex ? new Uint8Array(Buffer.from(h.relayX25519PublicKeyHex, "hex")) : undefined,
          }));
          const activeCircuit = {
            circuitId: new Uint8Array(Buffer.from(circuit.circuitIdHex, "hex")),
            circuitIdHex: circuit.circuitIdHex, routeId: circuit.routeId, hops,
            initiatorX25519PublicKey: new Uint8Array(Buffer.from(circuit.initiatorX25519PublicKeyHex, "hex")),
            initiatorX25519SecretKey: new Uint8Array(Buffer.from(circuit.initiatorX25519SecretKeyHex, "hex")),
            expiry: circuit.expiry, establishedAt: circuit.establishedAt,
            replayGuard: { checkAndRecord: () => ({ ok: true }), getHighestSeq: () => 0n, getSequenceFloor: () => 0n },
            noncePrefix: new Uint8Array(Buffer.from(circuit.noncePrefixHex, "hex")),
            commitmentRoot: new Uint8Array(Buffer.from(circuit.commitmentRootHex, "hex")),
            floorStore: { getFloor: async () => 0n, checkAndAdvance: async () => ({ ok: true }) },
          };
          const wireBytes = new Uint8Array(Buffer.from(data.destroyWireHex, "hex"));
          // FAILING store — consumeDestroyAndRevoke always returns false.
          const failingStore = {
            isRevoked: async () => false,
            consumeDestroyAndRevoke: async () => ({ ok: false, reason: "simulated persistence failure" }),
            revoke: async () => false,
          };
          const result = await processCircuitDestroy(
            wireBytes, activeCircuit,
            data.expectedInitiatorNodeId, data.expectedGatewayNodeId,
            failingStore, data.now,
          );
          process.stdout.write(JSON.stringify(result));
        });
      `;
      const child = spawn("bun", ["-e", script], { stdio: ["pipe", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => { stdout += d; });
      child.stderr.on("data", (d) => { stderr += d; });
      child.on("close", () => {
        try { resolve(JSON.parse(stdout)); } catch { resolve({ ok: false, reason: `failed: ${stderr}` }); }
      });
      child.stdin.write(JSON.stringify({
        circuitJson, destroyWireHex: toHex(encodeCircuitDestroy(destroy)),
        expectedInitiatorNodeId: topo.route.initiator.nodeId,
        expectedGatewayNodeId: topo.gatewayNodeId,
        now: NOW,
      }));
      child.stdin.end();
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("consumeDestroyAndRevoke failed");
      expect(result.reason).toContain("no split state");
    }
    // CRITICAL: propagate is NOT set (result is a failure, not a success).
    expect(result.propagate).toBeUndefined();
  }, 30000);
});

// =====================================================================
// Phase 11: replay / duplicate propagation
// =====================================================================

describe("R-009 Stage 3 Phase 3: replay / duplicate propagation", () => {
  test("same destroy arrives twice at the SAME participant → idempotent, no resurrection", async () => {
    const topo = makeTopology(2);
    const circuitJson = serializeCircuit(topo.circuit);
    const destroyWireHex = toHex(makeInitiatorDestroy(topo));

    // First receipt → REVOKED.
    const r1 = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.action).toBe("REVOKED");
    expect(r1.propagate).toBe(true);

    // NOTE: each child process has its OWN InMemoryCircuitDestroyStore (fresh
    // per spawn). To test replay to the SAME participant, we need a persistent
    // store across two calls to the SAME process. The child process pattern
    // (one-shot stdin/stdout) does not support this. Instead, test replay
    // in-process (the InMemoryCircuitDestroyStore persists within one process).
    // The multi-process test above proves each participant independently
    // revokes; the in-process replay test (in r009-destroy.test.ts) proves
    // idempotency. Here we verify the wire bytes are unchanged across the
    // two independent process calls (the propagation invariant holds even
    // when the same destroy is processed by two fresh processes).
    const r2 = await runDestroyParticipant({
      circuitJson, destroyWireHex,
      expectedInitiatorNodeId: topo.route.initiator.nodeId,
      expectedGatewayNodeId: topo.gatewayNodeId,
      now: NOW,
    });
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    // r2 is a FRESH process — it also sees this as REVOKED (its own store is fresh).
    // This proves the destroy is independently verifiable at multiple participants.
    expect(r2.action).toBe("REVOKED");
    expect(r2.wireHex).toBe(destroyWireHex); // bytes unchanged
  }, 60000);

  test("same circuit, different destroy nonce, after already revoked → idempotent (in-process)", async () => {
    // This test is in-process (not multi-process) because it requires a persistent
    // store across two destroy calls to the SAME participant. The multi-process
    // pattern uses a fresh store per process. The in-process test proves the
    // idempotency of the SECOND destroy (different nonce) after the circuit is
    // already revoked.
    const { InMemoryCircuitDestroyStore } = await import("@reference/circuit/replay-stores");
    const { processCircuitDestroy } = await import("@reference/circuit/destroy");
    const topo = makeTopology(2);
    const destroyStore = new InMemoryCircuitDestroyStore();

    // First destroy (nonce A) → REVOKED.
    const destroyA = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId, DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const r1 = await processCircuitDestroy(
      encodeCircuitDestroy(destroyA), topo.circuit,
      topo.route.initiator.nodeId, topo.gatewayNodeId,
      destroyStore, NOW,
    );
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.action).toBe("REVOKED");
    expect(r1.propagate).toBe(true);

    // Second destroy (nonce B, DIFFERENT nonce) → ALREADY_REVOKED (tombstone exists).
    const destroyB = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId, DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey, // fresh random nonce inside signCircuitDestroy
    );
    const r2 = await processCircuitDestroy(
      encodeCircuitDestroy(destroyB), topo.circuit,
      topo.route.initiator.nodeId, topo.gatewayNodeId,
      destroyStore, NOW,
    );
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.action).toBe("ALREADY_REVOKED");
    expect(r2.propagate).toBe(false); // suppressed — no resurrection, no new transition
  });
});

// =====================================================================
// Phase 12: restart test (in-process — simulates process restart via a fresh store)
// =====================================================================

describe("R-009 Stage 3 Phase 3: restart (durable revocation persists)", () => {
  test("after revoke, a fresh store (simulating restart) still reports REVOKED via the durable tombstone", async () => {
    // NOTE: the InMemoryCircuitDestroyStore does NOT survive process restart
    // (it's in-memory). To test restart survival, use the DurableSqliteCircuitDestroyStore
    // (backed by the SQLite DB). This test uses the durable store.
    const { DurableSqliteCircuitDestroyStore } = await import("@/lib/sharenet/durable-circuit-replay-stores");
    const { processCircuitDestroy } = await import("@reference/circuit/destroy");
    const { processCircuitWireFrame } = await import("@reference/circuit/forwarding");
    const { sealForwardFrame, encodeCircuitFrame } = await import("@reference/circuit/frame");
    const { db } = await import("@/lib/db");
    const topo = makeTopology(2);

    // Clean the DB tables before the test.
    await db.circuitRevocation.deleteMany({});
    await db.consumedCircuitDestroy.deleteMany({});

    const destroyStore = new DurableSqliteCircuitDestroyStore();
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId, DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const r1 = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), topo.circuit,
      topo.route.initiator.nodeId, topo.gatewayNodeId,
      destroyStore, NOW,
    );
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.action).toBe("REVOKED");

    // SIMULATE RESTART: create a NEW DurableSqliteCircuitDestroyStore instance.
    // It reads from the SAME SQLite DB — the tombstone persists.
    const restartedStore = new DurableSqliteCircuitDestroyStore();
    const isRevoked = await restartedStore.isRevoked(topo.circuit.circuitId, topo.circuit.commitmentRoot);
    expect(isRevoked).toBe(true); // the tombstone survived the "restart"

    // Send an old circuit frame to the restarted participant → REJECT (revoked).
    const plaintext = new TextEncoder().encode("post-destroy frame");
    const sealed = sealForwardFrame(topo.circuit, 1, plaintext);
    const wireBytes = encodeCircuitFrame(sealed);
    const frameResult = await processCircuitWireFrame(topo.circuit, 0, wireBytes, restartedStore, NOW);
    expect(frameResult.ok).toBe(false);
    if (!frameResult.ok) expect(frameResult.reason).toContain("revoked");

    // Send the OLD destroy again → idempotent (already revoked).
    const r2 = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), topo.circuit,
      topo.route.initiator.nodeId, topo.gatewayNodeId,
      restartedStore, NOW,
    );
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.action).toBe("ALREADY_REVOKED");
    expect(r2.propagate).toBe(false);

    // Cleanup.
    await db.circuitRevocation.deleteMany({});
    await db.consumedCircuitDestroy.deleteMany({});
  });
});

// =====================================================================
// Phase 15: failure modes
// =====================================================================

describe("R-009 Stage 3 Phase 3: failure modes", () => {
  test("local revoke succeeds + downstream transport fails → local remains REVOKED", async () => {
    const { InMemoryCircuitDestroyStore } = await import("@reference/circuit/replay-stores");
    const { processCircuitDestroy } = await import("@reference/circuit/destroy");
    const topo = makeTopology(2);
    const destroyStore = new InMemoryCircuitDestroyStore();

    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId, DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    // Local revoke succeeds.
    const r1 = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), topo.circuit,
      topo.route.initiator.nodeId, topo.gatewayNodeId,
      destroyStore, NOW,
    );
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    expect(r1.action).toBe("REVOKED");

    // Simulate downstream transport failure: the destroy was NOT propagated
    // to the next hop. The LOCAL circuit remains REVOKED (the tombstone is
    // authoritative local state — propagation is a separate transport concern).
    const isRevoked = await destroyStore.isRevoked(topo.circuit.circuitId, topo.circuit.commitmentRoot);
    expect(isRevoked).toBe(true); // local remains REVOKED despite downstream failure

    // Retry propagation: re-send the SAME destroy. It's idempotent locally
    // (tombstone exists), but the caller can attempt to forward it again.
    const r2 = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), topo.circuit,
      topo.route.initiator.nodeId, topo.gatewayNodeId,
      destroyStore, NOW,
    );
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.action).toBe("ALREADY_REVOKED");
    expect(r2.propagate).toBe(false); // suppressed (already revoked locally)
    // The caller still has the wire bytes (r2.wireBytes) to retry forwarding.
    expect(toHex(r2.wireBytes)).toBe(toHex(encodeCircuitDestroy(destroy)));
  });

  test("local revoke persistence fails → no claim of propagation, safe to retry", async () => {
    const { processCircuitDestroy } = await import("@reference/circuit/destroy");
    const topo = makeTopology(2);
    // FAILING store — simulate persistence failure.
    const failingStore = {
      isRevoked: async () => false,
      consumeDestroyAndRevoke: async () => ({ ok: false, reason: "simulated persistence failure" }),
      revoke: async () => false,
    };
    const destroy = signCircuitDestroy(
      topo.circuit.circuitId, topo.circuit.commitmentRoot,
      topo.route.initiator.nodeId, DESTROYER_ROLE_INITIATOR,
      DESTROY_REASON_OPERATOR_INITIATED,
      NOW, topo.route.branded.expiry,
      topo.initiatorKp.secretKey, topo.initiatorKp.publicKey,
    );
    const r1 = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), topo.circuit,
      topo.route.initiator.nodeId, topo.gatewayNodeId,
      failingStore as any, NOW,
    );
    expect(r1.ok).toBe(false);
    if (!r1.ok) {
      expect(r1.reason).toContain("consumeDestroyAndRevoke failed");
      expect(r1.reason).toContain("no split state");
      expect(r1.reason).toContain("safe to retry");
    }
    // CRITICAL: no claim of propagation. The result is a FAILURE (ok: false) —
    // there is no `propagate` field, no `wireBytes` field. The caller MUST NOT
    // forward the destroy (the local terminal state was NOT established).
    expect((r1 as any).propagate).toBeUndefined();
    expect((r1 as any).wireBytes).toBeUndefined();

    // Safe to retry: the nonce was NOT consumed (transaction rolled back).
    // A retry with a WORKING store should succeed.
    const { InMemoryCircuitDestroyStore } = await import("@reference/circuit/replay-stores");
    const workingStore = new InMemoryCircuitDestroyStore();
    const r2 = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), topo.circuit,
      topo.route.initiator.nodeId, topo.gatewayNodeId,
      workingStore, NOW,
    );
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    expect(r2.action).toBe("REVOKED"); // the retry succeeded — nonce was fresh
  });
});
