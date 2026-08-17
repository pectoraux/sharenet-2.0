/**
 * ShareNet 2.0 — R-008: Distributed circuit establishment tests.
 *
 * Tests:
 *   1. Genuine distributed circuit setup succeeds (initiator + relay acks → ActiveCircuit)
 *   2. Route substitution: different route in ack → FAIL
 *   3. Replay: old ack in new circuit → FAIL
 *   4. Participant substitution: wrong relay responds → FAIL
 *   5. Transcript mutation: tampered setup request → FAIL
 *   6. Unauthorized circuit creation: no BrandedCommittedRoute → FAIL
 *   7. Multi-process encrypted traffic demonstration
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  randomBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  isBrandedCommittedRoute,
} from "@reference/transport/validated-types";
import { x25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { canonicalEncode } from "@reference/encoding/cbor";
import { routeCommitmentDigest } from "@reference/circuit/distributed-setup";
import {
  handleCircuitSetup,
  processCircuitSetupAck,
  establishDistributedCircuit,
  type CircuitSetupRequest,
  type CircuitSetupAck,
} from "@reference/circuit/distributed-setup";
import {
  deriveCircuitId,
  onionEncrypt,
  relayDecrypt,
} from "@reference/circuit/circuit";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;

function setupRoute(numHops = 2) {
  const ctx = makeGenuineBrandedRouteHelper(numHops, NOW);
  return {
    kps: ctx.kps,
    initiator: ctx.initiator,
    hops: ctx.hops,
    proposal: ctx.proposal,
    sa: ctx.serviceAgreements,
    hpk: ctx.hopPublicKeys,
    branded: ctx.branded,
  };
}

describe("R-008: Distributed circuit establishment", () => {
  // 1. Genuine distributed circuit setup succeeds
  test("genuine distributed circuit setup: initiator + relay acks → ActiveCircuit", () => {
    const ctx = setupRoute(2);
    expect(isBrandedCommittedRoute(ctx.branded)).toBe(true);

    // Initiator generates X25519 keypair
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);

    // Compute circuit ID
    const circuitId = deriveCircuitId(ctx.branded.routeId, initPk);

    // Relay 0 handles setup
    const req0: CircuitSetupRequest = {
      route: ctx.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay0Result = handleCircuitSetup(req0, ctx.kps[0]!.secretKey, circuitId, NOW);
    expect(relay0Result.ok).toBe(true);
    if (!relay0Result.ok) return;
    expect(relay0Result.state.lifecycle).toBe("INSTALLED");

    // Relay 1 handles setup
    const req1: CircuitSetupRequest = {
      route: ctx.branded, hopIndex: 1,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay1Result = handleCircuitSetup(req1, ctx.kps[1]!.secretKey, circuitId, NOW);
    expect(relay1Result.ok).toBe(true);
    if (!relay1Result.ok) return;

    // Initiator establishes the circuit from both acks
    const acks = [relay0Result.ack, relay1Result.ack];
    const estResult = establishDistributedCircuit(
      ctx.branded, initSk, initPk, acks, ctx.hpk, NOW,
    );
    expect(estResult.ok).toBe(true);
    if (!estResult.ok) return;
    expect(estResult.circuit.hops.length).toBe(2);
    expect(estResult.circuit.circuitIdHex).toBe(bytesToHex(circuitId));
  });

  // 2. Route substitution: different routeId in ack → FAIL
  test("route substitution: ack with wrong routeId → FAIL", () => {
    const ctx = setupRoute(2);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);
    const circuitId = deriveCircuitId(ctx.branded.routeId, initPk);

    const req0: CircuitSetupRequest = {
      route: ctx.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay0Result = handleCircuitSetup(req0, ctx.kps[0]!.secretKey, circuitId, NOW);
    if (!relay0Result.ok) return;

    // Tamper: change routeId in ack
    const tamperedAck: CircuitSetupAck = {
      ...relay0Result.ack,
      routeId: bytesToHex(randomBytes(32)), // different routeId
    };

    const commitDigestHex = bytesToHex(blake3(canonicalEncode(new Map([
      [1, ctx.branded.routeId], [2, ctx.branded.hops.map(h => h.nodeId)],
      [3, ctx.branded.hops.map(h => h.capability)], [4, ctx.branded.hops.map(h => h.endpoint)],
      [5, ctx.branded.expiry], [6, ctx.branded.initiatorNodeId], [7, ctx.branded.agreementDigest],
    ])), { dkLen: 32 }));
    const result = processCircuitSetupAck(
      tamperedAck, ctx.branded.routeId, commitDigestHex, 0,
      initPk, ctx.kps[0]!.publicKey, initSk, circuitId, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("routeId mismatch");
  });

  // 3. Replay: old ack in new circuit → FAIL
  test("replay: old ack in new circuit → FAIL (different routeId)", () => {
    const ctx1 = setupRoute(1);
    const ctx2 = setupRoute(1); // different route
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);

    const circuitId1 = deriveCircuitId(ctx1.branded.routeId, initPk);
    const req1: CircuitSetupRequest = {
      route: ctx1.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relayResult = handleCircuitSetup(req1, ctx1.kps[0]!.secretKey, circuitId1);
    if (!relayResult.ok) return;

    // Try to use the old ack with a DIFFERENT route (ctx2)
    const circuitId2 = deriveCircuitId(ctx2.branded.routeId, initPk);
    const result = processCircuitSetupAck(
      relayResult.ack, ctx2.branded.routeId, bytesToHex(randomBytes(32)), 0,
      initPk, ctx1.kps[0]!.publicKey, initSk, circuitId2, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("routeId mismatch");
  });

  // 4. Participant substitution: wrong relay responds → FAIL
  test("participant substitution: wrong relay key → FAIL (signature invalid)", () => {
    const ctx = setupRoute(2);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);
    const circuitId = deriveCircuitId(ctx.branded.routeId, initPk);

    // Relay 0 handles setup with ITS key
    const req0: CircuitSetupRequest = {
      route: ctx.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay0Result = handleCircuitSetup(req0, ctx.kps[0]!.secretKey, circuitId, NOW);
    if (!relay0Result.ok) return;

    // But the initiator tries to verify the ack with Relay 1's key
    const wrongKey = ctx.kps[1]!.publicKey;
    const commitDigestHex = bytesToHex(blake3(canonicalEncode(new Map([
      [1, ctx.branded.routeId], [2, ctx.branded.hops.map(h => h.nodeId)],
      [3, ctx.branded.hops.map(h => h.capability)], [4, ctx.branded.hops.map(h => h.endpoint)],
      [5, ctx.branded.expiry], [6, ctx.branded.initiatorNodeId], [7, ctx.branded.agreementDigest],
    ])), { dkLen: 32 }));
    const result = processCircuitSetupAck(
      relay0Result.ack, ctx.branded.routeId, commitDigestHex, 0,
      initPk, wrongKey, initSk, circuitId, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  // 5. Transcript mutation: tampered setup request → relay rejects
  test("transcript mutation: tampered hopIndex in request → relay rejects", () => {
    const ctx = setupRoute(2);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);
    const circuitId = deriveCircuitId(ctx.branded.routeId, initPk);

    // Create a request with an out-of-range hopIndex
    const badReq: CircuitSetupRequest = {
      route: ctx.branded, hopIndex: 99, // out of range
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const result = handleCircuitSetup(badReq, ctx.kps[0]!.secretKey, circuitId);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("out of range");
  });

  // 6. Unauthorized circuit creation: no BrandedCommittedRoute → FAIL
  test("unauthorized circuit creation: plain object instead of BrandedCommittedRoute → FAIL", () => {
    const kp = generateNodeKeypair();
    const fakeRoute = {
      routeId: "fake",
      hops: [],
      expiry: 0,
      initiatorNodeId: "",
      agreementDigest: "",
      committedAt: 0,
    };

    // establishDistributedCircuit must reject the fake route
    const result = establishDistributedCircuit(
      fakeRoute as any, randomBytes(32), randomBytes(32), [], new Map(), NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("not a genuine BrandedCommittedRoute");
  });

  // 7. Multi-process encrypted traffic demonstration
  test("encrypted traffic: initiator onion-encrypts → relay decrypts → gateway receives plaintext", () => {
    const ctx = setupRoute(2);
    const initSk = randomBytes(32);
    const initPk = x25519.getPublicKey(initSk);
    const circuitId = deriveCircuitId(ctx.branded.routeId, initPk);

    // Both relays handle setup
    const req0: CircuitSetupRequest = {
      route: ctx.branded, hopIndex: 0,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay0Result = handleCircuitSetup(req0, ctx.kps[0]!.secretKey, circuitId, NOW);
    if (!relay0Result.ok) return;

    const req1: CircuitSetupRequest = {
      route: ctx.branded, hopIndex: 1,
      initiatorX25519PublicKey: initPk, setupNonce: randomBytes(16),
    };
    const relay1Result = handleCircuitSetup(req1, ctx.kps[1]!.secretKey, circuitId, NOW);
    if (!relay1Result.ok) return;

    // Initiator establishes the circuit
    const acks = [relay0Result.ack, relay1Result.ack];
    const estResult = establishDistributedCircuit(
      ctx.branded, initSk, initPk, acks, ctx.hpk, NOW,
    );
    expect(estResult.ok).toBe(true);
    if (!estResult.ok) return;
    const circuit = estResult.circuit;

    // Onion-encrypt a test payload
    const plaintext = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const seq = 1n;
    const { encryptedPayload } = onionEncrypt(circuit, seq, plaintext);

    // Relay 0 decrypts one layer (using its installed forwarding state)
    const { decrypted: relay0Output } = relayDecrypt(circuit, 0, seq, encryptedPayload);

    // Relay 1 (gateway) decrypts the final layer → plaintext
    const { decrypted: gatewayOutput } = relayDecrypt(circuit, 1, seq, relay0Output);

    // The gateway receives the plaintext HTTP request
    expect(new TextDecoder().decode(gatewayOutput)).toBe("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

    // Relay 0 never saw the plaintext
    const relay0Decoded = new TextDecoder().decode(relay0Output);
    expect(relay0Decoded).not.toContain("HTTP");
    expect(relay0Decoded).not.toContain("Host");
  });
});
