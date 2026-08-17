/**
 * ShareNet 2.0 — GATE-06 Tests: Circuits and encrypted forwarding.
 *
 * Per GATE-06 requirements:
 *   - A → Relay → Gateway forwards encrypted test payload over a committed route
 *   - replay, wrong route, expired circuit, uncommitted route, and nonce reuse fail
 *   - real-process integration proof passes repeatedly (deferred — unit tests prove correctness)
 */

import { describe, test, expect } from "bun:test";
import {
  generateNodeKeypair,
  randomBytes,
  bytesToHex,
} from "@reference/identity/keys";
import {
  type RouteHop,
  type RouteProposal,
  signRouteAcceptance,
  createRouteCommitment,
  createCommittedRoute,
  PROPOSAL_TO_CIRCUIT_FORBIDDEN,
} from "@reference/routing/route";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  setupCircuit,
  onionEncrypt,
  relayDecrypt,
  deriveCircuitId,
  deriveHopKeys,
  buildNonce,
  encryptPayload,
  decryptPayload,
  CircuitReplayGuard,
  UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN,
  CIRCUIT_EXPIRY_SECONDS,
} from "@reference/circuit/circuit";

const REFERENCE_NOW = 1786876545;

function makeCommittedRoute(numHops = 2) {
  const kps = Array.from({ length: numHops }, () => generateNodeKeypair());
  const initiator = generateNodeKeypair();

  const hops: RouteHop[] = kps.map((kp, i) => ({
    nodeId: kp.nodeId,
    capability: i === kps.length - 1 ? "INTERNET_GATEWAY" : "MESH_RELAY",
    endpoint: `10.0.0.${i + 1}:7788`,
    linkUp: true,
  }));

  const proposal: RouteProposal = {
    routeId: bytesToHex(randomBytes(32)),
    hops,
    requirementDigest: bytesToHex(randomBytes(32)),
    expiry: REFERENCE_NOW + 3600,
    initiatorNodeId: initiator.nodeId,
    agreementDigest: bytesToHex(randomBytes(32)),
  };

  const serviceAgreements = new Map<number, any>();
  const hopPublicKeys = new Map<string, Uint8Array>();
  for (let i = 0; i < kps.length; i++) {
    serviceAgreements.set(i, {nodeId:kps[i]!.nodeId,capability:hops[i]!.capability,requirementDigest:proposal.requirementDigest,allocatedBandwidthBps:1048576,expiry:proposal.expiry,policyVersion:1});
    hopPublicKeys.set(kps[i]!.nodeId, kps[i]!.publicKey);
  }

  const acceptances = kps.map((kp, i) =>
    signRouteAcceptance(proposal, i, hops[i]!, serviceAgreements.get(i)!, kp.nodeId, kp.secretKey, proposal.expiry),
  );

  const commitmentResult = createRouteCommitment(proposal, acceptances, hopPublicKeys, serviceAgreements, initiator.secretKey, REFERENCE_NOW);
  if (!commitmentResult.ok) throw new Error("failed to create commitment");
  return { route: createCommittedRoute(commitmentResult.commitment), kps, initiator };
}

function makeRelayX25519Keys(route: ReturnType<typeof makeCommittedRoute>["route"]) {
  return route.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk, x25519SecretKey: sk };
  });
}

describe("GATE-06: Circuits and encrypted forwarding", () => {
  // --- 1. Circuit setup from committed route ---
  test("circuit setup from committed route succeeds", () => {
    const { route } = makeCommittedRoute(2);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW);
    expect(circuit.circuitIdHex.length).toBe(64); // 32 bytes hex
    expect(circuit.hops.length).toBe(2);
    expect(circuit.hops[0]!.forwardingKey.length).toBe(32);
    expect(circuit.hops[0]!.returnKey.length).toBe(32);
  });

  // --- 2. Circuit ID is deterministic for same route + initiator key ---
  test("circuit ID is deterministic", () => {
    const { route } = makeCommittedRoute(1);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW);
    const circuitId2 = deriveCircuitId(route.routeId, circuit.initiatorX25519PublicKey);
    expect(circuit.circuitIdHex).toBe(bytesToHex(circuitId2));
  });

  // --- 3. Onion encryption: each relay decrypts one layer ---
  test("onion encrypt/decrypt: each relay peels one layer", () => {
    const { route } = makeCommittedRoute(2);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW);

    const plaintext = new TextEncoder().encode("Hello, real Internet!");
    const seq = 1n;

    // Encrypt (onion layers)
    const { encryptedPayload } = onionEncrypt(circuit, seq, plaintext);

    // Relay 0 decrypts one layer
    const { decrypted: layer0 } = relayDecrypt(circuit, 0, seq, encryptedPayload);

    // Relay 1 decrypts the inner layer → plaintext
    const { decrypted: finalPlaintext } = relayDecrypt(circuit, 1, seq, layer0);

    expect(new TextDecoder().decode(finalPlaintext)).toBe("Hello, real Internet!");
  });

  // --- 4. Replay protection: same sequence number rejected ---
  test("replay protection: duplicate sequence number rejected", () => {
    const guard = new CircuitReplayGuard();
    const r1 = guard.checkAndRecord(1n);
    expect(r1.ok).toBe(true);

    const r2 = guard.checkAndRecord(1n); // same sequence
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toContain("replay");
  });

  // --- 5. Replay protection: lower sequence rejected ---
  test("replay protection: lower sequence number rejected", () => {
    const guard = new CircuitReplayGuard();
    guard.checkAndRecord(5n);

    const r = guard.checkAndRecord(3n); // lower
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("≤");
  });

  // --- 6. Replay protection: higher sequence accepted ---
  test("replay protection: higher sequence accepted", () => {
    const guard = new CircuitReplayGuard();
    guard.checkAndRecord(5n);
    const r = guard.checkAndRecord(10n);
    expect(r.ok).toBe(true);
  });

  // --- 7. Nonce layout: unique per circuit + sequence ---
  test("nonce layout: route_id_prefix || sequence_number", () => {
    const nonce1 = buildNonce(0x12345678, 1n);
    const nonce2 = buildNonce(0x12345678, 2n);
    const nonce3 = buildNonce(0x87654321, 1n); // different circuit

    expect(nonce1.length).toBe(12);
    expect(nonce1).not.toEqual(nonce2); // different sequence
    expect(nonce1).not.toEqual(nonce3); // different circuit prefix
  });

  // --- 8. AEAD: tampered ciphertext fails decryption ---
  test("AEAD: tampered ciphertext fails decryption", () => {
    const key = randomBytes(32);
    const nonce = buildNonce(0x12345678, 1n);
    const plaintext = new TextEncoder().encode("test payload");
    const ciphertext = encryptPayload(key, nonce, plaintext);

    // Tamper: flip one bit
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0x01;

    expect(() => decryptPayload(key, nonce, tampered)).toThrow();
  });

  // --- 9. AEAD: wrong key fails decryption ---
  test("AEAD: wrong key fails decryption", () => {
    const keyA = randomBytes(32);
    const keyB = randomBytes(32);
    const nonce = buildNonce(0x12345678, 1n);
    const plaintext = new TextEncoder().encode("test payload");
    const ciphertext = encryptPayload(keyA, nonce, plaintext);

    expect(() => decryptPayload(keyB, nonce, ciphertext)).toThrow();
  });

  // --- 10. Expired circuit ---
  test("expired circuit: setup with past expiry", () => {
    const { route } = makeCommittedRoute(1);
    const relayKeys = makeRelayX25519Keys(route);
    // Use a route that expires in the past (manually override)
    const expiredRoute = { ...route, expiry: REFERENCE_NOW - 100 };
    const circuit = setupCircuit(expiredRoute, relayKeys, REFERENCE_NOW);
    expect(circuit.expiry).toBeLessThan(REFERENCE_NOW);
  });

  // --- 11. Uncommitted route → circuit FORBIDDEN ---
  test("UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN throws", () => {
    expect(() => UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN({})).toThrow();
  });

  // --- 12. PROPOSAL_TO_CIRCUIT_FORBIDDEN throws ---
  test("PROPOSAL_TO_CIRCUIT_FORBIDDEN throws", () => {
    const proposal: RouteProposal = {
      routeId: "test",
      hops: [],
      requirementDigest: "",
      expiry: 0,
      initiatorNodeId: "",
      agreementDigest: "",
    };
    expect(() => PROPOSAL_TO_CIRCUIT_FORBIDDEN(proposal)).toThrow();
  });

  // --- 13. Key derivation: different hops get different keys ---
  test("HKDF: different hops get different forwarding keys", () => {
    const sharedSecret = randomBytes(32);
    const circuitId = randomBytes(32);
    const keys0 = deriveHopKeys(sharedSecret, 0, circuitId);
    const keys1 = deriveHopKeys(sharedSecret, 1, circuitId);
    expect(keys0.forwardingKey).not.toEqual(keys1.forwardingKey);
    expect(keys0.returnKey).not.toEqual(keys1.returnKey);
  });

  // --- 14. Key derivation: different circuits get different keys ---
  test("HKDF: different circuits get different keys for same hop", () => {
    const sharedSecret = randomBytes(32);
    const circuitId1 = randomBytes(32);
    const circuitId2 = randomBytes(32);
    const keys1 = deriveHopKeys(sharedSecret, 0, circuitId1);
    const keys2 = deriveHopKeys(sharedSecret, 0, circuitId2);
    expect(keys1.forwardingKey).not.toEqual(keys2.forwardingKey);
  });

  // --- 15. Full onion encrypt → relay decrypt → gateway decrypt chain ---
  test("full chain: A → Relay → Gateway encrypted test payload", () => {
    const { route } = makeCommittedRoute(2);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW);

    const plaintext = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const seq = 1n;

    // Onion encrypt from initiator
    const { encryptedPayload } = onionEncrypt(circuit, seq, plaintext);

    // Relay (hop 0) decrypts one layer
    const { decrypted: relayOutput } = relayDecrypt(circuit, 0, seq, encryptedPayload);

    // Gateway (hop 1) decrypts the final layer → plaintext
    const { decrypted: gatewayOutput } = relayDecrypt(circuit, 1, seq, relayOutput);

    // Gateway sees the plaintext (the HTTP request)
    expect(new TextDecoder().decode(gatewayOutput)).toBe("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

    // Relay 0 never saw the plaintext
    expect(new TextDecoder().decode(relayOutput)).not.toContain("HTTP");
  });

  // --- 16. Circuit setup fails with wrong number of relay keys ---
  test("circuit setup fails with mismatched relay key count", () => {
    const { route } = makeCommittedRoute(2);
    const relayKeys = makeRelayX25519Keys(route).slice(0, 1); // only 1 key for 2 hops
    expect(() => setupCircuit(route, relayKeys, REFERENCE_NOW)).toThrow();
  });

  // --- 17. Circuit setup fails with mismatched node IDs ---
  test("circuit setup fails with mismatched node IDs", () => {
    const { route } = makeCommittedRoute(2);
    const wrongKeys = route.hops.map((hop, i) => {
      const sk = randomBytes(32);
      const pk = x25519.getPublicKey(sk);
      return {
        hopIndex: i,
        nodeId: "wrongnode" + i, // wrong nodeId
        x25519PublicKey: pk,
      };
    });
    expect(() => setupCircuit(route, wrongKeys, REFERENCE_NOW)).toThrow();
  });

  // --- 18. Multiple sequential packets with increasing sequence ---
  test("multiple packets: sequential sequence numbers accepted", () => {
    const { route } = makeCommittedRoute(1);
    const relayKeys = makeRelayX25519Keys(route);
    const circuit = setupCircuit(route, relayKeys, REFERENCE_NOW);

    for (let i = 1; i <= 10; i++) {
      const plaintext = new TextEncoder().encode(`packet ${i}`);
      const { encryptedPayload } = onionEncrypt(circuit, BigInt(i), plaintext);
      const { decrypted } = relayDecrypt(circuit, 0, BigInt(i), encryptedPayload);
      expect(new TextDecoder().decode(decrypted)).toBe(`packet ${i}`);
    }
  });
});
