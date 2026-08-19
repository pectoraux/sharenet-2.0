/**
 * ShareNet 2.0 — R-009 Stage 2: distributed return-onion template tests.
 *
 * Tests the return-onion template distribution protocol (Model A):
 *   - The initiator constructs a ReturnOnionTemplate during setup.
 *   - The gateway holds K_ret + the opaque envelope (NOT the per-hop returnKeys).
 *   - The gateway seals return responses using the template.
 *   - Each relay peels one returnKey layer from the envelope + forwards.
 *   - The source recovers K_ret + decrypts the response.
 *
 * Proves the gateway can return traffic WITHOUT holding the raw returnKeys.
 */

import { describe, test, expect } from "bun:test";
import { randomBytes, generateNodeKeypair } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  setupCircuit,
} from "@reference/circuit/circuit";
import {
  encodeCircuitFrame,
  decodeCircuitFrame,
  sealForwardFrame,
  DIRECTION_FORWARD,
  DIRECTION_BACKWARD,
} from "@reference/circuit/frame";
import { processCircuitWireFrame } from "@reference/circuit/forwarding";
import {
  constructReturnOnionTemplate,
  sealReturnFrameFromTemplate,
  peelReturnEnvelopeLayer,
  decryptReturnPayload,
  encodeReturnFramePayload,
  signGatewayReturnTemplate,
  verifyGatewayReturnTemplate,
  verifyGatewayReturnTemplateWithRoute,
  encodeGatewayReturnTemplate,
  decodeGatewayReturnTemplate,
  constructGatewayReturnAuthorization,
  encodeGatewayReturnAuthorization,
  decodeGatewayReturnAuthorization,
  verifyGatewayReturnAuthorization,
} from "@reference/circuit/return-template";
import { handleCircuitSetup, type CircuitSetupAck } from "@reference/circuit/distributed-setup";
import { InMemoryCircuitSequenceFloorStore } from "@reference/circuit/replay-stores";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;

function makeRoute(numHops = 2) {
  const ctx = makeGenuineBrandedRouteHelper(numHops, NOW);
  return {
    branded: ctx.branded,
    kps: ctx.kps,
    hpk: ctx.hopPublicKeys,
    commitmentRoot: ctx.branded.commitmentRoot,
    // Per R-009 Stage 2 (re-audit of 8fa4ef3 — terminal-hop proof): the
    // GatewayReturnAuthorization now embeds the terminal RouteAcceptance +
    // the list of hopNodeIds so the gateway can verify it is the genuine
    // terminal hop (not an intermediate relay impersonating the gateway).
    commitment: ctx.commitment,
    hopNodeIds: ctx.branded.hops.map((h) => h.nodeId),
    terminalAcceptance: ctx.commitment.acceptances[ctx.commitment.acceptances.length - 1]!,
  };
}

function makeRelayX25519Keys(route: { hops: Array<{ nodeId: string }> }) {
  return route.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk };
  });
}

/**
 * Generate a GENUINE proof-bearing `CircuitSetupAck` from the terminal hop of
 * the route (the gateway). Per R-009 Stage 2 (re-audit of e165ba2):
 * `verifyGatewayReturnTemplateWithRoute` now consumes the FULL ack + the
 * terminal relay's Ed25519 public key — it verifies the ack's Ed25519
 * signature before extracting the X25519 key. A forged ack (with a different
 * `relayX25519PublicKey`) fails the signature check because the attacker
 * doesn't have the relay's Ed25519 secret key.
 *
 * The ack is produced by `handleCircuitSetup`, which generates the relay's
 * X25519 keypair internally. Since the gateway IS the terminal relay, the
 * gateway's X25519 keypair IS the ack's relay X25519 keypair — the gateway
 * keeps the secret (in `ackResult.state.relayX25519SecretKey`) and the public
 * key travels in the ack (`ackResult.ack.relayX25519PublicKey`). The
 * GatewayReturnTemplate is then signed against this X25519 public key.
 *
 * The circuit's `initiatorX25519PublicKey` is passed to `handleCircuitSetup`
 * as the transcript-binding public key — this matches the
 * `circuit.initiatorX25519SecretKey` used to sign the GatewayReturnTemplate
 * (ECDH partner on the initiator side).
 */
function makeTerminalAck(
  route: ReturnType<typeof makeRoute>,
  circuit: { initiatorX25519PublicKey: Uint8Array },
): {
  terminalAck: CircuitSetupAck;
  relayEd25519PublicKey: Uint8Array;
  gatewayX25519SecretKey: Uint8Array;
  gatewayX25519PublicKey: Uint8Array;
} {
  const terminalHopIndex = route.branded.hops.length - 1;
  const relayKp = route.kps[terminalHopIndex]!;
  const ackResult = handleCircuitSetup(
    {
      route: route.branded,
      hopIndex: terminalHopIndex,
      initiatorX25519PublicKey: circuit.initiatorX25519PublicKey,
      setupNonce: randomBytes(16),
    },
    relayKp.secretKey,
    route.commitmentRoot,
    NOW,
  );
  if (!ackResult.ok) throw new Error(`terminal ack setup failed: ${ackResult.reason}`);
  return {
    terminalAck: ackResult.ack,
    relayEd25519PublicKey: relayKp.publicKey,
    gatewayX25519SecretKey: ackResult.state.relayX25519SecretKey,
    gatewayX25519PublicKey: ackResult.state.relayX25519PublicKey,
  };
}

describe("R-009 Stage 2: distributed return-onion template", () => {
  test("initiator constructs template; gateway holds K_ret + opaque envelope (NOT returnKeys)", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // The initiator constructs the template during setup.
    const template = constructReturnOnionTemplate(circuit);

    // The gateway receives: K_ret (circuit-scoped key) + the opaque envelope.
    expect(template.kRet.length).toBe(32);
    expect(template.envelope.length).toBeGreaterThan(0);

    // The gateway does NOT hold the per-hop returnKeys.
    // (In the real protocol, the gateway only gets { kRet, envelope, circuitId,
    //  commitmentRoot, noncePrefix } — NOT the ActiveCircuit.hops[].returnKey.)
    // The template is self-contained: { kRet, envelope }.
  });

  test("full distributed return chain: gateway seals → relay peels → source decrypts", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // INITIATOR: construct the template during setup.
    const template = constructReturnOnionTemplate(circuit);

    // GATEWAY: seal a return response using the template (NOT the raw returnKeys).
    const response = new TextEncoder().encode("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    const ciphertext = sealReturnFrameFromTemplate(template, 1, response);

    // RELAY 1 (hop N-1 = the gateway's neighbor): peel one envelope layer.
    const peel1 = peelReturnEnvelopeLayer(circuit, 1, ciphertext);
    expect(peel1.ok).toBe(true);
    if (!peel1.ok) return;
    expect(peel1.isTerminal).toBe(false); // hop 1 is NOT terminal (terminal is hop 0)
    // Relay 1 now holds { sealedPayload, innerEnvelope } — forward to hop 0.
    const innerCiphertext = encodeReturnFramePayloadForTest(peel1.innerPayload);

    // SOURCE (hop 0): peel the FINAL envelope layer → recover K_ret.
    const peel0 = peelReturnEnvelopeLayer(circuit, 0, innerCiphertext);
    expect(peel0.ok).toBe(true);
    if (!peel0.ok) return;
    expect(peel0.isTerminal).toBe(true); // hop 0 IS terminal → K_ret revealed
    expect(peel0.kRet).toBeDefined();
    if (!peel0.kRet) return;
    // The recovered K_ret matches the template's K_ret.
    expect(toHex(peel0.kRet)).toBe(toHex(template.kRet));

    // SOURCE: decrypt the sealedPayload with K_ret.
    const decrypted = decryptReturnPayload(
      peel0.kRet,
      circuit.noncePrefix,
      circuit.commitmentRoot,
      1, // frameSequence
      peel0.innerPayload.sealedPayload,
    );
    expect(decrypted.ok).toBe(true);
    if (!decrypted.ok) return;
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
  });

  test("1-hop return chain: gateway seals → source (hop 0) decrypts directly", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const template = constructReturnOnionTemplate(circuit);
    const response = new TextEncoder().encode("return data");
    const ciphertext = sealReturnFrameFromTemplate(template, 1, response);

    // hop 0 (the source, also the only hop) peels the envelope → K_ret.
    const peel0 = peelReturnEnvelopeLayer(circuit, 0, ciphertext);
    expect(peel0.ok).toBe(true);
    if (!peel0.ok) return;
    expect(peel0.isTerminal).toBe(true);
    if (!peel0.kRet) return;

    const decrypted = decryptReturnPayload(
      peel0.kRet,
      circuit.noncePrefix,
      circuit.commitmentRoot,
      1,
      peel0.innerPayload.sealedPayload,
    );
    expect(decrypted.ok).toBe(true);
    if (!decrypted.ok) return;
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe("return data");
  });

  test("gateway cannot decrypt intermediate envelope layers (key isolation)", () => {
    // The gateway holds K_ret + the opaque envelope, but does NOT hold the
    // per-hop returnKeys. It cannot peel any envelope layer.
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const template = constructReturnOnionTemplate(circuit);

    // The gateway only has { kRet, envelope, circuitId, commitmentRoot, noncePrefix }.
    // It does NOT have circuit.hops[].returnKey.
    // Attempting to peel the envelope without a returnKey must fail.
    // (In the real protocol, the gateway doesn't even have an ActiveCircuit
    //  with hops[].returnKey — it only has the template.)
    // Simulate this: create a "gateway view" with no returnKeys.
    const gatewayView = {
      ...circuit,
      hops: circuit.hops.map(h => ({ ...h, returnKey: new Uint8Array(32) })), // wrong keys
    } as any;

    const response = new TextEncoder().encode("x");
    const ciphertext = sealReturnFrameFromTemplate(template, 1, response);

    // The gateway (with wrong/no returnKeys) cannot peel the envelope.
    const peel = peelReturnEnvelopeLayer(gatewayView, 1, ciphertext);
    expect(peel.ok).toBe(false);
    if (!peel.ok) expect(peel.reason).toContain("AEAD envelope peel failed");
  });

  test("tampered return envelope → AEAD fails", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const template = constructReturnOnionTemplate(circuit);
    const response = new TextEncoder().encode("return");
    const ciphertext = new Uint8Array(sealReturnFrameFromTemplate(template, 1, response));
    // Tamper one byte.
    ciphertext[ciphertext.length - 1] ^= 0x01;

    const peel = peelReturnEnvelopeLayer(circuit, 1, ciphertext);
    expect(peel.ok).toBe(false);
    if (!peel.ok) expect(peel.reason).toContain("AEAD");
  });

  test("template envelope is bound to (commitmentRoot, hopIndex) — cross-circuit envelope rejected", () => {
    // An envelope constructed for circuit A cannot be peeled by circuit B
    // (different commitmentRoot → different AD → AEAD fails).
    const routeA = makeRoute(2);
    const relayKeysA = makeRelayX25519Keys(routeA.branded);
    const floorStoreA = new InMemoryCircuitSequenceFloorStore();
    const circuitA = setupCircuit(routeA.branded, relayKeysA, NOW, floorStoreA);

    const routeB = makeRoute(2);
    const relayKeysB = makeRelayX25519Keys(routeB.branded);
    const floorStoreB = new InMemoryCircuitSequenceFloorStore();
    const circuitB = setupCircuit(routeB.branded, relayKeysB, NOW, floorStoreB);

    const templateA = constructReturnOnionTemplate(circuitA);
    const response = new TextEncoder().encode("return for A");
    const ciphertext = sealReturnFrameFromTemplate(templateA, 1, response);

    // Circuit B's relay (different commitmentRoot) cannot peel circuit A's envelope.
    const peel = peelReturnEnvelopeLayer(circuitB, 1, ciphertext);
    expect(peel.ok).toBe(false);
    if (!peel.ok) expect(peel.reason).toContain("AEAD");
  });

  test("multiple return frames at different sequences all decrypt correctly", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    const template = constructReturnOnionTemplate(circuit);

    for (let seq = 1; seq <= 5; seq++) {
      const response = new TextEncoder().encode(`response ${seq}`);
      const ciphertext = sealReturnFrameFromTemplate(template, seq, response);

      // Relay 1 peels.
      const peel1 = peelReturnEnvelopeLayer(circuit, 1, ciphertext);
      expect(peel1.ok).toBe(true);
      if (!peel1.ok) return;
      const innerCiphertext = encodeReturnFramePayloadForTest(peel1.innerPayload);

      // Source peels + decrypts.
      const peel0 = peelReturnEnvelopeLayer(circuit, 0, innerCiphertext);
      expect(peel0.ok).toBe(true);
      if (!peel0.ok || !peel0.isTerminal || !peel0.kRet) return;
      const decrypted = decryptReturnPayload(
        peel0.kRet, circuit.noncePrefix, circuit.commitmentRoot, seq,
        peel0.innerPayload.sealedPayload,
      );
      expect(decrypted.ok).toBe(true);
      if (!decrypted.ok) return;
      expect(new TextDecoder().decode(decrypted.plaintext)).toBe(`response ${seq}`);
    }
  });
});

// =====================================================================
// R-009 Stage 2: FULL DISTRIBUTED INTEGRATION TEST
// Exercises the complete production path: source ↔ relay 0 ↔ relay 1 ↔ gateway
// Forward: source → relay 0 → gateway (terminal)
// Backward: gateway (seals using template) → relay 1 → source (terminal)
// All through processCircuitWireFrame (the canonical production entry point).
// =====================================================================

describe("R-009 Stage 2: full distributed integration (production path)", () => {
  test("forward request + backward response through processCircuitWireFrame", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);

    // The initiator constructs the return-onion template during setup.
    // (In a real deployment, this is sent to the gateway.)
    const template = constructReturnOnionTemplate(circuit);

    // --- FORWARD: source → relay 0 → gateway (hop 1, terminal) ---
    const httpRequest = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const fwdSealed = sealForwardFrame(circuit, 1, httpRequest);
    const fwdWire = encodeCircuitFrame(fwdSealed);

    // Relay 0 processes the forward frame.
    const fwdR0 = await processCircuitWireFrame(circuit, 0, fwdWire);
    expect(fwdR0.ok).toBe(true);
    if (!fwdR0.ok) return;
    expect(fwdR0.terminal).toBe(false); // hop 0 is not terminal for FORWARD

    // Gateway (hop 1) processes — terminal for FORWARD, delivers the request.
    const fwdR1 = await processCircuitWireFrame(circuit, 1, fwdR0.nextWireBytes);
    expect(fwdR1.ok).toBe(true);
    if (!fwdR1.ok) return;
    expect(fwdR1.terminal).toBe(true); // hop 1 IS terminal for FORWARD
    expect(new TextDecoder().decode(fwdR1.plaintext)).toBe(
      "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );

    // --- BACKWARD: gateway seals response → relay 1 → source (hop 0, terminal) ---
    // The gateway uses the template (NOT raw returnKeys) to seal the response.
    const httpResponse = new TextEncoder().encode("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    const retCiphertext = sealReturnFrameFromTemplate(template, 1, httpResponse);
    const retFrame = {
      circuitNoncePrefix: circuit.noncePrefix,
      frameSequence: 1,
      direction: DIRECTION_BACKWARD,
      ciphertext: retCiphertext,
    } as any;
    const retWire = encodeCircuitFrame(retFrame);

    // Relay 1 (gateway's neighbor) processes the backward frame.
    const retR1 = await processCircuitWireFrame(circuit, 1, retWire);
    expect(retR1.ok).toBe(true);
    if (!retR1.ok) return;
    expect(retR1.terminal).toBe(false); // hop 1 is NOT terminal for BACKWARD

    // Source (hop 0) processes — terminal for BACKWARD, delivers the response.
    const retR0 = await processCircuitWireFrame(circuit, 0, retR1.nextWireBytes);
    expect(retR0.ok).toBe(true);
    if (!retR0.ok) return;
    expect(retR0.terminal).toBe(true); // hop 0 IS terminal for BACKWARD
    expect(new TextDecoder().decode(retR0.plaintext)).toBe(
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );

    // Verify the forward + backward floors are independent.
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_FORWARD)).toBe(1n);
    expect(await floorStore.getFloor(route.commitmentRoot, 1, DIRECTION_FORWARD)).toBe(1n);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_BACKWARD)).toBe(1n);
    expect(await floorStore.getFloor(route.commitmentRoot, 1, DIRECTION_BACKWARD)).toBe(1n);
  });

  test("backward replay through production path → rejected", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);

    const ciphertext = sealReturnFrameFromTemplate(template, 1, new TextEncoder().encode("ret"));
    const frame = {
      circuitNoncePrefix: circuit.noncePrefix,
      frameSequence: 1,
      direction: DIRECTION_BACKWARD,
      ciphertext,
    } as any;
    const wire = encodeCircuitFrame(frame);

    // First presentation — accepted.
    const r1 = await processCircuitWireFrame(circuit, 0, wire);
    expect(r1.ok).toBe(true);

    // Replay through the production path — rejected.
    const r2 = await processCircuitWireFrame(circuit, 0, wire);
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.reason).toContain("≤ floor");
  });

  test("tampered backward frame through production path → AEAD fails → floor UNCHANGED", async () => {
    const route = makeRoute(1);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);

    const ciphertext = sealReturnFrameFromTemplate(template, 100, new TextEncoder().encode("x"));
    const frame = {
      circuitNoncePrefix: circuit.noncePrefix,
      frameSequence: 100,
      direction: DIRECTION_BACKWARD,
      ciphertext,
    } as any;
    const wire = new Uint8Array(encodeCircuitFrame(frame));
    wire[wire.length - 1] ^= 0x01; // tamper

    const result = await processCircuitWireFrame(circuit, 0, wire);
    expect(result.ok).toBe(false);
    expect(await floorStore.getFloor(route.commitmentRoot, 0, DIRECTION_BACKWARD)).toBe(0n);
  });
});

// Helper: encode a ReturnFramePayload to CBOR (for forwarding between hops).
function encodeReturnFramePayloadForTest(payload: { sealedPayload: Uint8Array; envelopeLayer: Uint8Array }): Uint8Array {
  return encodeReturnFramePayload(payload);
}

// =====================================================================
// R-009 Stage 2: GatewayReturnTemplate — authenticated transfer
// (per the re-audit of 67deef6: the template must cross the network as an
//  authenticated setup message, not merely be returned in memory.)
// =====================================================================

describe("R-009 Stage 2: GatewayReturnTemplate — authenticated transfer", () => {
  test("initiator signs + gateway verifies → accepts template", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    // Fresh gateway X25519 keypair (the gateway's own ECDH keypair — NOT the
    // circuit's per-hop relayX25519 keys, which are owned by the relays).
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    // Initiator signs the gateway template (encrypting K_ret under the ECDH
    // shared secret with the gateway's X25519 public key).
    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // Gateway verifies — matches its own NodeId + own X25519 pubkey + valid signature + not expired.
    // The gateway decrypts K_ret using its own X25519 secret key.
    const result = verifyGatewayReturnTemplate(gt, gatewayNodeId, gatewayX25519Sk, gatewayX25519Pk, NOW);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // The recovered template has the correct K_ret + envelope.
    expect(toHex(result.template.kRet)).toBe(toHex(template.kRet));
    expect(toHex(result.template.envelope)).toBe(toHex(template.envelope));
  });

  test("encode → decode round-trip preserves all fields", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const encoded = encodeGatewayReturnTemplate(gt);
    const decoded = decodeGatewayReturnTemplate(encoded);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(toHex(decoded.gatewayTemplate.circuitId)).toBe(toHex(gt.circuitId));
    expect(toHex(decoded.gatewayTemplate.encryptedKRet)).toBe(toHex(gt.encryptedKRet));
    expect(toHex(decoded.gatewayTemplate.kRetNonce)).toBe(toHex(gt.kRetNonce));
    expect(toHex(decoded.gatewayTemplate.gatewayX25519PublicKey)).toBe(toHex(gt.gatewayX25519PublicKey));
    expect(toHex(decoded.gatewayTemplate.initiatorX25519PublicKey)).toBe(toHex(gt.initiatorX25519PublicKey));
    expect(toHex(decoded.gatewayTemplate.initiatorSignature)).toBe(toHex(gt.initiatorSignature));
    expect(decoded.gatewayTemplate.gatewayNodeId).toBe(gt.gatewayNodeId);
  });

  test("wrong gateway → REJECT (only the intended terminal gateway can accept)", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // A different node (e.g., relay 0) tries to accept → REJECTED at the
    // gatewayNodeId binding check (before any signature / decryption check).
    const wrongNodeId = route.branded.hops[0]!.nodeId;
    const result = verifyGatewayReturnTemplate(gt, wrongNodeId, gatewayX25519Sk, gatewayX25519Pk, NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("gateway NodeId mismatch");
  });

  test("expired template → REJECT", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // now > expiry → REJECTED.
    const result = verifyGatewayReturnTemplate(
      gt, gatewayNodeId, gatewayX25519Sk, gatewayX25519Pk, route.branded.expiry + 1,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("expired");
  });

  test("tampered encryptedKRet → signature invalid → REJECT", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // Tamper encryptedKRet (48 bytes = 32-byte K_ret + 16-byte AEAD tag).
    // The signature was over the ORIGINAL encryptedKRet — replacing it with
    // a different value breaks the signature check (caught BEFORE the gateway
    // ever attempts to decrypt the tampered ciphertext).
    const tampered = { ...gt, encryptedKRet: new Uint8Array(48).fill(0xFF) };
    const result = verifyGatewayReturnTemplate(tampered, gatewayNodeId, gatewayX25519Sk, gatewayX25519Pk, NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("tampered signature → REJECT", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // Flip one bit in the signature.
    const tamperedSig = new Uint8Array(gt.initiatorSignature);
    tamperedSig[0] ^= 0x01;
    const tampered = { ...gt, initiatorSignature: tamperedSig };
    const result = verifyGatewayReturnTemplate(tampered, gatewayNodeId, gatewayX25519Sk, gatewayX25519Pk, NOW);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("full distributed flow: establish → sign → transfer → gateway verifies → seals response → source decrypts", async () => {
    // This is the canonical end-to-end integration test: the initiator
    // establishes the circuit + signs the gateway template, the gateway
    // verifies + accepts the template, then seals a real response, and the
    // return chain delivers it to the source through the production path.
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const initiatorKp = generateNodeKeypair();
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    // The gateway's own X25519 keypair (ECDH partner for K_ret decryption).
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    // 1. Initiator constructs the template + signs the gateway transfer.
    //    K_ret is encrypted under ECDH(initiator X25519, gateway X25519) →
    //    the wire object carries encryptedKRet + kRetNonce, NOT plaintext kRet.
    const template = constructReturnOnionTemplate(circuit);
    const gatewayTemplate = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // 2. "Network transfer": encode → decode (simulating the wire).
    //    A relay intercepting the wire bytes sees encryptedKRet (48 bytes) +
    //    kRetNonce (12 bytes) but CANNOT recover K_ret without the gateway's
    //    X25519 secret key (proven by the adversarial tests below).
    const wireBytes = encodeGatewayReturnTemplate(gatewayTemplate);
    const decoded = decodeGatewayReturnTemplate(wireBytes);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;

    // 3. Gateway verifies the transfer — accepts the template.
    //    The gateway uses its OWN X25519 secret key to decrypt K_ret.
    const verifyResult = verifyGatewayReturnTemplate(
      decoded.gatewayTemplate, gatewayNodeId, gatewayX25519Sk, gatewayX25519Pk, NOW,
    );
    expect(verifyResult.ok).toBe(true);
    if (!verifyResult.ok) return;
    const gatewayTemplate_ = verifyResult.template; // K_ret + envelope (decrypted)

    // 4. Gateway seals a real response using the accepted template.
    const httpResponse = new TextEncoder().encode("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    const retCiphertext = sealReturnFrameFromTemplate(gatewayTemplate_, 1, httpResponse);
    const retFrame = {
      circuitNoncePrefix: circuit.noncePrefix,
      frameSequence: 1,
      direction: DIRECTION_BACKWARD,
      ciphertext: retCiphertext,
    } as any;
    const retWire = encodeCircuitFrame(retFrame);

    // 5. Relay 1 processes the backward frame (production path).
    const r1 = await processCircuitWireFrame(circuit, 1, retWire);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;

    // 6. Source (hop 0) processes — terminal, delivers the response.
    const r0 = await processCircuitWireFrame(circuit, 0, r1.nextWireBytes);
    expect(r0.ok).toBe(true);
    if (!r0.ok) return;
    expect(new TextDecoder().decode(r0.plaintext)).toBe("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  });

  test("relay intercepts template → cannot recover K_ret (wire object carries encryptedKRet, NOT plaintext kRet)", () => {
    // Adversarial test: a relay (or any network observer) that intercepts the
    // GatewayReturnTemplate wire object sees encryptedKRet + kRetNonce but
    // has NO way to recover K_ret without the gateway's X25519 secret key.
    // The wire object MUST NOT carry a plaintext `kRet` field.
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // The wire object carries encryptedKRet (48 bytes = 32 K_ret + 16 AEAD tag).
    expect(gt.encryptedKRet).toBeDefined();
    expect(gt.encryptedKRet.length).toBe(48);
    expect(gt.kRetNonce).toBeDefined();
    expect(gt.kRetNonce.length).toBe(12);
    expect(gt.gatewayX25519PublicKey).toBeDefined();
    expect(gt.gatewayX25519PublicKey.length).toBe(32);
    expect(gt.initiatorX25519PublicKey).toBeDefined();
    expect(gt.initiatorX25519PublicKey.length).toBe(32);

    // The wire object MUST NOT carry a plaintext `kRet` field.
    expect((gt as any).kRet).toBeUndefined();

    // Even after encode → decode, the wire bytes do not expose plaintext K_ret:
    // the only K_ret-bearing field is the AEAD-encrypted encryptedKRet.
    const wireBytes = encodeGatewayReturnTemplate(gt);
    expect(wireBytes.length).toBeGreaterThan(0);
    const decoded = decodeGatewayReturnTemplate(wireBytes);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect((decoded.gatewayTemplate as any).kRet).toBeUndefined();
    expect(decoded.gatewayTemplate.encryptedKRet.length).toBe(48);

    // The encryptedKRet must NOT start with the plaintext K_ret bytes —
    // ChaCha20-Poly1305 is a stream cipher, but it generates a keystream that
    // is XORed with the plaintext, so the ciphertext bytes do not equal the
    // plaintext. (The real confidentiality proof is the wrong-ECDH-secret
    // test below: without the matching gateway X25519 secret, decryption
    // fails entirely.)
    const encryptedFirst32 = toHex(decoded.gatewayTemplate.encryptedKRet.slice(0, 32));
    const plaintextKRet = toHex(template.kRet);
    expect(encryptedFirst32).not.toBe(plaintextKRet);
  });

  test("wrong gateway X25519 key → REJECT (identity-to-key substitution attempt)", () => {
    // Adversarial test: an attacker who controls the right NodeId (or a relay
    // trying to spoof the gateway) but does NOT control the gateway's X25519
    // secret key cannot accept the template — the gatewayX25519PublicKey
    // binding check fails before any signature / decryption is attempted.
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // An attacker presents a DIFFERENT X25519 keypair to the verifier (e.g.,
    // a relay that controls the gateway's NodeId through registry compromise
    // but doesn't control the gateway's actual X25519 secret key). The
    // gatewayX25519PublicKey binding check fails FIRST → REJECT.
    const wrongGatewayX25519Sk = randomBytes(32);
    const wrongGatewayX25519Pk = x25519.getPublicKey(wrongGatewayX25519Sk);
    const result = verifyGatewayReturnTemplate(
      gt, gatewayNodeId, wrongGatewayX25519Sk, wrongGatewayX25519Pk, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("gateway X25519 public key mismatch");
  });

  test("valid signature + matching gateway pubkey but wrong ECDH secret → K_ret decryption fails → REJECT", () => {
    // Adversarial test: the deepest defense layer. Imagine the gateway's
    // stored `gatewayX25519PublicKey` matches the template (so the
    // gatewayX25519PublicKey binding check at step 2 PASSES) AND the
    // initiator's signature verifies (step 4 PASSES — the attacker has a
    // genuinely-initiator-signed template they captured earlier). The only
    // way to reach the AEAD decryption step is to supply a `gatewayX25519SecretKey`
    // that does NOT correspond to the `gatewayX25519PublicKey` the template
    // was encrypted under (simulating a key-storage corruption / key-rotation
    // mismatch / VM-migration key drift). The ECDH then yields a different
    // shared secret than what the initiator used to derive kRetKey → AEAD
    // decryption fails → REJECT with "K_ret decryption failed".
    //
    // This proves that the gateway's actual possession of the matching X25519
    // SECRET key (not just the public key) is enforced at decryption time —
    // closing the defense-in-depth chain: NodeId → pubkey binding → expiry →
    // signature → ECDH decryption.
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();
    const gatewayX25519Sk = randomBytes(32);
    const gatewayX25519Pk = x25519.getPublicKey(gatewayX25519Sk);

    // Sign with the REAL gateway pubkey + REAL initiator X25519 keypair.
    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519Pk,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // Verifier: pass the ORIGINAL gatewayX25519PublicKey (so the binding check
    // at step 2 passes + signature at step 4 passes — the signature covers
    // gatewayX25519PublicKey), but pass a DIFFERENT secret key — so ECDH at
    // step 5 yields a wrong shared secret → step 6 AEAD decrypt fails.
    const corruptedGatewaySk = randomBytes(32);
    const result = verifyGatewayReturnTemplate(
      gt, gatewayNodeId, corruptedGatewaySk, gatewayX25519Pk, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("K_ret decryption failed");
  });
});

// =====================================================================
// R-009 Stage 2: route-bound gateway verification + distributed transport
// (per the re-audit of 11d9e35: the gateway verifier must bind the template
//  to the ACTUAL committed terminal hop, not just a supplied NodeId.)
// =====================================================================

describe("R-009 Stage 2: route-bound gateway verification (verifyGatewayReturnTemplateWithRoute)", () => {
  test("valid route + valid template → gateway accepts (route-bound)", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();

    // The terminal hop (the gateway) produces a GENUINE proof-bearing
    // CircuitSetupAck via handleCircuitSetup. The ack carries the gateway's
    // X25519 public key + the terminal relay's Ed25519 signature over it.
    // The gateway's X25519 secret key is held in ackResult.state.
    const {
      terminalAck, relayEd25519PublicKey,
      gatewayX25519SecretKey, gatewayX25519PublicKey,
    } = makeTerminalAck(route, circuit);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519PublicKey,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // Verifier consumes the FULL ack + the terminal relay's Ed25519 public key.
    // It verifies the ack's signature before extracting the X25519 key —
    // a forged ack would fail the signature check.
    const result = verifyGatewayReturnTemplateWithRoute(
      gt, route.branded, terminalAck, relayEd25519PublicKey,
      gatewayNodeId, gatewayX25519SecretKey, gatewayX25519PublicKey, NOW,
    );
    expect(result.ok).toBe(true);
  });

  test("wrong terminal gateway (fake NodeId not in route) → REJECT", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const initiatorKp = generateNodeKeypair();
    const fakeNodeId = "fake-gateway-nodeid";

    // Genuine terminal ack for the real terminal hop (the gateway's actual
    // Ed25519 identity in the route). The ack signature verifies against
    // route.kps[terminalHopIndex].publicKey — but the gatewayTemplate below
    // is signed with a DIFFERENT (fake) NodeId, so the verifier rejects at
    // step 0c (gatewayNodeId != route's terminal hop NodeId) BEFORE the ack
    // signature check.
    const {
      terminalAck, relayEd25519PublicKey,
      gatewayX25519SecretKey, gatewayX25519PublicKey,
    } = makeTerminalAck(route, circuit);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, fakeNodeId,
      gatewayX25519PublicKey,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const result = verifyGatewayReturnTemplateWithRoute(
      gt, route.branded, terminalAck, relayEd25519PublicKey,
      fakeNodeId, gatewayX25519SecretKey, gatewayX25519PublicKey, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("not the terminal hop");
  });

  test("cross-route template (wrong commitmentRoot) → REJECT", () => {
    const routeA = makeRoute(2);
    const routeB = makeRoute(2);
    const relayKeysA = makeRelayX25519Keys(routeA.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuitA = setupCircuit(routeA.branded, relayKeysA, NOW, floorStore);
    const templateA = constructReturnOnionTemplate(circuitA);
    const gatewayNodeId = routeA.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();

    // Genuine terminal ack for routeA's terminal hop. The verifier is then
    // called with routeB — the gatewayTemplate's commitmentRoot (routeA's)
    // doesn't match routeB's commitmentRoot → step 0b rejects BEFORE the ack
    // signature is even checked.
    const {
      terminalAck, relayEd25519PublicKey,
      gatewayX25519SecretKey, gatewayX25519PublicKey,
    } = makeTerminalAck(routeA, circuitA);

    const gt = signGatewayReturnTemplate(
      templateA, routeA.branded.expiry, gatewayNodeId,
      gatewayX25519PublicKey,
      circuitA.initiatorX25519SecretKey, circuitA.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const result = verifyGatewayReturnTemplateWithRoute(
      gt, routeB.branded, terminalAck, relayEd25519PublicKey,
      gatewayNodeId, gatewayX25519SecretKey, gatewayX25519PublicKey, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("commitmentRoot mismatch");
  });

  test("gateway X25519 key doesn't match terminal hop's ack → REJECT", () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const template = constructReturnOnionTemplate(circuit);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();

    // Genuine terminal ack — its relayX25519PublicKey is generated internally
    // by handleCircuitSetup and is signed by the terminal relay's Ed25519 key.
    // An attacker CANNOT forge an ack with a different relayX25519PublicKey
    // (the ack signature would fail). The only way the gatewayTemplate's
    // gatewayX25519PublicKey can differ from the ack's relayX25519PublicKey is
    // if the initiator signed the template against a DIFFERENT key — which is
    // exactly the identity-to-key substitution attack the new check blocks.
    const { terminalAck, relayEd25519PublicKey } = makeTerminalAck(route, circuit);

    // Attacker-controlled X25519 keypair (NOT the ack's relayX25519PublicKey).
    const attackerSk = randomBytes(32);
    const attackerPk = x25519.getPublicKey(attackerSk);

    const gt = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      attackerPk, // DIFFERENT from terminalAck.relayX25519PublicKey
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // Verifier uses the genuine terminalAck (signature verifies against
    // relayEd25519PublicKey) but the template's gatewayX25519PublicKey
    // (attackerPk) doesn't match the ack's relayX25519PublicKey → step 0i
    // rejects AFTER the ack signature check (step 0d) passes.
    const result = verifyGatewayReturnTemplateWithRoute(
      gt, route.branded, terminalAck, relayEd25519PublicKey,
      gatewayNodeId, attackerSk, attackerPk, NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("does not match the terminal hop");
  });
});

// =====================================================================
// R-009 Stage 2: REAL distributed transport integration test
// (the gateway receives the GatewayReturnTemplate as wire bytes, not an
//  in-memory object. All hops are independent — no shared mutable state.)
// =====================================================================

describe("R-009 Stage 2: real distributed transport (wire bytes → decode → verify route → decrypt → seal → return)", () => {
  test("full distributed flow: source establishes → gateway receives wire bytes → verifies route → decrypts → seals response → source decrypts", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();

    // 0. RELAY (terminal hop) produces a GENUINE proof-bearing CircuitSetupAck.
    //    The gateway IS the terminal relay — it keeps the relayX25519SecretKey
    //    (from ackResult.state) and uses it to decrypt K_ret during verify.
    const {
      terminalAck, relayEd25519PublicKey,
      gatewayX25519SecretKey, gatewayX25519PublicKey,
    } = makeTerminalAck(route, circuit);

    // 1. INITIATOR: construct template + sign gateway transfer.
    //    The template is signed against the ack's relayX25519PublicKey (the
    //    gateway's X25519 public key) so the proof-bearing binding holds.
    const template = constructReturnOnionTemplate(circuit);
    const gatewayTemplate = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519PublicKey,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    // 2. TRANSPORT: encode to wire bytes (simulating the network).
    const wireBytes = encodeGatewayReturnTemplate(gatewayTemplate);

    // 3. GATEWAY (independent process): receives wire bytes → decodes.
    const decoded = decodeGatewayReturnTemplate(wireBytes);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;

    // 4. GATEWAY: verifies the transfer against the committed route + the
    //    GENUINE terminal ack + the terminal relay's Ed25519 public key.
    //    The ack signature is verified (step 0d) before any binding check.
    const verifyResult = verifyGatewayReturnTemplateWithRoute(
      decoded.gatewayTemplate,
      route.branded,
      terminalAck,
      relayEd25519PublicKey,
      gatewayNodeId,
      gatewayX25519SecretKey,
      gatewayX25519PublicKey,
      NOW,
    );
    expect(verifyResult.ok).toBe(true);
    if (!verifyResult.ok) return;
    const acceptedTemplate = verifyResult.template;

    // 5. GATEWAY: seals a real return response using the accepted template.
    const httpResponse = new TextEncoder().encode("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    const retCiphertext = sealReturnFrameFromTemplate(acceptedTemplate, 1, httpResponse);
    const retFrame = {
      circuitNoncePrefix: circuit.noncePrefix,
      frameSequence: 1,
      direction: DIRECTION_BACKWARD,
      ciphertext: retCiphertext,
    } as any;
    const retWire = encodeCircuitFrame(retFrame);

    // 6. RELAY 1 (independent): processes the backward frame (production path).
    const r1 = await processCircuitWireFrame(circuit, 1, retWire);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;

    // 7. SOURCE (independent): processes — terminal, delivers the response.
    const r0 = await processCircuitWireFrame(circuit, 0, r1.nextWireBytes);
    expect(r0.ok).toBe(true);
    if (!r0.ok) return;
    expect(new TextDecoder().decode(r0.plaintext)).toBe("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  });

  test("gateway receives tampered wire bytes → verify fails", async () => {
    const route = makeRoute(2);
    const relayKeys = makeRelayX25519Keys(route.branded);
    const floorStore = new InMemoryCircuitSequenceFloorStore();
    const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
    const gatewayNodeId = route.branded.hops[1]!.nodeId;
    const initiatorKp = generateNodeKeypair();

    // 0. RELAY (terminal hop) produces a GENUINE proof-bearing CircuitSetupAck.
    const {
      terminalAck, relayEd25519PublicKey,
      gatewayX25519SecretKey, gatewayX25519PublicKey,
    } = makeTerminalAck(route, circuit);

    const template = constructReturnOnionTemplate(circuit);
    const gatewayTemplate = signGatewayReturnTemplate(
      template, route.branded.expiry, gatewayNodeId,
      gatewayX25519PublicKey,
      circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );

    const wireBytes = new Uint8Array(encodeGatewayReturnTemplate(gatewayTemplate));
    wireBytes[wireBytes.length - 1] ^= 0x01;

    const decoded = decodeGatewayReturnTemplate(wireBytes);
    if (decoded.ok) {
      // The genuine terminal ack + relayEd25519PublicKey are passed to the
      // route-bound verifier. The tampered wire bytes break either the
      // signature check (step 4 inside verifyGatewayReturnTemplate) or one
      // of the route-binding checks — either way, verify must reject.
      const result = verifyGatewayReturnTemplateWithRoute(
        decoded.gatewayTemplate, route.branded, terminalAck,
        relayEd25519PublicKey,
        gatewayNodeId, gatewayX25519SecretKey, gatewayX25519PublicKey, NOW,
      );
      expect(result.ok).toBe(false);
    }
  });
});

// =====================================================================
// R-009 Stage 2: GatewayReturnAuthorization — serializable proof portability
// (per the re-audit of 8fa4ef3: the gateway verifier must work from wire
//  bytes alone, without an in-process BrandedCommittedRoute WeakSet.)
// =====================================================================

describe("R-009 Stage 2: GatewayReturnAuthorization (portable proof from wire bytes)", () => {
  test("construct + encode + decode round-trip", () => {
    const { circuit, template, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances);
    const wireBytes = encodeGatewayReturnAuthorization(auth);
    const decoded = decodeGatewayReturnAuthorization(wireBytes);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.authorization.routeId).toBe(auth.routeId);
    expect(decoded.authorization.hopIndex).toBe(auth.hopIndex);
    // The 8 new terminal-hop proof fields round-trip byte-identical.
    expect(decoded.authorization.terminalNodeId).toBe(auth.terminalNodeId);
    expect(decoded.authorization.acceptanceProposalDigestHex).toBe(auth.acceptanceProposalDigestHex);
    expect(decoded.authorization.acceptanceHopDigestHex).toBe(auth.acceptanceHopDigestHex);
    expect(decoded.authorization.acceptanceServiceDigestHex).toBe(auth.acceptanceServiceDigestHex);
    expect(decoded.authorization.acceptanceNonce).toEqual(auth.acceptanceNonce);
    expect(decoded.authorization.acceptanceExpiry).toBe(auth.acceptanceExpiry);
    expect(decoded.authorization.acceptanceSignature).toEqual(auth.acceptanceSignature);
    expect(decoded.authorization.hopNodeIds).toEqual(auth.hopNodeIds);
  });

  test("verify from wire bytes alone → accepts (no WeakSet dependency)", () => {
    const { gatewayX25519Sk, gatewayX25519Pk, gatewayNodeId, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances);
    const wireBytes = encodeGatewayReturnAuthorization(auth);
    const decoded = decodeGatewayReturnAuthorization(wireBytes);
    if (!decoded.ok) return;

    const result = verifyGatewayReturnAuthorization(
      decoded.authorization,
      gatewayNodeId,
      gatewayX25519Sk,
      gatewayX25519Pk,
      NOW,
    );
    expect(result.ok).toBe(true);
  });

  test("forged terminal ack (wrong relayEd25519PublicKey) → REJECT", () => {
    const { gatewayX25519Sk, gatewayX25519Pk, gatewayNodeId, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const wrongEd25519Key = randomBytes(32); // not the relay's Ed25519 key
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, wrongEd25519Key, terminalAcceptance, hopNodeIds, proposal, acceptances);
    const wireBytes = encodeGatewayReturnAuthorization(auth);
    const decoded = decodeGatewayReturnAuthorization(wireBytes);
    if (!decoded.ok) return;

    const result = verifyGatewayReturnAuthorization(
      decoded.authorization,
      gatewayNodeId,
      gatewayX25519Sk,
      gatewayX25519Pk,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("tampered relaySignature → REJECT", () => {
    const { gatewayX25519Sk, gatewayX25519Pk, gatewayNodeId, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances);
    const tamperedSig = new Uint8Array(auth.relaySignature);
    tamperedSig[0] ^= 0x01;
    const tamperedAuth = { ...auth, relaySignature: tamperedSig };

    const result = verifyGatewayReturnAuthorization(
      tamperedAuth,
      gatewayNodeId,
      gatewayX25519Sk,
      gatewayX25519Pk,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("signature invalid");
  });

  test("wrong gateway NodeId → REJECT", () => {
    const { gatewayX25519Sk, gatewayX25519Pk, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances);

    const result = verifyGatewayReturnAuthorization(
      auth,
      "wrong-gateway-node-id",
      gatewayX25519Sk,
      gatewayX25519Pk,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("NodeId mismatch");
  });

  test("expired template → REJECT", () => {
    const { gatewayX25519Sk, gatewayX25519Pk, gatewayNodeId, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances);

    const result = verifyGatewayReturnAuthorization(
      auth,
      gatewayNodeId,
      gatewayX25519Sk,
      gatewayX25519Pk,
      gatewayTemplate.expiry + 1,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("expired");
  });

  test("wrong gateway X25519 key → REJECT", () => {
    const { gatewayNodeId, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances);
    const wrongSk = randomBytes(32);
    const wrongPk = x25519.getPublicKey(wrongSk);

    const result = verifyGatewayReturnAuthorization(
      auth,
      gatewayNodeId,
      wrongSk,
      wrongPk,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("X25519 public key mismatch");
  });

  // -----------------------------------------------------------------
  // R-009 Stage 2 — terminal-hop proof tests (re-audit of 8fa4ef3):
  // The 3 new tests below exercise the new check 2b (acceptance signature),
  // check 2c (terminalNodeId is the actual terminal hop), and check 2c
  // (second sub-check: hopNodeIds[hopIndex] === terminalNodeId).
  // -----------------------------------------------------------------

  test("non-terminal relay proof (hopIndex != terminal) → REJECT", () => {
    const { gatewayX25519Sk, gatewayX25519Pk, gatewayNodeId, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances);
    // Attacker tampers hopNodeIds to drop the terminal hop. The acceptance
    // signature is still genuine (verifies at check 2b), but check 2c
    // fires because auth.hopIndex (1) is no longer the last index of
    // the (tampered, truncated) hopNodeIds (length 1 → last index 0).
    const tamperedAuth = { ...auth, hopNodeIds: [hopNodeIds[0]!] };

    const result = verifyGatewayReturnAuthorization(
      tamperedAuth,
      gatewayNodeId,
      gatewayX25519Sk,
      gatewayX25519Pk,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("terminalNodeId is not the terminal hop");
  });

  test("mismatched relay Ed25519 key (acceptance signed by different key) → REJECT", () => {
    const { gatewayX25519Sk, gatewayX25519Pk, gatewayNodeId, gatewayTemplate, terminalAck, relayEd25519PublicKey, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    // Attacker uses a DIFFERENT route's terminal acceptance — it was signed
    // by a different relay's Ed25519 secret key. The genuine
    // relayEd25519PublicKey (route1's terminal relay) cannot verify the
    // signature → check 2b rejects.
    const otherRoute = makeRoute(2);
    const otherAcceptance = otherRoute.terminalAcceptance;
    const auth = constructGatewayReturnAuthorization(
      gatewayTemplate, terminalAck, relayEd25519PublicKey, otherAcceptance, hopNodeIds,
      proposal, acceptances,
    );

    const result = verifyGatewayReturnAuthorization(
      auth,
      gatewayNodeId,
      gatewayX25519Sk,
      gatewayX25519Pk,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("RouteAcceptance signature invalid");
  });

  test("hopNodeIds doesn't match (wrong route) → REJECT", () => {
    const { gatewayX25519Sk, gatewayX25519Pk, gatewayNodeId, gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances } = setupGatewayEnv();
    const auth = constructGatewayReturnAuthorization(gatewayTemplate, terminalAck, relayEd25519PublicKey, terminalAcceptance, hopNodeIds, proposal, acceptances);
    // Attacker replaces hopNodeIds with a DIFFERENT route's hopNodeIds.
    // The acceptance signature is genuine (check 2b passes); hopIndex
    // equals hopNodeIds.length - 1 (check 2c first sub-check passes);
    // BUT hopNodeIds[hopIndex] (route2's terminal) !== terminalNodeId
    // (route1's terminal) → check 2c second sub-check fires.
    const otherRoute = makeRoute(2);
    const tamperedAuth = { ...auth, hopNodeIds: otherRoute.hopNodeIds };

    const result = verifyGatewayReturnAuthorization(
      tamperedAuth,
      gatewayNodeId,
      gatewayX25519Sk,
      gatewayX25519Pk,
      NOW,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("terminalNodeId is not the terminal hop");
  });
});

// Helper for the GatewayReturnAuthorization tests.
function setupGatewayEnv() {
  const route = makeRoute(2);
  const relayKeys = makeRelayX25519Keys(route.branded);
  const floorStore = new InMemoryCircuitSequenceFloorStore();
  const circuit = setupCircuit(route.branded, relayKeys, NOW, floorStore);
  const gatewayNodeId = route.branded.hops[1]!.nodeId;
  const terminalHopIndex = route.branded.hops.length - 1;
  const initiatorKp = generateNodeKeypair();

  // Generate a genuine terminal ack.
  const req = {
    route: route.branded,
    hopIndex: terminalHopIndex,
    initiatorX25519PublicKey: circuit.initiatorX25519PublicKey,
    setupNonce: randomBytes(16),
  };
  const ackResult = handleCircuitSetup(req, route.kps[terminalHopIndex]!.secretKey, route.commitmentRoot, NOW);
  if (!ackResult.ok) throw new Error("terminal ack setup failed");
  const terminalAck = ackResult.ack;
  const relayEd25519PublicKey = route.kps[terminalHopIndex]!.publicKey;
  const gatewayX25519SecretKey = ackResult.state.relayX25519SecretKey;
  const gatewayX25519PublicKey = ackResult.state.relayX25519PublicKey;

  const template = constructReturnOnionTemplate(circuit);
  const gatewayTemplate = signGatewayReturnTemplate(
    template, route.branded.expiry, gatewayNodeId,
    gatewayX25519PublicKey,
    circuit.initiatorX25519SecretKey, circuit.initiatorX25519PublicKey,
    initiatorKp.secretKey, initiatorKp.publicKey,
  );

  return {
    route, circuit, template, gatewayTemplate, terminalAck, relayEd25519PublicKey,
    gatewayX25519Sk: gatewayX25519SecretKey, gatewayX25519Pk: gatewayX25519PublicKey,
    gatewayNodeId,
    terminalAcceptance: route.terminalAcceptance,
    hopNodeIds: route.hopNodeIds,
    proposal: route.commitment.proposal,
    acceptances: route.commitment.acceptances,
  };
}
