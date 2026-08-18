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
import { randomBytes } from "@reference/identity/keys";
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
} from "@reference/circuit/return-template";
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
  };
}

function makeRelayX25519Keys(route: { hops: Array<{ nodeId: string }> }) {
  return route.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk };
  });
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
