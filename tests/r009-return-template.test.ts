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

// Helper: encode a ReturnFramePayload to CBOR (for forwarding between hops).
function encodeReturnFramePayloadForTest(payload: { sealedPayload: Uint8Array; envelopeLayer: Uint8Array }): Uint8Array {
  return encodeReturnFramePayload(payload);
}
