import { bytesToHex } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  deriveCircuitId,
  deriveHopKeys,
  deriveNoncePrefix,
} from "@reference/circuit/circuit";
import {
  encodeCircuitFrame,
  decodeCircuitFrame,
  DIRECTION_BACKWARD,
  type CircuitFrame,
} from "@reference/circuit/frame";
import { forwardFrame } from "@reference/circuit/forwarding";
import {
  constructReturnOnionTemplate,
  sealReturnFrameFromTemplate,
  type ReturnOnionTemplate,
} from "@reference/circuit/return-template";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;
const INIT_SK = new Uint8Array(32).fill(0x01);
const RELAY0_SK = new Uint8Array(32).fill(0x02);
const RELAY1_SK = new Uint8Array(32).fill(0x03);
// Fixed K_ret for deterministic vectors.
const K_RET = new Uint8Array(32).fill(0xAA);

const ctx = makeGenuineBrandedRouteHelper(2, NOW);
const commitmentRoot = ctx.branded.commitmentRoot;
const initSk = INIT_SK;
const initPk = x25519.getPublicKey(initSk);
const relay0Pk = x25519.getPublicKey(RELAY0_SK);
const relay1Pk = x25519.getPublicKey(RELAY1_SK);
const relayKeys = [
  { hopIndex: 0, nodeId: ctx.branded.hops[0]!.nodeId, x25519PublicKey: relay0Pk },
  { hopIndex: 1, nodeId: ctx.branded.hops[1]!.nodeId, x25519PublicKey: relay1Pk },
];

const sharedSecret0 = x25519.getSharedSecret(initSk, relay0Pk);
const sharedSecret1 = x25519.getSharedSecret(initSk, relay1Pk);
const keys0 = deriveHopKeys(sharedSecret0, 0, commitmentRoot);
const keys1 = deriveHopKeys(sharedSecret1, 1, commitmentRoot);
const noncePrefix = deriveNoncePrefix(commitmentRoot, initPk);
const circuitId = deriveCircuitId(commitmentRoot, initPk);

const circuit = {
  circuitId,
  circuitIdHex: toHex(circuitId),
  routeId: ctx.branded.routeId,
  hops: [
    { hopIndex: 0, nodeId: ctx.branded.hops[0]!.nodeId, forwardingKey: keys0.forwardingKey, returnKey: keys0.returnKey, relayX25519PublicKey: relay0Pk },
    { hopIndex: 1, nodeId: ctx.branded.hops[1]!.nodeId, forwardingKey: keys1.forwardingKey, returnKey: keys1.returnKey, relayX25519PublicKey: relay1Pk },
  ],
  initiatorX25519PublicKey: initPk,
  initiatorX25519SecretKey: initSk,
  expiry: ctx.branded.expiry,
  establishedAt: NOW,
  replayGuard: { checkAndRecord: () => ({ ok: true }), getHighestSeq: () => 0n, getSequenceFloor: () => 0n },
  noncePrefix,
  commitmentRoot,
  floorStore: { getFloor: async () => 0n, checkAndAdvance: async () => ({ ok: true }) },
} as any;

const template = constructReturnOnionTemplate(circuit, K_RET);
const plaintext = new TextEncoder().encode("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

// Gateway seals the return response using the template (production path).
const ciphertext = sealReturnFrameFromTemplate(template, 1, plaintext);
const backwardFrame: CircuitFrame = {
  circuitNoncePrefix: circuit.noncePrefix,
  frameSequence: 1,
  direction: DIRECTION_BACKWARD,
  ciphertext,
};
const wireBytes = encodeCircuitFrame(backwardFrame);
const wireHex = toHex(wireBytes);

// forwardFrame at hop 1 (backward) — peels returnKey_1 from the envelope.
const fwd1 = forwardFrame(circuit, 1, backwardFrame);
const fwd1NextFrameHex = (fwd1.ok && !fwd1.terminal) ? toHex(encodeCircuitFrame(fwd1.nextFrame)) : "";

// forwardFrame at hop 0 (backward, terminal) — recovers K_ret + decrypts.
let fwd0PlaintextHex = "";
if (fwd1.ok && !fwd1.terminal) {
  const fwd0 = forwardFrame(circuit, 0, fwd1.nextFrame);
  if (fwd0.ok && fwd0.terminal) fwd0PlaintextHex = toHex(fwd0.plaintext);
}

// Tampered return frame → AEAD fails.
const tamperedFrame = { ...backwardFrame, ciphertext: new Uint8Array(ciphertext).map((b, i) => i === 0 ? b ^ 0x01 : b) };
const tamperedResult = forwardFrame(circuit, 1, tamperedFrame);

const output = {
  id: "V-CIRCUIT-FRAME-002",
  status: "frozen",
  spec: "spec/08-circuits.md §4.6a, §4.8, R-009 Stage 2",
  adr: "adr/0021-return-onion-template-distribution.md",
  description: "CircuitFrame backward (return) via the distributed return-onion template model. The gateway seals the response with K_ret + attaches the opaque envelope. forwardFrame routes BACKWARD through peelReturnEnvelopeLayer (peels returnKey from the envelope, NOT from the frame ciphertext). Terminal hop (hop 0 = source) recovers K_ret + decrypts. This is the CANONICAL BACKWARD wire format (CBOR { sealedPayload, envelopeLayer }) — there is no competing backward construction.",
  sharedInputs: {
    commitmentRootHex: toHex(commitmentRoot),
    noncePrefixHex: toHex(noncePrefix),
    circuitIdHex: toHex(circuitId),
    initiatorX25519SecretKeyHex: toHex(initSk),
    initiatorX25519PubHex: toHex(initPk),
    relay0X25519SecretKeyHex: toHex(RELAY0_SK),
    relay0X25519PubHex: toHex(relay0Pk),
    relay1X25519SecretKeyHex: toHex(RELAY1_SK),
    relay1X25519PubHex: toHex(relay1Pk),
    forwardingKey0Hex: toHex(keys0.forwardingKey),
    forwardingKey1Hex: toHex(keys1.forwardingKey),
    returnKey0Hex: toHex(keys0.returnKey),
    returnKey1Hex: toHex(keys1.returnKey),
    kRetHex: toHex(K_RET),
    plaintextHex: toHex(plaintext),
    plaintextAscii: new TextDecoder().decode(plaintext),
    referenceNow: NOW,
  },
  vectors: [
    {
      name: "seal-return-from-template",
      description: "Gateway seals return response using the ReturnOnionTemplate → backward CircuitFrame (CBOR { sealedPayload, envelope }).",
      input: { frameSequence: 1, plaintextHex: toHex(plaintext) },
      expected: {
        wireHex,
        ciphertextLen: ciphertext.length,
        direction: DIRECTION_BACKWARD,
      },
    },
    {
      name: "forward-frame-hop1-backward",
      description: "forwardFrame at hop 1 (backward): peels returnKey_1 from the envelope → nextFrame for hop 0. NOT terminal.",
      input: { frame: "backwardFrame@seq1" },
      expected: {
        ok: true,
        terminal: false,
        nextFrameHex: fwd1NextFrameHex,
      },
    },
    {
      name: "forward-frame-hop0-backward-terminal",
      description: "forwardFrame at hop 0 (backward, terminal): recovers K_ret + decrypts the sealedPayload → response plaintext.",
      input: { frame: "nextFrame@hop1" },
      expected: {
        ok: true,
        terminal: true,
        plaintextHex: fwd0PlaintextHex,
        plaintextAscii: new TextDecoder().decode(plaintext),
      },
    },
    {
      name: "tampered-return-ciphertext-rejected",
      description: "forwardFrame (backward) with a tampered ciphertext → AEAD envelope peel fails (ok=false).",
      input: { frame: "tampered@seq1" },
      expected: { ok: false, reasonContains: "AEAD" },
    },
  ],
  verification: {
    runner: "ts-vector-runner.ts:verifyCircuitFrameVector + py_vector_verifier.py:verify_circuit_frame_vector",
    notes: "Same fixed seeds as V-CIRCUIT-FRAME-001. The backward frame uses the distributed return-onion template model (CBOR { sealedPayload, envelopeLayer }) — the CANONICAL backward wire format. forwardFrame routes BACKWARD through peelReturnEnvelopeLayer. The gateway holds K_ret (from the template) — NOT the raw returnKeys.",
  },
};

console.log(JSON.stringify(output, null, 2));
