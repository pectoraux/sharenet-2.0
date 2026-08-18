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
  sealForwardFrame,
  openFrame,
  DIRECTION_FORWARD,
  type CircuitFrame,
} from "@reference/circuit/frame";
import { forwardFrame } from "@reference/circuit/forwarding";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;

// FIXED seeds for reproducibility (frozen vector).
const INIT_SK = new Uint8Array(32).fill(0x01);
const RELAY0_SK = new Uint8Array(32).fill(0x02);
const RELAY1_SK = new Uint8Array(32).fill(0x03);

// Build a deterministic 2-hop route (gives us commitmentRoot).
const ctx = makeGenuineBrandedRouteHelper(2, NOW);
const commitmentRoot = ctx.branded.commitmentRoot;
const initSk = INIT_SK;
const initPk = x25519.getPublicKey(initSk);

const relay0Pk = x25519.getPublicKey(RELAY0_SK);
const relay1Pk = x25519.getPublicKey(RELAY1_SK);

// Derive per-hop keys from FIXED ECDH (deterministic).
const sharedSecret0 = x25519.getSharedSecret(initSk, relay0Pk);
const sharedSecret1 = x25519.getSharedSecret(initSk, relay1Pk);
const keys0 = deriveHopKeys(sharedSecret0, 0, commitmentRoot);
const keys1 = deriveHopKeys(sharedSecret1, 1, commitmentRoot);

const noncePrefix = deriveNoncePrefix(commitmentRoot);
const circuitId = deriveCircuitId(commitmentRoot, initPk);

// Construct a MINIMAL ActiveCircuit manually (NO setupCircuit — that generates
// random keys). The frame functions only use: commitmentRoot, noncePrefix,
// hops[].forwardingKey/returnKey.
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

const plaintext = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

// --- Generate all vectors ---
const testFrame: CircuitFrame = {
  circuitNoncePrefix: noncePrefix,
  frameSequence: 1,
  direction: DIRECTION_FORWARD,
  ciphertext: new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]),
};
const encoded = encodeCircuitFrame(testFrame);
const decoded = decodeCircuitFrame(encoded);
const malformedDecoded = decodeCircuitFrame(new Uint8Array([0x00, 0x01, 0x02]));

const sealed = sealForwardFrame(circuit, 1, plaintext);
const sealedEncoded = encodeCircuitFrame(sealed);

const open0 = openFrame(circuit, 0, sealed);
const open0PayloadHex = open0.ok ? toHex(open0.payload) : "";

const fwd0 = forwardFrame(circuit, 0, sealed);
const fwd0NextFrameEncodedHex = (fwd0.ok && !fwd0.terminal) ? toHex(encodeCircuitFrame(fwd0.nextFrame)) : "";

let fwd1PlaintextHex = "";
if (fwd0.ok && !fwd0.terminal) {
  const fwd1 = forwardFrame(circuit, 1, fwd0.nextFrame);
  if (fwd1.ok && fwd1.terminal) fwd1PlaintextHex = toHex(fwd1.plaintext);
}

const tampered = { ...sealed, ciphertext: new Uint8Array(sealed.ciphertext).map((b, i) => i === 0 ? b ^ 0x01 : b) };
const tamperedResult = openFrame(circuit, 0, tampered);

const wrongCircuitFrame = { ...sealed, circuitNoncePrefix: new Uint8Array(8).fill(0xff) };
const wrongCircuitResult = openFrame(circuit, 0, wrongCircuitFrame);

const output = {
  id: "V-CIRCUIT-FRAME-001",
  status: "frozen",
  spec: "spec/08-circuits.md §4.6, spec/00 §24, GATE-06, R-009",
  adr: "adr/0017-protocol-freeze-reconciliation.md",
  description: "CircuitFrame wire object: canonical CBOR encode/decode (ADR-0004 integer-keyed map), sealForwardFrame (onion-encrypt using the frozen R-008 crypto substrate), openFrame (AEAD-peel one layer), forwardFrame (relay forwarding). Per spec/08 §4.6: the frame carries circuit_nonce_prefix (8 bytes), frame_sequence (u32 BE), direction (0x01 forward / 0x02 backward), and the onion ciphertext. The AEAD AD is domain || commitment_root || frame_sequence || direction (FROZEN per R-008). R-009 builds the packet protocol ON TOP of the frozen R-008 crypto substrate — no crypto primitives are modified.",
  sharedInputs: {
    commitmentRootHex: toHex(commitmentRoot),
    noncePrefixHex: toHex(noncePrefix),
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
    plaintextHex: toHex(plaintext),
    plaintextAscii: new TextDecoder().decode(plaintext),
    referenceNow: NOW,
  },
  vectors: [
    {
      name: "encode-frame",
      description: "Encode a CircuitFrame with known fields to canonical CBOR (ADR-0004 integer-keyed map).",
      input: {
        circuitNoncePrefixHex: toHex(noncePrefix),
        frameSequence: 1,
        direction: DIRECTION_FORWARD,
        ciphertextHex: toHex(testFrame.ciphertext),
      },
      expected: { encodedHex: toHex(encoded) },
    },
    {
      name: "decode-frame",
      description: "Decode the canonical CBOR back to a CircuitFrame + validate field sizes.",
      input: { encodedHex: toHex(encoded) },
      expected: {
        ok: true,
        frameSequence: 1,
        direction: DIRECTION_FORWARD,
        circuitNoncePrefixHex: toHex(noncePrefix),
        ciphertextHex: toHex(testFrame.ciphertext),
      },
    },
    {
      name: "decode-malformed",
      description: "Decode invalid CBOR bytes → ok=false (malformed frame rejected before any crypto).",
      input: { encodedHex: toHex(new Uint8Array([0x00, 0x01, 0x02])) },
      expected: { ok: false },
    },
    {
      name: "seal-forward-frame",
      description: "sealForwardFrame: 2-hop onion-encrypt the plaintext at seq=1 → CircuitFrame, then encode to wire.",
      input: { frameSequence: 1, plaintextHex: toHex(plaintext) },
      expected: {
        circuitNoncePrefixHex: toHex(noncePrefix),
        frameSequence: 1,
        direction: DIRECTION_FORWARD,
        sealedEncodedHex: toHex(sealedEncoded),
        ciphertextLen: sealed.ciphertext.length,
      },
    },
    {
      name: "open-frame-hop0",
      description: "openFrame at hop 0: peel the outermost layer (forwardingKey0). isTerminal=false (hop 1 is terminal for a 2-hop circuit).",
      input: { frame: "sealedForwardFrame@seq1" },
      expected: {
        ok: true,
        isTerminal: false,
        payloadHex: open0PayloadHex,
        payloadLen: open0.ok ? open0.payload.length : 0,
      },
    },
    {
      name: "forward-frame-hop0",
      description: "forwardFrame at hop 0: produces nextFrame (same header + inner ciphertext) for hop 1.",
      input: { frame: "sealedForwardFrame@seq1" },
      expected: {
        ok: true,
        terminal: false,
        nextFrameEncodedHex: fwd0NextFrameEncodedHex,
        nextFrameCiphertextLen: (fwd0.ok && !fwd0.terminal) ? fwd0.nextFrame.ciphertext.length : 0,
      },
    },
    {
      name: "forward-frame-hop1-terminal",
      description: "forwardFrame at hop 1 (terminal hop): delivers the original application plaintext.",
      input: { frame: "nextFrame@hop0" },
      expected: {
        ok: true,
        terminal: true,
        plaintextHex: fwd1PlaintextHex,
        plaintextAscii: new TextDecoder().decode(plaintext),
      },
    },
    {
      name: "tampered-ciphertext-rejected",
      description: "openFrame with a single bit flipped in the ciphertext → AEAD authentication fails (ok=false). Per R-008 frozen ordering: the floor is NOT advanced.",
      input: { frame: "tampered@seq1" },
      expected: { ok: false, reasonContains: "AEAD authentication failed" },
    },
    {
      name: "wrong-circuit-rejected",
      description: "openFrame with a mismatched circuit_nonce_prefix → rejected (frame does not belong to this circuit).",
      input: { frame: "wrongNoncePrefix@seq1" },
      expected: { ok: false, reasonContains: "nonce_prefix mismatch" },
    },
  ],
  verification: {
    runner: "ts-vector-runner.ts:verifyCircuitFrameVector + py_vector_verifier.py:verify_circuit_frame_vector",
    notes: "All vectors use fixed seeds (initSk=0x01*32, relay0Sk=0x02*32, relay1Sk=0x03*32) for reproducibility. The forwardingKeys are derived from deterministic X25519 ECDH + HKDF (salt=commitment_root). The verifier reconstructs a minimal ActiveCircuit from sharedInputs and tests the frame primitives. R-008 crypto substrate (buildNonce, buildCircuitFrameAD, encryptPayload, decryptPayload) is NOT modified — R-009 builds on top.",
  },
};

console.log(JSON.stringify(output, null, 2));
