/**
 * R-009 Stage 2: Generate V-CIRCUIT-FRAME-002 conformance vectors
 * for the backward (return) onion.
 *
 * Uses the same fixed seeds as V-CIRCUIT-FRAME-001 (deterministic).
 */
import { bytesToHex } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex, canonicalEncode } from "@reference/encoding/cbor";
import {
  deriveCircuitId,
  deriveHopKeys,
  deriveNoncePrefix,
} from "@reference/circuit/circuit";
import {
  encodeCircuitFrame,
  decodeCircuitFrame,
  sealReturnFrame,
  openFrame,
  DIRECTION_BACKWARD,
} from "@reference/circuit/frame";
import { forwardFrame } from "@reference/circuit/forwarding";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;
const INIT_SK = new Uint8Array(32).fill(0x01);
const RELAY0_SK = new Uint8Array(32).fill(0x02);
const RELAY1_SK = new Uint8Array(32).fill(0x03);

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

const plaintext = new TextEncoder().encode("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

// Vector: seal a return frame
const sealed = sealReturnFrame(circuit, 1, plaintext);
const sealedEncoded = encodeCircuitFrame(sealed);

// Vector: openFrame at hop 1 (NOT terminal for backward — terminal is hop 0)
const open1 = openFrame(circuit, 1, sealed);
const open1PayloadHex = open1.ok ? toHex(open1.payload) : "";

// Vector: forwardFrame at hop 1 → produces nextFrame for hop 0
const fwd1 = forwardFrame(circuit, 1, sealed);
const fwd1NextFrameEncodedHex = (fwd1.ok && !fwd1.terminal) ? toHex(encodeCircuitFrame(fwd1.nextFrame)) : "";

// Vector: forwardFrame at hop 0 (terminal) → delivers plaintext
let fwd0PlaintextHex = "";
if (fwd1.ok && !fwd1.terminal) {
  const fwd0 = forwardFrame(circuit, 0, fwd1.nextFrame);
  if (fwd0.ok && fwd0.terminal) fwd0PlaintextHex = toHex(fwd0.plaintext);
}

// Vector: tampered return ciphertext → AEAD fails
const tampered = { ...sealed, ciphertext: new Uint8Array(sealed.ciphertext).map((b, i) => i === 0 ? b ^ 0x01 : b) };
const tamperedResult = openFrame(circuit, 1, tampered);

const output = {
  id: "V-CIRCUIT-FRAME-002",
  status: "frozen",
  spec: "spec/08-circuits.md §4.6a, §4.6, R-009 Stage 2",
  adr: "adr/0019-receiver-local-replay-protection.md",
  description: "CircuitFrame backward (return) onion: sealReturnFrame (gateway onion-encrypts using returnKeys, mirror of forward onion), openFrame (relay AEAD-peels one returnKey layer), forwardFrame (relay forwarding backward). Per spec/08 §4.6a: backward frames use direction=0x02 + returnKey. The terminal hop for BACKWARD is hop 0 (the source). Built ON the frozen R-008 crypto substrate + the R-009 Stage 1 receiver-local replay namespace (commitmentRoot, hopIndex, direction) — forward + backward floors are independent by construction.",
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
      name: "seal-return-frame",
      description: "sealReturnFrame: 2-hop return-onion encrypt the plaintext at seq=1 (gateway → source). Uses returnKey1 (outermost) then returnKey0 (innermost).",
      input: { frameSequence: 1, plaintextHex: toHex(plaintext) },
      expected: {
        circuitNoncePrefixHex: toHex(noncePrefix),
        frameSequence: 1,
        direction: DIRECTION_BACKWARD,
        sealedEncodedHex: toHex(sealedEncoded),
        ciphertextLen: sealed.ciphertext.length,
      },
    },
    {
      name: "open-frame-hop1-backward",
      description: "openFrame at hop 1 (backward): peel the outermost returnKey layer. isTerminal=false (terminal for backward is hop 0).",
      input: { frame: "sealedReturnFrame@seq1" },
      expected: {
        ok: true,
        isTerminal: false,
        payloadHex: open1PayloadHex,
        payloadLen: open1.ok ? open1.payload.length : 0,
      },
    },
    {
      name: "forward-frame-hop1-backward",
      description: "forwardFrame at hop 1 (backward): produces nextFrame for hop 0 (the source).",
      input: { frame: "sealedReturnFrame@seq1" },
      expected: {
        ok: true,
        terminal: false,
        nextFrameEncodedHex: fwd1NextFrameEncodedHex,
        nextFrameCiphertextLen: (fwd1.ok && !fwd1.terminal) ? fwd1.nextFrame.ciphertext.length : 0,
      },
    },
    {
      name: "forward-frame-hop0-backward-terminal",
      description: "forwardFrame at hop 0 (backward, terminal): delivers the original return plaintext to the source.",
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
      description: "openFrame (backward) with a single bit flipped in the ciphertext → AEAD authentication fails (ok=false).",
      input: { frame: "tamperedReturn@seq1" },
      expected: { ok: false, reasonContains: "AEAD authentication failed" },
    },
  ],
  verification: {
    runner: "ts-vector-runner.ts:verifyCircuitFrameVector + py_vector_verifier.py:verify_circuit_frame_vector",
    notes: "Same fixed seeds as V-CIRCUIT-FRAME-001. The return-onion is the mirror of the forward onion: returnKey1 (outermost) → returnKey0 (innermost). The terminal hop for backward is hop 0 (the source). The receiver-local replay floor (root, hopIndex, direction) handles forward + backward independently — a forward + backward frame at the same seq are both accepted.",
  },
};

console.log(JSON.stringify(output, null, 2));
