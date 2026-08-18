import { bytesToHex } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  deriveCircuitId,
  deriveHopKeys,
  deriveNoncePrefix,
} from "@reference/circuit/circuit";
import {
  constructReturnOnionTemplate,
  sealReturnFrameFromTemplate,
  peelReturnEnvelopeLayer,
  decryptReturnPayload,
  encodeReturnFramePayload,
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

// Vector: construct template
const envelopeHex = toHex(template.envelope);

// Vector: gateway seals return using template
const ciphertext = sealReturnFrameFromTemplate(template, 1, plaintext);
const ciphertextHex = toHex(ciphertext);

// Vector: relay 1 peels one envelope layer
const peel1 = peelReturnEnvelopeLayer(circuit, 1, ciphertext);
const innerCiphertextHex = peel1.ok ? toHex(encodeReturnFramePayload(peel1.innerPayload)) : "";

// Vector: source (hop 0) peels final layer → K_ret + decrypts
let plaintextHex = "";
let kRetHex = "";
if (peel1.ok) {
  const peel0 = peelReturnEnvelopeLayer(circuit, 0, encodeReturnFramePayload(peel1.innerPayload));
  if (peel0.ok && peel0.isTerminal && peel0.kRet) {
    kRetHex = toHex(peel0.kRet);
    const dec = decryptReturnPayload(peel0.kRet, circuit.noncePrefix, circuit.commitmentRoot, 1, peel0.innerPayload.sealedPayload);
    if (dec.ok) plaintextHex = toHex(dec.plaintext);
  }
}

// Vector: tampered envelope → fails
const tampered = new Uint8Array(ciphertext);
tampered[tampered.length - 1] ^= 0x01;
const tamperedResult = peelReturnEnvelopeLayer(circuit, 1, tampered);

const output = {
  id: "V-CIRCUIT-RETURN-TEMPLATE-001",
  status: "frozen",
  spec: "spec/08-circuits.md §5a, R-009 Stage 2",
  adr: "adr/0021-return-onion-template-distribution.md",
  description: "ReturnOnionTemplate: the initiator constructs a layered encrypted envelope wrapping K_ret (circuit-scoped return key) during setup. The gateway holds K_ret + the opaque envelope (NOT the per-hop returnKeys). To send a return response, the gateway seals the payload with K_ret and attaches the envelope; each relay peels one returnKey layer; the source recovers K_ret and decrypts. Model A (layered encrypted return template) — the gateway can return traffic without holding raw returnKeys.",
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
    returnKey0Hex: toHex(keys0.returnKey),
    returnKey1Hex: toHex(keys1.returnKey),
    kRetHex: toHex(K_RET),
    plaintextHex: toHex(plaintext),
    plaintextAscii: new TextDecoder().decode(plaintext),
    referenceNow: NOW,
  },
  vectors: [
    {
      name: "construct-template",
      description: "constructReturnOnionTemplate: N-layer-deep envelope wrapping K_ret. Envelope = AEAD(returnKey_0, K_ret) then AEAD(returnKey_1, env_0).",
      input: {},
      expected: {
        kRetHex: toHex(K_RET),
        envelopeHex,
        envelopeLen: template.envelope.length,
      },
    },
    {
      name: "seal-return-from-template",
      description: "sealReturnFrameFromTemplate: gateway seals the response with K_ret + attaches the envelope → backward frame ciphertext (CBOR { sealedPayload, envelope }).",
      input: { frameSequence: 1, plaintextHex: toHex(plaintext) },
      expected: {
        ciphertextHex,
        ciphertextLen: ciphertext.length,
      },
    },
    {
      name: "peel-envelope-hop1",
      description: "peelReturnEnvelopeLayer at hop 1: peels returnKey_1 from the envelope → inner { sealedPayload, innerEnvelope }. NOT terminal (terminal is hop 0).",
      input: { ciphertextHex },
      expected: {
        ok: true,
        isTerminal: false,
        innerCiphertextHex,
      },
    },
    {
      name: "peel-envelope-hop0-terminal",
      description: "peelReturnEnvelopeLayer at hop 0 (terminal): peels returnKey_0 → recovers K_ret. K_ret matches the template's.",
      input: { innerCiphertextHex },
      expected: {
        ok: true,
        isTerminal: true,
        kRetHex,
      },
    },
    {
      name: "decrypt-return-payload",
      description: "decryptReturnPayload: source decrypts the sealedPayload with K_ret → original response plaintext.",
      input: { kRetHex, frameSequence: 1, sealedPayloadHex: "derived-from-peel" },
      expected: {
        ok: true,
        plaintextHex,
        plaintextAscii: new TextDecoder().decode(plaintext),
      },
    },
    {
      name: "tampered-envelope-rejected",
      description: "peelReturnEnvelopeLayer with a tampered envelope → AEAD fails (ok=false).",
      input: { tamperedCiphertextHex: toHex(tampered) },
      expected: {
        ok: false,
        reasonContains: "AEAD",
      },
    },
  ],
  verification: {
    runner: "ts-vector-runner.ts:verifyCircuitReturnTemplateVector + py_vector_verifier.py:verify_circuit_return_template_vector",
    notes: "Fixed seeds (initSk=0x01*32, relay0Sk=0x02*32, relay1Sk=0x03*32, kRet=0xAA*32) for reproducibility. The envelope is N AEAD layers deep (one per hop's returnKey), wrapping K_ret. The gateway holds K_ret + the opaque envelope — it does NOT hold the per-hop returnKeys.",
  },
};

console.log(JSON.stringify(output, null, 2));
