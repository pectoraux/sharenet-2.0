import { bytesToHex } from "@reference/identity/keys";
import { ed25519 } from "@noble/curves/ed25519.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  deriveCircuitId,
  deriveHopKeys,
  deriveNoncePrefix,
} from "@reference/circuit/circuit";
import {
  constructReturnOnionTemplate,
  signGatewayReturnTemplate,
  verifyGatewayReturnTemplate,
  encodeGatewayReturnTemplate,
  decodeGatewayReturnTemplate,
} from "@reference/circuit/return-template";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;
const INIT_SK = new Uint8Array(32).fill(0x01);
const RELAY0_SK = new Uint8Array(32).fill(0x02);
const RELAY1_SK = new Uint8Array(32).fill(0x03);
const K_RET = new Uint8Array(32).fill(0xAA);
const INIT_ED25519_SK = new Uint8Array(32).fill(0x04);
const INIT_ED25519_PK = ed25519.getPublicKey(INIT_ED25519_SK);
// Gateway X25519 keypair (the relay's ephemeral key for the circuit).
const GW_X25519_SK = new Uint8Array(32).fill(0x05);
const GW_X25519_PK = x25519.getPublicKey(GW_X25519_SK);

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
const gatewayNodeId = ctx.branded.hops[1]!.nodeId;
const expiry = ctx.branded.expiry;

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
  expiry,
  establishedAt: NOW,
  replayGuard: { checkAndRecord: () => ({ ok: true }), getHighestSeq: () => 0n, getSequenceFloor: () => 0n },
  noncePrefix,
  commitmentRoot,
  floorStore: { getFloor: async () => 0n, checkAndAdvance: async () => ({ ok: true }) },
} as any;

const template = constructReturnOnionTemplate(circuit, K_RET);
const gatewayTemplate = signGatewayReturnTemplate(
  template, expiry, gatewayNodeId,
  GW_X25519_PK,  // gateway X25519 public key
  initSk, initPk,  // initiator X25519 keypair
  INIT_ED25519_SK, INIT_ED25519_PK,  // initiator Ed25519 keypair
);

const encoded = encodeGatewayReturnTemplate(gatewayTemplate);
const decoded = decodeGatewayReturnTemplate(encoded);
const verified = verifyGatewayReturnTemplate(gatewayTemplate, gatewayNodeId, GW_X25519_SK, GW_X25519_PK, NOW);

// Negative: wrong gateway NodeId
const wrongNodeId = verifyGatewayReturnTemplate(gatewayTemplate, "wrong-node-id", GW_X25519_SK, GW_X25519_PK, NOW);

// Negative: expired
const expiredResult = verifyGatewayReturnTemplate(gatewayTemplate, gatewayNodeId, GW_X25519_SK, GW_X25519_PK, expiry + 1);

// Negative: wrong gateway X25519 key (identity-to-key substitution)
const wrongKeySk = new Uint8Array(32).fill(0x06);
const wrongKeyPk = x25519.getPublicKey(wrongKeySk);
const wrongKeyResult = verifyGatewayReturnTemplate(gatewayTemplate, gatewayNodeId, wrongKeySk, wrongKeyPk, NOW);

// Negative: tampered encryptedKRet
const tamperedTemplate = { ...gatewayTemplate, encryptedKRet: new Uint8Array(48).fill(0xFF) };
const tamperedResult = verifyGatewayReturnTemplate(tamperedTemplate, gatewayNodeId, GW_X25519_SK, GW_X25519_PK, NOW);

// Negative: tampered signature
const tamperedSig = new Uint8Array(gatewayTemplate.initiatorSignature);
tamperedSig[0] ^= 0x01;
const tamperedSigTemplate = { ...gatewayTemplate, initiatorSignature: tamperedSig };
const tamperedSigResult = verifyGatewayReturnTemplate(tamperedSigTemplate, gatewayNodeId, GW_X25519_SK, GW_X25519_PK, NOW);

const output = {
  id: "V-CIRCUIT-GATEWAY-TEMPLATE-001",
  status: "frozen",
  spec: "spec/08-circuits.md §4.8a, R-009 Stage 2",
  adr: "adr/0021-return-onion-template-distribution.md",
  description: "GatewayReturnTemplate: the CONFIDENTIAL + authenticated transfer wire object. K_ret is encrypted to the gateway's X25519 public key (NOT plaintext). The initiator signs the complete binding including encryptedKRet + gatewayX25519PublicKey. The gateway verifies the signature + checks its own NodeId + X25519 public key + expiry, then decrypts K_ret via ECDH.",
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
    gatewayX25519SecretKeyHex: toHex(GW_X25519_SK),
    gatewayX25519PubHex: toHex(GW_X25519_PK),
    initiatorEd25519SecretKeyHex: toHex(INIT_ED25519_SK),
    initiatorEd25519PubHex: toHex(INIT_ED25519_PK),
    gatewayNodeId,
    expiry,
    referenceNow: NOW,
  },
  vectors: [
    {
      name: "sign-gateway-template",
      description: "signGatewayReturnTemplate: initiator encrypts K_ret to the gateway's X25519 key + signs the complete binding.",
      input: {},
      expected: {
        gatewayNodeId,
        expiry,
        initiatorEd25519PubHex: toHex(INIT_ED25519_PK),
        gatewayX25519PubHex: toHex(GW_X25519_PK),
        initiatorX25519PubHex: toHex(initPk),
        encryptedKRetLen: 48,
        kRetNonceLen: 12,
        encodedLen: encoded.length,
      },
    },
    {
      name: "decode-gateway-template",
      description: "decodeGatewayReturnTemplate: decode the canonical CBOR wire bytes back to the GatewayReturnTemplate.",
      input: { encodedHex: toHex(encoded) },
      expected: { ok: true },
    },
    {
      name: "verify-gateway-template",
      description: "verifyGatewayReturnTemplate: gateway verifies signature + NodeId + X25519 key + expiry → decrypts K_ret → accepts.",
      input: {},
      expected: { ok: true },
    },
    {
      name: "wrong-gateway-rejected",
      description: "verifyGatewayReturnTemplate with wrong gatewayNodeId → REJECT.",
      input: { expectedGatewayNodeId: "wrong-node-id" },
      expected: { ok: false, reasonContains: "gateway NodeId mismatch" },
    },
    {
      name: "wrong-gateway-key-rejected",
      description: "verifyGatewayReturnTemplate with wrong gatewayX25519PublicKey → REJECT (identity-to-key substitution).",
      input: {},
      expected: { ok: false, reasonContains: "X25519 public key mismatch" },
    },
    {
      name: "expired-template-rejected",
      description: "verifyGatewayReturnTemplate with now > expiry → REJECT.",
      input: { now: expiry + 1 },
      expected: { ok: false, reasonContains: "expired" },
    },
    {
      name: "tampered-encrypted-kret-rejected",
      description: "verifyGatewayReturnTemplate with tampered encryptedKRet → signature invalid → REJECT.",
      input: { tamperedField: "encryptedKRet" },
      expected: { ok: false, reasonContains: "signature invalid" },
    },
    {
      name: "tampered-signature-rejected",
      description: "verifyGatewayReturnTemplate with a flipped signature byte → REJECT.",
      input: { tamperedField: "signature" },
      expected: { ok: false, reasonContains: "signature invalid" },
    },
  ],
  verification: {
    runner: "ts-vector-runner.ts:verifyCircuitGatewayTemplateVector + py_vector_verifier.py:verify_circuit_gateway_template_vector",
    notes: "Fixed seeds for reproducibility. K_ret is ENCRYPTED to the gateway's X25519 public key — NOT plaintext. The wire object carries encryptedKRet (48 bytes) + kRetNonce (12 bytes). The gateway decrypts K_ret via ECDH(gateway_x25519_secret, initiator_x25519_public) + HKDF + ChaCha20-Poly1305.",
  },
};

console.log(JSON.stringify(output, null, 2));
