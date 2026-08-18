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
  gatewayReturnTemplateSigningPayload,
  GATEWAY_RETURN_TEMPLATE_DOMAIN,
} from "@reference/circuit/return-template";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

const NOW = 1786876545;
const INIT_SK = new Uint8Array(32).fill(0x01);
const RELAY0_SK = new Uint8Array(32).fill(0x02);
const RELAY1_SK = new Uint8Array(32).fill(0x03);
const K_RET = new Uint8Array(32).fill(0xAA);
// Fixed initiator Ed25519 keypair for deterministic vectors.
const INIT_ED25519_SK = new Uint8Array(32).fill(0x04);
const INIT_ED25519_PK = ed25519.getPublicKey(INIT_ED25519_SK);

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
  INIT_ED25519_SK, INIT_ED25519_PK,
);

const encoded = encodeGatewayReturnTemplate(gatewayTemplate);
const decoded = decodeGatewayReturnTemplate(encoded);
const verified = verifyGatewayReturnTemplate(gatewayTemplate, gatewayNodeId, NOW);

// Negative: wrong gateway
const wrongGateway = verifyGatewayReturnTemplate(gatewayTemplate, "wrong-node-id", NOW);

// Negative: expired
const expiredResult = verifyGatewayReturnTemplate(gatewayTemplate, gatewayNodeId, expiry + 1);

// Negative: tampered kRet
const tamperedTemplate = { ...gatewayTemplate, kRet: new Uint8Array(32).fill(0xFF) };
const tamperedResult = verifyGatewayReturnTemplate(tamperedTemplate, gatewayNodeId, NOW);

// Negative: tampered signature
const tamperedSig = new Uint8Array(gatewayTemplate.initiatorSignature);
tamperedSig[0] ^= 0x01;
const tamperedSigTemplate = { ...gatewayTemplate, initiatorSignature: tamperedSig };
const tamperedSigResult = verifyGatewayReturnTemplate(tamperedSigTemplate, gatewayNodeId, NOW);

// Signing payload
const payload = gatewayReturnTemplateSigningPayload(
  circuitId, commitmentRoot, noncePrefix, K_RET, template.envelope, expiry, gatewayNodeId,
);

const output = {
  id: "V-CIRCUIT-GATEWAY-TEMPLATE-001",
  status: "frozen",
  spec: "spec/08-circuits.md §4.8a, R-009 Stage 2",
  adr: "adr/0021-return-onion-template-distribution.md",
  description: "GatewayReturnTemplate: the authenticated transfer wire object. The initiator signs the template binding it to (circuitId, commitmentRoot, noncePrefix, kRet, envelope, expiry, gatewayNodeId). The gateway verifies the signature + checks its own NodeId + expiry. Only the intended terminal gateway can accept the template. Domain: SHARENET/CIRCUIT/RETURN/TEMPLATE/1.",
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
    initiatorEd25519SecretKeyHex: toHex(INIT_ED25519_SK),
    initiatorEd25519PubHex: toHex(INIT_ED25519_PK),
    gatewayNodeId,
    expiry,
    referenceNow: NOW,
  },
  vectors: [
    {
      name: "sign-gateway-template",
      description: "signGatewayReturnTemplate: initiator signs the template binding (circuitId, commitmentRoot, noncePrefix, kRet, envelope, expiry, gatewayNodeId).",
      input: {},
      expected: {
        gatewayNodeId,
        expiry,
        initiatorEd25519PubHex: toHex(INIT_ED25519_PK),
        signatureHex: toHex(gatewayTemplate.initiatorSignature),
        encodedHex: toHex(encoded),
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
      description: "verifyGatewayReturnTemplate: gateway verifies the signature + checks NodeId + expiry → accepts, extracts ReturnOnionTemplate.",
      input: {},
      expected: { ok: true },
    },
    {
      name: "wrong-gateway-rejected",
      description: "verifyGatewayReturnTemplate with wrong gatewayNodeId → REJECT (only the intended gateway can accept).",
      input: { expectedGatewayNodeId: "wrong-node-id" },
      expected: { ok: false, reasonContains: "gateway NodeId mismatch" },
    },
    {
      name: "expired-template-rejected",
      description: "verifyGatewayReturnTemplate with now > expiry → REJECT.",
      input: { now: expiry + 1 },
      expected: { ok: false, reasonContains: "expired" },
    },
    {
      name: "tampered-kret-rejected",
      description: "verifyGatewayReturnTemplate with tampered kRet → signature invalid → REJECT.",
      input: { tamperedField: "kRet" },
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
    notes: "Fixed seeds (initSk=0x01*32, relay0Sk=0x02*32, relay1Sk=0x03*32, kRet=0xAA*32, initEd25519Sk=0x04*32). The GatewayReturnTemplate is the authenticated transfer wire object — the initiator signs it, the gateway verifies the signature + checks its own NodeId + expiry. Only the intended terminal gateway can accept the template.",
  },
};

console.log(JSON.stringify(output, null, 2));
