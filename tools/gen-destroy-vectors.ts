import { bytesToHex } from "@reference/identity/keys";
import { ed25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  signCircuitDestroy,
  verifyCircuitDestroy,
  encodeCircuitDestroy,
  decodeCircuitDestroy,
  DESTROYER_ROLE_INITIATOR,
  DESTROYER_ROLE_GATEWAY,
  DESTROY_REASON_OPERATOR_INITIATED,
  DESTROY_REASON_CIRCUIT_EXPIRED,
} from "@reference/circuit/destroy";
import { randomBytes } from "@noble/hashes/utils.js";

const NOW = 1786876545;
const EXPIRY = NOW + 3600;
const INIT_ED25519_SK = new Uint8Array(32).fill(0x10);
const INIT_ED25519_PK = ed25519.getPublicKey(INIT_ED25519_SK);
const GW_ED25519_SK = new Uint8Array(32).fill(0x20);
const GW_ED25519_PK = ed25519.getPublicKey(GW_ED25519_SK);

const circuitId = randomBytes(32);
const commitmentRoot = randomBytes(32);
const routeId = "route:" + toHex(commitmentRoot);

const destroy = signCircuitDestroy(
  circuitId, commitmentRoot,
  "initiator-node-id",
  DESTROYER_ROLE_INITIATOR,
  DESTROY_REASON_OPERATOR_INITIATED,
  NOW, EXPIRY,
  INIT_ED25519_SK, INIT_ED25519_PK,
);

const encoded = encodeCircuitDestroy(destroy);
const decoded = decodeCircuitDestroy(encoded);
const verified = verifyCircuitDestroy(destroy);

// Wrong signer
const wrongDestroy = { ...destroy, destroyerNodeId: "wrong-node-id" };
// Tampered reason
const tamperedReason = { ...destroy, destroyReason: 0x99 };
// Tampered nonce
const tamperedNonceDestroy = { ...destroy, destroyNonce: new Uint8Array(16).fill(0xFF) };

const output = {
  id: "V-CIRCUIT-DESTROY-001",
  status: "frozen",
  spec: "spec/08-circuits.md §6.5a, ADR-0022",
  description: "CircuitDestroy: authenticated circuit teardown wire object. The initiator or gateway signs a destroy message binding (circuitId, commitmentRoot, routeId, destroyerNodeId, destroyerRole, destroyReason, destroyNonce, issuedAt, expiry). Domain: SHARENET/CIRCUIT/DESTROY/1.",
  sharedInputs: {
    circuitIdHex: toHex(circuitId),
    commitmentRootHex: toHex(commitmentRoot),
    routeId,
    expiry: EXPIRY,
    referenceNow: NOW,
    initiatorEd25519SecretKeyHex: toHex(INIT_ED25519_SK),
    initiatorEd25519PubHex: toHex(INIT_ED25519_PK),
    gatewayEd25519SecretKeyHex: toHex(GW_ED25519_SK),
    gatewayEd25519PubHex: toHex(GW_ED25519_PK),
  },
  vectors: [
    {
      name: "sign-destroy",
      description: "signCircuitDestroy: initiator signs a destroy message.",
      input: {},
      expected: {
        destroyerNodeId: "initiator-node-id",
        destroyerRole: DESTROYER_ROLE_INITIATOR,
        destroyReason: DESTROY_REASON_OPERATOR_INITIATED,
        routeId,
        encodedLen: encoded.length,
      },
    },
    {
      name: "decode-destroy",
      description: "decodeCircuitDestroy: decode the canonical CBOR wire bytes.",
      input: { encodedHex: toHex(encoded) },
      expected: { ok: true },
    },
    {
      name: "verify-destroy",
      description: "verifyCircuitDestroy: verify the signature + routeId + role.",
      input: {},
      expected: { ok: true },
    },
    {
      name: "wrong-signer-rejected",
      description: "verifyCircuitDestroy with wrong destroyerNodeId → signature invalid (the signing payload includes destroyerNodeId).",
      input: {},
      expected: { ok: false, reasonContains: "signature invalid" },
    },
    {
      name: "tampered-reason-rejected",
      description: "verifyCircuitDestroy with tampered destroyReason → signature invalid.",
      input: {},
      expected: { ok: false, reasonContains: "signature invalid" },
    },
    {
      name: "tampered-nonce-rejected",
      description: "verifyCircuitDestroy with tampered destroyNonce → signature invalid.",
      input: {},
      expected: { ok: false, reasonContains: "signature invalid" },
    },
    {
      name: "invalid-role-rejected",
      description: "verifyCircuitDestroy with invalid destroyerRole (0x03) → REJECT.",
      input: {},
      expected: { ok: false, reasonContains: "invalid destroyerRole" },
    },
    {
      name: "wrong-routeId-rejected",
      description: "verifyCircuitDestroy with wrong routeId → REJECT.",
      input: {},
      expected: { ok: false, reasonContains: "routeId mismatch" },
    },
  ],
  verification: {
    runner: "ts-vector-runner.ts:verifyCircuitDestroyVector + py_vector_verifier.py:verify_circuit_destroy_vector",
    notes: "Fixed seeds for reproducibility. The CircuitDestroy wire object carries circuitId, commitmentRoot, destroyerNodeId, destroyerRole, destroyReason, destroyNonce, issuedAt, expiry, destroyerEd25519PublicKey, signature. Domain: SHARENET/CIRCUIT/DESTROY/1.",
  },
};

console.log(JSON.stringify(output, null, 2));
