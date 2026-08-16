/**
 * POST /api/sharenet/protocol/node-id
 * Generates a fresh Ed25519 keypair + derived NodeId.
 *
 * Per spec/02 §2.1: NodeId = "node:" + hex(BLAKE2b-256("sharenet-node-id-v1" || pubKey))
 *
 * The generated secret key is returned ONCE to the caller. The server
 * does NOT persist it (this is a stateless key-generation utility for the
 * playground). Real nodes keep their secret key locally and never send it
 * to anyone.
 */

import { json, withErrors } from "@/lib/http/api-helpers";
import { generateNodeKeypair, bytesToHex } from "@reference/identity/keys";

export const POST = withErrors(async () => {
  const kp = generateNodeKeypair();
  return json({
    ok: true,
    nodeId: kp.nodeId,
    publicKeyHex: bytesToHex(kp.publicKey),
    secretKeyHex: bytesToHex(kp.secretKey),
    warning:
      "The secret key is shown ONCE and never persisted by the server. " +
      "Store it locally and never transmit it. Anyone with this secret key " +
      "can sign advertisements as this NodeId (spec/02 §3).",
    derivation: {
      domain: "sharenet-node-id-v1",
      algorithm: "BLAKE2b-256",
      formula: 'NodeId = "node:" + hex(BLAKE2b-256("sharenet-node-id-v1" || Ed25519PublicKey))',
      reference: "ADR-0003, spec/02 §2.1",
    },
  });
});
