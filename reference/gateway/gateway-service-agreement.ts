/**
 * ShareNet 2.0 — GatewayServiceAgreement (spec/09 §3.1).
 *
 * The canonical dual-signed wire object that establishes a gateway
 * service session between a gateway and a source. Both parties sign
 * the same body with domain-separated signing payloads.
 *
 * This is distinct from the routing-internal `ServiceAgreement` (in
 * service-negotiation.ts), which is an unsigned digest input used for
 * route construction. `GatewayServiceAgreement` is the wire-level
 * agreement that crosses the gateway↔source trust boundary.
 */

import { signMessage, verifySignature } from "../identity/keys";
import { randomBytes } from "@noble/hashes/utils.js";
import { canonicalEncode, toHex } from "../encoding/cbor";

// -----------------------------------------------------------------------
// Constants (FROZEN per spec/09 §3.1)
// -----------------------------------------------------------------------

export const GATEWAY_SVC_AGREEMENT_DOMAIN_GATEWAY = "sharenet-gateway-agreement-gateway-v1";
export const GATEWAY_SVC_AGREEMENT_DOMAIN_SOURCE = "sharenet-gateway-agreement-source-v1";

// -----------------------------------------------------------------------
// GatewayServiceAgreement
// -----------------------------------------------------------------------

export interface GatewayServiceAgreementBody {
  agreementVersion: number;
  gatewayId: string;
  sourceId: string;
  circuitId: string;
  serviceClass: string;
  destinationScope: string;
  maxBytes: number;
  maxDuration: number;
  startsAt: number;
  expiresAt: number;
  agreementNonce: Uint8Array;
}

export interface GatewayServiceAgreement extends GatewayServiceAgreementBody {
  gatewaySignature: Uint8Array;
  sourceSignature: Uint8Array;
}

/**
 * Canonical CBOR encoding of the agreement body (keys 1–11).
 * The signatures are NOT included in the body — they are computed over
 * domain || body.
 */
export function encodeGatewayServiceAgreementBody(body: GatewayServiceAgreementBody): Uint8Array {
  const m = new Map<number, unknown>([
    [1, body.agreementVersion],
    [2, body.gatewayId],
    [3, body.sourceId],
    [4, body.circuitId],
    [5, body.serviceClass],
    [6, body.destinationScope],
    [7, body.maxBytes],
    [8, body.maxDuration],
    [9, body.startsAt],
    [10, body.expiresAt],
    [11, body.agreementNonce],
  ]);
  return canonicalEncode(m);
}

/**
 * Compute the gateway's signing payload: domain || body.
 */
export function gatewayServiceAgreementGatewaySigningPayload(body: GatewayServiceAgreementBody): Uint8Array {
  const domain = new TextEncoder().encode(GATEWAY_SVC_AGREEMENT_DOMAIN_GATEWAY);
  const bodyBytes = encodeGatewayServiceAgreementBody(body);
  const out = new Uint8Array(domain.length + bodyBytes.length);
  out.set(domain, 0);
  out.set(bodyBytes, domain.length);
  return out;
}

/**
 * Compute the source's signing payload: domain || body.
 */
export function gatewayServiceAgreementSourceSigningPayload(body: GatewayServiceAgreementBody): Uint8Array {
  const domain = new TextEncoder().encode(GATEWAY_SVC_AGREEMENT_DOMAIN_SOURCE);
  const bodyBytes = encodeGatewayServiceAgreementBody(body);
  const out = new Uint8Array(domain.length + bodyBytes.length);
  out.set(domain, 0);
  out.set(bodyBytes, domain.length);
  return out;
}

/**
 * Create a dual-signed GatewayServiceAgreement.
 */
export function createGatewayServiceAgreement(
  body: Omit<GatewayServiceAgreementBody, "agreementNonce">,
  gatewaySecretKey: Uint8Array,
  sourceSecretKey: Uint8Array,
): GatewayServiceAgreement {
  const fullBody: GatewayServiceAgreementBody = {
    ...body,
    agreementNonce: randomBytes(16),
  };
  const gatewayPayload = gatewayServiceAgreementGatewaySigningPayload(fullBody);
  const sourcePayload = gatewayServiceAgreementSourceSigningPayload(fullBody);
  const gatewaySignature = signMessage(gatewaySecretKey, gatewayPayload);
  const sourceSignature = signMessage(sourceSecretKey, sourcePayload);
  return { ...fullBody, gatewaySignature, sourceSignature };
}

/**
 * Verify a GatewayServiceAgreement — both signatures must be valid.
 */
export function verifyGatewayServiceAgreement(
  agreement: GatewayServiceAgreement,
  gatewayPublicKey: Uint8Array,
  sourcePublicKey: Uint8Array,
): { ok: true } | { ok: false; reason: string } {
  const body: GatewayServiceAgreementBody = {
    agreementVersion: agreement.agreementVersion,
    gatewayId: agreement.gatewayId,
    sourceId: agreement.sourceId,
    circuitId: agreement.circuitId,
    serviceClass: agreement.serviceClass,
    destinationScope: agreement.destinationScope,
    maxBytes: agreement.maxBytes,
    maxDuration: agreement.maxDuration,
    startsAt: agreement.startsAt,
    expiresAt: agreement.expiresAt,
    agreementNonce: agreement.agreementNonce,
  };
  const gatewayPayload = gatewayServiceAgreementGatewaySigningPayload(body);
  if (!verifySignature(gatewayPublicKey, gatewayPayload, agreement.gatewaySignature)) {
    return { ok: false, reason: "gateway signature invalid" };
  }
  const sourcePayload = gatewayServiceAgreementSourceSigningPayload(body);
  if (!verifySignature(sourcePublicKey, sourcePayload, agreement.sourceSignature)) {
    return { ok: false, reason: "source signature invalid" };
  }
  return { ok: true };
}
