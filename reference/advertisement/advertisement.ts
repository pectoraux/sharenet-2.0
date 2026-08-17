/**
 * NodeAdvertisement — signed, expiring, monotonic-sequence advertisement.
 *
 * Per spec/03-node-advertisements.md, ADR-0004, and ADR-0017 (protocol freeze):
 *
 *   Wire format = Canonical CBOR (RFC 8949 §4.2.2) over an INTEGER-keyed map.
 *
 *   Signature  = Ed25519.sign(
 *                  utf8("SHARENET/ADVERTISEMENT/1") || canonical_cbor(advertisement_without_signature),
 *                  secretKey
 *                )
 *
 * Per ADR-0017: the old domain tag "sharenet-advertisement-v1" is RETIRED.
 * The canonical domain tag is "SHARENET/ADVERTISEMENT/1".
 *
 * Verification (spec/03 §5) MUST check:
 *   1. signature                          — cryptographic validity
 *   2. identity binding                   — NodeId == deriveNodeId(signing_public_key)
 *   3. timestamp validity                 — within CLOCK_SKEW of "now"
 *   4. expiry                             — not in the past
 *   5. monotonic sequence                 — n > current floor (replay protection)
 *   6. canonical encoding                 — bytes are already in canonical form
 *
 * Per spec/14 §3 + ADR-0006: expiration MUST NOT reset the sequence floor.
 * A tombstone keeps the floor even after expiry to prevent replay.
 */

import { canonicalEncode, canonicalDecode, bytesEqual, toHex, fromHex } from "../encoding/cbor";
import {
  deriveNodeId,
  verifyNodeIdBinding,
  verifySignature,
  signMessage,
  isValidNodeIdFormat,
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  bytesToHex,
} from "../identity/keys";

/** Domain-separation tag for advertisement signatures. FROZEN per spec/14 §4 + ADR-0017. */
export const ADVERTISEMENT_SIGNATURE_DOMAIN = "SHARENET/ADVERTISEMENT/1";

/** Clock skew tolerance for timestamp validation (seconds). spec/03 §5.3. */
export const CLOCK_SKEW_SECONDS = 300;

/** Maximum advertisement TTL (seconds). spec/03 §5.4. */
export const MAX_ADVERTISEMENT_TTL_SECONDS = 86400;

/**
 * Network capability vocabulary. spec/00 §20.
 *
 * A capability means: "this node supports this service class."
 * It does NOT mean the service is currently available.
 * It does NOT mean the requester is authorized to use it.
 */
export type NodeCapability =
  | "MESH_RELAY"
  | "INTERNET_GATEWAY"
  | "CONTENT_SEED"
  | "STORAGE"
  | "DISCOVERY"
  | "SYNC"
  | "COMPUTE"
  | "CRYPTO_RELAY"
  | "CRYPTO_GATEWAY"
  | "PAYMENT_RELAY";

export const ALL_CAPABILITIES: readonly NodeCapability[] = [
  "MESH_RELAY",
  "INTERNET_GATEWAY",
  "CONTENT_SEED",
  "STORAGE",
  "DISCOVERY",
  "SYNC",
  "COMPUTE",
  "CRYPTO_RELAY",
  "CRYPTO_GATEWAY",
  "PAYMENT_RELAY",
] as const;

/** Endpoint transport type. */
export type EndpointType = "tcp" | "ws" | "quic" | "tor";

export interface NodeEndpoint {
  type: EndpointType;
  address: string; // e.g. "1.2.3.4:7788" or "host.example"
  port: number;
}

/**
 * Integer map keys for canonical CBOR (per ADR-0004 — eliminates locale/encoding ambiguity).
 * These are FROZEN; adding new fields requires a protocol_version bump and a new key.
 */
export const ADV_KEY = {
  PROTOCOL_VERSION: 1,
  NODE_ID: 2,
  SIGNING_PUBLIC_KEY: 3,
  CAPABILITIES: 4,
  ENDPOINTS: 5,
  CIRCUIT_PUBLIC_KEY: 6, // optional
  GATEWAY_POLICY: 7, // optional
  SEQUENCE: 8,
  TIMESTAMP: 9,
  EXPIRY: 10,
  NONCE: 11,
  SIGNATURE: 12,
} as const;

/** Shape of the canonical-CBOR-encodable advertisement body (no signature field). */
export interface NodeAdvertisementBody {
  protocolVersion: number;
  nodeId: string;
  signingPublicKey: Uint8Array;
  capabilities: NodeCapability[];
  endpoints: NodeEndpoint[];
  circuitPublicKey?: Uint8Array;
  gatewayPolicy?: Record<string, unknown>;
  sequence: number;
  timestamp: number; // unix seconds
  expiry: number; // unix seconds
  nonce: Uint8Array; // 16 random bytes
}

/** Full advertisement including signature. */
export interface NodeAdvertisement extends NodeAdvertisementBody {
  signature: Uint8Array; // 64-byte Ed25519 signature over the body
}

/**
 * Encode the advertisement body to canonical CBOR bytes.
 * The signature is computed over these bytes (after applying the domain prefix).
 * The signature itself is NEVER part of the signed bytes.
 */
export function encodeAdvertisementBody(body: NodeAdvertisementBody): Uint8Array {
  // Build an integer-keyed Map so cborg emits integer CBOR map keys (not strings).
  const map = new Map<number, unknown>();
  map.set(ADV_KEY.PROTOCOL_VERSION, body.protocolVersion);
  map.set(ADV_KEY.NODE_ID, body.nodeId);
  map.set(ADV_KEY.SIGNING_PUBLIC_KEY, body.signingPublicKey);
  map.set(ADV_KEY.CAPABILITIES, body.capabilities);
  map.set(
    ADV_KEY.ENDPOINTS,
    body.endpoints.map((e) => {
      const em = new Map<number, unknown>();
      em.set(1, e.type);
      em.set(2, e.address);
      em.set(3, e.port);
      return em;
    }),
  );
  if (body.circuitPublicKey) {
    map.set(ADV_KEY.CIRCUIT_PUBLIC_KEY, body.circuitPublicKey);
  }
  if (body.gatewayPolicy) {
    map.set(ADV_KEY.GATEWAY_POLICY, body.gatewayPolicy);
  }
  map.set(ADV_KEY.SEQUENCE, body.sequence);
  map.set(ADV_KEY.TIMESTAMP, body.timestamp);
  map.set(ADV_KEY.EXPIRY, body.expiry);
  map.set(ADV_KEY.NONCE, body.nonce);
  return canonicalEncode(map);
}

/** Encode a full advertisement (including signature) to canonical CBOR. */
export function encodeAdvertisement(adv: NodeAdvertisement): Uint8Array {
  const map = new Map<number, unknown>();
  map.set(ADV_KEY.PROTOCOL_VERSION, adv.protocolVersion);
  map.set(ADV_KEY.NODE_ID, adv.nodeId);
  map.set(ADV_KEY.SIGNING_PUBLIC_KEY, adv.signingPublicKey);
  map.set(ADV_KEY.CAPABILITIES, adv.capabilities);
  map.set(
    ADV_KEY.ENDPOINTS,
    adv.endpoints.map((e) => {
      const em = new Map<number, unknown>();
      em.set(1, e.type);
      em.set(2, e.address);
      em.set(3, e.port);
      return em;
    }),
  );
  if (adv.circuitPublicKey) {
    map.set(ADV_KEY.CIRCUIT_PUBLIC_KEY, adv.circuitPublicKey);
  }
  if (adv.gatewayPolicy) {
    map.set(ADV_KEY.GATEWAY_POLICY, adv.gatewayPolicy);
  }
  map.set(ADV_KEY.SEQUENCE, adv.sequence);
  map.set(ADV_KEY.TIMESTAMP, adv.timestamp);
  map.set(ADV_KEY.EXPIRY, adv.expiry);
  map.set(ADV_KEY.NONCE, adv.nonce);
  map.set(ADV_KEY.SIGNATURE, adv.signature);
  return canonicalEncode(map);
}

/** Compute the bytes-to-be-signed for an advertisement body. */
export function advertisementSigningPayload(body: NodeAdvertisementBody): Uint8Array {
  const bodyBytes = encodeAdvertisementBody(body);
  const domain = new TextEncoder().encode(ADVERTISEMENT_SIGNATURE_DOMAIN);
  const payload = new Uint8Array(domain.length + bodyBytes.length);
  payload.set(domain, 0);
  payload.set(bodyBytes, domain.length);
  return payload;
}

/**
 * Sign an advertisement body, producing a full NodeAdvertisement.
 * Returns the advertisement with a 64-byte Ed25519 signature attached.
 */
export function signAdvertisement(
  body: NodeAdvertisementBody,
  secretKey: Uint8Array,
): NodeAdvertisement {
  // Verify the body's nodeId matches the keypair BEFORE signing.
  if (!verifyNodeIdBinding(body.nodeId, body.signingPublicKey)) {
    throw new Error(
      "refusing to sign advertisement: nodeId does not match canonical derivation of signingPublicKey",
    );
  }
  if (!isValidNodeIdFormat(body.nodeId)) {
    throw new Error("refusing to sign advertisement: malformed nodeId");
  }
  if (body.signingPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error("invalid signingPublicKey length");
  }
  if (body.nonce.length !== 16) {
    throw new Error("advertisement nonce MUST be 16 bytes");
  }
  if (body.expiry <= body.timestamp) {
    throw new Error("advertisement expiry must be after timestamp");
  }
  if (body.expiry - body.timestamp > MAX_ADVERTISEMENT_TTL_SECONDS) {
    throw new Error(
      `advertisement TTL exceeds max (${MAX_ADVERTISEMENT_TTL_SECONDS}s) per spec/03 §5.4`,
    );
  }
  const payload = advertisementSigningPayload(body);
  const signature = signMessage(secretKey, payload);
  return { ...body, signature };
}

/**
 * Verification error categories. Each maps to a specific spec/03 §5 check.
 */
export type AdvertisementVerificationError =
  | "INVALID_SIGNATURE"
  | "IDENTITY_BINDING_MISMATCH" // spec/02 §3, spec/03 §5.2
  | "TIMESTAMP_OUT_OF_RANGE" // spec/03 §5.3 (clock skew)
  | "EXPIRED" // spec/03 §5.4
  | "TTL_TOO_LONG"
  | "MALFORMED_NODE_ID"
  | "MALFORMED_PUBLIC_KEY"
  | "MALFORMED_SIGNATURE"
  | "MALFORMED_NONCE"
  | "INVALID_CAPABILITY"
  | "CANONICAL_ENCODING_VIOLATION";

export interface VerifiedNodeAdvertisement {
  advertisement: NodeAdvertisement;
  verifiedAt: number;
  bodyBytes: Uint8Array; // the canonical bytes that were signed
}

/**
 * Verify a NodeAdvertisement cryptographically.
 *
 * Performs spec/03 §5 checks 1, 2, 3, 4, 6. The monotonic-sequence check
 * (§5.5) is performed separately by `acceptAdvertisement` against the
 * persistent sequence floor — it requires database state.
 *
 * @param now Unix seconds; defaults to Date.now()/1000. Override in tests.
 */
export function verifyAdvertisement(
  adv: NodeAdvertisement,
  now: number = Math.floor(Date.now() / 1000),
): { ok: true; verified: VerifiedNodeAdvertisement } | { ok: false; error: AdvertisementVerificationError; detail: string } {
  // §5.6 canonical encoding — re-encode body and confirm byte-identity
  // (this also catches malformed payloads early)
  let bodyBytes: Uint8Array;
  try {
    const recomputed = encodeAdvertisementBody(adv);
    bodyBytes = recomputed;
  } catch (e) {
    return {
      ok: false,
      error: "CANONICAL_ENCODING_VIOLATION",
      detail: `could not re-encode body: ${(e as Error).message}`,
    };
  }

  // §5.1 + structural checks
  if (adv.signingPublicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    return { ok: false, error: "MALFORMED_PUBLIC_KEY", detail: "expected 32-byte Ed25519 public key" };
  }
  if (adv.signature.length !== ED25519_SIGNATURE_BYTES) {
    return { ok: false, error: "MALFORMED_SIGNATURE", detail: "expected 64-byte Ed25519 signature" };
  }
  if (adv.nonce.length !== 16) {
    return { ok: false, error: "MALFORMED_NONCE", detail: "nonce MUST be 16 bytes" };
  }
  if (!isValidNodeIdFormat(adv.nodeId)) {
    return { ok: false, error: "MALFORMED_NODE_ID", detail: `nodeId format invalid: ${adv.nodeId}` };
  }

  // §5.2 identity binding — nodeId MUST equal canonical derivation of signingPublicKey
  if (!verifyNodeIdBinding(adv.nodeId, adv.signingPublicKey)) {
    return {
      ok: false,
      error: "IDENTITY_BINDING_MISMATCH",
      detail:
        "nodeId does not match deriveNodeId(signingPublicKey). " +
        "A node MUST NOT be allowed to claim an arbitrary NodeId (spec/02 §3).",
    };
  }

  // Capability validity
  for (const cap of adv.capabilities) {
    if (!ALL_CAPABILITIES.includes(cap)) {
      return { ok: false, error: "INVALID_CAPABILITY", detail: `unknown capability: ${cap}` };
    }
  }

  // §5.3 timestamp validity (clock skew window)
  if (Math.abs(adv.timestamp - now) > CLOCK_SKEW_SECONDS) {
    return {
      ok: false,
      error: "TIMESTAMP_OUT_OF_RANGE",
      detail: `timestamp ${adv.timestamp} is outside ±${CLOCK_SKEW_SECONDS}s of now ${now}`,
    };
  }

  // §5.4 expiry
  if (adv.expiry <= now) {
    return { ok: false, error: "EXPIRED", detail: `expiry ${adv.expiry} <= now ${now}` };
  }
  if (adv.expiry - adv.timestamp > MAX_ADVERTISEMENT_TTL_SECONDS) {
    return {
      ok: false,
      error: "TTL_TOO_LONG",
      detail: `TTL ${adv.expiry - adv.timestamp}s exceeds max ${MAX_ADVERTISEMENT_TTL_SECONDS}s`,
    };
  }

  // §5.1 signature verification
  const payload = advertisementSigningPayload(adv);
  if (!verifySignature(adv.signingPublicKey, payload, adv.signature)) {
    return { ok: false, error: "INVALID_SIGNATURE", detail: "Ed25519 signature did not verify" };
  }

  return {
    ok: true,
    verified: { advertisement: adv, verifiedAt: now, bodyBytes },
  };
}

// ---------------------------------------------------------------------
// Serialization (hex) for transport / storage / debugging
// ---------------------------------------------------------------------

/** Serialize a full advertisement to a hex string for transport or storage. */
export function advertisementToHex(adv: NodeAdvertisement): string {
  return toHex(encodeAdvertisement(adv));
}

/** Deserialize an advertisement from a hex string. Throws on malformed input. */
export function advertisementFromHex(hex: string): NodeAdvertisement {
  return advertisementFromBytes(fromHex(hex));
}

/** Deserialize an advertisement from canonical CBOR bytes. */
export function advertisementFromBytes(bytes: Uint8Array): NodeAdvertisement {
  const map = canonicalDecode<Map<number, unknown>>(bytes);
  if (!(map instanceof Map)) {
    throw new Error("advertisement bytes did not decode to a CBOR map");
  }
  const get = <T>(key: number): T => {
    if (!map.has(key)) throw new Error(`advertisement missing required field key ${key}`);
    return map.get(key) as T;
  };
  const getOpt = <T>(key: number): T | undefined => {
    return map.has(key) ? (map.get(key) as T) : undefined;
  };

  const endpointsRaw = get<unknown[]>(ADV_KEY.ENDPOINTS);
  const endpoints: NodeEndpoint[] = endpointsRaw.map((em) => {
    if (!(em instanceof Map)) throw new Error("endpoint is not a CBOR map");
    return {
      type: em.get(1) as EndpointType,
      address: em.get(2) as string,
      port: em.get(3) as number,
    };
  });

  const adv: NodeAdvertisement = {
    protocolVersion: get<number>(ADV_KEY.PROTOCOL_VERSION),
    nodeId: get<string>(ADV_KEY.NODE_ID),
    signingPublicKey: new Uint8Array(get<number[]>(ADV_KEY.SIGNING_PUBLIC_KEY)),
    capabilities: get<NodeCapability[]>(ADV_KEY.CAPABILITIES),
    endpoints,
    circuitPublicKey: getOpt<number[]>(ADV_KEY.CIRCUIT_PUBLIC_KEY)
      ? new Uint8Array(getOpt<number[]>(ADV_KEY.CIRCUIT_PUBLIC_KEY)!)
      : undefined,
    gatewayPolicy: getOpt<Record<string, unknown>>(ADV_KEY.GATEWAY_POLICY),
    sequence: get<number>(ADV_KEY.SEQUENCE),
    timestamp: get<number>(ADV_KEY.TIMESTAMP),
    expiry: get<number>(ADV_KEY.EXPIRY),
    nonce: new Uint8Array(get<number[]>(ADV_KEY.NONCE)),
    signature: new Uint8Array(get<number[]>(ADV_KEY.SIGNATURE)),
  };
  return adv;
}

/** Human-readable summary for UI display. */
export function advertisementSummary(adv: NodeAdvertisement): string {
  return `node=${adv.nodeId.slice(0, 16)}… seq=${adv.sequence} caps=[${adv.capabilities.join(",")}] exp=${adv.expiry}`;
}

/** Two advertisements are byte-identical iff their serialized forms match. */
export function advertisementsEqual(a: NodeAdvertisement, b: NodeAdvertisement): boolean {
  return bytesEqual(encodeAdvertisement(a), encodeAdvertisement(b));
}

/** Convenience: derive the expected NodeId for the advertisement's public key. */
export function expectedNodeIdForAdvertisement(adv: NodeAdvertisement): string {
  return deriveNodeId(adv.signingPublicKey);
}

// Re-export key helpers for callers
export { bytesToHex };
