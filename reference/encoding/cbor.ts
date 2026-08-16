/**
 * Canonical CBOR encoding — RFC 8949 §4.2.2 Deterministic Encoding.
 *
 * Per ADR-0004, every implementation MUST produce byte-identical output
 * for the same logical input. This module is the single source of truth
 * for the canonical wire format used in ShareNet 2.0.
 *
 * Rules enforced (RFC 8949 §4.2.2):
 *   1. Map keys sorted in bytewise lexicographic order of their canonical CBOR encodings.
 *   2. Integers encoded in the shortest form possible.
 *   3. Strings/byte-strings in shortest definite length form (no indefinite length).
 *   4. No "undefined" values; no NaN payloads with non-canonical bits.
 *   5. Simple values encoded canonically.
 *
 * Per ADR-0004, ShareNet advertisement/route wire payloads use INTEGER map keys
 * (not string keys) to eliminate any locale/encoding ambiguity across implementations.
 */

import { encode as cborEncode, decode as cborDecode } from "cborg";

/**
 * Canonical-encode any CBOR-compatible value to bytes.
 * cborg's `canonical: true` option enforces RFC 8949 §4.2.2.
 */
export function canonicalEncode(value: unknown): Uint8Array {
  return cborEncode(value, { canonical: true });
}

/**
 * Decode canonical CBOR bytes back to a value.
 * Decoding is permissive (accepts any valid CBOR) — the canonical guarantee
 * is one-directional: encoding is deterministic, decoding accepts the canonical form.
 *
 * `useMaps: true` is REQUIRED so that integer-keyed CBOR maps (used by ShareNet
 * advertisements per ADR-0004) round-trip correctly. Without it cborg would try to
 * coerce non-string keys into a plain JS object, which throws.
 */
export function canonicalDecode<T = unknown>(bytes: Uint8Array): T {
  return cborDecode(bytes, { useMaps: true }) as T;
}

/**
 * Verify that re-encoding a value yields the same bytes.
 * Used by architecture regression tests and by the advertisement verifier
 * to guarantee no semantic ambiguity exists in the wire format.
 */
export function isCanonical(bytes: Uint8Array): boolean {
  try {
    const value = canonicalDecode(bytes);
    const reencoded = canonicalEncode(value);
    return bytesEqual(bytes, reencoded);
  } catch {
    return false;
  }
}

/** Hex helper for golden vectors and debugging. */
export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

/** Parse hex string to Uint8Array. Throws on invalid input. */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`invalid hex length: ${hex.length}`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`invalid hex byte at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

/** Constant-time-ish byte equality (length leaks, content does not). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
