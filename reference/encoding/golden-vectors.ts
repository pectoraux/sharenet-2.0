/**
 * Golden vector for canonical CBOR encoding.
 *
 * Per spec/17-conformance.md §2.1, the canonical CBOR vector MUST be byte-stable
 * across all ShareNet implementations. Any implementation that produces a
 * different byte sequence for these inputs is non-conformant.
 *
 * Vectors generated against RFC 8949 §4.2.2 deterministic encoding using cborg
 * with `canonical: true` and verified against hand-computed expected outputs.
 *
 * Each vector asserts: canonicalEncode(input) === expectedHex AND
 *                     isCanonical(canonicalEncode(input)) === true.
 */

import { canonicalEncode, canonicalDecode, isCanonical, toHex, fromHex } from "./cbor";

export interface CborVector {
  name: string;
  input: unknown;
  expectedHex: string;
  description: string;
}

/**
 * Canonical CBOR golden vectors.
 * These byte sequences are FROZEN — do not modify them. They are the
 * conformance reference. See ADR-0004.
 */
export const CBOR_GOLDEN_VECTORS: readonly CborVector[] = [
  {
    name: "unsigned-int-0",
    input: 0,
    expectedHex: "00",
    description: "Integer 0 encodes as a single byte 0x00 (shortest form).",
  },
  {
    name: "unsigned-int-1",
    input: 1,
    expectedHex: "01",
    description: "Integer 1 encodes as 0x01.",
  },
  {
    name: "unsigned-int-23",
    input: 23,
    expectedHex: "17",
    description: "23 is the largest value fitting in the immediate-info nibble.",
  },
  {
    name: "unsigned-int-24",
    input: 24,
    expectedHex: "1818",
    description: "24 forces a 1-byte length prefix: 0x18 0x18.",
  },
  {
    name: "unsigned-int-100",
    input: 100,
    expectedHex: "1864",
    description: "100 = 0x64 with the 1-byte uint prefix.",
  },
  {
    name: "negative-int--1",
    input: -1,
    expectedHex: "20",
    description: "Negative integer -1 encodes as 0x20.",
  },
  {
    name: "empty-byte-string",
    input: new Uint8Array(0),
    expectedHex: "40",
    description: "Empty byte string: 0x40.",
  },
  {
    name: "short-byte-string",
    input: new Uint8Array([0x01, 0x02, 0x03]),
    expectedHex: "43010203",
    description: "3-byte byte string: 0x43 (length=3) followed by the bytes.",
  },
  {
    name: "empty-text-string",
    input: "",
    expectedHex: "60",
    description: "Empty text string: 0x60.",
  },
  {
    name: "short-text-string",
    input: "abc",
    expectedHex: "63616263",
    description: "Text 'abc': 0x63 then UTF-8 bytes 61 62 63.",
  },
  {
    name: "empty-array",
    input: [],
    expectedHex: "80",
    description: "Empty array (definite-length 0): 0x80.",
  },
  {
    name: "small-array",
    input: [1, 2, 3],
    expectedHex: "83010203",
    description: "Array of length 3 with three small ints.",
  },
  {
    name: "empty-map",
    input: {},
    expectedHex: "a0",
    description: "Empty map: 0xa0.",
  },
  {
    name: "sorted-string-keys-map",
    input: { b: 2, a: 1, c: 3 },
    expectedHex: "a3616101616202616303",
    description:
      "Map keys MUST be sorted in bytewise lexicographic order of their CBOR encodings. " +
      "Input is {b,a,c}; canonical output is {a,b,c}.",
  },
  {
    name: "integer-keys-map",
    input: new Map<number, string>([
      [3, "c"],
      [1, "a"],
      [2, "b"],
    ]),
    expectedHex: "a3016161026162036163",
    // 0xa3 = map(3)
    // 0x01 = key 1, 0x61 0x61 = "a"
    // 0x02 = key 2, 0x61 0x62 = "b"
    // 0x03 = key 3, 0x61 0x63 = "c"
    // NOTE: A plain JS object literal coerces {3:"c"} to string key "3".
    // ShareNet advertisement maps use Map<number, ...> per ADR-0004 to guarantee
    // integer CBOR keys, not stringified-integer keys.
    description:
      "Integer map keys (used by ShareNet advertisements per ADR-0004) sort numerically " +
      "and eliminate any locale/encoding ambiguity. A Map<number, ...> MUST be used in JS " +
      "to preserve integer key type; JS object literals coerce numeric keys to strings.",
  },
  {
    name: "boolean-true",
    input: true,
    expectedHex: "f5",
    description: "Canonical CBOR encodes boolean true as simple value 21 (0xf5).",
  },
  {
    name: "boolean-false",
    input: false,
    expectedHex: "f4",
    description: "Boolean false as simple value 20 (0xf4).",
  },
  {
    name: "null",
    input: null,
    expectedHex: "f6",
    description: "null as simple value 22 (0xf6).",
  },
  {
    name: "nested-map-with-array",
    input: { a: [1, 2], b: { x: 1 } },
    expectedHex: "a261618201026162a1617801",
    // 0xa2 = map(2)
    // 0x61 0x61 = "a", 0x82 = array(2), 0x01 0x02
    // 0x61 0x62 = "b", 0xa1 = map(1), 0x61 0x78 = "x", 0x01 = 1
    description:
      "Nested map+array structure exercises recursive deterministic encoding. " +
      "Keys are sorted by canonical-byte order: 'a' (0x61) < 'b' (0x62).",
  },
] as const;

export interface CborVectorResult {
  name: string;
  passed: boolean;
  actualHex: string;
  expectedHex: string;
  description: string;
}

/** Run all canonical CBOR golden vectors. */
export function runCborGoldenVectors(): CborVectorResult[] {
  return CBOR_GOLDEN_VECTORS.map((v) => {
    const encoded = canonicalEncode(v.input);
    const actualHex = toHex(encoded);
    const passed = actualHex === v.expectedHex;
    // Also assert that the canonical property holds (re-encoding is stable).
    const canonical = isCanonical(encoded);
    return {
      name: v.name,
      passed: passed && canonical,
      actualHex,
      expectedHex: v.expectedHex,
      description: v.description,
    };
  });
}

/** Round-trip sanity: decode -> re-encode -> compare bytes. */
export function roundTrip(hex: string): { ok: boolean; reencoded: string } {
  const bytes = fromHex(hex);
  const value = canonicalDecode(bytes);
  const reencoded = canonicalEncode(value);
  return { ok: toHex(reencoded) === hex, reencoded: toHex(reencoded) };
}
