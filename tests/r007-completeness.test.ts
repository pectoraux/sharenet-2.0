/**
 * ShareNet 2.0 — R-007: Registry-driven vector completeness guard.
 *
 * Per the R-007 final exit condition:
 *
 *   "adding a new normative protocol object without adding a conformance
 *    vector MUST fail CI automatically."
 *
 * This test reads the canonical protocol-schema registry
 * (`spec/schemas/protocol-registry.json`) and derives the required vector
 * families from it — NOT from a hard-coded list. Every object in the
 * registry declares a `conformance_vector_family` prefix; the test
 * verifies that the MANIFEST contains at least one entry matching each
 * prefix.
 *
 * If a new protocol object is added to the registry without a
 * corresponding vector family in the manifest, this test fails.
 */

import { describe, test, expect } from "bun:test";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const MANIFEST_PATH = join(process.cwd(), "conformance", "vectors", "MANIFEST.json");
const MANIFEST = JSON.parse(readFileSync(MANIFEST_PATH, "utf-8"));

const REGISTRY_PATH = join(process.cwd(), "spec", "schemas", "protocol-registry.json");
const REGISTRY = JSON.parse(readFileSync(REGISTRY_PATH, "utf-8"));

/**
 * Derive the set of required vector-family prefixes from the protocol
 * registry. Each object in the registry declares a
 * `conformance_vector_family` — we collect the unique set.
 */
function getRequiredVectorFamilies(): Set<string> {
  const families = new Set<string>();
  for (const layer of Object.values(REGISTRY.layers)) {
    for (const obj of Object.values((layer as any).objects)) {
      const family = (obj as any).conformance_vector_family;
      if (family) families.add(family);
    }
  }
  return families;
}

/**
 * Get all vector IDs from the manifest.
 */
function getManifestVectorIds(): string[] {
  return MANIFEST.vectors.map((v: any) => v.id);
}

describe("R-007: Registry-driven vector completeness", () => {
  test("protocol registry is valid JSON with the expected structure", () => {
    expect(REGISTRY.version).toBe(1);
    expect(REGISTRY.layers).toBeDefined();
    expect(Object.keys(REGISTRY.layers).length).toBeGreaterThan(0);
  });

  test("MANIFEST.json has the expected structure", () => {
    expect(MANIFEST.vectors).toBeDefined();
    expect(Array.isArray(MANIFEST.vectors)).toBe(true);
    expect(MANIFEST.vectors.length).toBeGreaterThan(0);
  });

  test("every protocol-registry object has a corresponding vector family in the manifest", () => {
    const requiredFamilies = getRequiredVectorFamilies();
    const manifestIds = getManifestVectorIds();
    const missing: string[] = [];

    for (const family of requiredFamilies) {
      const hasVector = manifestIds.some((id) => id.startsWith(family));
      if (!hasVector) {
        missing.push(family);
      }
    }

    // If this fails, a protocol object was added to the registry without
    // a corresponding conformance vector family. Add the vector file +
    // manifest entry, or remove the object from the registry.
    expect(missing).toEqual([]);
  });

  test("total vector count meets the minimum threshold (≥ 25)", () => {
    expect(MANIFEST.vectors.length).toBeGreaterThanOrEqual(25);
  });

  test("every manifest entry references a file that exists", () => {
    for (const v of MANIFEST.vectors) {
      const path = join(process.cwd(), "conformance", "vectors", v.file);
      expect(existsSync(path)).toBe(true);
    }
  });

  test("registry covers all protocol layers", () => {
    const expectedLayers = [
      "identity", "encoding", "link", "topology",
      "routing", "service", "circuit", "gateway", "economics",
    ];
    for (const layer of expectedLayers) {
      expect(REGISTRY.layers[layer]).toBeDefined();
    }
  });

  test("every registry object has a conformance_vector_family declared", () => {
    for (const [layerName, layer] of Object.entries(REGISTRY.layers)) {
      for (const [objName, obj] of Object.entries((layer as any).objects)) {
        expect((obj as any).conformance_vector_family).toBeDefined();
      }
    }
  });
});
