/**
 * ShareNet 2.0 — R-007: Registry-driven vector completeness guard.
 *
 * Per the R-007 final exit condition:
 *
 *   "adding a new normative protocol object without adding a conformance
 *    vector MUST fail CI automatically."
 *
 * This test enforces the FULL end-to-end chain:
 *
 *   registry ↔ manifest ↔ TS runner ↔ Python runner
 *
 *   1. Every `kind: "wire"` object in the registry has at least one
 *      vector in the manifest with a matching ID prefix.
 *   2. Every manifest vector ID has a dispatch branch in BOTH the TS
 *      runner (`conformance/runners/ts-vector-runner.ts`) AND the Python
 *      runner (`conformance/runners/py_vector_verifier.py`).
 *   3. Dispatch prefixes are EXTRACTED FROM THE RUNNER SOURCE FILES
 *      (not hard-coded in this test) by regex-matching the
 *      `.startsWith("V-…")` calls — so adding a new vector family
 *      requires a corresponding branch in BOTH runners or this test
 *      fails.
 */

import { describe, test, expect } from "bun:test";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const MANIFEST_PATH = join(process.cwd(), "conformance", "vectors", "MANIFEST.json");
const MANIFEST = JSON.parse(readFileSync(MANIFEST_PATH, "utf-8"));

const REGISTRY_PATH = join(process.cwd(), "spec", "schemas", "protocol-registry.json");
const REGISTRY = JSON.parse(readFileSync(REGISTRY_PATH, "utf-8"));

const TS_RUNNER_PATH = join(process.cwd(), "conformance", "runners", "ts-vector-runner.ts");
const PY_RUNNER_PATH = join(process.cwd(), "conformance", "runners", "py_vector_verifier.py");
const TS_RUNNER_SRC = readFileSync(TS_RUNNER_PATH, "utf-8");
const PY_RUNNER_SRC = readFileSync(PY_RUNNER_PATH, "utf-8");

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
 * Derive the set of vector families required specifically for `kind: "wire"`
 * objects. Wire objects cross a process/network/language boundary and so
 * MUST have a conformance vector. (sub_object / state / rule kinds are
 * covered by their parent wire object's vector family — they don't need
 * their own.)
 */
function getRequiredWireVectorFamilies(): Set<string> {
  const families = new Set<string>();
  for (const layer of Object.values(REGISTRY.layers)) {
    for (const obj of Object.values((layer as any).objects)) {
      if ((obj as any).kind === "wire") {
        const family = (obj as any).conformance_vector_family;
        if (family) families.add(family);
      }
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

/**
 * Extract dispatch prefixes from the TS runner source.
 *
 * The TS runner dispatches on `data.id?.startsWith("V-…")`. We regex-match
 * every such call and collect the unique set of prefix literals.
 */
function getTsRunnerDispatchPrefixes(): Set<string> {
  const out = new Set<string>();
  // Match: .startsWith("V-PREFIX")
  const re = /\.startsWith\(\s*"([^"]+)"\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(TS_RUNNER_SRC)) !== null) {
    const lit = m[1]!;
    if (lit.startsWith("V-")) out.add(lit);
  }
  return out;
}

/**
 * Extract dispatch prefixes from the Python runner source.
 *
 * The Python runner dispatches on `vid.startswith("V-…")`. We regex-match
 * every such call and collect the unique set of prefix literals.
 */
function getPyRunnerDispatchPrefixes(): Set<string> {
  const out = new Set<string>();
  // Match: .startswith("V-PREFIX")
  const re = /\.startswith\(\s*"([^"]+)"\s*\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(PY_RUNNER_SRC)) !== null) {
    const lit = m[1]!;
    if (lit.startsWith("V-")) out.add(lit);
  }
  return out;
}

describe("R-007: Registry-driven vector completeness", () => {
  test("protocol registry is valid JSON with the expected structure", () => {
    expect(REGISTRY.version).toBe(3);
    expect(REGISTRY.object_kinds).toBeDefined();
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

  test("every `kind: \"wire\" registry object has a corresponding vector in the manifest", () => {
    // Wire objects cross a process/network/language boundary — they are the
    // hard requirement. sub_object / state / rule kinds are covered by their
    // parent's vector family and don't need their own manifest entry.
    const wireFamilies = getRequiredWireVectorFamilies();
    const manifestIds = getManifestVectorIds();
    const missing: string[] = [];

    for (const family of wireFamilies) {
      const hasVector = manifestIds.some((id) => id.startsWith(family));
      if (!hasVector) {
        missing.push(family);
      }
    }

    // If this fails, a wire object was added to the registry without a
    // corresponding conformance vector. Wire objects MUST have a vector.
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

  test("every wire object has a maturity field declared", () => {
    // Maturity declares whether a wire object has a TypeScript reference
    // implementation (`reference-implemented`) or is a spec-frozen wire
    // format with no implementation yet (`spec-frozen`). Every wire object
    // MUST declare one or the other — a wire object with no maturity is
    // an underspecified protocol surface that must not be allowed.
    const wireObjects: Array<{ layer: string; name: string; obj: any }> = [];
    for (const [layerName, layer] of Object.entries(REGISTRY.layers)) {
      for (const [objName, obj] of Object.entries((layer as any).objects)) {
        if ((obj as any).kind === "wire") {
          wireObjects.push({ layer: layerName, name: objName, obj });
        }
      }
    }
    expect(wireObjects.length).toBeGreaterThan(0);
    for (const { layer, name, obj } of wireObjects) {
      expect(obj.maturity).toBeDefined();
      expect(
        obj.maturity === "reference-implemented" || obj.maturity === "spec-frozen",
        `wire object ${layer}/${name} has invalid maturity "${obj.maturity}"`,
      ).toBe(true);
    }
  });

  test("every spec-frozen wire object has status 'frozen' (spec-frozen) in its vector file", () => {
    // For every registry wire object with maturity="spec-frozen", every
    // vector file in the manifest that belongs to its family MUST carry a
    // top-level `status` field set to either "frozen" or "spec-frozen".
    // (Existing vectors use "frozen"; the test accepts "spec-frozen" as a
    // forward-compatible spelling of the same concept.) A spec-frozen
    // vector without a `status` field, or with status="draft", would mean
    // the canonical bytes are NOT yet committed — a contradiction.
    const specFrozenFamilies = new Set<string>();
    for (const layer of Object.values(REGISTRY.layers)) {
      for (const obj of Object.values((layer as any).objects)) {
        if ((obj as any).kind === "wire" && (obj as any).maturity === "spec-frozen") {
          const family = (obj as any).conformance_vector_family;
          if (family) specFrozenFamilies.add(family);
        }
      }
    }
    // Sanity: the registry actually has spec-frozen wire objects.
    expect(specFrozenFamilies.size).toBeGreaterThan(0);

    const offenders: string[] = [];
    for (const v of MANIFEST.vectors) {
      const matchesFamily = [...specFrozenFamilies].some((f) =>
        v.id.startsWith(f),
      );
      if (!matchesFamily) continue;

      const path = join(process.cwd(), "conformance", "vectors", v.file);
      const vec = JSON.parse(readFileSync(path, "utf-8"));
      const status = vec.status;
      if (status !== "frozen" && status !== "spec-frozen") {
        offenders.push(
          `${v.id} (${v.file}): expected status "frozen" or "spec-frozen", got "${status}"`,
        );
      }
    }

    // If this fails, a spec-frozen wire object's vector file does not carry
    // status "frozen"/"spec-frozen". Update the vector file's status field,
    // OR change the registry maturity to "reference-implemented" once a TS
    // implementation exists.
    expect(offenders).toEqual([]);
  });

  // -----------------------------------------------------------------
  // End-to-end chain: manifest ↔ TS runner ↔ Python runner.
  //
  // Every manifest vector ID must be dispatched by BOTH the TS runner
  // and the Python runner. Dispatch prefixes are extracted from the
  // runner source files by regex-matching the `.startsWith("V-…")`
  // calls — not hard-coded here.
  // -----------------------------------------------------------------

  test("TS runner source has at least one dispatch branch", () => {
    const tsPrefixes = getTsRunnerDispatchPrefixes();
    expect(tsPrefixes.size).toBeGreaterThan(0);
  });

  test("Python runner source has at least one dispatch branch", () => {
    const pyPrefixes = getPyRunnerDispatchPrefixes();
    expect(pyPrefixes.size).toBeGreaterThan(0);
  });

  test("every manifest vector ID is dispatched by the TS runner", () => {
    const tsPrefixes = getTsRunnerDispatchPrefixes();
    const manifestIds = getManifestVectorIds();
    const undispatched: string[] = [];

    for (const id of manifestIds) {
      const matched = [...tsPrefixes].some((p) => id.startsWith(p));
      if (!matched) {
        undispatched.push(id);
      }
    }

    // If this fails, a vector was added to the manifest without a
    // corresponding `data.id?.startsWith("V-…")` branch in
    // conformance/runners/ts-vector-runner.ts. Add the dispatch branch.
    expect(undispatched).toEqual([]);
  });

  test("every manifest vector ID is dispatched by the Python runner", () => {
    const pyPrefixes = getPyRunnerDispatchPrefixes();
    const manifestIds = getManifestVectorIds();
    const undispatched: string[] = [];

    for (const id of manifestIds) {
      const matched = [...pyPrefixes].some((p) => id.startsWith(p));
      if (!matched) {
        undispatched.push(id);
      }
    }

    // If this fails, a vector was added to the manifest without a
    // corresponding `vid.startswith("V-…")` branch in
    // conformance/runners/py_vector_verifier.py. Add the dispatch branch.
    expect(undispatched).toEqual([]);
  });

  test("TS runner and Python runner dispatch the same set of vector prefixes", () => {
    const tsPrefixes = getTsRunnerDispatchPrefixes();
    const pyPrefixes = getPyRunnerDispatchPrefixes();

    const onlyTs = [...tsPrefixes].filter((p) => !pyPrefixes.has(p));
    const onlyPy = [...pyPrefixes].filter((p) => !tsPrefixes.has(p));

    // If this fails, the two runners have diverged: one has a dispatch
    // branch the other is missing. Cross-language conformance requires
    // both runners to dispatch the same set of vector families.
    expect({ onlyTs, onlyPy }).toEqual({ onlyTs: [], onlyPy: [] });
  });

  test("every manifest vector ID prefix is backed by a registry family declaration", () => {
    // Reverse direction of the existing registry→manifest test:
    // every manifest ID's prefix must come from a registry family.
    // This catches "phantom" manifest entries that have no corresponding
    // registry object (orphan vectors).
    const requiredFamilies = getRequiredVectorFamilies();
    const manifestIds = getManifestVectorIds();
    const orphans: string[] = [];

    for (const id of manifestIds) {
      const matched = [...requiredFamilies].some((f) => id.startsWith(f));
      if (!matched) {
        orphans.push(id);
      }
    }

    // If this fails, a manifest vector ID has no corresponding
    // conformance_vector_family in the registry. Either add the family
    // to the registry (if it is a real protocol object) or remove the
    // orphan vector from the manifest.
    expect(orphans).toEqual([]);
  });

  // -----------------------------------------------------------------
  // Spec ↔ Registry inventory check.
  //
  // Every CDDL-defined wire object in the normative specs MUST appear in
  // the protocol registry. This test parses the spec markdown files for
  // CDDL-style object definitions (```
  // ObjectName = { ... }```) and verifies each ObjectName appears as a
  // key in the registry. This prevents a new spec object from being added
  // without the registry being updated.
  // -----------------------------------------------------------------

  test("every CDDL-defined object in spec markdown appears in the protocol registry", () => {
    const specDir = join(process.cwd(), "spec");
    const specFiles = [
      "02-identity.md", "03-node-advertisements.md", "04-links.md",
      "05-discovery.md", "06-topology.md", "07-routing.md",
      "08-circuits.md", "09-internet-gateway.md", "11-contribution.md",
    ];

    // Collect all object names defined in the registry
    const registryObjectNames = new Set<string>();
    for (const layer of Object.values(REGISTRY.layers)) {
      for (const objName of Object.keys((layer as any).objects)) {
        registryObjectNames.add(objName);
      }
    }

    const missing: string[] = [];

    for (const specFile of specFiles) {
      const specPath = join(specDir, specFile);
      if (!existsSync(specPath)) continue;

      const spec = readFileSync(specPath, "utf-8");

      // Match CDDL-style definitions: "ObjectName = {" or "ObjectName = ["
      // These are the normative wire object definitions in the specs.
      const cddlRegex = /^(\w+)\s*=\s*[{[]/gm;
      let match: RegExpExecArray | null;

      while ((match = cddlRegex.exec(spec)) !== null) {
        const objName = match[1]!;

        // Skip non-object constructs (keywords, comments, etc.)
        // These are common spec words that appear before `{` but are not
        // CDDL object definitions.
        const skipNames = new Set([
          "PathValidationResult", // this one IS in the registry already
          "RouteProposal", "RouteHop", "RouteAcceptance", "RouteCommitment",
          "CommittedRoute", "SignedRouteProposal",
        ]);
        // Actually we should NOT skip — we should check ALL of them.
        // Let me just check if the object name is in the registry.
        if (!registryObjectNames.has(objName)) {
          // Check if it's a known sub-object or a spec-only name that
          // isn't a wire object (e.g. "PathValidationResult" body)
          // We allow a small allowlist of known non-registry constructs
          const knownNonRegistry = new Set([
            // These are spec constructs that are NOT protocol objects:
            "PathValidationResult", // IS in registry
            "if", "for", "while", // code blocks
          ]);
          if (!knownNonRegistry.has(objName)) {
            // Check more carefully — is this really a CDDL object definition
            // or just a markdown table/code fence?
            // Only flag if it looks like a real wire object (has fields inside)
            const afterMatch = spec.slice(match.index! + match[0].length);
            const hasFields = /^\s*\w+:/m.test(afterMatch);
            if (hasFields && !missing.includes(objName)) {
              missing.push(objName);
            }
          }
        }
      }
    }

    // If this fails, a CDDL object was defined in a normative spec but
    // is not present in the protocol registry. Either add the object to
    // spec/schemas/protocol-registry.json or remove the CDDL definition
    // from the spec.
    expect(missing).toEqual([]);
  });
});
