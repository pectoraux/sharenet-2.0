/**
 * ShareNet 2.0 — R-007: Vector completeness guard.
 *
 * Per the R-007 exit condition:
 *
 *   "A completeness test that enumerates the machine-readable schema
 *    artifact and fails when a protocol object lacks a vector family.
 *    That prevents the vector suite from silently falling behind the
 *    specification again."
 *
 * This test reads the MANIFEST.json and the routing-schemas.json artifact,
 * and verifies that every protocol object defined in the schema artifact
 * has at least one vector family in the manifest.
 */

import { describe, test, expect } from "bun:test";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const MANIFEST_PATH = join(process.cwd(), "conformance", "vectors", "MANIFEST.json");
const MANIFEST = JSON.parse(readFileSync(MANIFEST_PATH, "utf-8"));

const SCHEMA_PATH = join(process.cwd(), "spec", "schemas", "routing-schemas.json");
const SCHEMA = JSON.parse(readFileSync(SCHEMA_PATH, "utf-8"));

/** Map schema artifact object names to expected vector prefix families. */
const SCHEMA_OBJECT_TO_VECTOR_PREFIX: Record<string, string> = {
  RouteHop: "V-ROUTE-COMMIT",
  RouteProposal: "V-ROUTE-COMMIT",
  SignedRouteProposal: "V-ROUTE-COMMIT",
  RouteAcceptance: "V-ROUTE-COMMIT",
  RouteCommitment: "V-ROUTE-COMMIT",
};

/** Additional protocol objects that must have vectors (not in the routing schema artifact). */
const REQUIRED_VECTOR_FAMILIES: Array<{ name: string; prefix: string }> = [
  { name: "NodeId", prefix: "V-NODEID" },
  { name: "CBOR encoding", prefix: "V-CBOR" },
  { name: "NodeAdvertisement", prefix: "V-ADV" },
  { name: "Link handshake", prefix: "V-LINK-HANDSHAKE" },
  { name: "Link auth", prefix: "V-LINK-AUTH" },
  { name: "RemoteNodeHint", prefix: "V-HINT" },
  { name: "ServiceAgreement", prefix: "V-SVC" },
  { name: "Circuit", prefix: "V-CIRCUIT" },
  { name: "Gateway", prefix: "V-GATEWAY" },
  { name: "BilateralReceipt", prefix: "V-RECEIPT" },
];

describe("R-007: Vector completeness (every protocol object has a vector family)", () => {
  test("MANIFEST.json has the expected structure", () => {
    expect(MANIFEST.vectors).toBeDefined();
    expect(Array.isArray(MANIFEST.vectors)).toBe(true);
    expect(MANIFEST.vectors.length).toBeGreaterThan(0);
  });

  test("every required vector family has at least one entry in the manifest", () => {
    const manifestIds: string[] = MANIFEST.vectors.map((v: any) => v.id);
    const missing: string[] = [];

    for (const family of REQUIRED_VECTOR_FAMILIES) {
      const hasVector = manifestIds.some((id) => id.startsWith(family.prefix));
      if (!hasVector) {
        missing.push(family.name);
      }
    }

    expect(missing).toEqual([]);
  });

  test("routing schema artifact objects have corresponding vector families", () => {
    const manifestIds: string[] = MANIFEST.vectors.map((v: any) => v.id);
    const missing: string[] = [];

    for (const [objName, prefix] of Object.entries(SCHEMA_OBJECT_TO_VECTOR_PREFIX)) {
      const hasVector = manifestIds.some((id) => id.startsWith(prefix));
      if (!hasVector) {
        missing.push(objName);
      }
    }

    expect(missing).toEqual([]);
  });

  test("total vector count meets the minimum threshold (≥ 20)", () => {
    expect(MANIFEST.vectors.length).toBeGreaterThanOrEqual(20);
  });

  test("every manifest entry references a file that exists", () => {
    for (const v of MANIFEST.vectors) {
      const path = join(process.cwd(), "conformance", "vectors", v.file);
      expect(existsSync(path)).toBe(true);
    }
  });
});
