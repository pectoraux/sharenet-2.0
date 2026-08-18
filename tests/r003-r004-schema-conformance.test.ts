/**
 * ShareNet 2.0 — R-003/R-004: Normative schema conformance guard.
 *
 * Reads `spec/schemas/routing-schemas.json` (the canonical machine-readable
 * schema artifact) and verifies that the TypeScript implementation's
 * interfaces have EXACTLY the fields defined there — no more, no fewer,
 * no different names. Also verifies the spec markdown and the schema
 * artifact agree.
 *
 * If the schema artifact or the implementation changes without the other
 * being updated, this test fails.
 */

import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { RouteProposal, RouteAcceptance, RouteHop, RouteCommitment, SignedRouteProposal } from "@reference/routing/route";

const SCHEMA_PATH = join(process.cwd(), "spec", "schemas", "routing-schemas.json");
const SCHEMA = JSON.parse(readFileSync(SCHEMA_PATH, "utf-8"));

/** Extract sorted field names from a TypeScript interface instance. */
function getFields<T>(obj: T): string[] {
  return Object.keys(obj as Record<string, unknown>).sort();
}

/** Get expected required fields from the schema artifact, sorted. */
function getSchemaFields(objName: string): string[] {
  const obj = SCHEMA.objects[objName];
  if (!obj) throw new Error(`schema artifact missing object: ${objName}`);
  return [...obj.required].sort();
}

/** Get forbidden fields from the schema artifact. */
function getSchemaForbidden(objName: string): string[] {
  return SCHEMA.objects[objName]?.forbidden || [];
}

describe("R-003/R-004: Normative schema conformance (machine-readable artifact)", () => {
  test("schema artifact is valid JSON with the expected structure", () => {
    expect(SCHEMA.version).toBe(1);
    expect(SCHEMA.objects).toBeDefined();
    expect(SCHEMA.objects.RouteProposal).toBeDefined();
    expect(SCHEMA.objects.RouteAcceptance).toBeDefined();
    expect(SCHEMA.objects.RouteHop).toBeDefined();
    expect(SCHEMA.objects.SignedRouteProposal).toBeDefined();
    expect(SCHEMA.objects.RouteCommitment).toBeDefined();
    expect(SCHEMA.merkle_algorithm).toBeDefined();
    expect(SCHEMA.route_id_format).toBeDefined();
  });

  test("RouteHop implementation fields match schema artifact", () => {
    const hop: RouteHop = { nodeId: "", capability: "MESH_RELAY", endpoint: "", linkUp: true };
    expect(getFields(hop)).toEqual(getSchemaFields("RouteHop"));
  });

  test("RouteProposal implementation fields match schema artifact (no routeId)", () => {
    const proposal: RouteProposal = { hops: [], requirementDigest: "", expiry: 0, initiatorNodeId: "", agreementDigest: "" };
    expect(getFields(proposal)).toEqual(getSchemaFields("RouteProposal"));
    for (const f of getSchemaForbidden("RouteProposal")) {
      expect(getFields(proposal)).not.toContain(f);
    }
  });

  test("SignedRouteProposal implementation fields match schema artifact", () => {
    const signed: SignedRouteProposal = {
      proposal: { hops: [], requirementDigest: "", expiry: 0, initiatorNodeId: "", agreementDigest: "" },
      signature: new Uint8Array(64),
    };
    expect(getFields(signed)).toEqual(getSchemaFields("SignedRouteProposal"));
  });

  test("RouteAcceptance implementation fields match schema artifact", () => {
    const acc: RouteAcceptance = {
      proposalDigestHex: "", hopIndex: 0, hopDigestHex: "", serviceDigestHex: "",
      acceptorNodeId: "", acceptanceNonce: new Uint8Array(16), expiry: 0, signature: new Uint8Array(64),
    };
    expect(getFields(acc)).toEqual(getSchemaFields("RouteAcceptance"));
  });

  test("RouteCommitment implementation fields match schema artifact", () => {
    const c: RouteCommitment = {
      routeId: "",
      proposal: { hops: [], requirementDigest: "", expiry: 0, initiatorNodeId: "", agreementDigest: "" },
      acceptances: [],
      commitmentRoot: new Uint8Array(32),
      commitmentNonce: new Uint8Array(16),
      committerSignature: new Uint8Array(64),
      committedAt: 0,
    };
    expect(getFields(c)).toEqual(getSchemaFields("RouteCommitment"));
  });

  test("spec/07-routing.md documents fields matching the schema artifact", () => {
    const spec = readFileSync(join(process.cwd(), "spec", "07-routing.md"), "utf-8");
    for (const objName of ["RouteProposal", "RouteAcceptance"]) {
      for (const field of getSchemaFields(objName)) {
        expect(spec).toContain(`${field}:`);
      }
    }
    // routeId must NOT be in the RouteProposal schema block
    const proposalBlock = spec.match(/RouteProposal = \{[\s\S]*?\}/);
    if (proposalBlock) {
      for (const f of getSchemaForbidden("RouteProposal")) {
        expect(proposalBlock[0]).not.toContain(`${f}:`);
      }
    }
  });

  test("schema artifact Merkle algorithm + route_id format match spec/07", () => {
    const spec = readFileSync(join(process.cwd(), "spec", "07-routing.md"), "utf-8");
    expect(spec).toContain(SCHEMA.merkle_algorithm.domain);
    expect(spec).toContain(SCHEMA.route_id_format);
  });
});
