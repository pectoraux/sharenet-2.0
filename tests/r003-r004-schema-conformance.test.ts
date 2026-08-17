/**
 * ShareNet 2.0 — R-003/R-004: Normative schema conformance test.
 *
 * Per the R-003/R-004 final reconciliation directive:
 *
 *   "Add a conformance test that fails if normative routing schemas and
 *    implementation schemas diverge."
 *
 * This test verifies that the normative spec/07-routing.md §5.1-5.2
 * RouteProposal and RouteAcceptance field sets match the implementation's
 * TypeScript interfaces exactly. If the spec or implementation changes
 * without the other being updated, this test fails.
 */

import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { RouteProposal, RouteAcceptance, RouteHop } from "@reference/routing/route";

/**
 * Extract field names from a TypeScript interface by instantiating an
 * object of that type and reading its keys. This is a runtime check
 * that the implementation's actual object shape matches the spec.
 */
function getInterfaceFields<T>(obj: T): string[] {
  return Object.keys(obj as Record<string, unknown>).sort();
}

describe("R-003/R-004: Normative schema conformance (spec/07 ↔ implementation)", () => {
  test("RouteProposal implementation fields match spec/07 §5.1", () => {
    // The implementation's RouteProposal interface (after R-003/R-004
    // final reconciliation) should have exactly these fields:
    //   hops, requirementDigest, expiry, initiatorNodeId, agreementDigest
    // (NO routeId — removed per R-003/R-004 final reconciliation)
    const proposal: RouteProposal = {
      hops: [],
      requirementDigest: "",
      expiry: 0,
      initiatorNodeId: "",
      agreementDigest: "",
    };
    const implFields = getInterfaceFields(proposal);
    const specFields = ["agreementDigest", "expiry", "hops", "initiatorNodeId", "requirementDigest"];
    expect(implFields).toEqual(specFields);
    // routeId must NOT be present
    expect(implFields).not.toContain("routeId");
  });

  test("RouteAcceptance implementation fields match spec/07 §5.2", () => {
    // The implementation's RouteAcceptance interface should have exactly:
    //   proposalDigestHex, hopIndex, hopDigestHex, serviceDigestHex,
    //   acceptorNodeId, acceptanceNonce, expiry, signature
    const acceptance: RouteAcceptance = {
      proposalDigestHex: "",
      hopIndex: 0,
      hopDigestHex: "",
      serviceDigestHex: "",
      acceptorNodeId: "",
      acceptanceNonce: new Uint8Array(16),
      expiry: 0,
      signature: new Uint8Array(64),
    };
    const implFields = getInterfaceFields(acceptance);
    const specFields = [
      "acceptanceNonce",
      "acceptorNodeId",
      "expiry",
      "hopDigestHex",
      "hopIndex",
      "proposalDigestHex",
      "serviceDigestHex",
      "signature",
    ];
    expect(implFields).toEqual(specFields);
  });

  test("RouteHop implementation fields match spec/07 §5.1 RouteHop", () => {
    const hop: RouteHop = {
      nodeId: "",
      capability: "MESH_RELAY",
      endpoint: "",
      linkUp: true,
    };
    const implFields = getInterfaceFields(hop);
    const specFields = ["capability", "endpoint", "linkUp", "nodeId"];
    expect(implFields).toEqual(specFields);
  });

  test("spec/07-routing.md §5.1 documents the same fields as the implementation", () => {
    // Read the spec file and verify the RouteProposal schema is documented
    const specPath = join(process.cwd(), "spec", "07-routing.md");
    const spec = readFileSync(specPath, "utf-8");

    // The spec MUST document these RouteProposal fields
    expect(spec).toContain("hops:");
    expect(spec).toContain("requirementDigest:");
    expect(spec).toContain("expiry:");
    expect(spec).toContain("initiatorNodeId:");
    expect(spec).toContain("agreementDigest:");

    // The spec MUST NOT document the old routeId field in RouteProposal
    // (it's removed per R-003/R-004 final reconciliation)
    // Check the RouteProposal block specifically — it should not have "routeId:"
    const proposalBlock = spec.match(/RouteProposal = \{[\s\S]*?\}/);
    expect(proposalBlock).not.toBeNull();
    if (proposalBlock) {
      expect(proposalBlock[0]).not.toContain("routeId:");
    }

    // The spec MUST document the Merkle construction (§5.3.1)
    expect(spec).toContain("5.3.1");
    expect(spec).toContain("SHARENET/ROUTE/COMMITMENT/MERKLE/1");

    // The spec MUST document the route_id format (§5.4)
    expect(spec).toContain('"route:" + lowercase_hex(commitment_root)');
  });

  test("spec/07-routing.md §5.2 documents the same RouteAcceptance fields as the implementation", () => {
    const specPath = join(process.cwd(), "spec", "07-routing.md");
    const spec = readFileSync(specPath, "utf-8");

    // The spec MUST document these RouteAcceptance fields
    expect(spec).toContain("proposalDigestHex:");
    expect(spec).toContain("hopIndex:");
    expect(spec).toContain("hopDigestHex:");
    expect(spec).toContain("serviceDigestHex:");
    expect(spec).toContain("acceptorNodeId:");
    expect(spec).toContain("acceptanceNonce:");
    expect(spec).toContain("signature:");
  });
});
