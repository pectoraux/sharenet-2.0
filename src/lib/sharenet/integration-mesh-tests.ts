/**
 * ShareNet 2.0 — Integration test: two-process advertisement-verification exchange.
 *
 * Per the corrective milestone (2026-08-16, B4):
 *   This is the ONLY test command allowed to start/query node-link processes
 *   or use localhost sockets. It is separate from `test:arch` (which is
 *   deterministic, no HTTP, no localhost, no DB).
 *
 * This test (formerly architecture test #25) verifies that two real
 * independent Bun processes (Node A on control=3001/wire=7788, Node B on
 * control=3002/wire=7789) can complete an advertisement-verification exchange
 * over a real TCP socket.
 *
 * What it proves:
 *   - Both nodes generate distinct Ed25519 keypairs + canonical NodeIds.
 *   - Node A dials Node B's wire port.
 *   - Both nodes report ADV_VERIFIED (advertisement-verified, NOT LINK_UP —
 *     see ADR-0016 for the replay defect).
 *   - The two LinkIds differ (directional invariant: A→B ≠ B→A).
 *   - Mutual NodeId binding (A's link points to B's nodeId, B's to A's).
 *
 * What it does NOT prove (per ADR-0016):
 *   - Fresh possession of the signing key bound to the connection transcript.
 *   - Resistance to advertisement replay.
 *   - The link is "authenticated" in the cryptographic sense.
 *
 * Usage:
 *   bun run test:integration:mesh
 *
 * Exit code: 0 if the test passed. 1 if it failed. 2 if it was skipped
 * (mini-services unreachable).
 */

interface IntegrationResult {
  status: "passed" | "failed" | "skipped";
  reason?: string;
  detail?: string;
}

async function runMeshIntegrationTest(): Promise<IntegrationResult> {
  // Step 1: check both node processes are reachable.
  const [aStatus, bStatus] = await Promise.all([
    fetch("http://localhost:3001/status", { signal: AbortSignal.timeout(2000) })
      .then((r) => r.json() as Promise<{ ok: boolean; node?: { nodeId: string } }>)
      .catch(() => null),
    fetch("http://localhost:3002/status", { signal: AbortSignal.timeout(2000) })
      .then((r) => r.json() as Promise<{ ok: boolean; node?: { nodeId: string } }>)
      .catch(() => null),
  ]);

  if (!aStatus?.ok || !bStatus?.ok) {
    return {
      status: "skipped",
      reason: `node-link mini-services not reachable on localhost:3001/3002 (run 'bash mini-services/node-link/start-mesh.sh' locally)`,
      detail: `node-a=${aStatus?.ok ? "up" : "down"}, node-b=${bStatus?.ok ? "up" : "down"}`,
    };
  }

  // Step 2: tell Node A to dial Node B's wire port (7789).
  const dialRes = await fetch("http://localhost:3001/dial", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host: "127.0.0.1", port: 7789 }),
    signal: AbortSignal.timeout(15000),
  })
    .then((r) => r.json() as Promise<{ ok: boolean; linkId?: string; reason?: string }>)
    .catch((e) => ({ ok: false, reason: e.message } as const));

  if (!dialRes.ok || !dialRes.linkId) {
    return {
      status: "failed",
      reason: `dial failed: ${dialRes.reason ?? "no linkId"}`,
    };
  }

  // Step 3: query both nodes' link registries — both should report ADV_VERIFIED.
  const [aLinks, bLinks] = await Promise.all([
    fetch("http://localhost:3001/links", { signal: AbortSignal.timeout(2000) })
      .then((r) => r.json() as Promise<{ links: Array<{ state: string; localNodeId: string; remoteNodeId: string; linkId: string }> }>)
      .catch(() => ({ links: [] })),
    fetch("http://localhost:3002/links", { signal: AbortSignal.timeout(2000) })
      .then((r) => r.json() as Promise<{ links: Array<{ state: string; localNodeId: string; remoteNodeId: string; linkId: string }> }>)
      .catch(() => ({ links: [] })),
  ]);

  const aUp = aLinks.links.find((l) => l.state === "ADV_VERIFIED");
  const bUp = bLinks.links.find((l) => l.state === "ADV_VERIFIED");

  if (!aUp || !bUp) {
    return {
      status: "failed",
      reason: `both nodes should report ADV_VERIFIED; node-a has ${aLinks.links.length} link(s), node-b has ${bLinks.links.length} link(s)`,
    };
  }

  // Step 4: assert the directional invariant — A's linkId ≠ B's linkId.
  const directional = aUp.linkId !== bUp.linkId;

  // Step 5: assert mutual NodeId binding.
  const aSeesB = aUp.remoteNodeId === bStatus.node!.nodeId;
  const bSeesA = bUp.remoteNodeId === aStatus.node!.nodeId;

  if (directional && aSeesB && bSeesA) {
    return {
      status: "passed",
      detail: `directional=${directional}, A→B sees B=${aSeesB}, B→A sees A=${bSeesA}`,
    };
  }

  return {
    status: "failed",
    reason: `directional=${directional}, A→B sees B=${aSeesB}, B→A sees A=${bSeesA}`,
  };
}

// Run and report.
const result = await runMeshIntegrationTest();
console.log("");
console.log("=== ShareNet 2.0 Integration Test: Two-Process Advertisement-Verification Exchange ===");
console.log(`Status: ${result.status.toUpperCase()}`);
if (result.reason) console.log(`Reason: ${result.reason}`);
if (result.detail) console.log(`Detail: ${result.detail}`);
console.log("");

if (result.status === "passed") process.exit(0);
if (result.status === "skipped") process.exit(2);
process.exit(1);
