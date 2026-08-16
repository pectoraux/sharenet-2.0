/**
 * ShareNet 2.0 — Direct architecture test runner.
 *
 * Per the corrective milestone (2026-08-16, requirement 5):
 *   `test:arch` must be runnable without requiring a web server or `curl`.
 *
 * This script runs the architecture test suite directly via `bun run`,
 * with no HTTP server, no curl, no network dependency. It is deterministic
 * for tests #1-24, #25, and #25 returns `skipped` when the node-link
 * mini-services are not reachable.
 *
 * Usage:
 *   bun run test:arch
 *
 * Exit code: 0 if no tests FAILED (skipped is OK). 1 if any test FAILED.
 */

import { runArchitectureTests } from "./architecture-tests";

const result = await runArchitectureTests();

console.log("");
console.log("=== ShareNet 2.0 Architecture Regression Tests ===");
console.log(`Spec: ${result.spec}`);
console.log(`Ran at: ${result.ranAt}`);
console.log(`Duration: ${result.durationMs}ms`);
console.log("");
console.log(`  Total:   ${result.totalTests}`);
console.log(`  Passed:  ${result.passed}`);
console.log(`  Failed:  ${result.failed}`);
console.log(`  Skipped: ${result.skipped}`);
console.log("");

if (result.failed > 0) {
  console.log("FAILED tests:");
  for (const r of result.results.filter((r) => r.status === "failed")) {
    console.log(`  #${r.id} ${r.name}`);
    console.log(`    expected: ${r.expected}`);
    console.log(`    actual:   ${r.actual}`);
  }
  console.log("");
}

if (result.skipped > 0) {
  console.log("SKIPPED tests (NOT counted as passed):");
  for (const r of result.results.filter((r) => r.status === "skipped")) {
    console.log(`  #${r.id} ${r.name}`);
    console.log(`    reason: ${r.skipReason ?? r.actual}`);
  }
  console.log("");
}

// Exit 1 if any test FAILED. Skipped tests do NOT cause a failure.
process.exit(result.failed > 0 ? 1 : 0);
