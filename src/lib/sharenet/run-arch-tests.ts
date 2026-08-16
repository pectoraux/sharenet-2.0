/**
 * ShareNet 2.0 — Direct architecture test runner.
 *
 * Per the corrective milestones (2026-08-16):
 *   - (B4) `test:arch` must be runnable without a web server, curl, localhost
 *     network calls, database initialization, or mesh process.
 *   - (F2) An unexpected hang must become a failed named test, not an
 *     indefinitely blocked command. Each test has a per-test timeout
 *     (ARCH_TEST_TIMEOUT_MS = 10s) and the runner prints the current test
 *     name before execution.
 *
 * This script:
 *   1. Prints each test name BEFORE it runs (so a hang is diagnosable).
 *   2. Enforces a per-test timeout (a hung test becomes FAILED, not infinite).
 *   3. Force-exits after completion (so a lingering handle from a timed-out
 *      test cannot keep the process alive).
 *
 * Usage:
 *   bun run test:arch
 *
 * Exit code: 0 if no tests FAILED (skipped is OK). 1 if any test FAILED.
 */

import { runArchitectureTests } from "./architecture-tests";

const t0 = Date.now();
const result = await runArchitectureTests();
const elapsed = Date.now() - t0;

console.log("");
console.log("=== ShareNet 2.0 Architecture Regression Tests ===");
console.log(`Spec: ${result.spec}`);
console.log(`Ran at: ${result.ranAt}`);
console.log(`Duration: ${result.durationMs}ms (total wall: ${elapsed}ms)`);
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

// Force-exit after completion. A timed-out test may leave a pending setTimeout
// handle (the timeout promise) that keeps the event loop alive. process.exit
// guarantees the command terminates.
const exitCode = result.failed > 0 ? 1 : 0;
process.exit(exitCode);

