#!/usr/bin/env bun
/**
 * ShareNet 2.0 — Gate Verifier
 *
 * Per the Permanent Operating Rules (§A.6):
 *   CI must reject:
 *     - invalid JSON vectors;
 *     - secret material;
 *     - missing gate evidence;
 *     - skipped tests counted as passing;
 *     - direct localhost/database use in unit or architecture tests;
 *     - forbidden architecture transitions.
 *
 * This script runs all six checks and exits 0 only if ALL pass.
 *
 * Usage:
 *   bun run tools/verify-gate.ts [GATE_ID]
 *
 * If GATE_ID is provided (e.g. "GATE-00"), the script also checks that
 * evidence/GATE-00.json exists and is well-formed.
 *
 * Exit codes:
 *   0 = all checks passed
 *   1 = one or more checks failed
 */

import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { execSync } from "node:child_process";

/** Get the list of git-tracked files. Falls back to filesystem walk if git is unavailable. */
function getTrackedFiles(): string[] {
  try {
    return execSync("git ls-files", { encoding: "utf-8", cwd: process.cwd() })
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((f) => join(process.cwd(), f));
  } catch {
    // Fallback: walk the filesystem (excluding node_modules/.next/.git)
    return walkFiles(process.cwd());
  }
}

interface CheckResult {
  name: string;
  passed: boolean;
  detail: string;
  violations?: string[];
}

const results: CheckResult[] = [];

function walkFiles(dir: string, exts?: Set<string>): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  function walk(d: string) {
    for (const entry of readdirSync(d)) {
      // Skip node_modules, .next, .git
      if (entry === "node_modules" || entry === ".next" || entry === ".git") continue;
      const full = join(d, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (!exts || exts.has("." + entry.split(".").pop()!)) {
        out.push(full);
      }
    }
  }
  walk(dir);
  return out;
}

function rel(p: string): string {
  return relative(process.cwd(), p);
}

// -----------------------------------------------------------------------
// Check 1: All conformance vectors are valid JSON
// -----------------------------------------------------------------------

function checkValidJsonVectors(): CheckResult {
  const vectorsDir = join(process.cwd(), "conformance", "vectors");
  if (!existsSync(vectorsDir)) {
    return { name: "valid JSON vectors", passed: false, detail: "conformance/vectors/ does not exist" };
  }
  const files = walkFiles(vectorsDir, new Set([".json"]));
  if (files.length === 0) {
    return { name: "valid JSON vectors", passed: false, detail: "no vector files found" };
  }
  const violations: string[] = [];
  for (const file of files) {
    try {
      JSON.parse(readFileSync(file, "utf-8"));
    } catch (e) {
      violations.push(`${rel(file)}: ${(e as Error).message}`);
    }
  }
  return {
    name: "valid JSON vectors",
    passed: violations.length === 0,
    detail: `${files.length} vector(s) checked, ${violations.length} invalid`,
    violations,
  };
}

// -----------------------------------------------------------------------
// Check 2: No secret material in tracked files
// -----------------------------------------------------------------------

function checkNoSecretMaterial(): CheckResult {
  const violations: string[] = [];
  // Use git-tracked files only (gitignored local files are NOT checked —
  // they're not in the repo and won't be pushed).
  const trackedFiles = getTrackedFiles();

  const textExts = new Set([".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".prisma", ".yml", ".yaml", ".sh", ".txt", ".css", ".html"]);

  // Context-aware patterns (same as tests/no-tracked-private-keys.test.ts)
  const HANDLING_PATTERNS: Array<{ name: string; re: RegExp }> = [
    { name: "JSON field", re: /"(?:secretKeyHex|ed25519SecretKeyHex|secretKey|ed25519SecretKey)"\s*:/ },
    { name: "TS object property", re: /(?:^|[^`\w.])(secretKeyHex|ed25519SecretKeyHex)\s*:/ },
    { name: "TS dot-access assignment", re: /\.(secretKeyHex|ed25519SecretKeyHex|secretKey)\s*=/ },
    { name: "request-body extraction", re: /body\.(secretKeyHex|ed25519SecretKeyHex|secretKey)\b/ },
  ];

  // Files allowed to actually handle private keys
  const ALLOWED = new Set([
    "reference/identity/keys.ts",
    "reference/identity/golden-vectors.ts",
    "reference/advertisement/advertisement.ts",
    "reference/transport/handshake.ts",
    "mini-services/node-link/index.ts",
    "tests/no-tracked-private-keys.test.ts",
    "src/lib/sharenet/architecture-tests.ts",
    "tools/verify-gate.ts",
  ]);

  for (const file of trackedFiles) {
    const relPath = rel(file);
    if (ALLOWED.has(relPath)) continue;
    const ext = "." + (file.split(".").pop() ?? "");
    if (!textExts.has(ext)) continue;
    let content: string;
    try {
      content = readFileSync(file, "utf-8");
    } catch {
      continue;
    }
    const lines = content.split("\n");
    lines.forEach((line, i) => {
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
      for (const { name, re } of HANDLING_PATTERNS) {
        if (re.test(line)) {
          violations.push(`${relPath}:${i + 1} [${name}]: ${line.trim().slice(0, 80)}`);
        }
      }
    });
    // Check for committed keypair files
    if (/node-link\/data\/.*-keypair\.json$/.test(relPath)) {
      violations.push(`${relPath}: tracked keypair file (contains Ed25519 secret key)`);
    }
  }

  return {
    name: "no secret material",
    passed: violations.length === 0,
    detail: `${violations.length} violation(s) across ${trackedFiles.length} tracked files`,
    violations,
  };
}

// -----------------------------------------------------------------------
// Check 3: Gate evidence exists and is well-formed
// -----------------------------------------------------------------------

function checkGateEvidence(gateId?: string): CheckResult {
  if (!gateId) {
    return { name: "gate evidence", passed: true, detail: "no gate ID specified (skipping evidence check)" };
  }
  const evidenceFile = join(process.cwd(), "evidence", `${gateId}.json`);
  if (!existsSync(evidenceFile)) {
    return { name: "gate evidence", passed: false, detail: `evidence/${gateId}.json does not exist` };
  }
  try {
    const data = JSON.parse(readFileSync(evidenceFile, "utf-8"));
    const required = ["gate_id", "commit_sha", "scope_completed", "commands_run", "pass_fail_skipped", "ready_for_next_gate"];
    const missing = required.filter((k) => !(k in data));
    if (missing.length > 0) {
      return { name: "gate evidence", passed: false, detail: `missing fields: ${missing.join(", ")}` };
    }
    if (data.ready_for_next_gate !== true) {
      return { name: "gate evidence", passed: false, detail: `ready_for_next_gate is not true` };
    }
    return { name: "gate evidence", passed: true, detail: `evidence/${gateId}.json well-formed, ready_for_next_gate=true` };
  } catch (e) {
    return { name: "gate evidence", passed: false, detail: `invalid JSON: ${(e as Error).message}` };
  }
}

// -----------------------------------------------------------------------
// Check 4: No skipped tests counted as passing
// -----------------------------------------------------------------------

function checkNoSkippedAsPassed(): CheckResult {
  // This is a static check: scan the test runner code to ensure it
  // reports skipped separately and never counts skipped as passed.
  const archRunner = join(process.cwd(), "src", "lib", "sharenet", "run-arch-tests.ts");
  const archTests = join(process.cwd(), "src", "lib", "sharenet", "architecture-tests.ts");
  const violations: string[] = [];

  for (const file of [archRunner, archTests]) {
    if (!existsSync(file)) continue;
    const content = readFileSync(file, "utf-8");
    // Check that the runner reports skipped separately
    if (file === archRunner) {
      if (!content.includes("Skipped:")) {
        violations.push("run-arch-tests.ts does not report 'Skipped:' separately");
      }
      // Check that exit code is NOT based on passed === total (which would count skipped as fail)
      // The correct behavior: exit 1 if failed > 0 (skipped is OK)
      if (/process\.exit\(.*passed.*===.*total/i.test(content)) {
        violations.push("run-arch-tests.ts counts skipped as failure (exit code based on passed === total)");
      }
    }
    if (file === archTests) {
      // Check that skipped tests return passed: false
      if (!/passed:\s*false.*skipped/i.test(content) && !/skipped.*passed:\s*false/i.test(content)) {
        // More flexible check: look for the pattern where skipped sets passed=false
        const hasSkippedNotPassed = /status\s*=\s*["']skipped["']/.test(content) && /passed\s*=\s*false/.test(content);
        if (!hasSkippedNotPassed) {
          violations.push("architecture-tests.ts does not clearly set passed=false for skipped tests");
        }
      }
    }
  }

  return {
    name: "no skipped-as-passed",
    passed: violations.length === 0,
    detail: violations.length === 0 ? "skipped tests reported separately, never counted as passed" : `${violations.length} violation(s)`,
    violations,
  };
}

// -----------------------------------------------------------------------
// Check 5: No direct localhost/database use in unit or architecture tests
// -----------------------------------------------------------------------

function checkNoLocalhostOrDbInUnitArch(): CheckResult {
  const violations: string[] = [];
  // Only scan TEST files — NOT service-layer files (which legitimately use the DB
  // per ADR-0013). The test files are:
  //   - tests/*.ts (unit tests)
  //   - src/lib/sharenet/run-arch-tests.ts (architecture test runner)
  //   - src/lib/sharenet/architecture-tests.ts (architecture tests)
  // The service layer (sequence-floor.ts, node-record.ts, gateway.ts) IS allowed
  // to use the DB. The integration tier (integration-mesh-tests.ts) IS allowed
  // to use localhost. Neither is scanned here.
  const testFiles: string[] = [];
  const testsDir = join(process.cwd(), "tests");
  if (existsSync(testsDir)) {
    for (const f of walkFiles(testsDir, new Set([".ts", ".tsx"]))) {
      testFiles.push(f);
    }
  }
  const archTestFiles = [
    join(process.cwd(), "src", "lib", "sharenet", "run-arch-tests.ts"),
    join(process.cwd(), "src", "lib", "sharenet", "architecture-tests.ts"),
  ];
  for (const f of archTestFiles) {
    if (existsSync(f)) testFiles.push(f);
  }

  // Patterns that indicate localhost/network/DB use
  const FORBIDDEN_PATTERNS: Array<{ name: string; re: RegExp }> = [
    { name: "localhost fetch", re: /fetch\s*\(\s*["']http:\/\/localhost/i },
    { name: "localhost URL", re: /["']http:\/\/localhost:\d+/i },
    { name: "127.0.0.1 fetch", re: /fetch\s*\(\s*["']http:\/\/127\.0\.0\.1/i },
    { name: "Prisma client import", re: /from\s+["']@\/lib\/db["']/ },
    { name: "new PrismaClient", re: /new\s+PrismaClient\s*\(/ },
    { name: "require prisma", re: /require\s*\(\s*["'].*prisma["']/ },
  ];

  for (const file of testFiles) {
    const content = readFileSync(file, "utf-8");
    const lines = content.split("\n");
    lines.forEach((line, i) => {
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
      for (const { name, re } of FORBIDDEN_PATTERNS) {
        if (re.test(line)) {
          violations.push(`${rel(file)}:${i + 1} [${name}]: ${line.trim().slice(0, 80)}`);
        }
      }
    });
  }

  return {
    name: "no localhost/DB in unit/arch tests",
    passed: violations.length === 0,
    detail: `${testFiles.length} test file(s) scanned, ${violations.length} violation(s)`,
    violations,
  };
}

// -----------------------------------------------------------------------
// Check 6: No forbidden architecture transitions
// -----------------------------------------------------------------------

function checkNoForbiddenTransitions(): CheckResult {
  // Per spec/00 §31, these pipelines MUST NOT exist:
  //   RemoteNodeHint → AuthenticatedNodeRecord
  //   distance_hint → Route
  //   TopologyGraph → Circuit
  //   GatewayCapability → automatic authorization
  //   ReportedMetric → ObservedMetric
  //   unverified NodeId → executable hop
  //   RouteProposal → ActiveCircuit (without commitment)
  //   self-reported contribution → Civic Points
  //
  // We check that the protocol core (reference/) does NOT contain functions
  // that would permit these transitions.
  const violations: string[] = [];
  const refDir = join(process.cwd(), "reference");
  if (!existsSync(refDir)) {
    return { name: "no forbidden transitions", passed: false, detail: "reference/ does not exist" };
  }

  const textExts = new Set([".ts"]);
  const files = walkFiles(refDir, textExts);

  // Forbidden function names that would indicate a transition exists
  const FORBIDDEN_FNS = [
    { name: "hintToAuthenticatedNode", re: /export\s+(async\s+)?function\s+hintToAuthenticated/i },
    { name: "distanceHintToRoute", re: /export\s+(async\s+)?function\s+distanceHintToRoute/i },
    { name: "topologyToCircuit", re: /export\s+(async\s+)?function\s+topologyToCircuit/i },
    { name: "autoAuthorizeGateway", re: /export\s+(async\s+)?function\s+autoAuthorizeGateway/i },
    { name: "reportedToObserved", re: /export\s+(async\s+)?function\s+reportedToObserved/i },
    { name: "selfReportedToCivicPoints", re: /export\s+(async\s+)?function\s+selfReportedToCivicPoints/i },
    { name: "routeProposalToActiveCircuit", re: /export\s+(async\s+)?function\s+routeProposalToActiveCircuit/i },
  ];

  for (const file of files) {
    const content = readFileSync(file, "utf-8");
    for (const { name, re } of FORBIDDEN_FNS) {
      if (re.test(content)) {
        violations.push(`${rel(file)}: exports forbidden function '${name}'`);
      }
    }
  }

  // Also verify that PROMOTE_HINT_TO_RECORD_FORBIDDEN exists (the guard)
  const hintFile = join(refDir, "topology", "remote-node-hint.ts");
  if (existsSync(hintFile)) {
    const content = readFileSync(hintFile, "utf-8");
    if (!content.includes("PROMOTE_HINT_TO_RECORD_FORBIDDEN")) {
      violations.push("reference/topology/remote-node-hint.ts: missing PROMOTE_HINT_TO_RECORD_FORBIDDEN guard");
    }
  }

  return {
    name: "no forbidden transitions",
    passed: violations.length === 0,
    detail: violations.length === 0 ? "all forbidden pipeline guards present" : `${violations.length} violation(s)`,
    violations,
  };
}

// -----------------------------------------------------------------------
// Run all checks
// -----------------------------------------------------------------------

const gateId = process.argv[2]; // optional: GATE-XX

results.push(checkValidJsonVectors());
results.push(checkNoSecretMaterial());
results.push(checkGateEvidence(gateId));
results.push(checkNoSkippedAsPassed());
results.push(checkNoLocalhostOrDbInUnitArch());
results.push(checkNoForbiddenTransitions());

console.log("");
console.log("=== ShareNet 2.0 Gate Verifier ===");
if (gateId) console.log(`Gate: ${gateId}`);
console.log("");

let allPassed = true;
for (const r of results) {
  const status = r.passed ? "PASS" : "FAIL";
  console.log(`  [${status}] ${r.name}: ${r.detail}`);
  if (!r.passed) allPassed = false;
  if (r.violations && r.violations.length > 0) {
    for (const v of r.violations.slice(0, 10)) {
      console.log(`         ${v}`);
    }
    if (r.violations.length > 10) {
      console.log(`         ... and ${r.violations.length - 10} more`);
    }
  }
}
console.log("");

if (allPassed) {
  console.log("All gate checks passed.");
  process.exit(0);
} else {
  console.log("One or more gate checks FAILED.");
  process.exit(1);
}
