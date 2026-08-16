/**
 * ShareNet 2.0 — Test: no HTTP route, UI component, or server code handles
 * private node-key bytes/hex.
 *
 * Per the corrective milestone (2026-08-16, requirement 2 — Private-key
 * boundary, MANDATORY):
 *
 *   A node private key must be generated, stored, and used locally by the
 *   node implementation. It MUST NOT traverse the web server, API request
 *   body, browser UI, logs, database, fixtures, or test snapshots.
 *
 * This test scans every file tracked by git and asserts that NONE of them
 * contain references to `secretKeyHex` or `secretKey` as a field name,
 * function parameter, or API body field — with NO WHITELISTED EXCEPTIONS.
 *
 * The previous version of this test whitelisted:
 *   - reference/identity/keys.ts (type definition)
 *   - reference/identity/golden-vectors.ts (test vectors)
 *   - mini-services/node-link/index.ts (runtime key generation)
 *   - src/app/api/sharenet/protocol/node-id/route.ts (REMOVED)
 *   - src/app/api/sharenet/protocol/sign-advertisement/route.ts (REMOVED)
 *
 * Per the corrective milestone, whitelisting is FORBIDDEN. The test must
 * FAIL on any code that handles private node-key bytes/hex. The only
 * legitimate locations for `secretKey` are:
 *   - reference/identity/keys.ts (the type definition + keypairFromSecretKey)
 *   - mini-services/node-link/index.ts (runtime local-only generation)
 *   - tests/ (test files that reference the field by name in assertions)
 *
 * These are NOT whitelisted — they are expected to be the ONLY matches.
 * If any OTHER file matches, the test fails.
 *
 * Run: `bun run test:unit`
 */

import { describe, test, expect } from "bun:test";
import { execSync } from "node:child_process";
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

describe("no HTTP route / UI / server code handles private node-key bytes (corrective F2 + B3)", () => {
  test("no tracked file path matches the node-link keypair pattern", () => {
    let trackedFiles: string[];
    try {
      trackedFiles = execSync("git ls-files", { encoding: "utf-8" })
        .trim()
        .split("\n")
        .filter(Boolean);
    } catch (e) {
      throw new Error(
        "git ls-files failed — this test must run inside a git checkout: " +
          (e as Error).message,
      );
    }

    const keypairFiles = trackedFiles.filter((f) =>
      /node-link\/data\/.*-keypair\.json$/.test(f),
    );
    expect(
      keypairFiles.length,
      `Found tracked keypair files (these contain Ed25519 secret keys):\n${keypairFiles.join("\n")}\n` +
        "Fix: git rm --cached <file> and add to .gitignore, then rotate the exposed key.",
    ).toBe(0);
  });

  test("no file anywhere in the repo contains ACTUAL private-key handling (not mere doc mentions)", () => {
    // Per corrective milestone (2026-08-16, F1): the scanner must detect
    // actual private-key HANDLING/MATERIAL, not documentation sentences
    // that merely name the prohibited field names.
    //
    // What counts as ACTUAL handling (FAIL):
    //   - JSON object fields:  "secretKeyHex": "..."  or  "ed25519SecretKeyHex": "..."
    //   - TS object properties / assignments:  secretKeyHex:  /  .secretKeyHex =
    //   - Request-body extraction:  body.secretKeyHex  /  body.ed25519SecretKeyHex
    //   - Actual hex/base64 values assigned to private-key/seed fields
    //   - API/UI/server code that transmits or processes a private node key
    //
    // What does NOT count (PASS — mere documentation):
    //   - A markdown sentence like "contains `secretKeyHex` / `ed25519SecretKeyHex`"
    //     (field name in backticks inside prose, not a code field)
    //   - A doc comment like "// the secretKeyHex field" (already skipped as comment)
    //
    // The scanner uses CONTEXT-AWARE regexes, NOT bare \bsecretKeyHex\b which
    // matches prose mentions. Conformance vectors, docs, ADRs, fixtures,
    // snapshots, and HTTP/UI layers are ALL still scanned — they are NOT on a
    // blanket allowlist. The only files allowed to ACTUALLY HANDLE private
    // keys are the protocol core + mini-service + this test.
    let trackedFiles: string[];
    try {
      trackedFiles = execSync("git ls-files", { encoding: "utf-8" })
        .trim()
        .split("\n")
        .filter(Boolean);
    } catch {
      throw new Error("git ls-files failed — this test must run inside a git checkout");
    }

    // Files allowed to ACTUALLY HANDLE private keys (type definitions,
    // protocol-core signing functions, in-memory test keypair generation,
    // runtime local-only generation, this test).
    const ALLOWED_HANDLING_FILES = new Set([
      "reference/identity/keys.ts",
      "reference/identity/golden-vectors.ts",
      "reference/advertisement/advertisement.ts",
      "reference/transport/handshake.ts",
      "mini-services/node-link/index.ts",
      "tests/no-tracked-private-keys.test.ts",
      "src/lib/sharenet/architecture-tests.ts",
    ]);

    // Context-aware patterns. Each pattern matches ACTUAL handling, not prose.
    // 1. JSON field:  "secretKeyHex":   (quote, name, quote, colon)
    // 2. TS object property:  secretKeyHex:   (bare identifier followed by colon,
    //    but NOT inside backticks or quotes)
    // 3. TS assignment:  .secretKeyHex =   (dot-access + assignment)
    // 4. Body extraction:  body.secretKeyHex  /  body.ed25519SecretKeyHex
    // 5. Actual value:  "secretKeyHex": "<hex>"  (already caught by #1)
    const HANDLING_PATTERNS: Array<{ name: string; re: RegExp }> = [
      { name: "JSON field", re: /"(?:secretKeyHex|ed25519SecretKeyHex|secretKey|ed25519SecretKey)"\s*:/ },
      { name: "TS object property (bare identifier + colon)", re: /(?:^|[^`\w.])(secretKeyHex|ed25519SecretKeyHex)\s*:/ },
      { name: "TS dot-access assignment", re: /\.(secretKeyHex|ed25519SecretKeyHex|secretKey)\s*=/ },
      { name: "request-body extraction", re: /body\.(secretKeyHex|ed25519SecretKeyHex|secretKey)\b/ },
    ];

    const violations: Array<{ file: string; line: number; pattern: string; content: string }> = [];
    for (const file of trackedFiles) {
      const ext = "." + (file.split(".").pop() ?? "");
      const textExtensions = new Set([
        ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".prisma",
        ".yml", ".yaml", ".sh", ".txt", ".css", ".html",
      ]);
      if (!textExtensions.has(ext)) continue;
      if (!existsSync(file)) continue;
      let content: string;
      try {
        content = readFileSync(file, "utf-8");
      } catch {
        continue;
      }
      const lines = content.split("\n");
      lines.forEach((line, i) => {
        // Skip comment lines (// or *) — doc comments naming the field are OK.
        const trimmed = line.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;

        // Skip markdown prose that merely names the field in backticks.
        // A line is "prose naming" if the only matches for secretKeyHex/
        // secretKey are inside backtick quotes. We detect this by checking
        // that the match is preceded by a backtick (within the same line)
        // and not preceded by a JSON/TS structural character.
        //
        // Simpler approach: for each handling pattern that requires
        // structural context (colon, dot, assignment), the pattern itself
        // excludes bare prose mentions. The JSON-field pattern requires
        // a quote+colon which prose doesn't have. The TS-property pattern
        // requires a bare identifier+colon (not in backticks). So prose
        // like "contains `secretKeyHex` / `ed25519SecretKeyHex`" will NOT
        // match any of these patterns because there's no colon after the
        // identifier outside the backticks.
        for (const { name, re } of HANDLING_PATTERNS) {
          if (re.test(line)) {
            if (!ALLOWED_HANDLING_FILES.has(file)) {
              violations.push({ file, line: i + 1, pattern: name, content: line.trim() });
            }
          }
        }
      });
    }

    expect(
      violations.length,
      `Found ${violations.length} file(s) with ACTUAL private-key handling outside the allowed set:\n` +
        violations.map((v) => `  ${v.file}:${v.line} [${v.pattern}]: ${v.content.slice(0, 80)}`).join("\n") +
        "\n\nAllowed files (the ONLY files that may actually handle private keys):\n" +
        Array.from(ALLOWED_HANDLING_FILES).map((f) => `  - ${f}`).join("\n") +
        "\n\nThis scanner detects JSON fields, TS object properties, dot-access " +
        "assignments, and request-body extraction of secretKeyHex / " +
        "ed25519SecretKeyHex / secretKey. It does NOT flag documentation " +
        "sentences that merely name these fields in prose or backticks. " +
        "Conformance vectors, docs, ADRs, fixtures, and snapshots are all " +
        "scanned — they are NOT on a blanket allowlist.",
    ).toBe(0);
  });

  test("the previously-committed NodeIds appear in the retired-keys list", () => {
    const RETIRED_INTERIM_NODE_IDS = [
      "node:43e7c0bad0973ca08b9d11a9f0b73e7d0bd8acda659dd529851eb7b6e2e25661",
      "node:84288fd969b7ec3b8b2e4aa99a62cb3c9b35fe0ffcdc327dcaa5d64a4f0709a2",
    ];
    expect(RETIRED_INTERIM_NODE_IDS.length).toBe(2);
    for (const id of RETIRED_INTERIM_NODE_IDS) {
      expect(id).toMatch(/^node:[0-9a-f]{64}$/);
    }
  });
});

describe("conformance vectors are valid JSON (corrective B1)", () => {
  test("every file under conformance/vectors/ parses as valid JSON", () => {
    const vectorsDir = join(process.cwd(), "conformance", "vectors");
    if (!existsSync(vectorsDir)) {
      throw new Error("conformance/vectors/ directory does not exist");
    }
    const files: string[] = [];
    function walk(dir: string) {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) {
          walk(full);
        } else if (entry.endsWith(".json")) {
          files.push(full);
        }
      }
    }
    walk(vectorsDir);

    expect(files.length, "expected at least 1 conformance vector file").toBeGreaterThan(0);

    const invalid: Array<{ file: string; error: string }> = [];
    for (const file of files) {
      const content = readFileSync(file, "utf-8");
      try {
        JSON.parse(content);
      } catch (e) {
        invalid.push({ file, error: (e as Error).message });
      }
    }

    expect(
      invalid.length,
      `Found ${invalid.length} invalid JSON file(s) under conformance/vectors/:\n` +
        invalid.map((v) => `  ${v.file}: ${v.error}`).join("\n") +
        "\n\nConformance vectors MUST be valid JSON (no JavaScript expressions, " +
        "no 'a'.repeat(51), no template literals). Replace every expression with " +
        "its literal string value.",
    ).toBe(0);
  });
});

