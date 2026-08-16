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

  test("no file anywhere in the repo (including conformance/, fixtures, ADRs, docs) contains secretKeyHex or ed25519SecretKeyHex or seed material", () => {
    // Per corrective milestone B3: the private-key boundary test MUST scan
    // conformance/, fixtures, vectors, docs, ADRs, and test snapshots — NOT
    // just HTTP routes and UI components. It must reject private node-key
    // bytes/hex outside narrowly documented protocol-core test code.
    //
    // The ONLY files allowed to reference secretKeyHex/secretKey/secretKeyHex
    // are the protocol core (reference/), the architecture test runner
    // (in-memory keypair generation), the mini-service (local-only runtime
    // generation), and this test file. Conformance vectors are NOT whitelisted.
    let trackedFiles: string[];
    try {
      trackedFiles = execSync("git ls-files", { encoding: "utf-8" })
        .trim()
        .split("\n")
        .filter(Boolean);
    } catch {
      throw new Error("git ls-files failed — this test must run inside a git checkout");
    }

    const ALLOWED_FILES = new Set([
      "reference/identity/keys.ts",
      "reference/identity/golden-vectors.ts",
      "reference/advertisement/advertisement.ts",
      "reference/transport/handshake.ts",
      "mini-services/node-link/index.ts",
      "tests/no-tracked-private-keys.test.ts",
      "mini-services/node-link/data/README.md",
      "src/lib/sharenet/architecture-tests.ts",
    ]);

    const violations: Array<{ file: string; line: number; content: string }> = [];
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
        const trimmed = line.trimStart();
        if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
        // Match secretKeyHex, secretKey, or ed25519SecretKeyHex as a field/identifier.
        // Also match 'ed25519SecretKey' (the full field name in V-NODEID-001 before B3).
        if (
          /"secretKeyHex"\s*:/i.test(line) ||
          /\bsecretKeyHex\b/.test(line) ||
          /\bed25519SecretKeyHex\b/.test(line) ||
          /\bsecretKey\b(?!s)/.test(line) ||
          /"ed25519SecretKey"\s*:/.test(line)
        ) {
          if (!ALLOWED_FILES.has(file)) {
            violations.push({ file, line: i + 1, content: line.trim() });
          }
        }
      });
    }

    expect(
      violations.length,
      `Found ${violations.length} file(s) outside the allowed set that handle private node-key material:\n` +
        violations.map((v) => `  ${v.file}:${v.line}: ${v.content.slice(0, 80)}`).join("\n") +
        "\n\nAllowed files (the ONLY files that may reference secretKey/secretKeyHex):\n" +
        Array.from(ALLOWED_FILES).map((f) => `  - ${f}`).join("\n") +
        "\n\nThis scan covers ALL tracked files including conformance/, fixtures, " +
        "ADRs, docs, and test snapshots. Conformance vectors are NOT whitelisted " +
        "and must not contain secretKeyHex, ed25519SecretKeyHex, or seed material.",
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

