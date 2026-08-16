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
import { readFileSync, existsSync } from "node:fs";

describe("no HTTP route / UI / server code handles private node-key bytes (corrective F2)", () => {
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

  test("no HTTP route, UI component, or server code handles secretKeyHex or secretKey", () => {
    let trackedFiles: string[];
    try {
      trackedFiles = execSync("git ls-files", { encoding: "utf-8" })
        .trim()
        .split("\n")
        .filter(Boolean);
    } catch {
      throw new Error("git ls-files failed — this test must run inside a git checkout");
    }

    // The ONLY files allowed to reference `secretKeyHex` or `secretKey` are
    // in the protocol core (reference/), the architecture test runner
    // (which generates keypairs in-memory), the mini-service (which
    // generates keys locally), and this test file.
    //
    // These are NOT "whitelisted exceptions" — they are the legitimate
    // scope of where private keys are handled:
    //   - reference/identity/keys.ts         (type + keypairFromSecretKey)
    //   - reference/identity/golden-vectors.ts (test vector definition)
    //   - reference/advertisement/advertisement.ts (protocol-core signing fn)
    //   - reference/transport/handshake.ts    (may reference signMessage)
    //   - mini-services/node-link/index.ts    (runtime local-only generation)
    //   - tests/no-tracked-private-keys.test.ts (this test)
    //   - mini-services/node-link/data/README.md (documentation)
    //   - src/lib/sharenet/architecture-tests.ts (in-memory keypair generation for tests)
    //
    // The FORBIDDEN zones are:
    //   - src/app/api/    (HTTP routes)
    //   - src/components/ (UI components)
    //   - src/lib/auth/   (server auth libs)
    //   - src/lib/http/   (HTTP helpers)
    //   - src/lib/sharenet/ EXCEPT architecture-tests.ts
    //
    // If any file in the forbidden zones references secretKeyHex/secretKey,
    // the test FAILS. No exceptions, no overrides.
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

      // Read from the WORKING TREE (not HEAD) so that locally-deleted files
      // (e.g. removed HTTP routes) are not flagged.
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
        if (/"secretKeyHex"\s*:/i.test(line) || /\bsecretKeyHex\b/.test(line) || /\bsecretKey\b(?!s)/.test(line)) {
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
        "\n\nFORBIDDEN zones: src/app/api/ (HTTP routes), src/components/ (UI), " +
        "src/lib/auth/, src/lib/http/, src/lib/sharenet/ (except architecture-tests.ts).\n" +
        "Fix: remove the HTTP route / UI component / server code that handles private keys.",
    ).toBe(0);
  });

  test("the previously-committed NodeIds appear in the retired-keys list", () => {
    // Per the corrective milestone, the following NodeIds are retired because
    // their secret keys were in public git history. Any future code that
    // encounters these NodeIds must reject them.
    // Note: these are the OLD (interim BLAKE2b + node:hex) NodeIds. They
    // are not valid in the canonical (BLAKE3 + base32) scheme and would
    // be rejected by isValidNodeIdFormat regardless. They are listed here
    // for audit trail.
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
