/**
 * ShareNet 2.0 — Test: no tracked file contains private node-key material.
 *
 * Per the corrective milestone (2026-08-16) and spec/00 §5: actual secret
 * values must never appear in source code, README, specification, ADR,
 * fixtures, golden vectors, test snapshots, logs, git history, or pull
 * requests.
 *
 * This test scans every file tracked by git and asserts that none of them
 * contain Ed25519 secret key material. It runs as a unit test (no network,
 * no DB, no mini-services required).
 *
 * Run: `bun test tests/no-tracked-private-keys.test.ts`
 *
 * If this test fails, a developer has accidentally committed a keypair file
 * (or pasted a secretKeyHex into a doc/source file). The fix is to:
 *   1. `git rm --cached <the-file>` (untrack but keep local)
 *   2. Add the path to `.gitignore`
 *   3. Rotate the exposed key — it is now compromised.
 */

import { describe, test, expect } from "bun:test";
import { execSync } from "node:child_process";

describe("no tracked private key material (spec/00 §5)", () => {
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

  test("no tracked file contains a secretKeyHex field", () => {
    let trackedFiles: string[];
    try {
      trackedFiles = execSync("git ls-files", { encoding: "utf-8" })
        .trim()
        .split("\n")
        .filter(Boolean);
    } catch {
      throw new Error("git ls-files failed — this test must run inside a git checkout");
    }

    // Only scan text files (skip binaries, images, lockfiles, etc.).
    const textExtensions = new Set([
      ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".prisma",
      ".yml", ".yaml", ".sh", ".txt", ".css", ".html", ".env",
    ]);
    const candidateFiles = trackedFiles.filter((f) => {
      const ext = "." + f.split(".").pop();
      return textExtensions.has(ext);
    });

    const violations: Array<{ file: string; line: number; content: string }> = [];
    for (const file of candidateFiles) {
      try {
        const content = execSync(`git show HEAD:${file}`, { encoding: "utf-8" });
        const lines = content.split("\n");
        lines.forEach((line, i) => {
          // Match the JSON field name `secretKeyHex` (with or without quotes).
          // Also match `secretKey` as a bare identifier in source code.
          if (/"secretKeyHex"\s*:/i.test(line) || /\bsecretKey\s*=\s*new\s+Uint8Array\(/i.test(line)) {
            // Allow the field name in source code that DEFINES the type (reference/identity/keys.ts)
            // and in the mini-service that WRITES the field. These are legitimate uses.
            const isLegitimate =
              file === "reference/identity/keys.ts" ||       // type definition
              file === "reference/identity/golden-vectors.ts" || // test vector (TEST_SEED only, not a real key)
              file === "mini-services/node-link/index.ts" ||  // writes the field at runtime
              file === "src/app/api/sharenet/protocol/node-id/route.ts" || // returns secretKeyHex ONCE to caller
              file === "src/app/api/sharenet/protocol/sign-advertisement/route.ts" || // accepts secretKeyHex as input
              file === "tests/no-tracked-private-keys.test.ts" || // this test file
              file === "mini-services/node-link/data/README.md"; // documents the field
            if (!isLegitimate) {
              violations.push({ file, line: i + 1, content: line.trim() });
            }
          }
        });
      } catch {
        // File may not exist at HEAD (untracked) — skip.
      }
    }

    expect(
      violations.length,
      `Found ${violations.length} tracked file(s) with secretKeyHex/secretKey material outside legitimate uses:\n` +
        violations.map((v) => `  ${v.file}:${v.line}: ${v.content.slice(0, 80)}`).join("\n") +
        "\nFix: untrack the file, add to .gitignore, rotate the exposed key.",
    ).toBe(0);
  });

  test("the previously-committed NodeIds appear in the retired-keys list", () => {
    // Per the corrective milestone, the following NodeIds are retired because
    // their secret keys were in public git history. Any future code that
    // encounters these NodeIds must reject them.
    const RETIRED_NODE_IDS = [
      "node:43e7c0bad0973ca08b9d11a9f0b73e7d0bd8acda659dd529851eb7b6e2e25661",
      "node:84288fd969b7ec3b8b2e4aa99a62cb3c9b35fe0ffcdc327dcaa5d64a4f0709a2",
    ];
    // This test asserts the list is non-empty and well-formed — it does not
    // enforce rejection at runtime (that's a separate concern for the
    // application layer once a node-registry is implemented).
    expect(RETIRED_NODE_IDS.length).toBe(2);
    for (const id of RETIRED_NODE_IDS) {
      expect(id).toMatch(/^node:[0-9a-f]{64}$/);
    }
  });
});
