/**
 * GET /api/sharenet/spec
 * Lists the spec/ and adr/ documents on disk. Public (read-only).
 */

import { json, withErrors } from "@/lib/http/api-helpers";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.cwd();

export const GET = withErrors(async () => {
  const specDir = join(ROOT, "spec");
  const adrDir = join(ROOT, "adr");
  const specFiles = existsSync(specDir) ? readdirSync(specDir).filter((f) => f.endsWith(".md")).sort() : [];
  const adrFiles = existsSync(adrDir) ? readdirSync(adrDir).filter((f) => f.endsWith(".md")).sort() : [];

  return json({
    ok: true,
    spec: specFiles.map((name) => ({
      name,
      path: `spec/${name}`,
      sizeBytes: stat(join(specDir, name)),
      preview: preview(join(specDir, name)),
    })),
    adr: adrFiles.map((name) => ({
      name,
      path: `adr/${name}`,
      sizeBytes: stat(join(adrDir, name)),
      preview: preview(join(adrDir, name)),
    })),
  });
});

function stat(p: string): number {
  try { return readFileSync(p).length; } catch { return 0; }
}

function preview(p: string): string {
  try {
    const text = readFileSync(p, "utf-8");
    // Return the first 600 chars (covers the title + abstract + first sections).
    return text.slice(0, 600);
  } catch {
    return "";
  }
}
