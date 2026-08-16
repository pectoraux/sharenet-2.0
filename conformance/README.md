# ShareNet 2.0 — Conformance Vectors

This directory holds frozen conformance vectors. Each subdirectory is
governed by `conformance/COVERAGE.md` (the coverage ledger).

| Subdirectory | Purpose | Status |
|--------------|---------|--------|
| `vectors/` | Frozen byte vectors (hex-encoded) with exact expected outputs | `planned` — see COVERAGE.md |
| `schemas/` | Canonical CDDL or JSON schemas for wire formats | `planned` |
| `runners/` | Scripts that execute vectors against an implementation | `planned` |
| `fixtures/` | Auxiliary fixtures (test keypairs with KNOWN-compromised secrets, etc.) | `planned` |

## Vector format (when authored)

Each vector is a single JSON file:

```json
{
  "id": "V-NODEID-001",
  "status": "draft",
  "spec": "spec/02-identity.md §2.1",
  "adr": "adr/0003-nodeid-derivation-frozen.md",
  "input": { "ed25519PublicKeyHex": "..." },
  "expected": { "nodeId": "node:..." },
  "computedAt": "2026-...",
  "computedBy": "reference/identity/keys.ts@<commit>",
  "notes": "..."
}
```

Until a vector file exists, the slot is `planned` and no file is committed.

## No fake values

Per the corrective milestone (2026-08-16):

- Do NOT commit placeholder hashes.
- Do NOT commit zero signatures.
- Do NOT commit invented expected values.
- Do NOT commit a vector with `status: "ratified"` until the Principal
  Architect has formally ratified it.

A `planned` slot has no file. An empty file is NOT a `planned` slot — it
is a violation of this rule.
