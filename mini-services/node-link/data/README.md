# node-link/data/

**This directory is gitignored.** Keypair files are generated at runtime
by the node-link mini-service and stored here for persistence across restarts.

## Why runtime-generated?

Per spec/00 §5 (Environment Variables / Secret Injection) and the corrective
milestone in ADR-0015-companion:

> Actual secret values must never appear in:
>   source code, README, specification, ADR, fixtures, golden vectors,
>   test snapshots, logs, git history, pull requests.

The Ed25519 `secretKeyHex` in each `*-keypair.json` file is a secret value.
Committing it would be a protocol-security defect.

## How keys are generated

The node-link mini-service (`mini-services/node-link/index.ts`) calls
`generateNodeKeypair()` from `reference/identity/keys.ts` on first boot when
no keypair file exists. The generated keypair is written to:

```
mini-services/node-link/data/<NODE_NAME>/<NODE_NAME>-keypair.json
```

The `NODE_NAME` environment variable controls the filename. The
`PERSIST_DIR` environment variable controls the parent directory (defaults
to `mini-services/node-link/data/<NODE_NAME>`).

## Retired keys (DO NOT REUSE)

The following NodeIds were previously committed to public git history
(corrective milestone 2026-08-16). They are **retired and must never be
reused**:

- `node:43e7c0bad0973ca08b9d11a9f0b73e7d0bd8acda659dd529851eb7b6e2e25661`
  (was `node-a`)
- `node:84288fd969b7ec3b8b2e4aa99a62cb3c9b35fe0ffcdc327dcaa5d64a4f0709a2`
  (was `node-b`)

Their corresponding Ed25519 secret keys are in git history and must be
treated as compromised. Any future ShareNet deployment that encounters
these NodeIds MUST reject them at the application layer.

## Local development

To generate fresh local development keys, delete this directory and restart
the mini-services:

```bash
rm -rf mini-services/node-link/data/
bash mini-services/node-link/start-mesh.sh
```

The mini-service will generate new keypairs on first boot.
