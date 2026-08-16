# ShareNet 2.0 — Milestone Tracker

Per the Permanent Operating Rules (§A.2), every session must update this file.
Advance only when `ready_for_next_gate: true` and CI verifies the gate evidence.

| Gate | Title | Status | Commit | Evidence |
|------|-------|--------|--------|----------|
| GATE-00 | Stabilize the repository | ✅ COMPLETE | `cac00cc` | `evidence/GATE-00.json` |
| GATE-01 | Conformance foundation | ✅ COMPLETE | `73eada1` | `evidence/GATE-01.json` |
| GATE-02 | Identity and persistent advertisement state | ✅ COMPLETE | `2c6ac24` | `evidence/GATE-02.json` |
| GATE-03 | Secure authenticated directed links | ✅ COMPLETE | `d4a241c` | `evidence/GATE-03.json` |
| GATE-04 | Discovery and topology hints | ✅ COMPLETE | `26eda87` | `evidence/GATE-04.json` |
| GATE-05 | Service negotiation and route commitment | ✅ COMPLETE | `9004c0e` | `evidence/GATE-05.json` |
| GATE-06 | Circuits and encrypted forwarding | ✅ COMPLETE | `fdf49f0` | `evidence/GATE-06.json` |
| GATE-07 | Mode A Internet gateway | ⏳ PENDING | — | — |
| GATE-08 | Recovery | ⏳ PENDING | — | — |
| GATE-09 | Linux transparent networking | ⏳ PENDING | — | — |
| GATE-10 | Android north-star | ⏳ PENDING | — | — |
| GATE-11 | Contribution proofs | ⏳ PENDING | — | — |
| GATE-12 | Civic Points | ⏳ PENDING | — | — |
| GATE-13 | Content, external crypto, compute | ⏳ PENDING | — | — |

## Gate exit criteria summary

### GATE-00 — Stabilize the repository
- lint: zero errors
- unit: zero failures
- architecture: zero failures/skips
- no private-key material
- gate verifier passes
- `bun install --frozen-lockfile`, lint, unit, architecture tests all complete in a clean checkout

### GATE-01 — Conformance foundation
- CDDL/JSON schemas for NodeId, advertisement, link handshake, topology hint, route, circuit, gateway negotiation
- Ratified NodeId and CBOR vectors
- Real Ed25519 advertisement vectors: valid, invalid signature, expired, malformed, rollback
- Vector runner reads files from `conformance/vectors/`; no runtime-only golden vectors
- At least one independent Python verifier for NodeId/CBOR/advertisement vectors

### GATE-02 — Identity and persistent advertisement state
- Canonical CBOR advertisement encoding
- Ed25519 verification
- Timestamp/TTL/nonce validation
- Persistent monotonic peer sequence floors
- Atomic local persistence abstraction
- `VerifiedNodeAdvertisement` and `AuthenticatedNodeRecord` as distinct types
- No hosted database dependency in `reference/`

### GATE-03 — Secure authenticated directed links
- Exact accepted handshake schema and ADR (ADR-0016 approved)
- Challenge cache, expiration, replay rejection, failure reasons
- Three-message possession-proof handshake
- Directional LinkId with ratified BLAKE3 schema/vector
- Real TCP integration: two independent processes
- Tests for valid, tampered, replayed, wrong-role, wrong-LinkId proof

### GATE-04 — Discovery and topology hints
- Endpoint discovery abstraction
- `RemoteNodeHint` type
- Signed propagation message
- Separate propagation sequence floor
- Bounded size, horizon, freshness, provenance, replay protection
- Direct gateways and gateway hints as separate APIs

### GATE-05 — Service negotiation and route commitment
- `ServiceRequirement`, capability offer, policy check, capacity check, service agreement
- `RouteProposal`, `RouteAcceptance`, `RouteCommitment`, `CommittedRoute`
- Each hop requires authenticated node, `LINK_UP`, transport, role, policy, service compatibility
- Acceptance signatures bind ordered hops, route ID, agreement digest, expiry

### GATE-06 — Circuits and encrypted forwarding
- X25519 key agreement
- HKDF/domain-separated key schedule
- AEAD algorithm and nonce layout frozen in ADR/vectors
- Replay protection
- Route/circuit binding
- Distributed relay setup, acknowledgements, possession proofs, expiration
- Relays never receive application plaintext

### GATE-07 — Mode A Internet gateway
- Request/response framing
- DNS policy and resolution semantics
- Destination allowlist
- Private, loopback, link-local, metadata/SSRF blocking after DNS resolution
- Per-peer/global quotas, shaping, rate limits, revocation
- Signed service measurements and structured audit events
- No open-proxy behavior

### GATE-08 — Recovery
- Link degradation/down detection
- Affected-route invalidation
- Alternative gateway discovery
- New route/new circuit
- No claim of arbitrary TCP migration

### GATE-09 — Linux transparent networking
- Linux TUN adapter
- Local proxy/TUN policy
- DNS leak prevention
- Process lifecycle and kill-switch behavior
- Browser integration test

### GATE-10 — Android north-star
- Android VPNService/TUN adapter only; no Android-specific protocol
- Lifecycle, permission, reconnect, battery/background handling
- Real relay/gateway topology
- Reproducible device test script
- Android mobile data OFF + Wi-Fi OFF + ordinary Chrome → real HTTPS

### GATE-11 — Contribution proofs
- Measured gateway/relay service
- Signed bilateral receipts
- Proof verification
- Append-only contribution ledger
- Fraud/replay/duplicate receipt tests

### GATE-12 — Civic Points
- Versioned valuation policy
- Verified proof → points → resource redemption
- No blockchain
- No free peer-to-peer transferability
- Routing remains independent of points

### GATE-13 — Content, external crypto, compute
1. Content-addressed storage/chunks/Merkle/manifests
2. External signed-transaction transport (private keys stay local)
3. Compute services
Each requires its own ADR, schemas, vectors, security tests, integration proof.
