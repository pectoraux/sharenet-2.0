# ADR-0014: LinkId Derivation Frozen + Two-Message Handshake

**Date:** 2026-08-16
**Status:** INTERIM — LinkId derivation pending ADR-0015 transitive resolution; two-message handshake pending ADR-0016 (replay defect).

> **⚠️ STATUS CORRECTION (2026-08-16, corrective milestone):**
>
> 1. The **LinkId derivation** portion of this ADR was labeled `FROZEN`. That
>    label is retracted — LinkId transitively depends on NodeId (the local
>    and remote NodeId strings are hash inputs), so LinkId cannot be frozen
>    until ADR-0015 resolves the NodeId algorithm. Until then, the LinkId
>    derivation is **INTERIM**.
>
> 2. The **two-message handshake** portion of this ADR was described as
>    producing an "authenticated directed link." That description is
>    **retracted** — see ADR-0016 (PROPOSAL) for the replay defect. The
>    handshake verifies signed advertisements but does NOT prove fresh
>    possession of the signing key bound to the connection transcript. A
>    captured advertisement is replayable. Until ADR-0016 is resolved, the
>    exchange is an "advertisement-verification exchange," NOT an
>    authenticated link.

## Context

spec/04-links.md mandates that links are **directed** (A→B does not imply
B→A) and that a link is created ONLY through an authenticated transport
connection (advertisement → endpoint → transport → peer auth → LinkUp).

Phase 3 (spec/00 §37, "second major deliverable") requires:

> real independent processes → authenticated directed network links.
> No simulator. No global in-memory graph. No fake transport.

To achieve this we need:

1. A **LinkId** that is directional, deterministic, and bound to a specific
   handshake instance (so reconnects produce new LinkIds — no replay).
2. A **handshake wire format** that two real processes exchange over a real
   socket to establish mutual authentication.
3. A **directed link record** that makes the direction explicit in the data
   structure (so the architecture test can assert A→B and B→A are distinct).

The NodeId derivation (ADR-0003) is frozen and cannot change. By the same
logic, the LinkId derivation must also be frozen — any change would break
cross-implementation link-state agreement.

## Decision

### 1. LinkId derivation (FROZEN)

```
LinkId = "link:" + hex(BLAKE2b-256(
  "sharenet-link-id-v1"
  ‖ localNodeId
  ‖ remoteNodeId
  ‖ localNonce    (16 bytes)
  ‖ remoteNonce   (16 bytes)
))
```

The domain-separation string `sharenet-link-id-v1` is FROZEN FOREVER.
Bumping it requires a new LinkId namespace and a coordinated migration.

**Why local/remote ordering (not sorted):** the ordering encodes direction.
A link from A→B uses `(localNodeId=A, remoteNodeId=B)` in the hash input,
producing a different LinkId than B→A's `(localNodeId=B, remoteNodeId=A)`.
This makes the directed invariant structurally enforced — you cannot compute
the reverse-direction LinkId without swapping the roles, which would require
a separate handshake.

**Why nonces:** without nonces, two reconnects between the same pair (A, B)
would produce identical LinkIds, allowing stale link-state to be confused
with fresh link-state. The 16-byte nonces bind the LinkId to a specific
handshake instance.

### 2. Two-message handshake (no round-trip-of-round-trips)

```
Initiator (A)                       Responder (B)
-----------                         -------------
1. SEND InitiateMessage(advertisement=A)  →
                                    2. verifyAdvertisement(A)
                                       IF FAIL → send RejectMessage, close
                                       IF OK  → SEND AcceptMessage(advertisement=B)
   ←
3. verifyAdvertisement(B)
   IF FAIL → close, no LinkUp
   IF OK  → LINK_UP (both sides)
```

Each message carries the sender's full signed NodeAdvertisement (hex-encoded
canonical CBOR). Verification runs the complete spec/03 §5 checks
(signature, identity binding, timestamp ±300s, expiry, canonical encoding).

The handshake is **minimal** for Phase 3:
- It does NOT establish a session key (that's Phase 6 X25519).
- It does NOT encrypt subsequent traffic (that's Phase 6 AEAD).
- It does NOT do service negotiation (that's Phase 5).

Phase 3 proves exactly what spec/00 §37 demands: two real processes, real
socket, mutual advertisement verification, directed LinkUp.

### 3. Wire format = length-prefixed canonical CBOR

```
[ 4 bytes big-endian length ] [ canonical CBOR message body ]
```

The message body is an integer-keyed CBOR map (ADR-0004) discriminated by
a `kind` field:
- `1` = InitiateMessage (carries advertisement)
- `2` = AcceptMessage (carries advertisement)
- `3` = RejectMessage (carries reason + received/expected NodeId)

Maximum message size: 64 KiB (defense against memory bombs).

### 4. Directed link record

```typescript
interface DirectedLink {
  linkId: string;        // directional
  localNodeId: string;
  remoteNodeId: string;
  localNonce: Uint8Array;
  remoteNonce: Uint8Array;
  remotePublicKey: Uint8Array;
  remoteCapabilities: readonly string[];
  remoteEndpoint: string;
  state: "LINK_PENDING" | "LINK_UP" | "LINK_DOWN";
  ...
}
```

The `localNodeId`/`remoteNodeId` fields make direction explicit. An
architecture regression test asserts that the LinkId for (A→B) ≠ the
LinkId for (B→A), even with the same nonces.

### 5. Architecture guard: endpoint ≠ link

`CREATE_LINK_FROM_ENDPOINT_FORBIDDEN(endpoint)` always throws. It exists so
the architecture regression test can call it and assert the throw — any
future code that tries to construct a DirectedLink from a bare endpoint
(without a verified handshake) is forbidden per spec/04 §2.

## Consequences

- LinkId is permanently bound to a specific handshake instance. Reconnects
  produce new LinkIds. This is correct: a new handshake is a new link.
- The handshake is 2 messages (1 round trip) — minimal latency for Phase 3.
- Subsequent traffic after LinkUp is unencrypted for Phase 3. This is
  acceptable because Phase 3 only proves link establishment, not traffic
  confidentiality. Phase 6 will add X25519 + AEAD on top of the established
  link.
- The wire format is length-prefixed canonical CBOR, consistent with the
  advertisement format (ADR-0004).
- A non-browser implementation (Rust/Go/C) can implement the same handshake
  and interoperate. The protocol core has zero HTTP/socket dependencies.

## Alternatives Considered

1. **Three-message handshake with explicit LinkUp ack** — rejected for
   Phase 3. The responder's AcceptMessage IS the implicit ack (it carries
   a verified advertisement). Adding a third message adds latency without
   adding security for the minimal Phase 3 proof.

2. **Session key establishment in the handshake** — rejected for Phase 3.
   That's Phase 6 (circuits, X25519, AEAD). Mixing it into Phase 3 would
   violate the "smallest correct implementation" discipline (spec/00 §40).

3. **Sorted NodeId ordering in LinkId** (instead of local/remote) —
   rejected. Sorted ordering would make A→B and B→A produce the same
   LinkId, destroying the directed invariant at the data-structure level.

4. **No nonces (LinkId = hash(localNodeId, remoteNodeId))** — rejected.
   Reconnects would reuse LinkIds, allowing stale link-state confusion.

## References

- spec/04-links.md (directed links, creation pipeline, state machine)
- spec/00 §37 (second major deliverable — real independent processes)
- spec/00 §40 (smallest correct implementation discipline)
- ADR-0003 (NodeId derivation frozen — same pattern applied to LinkId)
- ADR-0004 (canonical CBOR wire format)
- ADR-0007 (AuthenticatedNodeRecord pipeline — the handshake uses it)
- ADR-0013 (three-layer separation — handshake lives in `reference/transport/`,
  pure of HTTP/socket/DB concerns)
