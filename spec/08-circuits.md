# ShareNet 2.0 — Circuits

**Status:** Normative. This document defines circuits, their
construction pipeline, and the cryptographic invariants that bind a
circuit to a committed route.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. What a Circuit Is

A circuit is a cryptographic tunnel established over a `CommittedRoute`
(see `spec/07-routing.md` §5.4) that carries application traffic
between the source and the destination with per-hop forward secrecy,
replay protection, and route-binding.

A circuit is **not** a route. A route is the participant-accepted path;
a circuit is the live cryptographic channel that runs over it.

A circuit is **not** a Link. A Link is one hop; a circuit spans one or
more Links.

## 2. Circuit Construction Is Strict

A circuit MUST be constructed **only** from a `CommittedRoute`. The
following pipelines are **forbidden** and MUST be rejected by
conformance tests (`spec/17-conformance.md` §3.3):

```
RemoteNodeHint[]     ──> Circuit          (forbidden)
RouteProposal        ──> Circuit          (forbidden without commitment)
RouteAcceptance[]    ──> Circuit          (forbidden without source commitment)
```

The only permitted pipeline is:

```
CommittedRoute
      │
      ▼
CircuitSetup (source emits to all hops)
      │
      ▼
relay acknowledgements (each hop returns signed ack)
      │
      ▼
cryptographic possession proofs (X25519 ECDH + AEAD key derivation)
      │
      ▼
ActiveCircuit
```

## 3. Circuit Identity

The `CircuitId` is derived from the route commitment:

```
CircuitId = "circuit:" || hex(BLAKE2b-256("sharenet-circuit-id-v1"
                                          || route_id_bytes))
```

Where `route_id_bytes` is the 32-byte raw `commitment_root` of the
underlying `RouteCommitment` (see `spec/07-routing.md` §5.4).

Because the `commitment_root` is a Merkle root over per-hop
`RouteAcceptance`s, the `CircuitId` cryptographically binds the circuit
to the exact route and to every participant's acceptance. Tampering
with any hop's acceptance changes the `commitment_root`, changes the
`route_id`, and therefore changes the `CircuitId`.

## 4. Cryptographic Construction

### 4.1 Key Agreement

Each hop in the route performs X25519 ECDH with the source:

1. The source generates a fresh X25519 ephemeral keypair
   `(eph_priv, eph_pub)` per circuit.
2. Each hop holds a static X25519 circuit keypair whose public half is
   advertised as `circuit_public_key` (see `spec/03-node-advertisements.md`
   §2).
3. Per-hop shared secret: `dh_i = X25519(eph_priv, hop_i.circuit_pub)`.
4. Per-hop AEAD key:
   `key_i = HKDF-SHA256(salt = commitment_root, ikm = dh_i,
                       info = "sharenet-circuit-hop-key-v1" || i)`,
   where `i` is the 1-based hop index.
5. The source encrypts the next hop's `eph_pub` envelope under
   `key_i` (onion-style).

### 4.2 AEAD

The AEAD is ChaCha20-Poly1305 (or, if a platform lacks it, AES-GCM with
hardware acceleration — but ChaCha20-Poly1305 is the reference).

Each hop's AEAD key is used to (a) wrap the next-hop envelope in the
setup phase and (b) encrypt/decrypt relayed frames in the data phase.

### 4.3 Nonce Uniqueness

Each frame carries a 96-bit AEAD nonce composed of:

```
nonce = circuit_nonce_prefix (64 bits, fixed per circuit)
     || frame_sequence (32 bits, big-endian, starts at 0)
```

- `circuit_nonce_prefix` is derived as the first 8 bytes of
  `HKDF-SHA256(salt = commitment_root, ikm = "nonce-prefix",
               info = "sharenet-circuit-nonce-prefix-v1")`.
- `frame_sequence` is a 32-bit per-circuit counter. The circuit MUST
  terminate with an error if `frame_sequence` would overflow.
- Nonce reuse is catastrophic; the conformance suite MUST include a
  test that fails any implementation that reuses a `(circuit_id,
  frame_sequence)` pair.

### 4.4 Domain Separation

Every signature and every HKDF `info` string in the circuit layer is
prefixed by a unique domain-separation string. The full set:

| Domain                                | Use                                            |
|---------------------------------------|------------------------------------------------|
| `sharenet-circuit-id-v1`              | CircuitId derivation.                          |
| `sharenet-circuit-hop-key-v1`         | Per-hop AEAD key derivation.                   |
| `sharenet-circuit-nonce-prefix-v1`    | Per-circuit nonce prefix.                       |
| `sharenet-circuit-setup-ack-v1`       | Per-hop setup acknowledgement signature.       |
| `sharenet-circuit-possession-v1`      | Possession proof signature.                    |
| `sharenet-circuit-frame-v1`           | AEAD associated data for data frames.          |

No two uses share a domain string (see `spec/14-security.md` §4).

### 4.5 Replay Protection (FROZEN — ORDERED_STREAM)

The data-plane replay model is **ORDERED_STREAM** (frozen per R-008
hardening). This supersedes any earlier sliding-window language.

- `frame_sequence` is strictly increasing per circuit (starts at 1).
- A receiver rejects any frame whose sequence is `<=` the highest
  sequence already accepted on that circuit.
- There is no out-of-order acceptance window: gap tolerance is 0.
- There is no sliding window. The earlier "window of 64 sequences"
  language is **superseded** and MUST NOT be implemented.

Sequence floors persist across circuit re-key events (see
`spec/14-security.md` §3); a re-key MUST continue the counter from
the prior floor.

This freeze is recorded as the constant `CIRCUIT_REPLAY_MODEL =
"ORDERED_STREAM"` in `reference/circuit/circuit.ts` and is asserted by
conformance tests. R-009 (circuit packet semantics) MUST build on this
model and MUST NOT silently switch to a sliding-window / out-of-order
acceptance model without an explicit spec amendment.

### 4.5b ACK Freshness (R-008 hardening)

A `CircuitSetupAck` carries both an absolute deadline (`ackExpiry`) and
a creation timestamp (`ackTimestamp`). The initiator MUST reject an ack
unless ALL of the following hold:

1. `ackExpiry > now` — the ack has not passed its absolute deadline.
2. `ackExpiry > ackTimestamp` — sanity: the deadline follows creation.
3. `ackTimestamp <= now + ACK_MAX_CLOCK_SKEW_SECONDS` — the ack is not
   dated too far in the future (rejects replay-with-skew / malformed
   acks).
4. `now - ackTimestamp <= ACK_MAX_AGE_SECONDS` — the ack is consumed
   within a bounded relative freshness window (TTL), independent of the
   looser absolute expiry.

Bounds (3) and (4) are what make a captured ack unusable shortly after
issuance, even when its absolute `ackExpiry` is generous (e.g. 1 hour).
This bounds the setup-phase replay window to `ACK_MAX_AGE_SECONDS`.

### 4.6 Route / Circuit Binding

Every data frame carries, as AEAD associated data:

```
AD = "sharenet-circuit-frame-v1"
   || commitment_root (32 bytes)
   || frame_sequence (4 bytes big-endian)
   || direction (1 byte: 0x01 = forward, 0x02 = backward)
```

This binds the frame to a specific `CommittedRoute`. A frame
encrypted under a circuit's key but presented with a different
`commitment_root` MUST fail AEAD verification.

### 4.7 Expiration

A circuit carries `valid_until = min(hop.accepted_expiry for hop in
route)`. Once `now > valid_until`, the circuit MUST be torn down.
Expiry does NOT lower the sequence floor; a new circuit MUST start
from a fresh `(eph_priv, eph_pub)` and a new `circuit_nonce_prefix`.

## 5. Circuit Setup Protocol

```
Source ──CircuitSetup──> Hop_1 ──CircuitSetup──> Hop_2 ──> ... ──> Destination
   ▲                          │                       │                  │
   │                          ▼                       ▼                  ▼
   │                       ack_1                    ack_2              ack_dest
   │                          │                       │                  │
   └──── possession proof request ──────────────────────────────────────┘
                                       ▼
                          possession proof (signed ack chain)
                                       ▼
                                 ActiveCircuit
```

A `CircuitSetup` message is the source's `RouteCommitment` plus the
onion-encrypted per-hop envelope. Each hop decrypts its envelope,
verifies its own `RouteAcceptance` is in the commitment, returns a
signed `CircuitSetupAck`, and forwards the remaining onion to the next
hop.

A `possession proof` is a signed statement by each hop that it holds
the AEAD key derived from its X25519 shared secret. The source verifies
all proofs before declaring the circuit `ACTIVE`.

## 6. State

| State             | Meaning                                                            |
|-------------------|--------------------------------------------------------------------|
| `CIRCUIT_PENDING` | Setup messages in flight; not yet all-acks-verified.               |
| `CIRCUIT_ACTIVE`  | All hops acknowledged; possession proofs verified.                 |
| `CIRCUIT_EXPIRED` | `now > valid_until`; torn down; keys destroyed.                    |
| `CIRCUIT_REVOKED` | Operator- or source-initiated teardown; keys destroyed.            |

In `CIRCUIT_EXPIRED` or `CIRCUIT_REVOKED`, all derived keys MUST be
zeroized from memory. The sequence floor MUST be retained for replay
protection of any future circuit re-using the same route commitment
(re-key is permitted; re-key does NOT reset the sequence floor).

## 7. Invariants

1. A circuit exists only from a `CommittedRoute`.
2. The `CircuitId` is cryptographically bound to the route commitment.
3. Nonce reuse within a circuit is impossible by construction.
4. Domain separation is exhaustive; no two signature or KDF uses share
   a domain string.
5. Expiration does not reset the sequence floor.
6. A `CommittedRoute` with any `RouteAcceptance` whose `expiry` is in
   the past MUST NOT yield an `ActiveCircuit`.

## 8. Cross-References

- Route objects: `spec/07-routing.md` §5.
- Advertisement `circuit_public_key` field: `spec/03-node-advertisements.md`
  §2.
- Sequence floor persistence: `spec/14-security.md` §3.
- Domain separation register: `spec/14-security.md` §4.
- Forbidden pipelines and their executable guards:
  `spec/17-conformance.md` §3.
