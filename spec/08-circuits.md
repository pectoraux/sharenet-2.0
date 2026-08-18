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

The `CircuitId` is derived from the route commitment root and the
initiator's ephemeral X25519 public key:

```
CircuitId = BLAKE3-256(
    utf8("SHARENET/CIRCUIT/ID/1")
    || commitment_root       ; 32 bytes — the raw Merkle root
    || initiator_x25519_pub  ; 32 bytes — the source's ephemeral key
)
```

Per R-001 (ADR-0017): all hashing uses BLAKE3-256. The domain tag
`SHARENET/CIRCUIT/ID/1` is FROZEN.

The `commitment_root` is the 32-byte raw Merkle root of the
`RouteCommitment` (see `spec/07-routing.md` §5.3.1). It is NOT the
`route_id` string (which is `"route:" + hex(commitment_root)`).

Because the `commitment_root` is a Merkle root over per-hop
`RouteAcceptance`s, the `CircuitId` cryptographically binds the circuit
to the exact route and to every participant's acceptance. Tampering
with any hop's acceptance changes the `commitment_root`, and therefore
changes the `CircuitId`.

The `initiator_x25519_pub` binds the circuit to a specific ephemeral
key, preventing circuit ID reuse across initiator keypairs.

## 4. Cryptographic Construction

### 4.1 Key Agreement

Each hop in the route performs X25519 ECDH with the source:

1. The source generates a fresh X25519 ephemeral keypair
   `(eph_priv, eph_pub)` per circuit.
2. Each hop generates a fresh X25519 ephemeral keypair per circuit
   (providing forward secrecy per circuit — stronger than the
   original spec's static-key model).
3. Per-hop shared secret: `dh_i = X25519(eph_priv_source, eph_pub_hop_i)`.
4. Per-hop AEAD key:
   `key_i = HKDF-SHA256(salt = commitment_root, ikm = dh_i,
                       info = "SHARENET/CIRCUIT/KEY/1" || u8(hop_index))`,
   where `hop_index` is the 0-based hop index (1 byte).
5. The HKDF output is 64 bytes, split into:
   - `forwardingKey` (bytes 0–31): AEAD key for forward traffic
   - `returnKey` (bytes 32–63): AEAD key for return traffic

Per R-001 (ADR-0017): the domain tag `SHARENET/CIRCUIT/KEY/1` is FROZEN.
The salt is the 32-byte `commitment_root` (NOT empty), binding the
derived keys to the specific accepted route.

### 4.2 AEAD

The AEAD is ChaCha20-Poly1305 (256-bit key, 96-bit nonce, 128-bit tag).

Each hop's AEAD key is used to (a) wrap the next-hop envelope in the
setup phase and (b) encrypt/decrypt relayed frames in the data phase.

### 4.3 Nonce Uniqueness

Each frame carries a 96-bit AEAD nonce composed of:

```
nonce = circuit_nonce_prefix (64 bits, fixed per circuit instance)
     || frame_sequence (32 bits, big-endian, starts at 1)
```

- `circuit_nonce_prefix` is the first 8 bytes of:
  `HKDF-SHA256(salt = commitment_root, ikm = initiator_x25519_pub,
              info = "SHARENET/CIRCUIT/NONCE/1")`
  (32-byte output, first 8 bytes used as prefix). The `ikm` is the raw
  32-byte initiator ephemeral X25519 public key — the same key used in
  `CircuitId` derivation (§3). This binds the nonce space to the **circuit
  instance** (commitment_root + initiator ephemeral key), not just the
  route, so a re-key on the same route produces a FRESH nonce prefix (§4.7).
  See ADR-0020.
- `frame_sequence` is a 32-bit per-circuit counter starting at 1.
  The circuit MUST terminate with an error if `frame_sequence` would
  overflow.
- Nonce reuse is catastrophic; the conformance suite MUST include a
  test that fails any implementation that reuses a `(circuit_id,
  frame_sequence)` pair.

Per R-001 (ADR-0017): the domain tag `SHARENET/CIRCUIT/NONCE/1` is FROZEN.

### 4.4 Domain Separation

Every signature and every HKDF `info` string in the circuit layer is
prefixed by a unique domain-separation string. The full set (FROZEN per
R-001 / ADR-0017):

| Domain                                | Use                                            |
|---------------------------------------|------------------------------------------------|
| `SHARENET/CIRCUIT/ID/1`               | CircuitId derivation.                          |
| `SHARENET/CIRCUIT/KEY/1`              | Per-hop AEAD key derivation.                   |
| `SHARENET/CIRCUIT/NONCE/1`           | Per-circuit nonce prefix.                       |
| `SHARENET/CIRCUIT/SETUP/1`            | Circuit setup request signing.                 |
| `SHARENET/CIRCUIT/ACK/1`              | Circuit setup ack signing.                     |
| `SHARENET/CIRCUIT/POSSESSION/1`       | Possession proof signature.                    |
| `SHARENET/CIRCUIT/FRAME/1`           | AEAD associated data for data frames.          |

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

### 4.6 CircuitFrame (Data-Plane Wire Object)

A `CircuitFrame` is the data-plane wire object carrying encrypted
application traffic over a circuit. Each frame carries:

```
CircuitFrame = {
    circuit_nonce_prefix:  bstr .size 8,   ; per-circuit prefix (§4.3)
    frame_sequence:        uint .size 4,    ; big-endian, starts at 1
    direction:             uint .size 1,   ; 0x01 = forward, 0x02 = backward
    ciphertext:            bstr,           ; ChaCha20-Poly1305 encrypted payload
}
```

The AEAD associated data (AD) for each frame is:

```
AD = utf8("SHARENET/CIRCUIT/FRAME/1")
   || commitment_root       ; 32 bytes
   || frame_sequence        ; 4 bytes big-endian
   || direction             ; 1 byte
```

This binds the frame to a specific `CommittedRoute`. A frame
encrypted under a circuit's key but presented with a different
`commitment_root` MUST fail AEAD verification.

### 4.6a Forward + Backward (Return) Wire Protocol (R-009 Stage 2)

The circuit carries bidirectional traffic. Forward frames
(`direction = 0x01`) travel source → gateway; backward frames
(`direction = 0x02`) travel gateway → source.

There is ONE canonical `CircuitFrame.ciphertext` representation per
direction:

**FORWARD ciphertext** (the forward onion): N-layer-deep onion ciphertext.
The source onion-encrypts the plaintext from the outermost hop (last) to
the innermost hop (first), using each hop's `forwardingKey`. Each relay
peels one layer with its `forwardingKey`; the terminal hop (hop N-1, the
gateway) delivers the plaintext.

**BACKWARD ciphertext** (the distributed return-onion template model,
per §4.8 + ADR-0021): a CBOR pair `{ 1: sealedPayload, 2: envelopeLayer }`.
The gateway seals the response with `K_ret` (circuit-scoped key, held by
the gateway — NOT a relay key) + attaches the opaque envelope. Each relay
peels its `returnKey` from the `envelopeLayer` (NOT from the frame
ciphertext directly); the terminal hop (hop 0, the source) recovers `K_ret`
+ decrypts the `sealedPayload`. The gateway does NOT hold the per-hop
`returnKey`s.

The production frame path (`processCircuitWireFrame`) routes based on
direction: FORWARD → `openFrame(forwardingKey)`; BACKWARD →
`peelReturnEnvelopeLayer(returnKey)`. Both paths preserve the R-008 frozen
ordering: decode → AEAD authenticate → receiver-local durable commit →
forward/deliver.

Per §4.1, each hop's HKDF output is split into `forwardingKey` (bytes 0-31)
+ `returnKey` (bytes 32-63). The `returnKey` is used ONLY for
backward-direction envelope peeling (§4.8). The AEAD AD includes the
`direction` byte, so a forward frame + a backward frame at the same
`frame_sequence` are cryptographically distinct (different AD → different
AEAD tag).

**Replay protection (bidirectional):** per ADR-0019, the durable sequence
floor is keyed by `(commitmentRoot, hopIndex, direction)`. Forward + backward
floors are INDEPENDENT — a forward frame at seq=1 + a backward frame at
seq=1 are BOTH accepted at the same hop (different `direction` → different
floor row). A replay in either direction is caught by that direction's own
floor. Every hop commits its own floor for both directions.

### 4.7 Expiration

A circuit carries `valid_until = min(hop.accepted_expiry for hop in
route)`. Once `now > valid_until`, the circuit MUST be torn down.
Expiry does NOT lower the sequence floor; a new circuit MUST start
from a fresh `(eph_priv, eph_pub)` and a new `circuit_nonce_prefix`.

Per §4.3 (as amended by ADR-0020), the `circuit_nonce_prefix` is derived
from `(commitment_root, initiator_x25519_pub)`, so a fresh ephemeral
keypair produces a fresh nonce prefix by construction — satisfying the
"new circuit_nonce_prefix" requirement. The persistent receiver-local
sequence floor `(commitmentRoot, hopIndex, direction)` (per ADR-0019)
provides cross-re-key replay protection independently.

### 4.8 Return-Onion Template Distribution (R-009 Stage 2)

In the forward direction, the SOURCE holds all `forwardingKey`s (it derives
them from the ECDH with each relay). In the backward direction, the GATEWAY
must seal return traffic — but the gateway does NOT hold the intermediate
relays' `returnKey`s (it is not the initiator + does not have the other
relays' private keys).

The `ReturnOnionTemplate` (Model A — layered encrypted return template)
resolves this:

1. The INITIATOR (who holds all returnKeys from the setup ECDH) constructs
   the template during `establishDistributedCircuit`:
   - Generates a fresh per-circuit return key `K_ret` (32-byte AEAD key).
   - Wraps `K_ret` in N nested AEAD layers, one per hop's `returnKey`:
     `env_0 = AEAD(returnKey_0, K_ret)`, `env_1 = AEAD(returnKey_1, env_0)`,
     ..., `env_{N-1} = AEAD(returnKey_{N-1}, env_{N-2})`.
   - The template = `{ circuitId, commitmentRoot, noncePrefix, kRet, envelope = env_{N-1} }`.

2. The initiator sends the template to the GATEWAY (the terminal hop) during
   setup. The gateway holds `K_ret` (a circuit-scoped key — NOT a relay key)
   + the opaque envelope (it cannot decrypt any envelope layer).

3. To send a return response, the GATEWAY:
   - Seals the response with `K_ret`: `sealedPayload = AEAD(K_ret, nonce, response, AD)`.
   - Constructs a backward frame with `ciphertext = CBOR { sealedPayload, envelope }`.
   - Sends to hop N-1.

4. Each RELAY (hop i, from N-1 down to 1):
   - Decodes the ciphertext as `{ sealedPayload, envelopeLayer }`.
   - Peels its `returnKey` from `envelopeLayer`: `innerEnv = AEAD_decrypt(returnKey_i, envelopeLayer)`.
   - Forwards `{ sealedPayload, innerEnv }` to hop i-1.

5. The SOURCE (hop 0):
   - Peels the final envelope layer → recovers `K_ret`.
   - Decrypts `sealedPayload` with `K_ret` → response plaintext.

SECURITY PROPERTIES:
- The gateway holds `K_ret` (circuit-scoped) — NOT the per-hop `returnKey`s.
- Each relay peels only its own `returnKey` layer (onion property preserved
  for key distribution).
- The response payload is sealed once with `K_ret`. Intermediate relays see
  the sealed payload but cannot decrypt it (they don't hold `K_ret`).
- All material is bound to `(commitmentRoot, hopIndex, direction=BACKWARD)`
  via the AD + the envelope nonce construction.

See ADR-0021 for the full design rationale.

## 5. Circuit Setup Protocol

```
Source ──CircuitSetupRequest──> Hop_1
   ▲                          │
   │                          ▼
   │                       CircuitSetupAck (relay X25519 pubkey + possession proof)
   │                          │
   │  ←───────────────────────┘
   │
   (repeat for each hop)
   │
   ▼
ActiveCircuit
```

A `CircuitSetupRequest` is sent by the source to each hop individually.
It carries the `BrandedCommittedRoute`, the hop index, the source's
ephemeral X25519 public key, and a fresh setup nonce.

Each hop:
1. Verifies the route is a genuine `BrandedCommittedRoute` (WeakSet check)
2. Verifies it occupies the specified `hopIndex` in the route
3. Generates a fresh X25519 ephemeral keypair
4. Computes the shared secret with the initiator's X25519 public key
5. Derives forwarding + return keys via HKDF (salt = `commitment_root`)
6. Signs a possession proof binding: routeId + routeCommitmentDigest +
   hopIndex + relay_pubkey + initiator_pubkey + nonce + timestamps
7. Returns a `CircuitSetupAck` with the relay's X25519 public key +
   possession proof + freshness timestamps

The source verifies all acks + possession proofs before declaring the
circuit `ACTIVE`.

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
2. The `CircuitId` is cryptographically bound to the `commitment_root`
   and the initiator's ephemeral X25519 key.
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
