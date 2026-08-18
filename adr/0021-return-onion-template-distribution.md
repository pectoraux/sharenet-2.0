# ADR-0021: Return-onion template distribution (R-009 Stage 2)

**Date:** 2026-08-18
**Status:** ACCEPTED
**Phase:** R-009 Stage 2 (distributed return path)
**Supersedes:** The single-process `sealReturnFrame()` model (which required one process to hold all returnKeys).
**Superseded by:** None

## Context

R-009 Stage 2 introduced `sealReturnFrame()` — the return-onion sealing
primitive. The audit of `4ca7688` found that while the cryptography was
correct, the **distributed key-distribution architecture** was incomplete:

- `sealReturnFrame()` requires an `ActiveCircuit` containing ALL per-hop
  `returnKey`s.
- The initiator can derive these (it has the ECDH shared secrets).
- But the **gateway** (the terminal hop that seals return traffic) does NOT
  have the initiator's private key or the intermediate relays' private keys.
- The existing setup protocol (`CircuitSetupRequest` → `CircuitSetupAck`)
  establishes keys between the initiator and each relay — it does not
  distribute return-onion material to the gateway.

So `sealReturnFrame()` proved "a process that already possesses every return
key can construct a return onion" — but not "the actual Internet gateway in
a distributed ShareNet circuit can obtain the necessary return-onion material
without learning keys it should not possess."

## Decision

### Model A — Layered encrypted return template (`ReturnOnionTemplate`)

The initiator constructs a `ReturnOnionTemplate` during
`establishDistributedCircuit` and sends it to the gateway. The template
contains:

- `K_ret`: a fresh per-circuit return key (32-byte AEAD key). The gateway
  holds this — it is a **circuit-scoped key**, NOT a relay key.
- `envelope`: an N-layer-deep opaque encrypted blob wrapping `K_ret`. Each
  layer is AEAD-encrypted under a hop's `returnKey`. The gateway holds the
  outermost layer but **cannot decrypt any layer** (it does not have the
  `returnKey`s).

**Construction** (initiator-side, during setup):
```
K_ret = random(32)
env_0     = AEAD(returnKey_0, K_ret,     AD=root||hopIndex=0)
env_1     = AEAD(returnKey_1, env_0,     AD=root||hopIndex=1)
...
env_{N-1} = AEAD(returnKey_{N-1}, env_{N-2}, AD=root||hopIndex=N-1)
envelope  = env_{N-1}
```

**Gateway seals a return response**:
```
sealedPayload = AEAD(K_ret, nonce, response, AD=domain||root||seq||BACKWARD)
ciphertext = CBOR { 1: sealedPayload, 2: envelope }
```

**Each relay peels one layer**:
```
innerEnv = AEAD_decrypt(returnKey_i, envelopeLayer, AD=root||hopIndex=i)
forward { sealedPayload, innerEnv } to hop i-1
```

**Source (hop 0) recovers K_ret + decrypts**:
```
K_ret = AEAD_decrypt(returnKey_0, envelopeLayer, AD=root||hopIndex=0)
plaintext = AEAD_decrypt(K_ret, sealedPayload, AD=domain||root||seq||BACKWARD)
```

### Security properties

1. **Gateway key isolation**: the gateway holds `K_ret` (circuit-scoped) +
   the opaque envelope. It does NOT hold the per-hop `returnKey`s. It cannot
   decrypt forward traffic, intermediate returnKey layers, or other circuits'
   traffic.

2. **Onion property for key distribution**: each relay peels only its own
   `returnKey` layer from the envelope. The onion is on the KEY DISTRIBUTION
   (the envelope), not on the payload itself.

3. **Payload confidentiality**: the response payload is sealed once with
   `K_ret`. Intermediate relays see the sealed payload but cannot decrypt it
   (they don't hold `K_ret`).

4. **Binding**: all material is bound to `(commitmentRoot, hopIndex,
   direction=BACKWARD)` via the AD + the envelope nonce construction.

### Relationship to `sealReturnFrame()`

`sealReturnFrame()` (in `frame.ts`) remains as a **single-process test
primitive** — valid when one process holds all returnKeys (e.g., in unit
tests + conformance vectors that test the return-onion cryptography in
isolation). The distributed production path uses the template-based functions
in `return-template.ts`.

## Consequences

### Positive

- The gateway can seal return traffic without holding any per-hop `returnKey`.
- The gateway holds only `K_ret` (a circuit-scoped symmetric key) — not relay
  private keys or per-hop AEAD keys.
- The onion property is preserved for key distribution (each relay peels one
  layer).
- The existing `sealReturnFrame()` stays as a test primitive (no breaking
  change to the forward path or the single-process test vectors).

### Negative

- The return payload is sealed once (with `K_ret`), not N times (as in the
  forward onion). This is the necessary trade-off: the gateway cannot hold
  all `returnKey`s, so the onion must be on the key distribution, not the
  payload. The payload confidentiality is still preserved (only the source
  recovers `K_ret`).

## Cross-references

- `spec/08-circuits.md` §4.8 (Return-Onion Template Distribution — NEW)
- `reference/circuit/return-template.ts` — the implementation
- `conformance/vectors/V-CIRCUIT-RETURN-TEMPLATE-001.json` — the conformance vectors
- ADR-0019 (receiver-local replay protection — the floor keying is unchanged)
- ADR-0020 (re-key nonce-prefix binding — K_ret is fresh per circuit)
