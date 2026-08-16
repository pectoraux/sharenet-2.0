# ShareNet 2.0 — External Cryptocurrency Bridge

**Status:** Normative, **later phase** (Phase 11). This document
defines the only permitted path between ShareNet Civic Points and
external on-chain assets. Custody MUST remain with the user.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Scope

The external cryptocurrency bridge ("the bridge") allows a user to pay
for gateway service using an external cryptocurrency (e.g., BTC, ETH,
stablecoin) without ShareNet ever taking custody of the user's private
keys.

The bridge is **distinct** from Civic Points (see
`spec/12-civic-points.md`). Civic Points are internal accounting
credits; external cryptocurrency is on-chain assets. They are different
objects with different lifecycles, different security models, and
different revocation paths. They MUST NOT be conflated.

The bridge is introduced in Phase 11. The first deliverable MUST NOT
implement it.

## 2. Custody Model

ShareNet never holds the user's private keys. The user holds their
private keys in a wallet of their choosing (hardware wallet, mobile
wallet, desktop wallet). ShareNet interacts with the wallet only
through signed messages.

Concretely:

1. The user's wallet signs a `GatewayPaymentAuthorization` over the
   gateway's payment request.
2. The wallet broadcasts the on-chain transaction itself.
3. ShareNet observes the on-chain transaction (via a read-only RPC
   node or index) and matches it to the authorization.
4. ShareNet credits gateway authorization upon on-chain confirmation.

ShareNet software MUST NOT:

- Request, store, or transmit a user's private key.
- Sign on behalf of a user.
- Broadcast on-chain transactions on behalf of a user.
- Hold user funds in any custodial address.

A pull request that adds any of the above is a specification violation
and MUST fail conformance (see `spec/17-conformance.md` §3.5).

## 3. Payment Flow

```
+----------+                 +-----------+             +-----------+      +-----------+
|  Wallet  | ──sign auth──> | ShareNet  | ──request──>| Gateway   | ───> | On-chain  |
| (user)   |                 | (client)  |             |          |      | payment   |
+----------+                 +-----------+             +-----------+      +-----------+
      ▲                                                                                      │
      │                                                                                      │
      └───────────────── broadcast tx directly ─────────────────────────────────────────────┘
                                                (user's wallet, not ShareNet)
                                                                │
                                                                ▼
                                              +-----------+    +-----------+
                                              | Observer  |    | On-chain  |
                                              | (ShareNet |<---| confirm   |
                                              |  read-only|    |           |
                                              |  RPC)     |    |           |
                                              +-----------+    +-----------+
                                                      │
                                                      ▼
                                              GatewayAuthorization
                                              issued to source NodeId
```

### 3.1 GatewayPaymentRequest

```
GatewayPaymentRequest = {
  request_version: 1,
  gateway_id:       text,
  source_id:        text,
  circuit_id:       text,
  service_class:    text,
  amount_required:  uint,           ; smallest on-chain unit (e.g., satoshis)
  asset_id:         text,           ; e.g. "btc", "eth", "usdc-erc20"
  pay_to_address:  text,           ; gateway's on-chain address
  expires_at:       uint,
  request_nonce:   bstr .size 16,
  gateway_signature: bstr .size 64, ; Ed25519 by gateway
}
```

Signature domain: `"sharenet-gateway-payment-request-v1"`.

### 3.2 GatewayPaymentAuthorization

Signed by the user's wallet, NOT by ShareNet. The wallet signs the
canonical CBOR of the request plus a destination commitment.

```
GatewayPaymentAuthorization = {
  authorization_version: 1,
  request_hash:           bstr .size 32, ; BLAKE2b-256 of canonical request
  wallet_address:          text,         ; user's on-chain address
  tx_intent:               text,         ; description of tx (e.g., "pay X to Y")
  authorization_nonce:    bstr .size 16,
  wallet_signature:        bstr,         ; per-chain signature scheme
}
```

ShareNet does not interpret `wallet_signature`; it forwards the
authorization to the gateway and waits for on-chain confirmation.

## 4. Settlement Path

Once the on-chain transaction is confirmed and observed:

1. The gateway issues a `GatewayAuthorization` for the requesting
   `source_id`, valid for the service class and amount paid.
2. The gateway MAY also issue a `ContributionProof` for the
   `GATEWAY_EGRESS` that follows (see `spec/11-contribution.md`).
3. Civic Points are NOT issued directly from on-chain payment; they
   are issued only from verified contribution proofs.

This separation preserves the invariants of
`spec/12-civic-points.md`: external cryptocurrency buys gateway
authorization, not Civic Points. Civic Points are still only earned by
verified contributions.

## 5. Security Invariants

1. User private keys MUST remain with the user.
2. ShareNet MUST NOT sign on behalf of the user.
3. ShareNet MUST NOT broadcast on behalf of the user.
4. ShareNet MUST NOT hold custodial balances.
5. On-chain observations MUST be made via read-only RPC nodes; the
   observing node MUST NOT have wallet privileges.
6. The bridge MUST verify the on-chain confirmation has reached a
   configurable depth (default: 6 blocks for BTC, 35 for ETH) before
   issuing `GatewayAuthorization`.
7. Reorgs deeper than the configured depth MUST trigger authorization
   revocation and audit log entry.

## 6. Privacy

- Wallet addresses are on-chain public identifiers. ShareNet MUST NOT
  correlate wallet addresses with NodeIds in any publicly observable
  way. Internal correlation for accounting is permitted but MUST be
  access-controlled.
- A user MAY use a fresh address per payment to reduce linkability
  (BIP-32 hierarchical deterministic wallets).

## 7. Forbidden Behaviors

1. ShareNet software holding private keys in any form, including
   transient in-memory copies beyond the wallet's own process.
2. ShareNet software broadcasting transactions on the user's behalf.
3. ShareNet software advertising wallet services as a feature of the
   protocol core.
4. ShareNet software directly mapping on-chain assets to Civic Points
   at a fixed ratio without going through the contribution-proof path.

## 8. Phase Boundary

The bridge is introduced in Phase 11. Before Phase 11, all Civic
Points behavior is governed by `spec/12-civic-points.md` alone.

A Phase 9 implementation MUST NOT include bridge code, even as
stubs that return success. Bridge stubs MUST throw at runtime (see
`spec/01-architecture.md` §5).

## 9. Cross-References

- Civic Points: `spec/12-civic-points.md`.
- Contribution proofs: `spec/11-contribution.md` §3.
- Gateway authorization: `spec/09-internet-gateway.md` §3.
- Phase progression: `spec/01-architecture.md` §3.
- Custody-violation conformance test: `spec/17-conformance.md` §3.5.
