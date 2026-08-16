# ShareNet 2.0 — Platform Adapters

**Status:** Normative. This document defines the role of platform
adapters and the constraint that platform adapters MUST NOT create
platform-specific protocol semantics.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. The Protocol Core Is Platform-Agnostic

The ShareNet protocol core (identity, advertisement, link, discovery,
topology, routing, circuit, gateway, content, contribution, civic
points, bridge) is defined in `spec/00` through `spec/14` and is
platform-agnostic by construction. Every invariant in those documents
MUST hold on every platform ShareNet runs on.

A platform adapter's ONLY job is to bridge the platform's
networking APIs to the reference implementation's transport and
keystore abstractions. A platform adapter MUST NOT:

1. Introduce new protocol semantics.
2. Define new wire formats.
3. Define new signature domains.
4. Bypass any conformance test.
5. Change identity derivation, link state machine, routing pipeline,
   circuit construction, or gateway protections.

If a platform's API cannot express a required protocol behavior
without modification, the modification MUST be made in the protocol
core (via spec + ADR) and propagated to all platforms, not patched in
a single platform adapter.

## 2. Adapter Responsibilities

| Responsibility            | Linux TUN            | Windows              | macOS Network Ext.   | Android VPNService   | iOS                  |
|---------------------------|----------------------|----------------------|----------------------|----------------------|----------------------|
| Bring up virtual NIC      | TUN device           | WinTun / Wintap       | NEPacketTunnelProvider| VpnService Builder   | NEPacketTunnelProvider|
| Route DNS through ShareNet| `/etc/resolv.conf` rewrite | NRPT            | NEDNSProxyProvider   | `protect()` + DNS VPN| NEDNSProxyProvider   |
| Persist Ed25519 private key| `~/.sharenet/keys/`| `%APPDATA%\ShareNet\keys\`| Keychain            | Android Keystore     | Keychain             |
| Background operation      | systemd unit         | Service              | Network Extension    | Foreground service   | Network Extension    |
| CPU / battery awareness   | n/a                  | n/a                  | low-power mode       | Doze / background limits| low-power mode       |

## 3. Per-Platform Notes

### 3.1 Linux TUN

- The TUN device is brought up with `IFF_TUN | IFF_NO_PI`.
- The adapter reads IP packets from `/dev/net/tun`, parses them as IP,
  and submits them to the reference implementation as application
  traffic.
- DNS is intercepted by rewriting `/etc/resolv.conf` to point at the
  ShareNet resolver, or by using `iptables` `REDIRECT` rules.
- This is the platform adapter built in the first deliverable (Phase 10).

### 3.2 Windows Virtual Networking

- Use WinTun (wireguard's userspace TUN) for the virtual NIC.
- DNS is intercepted via NRPT (Name Resolution Policy Table).
- The Ed25519 private key is stored under `%APPDATA%\ShareNet\keys\`,
  encrypted with DPAPI.
- The adapter runs as a Windows Service.

### 3.3 macOS Network Extension

- Use `NEPacketTunnelProvider` for the TUN device.
- Use `NEDNSProxyProvider` for DNS.
- Store the Ed25519 private key in the Keychain, scoped to the
  ShareNet app's keychain access group.

### 3.4 Android VPNService

- Use `VpnService.Builder` to establish the TUN.
- Call `protect(socket)` on outbound sockets so they bypass the VPN
  and reach the underlying transport (cellular or Wi-Fi).
- Background operation requires a foreground service; the adapter MUST
  show a persistent notification while a circuit is active.
- Ed25519 private key is stored in the Android Keystore with
  `setUserAuthenticationRequired(false)` by default; operators MAY
  require biometric unlock.

### 3.5 iOS

- Use `NEPacketTunnelProvider` for the TUN device.
- Use `NEDNSProxyProvider` for DNS.
- Ed25519 private key is stored in the Keychain, scoped to the app's
  keychain access group.
- Background operation is constrained by iOS's Network Extension
  lifecycle; the adapter MUST gracefully handle suspension and
  resumption.

## 4. North-Star Scenario

The north-star demonstration of ShareNet 2.0 is:

> On an Android device with **mobile data OFF** and **Wi-Fi OFF**,
> Chrome (or any standard HTTP client) navigates to a real HTTPS
> website, with traffic flowing:
>
> ```
> Chrome → ShareNet VPN/TUN → relay_1 → relay_2 → … → gateway → real HTTPS site
> ```
>
> All protocol invariants preserved: NodeId binding, link
> authentication, route commitment, circuit AEAD, gateway policy
> enforcement, signed receipt for egress bytes.

This scenario is the Phase 10 exit condition (`spec/01-architecture.md`
§3). It is the closest to the proof diagram in `spec/00-thesis.md`
§1.1 that the first deliverable MUST demonstrate. Phase 10 builds the
Linux TUN adapter as the smallest correct demonstration; the Android
adapter follows once the platform-adapter invariants are verified on
Linux.

## 5. Platform Adapter Invariants

1. The adapter MUST NOT modify any byte of any protocol message.
2. The adapter MUST NOT make routing decisions; it forwards packets
   to the reference implementation's routing layer.
3. The adapter MUST NOT hold Ed25519 private keys in plaintext outside
   the platform's recommended keystore.
4. The adapter MUST NOT silently fail closed when a protocol invariant
   is violated; it MUST surface the failure to the user (notification)
   and to the audit log.
5. The adapter MUST NOT introduce new signature domains, new wire
   formats, or new protocol objects.

## 6. Reference Implementation Dependency

A platform adapter MUST link against the reference implementation's
TypeScript core. The adapter MAY be written in the platform's native
language (Kotlin, Swift, C++) IF AND ONLY IF it wraps the TypeScript
core via a foreign-function interface (e.g., a Node.js sidecar). A
platform adapter written entirely in native code that re-implements
the protocol from scratch is a specification violation: it duplicates
the protocol surface and risks divergence.

## 7. Cross-References

- Identity key storage: `spec/02-identity.md` §3.
- Link creation pipeline (must be honored by adapters):
  `spec/04-links.md` §3.
- Circuit AEAD (must be performed by the reference core, not the
  adapter): `spec/08-circuits.md` §4.
- Phase 10 exit condition: `spec/01-architecture.md` §3.
- Forbidden adapter behaviors (executable guards):
  `spec/17-conformance.md` §3.6.
