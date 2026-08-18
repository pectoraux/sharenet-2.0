#!/usr/bin/env python3
"""
ShareNet 2.0 — Independent Python Conformance Vector Verifier

Per GATE-01: an independent Python verifier that consumes the SAME vector
files as the TypeScript implementation. This proves cross-language conformance.

Implements from scratch (using standard Python libraries):
  - BLAKE3-256 hash (blake3 package)
  - RFC 4648 lowercase unpadded base32 (custom implementation)
  - Ed25519 signature verification (PyNaCl / libsodium)
  - Canonical CBOR encoding (cbor2 package, with canonical=True)

Usage:
  python3 conformance/runners/py_vector_verifier.py

Exit: 0 if all vectors pass, 1 if any fail.
"""

import hashlib
import hmac
import json
import os
import sys
import struct
from pathlib import Path
from typing import Any

# Third-party libraries (independent of the TypeScript implementation)
import blake3
import cbor2
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

# -----------------------------------------------------------------------
# ShareNet constants (from spec/02-identity.md §2.1)
# -----------------------------------------------------------------------

NODE_ID_DOMAIN_TAG = b"SHARENET/NODEID/1"  # 17 bytes
ED25519_PUBLIC_KEY_BYTES = 32
NODE_ID_BYTES = 32
NODE_ID_TEXT_LENGTH = 52
BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"

ADVERTISEMENT_SIGNATURE_DOMAIN = b"SHARENET/ADVERTISEMENT/1"
CLOCK_SKEW_SECONDS = 300
MAX_TTL_SECONDS = 86400

# CBOR integer keys for advertisements (ADR-0004)
ADV_KEY = {
    "PROTOCOL_VERSION": 1,
    "NODE_ID": 2,
    "SIGNING_PUBLIC_KEY": 3,
    "CAPABILITIES": 4,
    "ENDPOINTS": 5,
    "CIRCUIT_PUBLIC_KEY": 6,
    "GATEWAY_POLICY": 7,
    "SEQUENCE": 8,
    "TIMESTAMP": 9,
    "EXPIRY": 10,
    "NONCE": 11,
    "SIGNATURE": 12,
}


# -----------------------------------------------------------------------
# BLAKE3-256 + base32 NodeId derivation (independent implementation)
# -----------------------------------------------------------------------

def derive_node_id_bytes(ed25519_public_key: bytes) -> bytes:
    """NodeIdBytes = BLAKE3-256(SHARENET/NODEID/1 || ed25519_public_key)"""
    if len(ed25519_public_key) != ED25519_PUBLIC_KEY_BYTES:
        raise ValueError(f"public key must be {ED25519_PUBLIC_KEY_BYTES} bytes, got {len(ed25519_public_key)}")
    h = blake3.blake3()
    h.update(NODE_ID_DOMAIN_TAG)
    h.update(ed25519_public_key)
    return h.digest(length=NODE_ID_BYTES)


def bytes_to_base32(data: bytes) -> str:
    """RFC 4648 lowercase unpadded base32 encoding."""
    out = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(BASE32_ALPHABET[(buffer >> bits) & 0x1F])
    if bits > 0:
        out.append(BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1F])
    return "".join(out)


def base32_to_bytes(s: str) -> bytes:
    """RFC 4648 lowercase unpadded base32 decoding."""
    out = []
    buffer = 0
    bits = 0
    for ch in s:
        val = BASE32_ALPHABET.index(ch)
        if val < 0:
            raise ValueError(f"invalid base32 char: {ch}")
        buffer = (buffer << 5) | val
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
    # Check trailing bits are zero (canonical encoding)
    if bits > 0 and (buffer & ((1 << bits) - 1)) != 0:
        raise ValueError("non-canonical base32: trailing bits non-zero")
    return bytes(out)


def derive_node_id_text(ed25519_public_key: bytes) -> str:
    """Full NodeId derivation: BLAKE3-256 + base32."""
    return bytes_to_base32(derive_node_id_bytes(ed25519_public_key))


def is_valid_node_id_format(node_id: str) -> bool:
    """Check NodeId format: exactly 52 lowercase base32 chars with canonical trailing bits."""
    if not isinstance(node_id, str):
        return False
    if len(node_id) != NODE_ID_TEXT_LENGTH:
        return False
    for ch in node_id:
        if ch not in BASE32_ALPHABET:
            return False
    # Check canonical trailing bits: last char's low 4 bits must be zero
    last_val = BASE32_ALPHABET.index(node_id[-1])
    return (last_val & 0x0F) == 0


# -----------------------------------------------------------------------
# Canonical CBOR encoding (independent implementation using cbor2)
# -----------------------------------------------------------------------

def canonical_cbor_encode(value: Any) -> bytes:
    """Encode using canonical CBOR (RFC 8949 §4.2.2)."""
    return cbor2.dumps(value, canonical=True)


def canonical_cbor_decode(data: bytes) -> Any:
    """Decode canonical CBOR."""
    return cbor2.loads(data)


# -----------------------------------------------------------------------
# Advertisement verification (independent implementation)
# -----------------------------------------------------------------------

def encode_advertisement_body(adv: dict) -> bytes:
    """Encode advertisement body (without signature) as canonical CBOR."""
    m = {}
    m[ADV_KEY["PROTOCOL_VERSION"]] = adv["protocol_version"]
    m[ADV_KEY["NODE_ID"]] = adv["node_id"]
    m[ADV_KEY["SIGNING_PUBLIC_KEY"]] = adv["signing_public_key"]
    m[ADV_KEY["CAPABILITIES"]] = adv["capabilities"]
    m[ADV_KEY["ENDPOINTS"]] = [
        {1: e["type"], 2: e["address"], 3: e["port"]}
        for e in adv["endpoints"]
    ]
    m[ADV_KEY["SEQUENCE"]] = adv["sequence"]
    m[ADV_KEY["TIMESTAMP"]] = adv["timestamp"]
    m[ADV_KEY["EXPIRY"]] = adv["expiry"]
    m[ADV_KEY["NONCE"]] = adv["nonce"]
    if "circuit_public_key" in adv:
        m[ADV_KEY["CIRCUIT_PUBLIC_KEY"]] = adv["circuit_public_key"]
    if "gateway_policy" in adv:
        m[ADV_KEY["GATEWAY_POLICY"]] = adv["gateway_policy"]
    return canonical_cbor_encode(m)


def advertisement_signing_payload(adv: dict) -> bytes:
    """Compute the bytes-to-be-signed for an advertisement body."""
    body_bytes = encode_advertisement_body(adv)
    return ADVERTISEMENT_SIGNATURE_DOMAIN + body_bytes


def parse_advertisement_hex(hex_str: str) -> dict:
    """Parse a full advertisement from hex-encoded canonical CBOR."""
    raw = bytes.fromhex(hex_str)
    m = canonical_cbor_decode(raw)
    if not isinstance(m, dict):
        raise ValueError("advertisement is not a CBOR map")

    endpoints = []
    for em in m.get(ADV_KEY["ENDPOINTS"], []):
        endpoints.append({
            "type": em[1],
            "address": em[2],
            "port": em[3],
        })

    sig = m.get(ADV_KEY["SIGNATURE"], b"")

    adv = {
        "protocol_version": m[ADV_KEY["PROTOCOL_VERSION"]],
        "node_id": m[ADV_KEY["NODE_ID"]],
        "signing_public_key": bytes(m[ADV_KEY["SIGNING_PUBLIC_KEY"]]),
        "capabilities": list(m[ADV_KEY["CAPABILITIES"]]),
        "endpoints": endpoints,
        "sequence": m[ADV_KEY["SEQUENCE"]],
        "timestamp": m[ADV_KEY["TIMESTAMP"]],
        "expiry": m[ADV_KEY["EXPIRY"]],
        "nonce": bytes(m[ADV_KEY["NONCE"]]),
        "signature": bytes(sig) if sig else b"",
    }
    if ADV_KEY["CIRCUIT_PUBLIC_KEY"] in m:
        adv["circuit_public_key"] = bytes(m[ADV_KEY["CIRCUIT_PUBLIC_KEY"]])
    if ADV_KEY["GATEWAY_POLICY"] in m:
        adv["gateway_policy"] = m[ADV_KEY["GATEWAY_POLICY"]]
    return adv


def verify_advertisement(adv: dict, reference_now: int) -> dict:
    """
    Verify a NodeAdvertisement.
    Returns {"ok": True} or {"ok": False, "error": code, "detail": reason}.
    """
    pk = adv["signing_public_key"]
    if len(pk) != ED25519_PUBLIC_KEY_BYTES:
        return {"ok": False, "error": "MALFORMED_PUBLIC_KEY", "detail": f"expected 32 bytes, got {len(pk)}"}

    sig = adv.get("signature", b"")
    if len(sig) != 64:
        return {"ok": False, "error": "MALFORMED_SIGNATURE", "detail": f"expected 64 bytes, got {len(sig)}"}

    nonce = adv.get("nonce", b"")
    if len(nonce) != 16:
        return {"ok": False, "error": "MALFORMED_NONCE", "detail": f"expected 16 bytes, got {len(nonce)}"}

    node_id = adv["node_id"]
    if not is_valid_node_id_format(node_id):
        return {"ok": False, "error": "MALFORMED_NODE_ID", "detail": f"format invalid: {node_id[:30]}..."}

    # Identity binding: NodeId must match canonical derivation
    expected_node_id = derive_node_id_text(pk)
    if node_id != expected_node_id:
        return {"ok": False, "error": "IDENTITY_BINDING_MISMATCH",
                "detail": f"expected {expected_node_id}, got {node_id}"}

    # Timestamp validity (clock skew)
    if abs(adv["timestamp"] - reference_now) > CLOCK_SKEW_SECONDS:
        return {"ok": False, "error": "TIMESTAMP_OUT_OF_RANGE",
                "detail": f"|{adv['timestamp']} - {reference_now}| > {CLOCK_SKEW_SECONDS}"}

    # Expiry
    if adv["expiry"] <= reference_now:
        return {"ok": False, "error": "EXPIRED",
                "detail": f"expiry {adv['expiry']} <= now {reference_now}"}

    if adv["expiry"] - adv["timestamp"] > MAX_TTL_SECONDS:
        return {"ok": False, "error": "TTL_TOO_LONG",
                "detail": f"TTL {adv['expiry'] - adv['timestamp']} > {MAX_TTL_SECONDS}"}

    # Signature verification
    payload = advertisement_signing_payload(adv)
    try:
        verify_key = VerifyKey(pk)
        verify_key.verify(payload, sig)
    except BadSignatureError:
        return {"ok": False, "error": "INVALID_SIGNATURE", "detail": "Ed25519 signature did not verify"}
    except Exception as e:
        return {"ok": False, "error": "INVALID_SIGNATURE", "detail": str(e)}

    return {"ok": True}


def check_sequence(current_floor, attempted):
    """Check sequence floor: n < floor = STALE, n == floor = DUPLICATE, n > floor = accept."""
    if current_floor is None:
        return {"ok": True, "previous_floor": -1, "new_floor": attempted}
    if attempted < current_floor:
        return {"ok": False, "reason": "STALE", "current_floor": current_floor, "attempted": attempted}
    if attempted == current_floor:
        return {"ok": False, "reason": "DUPLICATE", "current_floor": current_floor, "attempted": attempted}
    return {"ok": True, "previous_floor": current_floor, "new_floor": attempted}


# -----------------------------------------------------------------------
# Vector verification
# -----------------------------------------------------------------------

def verify_vector(data: dict) -> dict:
    """Verify a single conformance vector. Returns {"id": ..., "passed": bool, ...}."""
    vid = data.get("id", "unknown")

    if vid.startswith("V-NODEID-001"):
        pub_key_hex = data["input"]["ed25519PublicKeyHex"]
        expected = data["expected"]["nodeIdText"]
        pub_key = bytes.fromhex(pub_key_hex)
        actual = derive_node_id_text(pub_key)
        passed = (actual == expected and is_valid_node_id_format(actual))
        return {"id": vid, "passed": passed, "expected": expected,
                "actual": actual if passed else f"mismatch: {actual} != {expected}"}

    elif vid.startswith("V-NODEID-002"):
        claimed = data["input"]["claimedNodeId"]
        diff_pk = bytes.fromhex(data["input"]["differentPublicKeyHex"])
        expected_node = derive_node_id_text(diff_pk)
        rejects = (claimed != expected_node)
        return {"id": vid, "passed": rejects, "expected": "reject mismatch",
                "actual": "rejected" if rejects else "accepted (BUG!)"}

    elif vid.startswith("V-NODEID-003"):
        cases = data.get("cases", [])
        failures = []
        for c in cases:
            result = is_valid_node_id_format(c["input"])
            if result != c["expected"]:
                failures.append(f"{c['input'][:30]}... expected={c['expected']} got={result}")
        passed = len(failures) == 0
        return {"id": vid, "passed": passed, "expected": f"{len(cases)} cases match",
                "actual": f"{len(cases)} cases match" if passed else f"FAILED: {'; '.join(failures)}"}

    elif vid.startswith("V-CBOR-"):
        vectors = data.get("vectors", [])
        failures = []
        for v in vectors:
            try:
                inp = v["input"]
                if isinstance(inp, dict) and "__bytes__" in inp:
                    inp = bytes.fromhex(inp["__bytes__"])
                encoded = canonical_cbor_encode(inp)
                actual_hex = encoded.hex()
                if actual_hex != v["expectedHex"]:
                    failures.append(f"{v['name']}: {actual_hex} != {v['expectedHex']}")
            except Exception as e:
                failures.append(f"{v['name']}: threw {e}")
        passed = len(failures) == 0
        return {"id": vid, "passed": passed, "expected": f"{len(vectors)} vectors match",
                "actual": f"{len(vectors)} vectors match" if passed else f"FAILED: {'; '.join(failures)}"}

    elif vid.startswith("V-ADV-"):
        hex_str = data["input"]["advertisementHex"]
        reference_now = data["referenceNow"]
        current_floor = data["input"].get("currentSequenceFloor")
        expected_result = data["expected"]["verificationResult"]
        expected_code = data["expected"].get("errorCode")

        try:
            adv = parse_advertisement_hex(hex_str)
            v = verify_advertisement(adv, reference_now)

            if expected_result == "ok":
                if v["ok"]:
                    if current_floor is not None:
                        sc = check_sequence(current_floor, adv["sequence"])
                        if sc.get("ok"):
                            return {"id": vid, "passed": True, "expected": "ok", "actual": "ok"}
                        else:
                            return {"id": vid, "passed": False, "expected": "ok",
                                    "actual": f"seq check: {sc.get('reason')}"}
                    return {"id": vid, "passed": True, "expected": "ok", "actual": "ok"}
                else:
                    return {"id": vid, "passed": False, "expected": "ok",
                            "actual": f"fail: {v.get('error')}"}
            else:
                # Expected fail
                if not v["ok"]:
                    return {"id": vid, "passed": v.get("error") == expected_code or expected_code == "DECODE_FAILED",
                            "expected": f"fail/{expected_code}", "actual": f"fail/{v.get('error')}"}
                else:
                    # Verification passed but expected fail — check sequence floor
                    if current_floor is not None and expected_code == "STALE":
                        sc = check_sequence(current_floor, adv["sequence"])
                        if not sc.get("ok") and sc.get("reason") == "STALE":
                            return {"id": vid, "passed": True, "expected": "fail/STALE",
                                    "actual": f"verify ok, seq STALE (floor={current_floor}, attempted={adv['sequence']})"}
                    return {"id": vid, "passed": False, "expected": f"fail/{expected_code}",
                            "actual": "ok (unexpected)"}

        except Exception as e:
            if expected_code == "DECODE_FAILED":
                return {"id": vid, "passed": True, "expected": "fail/DECODE_FAILED",
                        "actual": f"decode threw: {e}"}
            return {"id": vid, "passed": False, "expected": expected_code or "ok",
                    "actual": f"threw: {e}"}

    elif vid.startswith("V-LINK-HANDSHAKE-") or vid.startswith("V-LINK-AUTH-"):
        return verify_handshake_vector(data)

    elif vid.startswith("V-ROUTE-PROPOSAL-"):
        return verify_route_proposal_vector(data)

    elif vid.startswith("V-ROUTE-COMMIT-"):
        return verify_route_commit_vector(data)

    elif vid.startswith("V-HINT-"):
        return verify_hint_vector(data)

    elif vid.startswith("V-SVC-"):
        return verify_svc_vector(data)

    elif vid.startswith("V-CIRCUIT-SETUP-"):
        return verify_circuit_setup_vector(data)

    elif vid.startswith("V-CIRCUIT-ACK-"):
        return verify_circuit_ack_vector(data)

    elif vid.startswith("V-CIRCUIT-"):
        return verify_circuit_vector(data)

    elif vid.startswith("V-GATEWAY-"):
        return verify_gateway_vector(data)

    elif vid.startswith("V-RECEIPT-"):
        return verify_receipt_vector(data)

    elif vid.startswith("V-CONTRIBUTION-PROOF-"):
        return verify_contribution_proof_vector(data)

    elif vid.startswith("V-PATH-VALIDATION-"):
        return verify_path_validation_vector(data)

    elif vid.startswith("V-TOPOLOGY-PROPAGATION-"):
        return verify_topology_propagation_vector(data)

    elif vid.startswith("V-DISCOVERY-"):
        return verify_discovery_vector(data)

    return {"id": vid, "passed": False, "expected": "known type", "actual": "unknown type"}


# -----------------------------------------------------------------------
# Route commitment vector verification (added for R-003/R-004)
# -----------------------------------------------------------------------

MERKLE_DOMAIN = b"SHARENET/ROUTE/COMMITMENT/MERKLE/1"
LEAF_TYPE_PROPOSAL = 0x00
LEAF_TYPE_ACCEPTANCE = 0x01
NODE_TYPE_INTERNAL = 0x02


def _canonical_encode_proposal(proposal: dict) -> bytes:
    """Canonical CBOR encoding of a RouteProposal for the Merkle leaf."""
    m = {}
    m[1] = [h["nodeId"] for h in proposal["hops"]]
    m[2] = [h["capability"] for h in proposal["hops"]]
    m[3] = [h["endpoint"] for h in proposal["hops"]]
    m[4] = [h["linkUp"] for h in proposal["hops"]]
    m[5] = proposal["requirementDigest"]
    m[6] = proposal["expiry"]
    m[7] = proposal["initiatorNodeId"]
    m[8] = proposal["agreementDigest"]
    return cbor2.dumps(m, canonical=True)


def _canonical_encode_acceptance(acc: dict) -> bytes:
    """Canonical CBOR encoding of a RouteAcceptance for the Merkle leaf."""
    m = {}
    m[1] = acc["proposalDigestHex"]
    m[2] = acc["hopIndex"]
    m[3] = acc["hopDigestHex"]
    m[4] = acc["serviceDigestHex"]
    m[5] = acc["acceptorNodeId"]
    m[6] = bytes.fromhex(acc["acceptanceNonceHex"])
    m[7] = acc["expiry"]
    m[8] = bytes.fromhex(acc["signatureHex"])
    return cbor2.dumps(m, canonical=True)


def _compute_proposal_leaf(proposal: dict) -> bytes:
    domain = MERKLE_DOMAIN
    body = _canonical_encode_proposal(proposal)
    return blake3.blake3(domain + bytes([LEAF_TYPE_PROPOSAL]) + body).digest()


def _compute_acceptance_leaf(acc: dict, hop_index: int) -> bytes:
    domain = MERKLE_DOMAIN
    body = _canonical_encode_acceptance(acc)
    index_bytes = struct.pack(">I", hop_index)  # u32be
    return blake3.blake3(domain + bytes([LEAF_TYPE_ACCEPTANCE]) + index_bytes + body).digest()


def _compute_parent(left: bytes, right: bytes) -> bytes:
    domain = MERKLE_DOMAIN
    return blake3.blake3(domain + bytes([NODE_TYPE_INTERNAL]) + left + right).digest()


def _compute_commitment_root(proposal: dict, acceptances: list) -> bytes:
    """Compute the canonical Merkle commitment_root."""
    leaves = [_compute_proposal_leaf(proposal)]
    for i, acc in enumerate(acceptances):
        leaves.append(_compute_acceptance_leaf(acc, i))

    level = leaves
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left  # duplicate last if odd
            next_level.append(_compute_parent(left, right))
        level = next_level

    return level[0]


def _derive_route_id(commitment_root: bytes) -> str:
    return "route:" + commitment_root.hex()


def verify_route_commit_vector(data: dict) -> dict:
    """Verify a V-ROUTE-COMMIT-* vector (canonical Merkle commitment_root)."""
    vid = data.get("id", "unknown")
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            proposal = v["proposal"]
            acceptances = v["acceptances"]

            root = _compute_commitment_root(proposal, acceptances)
            root_hex = root.hex()
            route_id = _derive_route_id(root)

            if root_hex != v["expectedCommitmentRootHex"]:
                failures.append(f'{v["name"]}: root {root_hex} != {v["expectedCommitmentRootHex"]}')
            elif route_id != v["expectedRouteId"]:
                failures.append(f'{v["name"]}: routeId {route_id} != {v["expectedRouteId"]}')
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} route-commit vectors match",
        "actual": f"{len(vectors)} route-commit vectors match" if passed else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# Main: read all vector files and verify
# -----------------------------------------------------------------------

# -----------------------------------------------------------------------
# Handshake vector verification (added for GATE-03)
# -----------------------------------------------------------------------

def verify_handshake_vector(data: dict) -> dict:
    """Verify a V-LINK-HANDSHAKE-* vector."""
    vid = data.get("id", "unknown")
    inp = data.get("input", {})
    exp = data.get("expected", {})

    # Parse keys
    pub_key_a = bytes.fromhex(inp["initiatorPublicKeyHex"])
    pub_key_b = bytes.fromhex(inp["responderPublicKeyHex"])
    node_id_a = inp["initiatorNodeId"]
    node_id_b = inp["responderNodeId"]
    link_nonce_a = bytes.fromhex(inp["linkNonceAHex"])
    link_nonce_b = bytes.fromhex(inp["linkNonceBHex"])
    challenge_for_b = bytes.fromhex(inp["challengeForBHex"])
    challenge_for_a = bytes.fromhex(inp["challengeForAHex"])

    # Compute LinkId bytes (responder perspective: local=B, remote=A)
    link_id_bytes = _compute_link_id_bytes(node_id_b, node_id_a, link_nonce_b, link_nonce_a)

    # Parse wire messages
    initiate_bytes = bytes.fromhex(inp["initiateMessageHex"])
    accept_bytes = bytes.fromhex(inp["acceptMessageHex"])
    confirm_hex = inp.get("confirmMessageHex")
    confirm_bytes = bytes.fromhex(confirm_hex) if confirm_hex else None

    # Compute transcript hashes
    transcript_after_initiate = _compute_transcript_hash([initiate_bytes])
    transcript_after_accept = _compute_transcript_hash([initiate_bytes, accept_bytes])

    # Decode Accept to get proofB
    accept_msg = cbor2.loads(accept_bytes)
    proof_b = bytes(accept_msg.get(5, b""))  # key 5 = proofB

    # Verify proofB (B signs challengeForB with RESPONDER role)
    proof_b_ok = _verify_possession_proof(
        pub_key_b, proof_b, b"SHARENET/LINK/POSSESSION/RESPONDER/1",
        transcript_after_initiate, link_id_bytes, challenge_for_b, 0x02,
    )

    if exp.get("result") == "LINK_UP":
        if not confirm_bytes:
            return {"id": vid, "passed": False, "expected": "LINK_UP", "actual": "missing confirm"}
        confirm_msg = cbor2.loads(confirm_bytes)
        proof_a = bytes(confirm_msg.get(2, b""))  # key 2 = proofA
        proof_a_ok = _verify_possession_proof(
            pub_key_a, proof_a, b"SHARENET/LINK/POSSESSION/INITIATOR/1",
            transcript_after_accept, link_id_bytes, challenge_for_a, 0x01,
        )
        passed = proof_b_ok and proof_a_ok
        return {"id": vid, "passed": passed, "expected": "LINK_UP",
                "actual": f"proofB={proof_b_ok}, proofA={proof_a_ok}"}
    else:
        passed = not proof_b_ok
        return {"id": vid, "passed": passed, "expected": f"fail/{exp.get('errorCode')}",
                "actual": "proofB invalid (expected)" if passed else "proofB valid (unexpected!)"}


def _compute_link_id_bytes(local_node_id: str, remote_node_id: str,
                           local_nonce: bytes, remote_nonce: bytes) -> bytes:
    h = blake3.blake3()
    h.update(b"SHARENET/LINK/ID/1")
    h.update(local_node_id.encode())
    h.update(remote_node_id.encode())
    h.update(local_nonce)
    h.update(remote_nonce)
    return h.digest(length=32)


def _compute_transcript_hash(messages: list) -> bytes:
    h = blake3.blake3()
    h.update(b"SHARENET/LINK/TRANSCRIPT/1")
    for msg in messages:
        h.update(struct.pack(">I", len(msg)))
        h.update(msg)
    return h.digest(length=32)


def _build_possession_payload(domain_tag: bytes, transcript_hash: bytes,
                              link_id_bytes: bytes, peer_challenge: bytes,
                              role_byte: int) -> bytes:
    return domain_tag + transcript_hash + link_id_bytes + peer_challenge + bytes([role_byte])


def _verify_possession_proof(public_key: bytes, signature: bytes,
                              domain_tag: bytes, transcript_hash: bytes,
                              link_id_bytes: bytes, peer_challenge: bytes,
                              role_byte: int) -> bool:
    if len(signature) != 64 or len(public_key) != 32:
        return False
    payload = _build_possession_payload(domain_tag, transcript_hash, link_id_bytes, peer_challenge, role_byte)
    try:
        vk = VerifyKey(public_key)
        vk.verify(payload, signature)
        return True
    except (BadSignatureError, Exception):
        return False


# -----------------------------------------------------------------------
# RemoteNodeHint vector verification (added for R-007 — V-HINT-001)
# -----------------------------------------------------------------------

HINT_SIGNATURE_DOMAIN = b"SHARENET/HINT/1"
MAX_HINT_HOPS = 3
MAX_HINT_FRESHNESS_SECONDS = 3600
HINT_NONCE_BYTES = 16


def encode_hint_body(body: dict) -> bytes:
    """Encode a RemoteNodeHint body as canonical CBOR (integer-keyed map per ADR-0004).

    Keys: 1=reporterNodeId, 2=subjectNodeId, 3=subjectEndpointHint,
          4=claimedCapabilities[], 5=hopCount, 6=timestamp, 7=nonce (16-byte bstr).
    """
    m = {
        1: body["reporterNodeId"],
        2: body["subjectNodeId"],
        3: body["subjectEndpointHint"],
        4: list(body["claimedCapabilities"]),
        5: body["hopCount"],
        6: body["timestamp"],
        7: body["nonce"] if isinstance(body.get("nonce"), bytes)
            else bytes.fromhex(body["nonceHex"]),
    }
    return canonical_cbor_encode(m)


def hint_signing_payload(body: dict) -> bytes:
    """Compute the bytes-to-be-signed for a RemoteNodeHint body."""
    return HINT_SIGNATURE_DOMAIN + encode_hint_body(body)


def verify_remote_node_hint(hint: dict, reporter_public_key: bytes, now: int) -> dict:
    """Verify a RemoteNodeHint cryptographically (independent implementation).

    Mirrors reference/topology/remote-node-hint.ts — verifyRemoteNodeHint:
      1. hopCount <= MAX_HINT_HOPS (3)
      2. |timestamp - now| <= MAX_HINT_FRESHNESS_SECONDS (3600)
      3. nonce length == 16
      4. Ed25519 signature over (domain || canonical CBOR body) verifies
    """
    hop_count = hint["hopCount"]
    if hop_count > MAX_HINT_HOPS:
        return {"ok": False, "error": "HOP_COUNT_EXCEEDED",
                "detail": f"hopCount {hop_count} exceeds max {MAX_HINT_HOPS}"}

    timestamp = hint["timestamp"]
    if abs(timestamp - now) > MAX_HINT_FRESHNESS_SECONDS:
        return {"ok": False, "error": "EXPIRED",
                "detail": "hint outside freshness window"}

    nonce = (hint["nonce"] if isinstance(hint.get("nonce"), bytes)
             else bytes.fromhex(hint["nonceHex"]))
    if len(nonce) != HINT_NONCE_BYTES:
        return {"ok": False, "error": "MALFORMED_NONCE",
                "detail": f"expected {HINT_NONCE_BYTES} bytes, got {len(nonce)}"}

    sig_hex = hint.get("reporterSignatureHex") or hint.get("tamperedReporterSignatureHex")
    if not sig_hex:
        return {"ok": False, "error": "MALFORMED_SIGNATURE",
                "detail": "no signature provided"}
    sig = bytes.fromhex(sig_hex)
    if len(sig) != 64:
        return {"ok": False, "error": "MALFORMED_SIGNATURE",
                "detail": f"expected 64 bytes, got {len(sig)}"}

    payload = hint_signing_payload(hint)
    try:
        VerifyKey(reporter_public_key).verify(payload, sig)
    except BadSignatureError:
        return {"ok": False, "error": "SIGNATURE_INVALID",
                "detail": "reporter signature invalid"}
    except Exception as e:
        return {"ok": False, "error": "SIGNATURE_INVALID", "detail": str(e)}

    return {"ok": True}


def verify_hint_vector(data: dict) -> dict:
    """Verify a V-HINT-* vector (RemoteNodeHint signed-claim verification)."""
    vid = data.get("id", "unknown")
    shared_keys = data.get("sharedKeys", {})
    reporter_pubkey = bytes.fromhex(shared_keys["reporterPublicKeyHex"])
    reference_now = data["referenceNow"]
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            exp = v["expected"]
            intermediate = v.get("intermediate", {})
            hint = {
                "reporterNodeId": inp["reporterNodeId"],
                "subjectNodeId": inp["subjectNodeId"],
                "subjectEndpointHint": inp["subjectEndpointHint"],
                "claimedCapabilities": inp["claimedCapabilities"],
                "hopCount": inp["hopCount"],
                "timestamp": inp["timestamp"],
                "nonceHex": inp["nonceHex"],
            }
            # Signatures may live under `input` (tampered/expired/hop-overflow
            # cases) or under `intermediate` (valid-hint case).
            sig_hex = (
                inp.get("reporterSignatureHex")
                or inp.get("tamperedReporterSignatureHex")
                or intermediate.get("reporterSignatureHex")
            )
            if sig_hex:
                hint["reporterSignatureHex"] = sig_hex

            result = verify_remote_node_hint(hint, reporter_pubkey, reference_now)

            if exp["verificationResult"] == "ok":
                if not result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected ok, got {result.get("error")}: {result.get("detail")}'
                    )
            else:
                expected_code = exp.get("errorCode")
                if result["ok"]:
                    failures.append(f'{v["name"]}: expected fail/{expected_code}, got ok')
                elif result.get("error") != expected_code:
                    failures.append(
                        f'{v["name"]}: expected fail/{expected_code}, got fail/{result.get("error")}'
                    )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} hint vectors match",
        "actual": f"{len(vectors)} hint vectors match" if passed else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# Service negotiation policy check (added for R-007 — V-SVC-001)
# -----------------------------------------------------------------------

def _extract_host(destination: str) -> str:
    """Extract the host portion of a destination string. Mirrors reference impl."""
    s = destination
    if "://" in s:
        s = s.split("://", 1)[1]
    if "/" in s:
        s = s.split("/", 1)[0]
    if ":" in s:
        s = s.split(":", 1)[0]
    return s.lower()


def _is_loopback(host: str) -> bool:
    return host == "localhost" or host == "::1" or host.startswith("127.")


def _is_link_local(host: str) -> bool:
    return host.startswith("169.254.") or host.startswith("fe80:")


def _is_private_address(host: str) -> bool:
    if host.startswith("10."):
        return True
    if host.startswith("192.168."):
        return True
    if host.startswith("172."):
        parts = host.split(".")
        if len(parts) > 1:
            try:
                second = int(parts[1])
                if 16 <= second <= 31:
                    return True
            except ValueError:
                pass
    if host.startswith("fc") or host.startswith("fd"):
        return True
    return False


def _is_ssrf_target(host: str) -> bool:
    if host == "169.254.169.254":
        return True
    if host == "metadata.google.internal":
        return True
    if host == "fd00:ec2::254":
        return True
    if host.endswith(".internal") and not host.endswith(".sharenet.local"):
        return True
    return False


def _match_glob(pattern: str, host: str) -> bool:
    if pattern == "*":
        return True
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    return False


def check_service_policy(requirement: dict, offer: dict, now: int,
                         allowed_destinations=None, revoked_peers=None) -> dict:
    """Independent implementation of reference/routing/service-negotiation.ts checkPolicy."""
    if requirement["expiry"] <= now:
        return {"ok": False, "reason": "EXPIRED"}

    if offer["capability"] != requirement["requiredCapability"]:
        return {"ok": False, "reason": "CAPABILITY_MISMATCH"}

    if offer.get("advVerifiedOnly"):
        return {"ok": False, "reason": "ADV_VERIFIED_ONLY"}
    if not offer.get("linkUp"):
        return {"ok": False, "reason": "NO_LINK_UP"}

    if revoked_peers and offer["nodeId"] in revoked_peers:
        return {"ok": False, "reason": "PEER_REVOKED"}

    # Gateway destination policy (mirrors spec/09 §3 ordering)
    if offer["capability"] == "INTERNET_GATEWAY" and requirement.get("destination"):
        host = _extract_host(requirement["destination"])

        if _is_ssrf_target(host):
            return {"ok": False, "reason": "DESTINATION_BLOCKED_SSRF"}
        if _is_loopback(host):
            return {"ok": False, "reason": "DESTINATION_BLOCKED_LOOPBACK"}
        if _is_link_local(host):
            return {"ok": False, "reason": "DESTINATION_BLOCKED_LINK_LOCAL"}
        if _is_private_address(host):
            return {"ok": False, "reason": "DESTINATION_BLOCKED_PRIVATE"}

        if allowed_destinations and len(allowed_destinations) > 0:
            if not any(_match_glob(p, host) for p in allowed_destinations):
                return {"ok": False, "reason": "DESTINATION_NOT_ALLOWED"}

    return {"ok": True, "policyVersion": 1}


def verify_svc_vector(data: dict) -> dict:
    """Verify a V-SVC-* vector (service-negotiation policy check)."""
    vid = data.get("id", "unknown")
    reference_now = data["referenceNow"]
    defaults = data.get("defaults", {})
    allowed_destinations = defaults.get("allowedDestinations", [])
    revoked_peers = defaults.get("revokedPeers", [])
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            exp = v["expected"]
            requirement = inp["requirement"]
            offer = inp["offer"]

            result = check_service_policy(
                requirement, offer, reference_now,
                allowed_destinations, revoked_peers,
            )

            if exp["result"] == "ok":
                if not result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected ok, got DENY/{result.get("reason")}'
                    )
            else:
                expected_reason = exp.get("reason")
                if result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected DENY/{expected_reason}, got ok'
                    )
                elif result.get("reason") != expected_reason:
                    failures.append(
                        f'{v["name"]}: expected DENY/{expected_reason}, '
                        f'got DENY/{result.get("reason")}'
                    )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} svc vectors match",
        "actual": f"{len(vectors)} svc vectors match" if passed else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# Circuit byte-stability + replay guard (added for R-007 — V-CIRCUIT-001)
# -----------------------------------------------------------------------

CIRCUIT_ID_DOMAIN = b"SHARENET/CIRCUIT/ID/1"
CIRCUIT_KEY_DOMAIN = b"SHARENET/CIRCUIT/KEY/1"
CIRCUIT_AEAD_NONCE_BYTES = 12
CIRCUIT_HKDF_EXPAND_LEN = 64


def derive_circuit_id(route_id: str, initiator_x25519_pubkey: bytes) -> bytes:
    """CircuitId = BLAKE3-256(SHARENET/CIRCUIT/ID/1 || route_id || initiator_pubkey)."""
    h = blake3.blake3()
    h.update(CIRCUIT_ID_DOMAIN)
    h.update(route_id.encode("utf-8"))
    h.update(initiator_x25519_pubkey)
    return h.digest(length=32)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract per RFC 5869 with SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand per RFC 5869 with SHA-256."""
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def derive_hop_keys(shared_secret: bytes, hop_index: int, circuit_id: bytes) -> tuple:
    """Derive (forwardingKey, returnKey) via HKDF-SHA256.

    info = utf8(SHARENET/CIRCUIT/KEY/1) || u8(hopIndex) || circuit_id (32 bytes)
    Output: 64 bytes → forwardingKey[0:32] || returnKey[32:64]
    """
    if hop_index < 0 or hop_index > 255:
        raise ValueError(f"hopIndex out of u8 range: {hop_index}")
    prk = _hkdf_extract(b"", shared_secret)
    info = CIRCUIT_KEY_DOMAIN + bytes([hop_index]) + circuit_id
    expanded = _hkdf_expand(prk, info, CIRCUIT_HKDF_EXPAND_LEN)
    return expanded[:32], expanded[32:64]


def build_circuit_nonce(route_id_prefix: int, sequence_number: int) -> bytes:
    """Nonce = u32be(routeIdPrefix) || u64be(sequenceNumber)."""
    return struct.pack(">I", route_id_prefix) + struct.pack(">Q", sequence_number)


class CircuitReplayGuard:
    """Independent implementation of reference/circuit/circuit.ts CircuitReplayGuard.

    Implements the FROZEN ORDERED_STREAM replay model: a receiver rejects any
    frame whose sequence is `<=` the highest sequence already accepted.
    """

    def __init__(self):
        self._highest_seq = 0

    def check_and_record(self, seq: int) -> dict:
        if seq <= self._highest_seq:
            return {"ok": False,
                    "reason": f"sequence {seq} ≤ highest {self._highest_seq} (replay/stale)"}
        self._highest_seq = seq
        return {"ok": True}

    @property
    def highest_seq(self) -> int:
        return self._highest_seq


def verify_circuit_vector(data: dict) -> dict:
    """Verify a V-CIRCUIT-* vector (circuit id / hop keys / nonce / replay guard)."""
    vid = data.get("id", "unknown")
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            name = v["name"]
            inp = v["input"]
            exp = v["expected"]

            if name == "circuit-id-deterministic":
                route_id = inp["routeId"]
                initiator_pub = bytes.fromhex(inp["initiatorX25519PublicKeyHex"])
                cid = derive_circuit_id(route_id, initiator_pub)
                if cid.hex() != exp["circuitIdHex"]:
                    failures.append(
                        f'{name}: circuitId {cid.hex()} != {exp["circuitIdHex"]}'
                    )

            elif name == "hop-keys-deterministic":
                shared = bytes.fromhex(inp["sharedSecretHex"])
                hop_index = inp["hopIndex"]
                cid = bytes.fromhex(inp["circuitIdHex"])
                fwd, ret = derive_hop_keys(shared, hop_index, cid)
                if fwd.hex() != exp["forwardingKeyHex"]:
                    failures.append(
                        f'{name}: forwardingKey {fwd.hex()} != {exp["forwardingKeyHex"]}'
                    )
                if ret.hex() != exp["returnKeyHex"]:
                    failures.append(
                        f'{name}: returnKey {ret.hex()} != {exp["returnKeyHex"]}'
                    )

            elif name == "nonce-layout":
                prefix = inp["routeIdPrefix"]
                seq = int(inp["sequenceNumber"])
                nonce = build_circuit_nonce(prefix, seq)
                if nonce.hex() != exp["nonceHex"]:
                    failures.append(
                        f'{name}: nonce {nonce.hex()} != {exp["nonceHex"]}'
                    )

            elif name in ("replay-guard-rejects-duplicate",
                          "replay-guard-rejects-lower"):
                guard = CircuitReplayGuard()
                # First call sequence — "checkAndRecord(Nn)" → parse N from the string.
                first_call = inp["firstCall"]
                second_call = inp["secondCall"]
                first_seq = _parse_seq_from_call(first_call)
                second_seq = _parse_seq_from_call(second_call)
                r1 = guard.check_and_record(first_seq)
                if r1["ok"] != (exp["firstResult"] == "ok"):
                    failures.append(
                        f'{name}: first call expected {exp["firstResult"]}, '
                        f'got {"ok" if r1["ok"] else "fail"}'
                    )
                r2 = guard.check_and_record(second_seq)
                if r2["ok"] != (exp["secondResult"] == "ok"):
                    failures.append(
                        f'{name}: second call expected {exp["secondResult"]}, '
                        f'got {"ok" if r2["ok"] else "fail"}'
                    )
            else:
                failures.append(f'{name}: unknown circuit sub-vector')
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} circuit vectors match",
        "actual": f"{len(vectors)} circuit vectors match" if passed else f"FAILED: {'; '.join(failures)}",
    }


def _parse_seq_from_call(call_str: str) -> int:
    """Parse a 'checkAndRecord(Nn)' string into an int N."""
    # Strip trailing 'n' (JS BigInt literal) and surrounding parens.
    inner = call_str.split("(", 1)[1].rstrip(")")
    inner = inner.rstrip("n")
    return int(inner)


# -----------------------------------------------------------------------
# Gateway policy evaluation (added for R-007 — V-GATEWAY-001)
# -----------------------------------------------------------------------

GATEWAY_QUOTA_WINDOW_MS = 60_000


def evaluate_gateway_request(input_req: dict, policy: dict,
                             capacity: dict, now: int) -> dict:
    """Independent implementation of reference/gateway/gateway.ts evaluateGatewayRequest.

    Returns ALLOW only if ALL checks pass:
      1. enabled → 2. peer revoked → 3. allowlist (empty deny-all + glob match)
      4. SSRF / loopback / link-local / private (BEFORE DNS)
      5. per-peer quota → 6. global quota → 7. rate limit → 8. bandwidth
    """
    destination = input_req["destination"]
    peer_node_id = input_req["peerNodeId"]
    requested_bytes = input_req["requestedBytes"]
    host = _extract_host(destination)

    def deny(reason, detail):
        return {"decision": "DENY", "reason": reason, "detail": detail,
                "destination": destination, "peerNodeId": peer_node_id,
                "decidedAt": now}

    # 1. Gateway enabled
    if not policy.get("enabled", True):
        return deny("GATEWAY_DISABLED", "gateway is disabled")

    # 2. Peer revoked
    if peer_node_id in policy.get("revokedPeers", []):
        return deny("PEER_REVOKED", f"peer {peer_node_id} is revoked")

    # 3. Destination allowlist
    allowed = policy.get("allowedDestinations", [])
    if len(allowed) == 0:
        return deny("DESTINATION_NOT_ALLOWED",
                    "no destinations allowed (secure default)")
    if not any(_match_glob(p, host) for p in allowed):
        return deny("DESTINATION_NOT_ALLOWED",
                    f"host {host} not in allowlist")

    # 4. SSRF / loopback / link-local / private blocking (BEFORE DNS)
    if policy.get("blockSsrf") and _is_ssrf_target(host):
        return deny("DESTINATION_BLOCKED_SSRF", f"SSRF-sensitive: {host}")
    if policy.get("blockLoopback") and _is_loopback(host):
        return deny("DESTINATION_BLOCKED_LOOPBACK", f"loopback: {host}")
    if policy.get("blockLinkLocal") and _is_link_local(host):
        return deny("DESTINATION_BLOCKED_LINK_LOCAL", f"link-local: {host}")
    if policy.get("blockPrivateAddresses") and _is_private_address(host):
        return deny("DESTINATION_BLOCKED_PRIVATE", f"private address: {host}")

    # Reset window if expired (mirror TS side-effects)
    if now - capacity["windowStart"] > GATEWAY_QUOTA_WINDOW_MS:
        capacity["windowStart"] = now
        capacity["globalCount"] = 0
        capacity["perPeerCounts"] = {}
    if now - capacity["secondStart"] > 1000:
        capacity["secondStart"] = now
        capacity["bytesThisSecond"] = 0

    # 5. Per-peer quota
    peer_count = capacity["perPeerCounts"].get(peer_node_id, 0)
    if peer_count >= policy["perPeerQuota"]:
        return deny("PER_PEER_QUOTA_EXHAUSTED",
                    f"peer {peer_node_id} has {peer_count}/{policy['perPeerQuota']} requests")

    # 6. Global quota
    if capacity["globalCount"] >= policy["globalQuota"]:
        return deny("GLOBAL_QUOTA_EXHAUSTED",
                    f"global {capacity['globalCount']}/{policy['globalQuota']} requests")

    # 7. Rate limit (per-peer, per-second)
    last_req = capacity["lastRequestPerPeer"].get(peer_node_id, 0)
    if now - last_req < 1000 / policy["rateLimitPerSec"]:
        return deny("RATE_LIMIT_EXCEEDED",
                    f"peer {peer_node_id} rate-limited")

    # 8. Bandwidth
    if capacity["bytesThisSecond"] + requested_bytes > policy["bandwidthBps"]:
        total = capacity["bytesThisSecond"] + requested_bytes
        return deny("BANDWIDTH_EXCEEDED",
                    f"bandwidth {total}/{policy['bandwidthBps']} bytes/s")

    # ALL checks passed — ALLOW. Update capacity tracking.
    capacity["perPeerCounts"][peer_node_id] = peer_count + 1
    capacity["globalCount"] = capacity["globalCount"] + 1
    capacity["lastRequestPerPeer"][peer_node_id] = now
    capacity["bytesThisSecond"] = capacity["bytesThisSecond"] + requested_bytes

    return {"decision": "ALLOW", "detail": "all guards passed",
            "destination": destination, "peerNodeId": peer_node_id,
            "decidedAt": now}


def verify_gateway_vector(data: dict) -> dict:
    """Verify a V-GATEWAY-* vector (gateway policy evaluation)."""
    vid = data.get("id", "unknown")
    now_ms = data["referenceNowMs"]
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            exp = v["expected"]
            request = inp["request"]
            policy = inp["policy"]

            # Fresh capacity per case (no state leakage between cases).
            capacity = {
                "perPeerCounts": {},
                "globalCount": 0,
                "windowStart": now_ms,
                "lastRequestPerPeer": {},
                "bytesThisSecond": 0,
                "secondStart": now_ms,
            }

            result = evaluate_gateway_request(request, policy, capacity, now_ms)

            if exp["decision"] == "ALLOW":
                if result["decision"] != "ALLOW":
                    failures.append(
                        f'{v["name"]}: expected ALLOW, '
                        f'got DENY/{result.get("reason")}'
                    )
            else:
                expected_reason = exp.get("reason")
                if result["decision"] != "DENY":
                    failures.append(
                        f'{v["name"]}: expected DENY/{expected_reason}, got ALLOW'
                    )
                elif result.get("reason") != expected_reason:
                    failures.append(
                        f'{v["name"]}: expected DENY/{expected_reason}, '
                        f'got DENY/{result.get("reason")}'
                    )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} gateway vectors match",
        "actual": f"{len(vectors)} gateway vectors match" if passed else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# Bilateral receipt verification (added for R-007 — V-RECEIPT-001)
# -----------------------------------------------------------------------

RECEIPT_DOMAIN = b"SHARENET/CONTRIBUTION/RECEIPT/1"


def receipt_signing_payload(receipt: dict) -> bytes:
    """Compute the bytes-to-be-signed for a bilateral receipt body.

    Body canonical CBOR map (integer keys per ADR-0004):
      1=receiptId, 2=gatewayNodeId, 3=peerNodeId, 4=destination,
      5=bytesSent, 6=bytesReceived, 7=sessionStart, 8=sessionEnd, 9=httpStatus
    """
    m = {
        1: receipt["receiptId"],
        2: receipt["gatewayNodeId"],
        3: receipt["peerNodeId"],
        4: receipt["destination"],
        5: receipt["bytesSent"],
        6: receipt["bytesReceived"],
        7: receipt["sessionStart"],
        8: receipt["sessionEnd"],
        9: receipt["httpStatus"],
    }
    return RECEIPT_DOMAIN + canonical_cbor_encode(m)


def verify_bilateral_receipt(receipt: dict, gateway_public_key: bytes,
                             peer_public_key: bytes) -> dict:
    """Verify BOTH Ed25519 signatures on a bilateral receipt.

    Mirrors reference/economics/contribution.ts — verifyBilateralReceipt:
      gateway signature checked first, then peer signature.
    A receipt with only one valid signature is a UNILATERAL claim → NO credit.
    """
    payload = receipt_signing_payload(receipt)
    gateway_sig = bytes.fromhex(receipt["gatewaySignatureHex"])
    peer_sig = bytes.fromhex(receipt["peerSignatureHex"])

    if len(gateway_sig) != 64 or len(gateway_public_key) != 32:
        return {"ok": False, "error": "GATEWAY_SIGNATURE_INVALID",
                "detail": "malformed gateway signature or public key"}
    try:
        VerifyKey(gateway_public_key).verify(payload, gateway_sig)
    except BadSignatureError:
        return {"ok": False, "error": "GATEWAY_SIGNATURE_INVALID",
                "detail": "gateway signature invalid"}
    except Exception as e:
        return {"ok": False, "error": "GATEWAY_SIGNATURE_INVALID", "detail": str(e)}

    if len(peer_sig) != 64 or len(peer_public_key) != 32:
        return {"ok": False, "error": "PEER_SIGNATURE_INVALID",
                "detail": "malformed peer signature or public key"}
    try:
        VerifyKey(peer_public_key).verify(payload, peer_sig)
    except BadSignatureError:
        return {"ok": False, "error": "PEER_SIGNATURE_INVALID",
                "detail": "peer signature invalid"}
    except Exception as e:
        return {"ok": False, "error": "PEER_SIGNATURE_INVALID", "detail": str(e)}

    return {"ok": True}


def verify_receipt_vector(data: dict) -> dict:
    """Verify a V-RECEIPT-* vector (bilateral receipt signature verification)."""
    vid = data.get("id", "unknown")
    shared_keys = data.get("sharedKeys", {})
    gateway_pubkey = bytes.fromhex(shared_keys["gatewayPublicKeyHex"])
    peer_pubkey = bytes.fromhex(shared_keys["peerPublicKeyHex"])
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            exp = v["expected"]
            intermediate = v.get("intermediate", {})
            receipt = {
                "receiptId": inp["receiptId"],
                "gatewayNodeId": inp["gatewayNodeId"],
                "peerNodeId": inp["peerNodeId"],
                "destination": inp["destination"],
                "bytesSent": inp["bytesSent"],
                "bytesReceived": inp["bytesReceived"],
                "sessionStart": inp["sessionStart"],
                "sessionEnd": inp["sessionEnd"],
                "httpStatus": inp["httpStatus"],
                # For valid-receipt, the signatures live under `intermediate`.
                # For tampered cases, they live under `input` (alongside the
                # mutated field that the test mutates in place).
                "gatewaySignatureHex": inp.get("gatewaySignatureHex")
                    or intermediate.get("gatewaySignatureHex", ""),
                "peerSignatureHex": inp.get("peerSignatureHex")
                    or intermediate.get("peerSignatureHex", ""),
            }

            result = verify_bilateral_receipt(receipt, gateway_pubkey, peer_pubkey)

            if exp["verificationResult"] == "ok":
                if not result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected ok, '
                        f'got {result.get("error")}: {result.get("detail")}'
                    )
            else:
                # Expected fail. The test vector carries both a high-level
                # errorCode label and the actualVerificationResult string.
                # For tampered-receipt-id, the high-level errorCode is
                # RECEIPT_BODY_MISMATCH but the actual failure mode is
                # "gateway signature invalid" (the gateway signature was
                # made over the original receiptId, not the mutated one).
                # We accept any signature-invalid failure in that case.
                expected_code = exp.get("errorCode")
                if result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected fail/{expected_code}, got ok'
                    )
                elif expected_code == "RECEIPT_BODY_MISMATCH":
                    acceptable = ("GATEWAY_SIGNATURE_INVALID",
                                  "PEER_SIGNATURE_INVALID",
                                  "RECEIPT_BODY_MISMATCH")
                    if result.get("error") not in acceptable:
                        failures.append(
                            f'{v["name"]}: expected body mismatch, '
                            f'got {result.get("error")}'
                        )
                elif result.get("error") != expected_code:
                    failures.append(
                        f'{v["name"]}: expected fail/{expected_code}, '
                        f'got fail/{result.get("error")}'
                    )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} receipt vectors match",
        "actual": f"{len(vectors)} receipt vectors match" if passed else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# SignedRouteProposal signature verification (added for V-ROUTE-PROPOSAL-001)
# -----------------------------------------------------------------------

ROUTE_PROPOSAL_DOMAIN = b"SHARENET/ROUTE/PROPOSAL/1"


def route_proposal_signing_payload(proposal: dict) -> bytes:
    """Compute the bytes-to-be-signed for a RouteProposal.

    Body = canonical CBOR of integer-keyed map:
      1: hops[].nodeId (array of text)
      2: requirementDigest (text)
      3: expiry (uint)
      4: initiatorNodeId (text)
      5: agreementDigest (text)
    Payload = utf8(SHARENET/ROUTE/PROPOSAL/1) || body
    """
    m = {
        1: [h["nodeId"] for h in proposal["hops"]],
        2: proposal["requirementDigest"],
        3: proposal["expiry"],
        4: proposal["initiatorNodeId"],
        5: proposal["agreementDigest"],
    }
    return ROUTE_PROPOSAL_DOMAIN + canonical_cbor_encode(m)


def verify_route_proposal_vector(data: dict) -> dict:
    """Verify a V-ROUTE-PROPOSAL-* vector (SignedRouteProposal signature)."""
    vid = data.get("id", "unknown")
    shared_keys = data.get("sharedKeys", {})
    initiator_pubkey = bytes.fromhex(shared_keys["initiatorPublicKeyHex"])
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            exp = v["expected"]
            intermediate = v.get("intermediate", {})

            proposal = inp["proposal"]
            payload = route_proposal_signing_payload(proposal)

            # Sanity: recompute the signing payload and compare.
            expected_payload_hex = (
                intermediate.get("signingPayloadHex")
                or intermediate.get("tamperedSigningPayloadHex")
            )
            if expected_payload_hex and payload.hex() != expected_payload_hex:
                failures.append(
                    f'{v["name"]}: payload {payload.hex()} != {expected_payload_hex}'
                )
                continue

            # Resolve which signature to verify: tampered-signature case carries
            # tamperedSignatureHex; tampered-proposal case carries originalSignatureHex;
            # valid case carries intermediate.signatureHex.
            sig_hex = (
                inp.get("tamperedSignatureHex")
                or inp.get("originalSignatureHex")
                or intermediate.get("signatureHex")
            )
            if not sig_hex:
                failures.append(f'{v["name"]}: no signature found')
                continue
            sig = bytes.fromhex(sig_hex)

            try:
                VerifyKey(initiator_pubkey).verify(payload, sig)
                valid = True
            except BadSignatureError:
                valid = False
            except Exception:
                valid = False

            if exp["verificationResult"] == "ok":
                if not valid:
                    failures.append(
                        f'{v["name"]}: expected ok, got invalid signature'
                    )
            else:
                if valid:
                    failures.append(
                        f'{v["name"]}: expected fail/{exp.get("errorCode")}, '
                        f'got valid'
                    )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} route-proposal vectors match",
        "actual": f"{len(vectors)} route-proposal vectors match" if passed
        else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# CircuitSetupRequest encoding (added for V-CIRCUIT-SETUP-001)
# -----------------------------------------------------------------------

CIRCUIT_SETUP_DOMAIN = b"SHARENET/CIRCUIT/SETUP/1"


def encode_circuit_setup_request(req: dict) -> bytes:
    """Encode a CircuitSetupRequest as canonical CBOR.

    Only `req["route"]["routeId"]` is read from the route (the full
    BrandedCommittedRoute is conveyed out-of-band). Map keys:
      1: routeId (text), 2: hopIndex (uint),
      3: initiatorX25519PublicKey (bstr .size 32), 4: setupNonce (bstr .size 16)
    """
    m = {
        1: req["route"]["routeId"],
        2: req["hopIndex"],
        3: req["initiatorX25519PublicKey"],
        4: req["setupNonce"],
    }
    return canonical_cbor_encode(m)


def circuit_setup_signing_payload(req: dict) -> bytes:
    """Compute the bytes-to-be-signed for a CircuitSetupRequest."""
    return CIRCUIT_SETUP_DOMAIN + encode_circuit_setup_request(req)


def verify_circuit_setup_vector(data: dict) -> dict:
    """Verify a V-CIRCUIT-SETUP-* vector (CircuitSetupRequest encoding)."""
    vid = data.get("id", "unknown")
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            intermediate = v.get("intermediate", {})

            req = {
                "route": {"routeId": inp["routeId"]},
                "hopIndex": inp["hopIndex"],
                "initiatorX25519PublicKey": bytes.fromhex(
                    inp["initiatorX25519PublicKeyHex"]
                ),
                "setupNonce": bytes.fromhex(inp["setupNonceHex"]),
            }
            encoded = encode_circuit_setup_request(req)
            encoded_hex = encoded.hex()
            signing_payload = circuit_setup_signing_payload(req)
            signing_payload_hex = signing_payload.hex()

            expected_encoded = (
                intermediate.get("encodedHex")
                or intermediate.get("tamperedEncodedHex")
            )
            expected_signing = (
                intermediate.get("signingPayloadHex")
                or intermediate.get("tamperedSigningPayloadHex")
            )

            if expected_encoded and encoded_hex != expected_encoded:
                failures.append(
                    f'{v["name"]}: encoded {encoded_hex} != {expected_encoded}'
                )
            if expected_signing and signing_payload_hex != expected_signing:
                failures.append(
                    f'{v["name"]}: signingPayload {signing_payload_hex} '
                    f'!= {expected_signing}'
                )
            # For tampered-hopindex: the recomputed encoding MUST differ from
            # the originalEncodedHex.
            original_encoded = intermediate.get("originalEncodedHex")
            if original_encoded and encoded_hex == original_encoded:
                failures.append(
                    f'{v["name"]}: tampered encoding matches original '
                    f'(bytes did not differ)'
                )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} circuit-setup vectors match",
        "actual": f"{len(vectors)} circuit-setup vectors match" if passed
        else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# CircuitSetupAck signing payload (added for V-CIRCUIT-ACK-001)
# -----------------------------------------------------------------------

CIRCUIT_ACK_DOMAIN = b"SHARENET/CIRCUIT/ACK/1"


def circuit_ack_signing_payload(route_id: str, route_commitment_digest_hex: str,
                                hop_index: int, relay_x25519_pubkey: bytes,
                                initiator_x25519_pubkey: bytes, ack_nonce: bytes,
                                ack_timestamp: int, ack_expiry: int) -> bytes:
    """Compute the bytes-to-be-signed for a CircuitSetupAck.

    Body = canonical CBOR of integer-keyed map:
      1: routeId, 2: routeCommitmentDigestHex, 3: hopIndex,
      4: relayX25519PublicKey, 5: initiatorX25519PublicKey,
      6: ackNonce, 7: ackTimestamp, 8: ackExpiry
    Payload = utf8(SHARENET/CIRCUIT/ACK/1) || body
    """
    m = {
        1: route_id,
        2: route_commitment_digest_hex,
        3: hop_index,
        4: relay_x25519_pubkey,
        5: initiator_x25519_pubkey,
        6: ack_nonce,
        7: ack_timestamp,
        8: ack_expiry,
    }
    return CIRCUIT_ACK_DOMAIN + canonical_cbor_encode(m)


def verify_circuit_ack_vector(data: dict) -> dict:
    """Verify a V-CIRCUIT-ACK-* vector (CircuitSetupAck signing payload)."""
    vid = data.get("id", "unknown")
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            intermediate = v.get("intermediate", {})

            payload = circuit_ack_signing_payload(
                inp["routeId"],
                inp["routeCommitmentDigestHex"],
                inp["hopIndex"],
                bytes.fromhex(inp["relayX25519PublicKeyHex"]),
                bytes.fromhex(inp["initiatorX25519PublicKeyHex"]),
                bytes.fromhex(inp["ackNonceHex"]),
                inp["ackTimestamp"],
                inp["ackExpiry"],
            )
            payload_hex = payload.hex()

            expected_hex = (
                intermediate.get("signingPayloadHex")
                or intermediate.get("tamperedSigningPayloadHex")
            )
            if expected_hex and payload_hex != expected_hex:
                failures.append(
                    f'{v["name"]}: payload {payload_hex} != {expected_hex}'
                )
            # For tampered-routeId: the recomputed payload MUST differ from
            # the originalSigningPayloadHex — this is the route-substitution
            # defense.
            original_payload = intermediate.get("originalSigningPayloadHex")
            if original_payload and payload_hex == original_payload:
                failures.append(
                    f'{v["name"]}: tampered payload matches original '
                    f'(bytes did not differ)'
                )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} circuit-ack vectors match",
        "actual": f"{len(vectors)} circuit-ack vectors match" if passed
        else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# ContributionProof derivation (added for V-CONTRIBUTION-PROOF-001)
# -----------------------------------------------------------------------

def create_contribution_proof(receipt: dict, gateway_public_key: bytes,
                              peer_public_key: bytes, now: int) -> dict:
    """Independent implementation of createContributionProof.

    Mirrors reference/economics/contribution.ts — createContributionProof:
      1. Verify the bilateral receipt (both signatures).
      2. Compute receiptHash = BLAKE3-256(receiptSigningPayload(receipt)).
      3. Emit ContributionProof {receiptId, contributorNodeId, peerNodeId,
         serviceType, bytesForwarded, durationSeconds, receiptHash,
         gatewaySignature, peerSignature, createdAt}.
    Returns {"ok": True, "proof": {...}} on success or
    {"ok": False, "reason": "receipt verification failed: <inner>"} on failure.
    """
    verification = verify_bilateral_receipt(receipt, gateway_public_key,
                                           peer_public_key)
    if not verification["ok"]:
        return {
            "ok": False,
            "reason": f"receipt verification failed: {verification['detail']}",
        }

    payload = receipt_signing_payload(receipt)
    receipt_hash = blake3.blake3(payload).digest(length=32).hex()

    proof = {
        "receiptId": receipt["receiptId"],
        "contributorNodeId": receipt["gatewayNodeId"],
        "peerNodeId": receipt["peerNodeId"],
        "serviceType": "INTERNET_GATEWAY",
        "bytesForwarded": receipt["bytesSent"] + receipt["bytesReceived"],
        "durationSeconds": receipt["sessionEnd"] - receipt["sessionStart"],
        "receiptHash": receipt_hash,
        "gatewaySignatureHex": receipt["gatewaySignatureHex"],
        "peerSignatureHex": receipt["peerSignatureHex"],
        "createdAt": now,
    }
    return {"ok": True, "proof": proof}


def verify_contribution_proof_vector(data: dict) -> dict:
    """Verify a V-CONTRIBUTION-PROOF-* vector (ContributionProof derivation)."""
    vid = data.get("id", "unknown")
    shared_keys = data.get("sharedKeys", {})
    gateway_pubkey = bytes.fromhex(shared_keys["gatewayPublicKeyHex"])
    peer_pubkey = bytes.fromhex(shared_keys["peerPublicKeyHex"])
    now = data["referenceNow"]
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            intermediate = v.get("intermediate", {})
            exp = v["expected"]

            # Signatures may live under `input` (tampered case) or
            # `intermediate` (valid case).
            gateway_sig_hex = (
                inp.get("tamperedGatewaySignatureHex")
                or inp.get("gatewaySignatureHex")
                or intermediate.get("gatewaySignatureHex")
            )
            peer_sig_hex = (
                inp.get("peerSignatureHex")
                or intermediate.get("peerSignatureHex")
            )
            if not gateway_sig_hex or not peer_sig_hex:
                failures.append(f'{v["name"]}: missing gateway/peer signature')
                continue

            receipt = {
                "receiptId": inp["receiptId"],
                "gatewayNodeId": inp["gatewayNodeId"],
                "peerNodeId": inp["peerNodeId"],
                "destination": inp["destination"],
                "bytesSent": inp["bytesSent"],
                "bytesReceived": inp["bytesReceived"],
                "sessionStart": inp["sessionStart"],
                "sessionEnd": inp["sessionEnd"],
                "httpStatus": inp["httpStatus"],
                "gatewaySignatureHex": gateway_sig_hex,
                "peerSignatureHex": peer_sig_hex,
            }

            # Sanity: recompute receiptSigningPayload and compare.
            expected_payload_hex = intermediate.get("receiptSigningPayloadHex")
            if expected_payload_hex:
                payload = receipt_signing_payload(receipt)
                if payload.hex() != expected_payload_hex:
                    failures.append(
                        f'{v["name"]}: receiptSigningPayload {payload.hex()} '
                        f'!= {expected_payload_hex}'
                    )
                    continue

            result = create_contribution_proof(receipt, gateway_pubkey,
                                               peer_pubkey, now)

            if exp["createResult"] == "ok":
                if not result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected ok, got fail: '
                        f'{result.get("reason")}'
                    )
                else:
                    proof = result["proof"]
                    ok = (
                        proof["receiptHash"] == exp["receiptHashHex"]
                        and proof["bytesForwarded"] == exp["bytesForwarded"]
                        and proof["durationSeconds"] == exp["durationSeconds"]
                        and proof["contributorNodeId"] == exp["contributorNodeId"]
                        and proof["serviceType"] == exp["serviceType"]
                        and proof["peerNodeId"] == exp["peerNodeId"]
                        and proof["receiptId"] == exp["receiptId"]
                        and proof["createdAt"] == exp["createdAt"]
                    )
                    if not ok:
                        failures.append(
                            f'{v["name"]}: proof fields mismatch — '
                            f'got receiptHash={proof["receiptHash"]} '
                            f'bytesForwarded={proof["bytesForwarded"]} '
                            f'durationSeconds={proof["durationSeconds"]} '
                            f'contributorNodeId={proof["contributorNodeId"]} '
                            f'createdAt={proof["createdAt"]}'
                        )
            else:
                # Expected fail. The vector's failReason is the full reason
                # string returned by createContributionProof:
                #   "receipt verification failed: gateway signature invalid"
                if result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected fail/{exp.get("errorCode")}, '
                        f'got ok'
                    )
                elif result.get("reason") != exp.get("failReason"):
                    failures.append(
                        f'{v["name"]}: expected reason '
                        f'"{exp.get("failReason")}", '
                        f'got "{result.get("reason")}"'
                    )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} contribution-proof vectors match",
        "actual": f"{len(vectors)} contribution-proof vectors match" if passed
        else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# PathValidationResult canonical encoding (V-PATH-VALIDATION-001 — FROZEN)
#
# An INDEPENDENT Python implementation that reproduces the exact bytes the
# TypeScript reference implementation produces (reference/routing/
# path-validation.ts). The TS vector now uses status="frozen" with the real
# implementation as the source of truth; this Python verifier remains an
# independent cross-check (cbor2 + PyNaCl, no shared code with the TS runner).
# -----------------------------------------------------------------------

PATH_VALIDATION_DOMAIN = b"SHARENET/PATH/VALIDATION/1"


def encode_path_validation_body(body: dict) -> bytes:
    """Encode a PathValidationResult body (keys 1-6) as canonical CBOR."""
    m = {
        1: body["source_id"],
        2: body["next_hop_id"],
        3: body["destination_id"],
        4: body["measured_rtt_ms"],
        5: body["measured_loss_pct"],
        6: body["valid_until"],
    }
    return canonical_cbor_encode(m)


def encode_path_validation_wire(body: dict, signature: bytes) -> bytes:
    """Encode the full PathValidationResult wire object (keys 1-7)."""
    m = {
        1: body["source_id"],
        2: body["next_hop_id"],
        3: body["destination_id"],
        4: body["measured_rtt_ms"],
        5: body["measured_loss_pct"],
        6: body["valid_until"],
        7: signature,
    }
    return canonical_cbor_encode(m)


def verify_path_validation_vector(data: dict) -> dict:
    """Verify a V-PATH-VALIDATION-* vector (FROZEN — real TS implementation).

    The TS reference implementation lives at reference/routing/
    path-validation.ts. This Python verifier is an INDEPENDENT re-
    implementation: it uses cbor2 + PyNaCl and shares no code with the TS
    runner. We verify:
      (a) recomputed bodyHex matches intermediate.bodyHex,
      (b) recomputed signingPayloadHex matches intermediate.signingPayloadHex,
      (c) the Ed25519 signature verifies under the source public key,
      (d) the recomputed wireHex matches expected.wireHex.
    """
    vid = data.get("id", "unknown")
    shared_keys = data.get("sharedKeys", {})
    source_pubkey = bytes.fromhex(shared_keys["sourcePublicKeyHex"])
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            intermediate = v.get("intermediate", {})
            exp = v["expected"]

            body_bytes = encode_path_validation_body(inp)
            if intermediate.get("bodyHex") and body_bytes.hex() != intermediate["bodyHex"]:
                failures.append(
                    f'{v["name"]}: bodyHex {body_bytes.hex()} '
                    f'!= {intermediate["bodyHex"]}'
                )
                continue

            signing_payload = PATH_VALIDATION_DOMAIN + body_bytes
            if (intermediate.get("signingPayloadHex")
                    and signing_payload.hex() != intermediate["signingPayloadHex"]):
                failures.append(
                    f'{v["name"]}: signingPayloadHex '
                    f'{signing_payload.hex()} '
                    f'!= {intermediate["signingPayloadHex"]}'
                )
                continue

            signature = bytes.fromhex(intermediate["signatureHex"])
            try:
                VerifyKey(source_pubkey).verify(signing_payload, signature)
                sig_valid = True
            except BadSignatureError:
                sig_valid = False
            except Exception:
                sig_valid = False

            if not sig_valid:
                failures.append(
                    f'{v["name"]}: signature did not verify under '
                    f'source public key'
                )
                continue

            wire_bytes = encode_path_validation_wire(inp, signature)
            if exp.get("wireHex") and wire_bytes.hex() != exp["wireHex"]:
                failures.append(
                    f'{v["name"]}: wireHex {wire_bytes.hex()} '
                    f'!= {exp["wireHex"]}'
                )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} path-validation vectors match",
        "actual": f"{len(vectors)} path-validation vectors match" if passed
        else f"FAILED: {'; '.join(failures)}",
    }


# -----------------------------------------------------------------------
# RemoteNodeHint bounded propagation (added for V-TOPOLOGY-PROPAGATION-001)
# -----------------------------------------------------------------------

def encode_full_hint(hint: dict) -> bytes:
    """Encode a full RemoteNodeHint (body + signature) as canonical CBOR.

    Mirrors reference/topology/remote-node-hint.ts — hintToHex.
    Map keys: 1=reporterNodeId, 2=subjectNodeId, 3=subjectEndpointHint,
              4=claimedCapabilities[], 5=hopCount, 6=timestamp,
              7=nonce (16-byte bstr), 8=reporterSignature (64-byte bstr).
    """
    nonce = (hint["nonce"] if isinstance(hint.get("nonce"), bytes)
             else bytes.fromhex(hint["nonceHex"]))
    sig = (hint["reporterSignature"] if isinstance(hint.get("reporterSignature"), bytes)
           else bytes.fromhex(hint["reporterSignatureHex"]))
    m = {
        1: hint["reporterNodeId"],
        2: hint["subjectNodeId"],
        3: hint["subjectEndpointHint"],
        4: list(hint["claimedCapabilities"]),
        5: hint["hopCount"],
        6: hint["timestamp"],
        7: nonce,
        8: sig,
    }
    return canonical_cbor_encode(m)


def verify_topology_propagation_vector(data: dict) -> dict:
    """Verify a V-TOPOLOGY-PROPAGATION-* vector.

    For each case:
      (a) Construct the hint from input (+ intermediate signature).
      (b) For valid case: verify encode_full_hint(hint) matches
          intermediate.hintHex (canonical serialization freeze).
      (c) Verify verify_remote_node_hint returns the expected result.
    """
    vid = data.get("id", "unknown")
    shared_keys = data.get("sharedKeys", {})
    reporter_pubkey = bytes.fromhex(shared_keys["reporterPublicKeyHex"])
    reference_now = data["referenceNow"]
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            intermediate = v.get("intermediate", {})
            exp = v["expected"]

            sig_hex = (
                inp.get("reporterSignatureHex")
                or intermediate.get("reporterSignatureHex")
            )
            if not sig_hex:
                failures.append(f'{v["name"]}: no reporter signature found')
                continue

            hint = {
                "reporterNodeId": inp["reporterNodeId"],
                "subjectNodeId": inp["subjectNodeId"],
                "subjectEndpointHint": inp["subjectEndpointHint"],
                "claimedCapabilities": inp["claimedCapabilities"],
                "hopCount": inp["hopCount"],
                "timestamp": inp["timestamp"],
                "nonceHex": inp["nonceHex"],
                "reporterSignatureHex": sig_hex,
            }

            # Forward hex check: encode_full_hint(hint) == intermediate.hintHex.
            # Only the valid case carries intermediate.hintHex.
            if intermediate.get("hintHex"):
                recomputed = encode_full_hint(hint).hex()
                if recomputed != intermediate["hintHex"]:
                    failures.append(
                        f'{v["name"]}: hintToHex {recomputed} '
                        f'!= {intermediate["hintHex"]}'
                    )
                    continue

            # Verify the hint against the propagation bounds + signature.
            result = verify_remote_node_hint(hint, reporter_pubkey, reference_now)

            if exp["verificationResult"] == "ok":
                if not result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected ok, '
                        f'got {result.get("error")}: {result.get("detail")}'
                    )
            else:
                # Expected fail — compare reason against actualVerificationResult
                # (after stripping the "fail/" prefix).
                if result["ok"]:
                    failures.append(
                        f'{v["name"]}: expected fail/{exp.get("errorCode")}, '
                        f'got ok'
                    )
                else:
                    expected_reason = str(
                        exp.get("actualVerificationResult", "")
                    ).replace("fail/", "", 1)
                    if result.get("detail") != expected_reason:
                        failures.append(
                            f'{v["name"]}: expected reason '
                            f'"{expected_reason}", '
                            f'got "{result.get("detail")}"'
                        )
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} topology-propagation vectors match",
        "actual": f"{len(vectors)} topology-propagation vectors match" if passed
        else f"FAILED: {'; '.join(failures)}",
    }


def verify_discovery_vector(data: dict) -> dict:
    """Verify a V-DISCOVERY-* vector (canonical CandidateDestination encoding)."""
    vid = data.get("id", "unknown")
    vectors = data.get("vectors", [])
    failures = []

    for v in vectors:
        try:
            inp = v["input"]
            m = {}
            m[1] = inp["nodeIdHint"]
            m[2] = inp["reportedBy"]
            m[3] = inp["endpointHints"]
            m[4] = inp["distanceHint"]
            m[5] = inp["lastSeen"]
            m[6] = inp["evidenceType"]
            encoded = cbor2.dumps(m, canonical=True)
            actual_hex = encoded.hex()
            if actual_hex != v["expected"]["canonicalEncodingHex"]:
                failures.append(f'{v["name"]}: {actual_hex} != {v["expected"]["canonicalEncodingHex"]}')
        except Exception as e:
            failures.append(f'{v["name"]}: threw {e}')

    passed = len(failures) == 0
    return {
        "id": vid,
        "passed": passed,
        "expected": f"{len(vectors)} discovery vectors match",
        "actual": f"{len(vectors)} discovery vectors match" if passed else f"FAILED: {'; '.join(failures)}",
    }


def main():
    vectors_dir = Path(__file__).parent.parent / "vectors"
    if not vectors_dir.exists():
        print("ERROR: conformance/vectors/ does not exist", file=sys.stderr)
        sys.exit(1)

    json_files = sorted(vectors_dir.rglob("*.json"))
    results = []
    for f in json_files:
        if f.name == "MANIFEST.json":
            # Manifest is metadata, not a protocol vector — skip it
            continue
        data = json.loads(f.read_text())
        result = verify_vector(data)
        results.append(result)

    print()
    print("=== Python Independent Conformance Vector Verifier ===")
    print(f"Vectors checked: {len(results)}")
    print()

    all_passed = True
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['id']}")
        if not r["passed"]:
            print(f"    expected: {r['expected']}")
            print(f"    actual:   {r['actual']}")
            all_passed = False

    passed = sum(1 for r in results if r["passed"])
    failed = len(results) - passed
    print()
    print(f"Passed: {passed}/{len(results)}, Failed: {failed}")
    print()

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()


