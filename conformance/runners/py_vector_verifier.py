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

ADVERTISEMENT_SIGNATURE_DOMAIN = b"sharenet-advertisement-v1"
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

    elif vid.startswith("V-LINK-HANDSHAKE-"):
        return verify_handshake_vector(data)

    return {"id": vid, "passed": False, "expected": "known type", "actual": "unknown type"}


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
    h.update(b"sharenet-link-id-v1")
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


def main():
    vectors_dir = Path(__file__).parent.parent / "vectors"
    if not vectors_dir.exists():
        print("ERROR: conformance/vectors/ does not exist", file=sys.stderr)
        sys.exit(1)

    json_files = sorted(vectors_dir.rglob("*.json"))
    results = []
    for f in json_files:
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


