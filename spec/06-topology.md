# ShareNet 2.0 — Topology and RemoteNodeHint

**Status:** Normative. This document defines the `RemoteNodeHint` type,
its provenance, its propagation bounds, and the architectural guard
that prevents hint-to-record promotion.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. What Topology Is — and Is Not

In ShareNet, "topology" is the **set of claims** that nodes have made
about each other. It is not a routing table. It is not a graph that
yields routes by shortest-path. It is a provenance-tagged evidence
store.

A topology entry MAY be:

- `AUTHENTICATED`: the recording node performed the Link handshake of
  `spec/04-links.md` §3 with the subject node.
- `OBSERVED`: the recording node saw the subject's advertisement (but
  did not complete handshake).
- `REPORTED`: the recording node received a `RemoteNodeHint` from
  another node.

These three evidence classes MUST NOT be conflated. See
`spec/00-thesis.md` §4.6.

## 2. RemoteNodeHint Type

A `RemoteNodeHint` is the canonical carrier of a third-party claim:

```
RemoteNodeHint = {
  hint_version:    1,
  reporter_id:     text,         ; NodeId of the node making the claim
  reporter_pubkey: bstr .size 32,; Ed25519 public key of the reporter
  subject_id:      text,         ; claimed NodeId of the subject node
  subject_pubkey:  bstr .size 32,; claimed Ed25519 public key of the subject
  claim: {
    kind:    "exists" | "has_capability" | "has_endpoint",
    payload: any,                ; depends on kind
  },
  freshness:      uint,         ; Unix seconds at which reporter observed
  sequence:       uint,         ; monotonic per (reporter, subject) pair
  nonce:          bstr .size 16,
  signature:      bstr .size 64, ; Ed25519 by reporter
}
```

### 2.1 Signature Domain

```
signing_input = "sharenet-remote-node-hint-v1"
              || canonical_cbor(hint_without_signature_value)
digest        = BLAKE2b-256(signing_input)
signature     = Ed25519Sign(reporter_private_key, digest)
```

The domain-separation string `"sharenet-remote-node-hint-v1"` is
exactly 28 bytes of UTF-8, no NUL terminator, and MUST NOT be reused
for any other signature type.

### 2.2 Verification

A verifier MUST check:

1. Canonical encoding (re-encode, byte-equal).
2. `reporter_id == canonicalNodeIdText(reporter_pubkey)`.
3. `subject_id == canonicalNodeIdText(subject_pubkey)` (when
   `subject_pubkey` is provided; otherwise the hint is treated as
   weaker and MAY be discarded).
4. The signature verifies under `reporter_pubkey`.
5. Freshness: `|now - freshness| <= HINT_FRESHNESS_WINDOW`, where
   `HINT_FRESHNESS_WINDOW = 3600` seconds.
6. Sequence: monotonic per `(reporter_id, subject_id)` pair. Rejected
   if `<=` the prior high-water mark for that pair. **Expiry of a
   prior hint does NOT reset the sequence floor** (see
   `spec/14-security.md` §3).
7. Nonce uniqueness: the `(reporter_id, nonce)` pair MUST NOT have been
   seen within `HINT_FRESHNESS_WINDOW`.
8. Reporter is not on the revocation list.

A hint that fails any check MUST be discarded. A hint that passes is
stored as `REPORTED` evidence about the subject. It MUST NOT be stored
as `AUTHENTICATED` evidence, and it MUST NOT be used as the basis for
routing or circuit construction.

## 3. Architectural Guard: Hint-to-Record Promotion Is Forbidden

The pipeline

```
RemoteNodeHint  ──>  AuthenticatedNodeRecord
```

MUST be impossible. There MUST be no function, method, or operator in
the reference implementation that accepts a `RemoteNodeHint` and
returns an `AuthenticatedNodeRecord` without first completing the Link
handshake of `spec/04-links.md` §3.

This guard is **executable** and is enforced by the conformance suite
(`spec/17-conformance.md` §3.2). A pull request that adds such a
promotion function MUST fail the build.

The only legitimate promotion path is:

```
RemoteNodeHint ──> CandidateDestination ──> Link handshake ──> AuthenticatedNodeRecord
                  (see spec/05 §2)         (see spec/04 §3)
```

## 4. Bounded Propagation

A node that has received a `RemoteNodeHint` from peer R about subject
S MAY propagate the hint to a third peer T, subject to:

1. **Hop bound:** The hint MUST carry an `originator_id` field set to
   the original reporter. The hint MUST NOT be propagated more than
   `MAX_HINT_HOPS = 3` times. Each propagation MUST increment a
   `propagation_count` field; receiving nodes MUST discard hints with
   `propagation_count >= MAX_HINT_HOPS`.
2. **Freshness decay:** Each propagation MUST reduce the
   `freshness_window` by `FRESHNESS_DECAY = 600` seconds; receivers
   MUST reject hints whose remaining window is below zero.
3. **Provenance preservation:** The `reporter_id` and `signature`
   fields MUST NOT be modified by propagating intermediaries. A
   propagating intermediary MAY add its own signature over the same
   body in an `intermediary_signatures` array, but the original
   `reporter_id` and `signature` MUST remain unchanged.

## 5. Replay Protection

Because hints carry a `(reporter_id, subject_id, sequence)` triple,
replay protection is enforced by the sequence floor (see §2.2 step 6
and `spec/14-security.md` §3). A replayed hint is one whose sequence
is `<=` the receiver's recorded high-water mark for that pair. Such
hints MUST be discarded without further processing.

Replaying a hint with a fresh `nonce` does NOT bypass the sequence
floor. The sequence floor is keyed on `(reporter_id, subject_id)`, not
on `(reporter_id, nonce)`.

## 6. Storage and Indexing

Topology records are stored as evidence-typed entries in the topology
store. The store MUST be queryable by:

- `subject_id` → list of `(reporter_id, evidence_type, sequence,
  freshness)` tuples.
- `reporter_id` → list of hints signed by that reporter.
- `evidence_type` → all records of a given evidence class.

Records that fail the freshness check MUST be marked expired but
retained for `HINT_FRESHNESS_WINDOW` seconds so that replay detection
continues to function. After retention, records MAY be garbage
collected.

## 7. Invariants

1. No `RemoteNodeHint` is ever `AUTHENTICATED` evidence about the
   subject. At most it is `REPORTED` evidence authenticated **about
   the reporter**.
2. Hints do not propagate indefinitely.
3. Hints cannot substitute for a Link handshake.
4. Hints cannot be replayed past a sequence floor.
5. Hints cannot bypass the revocation list.

## 8. Cross-References

- Evidence types: `spec/00-thesis.md` §4.6.
- Discovery's use of referrals: `spec/05-discovery.md` §3.2.
- Routing pipeline that requires `AUTHENTICATED` peers:
  `spec/07-routing.md` §3.
- Sequence floor: `spec/14-security.md` §3.
- Conformance guard that prohibits promotion: `spec/17-conformance.md`
  §3.2.
