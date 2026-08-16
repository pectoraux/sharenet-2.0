# ADR 0006 — Sequence Floor Persistence

Date: 2024-Q3 (first deliverable)
Decision Maker: ShareNet 2.0 build orchestrator

## Status

**Accepted.** This decision fixes the design of the persistent
sequence floor store and the acceptance algorithm that consumes it.
The normative invariant is recorded in `spec/14-security.md` §3;
this ADR records the implementation strategy.

## Context

`spec/14-security.md` §3 ("Persistent Sequence Floors") mandates:

> Expiration of a prior object does NOT lower the sequence floor.

This invariant is shared across four distinct object types:

- NodeAdvertisement: keyed on `(node_id, sequence)` per
  `spec/03-node-advertisements.md` §5 step 7.
- RemoteNodeHint: keyed on `(reporter_id, subject_id, sequence)` per
  `spec/06-topology.md` §2.2 step 6.
- ContributionProof: keyed on `(issuer_id, proof_nonce)` per
  `spec/11-contribution.md` §3.1.
- Circuit frames: keyed on `(circuit_id, frame_sequence)` per
  `spec/08-circuits.md` §4.5.

The replay attack that motivates the invariant is documented in
`spec/14-security.md` §3: an attacker captures an old advertisement,
waits for it to expire, and replays it with a fresh `timestamp`/
`expiry` but the same `sequence`. Without the persistent floor, the
receiver would accept the replay as a "new" advertisement.

The store must prevent sequence wraparound (a 64-bit counter is
sufficient in practice), be queryable by `(node_id, sequence)` for
the acceptance algorithm, and be durable across process restarts
(per `spec/14-security.md` §3: "Sequence floors are persisted to
disk and survive process restarts").

## Decision

Persist `(node_id, current_max_sequence, last_advanced_at,
last_nonce)` in a SQLite table named `SequenceFloor`. The table is
created by the migration in Task 7. The columns are:

```
CREATE TABLE SequenceFloor (
  node_id              TEXT NOT NULL,
  current_max_sequence INTEGER NOT NULL,
  last_advanced_at    INTEGER NOT NULL,  -- Unix seconds
  last_nonce           BLOB NOT NULL,     -- 16 bytes
  PRIMARY KEY (node_id)
);
CREATE INDEX idx_sequencefloor_advanced_at
  ON SequenceFloor(last_advanced_at);
```

(For hint floors the primary key is `(reporter_id, subject_id)`;
for circuit frames it is `(circuit_id)`. Each domain has its own
table or a discriminator column.)

The advertisement acceptance algorithm runs the sequence check
**before** the expiry check, in this order (continuing the 9-step
algorithm in `spec/03-node-advertisements.md` §5):

1. Steps 1-6 of the spec algorithm (canonical encoding, field
   presence, identity binding, signature, timestamp, expiry).
2. **Sequence floor check.** Look up `current_max_sequence` for
   `node_id`.
   - `< current_max_sequence`: REJECT as stale (audit at INFO).
   - `== current_max_sequence`: REJECT as duplicate (audit at WARN —
     possible replay).
   - `> current_max_sequence`: accept and proceed.
3. **Expiry check (re-run after sequence check).** Reject if
   `now > expiry` or `expiry - timestamp > MAX_ADVERTISEMENT_TTL`.
   Even if this rejects, the floor is NOT updated.
4. **Nonce uniqueness check.** Reject if `(node_id, nonce)` was seen
   within the past `MAX_ADVERTISEMENT_TTL`.
5. **Revocation list check.** Reject if `node_id` is revoked.
6. **Floor update.** Atomically update `current_max_sequence`,
   `last_advanced_at`, `last_nonce`.

The update is wrapped in a SQLite `BEGIN IMMEDIATE` transaction.
The atomicity guarantees that two concurrent advertisements from the
same node cannot both pass step 2 and both update the floor.

A persistent tombstone retains the floor even after the
advertisement that established it has expired: the row is not deleted
on expiry. A garbage collector MAY delete `SequenceFloor` rows whose
`last_advanced_at` is older than `MAX_RETENTION` (default 90 days
per `spec/14-security.md` §3), but only after the row's TTL exceeds
every object's `MAX_*_TTL`.

Wraparound protection: the acceptance algorithm checks that
`advertisement.sequence <= current_max_sequence +
MAX_SEQUENCE_INCREMENT` (default `2^32`); a larger jump is a
protocol violation.

## Consequences

- **Storage grows linearly with distinct node count.** Each unique
  `node_id` that has ever issued an advertisement consumes one row
  in `SequenceFloor` (~80 bytes). For a network of 10^6 nodes this
  is ~80 MiB — acceptable.
- **No replay window opens on expiry.** The fundamental invariant is
  preserved: an attacker who captures an advertisement and waits for
  it to expire cannot replay it, because the floor retains the
  high-water mark.
- **The floor must be persisted synchronously.** A fsync is required
  before returning "accepted" to the caller; otherwise a crash
  between acceptance and persistence opens a replay window of one
  sequence number. SQLite's default WAL mode is sufficient;
  `PRAGMA synchronous = FULL` is set on the connection.
- **Concurrent writes from the same node are serialized.** A node
  that issues two advertisements in parallel must serialize them at
  the issuing side; the floor update will reject the second one.
- **Cross-process state.** In the first deliverable, the store is a
  single SQLite file. A multi-process deployment would need a shared
  store (Postgres in production per ADR 0001).
- **Wraparound is a non-issue for practical workloads.** A node
  issuing one advertisement per second for 100 years reaches 2^32,
  well below the 2^64 column maximum.
- **Audit logging of stale/duplicate rejections is mandatory.** The
  audit log records every sequence-floor rejection; repeated
  rejections from the same `node_id` signal attack or
  misconfiguration.

## Alternatives Considered

1. **TTL-based cache that purges the floor on expiry.** Rejected —
   this is precisely the attack the invariant forbids. An attacker
   waits for expiry, the cache purges the floor, and the replay is
   accepted as new.
2. **Monotonic clock in memory only (no persistence).** Rejected —
   lost on restart. A node that crashes and restarts loses its
   floor; an attacker who can force a restart opens a replay window.
3. **Persistent floor stored in a separate file per node.** Rejected
   — file system operations are slower than a single indexed table;
   SQLite provides the durability guarantee for free.
4. **Floor stored as a hash chain in the audit log.** Considered —
   elegant but querying the current floor requires scanning the log
   (O(n) in log size). An indexed table is O(1).
5. **A central sequence service.** Rejected — adds a network
   round-trip and a single point of failure.

## References

- `spec/14-security.md` §3 — persistent sequence floors (the
  normative invariant).
- `spec/03-node-advertisements.md` §5 step 7 — monotonic sequence
  check for advertisements.
- `spec/06-topology.md` §2.2 step 6 — sequence floor for hints.
- `spec/08-circuits.md` §4.5 — circuit frame sequence floor.
- `spec/11-contribution.md` §3.1 — contribution proof nonce floor.
- `spec/14-security.md` §5 — audit log hash chain.
- `spec/17-conformance.md` §2 test 5 —
  `advertisement_rejected_on_seq_floor_violation`.
- `spec/17-conformance.md` §3.8 — `expiration-resets-floor`
  forbidden pipeline guard.
- ADR 0001 — sandbox SQLite substitution.
- ADR 0010 — architecture regression tests.
- Michael Nygard ADR template — structural source.
