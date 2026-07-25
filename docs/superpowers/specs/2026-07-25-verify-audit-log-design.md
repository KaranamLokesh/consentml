# ConsentML v0 Week-7 Design: `verify_audit_log()`

**Status:** approved design, ready for implementation planning
**Date:** 2026-07-25

## Problem

The README promises a "tamper-evident audit trail." Weeks 5–6 built the trail —
every `training_run` and `revocation` event is appended to a hash-chained
`audit_log` — but nothing verifies it. The tamper-evidence is currently
asserted, not demonstrated. Anyone can edit the SQLite file and no code in the
package will notice.

Worse, the chain only covers the `audit_log` table's own rows. The attack that
matters most for a consent-and-deletion platform is not editing the log — it is
deleting a `subject_index` row so a subject no longer appears to have been in a
training run. Today that attack leaves the hash chain perfectly intact.

## Goal

Ship `verify_audit_log()` plus a `consentml verify` CLI subcommand that detects
both log tampering and silent divergence between the log and the live tables.

## Non-goals

- **Verification records no audit event.** It is strictly read-only. Recording
  "I verified myself" would grow the log unboundedly on every CI run, would
  carry no more trust than the log containing it, and would prevent verifying a
  read-only copy of a production database.
- **Revocation entries get no cross-check.** Their `n_affected_runs` was
  point-in-time and legitimately differs once later runs are recorded. Only the
  hash and link checks apply to them. This is a deliberate limitation, not an
  oversight.
- **No repair.** Verification reports; it never mutates.

## API

New module `src/consentml/verify.py`, mirroring the shape of `revoke.py`.

```python
@dataclass
class VerificationFinding:
    entry_id: int | None   # audit_log row id; None for findings with no log entry
    code: str              # machine-readable, see table below
    detail: str            # human-readable explanation

@dataclass
class VerificationReport:
    ok: bool               # True iff findings == []
    n_entries: int         # audit_log rows examined
    findings: list[VerificationFinding]
    generated_at: str      # UTC ISO-8601
    def to_dict(self) -> dict
```

```python
def verify_audit_log(*, db_path=None) -> VerificationReport
```

## Checks

### 1. Per-entry hash integrity

Recompute `sha256(prev_hash + timestamp + event_type + payload)` from each row's
**own stored fields** and compare to its stored `entry_hash`.

### 2. Chain linkage

The first entry's `prev_hash` must equal `GENESIS_HASH`. Each subsequent
`prev_hash` must equal the previous row's **stored** `entry_hash`.

Comparing against the previous *stored* hash rather than a running recomputed
hash is what prevents cascading findings. A single edited row yields exactly two
findings — a bad hash at entry *k* and a broken link at entry *k+1* — instead of
marking the entire tail invalid.

### 3. Referential cross-check

For each `training_run` audit entry, parse the payload and compare against the
live tables. Separately, detect training runs that were never logged at all.

| Code | Trigger |
|---|---|
| `bad_genesis` | First entry's `prev_hash` is not `GENESIS_HASH` |
| `entry_hash_mismatch` | Recomputed hash differs from stored `entry_hash` |
| `broken_link` | `prev_hash` differs from previous row's stored `entry_hash` |
| `malformed_payload` | Payload is not valid JSON, or lacks expected keys |
| `missing_run` | Payload `run_id` has no row in `training_runs` |
| `subject_count_mismatch` | `COUNT(*)` of `subject_index` for the run ≠ payload `n_subjects` |
| `run_modified` | `training_runs.model_hash` ≠ payload `model_hash` |
| `unlogged_run` | A `training_runs` row has no corresponding audit entry (`entry_id` is `None`) |

`subject_count_mismatch` is the check that closes the deleted-subject attack.
`unlogged_run` is its dual: a model trained without any audit record at all.

`malformed_payload` must be handled explicitly — a tampered payload can fail
`json.loads`, and an unhandled exception during verification would be a poor
failure mode for a tool whose entire job is to survive hostile input.

### Store additions

Two small query methods on `LineageStore`:

- `run_by_id(run_id) -> dict | None`
- `subject_count_for_run(run_id) -> int`
- `all_run_ids() -> set[str]` — for the `unlogged_run` check, which compares
  this set against the run ids named in `training_run` audit payloads

## CLI

```
consentml verify [--db PATH] [--json]
```

Exit **0** when clean, exit **1** when any finding exists, so it can gate CI.
This requires `main()` to return the subcommand's exit code rather than the
current hardcoded `return 0`; the existing `revoke` path keeps returning 0.

Human-readable output on success:

```
Audit log OK: 12 entries, chain intact.
```

On failure, one line per finding with entry id, code, and detail.

## Edge cases

- **Empty audit log** → `ok=True, n_entries=0`. Vacuously intact.
- **Fresh database** (schema created, nothing recorded) → same as above.
- A run recorded with zero subjects is legal and must not trip
  `subject_count_mismatch`.

## Testing

Target ~14 tests, holding the existing 100% coverage bar:

- clean log verifies OK; empty DB verifies OK
- tampered payload → `entry_hash_mismatch`
- tampered `prev_hash` → `broken_link`
- altered first `prev_hash` → `bad_genesis`
- non-JSON payload → `malformed_payload` (no exception escapes)
- deleted `subject_index` row → `subject_count_mismatch`
- deleted `training_runs` row → `missing_run`
- edited `model_hash` → `run_modified`
- directly-inserted run → `unlogged_run`
- **one edit yields exactly two findings** — the no-cascade guarantee
- `to_dict()` round-trips through JSON
- CLI: exit 0 clean, exit 1 tampered, `--json` output shape

Tests tamper by opening the SQLite file directly with `sqlite3` and issuing
`UPDATE`/`DELETE`, which is exactly the threat model.

## Forward compatibility with Week 8

Week 8 will re-shape `subject_index` for storage. Measured at 200k subjects, the
current schema costs **38.7 MB per training run** with no deduplication — the
same population retrained weekly stores the same hashes again every run,
extrapolating to **~10.1 GB for 1M subjects × 52 runs**. Interning subjects into
their own table with `INTEGER` foreign keys and 16-byte `BLOB` digests cuts the
marginal cost per run **7.4x**.

That migration must rewrite `subject_index` while proving it did not alter
recorded history — which is precisely why `verify_audit_log()` is built first.
The verifier is the evidence that the migration was faithful.

Coupling is low by design: only `subject_count_for_run` touches the columns that
change, so Week 8 rewrites one query and a few fixtures, not the verification
logic.
