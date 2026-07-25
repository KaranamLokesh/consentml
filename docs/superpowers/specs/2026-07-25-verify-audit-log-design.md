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
def verify_audit_log(*, db_path=None, expected_head=None) -> VerificationReport
```

`VerificationReport` also carries `head_hash: str` — the last entry's hash, or
`GENESIS_HASH` for an empty log. See the anchoring limitation below.

## Checks

### 1. Per-entry hash integrity

Recompute `sha256(prev_hash + timestamp + event_type + payload)` from each row's
**own stored fields** and compare to its stored `entry_hash`.

### 2. Chain linkage

The first entry's `prev_hash` must equal `GENESIS_HASH`. Each subsequent
`prev_hash` must equal the previous row's **stored** `entry_hash`.

Comparing against the previous *stored* hash rather than a running recomputed
hash is what prevents cascading findings. Working the two cases through:

- A naive tamperer edits a payload and leaves `entry_hash` alone → **one**
  `entry_hash_mismatch` at that entry. Entry *k+1*'s `prev_hash` still matches
  the unchanged stored hash, so no link breaks.
- A sophisticated tamperer edits the payload *and* recomputes `entry_hash` →
  that entry passes its own hash check, but entry *k+1*'s `prev_hash` no longer
  matches → **one** `broken_link` at *k+1*.

Either way a single edit yields a single finding, never a corrupted tail.

## Limitation: the chain needs an external anchor

A hash chain detects *partial* tampering. It cannot detect an attacker who
rewrites the log from genesis and recomputes every hash — that forgery verifies
clean, as does deleting the log and starting fresh. This is inherent to the
construction, not a gap in the implementation, and the README must not
overclaim past it.

The mitigation is to anchor the head hash outside the database. The report
therefore exposes `head_hash`, and `verify_audit_log(expected_head=...)`
compares against a previously anchored value, reporting `head_mismatch` when
they diverge. Operators record `head_hash` in CI logs or a separate system;
ConsentML deliberately does not build the anchor store itself.

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
| `run_modified` | `training_runs.model_hash` or `n_subjects` ≠ the logged value |
| `unlogged_run` | A `training_runs` row has no corresponding audit entry (`entry_id` is `None`) |
| `head_mismatch` | `expected_head` was supplied and differs from the actual head (`entry_id` is `None`) |

`subject_count_mismatch` is the check that closes the deleted-subject attack.
`unlogged_run` is its dual: a model trained without any audit record at all.

The subject count is compared against the **payload's** `n_subjects`, which the
hash chain protects — never against the `training_runs.n_subjects` column, which
an attacker can edit. Deleting a `subject_index` row *and* editing
`training_runs.n_subjects` to match leaves the tables internally consistent, so
only the audit payload reveals the deletion. That combined attack carries a
dedicated regression test, so a future "optimization" that reads the column
instead of counting rows fails loudly.

`malformed_payload` must be handled explicitly — a tampered payload can fail
`json.loads`, and an unhandled exception during verification would be a poor
failure mode for a tool whose entire job is to survive hostile input. In
practice this proved to be the hardest part of the module: implementation
surfaced three separate crash classes (JSON parsing to a non-dict, BLOB columns
raising `UnicodeDecodeError`, and deeply nested JSON raising `RecursionError`),
plus three more in the cross-check path (unhashable `run_id`, integers too wide
for SQLite to bind, and mixed `str`/`bytes` run ids breaking `sorted`). The
settled approach is to treat *any* `json.loads` failure as `malformed_payload`
rather than enumerate exception types, and to guard each attacker-reachable
comparison individually.

### Store additions

Three small query methods on `LineageStore`:

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
- edited `model_hash` → `run_modified`; edited `n_subjects` column → `run_modified`
- deleted `subject_index` row **plus** a matching `training_runs.n_subjects` edit
  → still `subject_count_mismatch`
- directly-inserted run → `unlogged_run`
- **one edit yields one finding** — the no-cascade guarantee, tested in both the
  naive and rehashed forms
- `head_hash` equals the last entry's hash; genesis for an empty log
- wholesale rewrite verifies clean *without* an anchor but trips `head_mismatch`
  *with* one
- `to_dict()` round-trips through JSON
- CLI: exit 0 clean, exit 1 tampered, `--json` output shape, `--expected-head`

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
