# ConsentML v0 Week-8 Design: interned subject storage + `consentml migrate`

**Status:** approved design, ready for implementation planning
**Date:** 2026-07-25

## Problem

`subject_index` stores `(run_id TEXT uuid, subject_id_hash TEXT hex)` — one row
per subject per run, with no deduplication across runs. Retraining weekly on a
stable customer base re-stores every hash every time. The marginal cost of a run
does not depend on how much its population overlaps previous runs.

Measured at 200k subjects: **38.7 MB per run**, flat, extrapolating to
**~10.06 GB at 1M subjects × 52 weekly runs**. That is well past comfortable for
a SQLite file.

Hashing is *not* a contributor and needs no change: 0.59 µs per subject, ~0.6 s
for 1M — negligible against a training run measured in minutes.

## Measured basis for the design

Two interning variants were benchmarked against the current schema, with correct
per-run inserts and indexes on both `subject_index` columns:

| Schema | first run | marginal/run | 1M × 52 runs |
|---|---|---|---|
| current | 38.7 MB | 38.7 MB | 10.06 GB |
| intern, `subject_key` as hex `TEXT` | 38.7 MB | **7.5 MB** | **1.95 GB** |
| intern, `subject_key` as 16-byte `BLOB` | 17.6 MB | **7.5 MB** | **1.95 GB** |

**Truncating hashes to 16-byte BLOBs is rejected.** Marginal cost is identical;
truncation only shrinks the one-time `subjects` table (~105 MB at 1M subjects),
and marginal cost dominates across 52 runs. It would cost a deliberate
cryptographic weakening, a changed stored format, and an awkward home for raw
identifiers under `hash_subject_ids=False` — in exchange for nothing on the
growth problem.

Storing `subject_key` as the existing hex `TEXT` keeps `hash_subject_id`
unchanged and lets raw identifiers live in the same column naturally.

## Schema v1

`audit_log` is **not touched**. Its rows, payloads, and hash chain survive the
migration byte-for-byte, which is what makes verification across the migration
meaningful: any disagreement afterward is real.

```sql
PRAGMA user_version = 1;

training_runs   run_pk INTEGER PRIMARY KEY,        -- new, internal only
                run_id TEXT NOT NULL UNIQUE,       -- unchanged, still the public id
                model_name, model_hash, data_source, subject_id_col,
                subject_ids_hashed, n_subjects, started_at, finished_at
                                                   -- all unchanged

subjects        subject_pk  INTEGER PRIMARY KEY,
                subject_key TEXT NOT NULL UNIQUE   -- hex hash, or the raw id
                                                   -- when hash_subject_ids=False

subject_index   run_pk     INTEGER NOT NULL REFERENCES training_runs(run_pk),
                subject_pk INTEGER NOT NULL REFERENCES subjects(subject_pk)

                INDEX on subject_index(subject_pk)  -- revocation lookups
                INDEX on subject_index(run_pk)      -- per-run counts, migration
```

## The change stays below `store.py`

Every `LineageStore` method keeps its signature and still exchanges `run_id` as
TEXT: `record_training_run`, `runs_for_subject_value`, `latest_run_for_model`,
`run_by_id`, `subject_count_for_run`, `all_run_ids`. Only the SQL inside changes.

Consequently `revoke.py`, `verify.py`, and `track.py` need **zero edits**, and
the existing 93 tests must pass unchanged. `cli.py` changes only to register the
new `migrate` subcommand. If any other caller requires changing, the abstraction
boundary was drawn wrong — that is a signal to stop and reconsider, not to edit
the caller.

## Interning dedups keys, not index rows

Each original `subject_index` row becomes exactly one `(run_pk, subject_pk)`
row. Deduplication happens in the `subjects` table — the *key* is stored once
and referenced many times.

This matters for correctness: per-run row counts are preserved exactly, which is
what `subject_count_mismatch` compares against the hash-protected audit payload.
If an old database holds duplicate `(run, subject)` rows, post-migration
verification will catch the changed count and fail loudly rather than silently
"cleaning" the data.

## `consentml migrate`

```
consentml migrate [--db PATH] [--allow-unverified] [--json]
```

1. Read `PRAGMA user_version`. Already 1 → report and exit 0. **Idempotent.**
2. Run `verify_audit_log()`. Any finding → print the findings, **change
   nothing**, exit non-zero.
3. Build the migrated database as a **new file alongside** the original.
4. Verify the new file. Only if clean, `os.replace()` it into position and leave
   the original as `<name>.pre-migration.bak`.
5. Report before/after size.

**Why it refuses on a failed pre-check.** Migrating a tampered database rewrites
it into a fresh, internally consistent one — laundering the tampering and
destroying the evidence. The operator must investigate first. `--allow-unverified`
exists for the genuinely stuck and must be explicit.

**Why build alongside rather than in place.** A failure leaves the original
untouched, so there is no rollback logic to get wrong. The cost is temporary
double disk usage, which the docs must state plainly given these files can reach
multiple GB.

**Why a separate command rather than auto-migrating on open.** Silently
rewriting an audit database is precisely the class of event this tool exists to
detect. It must be a deliberate operator action.

## Version guard: v0 is readable, not writable

The obvious guard — "refuse to open `user_version = 0`" — cannot work, because
`migrate` has to read a v0 database, and its pre-migration gate calls
`verify_audit_log()`, which opens one through `LineageStore`. A blanket refusal
would make migration impossible.

So the guard is on **writes**, not opens:

- `LineageStore` reads `PRAGMA user_version` on open and records it.
- **Read** methods work against both schemas. `runs_for_subject_value` and
  `subject_count_for_run` branch their SQL on the version; `latest_run_for_model`,
  `run_by_id`, `all_run_ids`, and `audit_entries` are unaffected because
  `training_runs`' public columns and `audit_log` are identical in both.
- **Write** methods (`record_training_run`, `record_revocation`) raise
  `ConsentMLError` on a v0 database, naming `consentml migrate`.
- Fresh databases are created at v1.

This is the minimum that makes migration possible. It also means
`verify_audit_log()` works unchanged on a v0 database, so the pre-migration gate
needs no duplicated verification logic — the single most important property of
this design, since a second implementation of the cross-checks would be a second
thing to get wrong.

The branching is confined to two queries and is **transitional**: once the
migration path is retired, the v0 branches go with it. Both branches must be
tested against real v0 and v1 databases, not mocks.

Silently misreading an old file — misinterpreting `subject_index` and reporting
confident nonsense about who was in which training set — remains the outcome
that cannot be allowed. Reading v0 correctly and refusing to write to it
achieves that; a blanket refusal would merely have made the tool unusable.

## Testing

- migration round-trips a seeded database: verification clean **before and
  after**
- `revoke()` returns identical reports pre- and post-migration — the real proof
  that lineage survived
- migration refuses on a tampered database, exits non-zero, and leaves the file
  **byte-identical** (assert on a hash of the file)
- migration is idempotent: running it twice is a no-op the second time
- per-run counts preserved, including a hand-crafted duplicate-`(run, subject)`
  database that must fail post-migration verification rather than be silently
  cleaned
- `LineageStore` **write** methods raise `ConsentMLError` on a `user_version = 0`
  file, with a message naming the migrate command
- `LineageStore` **read** methods return correct results on a v0 file:
  `runs_for_subject_value` and `subject_count_for_run` each tested against a real
  v0 database built with the old schema, not a mock
- `verify_audit_log()` runs correctly against a v0 database — the property the
  pre-migration gate depends on
- `revoke(dry_run=True)` works on a v0 database while a recording `revoke()`
  raises, since dry-run touches no write path
- `--allow-unverified` migrates a tampered database when explicitly asked
- the existing 93 tests pass unchanged
- a size-reduction assertion on a synthetic multi-run database, so the whole
  point of the exercise is pinned by a test rather than assumed

## Out of scope

Roaring-bitmap or other probabilistic per-run encodings. One bitmap blob per run
would take 200k subjects to roughly 30 KB, another ~100x, but it stops being
SQL-queryable and `revoke()` would have to load and test bitmaps per run. Revisit
only if 2 GB proves insufficient.
