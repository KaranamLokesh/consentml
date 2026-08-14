# Schema

`consentml.store.LineageStore` keeps everything in one SQLite file. This
page describes the current schema (v2) and what changed to get here.

## The four tables

- **`training_runs`** — one row per decorated training execution: model
  name, model hash, provenance, subject count, and start/finish times.
- **`subjects`** — each distinct subject key, stored once.
- **`subject_index`** — one row per `(run, subject)` pair, linking the two
  by integer foreign key.
- **`audit_log`** — the append-only, hash-chained event log: one entry per
  training run recorded and per revocation processed.

## Subject interning

`subjects` holds each distinct subject key exactly once; `subject_index`
references it by integer foreign key (`subject_pk`) rather than repeating
the key itself on every row. Before this, `subject_index` stored the key
inline, so a subject seen in fifty runs was written out fifty times.

The saving only shows up once subjects repeat across runs — a database's
first run still writes every key into `subjects`, so it grows about the
same as before. What changes is the *marginal* cost of each later run. At
200k subjects, the measured marginal cost per run dropped from 38.7 MB
(inline, no dedup) to 7.5 MB (interned) — the difference between storing
each subject's key once versus once per run.

## The hash chain

Each `audit_log` entry's `entry_hash` is `SHA-256(prev_hash + timestamp +
event_type + payload)`, and `prev_hash` is the previous entry's
`entry_hash` (or a genesis hash of all zeroes, for the first entry).

Each entry is hashed from its own stored fields and its link checked
against the previous row's stored hash independently — so a single
tampered row breaks the chain at that link without invalidating every
entry after it. `consentml verify` reports exactly which entries fail
either check, rather than one blanket "chain broken" for the whole log.

## What is hash-protected

A `training_run` audit entry's payload carries `provenance_sha256`, the
hash of the run's provenance JSON at the time it was recorded. That makes
edits to `training_runs.provenance` after the fact detectable: recompute
the hash of the stored value and compare it against the one in the
payload.

`training_runs.n_subjects` is not similarly protected — it's a plain
column, editable like any other. That's why verification doesn't trust it
directly: it recomputes the subject count from `subject_index` and
compares that against `n_subjects` in the audit payload, so a row edited
after the fact shows up as a mismatch instead of passing silently.

## Schema versions

Schema version is stored in `PRAGMA user_version`.

- **v0** — the original schema. `subject_index` stores each subject key
  inline (no interning), and `training_runs` has `data_source` and
  `subject_id_col` columns instead of `provenance`.
- **v1** — interns `subject_index` into the `subjects`/`subject_index`
  split used today, but `training_runs` still has `data_source` and
  `subject_id_col`, not yet `provenance`.
- **v2** (current) — adds the `provenance` column to `training_runs`,
  carrying a JSON document whose SHA-256 is what `training_run` audit
  entries hash-protect via `provenance_sha256`.

v0 and v1 databases can still be read — `consentml verify` and
`revoke(dry_run=True)` work against them as they are — but not written to;
`@track` and a recording `revoke()` call raise until the database is
migrated. See [Migrating a database](../guides/migrating.md) for what
`consentml migrate` does and what it preserves.
