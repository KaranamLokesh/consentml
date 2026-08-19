# Migrating a database

## When you need it

A lineage database created on either of ConsentML's two prior schemas — v0
or v1 — can still be read but not written to. `consentml verify` and
`revoke(dry_run=True)` work against it as it is; `@track` and a recording
`revoke()` call raise until it's migrated onto the current schema.

!!! note "SQLite only"
    Migration applies to SQLite lineage databases. The Snowflake lineage
    store is denormalized and has no schema-version progression, so there is
    no `migrate` operation for it — in the CLI or the Python API. See the
    [Snowflake guide](snowflake.md#migrate-has-no-snowflake-equivalent-by-design).

## Running it

```bash
consentml migrate --db lineage.db
```

Against a database already on the current schema, migration is a no-op:

```
Database is already on the current schema; nothing to do.
```

Against an older one:

```
Migrated: 28.0 KB -> 40.0 KB (+12.0 KB).
The new schema's tables and indexes add fixed overhead; deduplication only pays off once subjects repeat across many runs.
Original kept at lineage.db.pre-migration.bak
```

## What it does

Migration is gated by verification on both ends. Before touching anything it
runs the same check `consentml verify` does against the original database,
and refuses to migrate if that check fails: rewriting a tampered database
would produce a fresh, internally consistent one, which launders the
tampering and destroys the evidence.

The new database is built at a separate path alongside the original,
verified in turn, and only swapped into place once that second verification
is clean. A failure before the swap starts — either verification failing,
or the staging database failing to build — leaves the original completely
untouched. The swap itself is two renames: the original to
`<name>.pre-migration.bak`, then the staging database to the original's
path. If the first rename succeeds but the second fails, migration tries to
put the original back automatically; that recovery is itself a rename and
can fail too. When it does, the original is left sitting at
`<name>.pre-migration.bak` with nothing at the canonical path, and the error
tells you to restore it manually — move the backup back to the original
name — before retrying. Once the swap succeeds, the original is kept as
`<name>.pre-migration.bak` — delete it once you're satisfied with the
result. Because the new database is built before the original is touched,
migration needs enough free disk for two copies of the database while it
runs.

## Why the database may grow

The current schema interns subject IDs into their own table, referenced by
key from `subject_index`, instead of storing each subject's hash inline on
every row that mentions them. That's schema and index overhead a small
database pays for in full before it gets anything back. On a database with
two runs and three distinct subjects, migrating made it larger, not smaller:

```
Migrated: 28.0 KB -> 40.0 KB (+12.0 KB).
```

The saving only shows up once the same subject repeats across many runs —
one interned row instead of one row per run that mentions them. A database
where few subjects recur, or with few runs overall, can legitimately come
out of migration bigger than it went in; that's the expected shape of the
tradeoff, not a sign anything went wrong.

## Legacy runs after migration

Migration backfills each old run's provenance from its free-text
`data_source` column into `{"kind": "legacy", "label": <the original
string>, "subject_id_col": ...}` — nothing about the original value is
invented or reinterpreted, it's carried over verbatim under a `kind` that
says where it came from. What migration does not do is touch the audit log:
those runs' audit entries were hashed over payloads that included the old
`data_source` field directly, so rewriting them to match the new provenance
shape would invalidate every entry hash. A migrated run keeps its original,
pre-migration audit payload permanently.

`consentml verify` reflects that rather than papering over it. A run whose
audit entry has no `provenance_sha256` to check the stored provenance
against is counted as legacy and reported separately, both before and after
migration — migrating doesn't add hash protection retroactively, it only
changes how the value is represented in `training_runs`:

```bash
consentml verify --db lineage.db
```

```
Audit log OK: 2 entries, chain intact.
note: 2 run(s) predate provenance hashing; their provenance was not verified.
head: da8c75ca4c23a5ee0c9ffd17f5e671af0bad35aa87a1b98f95d1c6486371efe4
```

That `note` line is the point: a clean "Audit log OK" never implies more
coverage than `verify` actually checked. See
[the anchoring guide](anchoring.md) for what the `head` value on the last
line is for.
