# ConsentML

[![PyPI version](https://img.shields.io/pypi/v/consentml.svg)](https://pypi.org/project/consentml/)

Data-lineage tracking and consent-revocation reporting for production ML
pipelines. Add one decorator to your training function; when a user revokes
consent, ConsentML tells you which deployed models were trained on their data
and produces a tamper-evident audit trail.

## Documentation

This README covers the basics. The
[full site](https://consentml.lokeshkaranam.me/) has a
[Quickstart](https://consentml.lokeshkaranam.me/getting-started/quickstart/),
the [CLI and API reference](https://consentml.lokeshkaranam.me/reference/cli/),
and [why ConsentML is scoped the way it is](https://consentml.lokeshkaranam.me/why/).

## Tracking a training run

ConsentML loads the training data, so the lineage it records cannot disagree
with what the model actually trained on:

```python
from consentml import track
from consentml.sources.postgres import PostgresSource

@track(
    model_name="readmission-risk",
    source=PostgresSource(
        dsn="postgresql://user:pw@db.internal/clinic",
        query="""
            SELECT p.patient_id, p.age, l.ldl, p.outcome
            FROM patients p JOIN labs l USING (patient_id)
        """,
        subject_id_col="patient_id",
    ),
)
def train(df):
    return LogisticRegression().fit(df[["age", "ldl"]], df["outcome"])

model = train()    # no argument: ConsentML supplies the data
```

`source=` is evaluated at decoration time, not at call time: `@track` cannot
decorate a function that is later called against different data, since the
source (and therefore the data it loads) is fixed when the decorator runs.

Requires `pip install 'consentml[postgres]'`. Queries run in a read-only
transaction; ConsentML never writes to the database it reads from. Credentials
are never recorded — the stored provenance keeps host, port and database only.

For data already in memory:

```python
from consentml.sources import DataFrameSource

@track(model_name="m", source=DataFrameSource(df, subject_id_col="patient_id",
                                              label="clinic.patients"))
def train(df): ...
```

`label` is caller-asserted and recorded as such: ConsentML cannot verify where
an in-memory frame came from, and the stored record says so.

A null subject ID is refused by both sources. A null cannot be revoked, so
recording one would inflate the run's subject count with a subject no
revocation could ever match.

### What provenance records

Postgres runs are recorded with the exact query text and its SHA-256, plus the
tables the query plan touched:

```json
{
    "kind": "postgres",
    "host": "db.internal",
    "port": 5432,
    "database": "clinic",
    "query": "SELECT p.patient_id, p.age, l.ldl, p.outcome FROM patients p JOIN labs l USING (patient_id)",
    "query_sha256": "ac80473d33489424...",
    "referenced_tables": ["public.labs", "public.patients"],
    "referenced_tables_source": "explain",
    "n_rows": 3
}
```

The query text is authoritative; `referenced_tables` is advisory — it comes
from `EXPLAIN`, so a table the planner optimizes away will not appear.
`referenced_tables_source` says which mechanism produced the list, or
`"unavailable"` if `EXPLAIN` could not run.

The SHA-256 of the whole provenance record goes into the hash-chained audit
log, so editing provenance in the database is detected as `provenance_modified`.

More on tracking runs: <https://consentml.lokeshkaranam.me/getting-started/tracking/>

## Verifying the audit trail

```bash
consentml verify --db lineage.db
```

Verification checks three things: that every audit entry hashes to its recorded
value, that the chain links correctly, and that the log still agrees with the
live tables. That last check is the one that matters most — it catches a
`subject_index` row deleted to hide that someone was in a training set, or a
`training_runs.provenance` edited after the fact (reported as
`provenance_modified`), either of which the hash chain alone cannot see. Runs
recorded before provenance was hash-protected are counted separately as
`n_legacy_runs` rather than silently treated as checked.

Exit codes, so it can gate CI:

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Read the database and found problems (including: no database there) |
| 2 | Could not read the database at all |

`verify` and `migrate` share this contract: `migrate` exits 1 when it refuses to
migrate (including onto a missing database) and 0 once migrated or already
current. `revoke` does not use it — it always reports what it found and exits
0, whether or not the subject affected any models or the database exists yet;
it only exits 2 if the database cannot be read at all.

Verification never writes. It records no audit event of its own, and it will not
create a database that isn't there — a mistyped `--db` reports a missing
database rather than silently reporting a clean, empty one.

### Export a dossier

When a data subject exercises their right to erasure, `export` produces the
document you file: which models learned from their data, what you recommended
for each, when the request was processed, and whether the audit log backing it
is intact.

```bash
consentml export --subject-id user@example.com --db lineage.db
```

Writes `consentml-dossier-<key>.html` — self-contained, opens in any browser,
prints to PDF. `--format json` emits the same content machine-readably;
`--format pdf` writes a PDF directly and needs the optional extra:

```bash
pip install consentml[pdf]
```

Export never writes to the database, so it is safe to run against a copy of a
production lineage store. Exit codes match `verify`: 0 clean; 1 problems
found — the dossier is still written and reports them, unless there was no
lineage database at the path, in which case nothing is written; 2 the
database could not be read, or `--format pdf` was used without the extra
installed.

The dossier covers one subject. The audit log is a single global chain, so
exporting all of it to answer one subject's request would disclose every other
subject's activity.

More on exporting dossiers: <https://consentml.lokeshkaranam.me/getting-started/first-dossier/>

## Anchoring

A hash chain cannot detect an attacker who rewrites the whole log from genesis
and recomputes every hash. Record the `head_hash` that `verify` reports,
somewhere outside the database, and pass it back:

```bash
consentml verify --db lineage.db --expected-head <previously recorded hash>
```

The anchor is looked up across the whole chain rather than compared to the
current head, so a log that has legitimately grown since you anchored still
verifies; only a rewrite or truncation of history reports `head_mismatch`.

This proves history up to the anchor point. It says nothing about entries
appended after it — re-anchor regularly to narrow that window.

More on anchoring: <https://consentml.lokeshkaranam.me/guides/anchoring/>

## Upgrading an existing database

Databases created on either of the two prior schemas need a one-time upgrade
to the current one — the interned-storage layout, plus the `provenance`
column described above:

```bash
consentml migrate --db lineage.db
```

Migration verifies the audit log before it starts and **refuses to run** if
verification fails — rewriting a tampered database would launder the tampering.
The new database is built alongside the original and only swapped in once it
verifies clean, so a failure leaves the original untouched. The original is kept
as `<name>.pre-migration.bak`; delete it once you are satisfied. Migration
temporarily needs room for two copies of the database.

Until a database is migrated it can be read but not written to, so `@track` and
a recording `revoke()` will raise. `consentml verify` and
`revoke(dry_run=True)` keep working.

Migration backfills provenance from the old `data_source` string as
`{"kind": "legacy", ...}` and **does not touch the audit log** — those entries
were hashed over payloads containing `data_source`, and rewriting them would
invalidate every entry hash. Runs migrated this way keep legacy guarantees:
their provenance is not hash-protected, and `consentml verify` reports how many
such runs it did not check rather than implying it did.

More on migrating: <https://consentml.lokeshkaranam.me/guides/migrating/>

Status: beta (v0.x — the API may change before 1.0). MIT license.
