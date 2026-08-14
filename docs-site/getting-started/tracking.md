# Tracking a run

## The decorator

`@track` is the whole integration: one decorator, one `Source` describing
where the training data comes from. ConsentML loads the data itself, so what
it records can't disagree with what the model actually trained on:

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

`PostgresSource` needs the `consentml[postgres]` extra. The query runs in a
read-only transaction — ConsentML never writes to the database it reads
lineage from — and only host, port and database name are recorded;
credentials in the DSN never reach the stored provenance. See
[the Postgres guide](../guides/postgres.md) for the connection and query
requirements.

## Sources

`source=` is evaluated once, when the decorator runs, not each time the
wrapped function is called. That means `@track` binds a function to one
source for its lifetime: it cannot decorate a function meant to be called
later against different data, because the source — and therefore the data
that will be loaded — is already fixed by the time `train()` is called for
the first time. A training pipeline that trains the same function against
several datasets needs a separate `@track`-decorated function, or a separate
call site, per source.

## DataFrameSource

For data already in memory, `DataFrameSource` reads subject IDs out of a
column you name:

```python
from consentml.sources import DataFrameSource

@track(model_name="m", source=DataFrameSource(df, subject_id_col="patient_id",
                                              label="clinic.patients"))
def train(df): ...
```

`label` is caller-asserted: ConsentML has no way to check where an in-memory
frame actually came from, unlike `PostgresSource`, which ran the query
itself. The stored provenance records the label under `kind="dataframe"`
precisely so a reader of the audit trail can tell a self-reported label
apart from a connector-verified one — it is not a claim ConsentML is
vouching for.

## What gets recorded

A `PostgresSource` run is recorded with the exact query text and its
SHA-256, plus the tables the query plan touched:

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
from `EXPLAIN`, so a table the planner optimizes away won't appear there.
`referenced_tables_source` says which mechanism produced the list, or
`"unavailable"` if `EXPLAIN` couldn't run. A `DataFrameSource` run's
provenance is smaller — `kind`, the asserted `label`, the subject ID column,
and the row count — since there is no query to record.

Subject IDs themselves are never stored raw. Both sources hash each subject
ID to its SHA-256 digest before it reaches the database, so the lineage
store never holds a raw patient ID, email address, or other identifier —
only a digest that a later `revoke` call can re-derive from the same input
and match against.

## Null subject IDs are refused

Both sources reject a null in the subject ID column outright. Given a frame
with one missing `patient_id`, `@track` raises before training runs:

```
ConsentMLError: Subject ID column 'patient_id' has 1 null value(s); a null subject ID cannot be revoked, so refusing to record it as training coverage.
```

A null identifies no one in particular, so it can never be matched by a
future revocation. Recording it anyway would inflate the run's subject count
with a subject no revocation could ever reach — a training run that looks
like it covers one more person than any `revoke` call could actually find.
