# Postgres

## Install

```bash
pip install 'consentml[postgres]'
```

`PostgresSource` needs the `psycopg` driver, which comes with this extra.
Without it, importing `consentml.sources.postgres` fails with a clear message
telling you to install the extra rather than a bare `ImportError`.

## Usage

`PostgresSource` takes a DSN, the query that produces the training data, and
the name of the column that identifies the subject:

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

`source=` is evaluated once, when the decorator runs, not each time `train`
is called — see [Tracking a run](../getting-started/tracking.md) for what
that means for a function meant to train against more than one dataset.

## Read-only by construction

Before the query runs, `PostgresSource` sets the connection's `read_only`
flag, so Postgres executes the query inside a read-only transaction.
ConsentML never writes to the database it reads training data from, and a
query that tries to isn't filtered out in Python — Postgres itself rejects
it. A query containing an `UPDATE`, for example, fails like this:

```
ConsentMLError: the training query failed: cannot execute UPDATE in a read-only transaction
```

## What provenance records

Each run's provenance holds the exact query text, its SHA-256, the tables
the query plan touched, and where the query ran — never who is allowed to
run it:

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

Host, port and database name are recorded because they say where the data
came from; the username and password embedded in the DSN never are. They're
parsed out of the DSN before any connection opens, so a connection failure
can't put a password into a traceback that ends up in a log.

The query text is authoritative. `query_sha256` lets anyone reading the
provenance later confirm the query text hasn't changed since the run — and
the SHA-256 of the whole provenance record goes into the hash-chained audit
log, so an edit to `query` (or anything else in this JSON) directly in the
database shows up under `consentml verify` as `provenance_modified`.

## Referenced tables

`referenced_tables` comes from asking Postgres itself — `EXPLAIN (FORMAT
JSON, VERBOSE)` run against the same query — rather than ConsentML parsing
the SQL. That makes the list advisory, not authoritative: a table the query
planner optimizes away (a join eliminated by a foreign key, say) was never
in the plan Postgres reported, so it won't appear here even though the query
text still mentions it.

`referenced_tables_source` records which mechanism produced the list:
`"explain"` when the plan walk succeeded, `"unavailable"` when it didn't. A
failed `EXPLAIN` — a plan Postgres can't produce or a result ConsentML can't
parse — never fails the training run itself: this field is advisory data,
and advisory data can't be allowed to block the query that actually loads
the training set. The run proceeds with `referenced_tables` set to `null`
and the mechanism recorded as `"unavailable"`, so anyone reading the
provenance later can tell "the table list wasn't available" apart from "the
table list is empty."
