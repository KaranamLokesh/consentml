# Snowflake

ConsentML integrates with Snowflake in two independent places. You can use
either on its own:

1. **`SnowflakeSource`** reads the training set *out of* Snowflake and records
   its provenance — the data source. Lineage still lands in the default SQLite
   store unless you change it.
2. **`SnowflakeLineageStore`** persists the hash-chained lineage *in* Snowflake
   — the audit log. Reached with `store=` (on `@track` and `verify_audit_log`)
   or directly via `open_store`.

## Install

```bash
pip install 'consentml[snowflake]'
```

Both pieces need the `snowflake-connector-python` driver, which comes with this
extra. Without it, importing the Snowflake modules fails with a clear message
telling you to install the extra rather than a bare `ImportError`. The
connector is never imported at package import time, so `import consentml` stays
dependency-free for offline users.

Credentials come from you at call time (user/password or key-pair), never from
a file in the repo. Only the non-secret coordinates — account, database,
schema, warehouse — are ever recorded; the user, password, or key never are.

## `SnowflakeSource`: Snowflake supplies the training data

`SnowflakeSource` takes a connection dict, the query that produces the training
data, and the name of the column that identifies the subject:

```python
from consentml import track
from consentml.sources.snowflake import SnowflakeSource

connection = {
    "account": "ab12345.us-east-1",
    "user": "analyst_readonly",   # a role holding read-only grants
    "password": "...",            # from os.environ / a secret, never hardcoded
    "database": "CLINIC",
    "schema": "PUBLIC",
    "warehouse": "ANALYTICS_WH",
}

@track(
    model_name="readmission-risk",
    source=SnowflakeSource(
        connection=connection,
        query="SELECT PATIENT_ID, AGE, LDL, OUTCOME FROM patients",
        subject_id_col="PATIENT_ID",
    ),
)
def train(df):
    return LogisticRegression().fit(df[["AGE", "LDL"]], df["OUTCOME"])

model = train()    # no argument: ConsentML runs the query and supplies the data
```

`source=` is evaluated once, when the decorator runs, not each time `train` is
called — see [Tracking a run](../getting-started/tracking.md) for what that
means.

### Read-only is your responsibility

Unlike Postgres, Snowflake exposes no connection-level read-only flag, so
ConsentML cannot force it. Supply a `role` that holds **read-only grants** on
the data you read; ConsentML records the coordinates but cannot police the
permissions.

### What provenance records

Each run's provenance holds the exact query, its SHA-256, the tables the plan
touched (best-effort via `EXPLAIN USING JSON`), and where the data came from —
never the credentials:

```json
{
    "kind": "snowflake",
    "account": "ab12345.us-east-1",
    "database": "CLINIC",
    "schema": "PUBLIC",
    "warehouse": "ANALYTICS_WH",
    "query": "SELECT PATIENT_ID, AGE, LDL, OUTCOME FROM patients",
    "query_sha256": "5bf0b4af91782c86...",
    "referenced_tables": ["CLINIC.PUBLIC.PATIENTS"],
    "referenced_tables_source": "explain",
    "n_rows": 5
}
```

`referenced_tables_source` is `"explain"` when Snowflake's plan was parseable
and `"unavailable"` otherwise. A failed `EXPLAIN` is advisory only — it never
fails the training run.

## `SnowflakeLineageStore`: the audit log lives in Snowflake

To keep the hash-chained lineage itself in Snowflake, pass a connection dict as
`store=` on `@track`. A dict target selects Snowflake; a path or `None` keeps
the default SQLite store.

```python
@track(
    model_name="readmission-risk",
    store=connection,                       # lineage -> Snowflake
    source=SnowflakeSource(connection=connection, query=..., subject_id_col=...),
)
def train(df):
    ...
```

`store=` and `db_path=` are mutually exclusive; passing both raises
`ConsentMLError`. The same target works when verifying:

```python
from consentml import verify_audit_log

report = verify_audit_log(store=connection)
print(report.ok)
```

Because the connection dict is an explicit target (unlike a typo-able file
path), verification does not pre-check for a missing database: verifying a
never-written Snowflake chain reports `ok=True` with zero entries rather than a
`missing_database` finding.

### Driving the store directly

When you are not using `@track` — recording a run trained outside a decorated
function — reach the store through `open_store`:

```python
from consentml.store import open_store

store = open_store(connection)              # dict -> SnowflakeLineageStore
try:
    store.record_training_run(...)
    for entry in store.audit_entries():
        ...
finally:
    store.close()
```

A `snowflake://` URI is deliberately rejected as a target: it cannot safely
carry a password, so pass a dict.

### Same chain, different backend

The Snowflake schema is denormalized relative to SQLite — no subject interning,
since a columnar warehouse does not benefit from it — but the audit-log row
shape and the `entry_hash` formula are **byte-for-byte identical**. The same
`verify_audit_log` code verifies a chain no matter which backend wrote it.

!!! warning "Single writer per lineage table"
    The Snowflake store assumes a **single logical writer** per lineage table.
    The audit chain is a read-then-append (read the last `entry_hash`, write a
    row whose `prev_hash` is that value); a warehouse will not serialize that
    for you, so two concurrent writers could fork the chain. Coordinating
    multiple writers is an explicit non-goal.

!!! note "CLI stays SQLite-only"
    The Snowflake lineage store is reached through the Python API. The
    `consentml` command-line tool operates on local SQLite databases only.
