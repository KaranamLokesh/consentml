# Postgres connector: verified data provenance

Date: 2026-07-26
Status: implemented, 2026-07-27

## 1. Problem

`@track` takes `data_source` as a free-text string and never checks it. Nothing
reads it, nothing validates it, and the empty string is accepted. Its only
definition anywhere in the repository is the example value
`postgres://prod/customers`; the README does not mention it at all.

Two consequences follow:

- **Provenance is an assertion, not a fact.** The lineage store records what the
  caller typed. A run whose data came from `clinic.patients` and a run whose
  `data_source` says so are independent facts today.
- **The field cannot describe a join.** A training DataFrame assembled from
  three tables has one slot to name its origin. The type is wrong for the job.

`@track` also requires an in-memory pandas DataFrame, found by scanning the
decorated function's arguments for the first `DataFrame` instance. The README
claims ConsentML serves "production ML pipelines"; until the library can read
from the systems those pipelines read from, that claim is not backed.

This design closes the provenance gap. It does not close the in-memory gap —
see §9.

## 2. Scope

In scope: reading training data from Postgres, recording verified structured
provenance, and unifying the `@track` API behind a `Source` interface.

Out of scope: moving the lineage store itself to Postgres (a separate feature
that shares no code with this one); streaming or distributed sources; Snowflake.
The interface is designed so `SnowflakeSource` and `SparkSource` can be added
later without changing it (§8), but neither is built here.

Postgres is deliberately first even though the author's own tables live in
Snowflake (§8.1). The reason is CI: a Postgres service container is free,
hermetic, and runs on every pull request, which is what the 100% coverage gate
depends on. Snowflake in CI would require an account, credentials in repository
secrets, and per-query spend on a public repo, and contributors could not run
the suite at all. Postgres proves the `Source` abstraction cheaply; the
Snowflake source then lands as a small change against a validated interface.

The accepted cost: Postgres cannot be dogfooded against the author's real data,
so this connector will be well-tested but unexercised in production until
`SnowflakeSource` exists.

## 3. Decisions

| Question | Decision |
|---|---|
| Which side of the connection? | Source side. ConsentML reads training data; the lineage store stays SQLite. |
| Trust model | ConsentML loads the data and hands it to the training function. Lineage is true by construction. |
| Data shape | Materialized DataFrame. No streaming. |
| Provenance storage | Structured JSON in a new column; schema v2 + migration. |
| Legacy API | Removed. `source=` is the only form. |
| Query surface | Arbitrary SQL. Query text authoritative, plan-derived table list advisory. |

### 3.1 Why ConsentML owns the load

The alternative — the caller loads data and ConsentML separately queries for
subject IDs — produces two observations of a live table at two points in time.
The recorded subject set can diverge from the trained set with nothing to
signal it. That is the same class of failure as a false clean in
`verify_audit_log()`: the system reports a guarantee it did not check.

Owning the load makes the guarantee structural. One call to the source yields
both the payload and the subject IDs, so they cannot disagree.

The cost is invasiveness: ConsentML dictates how training data is loaded. This
is accepted.

## 4. The Source interface

```python
@dataclass(frozen=True)
class SourceResult:
    payload: object          # passed to the training function; never inspected
    subject_ids: list[str]   # distinct subject identifiers, pre-hashing
    provenance: dict         # JSON-serializable

class Source(Protocol):
    def load(self) -> SourceResult: ...
```

One method, one observation. `payload` is opaque to ConsentML — it is passed
through to the training function untouched. Nothing in the core depends on it
being a pandas DataFrame.

A rejected alternative was separate `load_payload()` / `subject_ids()` methods.
It would allow fetching subject IDs without materializing rows, which a
distributed source would want, but it reintroduces the two-observation skew
that §3.1 exists to eliminate.

### 4.1 New call shape

```python
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
    db_path="lineage.db",
)
def train(df):
    return LogisticRegression().fit(df[["age", "ldl"]], df["outcome"])

model = train()    # no argument: ConsentML injects the payload
```

The in-memory case keeps working through an explicit source:

```python
@track(model_name="m", source=DataFrameSource(df, subject_id_col="patient_id",
                                              label="clinic.patients"))
def train(df): ...
```

`@track`'s parameters become `model_name`, `source`, `hash_subject_ids` and
`db_path`. `data_source` is removed and `subject_id_col` moves onto the source,
where the column actually lives. `hash_subject_ids` stays on `@track`
unchanged, because it governs how the lineage store writes subject keys rather
than how a source reads them.

### 4.2 Module layout

| Module | Responsibility | Depends on |
|---|---|---|
| `sources/base.py` | `Source` protocol, `SourceResult` | nothing |
| `sources/dataframe.py` | `DataFrameSource` | pandas |
| `sources/postgres.py` | `PostgresSource` | psycopg (lazy) |
| `track.py` | call `load()`, inject payload, record run | `sources/base` only |

`track.py` shrinks: argument-scanning for a DataFrame and `subject_id_col`
validation both move into `DataFrameSource`.

psycopg is an optional extra, `pip install consentml[postgres]`, imported
inside `PostgresSource` so the core install stays pandas-only.

## 5. Provenance records

`PostgresSource`:

```json
{
  "kind": "postgres",
  "host": "db.internal",
  "port": 5432,
  "database": "clinic",
  "query": "SELECT p.patient_id, ... FROM patients p JOIN labs l USING (patient_id)",
  "query_sha256": "9f2c...",
  "referenced_tables": ["public.labs", "public.patients"],
  "referenced_tables_source": "explain",
  "n_rows": 12345
}
```

Username and password never appear. The DSN is parsed and only host, port and
database survive; the parse happens before the connection is opened, so a
connection failure cannot leak a password through a traceback.

**Connection fields are per-`kind`, not a shared schema.** `host`/`port`/
`database` are libpq-shaped and belong to `kind: "postgres"` alone; a Snowflake
record would carry account, warehouse, database and schema instead. Only
`kind`, `n_rows`, and — where the source runs a query — `query`,
`query_sha256`, `referenced_tables` and `referenced_tables_source` are common
across query-backed sources. Nothing in the core reads any of these fields;
they are recorded, hashed, and reported.

`referenced_tables` comes from `EXPLAIN (FORMAT JSON, VERBOSE)` — Postgres
reports the relations, so ConsentML never parses SQL. `VERBOSE` is
load-bearing, not cosmetic: without it Postgres omits the `Schema` key from
plan nodes entirely, so a table outside the `public` schema would silently
report as `public.<name>` instead of its real schema. The list is
**advisory**: tables the planner optimizes away will not appear. `query`
remains the authoritative record of what ran. `referenced_tables` is sorted
for stable hashing.

`referenced_tables_source` names the mechanism rather than assuming one, so
each engine declares how its list was obtained and how far it can be trusted.
`"explain"` means plan-derived and advisory; `"unavailable"` means not
obtained (§7). Engines that can report accessed objects authoritatively get
their own value (§8.1). A reader must be able to tell an advisory list from an
authoritative one without knowing which engine produced it.

`DataFrameSource`:

```json
{"kind": "dataframe", "label": "clinic.patients", "subject_id_col": "patient_id", "n_rows": 20}
```

`label` is optional and explicitly caller-asserted. This is where the
free-text field survives — only where nothing better is available, and marked
as an assertion rather than sitting in a column that looks verified.

## 6. Schema v2

`training_runs.data_source TEXT` is replaced by `training_runs.provenance TEXT`
holding JSON. `SCHEMA_VERSION` becomes 2.

The audit payload for `training_run` events replaces `data_source` with
`provenance_sha256` — the SHA-256 of the provenance JSON serialized with
`sort_keys=True`. The full query text is not put in the payload; a hash gives
tamper-evidence without bloating the log.

This closes an existing gap. Today `verify_audit_log()` compares only
`model_hash` and `n_subjects` against the payload, so editing `data_source`
directly in `training_runs` goes undetected. With `provenance_sha256` in the
hash-protected payload, verification recomputes it from the stored column.

New finding code: `provenance_modified`.

### 6.1 Migration v0/v1 → v2

Reuses the week-8 machinery: verify before starting, build alongside, atomic
rename, keep `<name>.pre-migration.bak`, refuse on a failed pre-check. The
same code path migrates a v0 database directly to v2 as well as v1 to v2 --
there is no intermediate v0 → v1 → v2 hop.

Backfill maps each old value to `{"kind": "legacy", "label": "<data_source>",
"subject_id_col": "<subject_id_col>"}`. No invention: the old string is
preserved verbatim under a kind that says where it came from.

**The audit log is not touched.** Existing entries were hashed with
`data_source` inside their payload; rewriting them would invalidate every entry
hash and turn a clean database into a failing one. Old entries therefore keep
their original payload shape permanently, and a v2 database will normally hold
a mixed log: pre-migration entries carrying `data_source`, post-migration
entries carrying `provenance_sha256`.

This works without special-casing `_REQUIRED_KEYS`, which for `training_run` is
`{run_id, model_name, model_hash, n_subjects}` — `data_source` was never
required, and `provenance_sha256` will not be either.

Verification branches on which key is present:

- payload has `provenance_sha256` → recompute the hash from the stored
  `provenance` column and report `provenance_modified` on mismatch;
- payload lacks `provenance_sha256` (whether or not it carries `data_source`)
  → legacy entry, counted, no provenance check.

Legacy runs keep legacy guarantees. Their backfilled provenance is not
hash-protected, and `verify` must not imply otherwise. `VerificationReport`
gains `n_legacy_runs` so a report can state plainly how many runs were not
provenance-checked.

Migration is one-way. v1 databases remain readable but not writable, per the
existing `_require_writable()` guard.

## 7. Error handling

**The source is fully resolved before the training function is called.** A bad
DSN, an unreachable host, or a missing subject column fails immediately rather
than after training completes. Training-time failures keep current behavior:
the run is recorded only after the function returns, so a crashed training run
leaves no lineage record.

| Condition | Behavior |
|---|---|
| psycopg not installed | `ConsentMLError` naming `pip install consentml[postgres]`, at `PostgresSource` construction |
| DSN unparseable / host unreachable | `ConsentMLError`, chained from the psycopg exception |
| `subject_id_col` absent from result | `ConsentMLError` before training |
| Empty result set | `ConsentMLError` — a run over zero subjects is nearly always a bug, and recording it produces a lineage entry that looks like real coverage |
| `EXPLAIN` fails | **Run proceeds.** `referenced_tables: null`, `referenced_tables_source: "unavailable"` |
| Query attempts a write | Rejected (§7.1) |

### 7.1 Never write to the source

**The requirement is that no source ever writes to the system it reads from.**
That is a property every `Source` implementation must guarantee; the mechanism
is the implementation's business and differs by engine.

`PostgresSource` satisfies it with an explicitly read-only transaction. A
Snowflake source would satisfy it with a read-only role, since Snowflake has no
equivalent transaction mode. The spec states the guarantee, not the mechanism,
so that a later source is held to the same standard rather than to Postgres's
implementation of it.

One constraint carried forward from weeks 7–8, where the same mistake was made
twice: psycopg exceptions are caught **narrowly and re-raised as
`ConsentMLError` with the original chained**, never absorbed into a broad
`except Exception`. The contract here is *fail clearly*, not *never raise*.
`sources/postgres.py` carries a comment saying so.

## 8. Designing for later sources

No Snowflake or Spark code is written here. Three properties keep the door open:

1. `payload` is opaque, so a Spark DataFrame passes through unchanged.
2. `provenance` is a free-form dict with a `kind` discriminator, so a new
   source adds a new shape without a schema change.
3. `subject_ids` is a plain list of strings — a distributed source computes
   `select(col).distinct()` on the cluster and collects only the distinct keys,
   which is far smaller than the row count.

The known strain: `load()` returning a materialized `SourceResult` assumes the
distinct subject set fits in driver memory. At the scale week 8 targeted
(1M subjects) that is a list of a million strings, which is fine. Beyond that
the interface would need revisiting — an acceptable limit to accept now rather
than design around speculatively.

### 8.1 Snowflake, the real production target

The author's tables are in Snowflake. It is not built here (§2), but it is the
source this interface must actually survive, so the constraints are recorded
now rather than rediscovered later.

- **Connection shape differs.** Account, user, warehouse, database, schema and
  role — not a libpq DSN. Handled by §5's per-`kind` connection fields. The
  credential-stripping rule is unchanged and absolute.
- **Read-only is a role, not a transaction.** See §7.1.
- **Table lineage may be authoritative rather than advisory.** Snowflake's
  `ACCESS_HISTORY` reports base objects accessed, which would be a genuinely
  better answer than a query plan — `referenced_tables_source:
  "access_history"`, and not marked advisory.

  **This needs verifying before any design depends on it.** `ACCESS_HISTORY` is
  known to populate with material latency, so it is likely unreadable at load
  time, when the provenance record is written. If that holds, the synchronous
  fallback is `EXPLAIN USING JSON` with `referenced_tables_source: "explain"`,
  identical in trust level to Postgres. A design that resolves lineage
  after the fact — backfilling provenance once `ACCESS_HISTORY` catches up —
  would break the hash-protected payload written at training time, so it is not
  a straightforward option.
- **Testing is the hard part**, and the reason Postgres goes first (§2).
  Whatever the Snowflake test strategy turns out to be, it must not weaken the
  100% coverage gate into a skip-if-no-credentials arrangement.

## 9. What this does not fix

`@track` still requires the training set to fit in memory. This design makes
provenance verified; it does not make ConsentML a big-data tool. The README's
"production ML pipelines" claim is better supported after this work but should
not be read as a scale claim.

Per-subject granularity is unchanged: one row per (run, subject), not per
record. Multiple rows for one subject still collapse.

## 10. Testing

The 100% coverage gate rules out skip-if-unavailable — skipped tests erode the
gate silently. Tests run against **a real Postgres service container in CI,
required, not optional.** Testing a database connector against a fake
connection would mostly prove the fake works.

Local development needs Docker, or `CONSENTML_TEST_PG_DSN` pointed at any
scratch instance. This is a real cost to local dev and the main downside of
this design.

Coverage targets:

- a genuine multi-table join yielding correct, sorted `referenced_tables`
- credentials absent from stored provenance, including on connection failure
- `EXPLAIN` degradation leaves `referenced_tables_source: "unavailable"` and
  does not fail the run
- read-only enforcement: a write query is rejected
- empty result, missing subject column, psycopg absent
- v0/v1 → v2 migration backfill produces `{"kind": "legacy", ...}`
- a mixed-payload audit log verifies clean, and `n_legacy_runs` is correct
- `provenance_modified` fires when the provenance column is edited
- `DataFrameSource` parity with the behavior `track.py` has today

## 11. Open items deliberately deferred

- `SnowflakeSource` (§8.1) — the author's real data, next after this.
- Lineage store on Postgres (concurrent writers across machines).
- Streaming / distributed sources.
- Audit export (JSON/PDF) and the docs site, both unrelated to this work.
