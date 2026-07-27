# Postgres Connector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the unverified free-text `data_source` with structured, hash-protected provenance, and let ConsentML read training data directly from Postgres so recorded lineage is true by construction.

**Architecture:** A `Source` protocol returns a single `SourceResult(payload, subject_ids, provenance)`; `@track` calls `source.load()`, injects `payload` into the training function, and records `provenance` as JSON in a new schema-v2 column whose SHA-256 goes into the hash-protected audit payload. `PostgresSource` runs arbitrary read-only SQL and derives an advisory table list from `EXPLAIN (FORMAT JSON)`.

**Tech Stack:** Python 3.10+, pandas, SQLite (lineage store), psycopg 3 (optional extra), pytest, GitHub Actions with a Postgres service container.

**Spec:** `docs/superpowers/specs/2026-07-26-postgres-connector-design.md`

---

## Deviation from the spec, resolved here

The spec did not address what happens to **v0 databases** once `SCHEMA_VERSION`
becomes 2. `_copy_into_v1()` currently migrates v0 → v1 only. Task 3 replaces it
with `_copy_into_v2()`, which reads either a v0 or a v1 source and writes v2 —
so both old formats reach the current schema in one step and the week-8 v0 tests
keep their value.

The spec's §4 `SourceResult` has exactly three fields, so `subject_id_col` has
nowhere to live in it. Task 1 therefore **drops the `subject_id_col` column**
from `training_runs` and records it inside `provenance`, where each source
describes how it identified subjects. Legacy migration preserves it as
`{"kind": "legacy", "label": ..., "subject_id_col": ...}` — lossless.

## File structure

**Create:**

| File | Responsibility |
|---|---|
| `src/consentml/sources/__init__.py` | Re-export `Source`, `SourceResult`, `DataFrameSource`, `PostgresSource` |
| `src/consentml/sources/base.py` | `Source` protocol, `SourceResult` dataclass |
| `src/consentml/sources/dataframe.py` | `DataFrameSource` |
| `src/consentml/sources/postgres.py` | `PostgresSource`, DSN sanitizing, EXPLAIN parsing |
| `tests/test_sources_dataframe.py` | `DataFrameSource` behavior |
| `tests/test_sources_postgres.py` | `PostgresSource` against a real Postgres |

**Modify:**

| File | Change |
|---|---|
| `src/consentml/store.py` | Schema v2: `provenance` column, drop `subject_id_col`; `provenance_sha256` in the audit payload |
| `src/consentml/verify.py` | `provenance_modified` finding, `n_legacy_runs` on the report |
| `src/consentml/migrate.py` | v0 **and** v1 → v2 |
| `src/consentml/track.py` | `source=` instead of `data_source=`/`subject_id_col=` |
| `src/consentml/revoke.py` | `AffectedModel.data_source` → `provenance` |
| `src/consentml/cli.py` | Report legacy (unchecked) runs in the verify summary |
| `src/consentml/__init__.py` | Export the source types |
| `tests/conftest.py` | v1 database builder, Postgres fixtures |
| `pyproject.toml` | `postgres` extra |
| `.github/workflows/ci.yml` | Postgres service container |
| `README.md`, `examples/consentml_demo.ipynb` | New API |

---

## Task 1: Schema v2 — provenance replaces data_source

**Files:**
- Modify: `src/consentml/store.py`
- Modify: `src/consentml/track.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_store.py`:

```python
import hashlib
import json
import sqlite3

from consentml.store import LineageStore, provenance_hash, provenance_text


def test_provenance_is_stored_as_sorted_json(tmp_path):
    store = LineageStore(db_path=tmp_path / "l.db")
    run_id = store.record_training_run(
        model_name="m",
        model_hash="mh",
        provenance={"kind": "dataframe", "label": "clinic.patients", "n_rows": 2},
        subject_ids_hashed=True,
        subject_id_values=["a", "b"],
        started_at="t0",
        finished_at="t1",
    )
    stored = store._conn.execute(
        "SELECT provenance FROM training_runs WHERE run_id = ?", (run_id,)
    ).fetchone()[0]
    assert json.loads(stored) == {
        "kind": "dataframe", "label": "clinic.patients", "n_rows": 2
    }
    assert stored == json.dumps(json.loads(stored), sort_keys=True)
    store.close()


def test_audit_payload_carries_provenance_sha256_not_data_source(tmp_path):
    store = LineageStore(db_path=tmp_path / "l.db")
    provenance = {"kind": "dataframe", "label": "x", "n_rows": 1}
    store.record_training_run(
        model_name="m",
        model_hash="mh",
        provenance=provenance,
        subject_ids_hashed=True,
        subject_id_values=["a"],
        started_at="t0",
        finished_at="t1",
    )
    payload = json.loads(store.audit_entries()[0]["payload"])
    assert "data_source" not in payload
    assert payload["provenance_sha256"] == provenance_hash(
        provenance_text(provenance)
    )
    store.close()


def test_schema_version_is_2(tmp_path):
    store = LineageStore(db_path=tmp_path / "l.db")
    assert store.schema_version == 2
    assert store._conn.execute("PRAGMA user_version").fetchone()[0] == 2
    cols = [c[1] for c in store._conn.execute("PRAGMA table_info(training_runs)")]
    assert "provenance" in cols
    assert "data_source" not in cols
    assert "subject_id_col" not in cols
    store.close()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_store.py -k "provenance or schema_version_is_2" -v`

Expected: FAIL — `ImportError: cannot import name 'provenance_hash' from 'consentml.store'`

- [ ] **Step 3: Implement the schema change**

In `src/consentml/store.py`, change `SCHEMA_VERSION` and the two column lists:

```python
GENESIS_HASH = "0" * 64
SCHEMA_VERSION = 2

_RUN_COLS = [
    "run_id", "model_name", "model_hash", "provenance",
    "subject_ids_hashed", "n_subjects", "started_at", "finished_at",
]
```

In `_SCHEMA`, replace the `training_runs` definition (leave `subjects`,
`subject_index`, its two indexes, and `audit_log` exactly as they are):

```sql
CREATE TABLE IF NOT EXISTS training_runs (
    run_pk INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    model_name TEXT NOT NULL,
    model_hash TEXT NOT NULL,
    provenance TEXT NOT NULL,
    subject_ids_hashed INTEGER NOT NULL,
    n_subjects INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);
```

Add these two module-level helpers after `default_db_path()`:

```python
def provenance_text(provenance: dict) -> str:
    """Canonical serialization of a provenance record.

    sort_keys is what makes the hash stable: two dicts with the same content
    must produce the same text, or verification would report a false
    provenance_modified on every run.
    """
    return json.dumps(provenance, sort_keys=True)


def provenance_hash(text) -> str | None:
    """SHA-256 of stored provenance text, or None if it isn't text.

    Returns None rather than raising for non-str input: the value comes
    straight out of a database column an attacker may have replaced with a
    BLOB or an integer, and verify_audit_log() must never raise on hostile
    database contents. A None here reports as provenance_modified.
    """
    if not isinstance(text, str):
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
```

Replace `record_training_run`'s signature and body (lines 124–180) with:

```python
    def record_training_run(
        self,
        *,
        model_name,
        model_hash,
        provenance,
        subject_ids_hashed,
        subject_id_values,
        started_at,
        finished_at,
    ) -> str:
        """Record one training run, its subject index rows, and an audit
        entry, in a single transaction. Returns the new run_id."""
        self._require_writable()
        run_id = str(uuid.uuid4())
        text = provenance_text(provenance)
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO training_runs (run_id, model_name, model_hash, "
                "provenance, subject_ids_hashed, n_subjects, "
                "started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    model_name,
                    model_hash,
                    text,
                    int(subject_ids_hashed),
                    len(subject_id_values),
                    started_at,
                    finished_at,
                ),
            )
            run_pk = cursor.lastrowid
            self._conn.executemany(
                "INSERT OR IGNORE INTO subjects (subject_key) VALUES (?)",
                [(v,) for v in subject_id_values],
            )
            self._conn.executemany(
                "INSERT INTO subject_index (run_pk, subject_pk) "
                "SELECT ?, subject_pk FROM subjects WHERE subject_key = ?",
                [(run_pk, v) for v in subject_id_values],
            )
            self._append_audit_entry(
                event_type="training_run",
                payload=json.dumps(
                    {
                        "run_id": run_id,
                        "model_name": model_name,
                        "model_hash": model_hash,
                        "provenance_sha256": provenance_hash(text),
                        "n_subjects": len(subject_id_values),
                    },
                    sort_keys=True,
                ),
            )
        return run_id
```

Update the module docstring's table list line to mention `provenance`:

```python
"""SQLite-backed lineage store.

Four tables:
- training_runs: one row per decorated training execution. Provenance is a
  JSON document whose SHA-256 is recorded in the audit log, so edits to it
  are detectable.
- subjects: each distinct subject key, stored once.
- subject_index: one row per (run, subject) pair, by integer foreign key.
- audit_log: append-only, hash-chained event log.

Schema version lives in PRAGMA user_version. Versions 0 and 1 predate the
provenance column; they can be read but not written -- see consentml.migrate.
"""
```

- [ ] **Step 4: Update `track.py` to pass provenance (bridge only)**

`track.py` still takes `data_source`; it just wraps it. Task 6 replaces this
entirely. In `src/consentml/track.py`, replace the `store.record_training_run`
call (lines 57–66) with:

```python
                store.record_training_run(
                    model_name=model_name,
                    model_hash=model_hash,
                    provenance={
                        "kind": "dataframe",
                        "label": data_source,
                        "subject_id_col": subject_id_col,
                        "n_rows": int(len(df)),
                    },
                    subject_ids_hashed=hash_subject_ids,
                    subject_id_values=subject_values,
                    started_at=started_at,
                    finished_at=finished_at,
                )
```

- [ ] **Step 5: Fix the two remaining `data_source` readers**

Exactly two modules read the dropped column. Both get their real treatment
later — this step only stops them raising `no such column`.

In `src/consentml/revoke.py`, change the `AffectedModel` field `data_source:
str` to `provenance: str` and the construction line
`data_source=r["data_source"],` to `provenance=r["provenance"],`. Task 6 turns
this into a parsed dict; a raw string is enough to keep the suite running now.

In `src/consentml/migrate.py`, leave `_RUN_COLS_V0` alone — it reads the *v0*
source database, which still has `data_source`. Task 3 rewrites this module.

In `tests/`, update any assertion on `data_source` to `provenance` and any
`store.record_training_run(data_source="s", subject_id_col="c", ...)` call to
`store.record_training_run(provenance={"kind": "dataframe", "label": "s"}, ...)`.

Run: `.venv/bin/python -m pytest -q`

Expected: `tests/test_migrate.py` still failing (Task 3 fixes it properly);
everything else passing.

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_store.py -v`

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/consentml/store.py src/consentml/track.py tests/test_store.py
git commit -m "feat: schema v2 stores structured provenance, hashed into the audit payload"
```

---

## Task 2: Verification detects provenance tampering

**Files:**
- Modify: `src/consentml/verify.py`
- Test: `tests/test_verify.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_verify.py`:

```python
import json
import sqlite3

from consentml import verify_audit_log
from consentml.store import LineageStore


def _one_run(db_path, provenance=None):
    store = LineageStore(db_path=db_path)
    store.record_training_run(
        model_name="m",
        model_hash="mh",
        provenance=provenance or {"kind": "dataframe", "label": "x", "n_rows": 1},
        subject_ids_hashed=True,
        subject_id_values=["a"],
        started_at="t0",
        finished_at="t1",
    )
    store.close()


def test_editing_provenance_is_detected(tmp_path):
    db = tmp_path / "l.db"
    _one_run(db)
    assert verify_audit_log(db_path=db).ok

    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE training_runs SET provenance = ?",
        (json.dumps({"kind": "dataframe", "label": "somewhere-else", "n_rows": 1},
                    sort_keys=True),),
    )
    conn.commit()
    conn.close()

    report = verify_audit_log(db_path=db)
    assert not report.ok
    assert [f.code for f in report.findings] == ["provenance_modified"]


def test_provenance_replaced_with_a_blob_is_detected_not_raised(tmp_path):
    db = tmp_path / "l.db"
    _one_run(db)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE training_runs SET provenance = ?", (b"\xff\xfe",))
    conn.commit()
    conn.close()

    report = verify_audit_log(db_path=db)
    assert [f.code for f in report.findings] == ["provenance_modified"]


def test_clean_v2_database_reports_no_legacy_runs(tmp_path):
    db = tmp_path / "l.db"
    _one_run(db)
    report = verify_audit_log(db_path=db)
    assert report.ok
    assert report.n_legacy_runs == 0
    assert report.to_dict()["n_legacy_runs"] == 0
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_verify.py -k "provenance or legacy_runs" -v`

Expected: FAIL — `AttributeError: 'VerificationReport' object has no attribute 'n_legacy_runs'`

- [ ] **Step 3: Implement**

In `src/consentml/verify.py`, extend the existing store import (line 19) from:

```python
from consentml.store import GENESIS_HASH, LineageStore, default_db_path
```

to:

```python
from consentml.store import (
    GENESIS_HASH,
    LineageStore,
    default_db_path,
    provenance_hash,
)
```

Add the field to `VerificationReport` (after `generated_at`, with a default so
existing construction sites stay valid) and surface it in `to_dict`:

```python
@dataclass
class VerificationReport:
    ok: bool
    n_entries: int
    head_hash: str
    findings: list
    generated_at: str
    n_legacy_runs: int = 0

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "n_entries": self.n_entries,
            "head_hash": self.head_hash,
            "findings": [asdict(f) for f in self.findings],
            "generated_at": self.generated_at,
            "n_legacy_runs": self.n_legacy_runs,
        }
```

`_check_references` must now return a count alongside its findings. Replace its
signature and docstring (lines 140–148) with:

```python
def _check_references(entries, parsed, store) -> tuple[list, int]:
    """Compare training_run entries against the live tables.

    Revocation entries are deliberately not cross-checked: their
    n_affected_runs was point-in-time and legitimately differs once later
    runs are recorded.

    Returns (findings, n_legacy_runs). A legacy run is one whose audit payload
    predates provenance hashing -- its provenance was backfilled by migration
    and is NOT hash-protected, so it is counted and reported rather than
    silently passing as if it had been checked.
    """
    findings = []
    logged_run_ids = set()
    n_legacy = 0
```

Change its final line (currently `return findings`, line 247) to:

```python
    return findings, n_legacy
```

Insert the provenance check immediately after the existing `run_modified`
loop (the `for field in ("model_hash", "n_subjects"):` block):

```python
        if "provenance_sha256" in payload:
            if provenance_hash(run["provenance"]) != payload["provenance_sha256"]:
                findings.append(
                    VerificationFinding(
                        entry_id=entry["id"],
                        code="provenance_modified",
                        detail=(
                            f"run {run_id}: provenance in training_runs does "
                            "not match the hash recorded in the audit log"
                        ),
                    )
                )
        else:
            # Pre-v2 entry: its payload was hashed before provenance existed
            # and must never be rewritten (see migrate.py), so there is
            # nothing to check it against. Counted so the report can say so
            # rather than implying it verified something it did not.
            n_legacy += 1
```

Update the call site inside `verify_audit_log`:

```python
        reference_findings, n_legacy = _check_references(entries, parsed, store)
        findings += reference_findings
```

and pass the count into the returned report:

```python
        return VerificationReport(
            ok=not findings,
            n_entries=len(entries),
            head_hash=head_hash,
            findings=findings,
            generated_at=datetime.now(timezone.utc).isoformat(),
            n_legacy_runs=n_legacy,
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_verify.py -v`

Expected: PASS

- [ ] **Step 5: Report legacy runs in the CLI**

In `src/consentml/cli.py`, `_print_verify_summary`, add after the `if
report.ok:` branch's print and before `print(f"head: ...")`:

```python
    if report.n_legacy_runs:
        print(
            f"note: {report.n_legacy_runs} run(s) predate provenance hashing; "
            "their provenance was not verified."
        )
```

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/python -m pytest -q`

Expected: migration tests still failing (Task 3); everything else passing.

- [ ] **Step 7: Commit**

```bash
git add src/consentml/verify.py src/consentml/cli.py tests/test_verify.py
git commit -m "feat: verification detects provenance tampering and counts legacy runs"
```

---

## Task 3: Migrate v0 and v1 databases to v2

**Files:**
- Modify: `src/consentml/migrate.py`
- Modify: `tests/conftest.py`
- Test: `tests/test_migrate.py`

- [ ] **Step 1: Add a v1 database builder to conftest**

Append to `tests/conftest.py`:

```python
_V1_SCHEMA = """
CREATE TABLE training_runs (
    run_pk INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    model_name TEXT NOT NULL,
    model_hash TEXT NOT NULL,
    data_source TEXT NOT NULL,
    subject_id_col TEXT NOT NULL,
    subject_ids_hashed INTEGER NOT NULL,
    n_subjects INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);
CREATE TABLE subjects (
    subject_pk INTEGER PRIMARY KEY,
    subject_key TEXT NOT NULL UNIQUE
);
CREATE TABLE subject_index (
    run_pk INTEGER NOT NULL REFERENCES training_runs(run_pk),
    subject_pk INTEGER NOT NULL REFERENCES subjects(subject_pk)
);
CREATE INDEX idx_si_subject ON subject_index(subject_pk);
CREATE INDEX idx_si_run ON subject_index(run_pk);
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""


def build_v1_db(path, runs=(("churn_v3", ("h1", "h2")),)):
    """Write a schema-v1 database with a valid hash chain. Returns run_ids."""
    conn = sqlite3.connect(path)
    conn.executescript(_V1_SCHEMA)
    conn.execute("PRAGMA user_version = 1")
    run_ids, prev = [], GENESIS
    for i, (model_name, subjects) in enumerate(runs):
        run_id = f"run-{i}"
        run_ids.append(run_id)
        started = f"2026-07-{i + 1:02d}T00:00:00+00:00"
        cur = conn.execute(
            "INSERT INTO training_runs (run_id, model_name, model_hash, "
            "data_source, subject_id_col, subject_ids_hashed, n_subjects, "
            "started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, model_name, f"hash_{i}", "postgres://prod/customers",
             "email", 1, len(subjects), started, started),
        )
        run_pk = cur.lastrowid
        conn.executemany(
            "INSERT OR IGNORE INTO subjects (subject_key) VALUES (?)",
            [(s,) for s in subjects],
        )
        conn.executemany(
            "INSERT INTO subject_index (run_pk, subject_pk) "
            "SELECT ?, subject_pk FROM subjects WHERE subject_key = ?",
            [(run_pk, s) for s in subjects],
        )
        timestamp = f"2026-07-{i + 1:02d}T00:00:01+00:00"
        payload = json.dumps(
            {
                "run_id": run_id,
                "model_name": model_name,
                "model_hash": f"hash_{i}",
                "data_source": "postgres://prod/customers",
                "n_subjects": len(subjects),
            },
            sort_keys=True,
        )
        entry_hash = hashlib.sha256(
            (prev + timestamp + "training_run" + payload).encode("utf-8")
        ).hexdigest()
        conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, payload, prev_hash, "
            "entry_hash) VALUES (?, ?, ?, ?, ?)",
            (timestamp, "training_run", payload, prev, entry_hash),
        )
        prev = entry_hash
    conn.commit()
    conn.close()
    return run_ids


@pytest.fixture
def v1_db(tmp_path):
    """A schema-v1 database with two runs sharing a subject."""
    path = tmp_path / "v1.db"
    build_v1_db(path, runs=(("churn_v3", ("h1", "h2")), ("upsell", ("h1", "h3"))))
    return path
```

- [ ] **Step 2: Write the failing test**

Add to `tests/test_migrate.py`:

```python
import json
import sqlite3

from consentml import migrate_database, verify_audit_log


def _provenances(db):
    conn = sqlite3.connect(db)
    try:
        return [json.loads(r[0])
                for r in conn.execute("SELECT provenance FROM training_runs")]
    finally:
        conn.close()


def test_v1_migrates_to_v2_with_legacy_provenance(v1_db):
    result = migrate_database(db_path=v1_db)
    assert result.migrated, result.error
    conn = sqlite3.connect(v1_db)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    conn.close()
    assert _provenances(v1_db) == [
        {"kind": "legacy", "label": "postgres://prod/customers",
         "subject_id_col": "email"},
        {"kind": "legacy", "label": "postgres://prod/customers",
         "subject_id_col": "email"},
    ]


def test_v0_migrates_straight_to_v2(legacy_db):
    result = migrate_database(db_path=legacy_db)
    assert result.migrated, result.error
    conn = sqlite3.connect(legacy_db)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
    conn.close()
    assert all(p["kind"] == "legacy" for p in _provenances(legacy_db))


def test_migration_leaves_the_audit_log_byte_identical(v1_db):
    conn = sqlite3.connect(v1_db)
    before = conn.execute(
        "SELECT id, timestamp, event_type, payload, prev_hash, entry_hash "
        "FROM audit_log ORDER BY id"
    ).fetchall()
    conn.close()

    assert migrate_database(db_path=v1_db).migrated

    conn = sqlite3.connect(v1_db)
    after = conn.execute(
        "SELECT id, timestamp, event_type, payload, prev_hash, entry_hash "
        "FROM audit_log ORDER BY id"
    ).fetchall()
    conn.close()
    assert after == before


def test_migrated_database_verifies_clean_and_counts_legacy_runs(v1_db):
    assert migrate_database(db_path=v1_db).migrated
    report = verify_audit_log(db_path=v1_db)
    assert report.ok, [f.detail for f in report.findings]
    assert report.n_legacy_runs == 2
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_migrate.py -k "v2 or byte_identical or legacy_runs" -v`

Expected: FAIL — `sqlite3.OperationalError: table training_runs has no column named provenance`

- [ ] **Step 4: Implement**

In `src/consentml/migrate.py`, replace `_RUN_COLS_V0` and `_copy_into_v1` with a
version-dispatching copy. Replace lines 21–104 with:

```python
_LEGACY_RUN_COLS = (
    "run_id, model_name, model_hash, data_source, subject_id_col, "
    "subject_ids_hashed, n_subjects, started_at, finished_at"
)

_V2_RUN_COLS = (
    "run_id, model_name, model_hash, provenance, "
    "subject_ids_hashed, n_subjects, started_at, finished_at"
)


def _legacy_provenance(data_source, subject_id_col) -> str:
    """Represent a pre-v2 data_source faithfully.

    Nothing is invented: the old free-text value is preserved verbatim under
    a kind that says exactly where it came from, so a reader can tell a
    migrated assertion from a connector-verified record.
    """
    return provenance_text(
        {
            "kind": "legacy",
            "label": data_source,
            "subject_id_col": subject_id_col,
        }
    )


def _subject_rows(src, version):
    """Yield (run_id, subject_key) for either source schema.

    v0 stores the key inline on subject_index; v1 interns it. Normalizing
    here means the insert path below is identical for both.
    """
    if version == 0:
        return src.execute("SELECT run_id, subject_id_hash FROM subject_index")
    return src.execute(
        "SELECT r.run_id, s.subject_key FROM subject_index si "
        "JOIN training_runs r ON r.run_pk = si.run_pk "
        "JOIN subjects s ON s.subject_pk = si.subject_pk"
    )


def _copy_into_v2(src_path, dst_path, src_version):
    """Build a v2 database at dst_path from a v0 or v1 database at src_path.

    The audit_log is copied verbatim and never rewritten: its entries were
    hashed over payloads containing data_source, so regenerating them would
    invalidate every entry hash and turn a clean database into a failing one.
    A migrated database therefore holds pre-v2 payloads permanently, and
    verify_audit_log() treats them as legacy rather than checking provenance
    it has no recorded hash for.
    """
    dst = sqlite3.connect(dst_path)
    try:
        dst.executescript(_SCHEMA)
        dst.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        src = sqlite3.connect(src_path)
        try:
            with dst:
                for row in src.execute(
                    f"SELECT {_LEGACY_RUN_COLS} FROM training_runs"
                ):
                    (run_id, model_name, model_hash, data_source,
                     subject_id_col, hashed, n_subjects, started, finished) = row
                    dst.execute(
                        f"INSERT INTO training_runs ({_V2_RUN_COLS}) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            run_id, model_name, model_hash,
                            _legacy_provenance(data_source, subject_id_col),
                            hashed, n_subjects, started, finished,
                        ),
                    )
                subject_rows = list(_subject_rows(src, src_version))
                # Intern the keys: each distinct value stored once...
                dst.executemany(
                    "INSERT OR IGNORE INTO subjects (subject_key) VALUES (?)",
                    [(key,) for _, key in subject_rows],
                )
                # ...but one index row per original row, so per-run counts
                # are preserved exactly.
                #
                # Measured ~8us/row with this per-row executemany, each doing
                # a two-table lookup. A set-based rewrite (ATTACH the source
                # db, single INSERT...SELECT...JOIN) measured ~10x faster.
                # Deliberately not taken: migration is a one-time offline
                # operation, and this is the one piece of code whose entire
                # job is not corrupting an audit trail, so the simpler, more
                # obviously-correct version is worth the wall-clock time.
                dst.executemany(
                    "INSERT INTO subject_index (run_pk, subject_pk) "
                    "SELECT r.run_pk, s.subject_pk FROM training_runs r, subjects s "
                    "WHERE r.run_id = ? AND s.subject_key = ?",
                    subject_rows,
                )
                for row in src.execute(
                    "SELECT id, timestamp, event_type, payload, prev_hash, "
                    "entry_hash FROM audit_log ORDER BY id"
                ):
                    dst.execute(
                        "INSERT INTO audit_log (id, timestamp, event_type, "
                        "payload, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?)",
                        row,
                    )
        finally:
            src.close()
    finally:
        dst.close()
```

Update the import at the top of `migrate.py`:

```python
from consentml.store import (
    SCHEMA_VERSION,
    _SCHEMA,
    default_db_path,
    provenance_text,
)
```

In `_migrate_database`, the `version` read is already in scope. Change the copy
call (line 201) from `_copy_into_v1(db, staging)` to:

```python
            _copy_into_v2(db, staging, version)
```

Update the module docstring's first line:

```python
"""Migrate a v0 or v1 lineage database onto the v2 provenance schema.
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_migrate.py -v`

Expected: PASS

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/python -m pytest -q`

Expected: PASS (revoke tests may need the column rename from Task 1 Step 5 —
if any still fail on `data_source`, fix them mechanically here.)

- [ ] **Step 7: Commit**

```bash
git add src/consentml/migrate.py tests/conftest.py tests/test_migrate.py
git commit -m "feat: migrate v0 and v1 databases to the v2 provenance schema"
```

---

## Task 4: The Source protocol

**Files:**
- Create: `src/consentml/sources/__init__.py`
- Create: `src/consentml/sources/base.py`
- Test: `tests/test_sources_dataframe.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_sources_dataframe.py`:

```python
from consentml.sources import Source, SourceResult


def test_source_result_is_frozen():
    result = SourceResult(payload=[1, 2], subject_ids=["a"], provenance={"kind": "x"})
    assert result.payload == [1, 2]
    assert result.subject_ids == ["a"]
    assert result.provenance == {"kind": "x"}
    try:
        result.payload = [3]
    except AttributeError:
        pass
    else:
        raise AssertionError("SourceResult should be frozen")


def test_any_object_with_load_satisfies_the_protocol():
    class Fake:
        def load(self):
            return SourceResult(payload=None, subject_ids=[], provenance={})

    assert isinstance(Fake(), Source)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_sources_dataframe.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'consentml.sources'`

- [ ] **Step 3: Implement**

Create `src/consentml/sources/base.py`:

```python
"""The Source interface: where training data and its provenance come from.

A Source is asked for everything in one call. That is the whole point: the
payload the model trains on and the subject IDs recorded as lineage come out
of a single observation of the underlying system, so they cannot disagree.
Splitting this into separate calls would reintroduce exactly the skew this
design exists to eliminate -- two queries against a live table at two points
in time, with nothing to signal that they diverged.
"""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class SourceResult:
    payload: object
    """Handed to the training function untouched. ConsentML never inspects
    it, so a pandas DataFrame, a Spark DataFrame, or anything else works."""

    subject_ids: list
    """Distinct subject identifiers, before hashing."""

    provenance: dict = field(default_factory=dict)
    """JSON-serializable record of where the data came from. Discriminated by
    a "kind" key; every other field is that kind's business."""


@runtime_checkable
class Source(Protocol):
    def load(self) -> SourceResult: ...
```

Create `src/consentml/sources/__init__.py`:

```python
"""Data sources for @track."""

from consentml.sources.base import Source, SourceResult

__all__ = ["Source", "SourceResult"]
```

Task 5 adds `DataFrameSource` to both lines. `PostgresSource` is deliberately
**never** re-exported here — it is imported from `consentml.sources.postgres`
directly, so `import consentml` never touches psycopg.

- [ ] **Step 4: Run the test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_sources_dataframe.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/consentml/sources/ tests/test_sources_dataframe.py
git commit -m "feat: Source protocol and SourceResult"
```

---

## Task 5: DataFrameSource

**Files:**
- Modify: `src/consentml/sources/dataframe.py`
- Modify: `src/consentml/sources/__init__.py`
- Test: `tests/test_sources_dataframe.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sources_dataframe.py`:

```python
import pandas as pd
import pytest

from consentml import ConsentMLError
from consentml.sources import DataFrameSource


def _df():
    return pd.DataFrame({"pid": ["P1", "P1", "P2"], "age": [30, 31, 40]})


def test_dedupes_subjects_and_passes_the_frame_through():
    df = _df()
    result = DataFrameSource(df, subject_id_col="pid").load()
    assert result.payload is df
    assert sorted(result.subject_ids) == ["P1", "P2"]


def test_provenance_records_label_and_row_count():
    result = DataFrameSource(
        _df(), subject_id_col="pid", label="clinic.patients"
    ).load()
    assert result.provenance == {
        "kind": "dataframe",
        "label": "clinic.patients",
        "subject_id_col": "pid",
        "n_rows": 3,
    }


def test_label_is_optional_and_defaults_to_none():
    result = DataFrameSource(_df(), subject_id_col="pid").load()
    assert result.provenance["label"] is None


def test_subject_ids_are_stringified():
    df = pd.DataFrame({"pid": [1, 2], "x": [0, 1]})
    result = DataFrameSource(df, subject_id_col="pid").load()
    assert sorted(result.subject_ids) == ["1", "2"]


def test_missing_subject_column_raises():
    with pytest.raises(ConsentMLError, match="nope"):
        DataFrameSource(_df(), subject_id_col="nope").load()


def test_empty_frame_raises():
    empty = pd.DataFrame({"pid": [], "age": []})
    with pytest.raises(ConsentMLError, match="no rows"):
        DataFrameSource(empty, subject_id_col="pid").load()


def test_non_dataframe_raises():
    with pytest.raises(ConsentMLError, match="DataFrame"):
        DataFrameSource([1, 2, 3], subject_id_col="pid").load()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_sources_dataframe.py -v`

Expected: FAIL — `ImportError: cannot import name 'DataFrameSource'`

- [ ] **Step 3: Implement**

Create `src/consentml/sources/dataframe.py`:

```python
"""In-memory pandas DataFrame source.

The validation @track used to do inline lives here now: this is the one place
that knows the payload is a DataFrame, so it is the one place entitled to
check its shape.
"""

import pandas as pd

from consentml.errors import ConsentMLError
from consentml.sources.base import SourceResult


class DataFrameSource:
    """Track a DataFrame the caller already has in memory.

    `label` is caller-asserted and unverifiable -- ConsentML has no way to
    check where an in-memory frame came from. It is recorded under
    kind="dataframe" precisely so a reader can tell it apart from a
    connector-verified record.
    """

    def __init__(self, df, *, subject_id_col, label=None):
        self._df = df
        self._subject_id_col = subject_id_col
        self._label = label

    def load(self) -> SourceResult:
        if not isinstance(self._df, pd.DataFrame):
            raise ConsentMLError(
                f"DataFrameSource needs a pandas DataFrame, got "
                f"{type(self._df).__name__}."
            )
        if self._subject_id_col not in self._df.columns:
            raise ConsentMLError(
                f"Subject ID column '{self._subject_id_col}' not found in "
                f"training DataFrame (columns: {list(self._df.columns)})."
            )
        if len(self._df) == 0:
            raise ConsentMLError(
                "Training DataFrame has no rows; refusing to record a "
                "training run over zero subjects."
            )
        subject_ids = self._df[self._subject_id_col].astype(str).unique().tolist()
        return SourceResult(
            payload=self._df,
            subject_ids=subject_ids,
            provenance={
                "kind": "dataframe",
                "label": self._label,
                "subject_id_col": self._subject_id_col,
                "n_rows": int(len(self._df)),
            },
        )
```

Add the export to `src/consentml/sources/__init__.py`:

```python
"""Data sources for @track."""

from consentml.sources.base import Source, SourceResult
from consentml.sources.dataframe import DataFrameSource

__all__ = ["Source", "SourceResult", "DataFrameSource"]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_sources_dataframe.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/consentml/sources/ tests/test_sources_dataframe.py
git commit -m "feat: DataFrameSource"
```

---

## Task 6: Rewire @track onto Source (breaking API change)

**Files:**
- Modify: `src/consentml/track.py`
- Modify: `src/consentml/revoke.py`
- Modify: `src/consentml/__init__.py`
- Test: `tests/test_track.py`, `tests/test_revoke.py`, `tests/test_integration.py`

- [ ] **Step 1: Write the failing test**

Replace the contents of `tests/test_track.py` with:

```python
import pandas as pd
import pytest

from consentml import ConsentMLError, track
from consentml.sources import DataFrameSource, SourceResult
from consentml.store import LineageStore


def _df():
    return pd.DataFrame({"pid": ["P1", "P2"], "x": [1, 2]})


def test_payload_is_injected_into_the_training_function(tmp_path):
    seen = {}

    @track(model_name="m", source=DataFrameSource(_df(), subject_id_col="pid"),
           db_path=tmp_path / "l.db")
    def train(df):
        seen["df"] = df
        return "model"

    assert train() == "model"
    assert list(seen["df"]["pid"]) == ["P1", "P2"]


def test_extra_arguments_are_passed_through(tmp_path):
    @track(model_name="m", source=DataFrameSource(_df(), subject_id_col="pid"),
           db_path=tmp_path / "l.db")
    def train(df, *, epochs):
        return epochs

    assert train(epochs=7) == 7


def test_provenance_from_the_source_is_recorded(tmp_path):
    db = tmp_path / "l.db"

    @track(model_name="m",
           source=DataFrameSource(_df(), subject_id_col="pid",
                                  label="clinic.patients"),
           db_path=db)
    def train(df):
        return "model"

    train()
    store = LineageStore(db_path=db)
    provenance = store._conn.execute(
        "SELECT provenance FROM training_runs"
    ).fetchone()[0]
    store.close()
    assert '"label": "clinic.patients"' in provenance
    assert '"kind": "dataframe"' in provenance


def test_source_failure_happens_before_training(tmp_path):
    called = []

    class Failing:
        def load(self):
            raise ConsentMLError("boom")

    @track(model_name="m", source=Failing(), db_path=tmp_path / "l.db")
    def train(df):
        called.append(True)
        return "model"

    with pytest.raises(ConsentMLError, match="boom"):
        train()
    assert called == []


def test_a_crashed_training_function_records_nothing(tmp_path):
    db = tmp_path / "l.db"

    @track(model_name="m", source=DataFrameSource(_df(), subject_id_col="pid"),
           db_path=db)
    def train(df):
        raise ValueError("training blew up")

    with pytest.raises(ValueError):
        train()
    store = LineageStore(db_path=db)
    assert store._conn.execute("SELECT COUNT(*) FROM training_runs").fetchone()[0] == 0
    store.close()


def test_hash_subject_ids_false_stores_raw_ids(tmp_path):
    db = tmp_path / "l.db"

    @track(model_name="m", source=DataFrameSource(_df(), subject_id_col="pid"),
           hash_subject_ids=False, db_path=db)
    def train(df):
        return "model"

    train()
    store = LineageStore(db_path=db)
    keys = {r[0] for r in store._conn.execute("SELECT subject_key FROM subjects")}
    store.close()
    assert keys == {"P1", "P2"}


def test_any_source_object_works(tmp_path):
    class Custom:
        def load(self):
            return SourceResult(
                payload="anything",
                subject_ids=["s1"],
                provenance={"kind": "custom"},
            )

    @track(model_name="m", source=Custom(), db_path=tmp_path / "l.db")
    def train(payload):
        assert payload == "anything"
        return "model"

    assert train() == "model"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_track.py -v`

Expected: FAIL — `TypeError: track() got an unexpected keyword argument 'source'`

- [ ] **Step 3: Implement**

Replace the whole of `src/consentml/track.py` with:

```python
"""The @track decorator: lineage capture around a training function."""

import functools
import hashlib
import pickle
from datetime import datetime, timezone

from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


def track(*, model_name, source, hash_subject_ids=True, db_path=None):
    """Record training-data lineage for the decorated training function.

    The source is loaded first and its payload passed to the decorated
    function as the first positional argument -- the caller does not supply
    training data. Loading first means a bad source fails immediately rather
    than after training has already run.

    The model is hashed (SHA-256 of its pickle) and the lineage record is
    written only after training completes, so a training run that raises
    leaves nothing behind.
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = source.load()
            subject_values = [
                hash_subject_id(s) if hash_subject_ids else s
                for s in result.subject_ids
            ]

            started_at = datetime.now(timezone.utc).isoformat()
            model = fn(result.payload, *args, **kwargs)
            finished_at = datetime.now(timezone.utc).isoformat()

            model_hash = hashlib.sha256(pickle.dumps(model)).hexdigest()
            store = LineageStore(db_path=db_path)
            try:
                store.record_training_run(
                    model_name=model_name,
                    model_hash=model_hash,
                    provenance=result.provenance,
                    subject_ids_hashed=hash_subject_ids,
                    subject_id_values=subject_values,
                    started_at=started_at,
                    finished_at=finished_at,
                )
            finally:
                store.close()
            return model

        return wrapper

    return decorator
```

In `src/consentml/revoke.py`, Task 1 Step 5 left `provenance: str` carrying raw
JSON text. Give it its real type — change the `AffectedModel` field to:

```python
    provenance: dict
```

add the JSON import at the top (`import json`), and replace the
`provenance=r["provenance"],` line inside the `AffectedModel(...)`
construction with:

```python
                    provenance=_parse_provenance(r["provenance"]),
```

Add this helper above the `revoke()` function:

```python
def _parse_provenance(text):
    """Provenance as a dict, or a marker if the column is unreadable.

    revoke() reports; it does not verify. A provenance value that isn't
    parseable JSON is a tampering signal, but reporting it is
    verify_audit_log()'s job -- here it must not crash a revocation report
    that is otherwise correct and legally required.
    """
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return {"kind": "unreadable"}
    return parsed if isinstance(parsed, dict) else {"kind": "unreadable"}
```

In `src/consentml/__init__.py`, add the source exports:

```python
"""ConsentML: training-data lineage and consent-revocation reporting."""

from consentml.errors import ConsentMLError
from consentml.migrate import MigrationResult, migrate_database
from consentml.revoke import AffectedModel, AffectedModelsReport, revoke
from consentml.sources import DataFrameSource, Source, SourceResult
from consentml.track import track
from consentml.verify import (
    VerificationFinding,
    VerificationReport,
    verify_audit_log,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "track",
    "revoke",
    "verify_audit_log",
    "migrate_database",
    "Source",
    "SourceResult",
    "DataFrameSource",
    "AffectedModel",
    "AffectedModelsReport",
    "VerificationFinding",
    "VerificationReport",
    "MigrationResult",
    "ConsentMLError",
    "__version__",
]
```

- [ ] **Step 4: Update every other test that calls @track**

`tests/test_revoke.py` and `tests/test_integration.py` construct training runs
with the old signature. Convert each call from:

```python
@track(data_source="s", subject_id_col="pid", model_name="m", db_path=db)
def train(df): ...
train(df)
```

to:

```python
@track(model_name="m", source=DataFrameSource(df, subject_id_col="pid",
                                              label="s"), db_path=db)
def train(df): ...
train()
```

and change any assertion on `m.data_source == "s"` to
`m.provenance["label"] == "s"`.

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest -q`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/consentml tests
git commit -m "feat!: @track takes a Source; data_source and subject_id_col are gone"
```

---

## Task 7: Postgres test infrastructure

**Files:**
- Modify: `pyproject.toml`
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/conftest.py`
- Create: `docker-compose.test.yml`

- [ ] **Step 1: Add the optional extra**

In `pyproject.toml`, add to `[project.optional-dependencies]`:

```toml
postgres = ["psycopg[binary]>=3.1"]
```

and add `"psycopg[binary]>=3.1"` to the `dev` list so the test suite can import
it.

- [ ] **Step 2: Add the CI service container**

In `.github/workflows/ci.yml`, inside the `test` job, add a `services` block
directly after `runs-on: ubuntu-latest`:

```yaml
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_PASSWORD: consentml
          POSTGRES_DB: consentml_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
```

and add an `env` block to the coverage step so the tests can find it:

```yaml
      - name: Test with coverage gate
        # --cov-fail-under=100 is deliberate. The suite has been at 100% since
        # week 5; letting it slip silently is how the gate stops meaning
        # anything. If a line genuinely cannot be covered, argue it in review
        # rather than lowering this number.
        env:
          CONSENTML_TEST_PG_DSN: postgresql://postgres:consentml@localhost:5432/consentml_test
        run: |
          pytest --cov=consentml --cov-report=term-missing --cov-fail-under=100
```

- [ ] **Step 3: Add a local Postgres for developers**

Create `docker-compose.test.yml`:

```yaml
# Postgres for the connector tests. The suite does not skip when this is
# absent -- a skipped test would quietly erode the 100% coverage gate -- so
# this needs to be running locally:
#
#   docker compose -f docker-compose.test.yml up -d
#   export CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: consentml
      POSTGRES_DB: consentml_test
    ports:
      - "5432:5432"
```

- [ ] **Step 4: Add the fixtures**

Append to `tests/conftest.py`:

```python
import os


@pytest.fixture(scope="session")
def pg_dsn():
    """DSN for the test Postgres.

    Fails loudly rather than skipping. A skip-if-unavailable fixture would
    let the connector's tests vanish from a run that still reports 100%
    coverage, which is exactly the kind of quiet false clean this project
    exists to prevent.
    """
    dsn = os.environ.get("CONSENTML_TEST_PG_DSN")
    if not dsn:
        raise RuntimeError(
            "CONSENTML_TEST_PG_DSN is not set. Start the test database with "
            "'docker compose -f docker-compose.test.yml up -d' and export "
            "CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost"
            ":5432/consentml_test"
        )
    return dsn


@pytest.fixture
def pg_tables(pg_dsn):
    """A patients/labs pair to join, dropped afterwards."""
    psycopg = pytest.importorskip("psycopg")
    with psycopg.connect(pg_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS labs, patients")
            cur.execute(
                "CREATE TABLE patients ("
                "patient_id text PRIMARY KEY, age int, outcome int)"
            )
            cur.execute("CREATE TABLE labs (patient_id text, ldl int)")
            cur.executemany(
                "INSERT INTO patients VALUES (%s, %s, %s)",
                [("P1", 30, 0), ("P2", 40, 1), ("P3", 50, 0)],
            )
            cur.executemany(
                "INSERT INTO labs VALUES (%s, %s)",
                [("P1", 100), ("P2", 120), ("P3", 140)],
            )
        conn.commit()
    yield pg_dsn
    with psycopg.connect(pg_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS labs, patients")
        conn.commit()
```

- [ ] **Step 5: Verify the fixture works**

```bash
docker compose -f docker-compose.test.yml up -d
```

Then:

```bash
CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest -q
```

Expected: PASS (no connector tests yet — this confirms the fixture imports and
the database is reachable).

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .github/workflows/ci.yml docker-compose.test.yml tests/conftest.py
git commit -m "test: real Postgres for the connector suite, in CI and locally"
```

---

## Task 8: PostgresSource — connection, query, subjects

**Files:**
- Modify: `src/consentml/sources/postgres.py`
- Test: `tests/test_sources_postgres.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_sources_postgres.py`:

```python
import pytest

from consentml import ConsentMLError
from consentml.sources.postgres import PostgresSource

QUERY = """
    SELECT p.patient_id, p.age, l.ldl, p.outcome
    FROM patients p JOIN labs l USING (patient_id)
"""


def test_loads_rows_into_a_dataframe(pg_tables):
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert list(result.payload.columns) == ["patient_id", "age", "ldl", "outcome"]
    assert len(result.payload) == 3


def test_subject_ids_are_distinct_and_stringified(pg_tables):
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert sorted(result.subject_ids) == ["P1", "P2", "P3"]


def test_provenance_records_query_and_hash(pg_tables):
    import hashlib

    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    p = result.provenance
    assert p["kind"] == "postgres"
    assert p["database"] == "consentml_test"
    assert p["query"] == QUERY
    assert p["query_sha256"] == hashlib.sha256(QUERY.encode("utf-8")).hexdigest()
    assert p["n_rows"] == 3


def test_credentials_never_appear_in_provenance(pg_tables):
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    flat = repr(result.provenance)
    assert "consentml@" not in flat
    assert "password" not in flat
    assert "user" not in result.provenance


def test_missing_subject_column_raises(pg_tables):
    with pytest.raises(ConsentMLError, match="nope"):
        PostgresSource(dsn=pg_tables, query=QUERY, subject_id_col="nope").load()


def test_empty_result_raises(pg_tables):
    with pytest.raises(ConsentMLError, match="no rows"):
        PostgresSource(
            dsn=pg_tables,
            query="SELECT * FROM patients WHERE patient_id = 'nobody'",
            subject_id_col="patient_id",
        ).load()


def test_unreachable_host_raises_consentml_error(pg_tables):
    source = PostgresSource(
        dsn="postgresql://nobody@127.0.0.1:1/none",
        query=QUERY,
        subject_id_col="patient_id",
    )
    with pytest.raises(ConsentMLError, match="could not connect"):
        source.load()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest tests/test_sources_postgres.py -v`

Expected: FAIL — `ImportError: cannot import name 'PostgresSource'`

- [ ] **Step 3: Implement**

Create `src/consentml/sources/postgres.py`:

```python
"""Postgres source: ConsentML runs the query, so lineage is not an assertion.

Exception discipline in this module: psycopg errors are caught NARROWLY and
re-raised as ConsentMLError with the original chained. The contract here is
*fail clearly*, not *never raise* -- a broad `except Exception` would swallow
genuine bugs, which is exactly how the exit-2 path was lost twice during
weeks 7-8.
"""

import hashlib

import pandas as pd

from consentml.errors import ConsentMLError
from consentml.sources.base import SourceResult


def _import_psycopg():
    try:
        import psycopg
    except ImportError as exc:
        raise ConsentMLError(
            "PostgresSource needs psycopg. Install it with: "
            "pip install 'consentml[postgres]'"
        ) from exc
    return psycopg


def _safe_conninfo(psycopg, dsn) -> dict:
    """Host, port and database only -- never user, never password.

    Parsed before any connection is opened, so a connection failure cannot
    put a password into a traceback that then lands in a log.
    """
    try:
        parsed = psycopg.conninfo.conninfo_to_dict(dsn)
    except psycopg.ProgrammingError as exc:
        raise ConsentMLError(f"could not parse the Postgres DSN: {exc}") from exc
    port = parsed.get("port")
    return {
        "host": parsed.get("host"),
        "port": int(port) if port is not None else None,
        "database": parsed.get("dbname"),
    }


class PostgresSource:
    """Track a training set read from Postgres with arbitrary SELECT SQL."""

    def __init__(self, *, dsn, query, subject_id_col):
        self._psycopg = _import_psycopg()
        self._dsn = dsn
        self._query = query
        self._subject_id_col = subject_id_col
        self._conninfo = _safe_conninfo(self._psycopg, dsn)

    def load(self) -> SourceResult:
        rows, columns = self._fetch()
        df = pd.DataFrame(rows, columns=columns)
        if self._subject_id_col not in df.columns:
            raise ConsentMLError(
                f"Subject ID column '{self._subject_id_col}' not found in "
                f"the query result (columns: {list(df.columns)})."
            )
        if len(df) == 0:
            raise ConsentMLError(
                "Query returned no rows; refusing to record a training run "
                "over zero subjects."
            )
        subject_ids = df[self._subject_id_col].astype(str).unique().tolist()
        return SourceResult(
            payload=df,
            subject_ids=subject_ids,
            provenance={
                "kind": "postgres",
                **self._conninfo,
                "query": self._query,
                "query_sha256": hashlib.sha256(
                    self._query.encode("utf-8")
                ).hexdigest(),
                "n_rows": int(len(df)),
            },
        )

    def _fetch(self):
        psycopg = self._psycopg
        try:
            conn = psycopg.connect(self._dsn)
        except psycopg.OperationalError as exc:
            raise ConsentMLError(
                f"could not connect to Postgres at "
                f"{self._conninfo['host']}:{self._conninfo['port']}: {exc}"
            ) from exc
        try:
            with conn.cursor() as cur:
                try:
                    cur.execute(self._query)
                    rows = cur.fetchall()
                    columns = [d.name for d in cur.description]
                except psycopg.Error as exc:
                    raise ConsentMLError(
                        f"the training query failed: {exc}"
                    ) from exc
            return rows, columns
        finally:
            conn.close()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest tests/test_sources_postgres.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/consentml/sources/postgres.py tests/test_sources_postgres.py
git commit -m "feat: PostgresSource loads training data and records verified provenance"
```

---

## Task 9: Referenced tables from EXPLAIN

**Files:**
- Modify: `src/consentml/sources/postgres.py`
- Test: `tests/test_sources_postgres.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sources_postgres.py`:

```python
def test_a_join_reports_both_tables(pg_tables):
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert result.provenance["referenced_tables"] == [
        "public.labs",
        "public.patients",
    ]
    assert result.provenance["referenced_tables_source"] == "explain"


def test_single_table_query_reports_one_table(pg_tables):
    result = PostgresSource(
        dsn=pg_tables,
        query="SELECT patient_id, age FROM patients",
        subject_id_col="patient_id",
    ).load()
    assert result.provenance["referenced_tables"] == ["public.patients"]


def test_explain_failure_degrades_without_failing_the_run(pg_tables, monkeypatch):
    from consentml.sources import postgres as pg_module

    def boom(cur, query):
        raise pg_module._explain_failed()

    monkeypatch.setattr(pg_module, "_run_explain", boom)
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert result.provenance["referenced_tables"] is None
    assert result.provenance["referenced_tables_source"] == "unavailable"
    assert len(result.payload) == 3
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest tests/test_sources_postgres.py -k "tables or explain" -v`

Expected: FAIL — `KeyError: 'referenced_tables'`

- [ ] **Step 3: Implement**

Add to `src/consentml/sources/postgres.py`, above the `PostgresSource` class:

```python
class _ExplainUnavailable(Exception):
    """EXPLAIN could not be run or parsed. Never reaches the caller."""


def _explain_failed():
    return _ExplainUnavailable()


def _relations(node, found):
    """Collect schema-qualified relation names from an EXPLAIN plan node.

    Postgres reports the relations itself, so ConsentML never parses SQL.
    The result is advisory: a table the planner optimizes away never appears
    in the plan and so never appears here.
    """
    if isinstance(node, dict):
        name = node.get("Relation Name")
        if name:
            schema = node.get("Schema", "public")
            found.add(f"{schema}.{name}")
        for value in node.values():
            _relations(value, found)
    elif isinstance(node, list):
        for item in node:
            _relations(item, found)
    return found


def _run_explain(cur, query):
    """Return the raw EXPLAIN plan JSON, or raise _ExplainUnavailable."""
    cur.execute("EXPLAIN (FORMAT JSON) " + query)
    row = cur.fetchone()
    if not row or not row[0]:
        raise _ExplainUnavailable()
    return row[0]
```

Replace `PostgresSource._fetch` with a version that explains first, and add
`_referenced_tables`:

```python
    def _referenced_tables(self, cur):
        """(sorted table list, mechanism) -- never raises.

        A failed EXPLAIN must not fail the training run: this list is
        advisory, and advisory data can never break the primary path. It
        also aborts the surrounding transaction in Postgres, so the
        rollback below is required for the real query to run afterwards.
        """
        psycopg = self._psycopg
        try:
            plan = _run_explain(cur, self._query)
        except (_ExplainUnavailable, psycopg.Error):
            cur.connection.rollback()
            return None, "unavailable"
        return sorted(_relations(plan, set())), "explain"

    def _fetch(self):
        psycopg = self._psycopg
        try:
            conn = psycopg.connect(self._dsn)
        except psycopg.OperationalError as exc:
            raise ConsentMLError(
                f"could not connect to Postgres at "
                f"{self._conninfo['host']}:{self._conninfo['port']}: {exc}"
            ) from exc
        try:
            with conn.cursor() as cur:
                tables, mechanism = self._referenced_tables(cur)
                try:
                    cur.execute(self._query)
                    rows = cur.fetchall()
                    columns = [d.name for d in cur.description]
                except psycopg.Error as exc:
                    raise ConsentMLError(
                        f"the training query failed: {exc}"
                    ) from exc
            return rows, columns, tables, mechanism
        finally:
            conn.close()
```

Update `load()` to unpack four values and record the two new fields:

```python
    def load(self) -> SourceResult:
        rows, columns, tables, mechanism = self._fetch()
        df = pd.DataFrame(rows, columns=columns)
        if self._subject_id_col not in df.columns:
            raise ConsentMLError(
                f"Subject ID column '{self._subject_id_col}' not found in "
                f"the query result (columns: {list(df.columns)})."
            )
        if len(df) == 0:
            raise ConsentMLError(
                "Query returned no rows; refusing to record a training run "
                "over zero subjects."
            )
        subject_ids = df[self._subject_id_col].astype(str).unique().tolist()
        return SourceResult(
            payload=df,
            subject_ids=subject_ids,
            provenance={
                "kind": "postgres",
                **self._conninfo,
                "query": self._query,
                "query_sha256": hashlib.sha256(
                    self._query.encode("utf-8")
                ).hexdigest(),
                "referenced_tables": tables,
                "referenced_tables_source": mechanism,
                "n_rows": int(len(df)),
            },
        )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest tests/test_sources_postgres.py -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/consentml/sources/postgres.py tests/test_sources_postgres.py
git commit -m "feat: advisory referenced_tables from EXPLAIN, degrading safely"
```

---

## Task 10: Read-only enforcement

**Files:**
- Modify: `src/consentml/sources/postgres.py`
- Test: `tests/test_sources_postgres.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sources_postgres.py`:

```python
def test_a_write_query_is_rejected(pg_tables):
    source = PostgresSource(
        dsn=pg_tables,
        query="INSERT INTO patients VALUES ('P9', 99, 1) RETURNING patient_id",
        subject_id_col="patient_id",
    )
    with pytest.raises(ConsentMLError):
        source.load()


def test_the_source_database_is_unchanged_after_a_rejected_write(pg_tables):
    import psycopg

    source = PostgresSource(
        dsn=pg_tables,
        query="INSERT INTO patients VALUES ('P9', 99, 1) RETURNING patient_id",
        subject_id_col="patient_id",
    )
    with pytest.raises(ConsentMLError):
        source.load()
    with psycopg.connect(pg_tables) as conn:
        count = conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
    assert count == 3


def test_missing_psycopg_names_the_install_command(monkeypatch):
    from consentml.sources import postgres as pg_module

    def no_psycopg():
        raise ConsentMLError(
            "PostgresSource needs psycopg. Install it with: "
            "pip install 'consentml[postgres]'"
        )

    monkeypatch.setattr(pg_module, "_import_psycopg", no_psycopg)
    with pytest.raises(ConsentMLError, match=r"consentml\[postgres\]"):
        PostgresSource(dsn="x", query="y", subject_id_col="z")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest tests/test_sources_postgres.py -k "write or psycopg" -v`

Expected: FAIL — the INSERT succeeds and `patients` gains a row.

- [ ] **Step 3: Implement**

In `_fetch`, set the connection read-only immediately after connecting and
before any statement runs (psycopg requires this before a transaction begins):

```python
        try:
            conn = psycopg.connect(self._dsn)
        except psycopg.OperationalError as exc:
            raise ConsentMLError(
                f"could not connect to Postgres at "
                f"{self._conninfo['host']}:{self._conninfo['port']}: {exc}"
            ) from exc
        try:
            # Set before any statement runs: psycopg only accepts this while
            # no transaction is open. ConsentML reads training data; it must
            # never be able to write to the system it is reading from.
            conn.read_only = True
            with conn.cursor() as cur:
```

The existing `except psycopg.Error` around `cur.execute(self._query)` already
converts the resulting `ReadOnlySqlTransaction` into a `ConsentMLError`, so no
further change is needed there.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest tests/test_sources_postgres.py -v`

Expected: PASS

- [ ] **Step 5: Run the full suite with coverage**

Run: `CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest --cov=consentml --cov-report=term-missing --cov-fail-under=100`

Expected: PASS at 100%. If any line is uncovered, add a test for it rather than
lowering the gate.

- [ ] **Step 6: Commit**

```bash
git add src/consentml/sources/postgres.py tests/test_sources_postgres.py
git commit -m "feat: PostgresSource reads in a read-only transaction"
```

---

## Task 11: Documentation and demo

**Files:**
- Modify: `README.md`
- Modify: `examples/consentml_demo.ipynb`
- Test: `tests/test_notebook.py` (existing, must still pass)

- [ ] **Step 1: Discard the dirty notebook outputs**

The working tree has executed outputs committed to nothing. Reset first so the
diff in this task is only the API change:

```bash
git checkout examples/consentml_demo.ipynb
```

- [ ] **Step 2: Add a README section**

Insert after the intro paragraph in `README.md`, before "## Verifying the audit
trail":

```markdown
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

### What provenance records

Postgres runs are recorded with the exact query text and its SHA-256, plus the
tables the query plan touched. The query text is authoritative;
`referenced_tables` is advisory — it comes from `EXPLAIN`, so a table the
planner optimizes away will not appear. `referenced_tables_source` says which
mechanism produced the list, or `"unavailable"` if `EXPLAIN` could not run.

The SHA-256 of the whole provenance record goes into the hash-chained audit
log, so editing provenance in the database is detected as `provenance_modified`.
```

- [ ] **Step 3: Update the migration section**

In `README.md`, replace the "## Upgrading an existing database" opening
paragraph with:

```markdown
## Upgrading an existing database

Databases created before the provenance schema (v0 or v1) need a one-time
upgrade:

```bash
consentml migrate --db lineage.db
```
```

and append to that section:

```markdown
Migration backfills provenance from the old `data_source` string as
`{"kind": "legacy", ...}` and **does not touch the audit log** — those entries
were hashed over payloads containing `data_source`, and rewriting them would
invalidate every entry hash. Runs migrated this way keep legacy guarantees:
their provenance is not hash-protected, and `consentml verify` reports how many
such runs it did not check rather than implying it did.
```

- [ ] **Step 4: Update the demo notebook**

In `examples/consentml_demo.ipynb`, change the `@track` cell to the
`DataFrameSource` form (the notebook has no Postgres available, so it must not
use `PostgresSource`):

```python
from consentml import track
from consentml.sources import DataFrameSource

@track(
    model_name="readmission-risk",
    source=DataFrameSource(patients, subject_id_col="patient_id",
                           label="clinic.patients"),
    db_path=DB,
)
def train(df):
    return LogisticRegression().fit(df[["age"]], df["outcome"])

model = train()
```

Then grep the notebook for any remaining reference and update it:

```bash
grep -n 'data_source\|subject_id_col=' examples/consentml_demo.ipynb
```

Every hit must become `provenance` or move inside the `DataFrameSource(...)`
call. The notebook must not reference `PostgresSource` — `tests/test_notebook.py`
executes it, and no Postgres is guaranteed at that point in the suite.

- [ ] **Step 5: Run the notebook regression test**

Run: `.venv/bin/python -m pytest tests/test_notebook.py -v`

Expected: PASS

- [ ] **Step 6: Run the full suite with coverage**

Run: `CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test .venv/bin/python -m pytest --cov=consentml --cov-report=term-missing --cov-fail-under=100`

Expected: PASS at 100%

- [ ] **Step 7: Commit**

```bash
git add README.md examples/consentml_demo.ipynb
git commit -m "docs: source-based @track, provenance, and the v2 migration"
```

---

## Done when

- `pytest --cov=consentml --cov-fail-under=100` passes with a live Postgres.
- CI is green on both 3.10 and 3.13 with the service container.
- `consentml verify` reports `provenance_modified` on an edited provenance
  column, and `n_legacy_runs` on a migrated database.
- `consentml migrate` takes both v0 and v1 databases to v2, leaving the audit
  log byte-identical.
- `README.md` shows the `source=` API and no longer implies `data_source`
  exists.
