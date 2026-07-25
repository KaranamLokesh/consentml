# ConsentML v0 Week-8 Interned Subject Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut `subject_index` growth from 38.7 MB per training run to 7.5 MB by interning subject keys into their own table, and ship `consentml migrate` to move existing databases onto the new schema with verification gates on both sides.

**Architecture:** A new schema v1 adds a `subjects` table (each key stored once) and switches `subject_index` to integer foreign keys. `audit_log` is untouched, so the hash chain survives migration byte-for-byte and `verify_audit_log()` can prove fidelity. All changes stay inside `store.py`: every public method keeps its signature and still exchanges `run_id` as TEXT, so `revoke.py`, `verify.py`, and `track.py` need no edits. Legacy v0 databases stay readable (two queries branch on version) but reject writes.

**Tech Stack:** Same as Weeks 5-7 — Python ≥3.10, stdlib `sqlite3`/`json`/`argparse`/`dataclasses`, pytest. No new dependencies.

**File structure:**

```
src/consentml/
├── errors.py       # new: ConsentMLError, moved here to break a circular import
├── track.py        # modify: re-export ConsentMLError from errors
├── store.py        # modify: v1 schema, version detection, write guard,
│                   #         interned writes, version-branching reads
├── migrate.py      # new: MigrationResult, migrate_database()
├── cli.py          # modify: `migrate` subcommand
└── __init__.py     # modify: export migrate_database, MigrationResult
tests/
├── test_store.py       # modify: interned-schema and version-guard tests
├── test_migrate.py     # new
├── test_cli.py         # modify: migrate subcommand tests
└── conftest.py         # new: shared legacy-v0 database builder
README.md               # modify: document migrate
```

**Conventions:** all commands run from the repo root with the venv: `.venv/bin/pytest ...`. Work happens on branch `v0-week8-interning`.

**Baseline before starting:** 93 tests passing, 100% coverage. Both numbers must hold at the end (the count will grow; coverage must stay at 100%).

**Two subtleties the implementer must not rediscover the hard way:**

1. **Fresh and legacy databases both report `user_version = 0`**, because the old code never set it. Version alone cannot distinguish them — detection must also check whether a `training_runs` table already exists. Getting this wrong means grafting v1 tables onto a legacy database.
2. **`__init__` currently runs `executescript(_SCHEMA)` on every open.** After this change the schema script must run *only* when creating a fresh database, never against a legacy one.

---

### Task 0: Branch

- [ ] **Step 1: Create the working branch**

```bash
git checkout -b v0-week8-interning
```

---

### Task 1: Move `ConsentMLError` out of `track.py`

`store.py` needs to raise `ConsentMLError` from its write guard, but `ConsentMLError` is defined in `track.py`, which imports `store.py`. Importing it back would be circular. This task moves the exception to its own module with zero behaviour change.

**Files:**
- Create: `src/consentml/errors.py`
- Modify: `src/consentml/track.py`
- Test: `tests/test_track.py` (append)

- [ ] **Step 1: Write the failing test** (append to `tests/test_track.py`)

```python
def test_consentml_error_importable_from_errors_module():
    from consentml.errors import ConsentMLError as FromErrors
    from consentml.track import ConsentMLError as FromTrack

    assert FromErrors is FromTrack
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_track.py::test_consentml_error_importable_from_errors_module -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'consentml.errors'`

- [ ] **Step 3: Create `src/consentml/errors.py`**

```python
"""Exception types shared across the package.

ConsentMLError lives here rather than in track.py so that store.py can raise
it without importing track.py, which would be circular.
"""


class ConsentMLError(Exception):
    """Raised for ConsentML usage errors (bad arguments, missing data)."""
```

- [ ] **Step 4: Update `src/consentml/track.py`**

Delete this class definition:

```python
class ConsentMLError(Exception):
    """Raised for ConsentML usage errors (bad arguments, missing data)."""
```

and add this import alongside the existing `from consentml.hashing import hash_subject_id` line:

```python
from consentml.errors import ConsentMLError
```

`from consentml.track import ConsentMLError` keeps working because the name is now bound in `track`'s namespace by the import. Do not add an `__all__` to `track.py`.

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest`
Expected: 94 passed. Nothing else should change — this is a pure move.

- [ ] **Step 6: Commit**

```bash
git add src/consentml/errors.py src/consentml/track.py tests/test_track.py
git commit -m "refactor: move ConsentMLError to its own module"
```

---

### Task 2: Schema v1 — version detection, interned writes, branching reads

This is one atomic task: the schema, the write path, and the read path must change together or the suite cannot be green in between.

**Files:**
- Modify: `src/consentml/store.py`
- Test: `tests/test_store.py` (append)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_store.py`)

```python
def test_fresh_database_is_schema_v1(store, tmp_path):
    assert store.schema_version == 1
    conn = sqlite3.connect(tmp_path / "lineage.db")
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    finally:
        conn.close()


def test_fresh_database_has_subjects_table(store, tmp_path):
    assert "subjects" in _table_names(tmp_path / "lineage.db")


def test_subject_keys_are_stored_once_across_runs(store, tmp_path):
    _record_sample_run(store, model_name="a", subject_hashes=("h1", "h2"))
    _record_sample_run(store, model_name="b", subject_hashes=("h1", "h2"))
    conn = sqlite3.connect(tmp_path / "lineage.db")
    try:
        n_subjects = conn.execute("SELECT COUNT(*) FROM subjects").fetchone()[0]
        n_index = conn.execute("SELECT COUNT(*) FROM subject_index").fetchone()[0]
    finally:
        conn.close()
    assert n_subjects == 2   # deduplicated
    assert n_index == 4      # one row per (run, subject), NOT deduplicated


def test_lookup_still_works_after_interning(store):
    run_id = _record_sample_run(store)
    runs = store.runs_for_subject_value("h1")
    assert [r["run_id"] for r in runs] == [run_id]
    assert runs[0]["model_name"] == "churn_v3"


def test_subject_count_for_run_after_interning(store):
    run_id = _record_sample_run(store, subject_hashes=("h1", "h2", "h3"))
    assert store.subject_count_for_run(run_id) == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_store.py -v`
Expected: `test_fresh_database_is_schema_v1` fails with `AttributeError: 'LineageStore' object has no attribute 'schema_version'`; `test_fresh_database_has_subjects_table` fails on the missing table; the two counting tests fail. The lookup tests pass already (they pass under the old schema too) — that is expected and correct, because they are regression guards for behaviour that must survive.

- [ ] **Step 3: Replace the schema and add version constants in `src/consentml/store.py`**

Add the import at the top, alongside the existing imports:

```python
from consentml.errors import ConsentMLError
```

Add after `GENESIS_HASH`:

```python
SCHEMA_VERSION = 1
```

Replace the whole `_SCHEMA = """..."""` block with:

```python
_SCHEMA = """
CREATE TABLE IF NOT EXISTS training_runs (
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

CREATE TABLE IF NOT EXISTS subjects (
    subject_pk INTEGER PRIMARY KEY,
    subject_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS subject_index (
    run_pk INTEGER NOT NULL REFERENCES training_runs(run_pk),
    subject_pk INTEGER NOT NULL REFERENCES subjects(subject_pk)
);

CREATE INDEX IF NOT EXISTS idx_si_subject ON subject_index(subject_pk);
CREATE INDEX IF NOT EXISTS idx_si_run ON subject_index(run_pk);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""
```

Note `audit_log` is byte-for-byte the same as before. That is deliberate and load-bearing.

- [ ] **Step 4: Replace `__init__` and add version detection**

Replace `__init__` with:

```python
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self.schema_version = self._detect_schema()
```

Add these two methods immediately after `__init__`:

```python
    def _detect_schema(self) -> int:
        """Return the schema version, creating a fresh v1 database if needed.

        A legacy database and an empty file both report user_version 0 -- the
        old code never set it -- so the presence of training_runs is what tells
        them apart. The schema script must never run against a legacy database.
        """
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version:
            return version
        existing = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='training_runs'"
        ).fetchone()
        if existing:
            return 0
        self._conn.executescript(_SCHEMA)
        self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._conn.commit()
        return SCHEMA_VERSION

    def _require_writable(self):
        if self.schema_version < SCHEMA_VERSION:
            raise ConsentMLError(
                f"{self.db_path} uses schema v{self.schema_version}; run "
                "'consentml migrate' to upgrade it before recording new events."
            )
```

- [ ] **Step 5: Rewrite `record_training_run` for the interned schema**

Replace the body of `record_training_run` (keep the signature exactly as it is) with:

```python
        self._require_writable()
        run_id = str(uuid.uuid4())
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO training_runs (run_id, model_name, model_hash, "
                "data_source, subject_id_col, subject_ids_hashed, n_subjects, "
                "started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    model_name,
                    model_hash,
                    data_source,
                    subject_id_col,
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
                        "data_source": data_source,
                        "n_subjects": len(subject_id_values),
                    },
                    sort_keys=True,
                ),
            )
        return run_id
```

The `INSERT OR IGNORE` dedups the *keys*; the second `executemany` still inserts one index row per value, so per-run counts are preserved exactly. Do not "optimise" the second statement into a deduplicating insert — `subject_count_mismatch` in `verify.py` compares those counts against the hash-protected audit payload.

- [ ] **Step 6: Add the write guard to `record_revocation`**

Add `self._require_writable()` as the first line of `record_revocation`, before the `with self._conn:` block.

- [ ] **Step 7: Branch the two version-dependent read queries**

Replace `runs_for_subject_value` with:

```python
    def runs_for_subject_value(self, subject_id_value) -> list[dict]:
        """Training runs whose subject index contains the given stored value
        (a hash when subject_ids_hashed, else the raw ID)."""
        cols = ", ".join(f"r.{c}" for c in _RUN_COLS)
        if self.schema_version == 0:
            sql = (
                f"SELECT {cols} FROM training_runs r "
                "JOIN subject_index s ON s.run_id = r.run_id "
                "WHERE s.subject_id_hash = ? ORDER BY r.started_at"
            )
        else:
            sql = (
                f"SELECT {cols} FROM training_runs r "
                "JOIN subject_index s ON s.run_pk = r.run_pk "
                "JOIN subjects sub ON sub.subject_pk = s.subject_pk "
                "WHERE sub.subject_key = ? ORDER BY r.started_at"
            )
        rows = self._conn.execute(sql, (subject_id_value,)).fetchall()
        return [dict(zip(_RUN_COLS, row)) for row in rows]
```

Replace `subject_count_for_run` with:

```python
    def subject_count_for_run(self, run_id) -> int:
        """How many subject_index rows currently exist for this run."""
        if self.schema_version == 0:
            sql = "SELECT COUNT(*) FROM subject_index WHERE run_id = ?"
        else:
            sql = (
                "SELECT COUNT(*) FROM subject_index s "
                "JOIN training_runs r ON r.run_pk = s.run_pk "
                "WHERE r.run_id = ?"
            )
        return self._conn.execute(sql, (run_id,)).fetchone()[0]
```

`latest_run_for_model`, `run_by_id`, `all_run_ids`, and `audit_entries` need **no changes** — they only touch columns that are identical in both schemas.

- [ ] **Step 8: Update the module docstring**

Replace the `store.py` module docstring with:

```python
"""SQLite-backed lineage store.

Four tables:
- training_runs: one row per decorated training execution.
- subjects: each distinct subject key, stored once.
- subject_index: one row per (run, subject) pair, by integer foreign key.
- audit_log: append-only, hash-chained event log.

Schema version lives in PRAGMA user_version. Version 0 databases predate
versioning; they can be read but not written -- see consentml.migrate.
"""
```

- [ ] **Step 9: Run the full suite**

Run: `.venv/bin/pytest`
Expected: 99 passed. **Every one of the 94 pre-existing tests must pass without modification.** If any test in `test_revoke.py`, `test_verify.py`, `test_track.py`, or `test_integration.py` needs editing, stop: the abstraction boundary was drawn wrong, and the fix belongs in `store.py`, not in the caller.

- [ ] **Step 10: Commit**

```bash
git add src/consentml/store.py tests/test_store.py
git commit -m "feat: intern subject keys into their own table (schema v1)"
```

---

### Task 3: Legacy v0 read compatibility

Task 2 wrote the branching code. This task proves it works against a real legacy database rather than a hypothetical one.

**Files:**
- Create: `tests/conftest.py`
- Test: `tests/test_store.py` (append)

- [ ] **Step 1: Create `tests/conftest.py` with a legacy-database builder**

```python
"""Shared fixtures.

legacy_db builds a real schema-v0 database with the pre-interning layout, so
the v0 read paths are tested against the actual old format rather than a mock.
"""

import hashlib
import json
import sqlite3

import pytest

_V0_SCHEMA = """
CREATE TABLE training_runs (
    run_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    model_hash TEXT NOT NULL,
    data_source TEXT NOT NULL,
    subject_id_col TEXT NOT NULL,
    subject_ids_hashed INTEGER NOT NULL,
    n_subjects INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);
CREATE TABLE subject_index (
    run_id TEXT NOT NULL REFERENCES training_runs(run_id),
    subject_id_hash TEXT NOT NULL
);
CREATE INDEX idx_subject_id_hash ON subject_index(subject_id_hash);
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""

GENESIS = "0" * 64


def build_legacy_db(path, runs=(("churn_v3", ("h1", "h2")),)):
    """Write a v0 database with a valid hash chain. Returns the run_ids."""
    conn = sqlite3.connect(path)
    conn.executescript(_V0_SCHEMA)
    run_ids, prev = [], GENESIS
    for i, (model_name, subjects) in enumerate(runs):
        run_id = f"run-{i}"
        run_ids.append(run_id)
        started = f"2026-07-{i + 1:02d}T00:00:00+00:00"
        conn.execute(
            "INSERT INTO training_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, model_name, f"hash_{i}", "postgres://prod/customers",
             "email", 1, len(subjects), started, started),
        )
        conn.executemany(
            "INSERT INTO subject_index VALUES (?, ?)",
            [(run_id, s) for s in subjects],
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
def legacy_db(tmp_path):
    """A schema-v0 database with two runs sharing a subject."""
    path = tmp_path / "legacy.db"
    build_legacy_db(
        path,
        runs=(("churn_v3", ("h1", "h2")), ("upsell", ("h1", "h3"))),
    )
    return path


@pytest.fixture
def build_legacy():
    """The v0 builder itself, for tests needing a custom run/subject layout.

    Exposed as a fixture rather than imported directly, so tests never depend
    on `from conftest import ...` resolving through pytest's path insertion.
    """
    return build_legacy_db
```

- [ ] **Step 2: Write the failing tests** (append to `tests/test_store.py`)

```python
from consentml.errors import ConsentMLError


def test_legacy_database_reports_version_zero(legacy_db):
    s = LineageStore(db_path=legacy_db)
    try:
        assert s.schema_version == 0
    finally:
        s.close()


def test_legacy_database_is_not_modified_on_open(legacy_db):
    before = legacy_db.read_bytes()
    LineageStore(db_path=legacy_db).close()
    assert legacy_db.read_bytes() == before


def test_legacy_reads_work(legacy_db):
    s = LineageStore(db_path=legacy_db)
    try:
        runs = s.runs_for_subject_value("h1")
        assert [r["model_name"] for r in runs] == ["churn_v3", "upsell"]
        assert s.subject_count_for_run("run-0") == 2
        assert s.all_run_ids() == {"run-0", "run-1"}
        assert s.run_by_id("run-0")["model_name"] == "churn_v3"
    finally:
        s.close()


def test_legacy_writes_are_refused(legacy_db):
    s = LineageStore(db_path=legacy_db)
    try:
        with pytest.raises(ConsentMLError, match="consentml migrate"):
            _record_sample_run(s)
        with pytest.raises(ConsentMLError, match="consentml migrate"):
            s.record_revocation(
                subject_key="k", n_affected_runs=0, recommended_actions=[]
            )
    finally:
        s.close()
```

- [ ] **Step 3: Run tests**

Run: `.venv/bin/pytest tests/test_store.py -v`
Expected: all pass. Task 2 already wrote the branching code, so these tests confirm it rather than drive it. If `test_legacy_database_is_not_modified_on_open` fails, `_detect_schema` is running the schema script against a legacy database — fix that before continuing.

- [ ] **Step 4: Add the cross-module legacy tests** (append to `tests/test_verify.py`)

```python
def test_verify_works_on_a_legacy_database(legacy_db):
    report = verify_audit_log(db_path=legacy_db)
    assert report.ok is True
    assert report.n_entries == 2


def test_verify_detects_tampering_in_a_legacy_database(legacy_db):
    _sql(legacy_db, "DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    report = verify_audit_log(db_path=legacy_db)
    assert "subject_count_mismatch" in _codes(report)
```

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest`
Expected: 105 passed.

That `verify_audit_log()` works unmodified on a v0 database is the property the migration gate depends on — it means there is only one implementation of the cross-checks, not two.

- [ ] **Step 6: Commit**

```bash
git add tests/conftest.py tests/test_store.py tests/test_verify.py
git commit -m "test: legacy v0 databases are readable, not writable"
```

---

### Task 4: `migrate_database()`

**Files:**
- Create: `src/consentml/migrate.py`
- Test: `tests/test_migrate.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_migrate.py
import hashlib
import sqlite3

import pytest

from consentml.migrate import MigrationResult, migrate_database
from consentml.revoke import revoke
from consentml.store import LineageStore
from consentml.verify import verify_audit_log


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_migrates_a_legacy_database(legacy_db):
    result = migrate_database(db_path=legacy_db)
    assert isinstance(result, MigrationResult)
    assert result.migrated is True
    assert result.already_current is False
    s = LineageStore(db_path=legacy_db)
    try:
        assert s.schema_version == 1
    finally:
        s.close()


def test_verification_clean_before_and_after(legacy_db):
    assert verify_audit_log(db_path=legacy_db).ok is True
    migrate_database(db_path=legacy_db)
    assert verify_audit_log(db_path=legacy_db).ok is True


def test_revoke_reports_are_identical_across_migration(legacy_db):
    before = revoke(subject_id="h1", db_path=legacy_db, dry_run=True).to_dict()
    migrate_database(db_path=legacy_db)
    after = revoke(subject_id="h1", db_path=legacy_db, dry_run=True).to_dict()
    for report in (before, after):
        report.pop("generated_at")
    assert before == after


def test_leaves_a_backup(legacy_db):
    original = _digest(legacy_db)
    result = migrate_database(db_path=legacy_db)
    backup = legacy_db.parent / (legacy_db.name + ".pre-migration.bak")
    assert backup.exists()
    assert _digest(backup) == original
    assert result.backup_path == str(backup)


def test_is_idempotent(legacy_db):
    migrate_database(db_path=legacy_db)
    second = migrate_database(db_path=legacy_db)
    assert second.already_current is True
    assert second.migrated is False


def test_refuses_a_tampered_database(legacy_db):
    conn = sqlite3.connect(legacy_db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    original = _digest(legacy_db)

    result = migrate_database(db_path=legacy_db)

    assert result.migrated is False
    assert "subject_count_mismatch" in [f.code for f in result.findings]
    assert _digest(legacy_db) == original  # byte-identical, untouched
    assert not (legacy_db.parent / (legacy_db.name + ".pre-migration.bak")).exists()


def test_allow_unverified_overrides_the_refusal(legacy_db):
    conn = sqlite3.connect(legacy_db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    result = migrate_database(db_path=legacy_db, allow_unverified=True)
    assert result.migrated is True


def test_missing_database_is_reported(tmp_path):
    result = migrate_database(db_path=tmp_path / "nope.db")
    assert result.migrated is False
    assert result.error is not None
    assert not (tmp_path / "nope.db").exists()


def test_subject_keys_are_deduplicated_but_counts_preserved(tmp_path, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=(("a", ("h1", "h2")), ("b", ("h1", "h2"))))
    migrate_database(db_path=db)
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM subjects").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM subject_index").fetchone()[0] == 4
    finally:
        conn.close()


def test_audit_log_survives_byte_for_byte(legacy_db):
    def rows(path):
        conn = sqlite3.connect(path)
        try:
            return conn.execute(
                "SELECT id, timestamp, event_type, payload, prev_hash, entry_hash "
                "FROM audit_log ORDER BY id"
            ).fetchall()
        finally:
            conn.close()

    before = rows(legacy_db)
    migrate_database(db_path=legacy_db)
    assert rows(legacy_db) == before
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_migrate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'consentml.migrate'`

- [ ] **Step 3: Write `src/consentml/migrate.py`**

```python
"""Migrate a v0 lineage database onto the interned v1 schema.

The migration is gated by verification on both sides. It refuses to run on a
database that fails verification, because rewriting a tampered database
produces a fresh, internally consistent one -- laundering the tampering and
destroying the evidence.

The new database is built alongside the original and only swapped into place
once it verifies clean, so a failure leaves the original untouched and there
is no rollback logic to get wrong. The cost is temporary double disk usage.
"""

import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from consentml.store import SCHEMA_VERSION, _SCHEMA, default_db_path
from consentml.verify import verify_audit_log

_RUN_COLS_V0 = (
    "run_id, model_name, model_hash, data_source, subject_id_col, "
    "subject_ids_hashed, n_subjects, started_at, finished_at"
)


@dataclass
class MigrationResult:
    migrated: bool
    already_current: bool
    findings: list = field(default_factory=list)
    bytes_before: int = 0
    bytes_after: int = 0
    backup_path: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "migrated": self.migrated,
            "already_current": self.already_current,
            "findings": [
                {"entry_id": f.entry_id, "code": f.code, "detail": f.detail}
                for f in self.findings
            ],
            "bytes_before": self.bytes_before,
            "bytes_after": self.bytes_after,
            "backup_path": self.backup_path,
            "error": self.error,
        }


def _copy_into_v1(src_path, dst_path):
    """Build a v1 database at dst_path from the v0 database at src_path."""
    dst = sqlite3.connect(dst_path)
    try:
        dst.executescript(_SCHEMA)
        dst.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        src = sqlite3.connect(src_path)
        try:
            with dst:
                for row in src.execute(
                    f"SELECT {_RUN_COLS_V0} FROM training_runs"
                ):
                    dst.execute(
                        f"INSERT INTO training_runs ({_RUN_COLS_V0}) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        row,
                    )
                # Intern the keys: each distinct value stored once...
                dst.executemany(
                    "INSERT OR IGNORE INTO subjects (subject_key) VALUES (?)",
                    src.execute("SELECT DISTINCT subject_id_hash FROM subject_index"),
                )
                # ...but one index row per original row, so per-run counts
                # are preserved exactly.
                dst.executemany(
                    "INSERT INTO subject_index (run_pk, subject_pk) "
                    "SELECT r.run_pk, s.subject_pk FROM training_runs r, subjects s "
                    "WHERE r.run_id = ? AND s.subject_key = ?",
                    src.execute("SELECT run_id, subject_id_hash FROM subject_index"),
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


def migrate_database(*, db_path=None, allow_unverified=False) -> MigrationResult:
    """Migrate a lineage database onto schema v1.

    Verifies before and after. Refuses to migrate a database that fails
    verification unless allow_unverified is set.
    """
    db = Path(db_path) if db_path is not None else default_db_path()
    if not db.exists():
        return MigrationResult(
            migrated=False,
            already_current=False,
            error=f"no lineage database at {db}",
        )

    conn = sqlite3.connect(db)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()
    if version >= SCHEMA_VERSION:
        return MigrationResult(
            migrated=False, already_current=True, bytes_before=db.stat().st_size
        )

    before = verify_audit_log(db_path=db)
    if not before.ok and not allow_unverified:
        return MigrationResult(
            migrated=False,
            already_current=False,
            findings=before.findings,
            bytes_before=db.stat().st_size,
            error="database failed verification; refusing to migrate",
        )

    bytes_before = db.stat().st_size
    staging = db.parent / (db.name + ".migrating")
    staging.unlink(missing_ok=True)
    try:
        _copy_into_v1(db, staging)
        after = verify_audit_log(db_path=staging)
        if not after.ok and not allow_unverified:
            return MigrationResult(
                migrated=False,
                already_current=False,
                findings=after.findings,
                bytes_before=bytes_before,
                error="migrated database failed verification; original untouched",
            )
        backup = db.parent / (db.name + ".pre-migration.bak")
        shutil.copy2(db, backup)
        os.replace(staging, db)
    finally:
        staging.unlink(missing_ok=True)

    return MigrationResult(
        migrated=True,
        already_current=False,
        bytes_before=bytes_before,
        bytes_after=db.stat().st_size,
        backup_path=str(backup),
    )
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_migrate.py -v`
Expected: 10 passed.

If `test_refuses_a_tampered_database` fails on the byte-identical assertion, something wrote to the original before the gate — the verification check must happen before any file is created.

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest`
Expected: 115 passed.

- [ ] **Step 6: Commit**

```bash
git add src/consentml/migrate.py tests/test_migrate.py
git commit -m "feat: migrate_database() with verification gates on both sides"
```

---

### Task 5: `consentml migrate` CLI

**Files:**
- Modify: `src/consentml/cli.py`
- Test: `tests/test_cli.py` (append)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cli.py`)

```python
def test_cli_migrate_succeeds(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    assert main(["migrate", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "Migrated" in out


def test_cli_migrate_is_idempotent(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    main(["migrate", "--db", str(db)])
    capsys.readouterr()
    assert main(["migrate", "--db", str(db)]) == 0
    assert "already" in capsys.readouterr().out.lower()


def test_cli_migrate_refuses_tampered_and_exits_one(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    conn = sqlite3.connect(db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    assert main(["migrate", "--db", str(db)]) == 1
    out = capsys.readouterr().out
    assert "subject_count_mismatch" in out


def test_cli_migrate_json(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    assert main(["migrate", "--db", str(db), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["migrated"] is True
    assert data["bytes_after"] > 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: the 4 new tests FAIL with `SystemExit: 2` — argparse rejects the unknown `migrate` subcommand.

- [ ] **Step 3: Update `src/consentml/cli.py`**

Add the import alongside the existing `from consentml.verify import verify_audit_log`:

```python
from consentml.migrate import migrate_database
```

Add this function immediately after `_print_verify_summary`:

```python
def _print_migrate_summary(result):
    if result.already_current:
        print("Database is already on the current schema; nothing to do.")
        return
    if not result.migrated:
        print(f"Migration refused: {result.error}")
        for f in result.findings:
            where = f"entry {f.entry_id}" if f.entry_id is not None else "tables"
            print(f"  - [{f.code}] {where}: {f.detail}")
        return
    saved = result.bytes_before - result.bytes_after
    print(
        f"Migrated: {result.bytes_before / 1e6:.1f} MB -> "
        f"{result.bytes_after / 1e6:.1f} MB ({saved / 1e6:+.1f} MB)."
    )
    print(f"Original kept at {result.backup_path}")
```

Register the subcommand immediately before the `args = parser.parse_args(argv)` line:

```python
    p_migrate = sub.add_parser(
        "migrate", help="Upgrade a lineage database to the current schema"
    )
    p_migrate.add_argument(
        "--db", default=None, help="Lineage DB path (default: ~/.consentml/lineage.db)"
    )
    p_migrate.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Migrate even if the database fails verification (not recommended)",
    )
    p_migrate.add_argument(
        "--json", dest="as_json", action="store_true", help="Emit JSON"
    )
```

Add this branch inside the existing `try:` block, before the `if args.command == "verify":` branch:

```python
        if args.command == "migrate":
            result = migrate_database(
                db_path=args.db, allow_unverified=args.allow_unverified
            )
        elif args.command == "verify":
```

(the existing `verify` branch becomes an `elif`, and the existing `else:` revoke branch is unchanged)

Then add this output branch immediately after the `try/except`, before the existing `if args.command == "verify":` output block:

```python
    if args.command == "migrate":
        if args.as_json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            _print_migrate_summary(result)
        return 0 if (result.migrated or result.already_current) else 1
```

- [ ] **Step 4: Run tests and exercise the CLI**

```bash
.venv/bin/pytest tests/test_cli.py -v
.venv/bin/consentml migrate --help
```

Expected: 15 passed; help text shows `migrate` usage including `--allow-unverified`.

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/pytest`
Expected: 119 passed.

- [ ] **Step 6: Commit**

```bash
git add src/consentml/cli.py tests/test_cli.py
git commit -m "feat: consentml migrate CLI"
```

---

### Task 6: Exports, size regression test, README, coverage gate

**Files:**
- Modify: `src/consentml/__init__.py`
- Modify: `README.md`
- Test: `tests/test_migrate.py` (append)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_migrate.py`)

```python
def test_public_api_exports_migrate():
    import consentml

    assert consentml.migrate_database is migrate_database
    assert consentml.MigrationResult is MigrationResult


def test_interning_shrinks_a_repeated_population(tmp_path, build_legacy):
    """The whole point of the exercise, pinned by a test.

    Five runs over the same 2000 subjects. Under the old schema every run
    re-stored every key; under v1 the keys are stored once.
    """
    keys = tuple(f"subject-hash-{i:06d}" for i in range(2000))
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=tuple((f"m{i}", keys) for i in range(5)))
    before = db.stat().st_size

    migrate_database(db_path=db)
    after = db.stat().st_size

    assert after < before * 0.6, f"expected a clear shrink, got {before} -> {after}"

    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM subjects").fetchone()[0] == 2000
        assert conn.execute(
            "SELECT COUNT(*) FROM subject_index"
        ).fetchone()[0] == 10000
    finally:
        conn.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_migrate.py -v`
Expected: `test_public_api_exports_migrate` FAILS with `AttributeError: module 'consentml' has no attribute 'migrate_database'`. `test_interning_shrinks_a_repeated_population` should already pass — it is a regression guard on Task 4's work.

- [ ] **Step 3: Update `src/consentml/__init__.py`**

```python
"""ConsentML: training-data lineage and consent-revocation reporting."""

from consentml.errors import ConsentMLError
from consentml.migrate import MigrationResult, migrate_database
from consentml.revoke import AffectedModel, AffectedModelsReport, revoke
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
    "AffectedModel",
    "AffectedModelsReport",
    "VerificationFinding",
    "VerificationReport",
    "MigrationResult",
    "ConsentMLError",
    "__version__",
]
```

- [ ] **Step 4: Add a migration section to `README.md`**

Insert this immediately before the final `Status: pre-release (v0 in development). MIT license.` line:

```markdown
## Upgrading an existing database

Databases created before the interned-storage schema need a one-time upgrade:

```bash
consentml migrate --db lineage.db
```

Migration verifies the audit log before it starts and **refuses to run** if
verification fails — rewriting a tampered database would launder the tampering.
The new database is built alongside the original and only swapped in once it
verifies clean, so a failure leaves the original untouched. Expect the original
file to still be on disk as `<name>.pre-migration.bak`; delete it once you are
satisfied. Migration temporarily needs room for two copies of the database.

Until a database is migrated it can be read but not written to, so `@track` and
a recording `revoke()` will raise. `consentml verify` and
`revoke(dry_run=True)` keep working.
```

- [ ] **Step 5: Run the full suite with coverage**

Run: `.venv/bin/pytest --cov=consentml --cov-report=term-missing`
Expected: 121 passed, total coverage 100%.

If coverage is below 100%, add tests for the uncovered lines. Do **not** add `# pragma: no cover` — if a line genuinely cannot be reached, say so and explain why rather than hiding it.

- [ ] **Step 6: Commit**

```bash
git add src/consentml/__init__.py README.md tests/test_migrate.py
git commit -m "feat: export migration API; document consentml migrate"
```

---

### Task 7: Verify the headline number and merge

- [ ] **Step 1: Confirm the real-world saving with a scale check**

Write this to a scratch file and run it (do not commit it):

```python
# /tmp/cml_scale_check.py
import sqlite3, tempfile, time
from pathlib import Path
from consentml.store import LineageStore

N, RUNS = 200_000, 5
db = Path(tempfile.mkdtemp()) / "scale.db"
keys = [f"hash-{i:08d}" for i in range(N)]
store = LineageStore(db_path=db)
sizes = []
for r in range(RUNS):
    store.record_training_run(
        model_name="churn", model_hash="h", data_source="src",
        subject_id_col="email", subject_ids_hashed=True,
        subject_id_values=keys,
        started_at=f"2026-07-{r + 1:02d}T00:00:00+00:00",
        finished_at=f"2026-07-{r + 1:02d}T00:01:00+00:00",
    )
    sizes.append(db.stat().st_size / 1e6)
store.close()
marginal = sizes[-1] - sizes[-2]
print(f"sizes (MB): {[round(s, 1) for s in sizes]}")
print(f"marginal per run: {marginal:.1f} MB   (v0 baseline was 38.7 MB)")
print(f"extrapolated 1M x 52 runs: {marginal * 5 * 52 / 1000:.2f} GB "
      f"(v0 baseline was 10.06 GB)")
```

Run: `.venv/bin/python /tmp/cml_scale_check.py`
Expected: marginal cost around 7.5 MB per run, extrapolating to roughly 2 GB.

Report the actual numbers. If the marginal cost is materially above ~10 MB, something in the write path is not interning correctly — investigate before merging rather than shipping a change that did not deliver its purpose.

- [ ] **Step 2: Full suite from a clean state**

```bash
.venv/bin/pytest --cov=consentml --cov-report=term-missing
```

Expected: 121 passed, 100% coverage.

- [ ] **Step 3: Merge**

```bash
git checkout main
git merge --no-ff v0-week8-interning -m "Merge v0-week8-interning: interned subject storage and consentml migrate"
```
