"""Shared fixtures.

build_legacy_db writes a real schema-v0 database with the pre-interning
layout, so the v0 read paths are tested against the actual old format rather
than a mock.
"""

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone

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


def append_audit_entry(path, event_type, payload) -> str:
    """Append one hash-chained audit_log row to the database at path.

    Mirrors LineageStore._append_audit_entry's arithmetic exactly (sha256 of
    prev_hash + timestamp + event_type + payload, prev_hash taken from the
    current last row or GENESIS if the log is empty). Extracted here because
    this same arithmetic used to be re-derived independently in
    build_legacy_db and in individual tests that hand-build an audit entry
    (e.g. a legacy payload shape mixed into an otherwise-current database) --
    three copies that could silently drift apart if the hash inputs ever
    changed. Returns the new entry's hash, for chaining consecutive calls.
    """
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row[0] if row else GENESIS
        timestamp = datetime.now(timezone.utc).isoformat()
        entry_hash = hashlib.sha256(
            (prev_hash + timestamp + event_type + payload).encode("utf-8")
        ).hexdigest()
        conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, payload, prev_hash, "
            "entry_hash) VALUES (?, ?, ?, ?, ?)",
            (timestamp, event_type, payload, prev_hash, entry_hash),
        )
        conn.commit()
        return entry_hash
    finally:
        conn.close()


def build_legacy_db(path, runs=(("churn_v3", ("h1", "h2")),)):
    """Write a v0 database with a valid hash chain. Returns the run_ids."""
    conn = sqlite3.connect(path)
    conn.executescript(_V0_SCHEMA)
    run_ids = []
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
        conn.commit()
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
        append_audit_entry(path, "training_run", payload)
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


@pytest.fixture
def append_entry():
    """append_audit_entry itself, for tests that need to hand-build a single
    audit_log row with a correctly computed hash-chain link -- e.g. a
    legacy payload shape appended after a normal v2 entry, to model a
    database that legitimately holds a mix of both.

    Exposed as a fixture for the same reason as build_legacy above.
    """
    return append_audit_entry


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
    """Write a schema-v1 database with a valid hash chain. Returns run_ids.

    Mirrors build_legacy_db above, just against the interned v1 layout
    (subjects/subject_index by run_pk/subject_pk instead of inline
    subject_id_hash). The audit entry for each run is appended via the
    shared append_audit_entry helper rather than re-deriving the hash-chain
    arithmetic here -- see that helper's docstring for why this used to
    drift across three copies. append_audit_entry reads the current last
    row itself, so calling it once per run in order chains them correctly
    without this function tracking prev_hash by hand.
    """
    conn = sqlite3.connect(path)
    conn.executescript(_V1_SCHEMA)
    conn.execute("PRAGMA user_version = 1")
    run_ids = []
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
        conn.commit()
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
        append_audit_entry(path, "training_run", payload)
    conn.close()
    return run_ids


@pytest.fixture
def v1_db(tmp_path):
    """A schema-v1 database with two runs sharing a subject."""
    path = tmp_path / "v1.db"
    build_v1_db(path, runs=(("churn_v3", ("h1", "h2")), ("upsell", ("h1", "h3"))))
    return path


@pytest.fixture
def build_v1():
    """The v1 builder itself, for tests needing a custom run/subject layout
    or a specific path -- mirrors the build_legacy fixture above, and for
    the same reason (no `from conftest import ...`)."""
    return build_v1_db


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
    import psycopg

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
