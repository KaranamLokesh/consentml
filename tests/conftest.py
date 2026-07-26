"""Shared fixtures.

build_legacy_db writes a real schema-v0 database with the pre-interning
layout, so the v0 read paths are tested against the actual old format rather
than a mock.
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
