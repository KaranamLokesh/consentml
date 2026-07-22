import sqlite3

import pytest

from consentml.store import LineageStore


@pytest.fixture
def store(tmp_path):
    s = LineageStore(db_path=tmp_path / "lineage.db")
    yield s
    s.close()


def _table_names(db_path):
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        conn.close()
    return {r[0] for r in rows}


def test_creates_schema_on_init(store, tmp_path):
    names = _table_names(tmp_path / "lineage.db")
    assert {"training_runs", "subject_index", "audit_log"} <= names


def test_creates_parent_directory(tmp_path):
    s = LineageStore(db_path=tmp_path / "nested" / "dir" / "lineage.db")
    s.close()
    assert (tmp_path / "nested" / "dir" / "lineage.db").exists()


def test_subject_index_is_indexed(store, tmp_path):
    conn = sqlite3.connect(tmp_path / "lineage.db")
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    finally:
        conn.close()
    assert "idx_subject_id_hash" in {r[0] for r in rows}


def test_init_is_idempotent(tmp_path):
    LineageStore(db_path=tmp_path / "lineage.db").close()
    LineageStore(db_path=tmp_path / "lineage.db").close()
