import hashlib
import json
import sqlite3

import pytest

from consentml.store import LineageStore, default_db_path


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


def test_default_db_path_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("CONSENTML_DB", str(tmp_path / "custom.db"))
    assert default_db_path() == tmp_path / "custom.db"


def test_default_db_path_home_fallback(monkeypatch):
    monkeypatch.delenv("CONSENTML_DB", raising=False)
    assert default_db_path().name == "lineage.db"
    assert default_db_path().parent.name == ".consentml"


def _record_sample_run(store, model_name="churn_v3", subject_hashes=("h1", "h2")):
    return store.record_training_run(
        model_name=model_name,
        model_hash="deadbeef",
        data_source="postgres://prod/customers",
        subject_id_col="email",
        subject_ids_hashed=True,
        subject_id_values=list(subject_hashes),
        started_at="2026-07-21T00:00:00+00:00",
        finished_at="2026-07-21T00:01:00+00:00",
    )


def test_record_training_run_returns_run_id_and_persists(store):
    run_id = _record_sample_run(store)
    runs = store.runs_for_subject_value("h1")
    assert len(runs) == 1
    assert runs[0]["run_id"] == run_id
    assert runs[0]["model_name"] == "churn_v3"
    assert runs[0]["n_subjects"] == 2


def test_runs_for_unknown_subject_is_empty(store):
    _record_sample_run(store)
    assert store.runs_for_subject_value("nope") == []


def test_subject_in_multiple_runs(store):
    a = _record_sample_run(store, model_name="model_a")
    b = _record_sample_run(store, model_name="model_b")
    run_ids = {r["run_id"] for r in store.runs_for_subject_value("h1")}
    assert run_ids == {a, b}


def test_recording_appends_audit_entry(store):
    run_id = _record_sample_run(store)
    entries = store.audit_entries()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["event_type"] == "training_run"
    assert json.loads(entry["payload"])["run_id"] == run_id


def test_audit_chain_links_and_hashes(store):
    _record_sample_run(store)
    _record_sample_run(store)
    first, second = store.audit_entries()
    assert first["prev_hash"] == "0" * 64
    assert second["prev_hash"] == first["entry_hash"]
    expected = hashlib.sha256(
        (
            second["prev_hash"]
            + second["timestamp"]
            + second["event_type"]
            + second["payload"]
        ).encode("utf-8")
    ).hexdigest()
    assert second["entry_hash"] == expected
