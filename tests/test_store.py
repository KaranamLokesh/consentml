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
    """subject_index must be indexed for subject lookups. Assert the intent
    (an index covering subject_pk exists) rather than a literal index name,
    so this doesn't break again the next time an index is renamed."""
    conn = sqlite3.connect(tmp_path / "lineage.db")
    try:
        index_names = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='index' AND tbl_name='subject_index'"
        ).fetchall()
        indexed_columns = set()
        for (name,) in index_names:
            indexed_columns.update(
                row[2] for row in conn.execute(f"PRAGMA index_info({name})")
            )
    finally:
        conn.close()
    assert "subject_pk" in indexed_columns


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


def _record_sample_run(
    store,
    model_name="churn_v3",
    subject_hashes=("h1", "h2"),
    started_at="2026-07-21T00:00:00+00:00",
):
    return store.record_training_run(
        model_name=model_name,
        model_hash="deadbeef",
        data_source="postgres://prod/customers",
        subject_id_col="email",
        subject_ids_hashed=True,
        subject_id_values=list(subject_hashes),
        started_at=started_at,
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


def test_latest_run_for_model_picks_latest_started_at(store):
    _record_sample_run(store, started_at="2026-07-01T00:00:00+00:00")
    newest = _record_sample_run(store, started_at="2026-07-15T00:00:00+00:00")
    latest = store.latest_run_for_model("churn_v3")
    assert latest["run_id"] == newest


def test_latest_run_for_unknown_model_is_none(store):
    assert store.latest_run_for_model("nope") is None


def test_record_revocation_appends_audit_entry_and_returns_id(store):
    entry_id = store.record_revocation(
        subject_key="abc123",
        n_affected_runs=2,
        recommended_actions=[{"model_name": "churn_v3", "action": "retrain"}],
    )
    entries = store.audit_entries()
    assert len(entries) == 1
    assert entries[0]["id"] == entry_id
    assert entries[0]["event_type"] == "revocation"
    payload = json.loads(entries[0]["payload"])
    assert payload["subject_key"] == "abc123"
    assert payload["n_affected_runs"] == 2
    assert payload["recommended_actions"] == [
        {"model_name": "churn_v3", "action": "retrain"}
    ]


def test_revocation_extends_hash_chain(store):
    _record_sample_run(store)
    store.record_revocation(subject_key="k", n_affected_runs=0, recommended_actions=[])
    first, second = store.audit_entries()
    assert second["prev_hash"] == first["entry_hash"]


def test_run_by_id_returns_the_run(store):
    run_id = _record_sample_run(store)
    run = store.run_by_id(run_id)
    assert run["run_id"] == run_id
    assert run["model_name"] == "churn_v3"
    assert run["n_subjects"] == 2


def test_run_by_id_unknown_is_none(store):
    assert store.run_by_id("nope") is None


def test_subject_count_for_run(store):
    run_id = _record_sample_run(store, subject_hashes=("h1", "h2", "h3"))
    assert store.subject_count_for_run(run_id) == 3


def test_subject_count_for_unknown_run_is_zero(store):
    assert store.subject_count_for_run("nope") == 0


def test_all_run_ids(store):
    a = _record_sample_run(store, model_name="a")
    b = _record_sample_run(store, model_name="b")
    assert store.all_run_ids() == {a, b}


def test_all_run_ids_empty(store):
    assert store.all_run_ids() == set()


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
