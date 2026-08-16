import pytest

from tests.fakes.snowflake import shim_connect


def test_shim_rewrites_identity_ddl():
    from tests.fakes.snowflake import _to_sqlite_ddl

    out = _to_sqlite_ddl("CREATE TABLE audit_log (id NUMBER IDENTITY PRIMARY KEY, t VARCHAR)")
    assert "INTEGER PRIMARY KEY AUTOINCREMENT" in out


def _store(monkeypatch):
    from consentml import snowflake_store as sfs
    monkeypatch.setattr(sfs, "_connect", shim_connect)
    return sfs.SnowflakeLineageStore(connection={"account": "a", "user": "u",
                                                 "password": "p", "database": "D",
                                                 "schema": "S", "warehouse": "W"})


def test_store_creates_schema_and_is_a_lineagestore(monkeypatch):
    from consentml.store import LineageStore
    store = _store(monkeypatch)
    try:
        assert isinstance(store, LineageStore)
        # schema_meta seeded to version 1
        cur = store._conn.cursor()
        with cur:
            cur.execute("SELECT version FROM schema_meta")
            assert cur.fetchone()[0] == 1
    finally:
        store.close()


def test_record_training_run_writes_run_subjects_and_audit(monkeypatch):
    store = _store(monkeypatch)
    try:
        run_id = store.record_training_run(
            model_name="churn", model_hash="h1",
            provenance={"kind": "snowflake", "query": "SELECT 1"},
            subject_ids_hashed=True,
            subject_id_values=["a", "b", "c"],
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
        )
        assert isinstance(run_id, str) and len(run_id) == 36
        # Narrowed per the brief's task-by-task alternative: query the tables
        # directly rather than via subject_count_for_run/audit_entries, which
        # are implemented in Tasks 6-7. Those tasks' own tests (below) cover
        # the same data through the real helper methods.
        cur = store._conn.cursor()
        with cur:
            cur.execute(
                "SELECT COUNT(*) FROM subject_index WHERE run_id = ?", (run_id,)
            )
            assert cur.fetchone()[0] == 3
            cur.execute("SELECT event_type, prev_hash FROM audit_log")
            rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "training_run"
        assert rows[0][1] == "0" * 64
    finally:
        store.close()
