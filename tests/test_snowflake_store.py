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


def test_read_methods(monkeypatch):
    store = _store(monkeypatch)
    try:
        rid = store.record_training_run(
            model_name="churn", model_hash="h1", provenance={"kind": "snowflake"},
            subject_ids_hashed=True, subject_id_values=["a", "b"],
            started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00")
        assert store.all_run_ids() == {rid}
        assert store.run_by_id(rid)["model_name"] == "churn"
        assert store.latest_run_for_model("churn")["run_id"] == rid
        assert store.subject_count_for_run(rid) == 2
        runs = store.runs_for_subject_value("a")
        assert [r["run_id"] for r in runs] == [rid]
        assert store.runs_for_subject_value("nobody") == []
        assert store.run_by_id("missing") is None
        assert store.latest_run_for_model("missing") is None
    finally:
        store.close()


def test_revocation_and_audit_entries_chain(monkeypatch):
    store = _store(monkeypatch)
    try:
        store.record_training_run(
            model_name="m", model_hash="h", provenance={"kind": "snowflake"},
            subject_ids_hashed=True, subject_id_values=["a"],
            started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00")
        store.record_revocation(subject_key="hashed-a", n_affected_runs=1,
                                recommended_actions=["retrain"])
        entries = store.audit_entries()
        assert [e["event_type"] for e in entries] == ["training_run", "revocation"]
        # chain links: each prev_hash equals the previous entry_hash
        assert entries[0]["prev_hash"] == "0" * 64
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    finally:
        store.close()


def test_record_revocation_returns_the_actual_audit_row_id(monkeypatch):
    # Pins the load-bearing property behind the MAX(id) decision (see
    # task-4-8-report.md): revoke.py stores this return value as
    # AffectedModelsReport.audit_log_entry_id, which the CLI prints and
    # test_revoke.py asserts for exact id-equality against the SQLite
    # backend. A prior audit entry (the training run) is seeded first so the
    # revocation's id (2) is distinct from "count of revocation rows" (1) --
    # a scoped-count regression would return 1 here and fail this assertion.
    store = _store(monkeypatch)
    try:
        store.record_training_run(
            model_name="m", model_hash="h", provenance={"kind": "snowflake"},
            subject_ids_hashed=True, subject_id_values=["a"],
            started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00")
        returned_id = store.record_revocation(
            subject_key="hashed-a", n_affected_runs=1, recommended_actions=["retrain"])
        assert returned_id == store.audit_entries()[-1]["id"]
    finally:
        store.close()


def test_import_connector_returns_the_real_module():
    from consentml import snowflake_store as sfs
    import snowflake.connector as expected

    assert sfs._import_connector() is expected


def test_import_connector_raises_consentml_error_when_missing(monkeypatch):
    import builtins
    from consentml import snowflake_store as sfs
    from consentml import ConsentMLError

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("snowflake"):
            raise ImportError("no snowflake connector")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ConsentMLError, match="pip install"):
        sfs._import_connector()


def test_connect_sets_qmark_paramstyle_and_autocommit_false(monkeypatch):
    from consentml import snowflake_store as sfs

    calls = {}

    class _FakeConnector:
        def connect(self, **params):
            calls.update(params)
            return "sentinel-conn"

    monkeypatch.setattr(sfs, "_import_connector", lambda: _FakeConnector())
    result = sfs._connect({"account": "a"})
    assert result == "sentinel-conn"
    assert calls == {"account": "a", "paramstyle": "qmark", "autocommit": False}


class _FailOnMatch:
    """Cursor wrapper that raises on the first execute/executemany whose SQL
    contains `trigger`, otherwise forwards to the real (shim) cursor."""

    def __init__(self, inner, trigger):
        self._inner = inner
        self._trigger = trigger

    def execute(self, sql, params=()):
        if self._trigger in sql:
            raise RuntimeError("boom")
        return self._inner.execute(sql, params)

    def executemany(self, sql, seq):
        if self._trigger in sql:
            raise RuntimeError("boom")
        return self._inner.executemany(sql, seq)

    def fetchone(self):
        return self._inner.fetchone()

    def fetchall(self):
        return self._inner.fetchall()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return self._inner.__exit__(*a)


def test_record_training_run_rolls_back_on_failure(monkeypatch):
    store = _store(monkeypatch)
    try:
        real_cursor = store._conn.cursor
        monkeypatch.setattr(
            store._conn, "cursor",
            lambda: _FailOnMatch(real_cursor(), "INSERT INTO subject_index"),
        )
        with pytest.raises(RuntimeError, match="boom"):
            store.record_training_run(
                model_name="m", model_hash="h", provenance={"kind": "snowflake"},
                subject_ids_hashed=True, subject_id_values=["a"],
                started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00")
        # No partial row from the failed transaction persisted.
        assert store.all_run_ids() == set()
        assert store.audit_entries() == []
    finally:
        store.close()


def test_record_revocation_rolls_back_on_failure(monkeypatch):
    store = _store(monkeypatch)
    try:
        store.record_training_run(
            model_name="m", model_hash="h", provenance={"kind": "snowflake"},
            subject_ids_hashed=True, subject_id_values=["a"],
            started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00")
        before = store.audit_entries()

        real_cursor = store._conn.cursor
        monkeypatch.setattr(
            store._conn, "cursor",
            lambda: _FailOnMatch(real_cursor(), "INSERT INTO audit_log"),
        )
        with pytest.raises(RuntimeError, match="boom"):
            store.record_revocation(subject_key="hashed-a", n_affected_runs=1,
                                    recommended_actions=["retrain"])
        # No partial revocation entry from the failed transaction persisted.
        assert store.audit_entries() == before
    finally:
        store.close()


def test_sqlite_and_snowflake_produce_identical_audit_chains(monkeypatch, tmp_path):
    from consentml.store import SQLiteLineageStore

    events = [
        dict(model_name="m1", model_hash="h1", provenance={"kind": "x", "q": "1"},
             subject_ids_hashed=True, subject_id_values=["a", "b"],
             started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00"),
        dict(model_name="m2", model_hash="h2", provenance={"kind": "x", "q": "2"},
             subject_ids_hashed=True, subject_id_values=["b", "c"],
             started_at="2026-01-02T00:00:00+00:00", finished_at="2026-01-02T00:00:01+00:00"),
    ]

    def chain(store):
        for e in events:
            store.record_training_run(**e)
        return [(x["event_type"], x["prev_hash"]) for x in store.audit_entries()], \
               [x["entry_hash"] for x in store.audit_entries()]

    sq = SQLiteLineageStore(db_path=tmp_path / "l.db")
    sf = _store(monkeypatch)
    try:
        sq_meta, _ = chain(sq)
        sf_meta, _ = chain(sf)
        # entry_hash embeds a wall-clock timestamp, so the hashes themselves
        # differ run-to-run; what must match is the CHAIN STRUCTURE: same
        # event order, and each prev_hash linking to the prior entry_hash.
        assert [m[0] for m in sq_meta] == [m[0] for m in sf_meta] == ["training_run", "training_run"]
        for entries in (sq.audit_entries(), sf.audit_entries()):
            assert entries[0]["prev_hash"] == "0" * 64
            assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    finally:
        sq.close()
        sf.close()
