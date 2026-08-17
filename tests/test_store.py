import hashlib
import json
import sqlite3

import pytest

from consentml.errors import ConsentMLError
from consentml.store import SQLiteLineageStore, default_db_path, provenance_hash, provenance_text
from consentml.verify import verify_audit_log


@pytest.fixture
def store(tmp_path):
    s = SQLiteLineageStore(db_path=tmp_path / "lineage.db")
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
    s = SQLiteLineageStore(db_path=tmp_path / "nested" / "dir" / "lineage.db")
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
    SQLiteLineageStore(db_path=tmp_path / "lineage.db").close()
    SQLiteLineageStore(db_path=tmp_path / "lineage.db").close()


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
        provenance={"kind": "dataframe", "label": "postgres://prod/customers"},
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


def test_fresh_database_is_schema_v2(store, tmp_path):
    assert store.schema_version == 2
    conn = sqlite3.connect(tmp_path / "lineage.db")
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 2
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


def test_legacy_database_reports_version_zero(legacy_db):
    s = SQLiteLineageStore(db_path=legacy_db)
    try:
        assert s.schema_version == 0
    finally:
        s.close()


def test_legacy_database_is_not_modified_on_open(legacy_db):
    before = legacy_db.read_bytes()
    SQLiteLineageStore(db_path=legacy_db).close()
    assert legacy_db.read_bytes() == before


def test_legacy_reads_work(legacy_db):
    s = SQLiteLineageStore(db_path=legacy_db)
    try:
        runs = s.runs_for_subject_value("h1")
        assert [r["model_name"] for r in runs] == ["churn_v3", "upsell"]
        assert s.subject_count_for_run("run-0") == 2
        assert s.all_run_ids() == {"run-0", "run-1"}
        assert s.run_by_id("run-0")["model_name"] == "churn_v3"
        # A v0 row's "provenance" is the old free-text data_source value,
        # not JSON -- pinned here so a future change can't quietly make this
        # look like structured provenance when it isn't.
        assert s.run_by_id("run-0")["provenance"] == "postgres://prod/customers"
    finally:
        s.close()


def test_legacy_writes_are_refused(legacy_db):
    s = SQLiteLineageStore(db_path=legacy_db)
    try:
        with pytest.raises(ConsentMLError, match="consentml migrate"):
            _record_sample_run(s)
        with pytest.raises(ConsentMLError, match="consentml migrate"):
            s.record_revocation(
                subject_key="k", n_affected_runs=0, recommended_actions=[]
            )
    finally:
        s.close()


def test_v1_database_reports_version_one(tmp_path, build_v1):
    path = tmp_path / "v1.db"
    build_v1(path)
    s = SQLiteLineageStore(db_path=path)
    try:
        assert s.schema_version == 1
    finally:
        s.close()


def test_v1_database_reads_work(tmp_path, build_v1):
    """A v1 database predates the provenance column but is not hostile --
    it's exactly what every database looked like before this task. All the
    read paths that transitively depend on the training_runs column list
    must keep working against it, not raise OperationalError."""
    path = tmp_path / "v1.db"
    run_id = build_v1(path)[0]
    s = SQLiteLineageStore(db_path=path)
    try:
        assert s.run_by_id(run_id)["model_name"] == "churn_v3"
        # A v1 row's "provenance" is the old free-text data_source value,
        # not JSON -- same as v0, pinned here so a future _parse_provenance
        # can't be written assuming every stored value is JSON.
        assert s.run_by_id(run_id)["provenance"] == "postgres://prod/customers"
        assert s.latest_run_for_model("churn_v3")["run_id"] == run_id
        assert [r["run_id"] for r in s.runs_for_subject_value("h1")] == [run_id]
        assert s.subject_count_for_run(run_id) == 2
        assert s.all_run_ids() == {run_id}
    finally:
        s.close()


def test_v1_database_writes_are_refused(tmp_path, build_v1):
    path = tmp_path / "v1.db"
    build_v1(path)
    s = SQLiteLineageStore(db_path=path)
    try:
        with pytest.raises(ConsentMLError, match="consentml migrate"):
            _record_sample_run(s)
    finally:
        s.close()


def test_v1_database_verifies_without_raising(tmp_path, build_v1):
    """The correctness bug this test guards against: verify_audit_log()'s
    contract is never raise on hostile database contents, and an honest,
    un-tampered v1 database is not hostile -- it must produce a clean
    report, not a traceback, from the OperationalError this schema change
    could otherwise introduce for every v1 database in the wild."""
    path = tmp_path / "v1.db"
    build_v1(path)
    report = verify_audit_log(db_path=path)
    assert report.ok is True


def test_provenance_is_stored_as_sorted_json(tmp_path):
    store = SQLiteLineageStore(db_path=tmp_path / "l.db")
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


def test_provenance_hash_is_stable_across_key_order():
    """sort_keys in provenance_text is what makes provenance_hash a function
    of *content*, not of the dict's insertion order. Without it, the same
    logical provenance recorded with keys in a different order would hash
    differently and every re-record would look like tampering."""
    assert provenance_hash(provenance_text({"kind": "x", "label": "y"})) == \
        provenance_hash(provenance_text({"label": "y", "kind": "x"}))


def test_audit_payload_carries_provenance_sha256_not_data_source(tmp_path):
    store = SQLiteLineageStore(db_path=tmp_path / "l.db")
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


def test_provenance_hash_of_non_string_is_none():
    """provenance_hash() is exercised here directly against a non-str value
    (nothing in this module's own call path can produce one): verify.py's
    _check_references feeds it values read straight from the provenance
    column, which a tampered database could hold as a BLOB or integer rather
    than TEXT."""
    assert provenance_hash(123) is None


def test_schema_version_is_2(tmp_path):
    store = SQLiteLineageStore(db_path=tmp_path / "l.db")
    assert store.schema_version == 2
    assert store._conn.execute("PRAGMA user_version").fetchone()[0] == 2
    cols = [c[1] for c in store._conn.execute("PRAGMA table_info(training_runs)")]
    assert "provenance" in cols
    assert "data_source" not in cols
    assert "subject_id_col" not in cols
    store.close()
