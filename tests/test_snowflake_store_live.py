# tests/test_snowflake_store_live.py
"""Live SnowflakeLineageStore tests. Skipped unless CONSENTML_SNOWFLAKE_TEST_*
is set. The only place the store's real Snowflake SQL (IDENTITY, transactions,
joins) is exercised -- the shim runs SQLite, not Snowflake."""
import pytest
from consentml.snowflake_store import SnowflakeLineageStore


@pytest.fixture
def live_store(snowflake_conn):
    # WARNING: this fixture DELETEs rows from training_runs, subject_index
    # and audit_log at teardown. snowflake_conn must point at a disposable
    # test database/schema -- never production. The DDL uses CREATE TABLE IF
    # NOT EXISTS, so it will attach to existing tables of the same name.
    store = SnowflakeLineageStore(connection=snowflake_conn)
    yield store
    # Clean up test rows the run created, then close.
    cur = store._conn.cursor()
    with cur:
        cur.execute("DELETE FROM subject_index")
        cur.execute("DELETE FROM training_runs")
        cur.execute("DELETE FROM audit_log")
    store._conn.commit()
    store.close()


def test_live_round_trip(live_store):
    rid = live_store.record_training_run(
        model_name="live", model_hash="h", provenance={"kind": "snowflake"},
        subject_ids_hashed=True, subject_id_values=["a", "b"],
        started_at="2026-01-01T00:00:00+00:00", finished_at="2026-01-01T00:00:01+00:00")
    assert live_store.subject_count_for_run(rid) == 2
    assert live_store.run_by_id(rid)["model_name"] == "live"
    entries = live_store.audit_entries()
    assert entries[-1]["prev_hash"] == "0" * 64
