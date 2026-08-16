# tests/test_sources_snowflake_live.py
"""Live Snowflake tests. Skipped unless CONSENTML_SNOWFLAKE_TEST_* is set.

These run real SQL against a real account and are the only place that confirms
the EXPLAIN USING JSON parsing against Snowflake's actual plan shape.
"""
from consentml.sources.snowflake import SnowflakeSource


def test_live_select_roundtrip(snowflake_conn):
    result = SnowflakeSource(
        connection=snowflake_conn,
        query="SELECT 1 AS SUBJECT_ID, 'a' AS FEATURE",
        subject_id_col="SUBJECT_ID",
    ).load()
    assert result.subject_ids == ["1"]
    assert result.provenance["kind"] == "snowflake"
    assert result.provenance["n_rows"] == 1
