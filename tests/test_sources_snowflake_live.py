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


def test_live_referenced_tables_against_a_real_table(snowflake_conn):
    """Validate EXPLAIN USING JSON table extraction against a real plan.

    test_live_select_roundtrip queries a table-less SELECT, so it never
    exercises _relations/_TABLE_KEYS. This test creates a scratch table, runs
    the source over it, and asserts referenced_tables picks the table up --
    the only real check that the parser's key names match Snowflake's actual
    plan shape. On failure it prints the raw EXPLAIN plan so _TABLE_KEYS can be
    corrected from the output (run with -s to always see it).

    Requires the test role to have CREATE TABLE on the target schema.
    """
    import snowflake.connector

    table = "CONSENTML_LIVETEST_REFTABLES"
    setup = snowflake.connector.connect(**snowflake_conn)
    cur = setup.cursor()
    try:
        cur.execute(f"CREATE OR REPLACE TABLE {table} (SUBJECT_ID STRING, FEATURE INT)")
        cur.execute(f"INSERT INTO {table} VALUES ('s1', 1), ('s2', 2)")
        setup.commit()

        result = SnowflakeSource(
            connection=snowflake_conn,
            query=f"SELECT SUBJECT_ID, FEATURE FROM {table}",
            subject_id_col="SUBJECT_ID",
        ).load()
        assert sorted(result.subject_ids) == ["s1", "s2"]

        rt = result.provenance["referenced_tables"]
        src = result.provenance["referenced_tables_source"]

        # Diagnostic: dump the raw plan so a parser mismatch is fixable from
        # the captured output (pytest shows captured stdout on failure).
        cur.execute(f"EXPLAIN USING JSON SELECT SUBJECT_ID, FEATURE FROM {table}")
        raw_plan = cur.fetchone()[0]
        print(f"\nreferenced_tables={rt!r}  source={src!r}")
        print(f"raw EXPLAIN plan:\n{raw_plan}")

        assert src == "explain", "EXPLAIN did not run/parse; see raw plan above"
        assert any(table in t.upper() for t in (rt or [])), (
            f"parser missed {table} in {rt!r}; see raw plan above to fix _TABLE_KEYS"
        )
    finally:
        cur.execute(f"DROP TABLE IF EXISTS {table}")
        setup.commit()
        setup.close()
