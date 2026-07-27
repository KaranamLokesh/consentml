import pytest

from consentml import ConsentMLError
from consentml.sources.postgres import PostgresSource

QUERY = """
    SELECT p.patient_id, p.age, l.ldl, p.outcome
    FROM patients p JOIN labs l USING (patient_id)
"""


def test_loads_rows_into_a_dataframe(pg_tables):
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert list(result.payload.columns) == ["patient_id", "age", "ldl", "outcome"]
    assert len(result.payload) == 3


def test_subject_ids_are_distinct_and_stringified(pg_tables):
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert sorted(result.subject_ids) == ["P1", "P2", "P3"]


def test_dedupes_subject_ids_across_repeated_rows(pg_tables):
    # QUERY above is a 1:1 join, so it can never exercise .unique() -- every
    # patient_id already appears exactly once. This query deliberately
    # returns each patient twice so dropping .unique() would inflate
    # subject_ids (and therefore n_subjects) without any test noticing.
    dup_query = (
        "SELECT patient_id, age, outcome FROM patients "
        "UNION ALL "
        "SELECT patient_id, age, outcome FROM patients"
    )
    result = PostgresSource(
        dsn=pg_tables, query=dup_query, subject_id_col="patient_id"
    ).load()
    assert len(result.payload) == 6
    assert sorted(result.subject_ids) == ["P1", "P2", "P3"]


def test_provenance_records_query_and_hash(pg_tables):
    import hashlib

    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    p = result.provenance
    assert p["kind"] == "postgres"
    assert p["database"] == "consentml_test"
    assert p["query"] == QUERY
    assert p["query_sha256"] == hashlib.sha256(QUERY.encode("utf-8")).hexdigest()
    assert p["n_rows"] == 3


def test_credentials_never_appear_in_provenance(pg_tables):
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    flat = repr(result.provenance)
    assert "consentml@" not in flat
    assert "password" not in flat
    assert "user" not in result.provenance


def test_conninfo_never_leaks_credentials_regardless_of_dsn():
    # test_credentials_never_appear_in_provenance above only pins the
    # absence of the CI DSN's specific password string, which is vacuously
    # true against the local trust-auth DSN that has no password at all.
    # This test constructs a DSN that definitely carries a username and
    # password and never connects -- _safe_conninfo runs at construction,
    # before any network call, so this exercises exactly the stripping
    # logic without needing a reachable server.
    source = PostgresSource(
        dsn="postgresql://sekret_user:sekret_pass@127.0.0.1:1/none",
        query=QUERY,
        subject_id_col="patient_id",
    )
    flat = repr(source._conninfo)
    assert "sekret_user" not in flat
    assert "sekret_pass" not in flat


def test_missing_subject_column_raises(pg_tables):
    with pytest.raises(ConsentMLError, match="nope"):
        PostgresSource(dsn=pg_tables, query=QUERY, subject_id_col="nope").load()


def test_empty_result_raises(pg_tables):
    with pytest.raises(ConsentMLError, match="no rows"):
        PostgresSource(
            dsn=pg_tables,
            query="SELECT * FROM patients WHERE patient_id = 'nobody'",
            subject_id_col="patient_id",
        ).load()


def test_null_subject_id_raises(pg_tables):
    with pytest.raises(ConsentMLError, match="null"):
        PostgresSource(
            dsn=pg_tables,
            query="SELECT NULL::text AS patient_id, age FROM patients",
            subject_id_col="patient_id",
        ).load()


def test_unreachable_host_raises_consentml_error(pg_tables):
    source = PostgresSource(
        dsn="postgresql://nobody@127.0.0.1:1/none",
        query=QUERY,
        subject_id_col="patient_id",
    )
    with pytest.raises(ConsentMLError, match="could not connect"):
        source.load()


def test_malformed_dsn_raises_consentml_error():
    # Exercises the ProgrammingError branch in _safe_conninfo, which runs at
    # construction time -- before any connection attempt.
    with pytest.raises(ConsentMLError, match="could not parse"):
        PostgresSource(dsn="not a=uri", query=QUERY, subject_id_col="patient_id")


def test_bad_query_raises_consentml_error(pg_tables):
    with pytest.raises(ConsentMLError, match="training query failed"):
        PostgresSource(
            dsn=pg_tables,
            query="SELECT * FROM table_that_does_not_exist",
            subject_id_col="patient_id",
        ).load()


def test_a_join_reports_both_tables(pg_tables):
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert result.provenance["referenced_tables"] == [
        "public.labs",
        "public.patients",
    ]
    assert result.provenance["referenced_tables_source"] == "explain"


def test_referenced_tables_are_sorted_even_if_the_planner_walk_is_not(
    pg_tables, monkeypatch
):
    # _relations returns a set, and set iteration order for just two table
    # names depends on Python's (per-process randomized) string hashing --
    # for "public.labs"/"public.patients" it can coincidentally already come
    # out alphabetical, so a broken `list(...)` in place of `sorted(...)` in
    # _referenced_tables can slip past test_a_join_reports_both_tables on
    # some runs and not others (reproduced locally by varying
    # PYTHONHASHSEED). Faking _relations to return a plain list -- whose
    # order is never hash-dependent -- pins the sort call deterministically.
    from consentml.sources import postgres as pg_module

    monkeypatch.setattr(
        pg_module, "_relations", lambda plan, found: ["public.zzz", "public.aaa"]
    )
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert result.provenance["referenced_tables"] == ["public.aaa", "public.zzz"]


def test_single_table_query_reports_one_table(pg_tables):
    result = PostgresSource(
        dsn=pg_tables,
        query="SELECT patient_id, age FROM patients",
        subject_id_col="patient_id",
    ).load()
    assert result.provenance["referenced_tables"] == ["public.patients"]


def test_a_table_in_a_non_public_schema_is_schema_qualified(pg_tables):
    # test_a_join_reports_both_tables and test_single_table_query_reports_one_
    # table both only ever see the public schema, so a version of _relations
    # that hardcodes "public" instead of reading the plan's "Schema" key
    # would pass both. This pins the actual Schema lookup.
    import psycopg

    with psycopg.connect(pg_tables) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE SCHEMA IF NOT EXISTS other")
            cur.execute("DROP TABLE IF EXISTS other.notes")
            cur.execute("CREATE TABLE other.notes (patient_id text, note text)")
            cur.executemany(
                "INSERT INTO other.notes VALUES (%s, %s)",
                [("P1", "n1"), ("P2", "n2"), ("P3", "n3")],
            )
        conn.commit()
    try:
        result = PostgresSource(
            dsn=pg_tables,
            query="SELECT patient_id, note FROM other.notes",
            subject_id_col="patient_id",
        ).load()
        assert result.provenance["referenced_tables"] == ["other.notes"]
    finally:
        with psycopg.connect(pg_tables) as conn:
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS other.notes")
                cur.execute("DROP SCHEMA IF EXISTS other")
            conn.commit()


def test_run_explain_raises_when_no_plan_row_is_returned():
    # Exercises _run_explain's own defensive branch directly: a cursor whose
    # fetchone() comes back empty (no row, or a row holding a falsy plan)
    # has no live path through the real Postgres driver to reach here, but
    # _run_explain must still not misinterpret it as a usable plan.
    from consentml.sources import postgres as pg_module

    class _EmptyCursor:
        def execute(self, sql):
            pass

        def fetchone(self):
            return None

    with pytest.raises(pg_module._ExplainUnavailable):
        pg_module._run_explain(_EmptyCursor(), "SELECT 1")


def test_referenced_tables_rollback_lets_the_real_query_run_after_explain_fails(
    pg_tables,
):
    # Pins the claim in _referenced_tables' docstring that a failed EXPLAIN
    # aborts the surrounding Postgres transaction, so the rollback is
    # required for anything to run afterwards on the same connection.
    #
    # test_bad_query_raises_consentml_error can't pin this: it runs the same
    # bad query through both EXPLAIN and the real execute(), so it fails
    # (and gets wrapped in the same generic "training query failed"
    # ConsentMLError) whether or not the rollback happens -- once via the
    # table genuinely not existing, once via "current transaction is
    # aborted" if the rollback is missing. Both look identical to that test.
    #
    # This also corrects an assumption in the task description: EXPLAIN
    # (without ANALYZE) never executes anything, so EXPLAINing a *write*
    # query under read_only succeeds fine -- confirmed manually against
    # this Postgres 14 instance. A bad *table name* is what actually aborts
    # the transaction, so that's what this test uses to force the failure.
    import psycopg

    source = PostgresSource(
        dsn=pg_tables,
        query="SELECT * FROM table_that_does_not_exist",
        subject_id_col="patient_id",
    )
    with psycopg.connect(pg_tables) as conn:
        conn.read_only = True
        with conn.cursor() as cur:
            tables, mechanism = source._referenced_tables(cur)
            assert tables is None
            assert mechanism == "unavailable"
            # Without the rollback, this raises InFailedSqlTransaction
            # instead of returning a row.
            cur.execute("SELECT 1")
            assert cur.fetchone() == (1,)


def test_explain_failure_degrades_without_failing_the_run(pg_tables, monkeypatch):
    from consentml.sources import postgres as pg_module

    def boom(cur, query):
        raise pg_module._explain_failed()

    monkeypatch.setattr(pg_module, "_run_explain", boom)
    result = PostgresSource(
        dsn=pg_tables, query=QUERY, subject_id_col="patient_id"
    ).load()
    assert result.provenance["referenced_tables"] is None
    assert result.provenance["referenced_tables_source"] == "unavailable"
    assert len(result.payload) == 3


def test_a_write_query_is_rejected(pg_tables):
    source = PostgresSource(
        dsn=pg_tables,
        query="INSERT INTO patients VALUES ('P9', 99, 1) RETURNING patient_id",
        subject_id_col="patient_id",
    )
    with pytest.raises(ConsentMLError):
        source.load()


def test_the_source_database_is_unchanged_after_a_rejected_write(pg_tables):
    import psycopg

    source = PostgresSource(
        dsn=pg_tables,
        query="INSERT INTO patients VALUES ('P9', 99, 1) RETURNING patient_id",
        subject_id_col="patient_id",
    )
    with pytest.raises(ConsentMLError):
        source.load()
    with psycopg.connect(pg_tables) as conn:
        count = conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0]
    assert count == 3


def test_missing_psycopg_raises_consentml_error(monkeypatch):
    # psycopg is a hard dev dependency now, so this can't happen in practice
    # via a plain `import psycopg` failure -- but PostgresSource is also
    # shipped for users who install consentml without the `postgres` extra,
    # and _import_psycopg's ImportError handling is what turns that into a
    # clear message instead of a raw traceback.
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "psycopg":
            raise ImportError("no module named psycopg")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ConsentMLError, match="pip install"):
        PostgresSource(
            dsn="postgresql://x/y", query=QUERY, subject_id_col="patient_id"
        )
