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
