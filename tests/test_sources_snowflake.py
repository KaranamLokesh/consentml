import builtins
import hashlib
import json
import traceback

import pytest

from consentml import ConsentMLError
from consentml.sources.snowflake import SnowflakeSource
from tests.fakes.snowflake import FakeSnowflakeConnection

MINIMAL_CONN = {
    "account": "acct",
    "user": "u",
    "password": "p",
    "database": "DB",
    "schema": "PUBLIC",
    "warehouse": "WH",
}

CONN = {"account": "acct", "user": "u", "password": "p",
        "database": "DB", "schema": "PUBLIC", "warehouse": "WH"}
QUERY = "SELECT patient_id, age FROM patients"


def test_missing_connector_raises_consentml_error(monkeypatch):
    from consentml.sources.snowflake import SnowflakeSource

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("snowflake"):
            raise ImportError("no snowflake connector")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ConsentMLError, match="pip install"):
        SnowflakeSource(connection=MINIMAL_CONN, query="SELECT 1", subject_id_col="x")


def test_conninfo_never_leaks_credentials():
    from consentml.sources.snowflake import _safe_conninfo

    info = _safe_conninfo({
        "account": "acct", "user": "sekret_user", "password": "sekret_pass",
        "private_key": b"KEYBYTES", "database": "DB", "schema": "S", "warehouse": "WH",
    })
    flat = repr(info)
    assert info == {"account": "acct", "database": "DB", "schema": "S", "warehouse": "WH"}
    assert "sekret_user" not in flat
    assert "sekret_pass" not in flat
    assert "KEYBYTES" not in flat


# --- Task 4: load() -- dataframe, subject-id contract, provenance ---------


def _script(rows, names=("PATIENT_ID", "AGE")):
    # EXPLAIN returns no usable plan here (mechanism -> unavailable); the real
    # query returns the given rows. Order matters: EXPLAIN is matched first.
    return [("EXPLAIN", [], None), ("SELECT", rows, names)]


def _install(monkeypatch, rows, names=("PATIENT_ID", "AGE")):
    from consentml.sources import snowflake as sf
    monkeypatch.setattr(sf, "_connect",
                        lambda connection: FakeSnowflakeConnection(_script(rows, names)))


def test_loads_rows_into_a_dataframe(monkeypatch):
    _install(monkeypatch, [("P1", 30), ("P2", 40), ("P3", 50)])
    result = SnowflakeSource(connection=CONN, query=QUERY, subject_id_col="PATIENT_ID").load()
    assert list(result.payload.columns) == ["PATIENT_ID", "AGE"]
    assert len(result.payload) == 3


def test_subject_ids_distinct_stringified(monkeypatch):
    _install(monkeypatch, [(1, 30), (1, 31), (2, 40)])  # int ids, repeated
    result = SnowflakeSource(connection=CONN, query=QUERY, subject_id_col="PATIENT_ID").load()
    assert sorted(result.subject_ids) == ["1", "2"]
    assert all(isinstance(s, str) for s in result.subject_ids)


def test_provenance_records_query_hash_and_excludes_credentials(monkeypatch):
    _install(monkeypatch, [("P1", 30)])
    p = SnowflakeSource(connection=CONN, query=QUERY, subject_id_col="PATIENT_ID").load().provenance
    assert p["kind"] == "snowflake"
    assert p["database"] == "DB"
    assert p["query_sha256"] == hashlib.sha256(QUERY.encode("utf-8")).hexdigest()
    assert p["n_rows"] == 1
    # NOTE: the brief's literal assertion here was `"u" not in repr(p)...`,
    # which is unsatisfiable regardless of correctness -- the mandated
    # "query" key contains the letter "u". Replaced with a key/value check
    # that actually pins the "no user field" intent, mirroring
    # test_credentials_never_appear_in_provenance in test_sources_postgres.py.
    assert "user" not in p
    assert "password" not in p
    assert "password" not in repr(p)


def test_missing_subject_column_raises(monkeypatch):
    _install(monkeypatch, [("P1", 30)])
    with pytest.raises(ConsentMLError, match="nope"):
        SnowflakeSource(connection=CONN, query=QUERY, subject_id_col="nope").load()


def test_empty_result_raises(monkeypatch):
    _install(monkeypatch, [])
    with pytest.raises(ConsentMLError, match="no rows"):
        SnowflakeSource(connection=CONN, query=QUERY, subject_id_col="PATIENT_ID").load()


def test_null_subject_id_raises(monkeypatch):
    _install(monkeypatch, [(None, 30), ("P2", 40)])
    with pytest.raises(ConsentMLError, match="null"):
        SnowflakeSource(connection=CONN, query=QUERY, subject_id_col="PATIENT_ID").load()
