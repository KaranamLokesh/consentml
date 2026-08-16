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
