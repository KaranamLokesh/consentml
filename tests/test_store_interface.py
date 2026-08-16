import abc
import pytest
from consentml.store import LineageStore, SQLiteLineageStore, compute_entry_hash
from consentml.store import open_store


def test_lineagestore_is_abstract():
    assert issubclass(LineageStore, abc.ABC)
    with pytest.raises(TypeError):
        LineageStore()  # abstract methods -> not instantiable


def test_sqlite_store_implements_the_interface():
    assert issubclass(SQLiteLineageStore, LineageStore)


def test_compute_entry_hash_matches_the_known_formula(tmp_path):
    import hashlib
    got = compute_entry_hash("0" * 64, "2026-01-01T00:00:00+00:00", "training_run", "{}")
    want = hashlib.sha256(("0" * 64 + "2026-01-01T00:00:00+00:00" + "training_run" + "{}").encode()).hexdigest()
    assert got == want


def test_open_store_defaults_to_sqlite(tmp_path):
    store = open_store(db_path=tmp_path / "l.db")
    try:
        assert isinstance(store, SQLiteLineageStore)
    finally:
        store.close()


def test_open_store_dict_target_builds_snowflake(monkeypatch):
    from tests.fakes.snowflake import shim_connect
    from consentml import snowflake_store as sfs
    monkeypatch.setattr(sfs, "_connect", shim_connect)
    store = open_store({"account": "a", "user": "u", "password": "p",
                        "database": "D", "schema": "S", "warehouse": "W"})
    try:
        assert type(store).__name__ == "SnowflakeLineageStore"
    finally:
        store.close()
