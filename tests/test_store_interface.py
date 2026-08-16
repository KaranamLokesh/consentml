import abc
import pytest
from consentml.store import LineageStore, SQLiteLineageStore, compute_entry_hash


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
