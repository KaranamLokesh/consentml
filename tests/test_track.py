import pandas as pd
import pytest

from consentml import ConsentMLError, track
from consentml.sources import DataFrameSource, SourceResult
from consentml.store import SQLiteLineageStore


def _df():
    return pd.DataFrame({"pid": ["P1", "P2"], "x": [1, 2]})


def test_payload_is_injected_into_the_training_function(tmp_path):
    seen = {}

    @track(model_name="m", source=DataFrameSource(_df(), subject_id_col="pid"),
           db_path=tmp_path / "l.db")
    def train(df):
        seen["df"] = df
        return "model"

    assert train() == "model"
    assert list(seen["df"]["pid"]) == ["P1", "P2"]


def test_extra_arguments_are_passed_through(tmp_path):
    @track(model_name="m", source=DataFrameSource(_df(), subject_id_col="pid"),
           db_path=tmp_path / "l.db")
    def train(df, *, epochs):
        return epochs

    assert train(epochs=7) == 7


def test_provenance_from_the_source_is_recorded(tmp_path):
    db = tmp_path / "l.db"

    @track(model_name="m",
           source=DataFrameSource(_df(), subject_id_col="pid",
                                  label="clinic.patients"),
           db_path=db)
    def train(df):
        return "model"

    train()
    store = SQLiteLineageStore(db_path=db)
    provenance = store._conn.execute(
        "SELECT provenance FROM training_runs"
    ).fetchone()[0]
    store.close()
    assert '"label": "clinic.patients"' in provenance
    assert '"kind": "dataframe"' in provenance


def test_source_failure_happens_before_training(tmp_path):
    called = []

    class Failing:
        def load(self):
            raise ConsentMLError("boom")

    @track(model_name="m", source=Failing(), db_path=tmp_path / "l.db")
    def train(df):
        called.append(True)
        return "model"

    with pytest.raises(ConsentMLError, match="boom"):
        train()
    assert called == []


def test_a_crashed_training_function_records_nothing(tmp_path):
    db = tmp_path / "l.db"

    @track(model_name="m", source=DataFrameSource(_df(), subject_id_col="pid"),
           db_path=db)
    def train(df):
        raise ValueError("training blew up")

    with pytest.raises(ValueError):
        train()
    store = SQLiteLineageStore(db_path=db)
    assert store._conn.execute("SELECT COUNT(*) FROM training_runs").fetchone()[0] == 0
    store.close()


def test_hash_subject_ids_false_stores_raw_ids(tmp_path):
    db = tmp_path / "l.db"

    @track(model_name="m", source=DataFrameSource(_df(), subject_id_col="pid"),
           hash_subject_ids=False, db_path=db)
    def train(df):
        return "model"

    train()
    store = SQLiteLineageStore(db_path=db)
    keys = {r[0] for r in store._conn.execute("SELECT subject_key FROM subjects")}
    store.close()
    assert keys == {"P1", "P2"}


def test_any_source_object_works(tmp_path):
    class Custom:
        def load(self):
            return SourceResult(
                payload="anything",
                subject_ids=["s1"],
                provenance={"kind": "custom"},
            )

    @track(model_name="m", source=Custom(), db_path=tmp_path / "l.db")
    def train(payload):
        assert payload == "anything"
        return "model"

    assert train() == "model"
