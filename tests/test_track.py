import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression

from consentml.hashing import hash_subject_id
from consentml.store import LineageStore
from consentml.track import ConsentMLError, track


@pytest.fixture
def df():
    return pd.DataFrame(
        {
            "email": ["a@x.com", "b@x.com", "a@x.com", "c@x.com"],
            "f1": [0.1, 0.9, 0.2, 0.8],
            "label": [0, 1, 0, 1],
        }
    )


def _train(df):
    model = LogisticRegression()
    model.fit(df[["f1"]], df["label"])
    return model


def test_track_records_lineage(tmp_path, df):
    db = tmp_path / "lineage.db"
    decorated = track(
        data_source="postgres://prod/customers",
        subject_id_col="email",
        model_name="churn_v3",
        db_path=db,
    )(_train)
    model = decorated(df)
    assert hasattr(model, "predict")  # training result passes through

    store = LineageStore(db_path=db)
    try:
        runs = store.runs_for_subject_value(hash_subject_id("a@x.com"))
        assert len(runs) == 1
        run = runs[0]
        assert run["model_name"] == "churn_v3"
        assert run["data_source"] == "postgres://prod/customers"
        assert run["n_subjects"] == 3  # unique subjects, not rows
        assert run["subject_ids_hashed"] == 1
        assert len(run["model_hash"]) == 64
        assert len(store.audit_entries()) == 1
    finally:
        store.close()


def test_track_finds_dataframe_in_kwargs(tmp_path, df):
    decorated = track(
        data_source="s",
        subject_id_col="email",
        model_name="m",
        db_path=tmp_path / "l.db",
    )(lambda **kw: _train(kw["df"]))
    decorated(df=df)


def test_track_unhashed_subject_ids(tmp_path, df):
    db = tmp_path / "lineage.db"
    decorated = track(
        data_source="s",
        subject_id_col="email",
        model_name="m",
        hash_subject_ids=False,
        db_path=db,
    )(_train)
    decorated(df)
    store = LineageStore(db_path=db)
    try:
        runs = store.runs_for_subject_value("a@x.com")
        assert len(runs) == 1
        assert runs[0]["subject_ids_hashed"] == 0
    finally:
        store.close()


def test_track_raises_when_no_dataframe(tmp_path):
    decorated = track(
        data_source="s",
        subject_id_col="email",
        model_name="m",
        db_path=tmp_path / "l.db",
    )(lambda x: x)
    with pytest.raises(ConsentMLError, match="No pandas DataFrame"):
        decorated(42)


def test_track_raises_when_column_missing(tmp_path, df):
    decorated = track(
        data_source="s",
        subject_id_col="user_id",
        model_name="m",
        db_path=tmp_path / "l.db",
    )(_train)
    with pytest.raises(ConsentMLError, match="user_id"):
        decorated(df)


def test_track_fails_before_training_runs(tmp_path, df):
    calls = []

    @track(
        data_source="s",
        subject_id_col="missing_col",
        model_name="m",
        db_path=tmp_path / "l.db",
    )
    def train(df):
        calls.append(1)

    with pytest.raises(ConsentMLError):
        train(df)
    assert calls == []  # validation happens before the expensive training call
