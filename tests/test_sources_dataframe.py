import pandas as pd
import pytest

from consentml import ConsentMLError
from consentml.sources import DataFrameSource, Source, SourceResult


def test_source_result_is_frozen():
    result = SourceResult(payload=[1, 2], subject_ids=["a"], provenance={"kind": "x"})
    assert result.payload == [1, 2]
    assert result.subject_ids == ["a"]
    assert result.provenance == {"kind": "x"}
    try:
        result.payload = [3]
    except AttributeError:
        pass
    else:
        raise AssertionError("SourceResult should be frozen")


def test_any_object_with_load_satisfies_the_protocol():
    class Fake:
        def load(self):
            return SourceResult(payload=None, subject_ids=[], provenance={})

    assert isinstance(Fake(), Source)


def _df():
    return pd.DataFrame({"pid": ["P1", "P1", "P2"], "age": [30, 31, 40]})


def test_dedupes_subjects_and_passes_the_frame_through():
    df = _df()
    result = DataFrameSource(df, subject_id_col="pid").load()
    assert result.payload is df
    assert sorted(result.subject_ids) == ["P1", "P2"]


def test_provenance_records_label_and_row_count():
    result = DataFrameSource(
        _df(), subject_id_col="pid", label="clinic.patients"
    ).load()
    assert result.provenance == {
        "kind": "dataframe",
        "label": "clinic.patients",
        "subject_id_col": "pid",
        "n_rows": 3,
    }


def test_label_is_optional_and_defaults_to_none():
    result = DataFrameSource(_df(), subject_id_col="pid").load()
    assert result.provenance["label"] is None


def test_subject_ids_are_stringified():
    df = pd.DataFrame({"pid": [1, 2], "x": [0, 1]})
    result = DataFrameSource(df, subject_id_col="pid").load()
    assert sorted(result.subject_ids) == ["1", "2"]


def test_missing_subject_column_raises():
    with pytest.raises(ConsentMLError, match="nope"):
        DataFrameSource(_df(), subject_id_col="nope").load()


def test_empty_frame_raises():
    empty = pd.DataFrame({"pid": [], "age": []})
    with pytest.raises(ConsentMLError, match="no rows"):
        DataFrameSource(empty, subject_id_col="pid").load()


def test_non_dataframe_raises():
    with pytest.raises(ConsentMLError, match="DataFrame"):
        DataFrameSource([1, 2, 3], subject_id_col="pid").load()
