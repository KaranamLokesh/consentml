from consentml.sources import Source, SourceResult


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
