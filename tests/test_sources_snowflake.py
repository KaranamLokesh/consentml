import builtins

import pytest

from consentml import ConsentMLError

MINIMAL_CONN = {
    "account": "acct",
    "user": "u",
    "password": "p",
    "database": "DB",
    "schema": "PUBLIC",
    "warehouse": "WH",
}


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
