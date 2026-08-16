"""Snowflake source: ConsentML runs the query, so lineage is not an assertion.

Exception discipline mirrors sources/postgres.py: connector errors are caught
NARROWLY and re-raised as ConsentMLError with the original chained. Unlike the
Postgres source, Snowflake exposes no connection-level read-only flag, so
write-rejection is NOT enforced here -- the caller is responsible for supplying
a role with read-only grants. This limitation is documented on the class.
"""

import hashlib

import pandas as pd

from consentml.errors import ConsentMLError
from consentml.sources.base import SourceResult


def _import_connector():
    try:
        import snowflake.connector as connector
    except ImportError as exc:
        raise ConsentMLError(
            "SnowflakeSource needs snowflake-connector-python. Install it "
            "with: pip install 'consentml[snowflake]'"
        ) from exc
    return connector


def _connect(connection: dict):
    """The single connection seam. Tests monkeypatch this module attribute to
    return a FakeSnowflakeConnection; production calls the real connector."""
    connector = _import_connector()
    return connector.connect(**connection)


_SAFE_KEYS = ("account", "database", "schema", "warehouse")


def _safe_conninfo(connection: dict) -> dict:
    """Account/database/schema/warehouse only -- never user, password, key.

    Built by allow-list, not deny-list: an unknown future auth field cannot
    leak because only the four safe keys are ever copied out. Keys are matched
    case-insensitively because the connector accepts either case.
    """
    lower = {k.lower(): v for k, v in connection.items()}
    return {k: lower.get(k) for k in _SAFE_KEYS}


class SnowflakeSource:
    def __init__(self, *, connection, query, subject_id_col):
        _import_connector()  # fail fast with a clear message if the extra is missing
        self._connection = dict(connection)
        self._query = query
        self._subject_id_col = subject_id_col
        self._conninfo = _safe_conninfo(self._connection)
