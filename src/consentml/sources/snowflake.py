"""Snowflake source: ConsentML runs the query, so lineage is not an assertion.

Exception discipline mirrors sources/postgres.py: connector errors are caught
NARROWLY and re-raised as ConsentMLError with the original chained. Unlike the
Postgres source, Snowflake exposes no connection-level read-only flag, so
write-rejection is NOT enforced here -- the caller is responsible for supplying
a role with read-only grants. This limitation is documented on the class.
"""

import hashlib
import json

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


class _ExplainUnavailable(Exception):
    """EXPLAIN could not be run or parsed. Never reaches the caller."""


_TABLE_KEYS = ("objects", "table", "Relation Name")


def _relations(node, found):
    """Collect table-like names from a Snowflake EXPLAIN JSON node.

    Best-effort and tolerant: the JSON shape is not a stable contract, so this
    walks the whole document and harvests string values found under any key in
    _TABLE_KEYS, whether the value is a bare string or a list of strings.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _TABLE_KEYS:
                if isinstance(value, str):
                    found.add(value)
                elif isinstance(value, list):
                    found.update(v for v in value if isinstance(v, str))
            _relations(value, found)
    elif isinstance(node, list):
        for item in node:
            _relations(item, found)
    return found


def _run_explain(cur, query):
    cur.execute("EXPLAIN USING JSON " + query)
    row = cur.fetchone()
    if not row or not row[0]:
        raise _ExplainUnavailable()
    try:
        return json.loads(row[0])
    except (TypeError, ValueError) as exc:
        raise _ExplainUnavailable() from exc


class SnowflakeSource:
    """Track a training set read from Snowflake with arbitrary SELECT SQL."""

    def __init__(self, *, connection, query, subject_id_col):
        _import_connector()  # fail fast with a clear message if the extra is missing
        self._connection = dict(connection)
        self._query = query
        self._subject_id_col = subject_id_col
        self._conninfo = _safe_conninfo(self._connection)

    def load(self) -> SourceResult:
        rows, columns, tables, mechanism = self._fetch()
        df = pd.DataFrame(rows, columns=columns)
        if self._subject_id_col not in df.columns:
            raise ConsentMLError(
                f"Subject ID column '{self._subject_id_col}' not found in the "
                f"query result (columns: {list(df.columns)})."
            )
        if len(df) == 0:
            raise ConsentMLError(
                "Query returned no rows; refusing to record a training run "
                "over zero subjects."
            )
        n_null = int(df[self._subject_id_col].isna().sum())
        if n_null:
            raise ConsentMLError(
                f"Subject ID column '{self._subject_id_col}' has {n_null} null "
                f"value(s); a null subject ID cannot be revoked, so refusing to "
                f"record it as training coverage."
            )
        subject_ids = df[self._subject_id_col].astype(str).unique().tolist()
        return SourceResult(
            payload=df,
            subject_ids=subject_ids,
            provenance={
                "kind": "snowflake",
                **self._conninfo,
                "query": self._query,
                "query_sha256": hashlib.sha256(self._query.encode("utf-8")).hexdigest(),
                "referenced_tables": tables,
                "referenced_tables_source": mechanism,
                "n_rows": int(len(df)),
            },
        )

    def _referenced_tables(self, cur):
        """(sorted table list, mechanism) -- never raises.

        Advisory: a failed EXPLAIN must not fail the training run.
        """
        connector = _import_connector()
        try:
            plan = _run_explain(cur, self._query)
        except (_ExplainUnavailable, connector.errors.Error):
            return None, "unavailable"
        return sorted(_relations(plan, set())), "explain"

    def _fetch(self):
        connector = _import_connector()
        try:
            conn = _connect(self._connection)
        except connector.errors.Error as exc:
            raise ConsentMLError(
                f"could not connect to Snowflake at account "
                f"{self._conninfo['account']}: {exc}"
            ) from exc
        try:
            with conn.cursor() as cur:
                tables, mechanism = self._referenced_tables(cur)
                try:
                    cur.execute(self._query)
                    rows = cur.fetchall()
                    columns = [d.name for d in cur.description]
                except connector.errors.Error as exc:
                    raise ConsentMLError(f"the training query failed: {exc}") from exc
            return rows, columns, tables, mechanism
        finally:
            conn.close()
