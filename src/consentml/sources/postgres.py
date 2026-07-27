"""Postgres source: ConsentML runs the query, so lineage is not an assertion.

Exception discipline in this module: psycopg errors are caught NARROWLY and
re-raised as ConsentMLError with the original chained. The contract here is
*fail clearly*, not *never raise* -- a broad `except Exception` would swallow
genuine bugs, which is exactly how the exit-2 path was lost twice during
weeks 7-8.
"""

import hashlib

import pandas as pd

from consentml.errors import ConsentMLError
from consentml.sources.base import SourceResult


def _import_psycopg():
    try:
        import psycopg
    except ImportError as exc:
        raise ConsentMLError(
            "PostgresSource needs psycopg. Install it with: "
            "pip install 'consentml[postgres]'"
        ) from exc
    return psycopg


def _safe_conninfo(psycopg, dsn) -> dict:
    """Host, port and database only -- never user, never password.

    Parsed before any connection is opened, so a connection failure cannot
    put a password into a traceback that then lands in a log.
    """
    try:
        parsed = psycopg.conninfo.conninfo_to_dict(dsn)
    except psycopg.ProgrammingError as exc:
        raise ConsentMLError(f"could not parse the Postgres DSN: {exc}") from exc
    port = parsed.get("port")
    return {
        "host": parsed.get("host"),
        "port": int(port) if port is not None else None,
        "database": parsed.get("dbname"),
    }


class _ExplainUnavailable(Exception):
    """EXPLAIN could not be run or parsed. Never reaches the caller."""


def _explain_failed():
    return _ExplainUnavailable()


def _relations(node, found):
    """Collect schema-qualified relation names from an EXPLAIN plan node.

    Postgres reports the relations itself, so ConsentML never parses SQL.
    The result is advisory: a table the planner optimizes away never appears
    in the plan and so never appears here.
    """
    if isinstance(node, dict):
        name = node.get("Relation Name")
        if name:
            schema = node.get("Schema", "public")
            found.add(f"{schema}.{name}")
        for value in node.values():
            _relations(value, found)
    elif isinstance(node, list):
        for item in node:
            _relations(item, found)
    return found


def _run_explain(cur, query):
    """Return the raw EXPLAIN plan JSON, or raise _ExplainUnavailable.

    VERBOSE is required, not cosmetic: without it Postgres omits the
    "Schema" key from plan nodes entirely (confirmed against 14 locally),
    so a table outside the search_path's default schema would silently
    fall back to the "public" default in _relations and be misreported.
    """
    cur.execute("EXPLAIN (FORMAT JSON, VERBOSE) " + query)
    row = cur.fetchone()
    if not row or not row[0]:
        raise _ExplainUnavailable()
    return row[0]


class PostgresSource:
    """Track a training set read from Postgres with arbitrary SELECT SQL."""

    def __init__(self, *, dsn, query, subject_id_col):
        self._psycopg = _import_psycopg()
        self._dsn = dsn
        self._query = query
        self._subject_id_col = subject_id_col
        self._conninfo = _safe_conninfo(self._psycopg, dsn)

    def load(self) -> SourceResult:
        rows, columns, tables, mechanism = self._fetch()
        df = pd.DataFrame(rows, columns=columns)
        if self._subject_id_col not in df.columns:
            raise ConsentMLError(
                f"Subject ID column '{self._subject_id_col}' not found in "
                f"the query result (columns: {list(df.columns)})."
            )
        if len(df) == 0:
            raise ConsentMLError(
                "Query returned no rows; refusing to record a training run "
                "over zero subjects."
            )
        # See SourceResult.subject_ids in sources/base.py for the full
        # contract (distinct, non-null, stringified) and why a null here
        # matters -- this is one of two call sites (sources/dataframe.py is
        # the other) that enforce it. Same hazard as DataFrameSource, just
        # arriving here as a SQL NULL instead of a missing value already in
        # memory.
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
                "kind": "postgres",
                **self._conninfo,
                "query": self._query,
                "query_sha256": hashlib.sha256(
                    self._query.encode("utf-8")
                ).hexdigest(),
                "referenced_tables": tables,
                "referenced_tables_source": mechanism,
                "n_rows": int(len(df)),
            },
        )

    def _referenced_tables(self, cur):
        """(sorted table list, mechanism) -- never raises.

        A failed EXPLAIN must not fail the training run: this list is
        advisory, and advisory data can never break the primary path. It
        also aborts the surrounding transaction in Postgres, so the
        rollback below is required for the real query to run afterwards.
        """
        psycopg = self._psycopg
        try:
            plan = _run_explain(cur, self._query)
        except (_ExplainUnavailable, psycopg.Error):
            cur.connection.rollback()
            return None, "unavailable"
        return sorted(_relations(plan, set())), "explain"

    def _fetch(self):
        psycopg = self._psycopg
        try:
            conn = psycopg.connect(self._dsn)
        except psycopg.OperationalError as exc:
            raise ConsentMLError(
                f"could not connect to Postgres at "
                f"{self._conninfo['host']}:{self._conninfo['port']}: {exc}"
            ) from exc
        try:
            # Set before any statement runs: psycopg only accepts this while
            # no transaction is open. ConsentML reads training data; it must
            # never be able to write to the system it is reading from.
            conn.read_only = True
            with conn.cursor() as cur:
                tables, mechanism = self._referenced_tables(cur)
                try:
                    cur.execute(self._query)
                    rows = cur.fetchall()
                    columns = [d.name for d in cur.description]
                except psycopg.Error as exc:
                    raise ConsentMLError(
                        f"the training query failed: {exc}"
                    ) from exc
            return rows, columns, tables, mechanism
        finally:
            conn.close()
