import re
import sqlite3

_IDENTITY_RE = re.compile(r"\bNUMBER\s+IDENTITY\s+PRIMARY\s+KEY\b", re.IGNORECASE)


def _to_sqlite_ddl(sql: str) -> str:
    """Rewrite the one Snowflake-ism the store's DDL uses.

    The store writes its IDENTITY primary key as exactly `NUMBER IDENTITY
    PRIMARY KEY`; SQLite spells the same intent `INTEGER PRIMARY KEY
    AUTOINCREMENT`. VARCHAR and NUMBER are accepted by SQLite as-is (dynamic
    typing), so nothing else needs translating."""
    return _IDENTITY_RE.sub("INTEGER PRIMARY KEY AUTOINCREMENT", sql)


class ShimCursor:
    def __init__(self, sqlite_cursor):
        self._cur = sqlite_cursor

    def execute(self, sql, params=()):
        self._cur.execute(_to_sqlite_ddl(sql), params)
        return self

    def executemany(self, sql, seq):
        self._cur.executemany(_to_sqlite_ddl(sql), seq)
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self._cur.close()
        return False


class ShimConnection:
    def __init__(self):
        self._conn = sqlite3.connect(":memory:")

    def cursor(self):
        return ShimCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


def shim_connect(connection: dict) -> ShimConnection:
    return ShimConnection()


# --- Scripted double for SnowflakeSource -----------------------------------
#
# Deterministic and account-free: unit tests match issued SQL against a
# script of canned responses. This exercises SnowflakeSource's own logic
# (dataframe build, subject-id contract, provenance) without a network or
# credentials; real SQL fidelity is the job of the gated live tests. This is
# a different class from ShimConnection above -- ShimConnection backs the
# store's richer in-memory DDL/DML shim; FakeSnowflakeConnection only ever
# needs to answer an EXPLAIN and one SELECT.


class _Col:
    def __init__(self, name):
        self.name = name


class _FakeCursor:
    def __init__(self, script):
        self._script = script
        self._rows = []
        self.description = None
        self.connection = None

    def execute(self, sql):
        for substr, rows, names in self._script:
            if substr in sql:
                self._rows = rows
                self.description = [_Col(n) for n in names] if names else None
                return self
        raise AssertionError(f"unscripted SQL: {sql!r}")

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeSnowflakeConnection:
    def __init__(self, script):
        self._script = script
        self.closed = False

    def cursor(self):
        cur = _FakeCursor(self._script)
        cur.connection = self
        return cur

    def close(self):
        self.closed = True
