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
