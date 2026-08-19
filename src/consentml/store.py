"""SQLite-backed lineage store.

Four tables:
- training_runs: one row per decorated training execution. Provenance is a
  JSON document whose SHA-256 is recorded in the audit log, so edits to it
  are detectable.
- subjects: each distinct subject key, stored once.
- subject_index: one row per (run, subject) pair, by integer foreign key.
- audit_log: append-only, hash-chained event log.

Schema version lives in PRAGMA user_version. Versions 0 and 1 predate the
provenance column; they can be read but not written -- see consentml.migrate.
"""

import abc
import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from consentml.errors import ConsentMLError

GENESIS_HASH = "0" * 64
SCHEMA_VERSION = 2

_RUN_COLS = [
    "run_id", "model_name", "model_hash", "provenance",
    "subject_ids_hashed", "n_subjects", "started_at", "finished_at",
]

# Schema versions before 2 (both v0 and v1) predate the provenance column --
# their training_runs table still has data_source and subject_id_col, not
# provenance. Selecting data_source AS provenance gives the query the same
# column count and order as _RUN_COLS; the "provenance" key itself comes
# from dict(zip(_RUN_COLS, row)) below matching row values positionally --
# the SQL alias is purely for readability and plays no part in that.
#
# The value that lands under "provenance" for a legacy row is therefore old
# free text (e.g. "postgres://prod/customers"), not JSON. Anything that
# parses provenance as JSON must tolerate a bare string here until a
# migration backfills these rows into the structured form.
#
# Derived from _RUN_COLS rather than hand-repeated: a column added to one
# list and not the other would otherwise make dict(zip(...)) below truncate
# silently instead of raising, on the first divergence in list length.
_RUN_COLS_LEGACY = [
    "data_source AS provenance" if c == "provenance" else c for c in _RUN_COLS
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS training_runs (
    run_pk INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    model_name TEXT NOT NULL,
    model_hash TEXT NOT NULL,
    provenance TEXT NOT NULL,
    subject_ids_hashed INTEGER NOT NULL,
    n_subjects INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subjects (
    subject_pk INTEGER PRIMARY KEY,
    subject_key TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS subject_index (
    run_pk INTEGER NOT NULL REFERENCES training_runs(run_pk),
    subject_pk INTEGER NOT NULL REFERENCES subjects(subject_pk)
);

-- Two indexes, not one: idx_si_subject serves revocation lookups
-- (runs_for_subject_value joins subjects -> subject_index), idx_si_run
-- serves subject_count_for_run, which verify_audit_log() calls once per
-- training run. Dropping either turns its query into a full scan of
-- subject_index -- fine at test scale, catastrophic on the
-- many-runs/many-subjects databases this schema exists for. The extra
-- index does eat into the storage savings from interning; that's a
-- deliberate trade of some dedup win for verification staying fast at
-- scale, not an oversight.
CREATE INDEX IF NOT EXISTS idx_si_subject ON subject_index(subject_pk);
CREATE INDEX IF NOT EXISTS idx_si_run ON subject_index(run_pk);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""


def default_db_path() -> Path:
    """DB path: $CONSENTML_DB if set, else ~/.consentml/lineage.db."""
    env = os.environ.get("CONSENTML_DB")
    if env:
        return Path(env)
    return Path.home() / ".consentml" / "lineage.db"


def provenance_text(provenance: dict) -> str:
    """Canonical serialization of a provenance record.

    sort_keys is what makes the hash stable: two dicts with the same content
    must produce the same text, or verification would report a false
    provenance_modified on every run.
    """
    return json.dumps(provenance, sort_keys=True)


def provenance_hash(text) -> str | None:
    """SHA-256 of stored provenance text, or None if it isn't text.

    Returns None rather than raising for non-str input: the value comes
    straight out of a database column an attacker may have replaced with a
    BLOB or an integer, and verify_audit_log() must never raise on hostile
    database contents. verify_audit_log() treats a None here as a sentinel
    that can never match a recorded hash -- including a payload whose
    provenance_sha256 was itself forged to JSON null -- and reports it as a
    provenance_modified finding.
    """
    if not isinstance(text, str):
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _lenient_text(raw):
    """Undecodable TEXT comes back as bytes instead of raising.

    sqlite3 decodes TEXT strictly, so a column holding invalid UTF-8 raises
    at fetch time -- before any verification logic can look at it. That
    turned a table-only tamper into an unreadable-database error and sent
    the CLI down the exit-2 path, reporting hostile *contents* through the
    I/O channel. Returning raw bytes instead lets the value reach the code
    that knows what to do with it: provenance_hash() returns None for
    non-str input, which reports as provenance_modified.

    Well-formed TEXT is unaffected -- it still decodes to str, so no other
    column's behavior changes.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw


def compute_entry_hash(prev_hash, timestamp, event_type, payload) -> str:
    """The audit-chain link formula, in one place so every backend hashes
    identically. Changing this reshapes every chain -- do not touch without a
    schema/version story."""
    return hashlib.sha256(
        (prev_hash + timestamp + event_type + payload).encode("utf-8")
    ).hexdigest()


class LineageStore(abc.ABC):
    """The backend-independent lineage store contract. Callers (track, verify,
    revoke, export) depend only on these methods; concrete backends
    (SQLiteLineageStore, SnowflakeLineageStore) implement them."""

    @abc.abstractmethod
    def record_training_run(self, *, model_name, model_hash, provenance,
                            subject_ids_hashed, subject_id_values,
                            started_at, finished_at) -> str: ...

    @abc.abstractmethod
    def runs_for_subject_value(self, subject_id_value) -> list[dict]: ...

    @abc.abstractmethod
    def latest_run_for_model(self, model_name) -> dict | None: ...

    @abc.abstractmethod
    def run_by_id(self, run_id) -> dict | None: ...

    @abc.abstractmethod
    def subject_count_for_run(self, run_id) -> int: ...

    @abc.abstractmethod
    def all_run_ids(self) -> set: ...

    @abc.abstractmethod
    def record_revocation(self, *, subject_key, n_affected_runs,
                          recommended_actions) -> int: ...

    @abc.abstractmethod
    def audit_entries(self) -> list[dict]: ...

    @abc.abstractmethod
    def close(self): ...


class SQLiteLineageStore(LineageStore):
    """The default, file-backed LineageStore, persisting lineage in SQLite."""

    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.text_factory = _lenient_text
        self.schema_version = self._detect_schema()

    def _detect_schema(self) -> int:
        """Return the schema version, creating a fresh v2 database if needed.

        A legacy database and an empty file both report user_version 0 -- the
        old code never set it -- so the presence of training_runs is what tells
        them apart. The schema script must never run against a legacy database.
        """
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version:
            return version
        existing = self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='training_runs'"
        ).fetchone()
        if existing:
            return 0
        self._conn.executescript(_SCHEMA)
        self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._conn.commit()
        return SCHEMA_VERSION

    def _require_writable(self):
        if self.schema_version < SCHEMA_VERSION:
            raise ConsentMLError(
                f"{self.db_path} uses schema v{self.schema_version}; run "
                "'consentml migrate' to upgrade it before recording new events."
            )

    def close(self):
        self._conn.close()

    def record_training_run(
        self,
        *,
        model_name,
        model_hash,
        provenance,
        subject_ids_hashed,
        subject_id_values,
        started_at,
        finished_at,
    ) -> str:
        """Record one training run, its subject index rows, and an audit
        entry, in a single transaction. Returns the new run_id."""
        self._require_writable()
        run_id = str(uuid.uuid4())
        text = provenance_text(provenance)
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO training_runs (run_id, model_name, model_hash, "
                "provenance, subject_ids_hashed, n_subjects, "
                "started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    model_name,
                    model_hash,
                    text,
                    int(subject_ids_hashed),
                    len(subject_id_values),
                    started_at,
                    finished_at,
                ),
            )
            run_pk = cursor.lastrowid
            self._conn.executemany(
                "INSERT OR IGNORE INTO subjects (subject_key) VALUES (?)",
                [(v,) for v in subject_id_values],
            )
            self._conn.executemany(
                "INSERT INTO subject_index (run_pk, subject_pk) "
                "SELECT ?, subject_pk FROM subjects WHERE subject_key = ?",
                [(run_pk, v) for v in subject_id_values],
            )
            self._append_audit_entry(
                event_type="training_run",
                payload=json.dumps(
                    {
                        "run_id": run_id,
                        "model_name": model_name,
                        "model_hash": model_hash,
                        "provenance_sha256": provenance_hash(text),
                        "n_subjects": len(subject_id_values),
                    },
                    sort_keys=True,
                ),
            )
        return run_id

    def _run_cols(self) -> list:
        """Column list for reading training_runs.

        Legacy names (_RUN_COLS_LEGACY) below SCHEMA_VERSION -- i.e. for
        both v0 and v1 -- else the current _RUN_COLS. This is purely a
        column-*name* concern, distinct from subject_index's join shape:
        v1's subject_index is already the interned run_pk/subject_pk layout
        v2 uses, so callers must keep gating the join shape on
        schema_version == 0 specifically, never on this same condition --
        that conflation is exactly how v1 databases ended up raising
        OperationalError on every read the first time this was written.
        """
        return _RUN_COLS_LEGACY if self.schema_version < SCHEMA_VERSION else _RUN_COLS

    def runs_for_subject_value(self, subject_id_value) -> list[dict]:
        """Training runs whose subject index contains the given stored value
        (a hash when subject_ids_hashed, else the raw ID)."""
        cols = ", ".join(f"r.{c}" for c in self._run_cols())
        if self.schema_version == 0:
            sql = (
                f"SELECT {cols} FROM training_runs r "
                "JOIN subject_index s ON s.run_id = r.run_id "
                "WHERE s.subject_id_hash = ? ORDER BY r.started_at"
            )
        else:
            sql = (
                f"SELECT {cols} FROM training_runs r "
                "JOIN subject_index s ON s.run_pk = r.run_pk "
                "JOIN subjects sub ON sub.subject_pk = s.subject_pk "
                "WHERE sub.subject_key = ? ORDER BY r.started_at"
            )
        rows = self._conn.execute(sql, (subject_id_value,)).fetchall()
        return [dict(zip(_RUN_COLS, row)) for row in rows]

    def latest_run_for_model(self, model_name) -> dict | None:
        """The most recent training run (by started_at) for a model name."""
        cols = ", ".join(self._run_cols())
        row = self._conn.execute(
            f"SELECT {cols} FROM training_runs "
            "WHERE model_name = ? ORDER BY started_at DESC LIMIT 1",
            (model_name,),
        ).fetchone()
        return dict(zip(_RUN_COLS, row)) if row else None

    def run_by_id(self, run_id) -> dict | None:
        """The training run with this id, or None if it is absent."""
        cols = ", ".join(self._run_cols())
        row = self._conn.execute(
            f"SELECT {cols} FROM training_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return dict(zip(_RUN_COLS, row)) if row else None

    def subject_count_for_run(self, run_id) -> int:
        """How many subject_index rows currently exist for this run."""
        if self.schema_version == 0:
            sql = "SELECT COUNT(*) FROM subject_index WHERE run_id = ?"
        else:
            sql = (
                "SELECT COUNT(*) FROM subject_index s "
                "JOIN training_runs r ON r.run_pk = s.run_pk "
                "WHERE r.run_id = ?"
            )
        return self._conn.execute(sql, (run_id,)).fetchone()[0]

    def all_run_ids(self) -> set:
        """Every run id present in training_runs."""
        rows = self._conn.execute("SELECT run_id FROM training_runs").fetchall()
        return {row[0] for row in rows}

    def record_revocation(self, *, subject_key, n_affected_runs, recommended_actions) -> int:
        """Append a revocation event to the audit log. Returns the entry id.

        The payload carries only the hashed subject key, never a raw ID."""
        self._require_writable()
        with self._conn:
            return self._append_audit_entry(
                event_type="revocation",
                payload=json.dumps(
                    {
                        "subject_key": subject_key,
                        "n_affected_runs": n_affected_runs,
                        "recommended_actions": recommended_actions,
                    },
                    sort_keys=True,
                ),
            )

    def audit_entries(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, timestamp, event_type, payload, prev_hash, entry_hash "
            "FROM audit_log ORDER BY id"
        ).fetchall()
        cols = ["id", "timestamp", "event_type", "payload", "prev_hash", "entry_hash"]
        return [dict(zip(cols, row)) for row in rows]

    def _append_audit_entry(self, *, event_type, payload):
        row = self._conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row[0] if row else GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()
        entry_hash = compute_entry_hash(prev_hash, timestamp, event_type, payload)
        cursor = self._conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, payload, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp, event_type, payload, prev_hash, entry_hash),
        )
        return cursor.lastrowid


def open_store(target=None, *, db_path=None, **kwargs) -> "LineageStore":
    """Return a LineageStore for `target`.

    SQLite is the default backend: a None/omitted target, or an explicit
    db_path, yields SQLiteLineageStore. A dict target, or a string starting
    'snowflake://', routes to SnowflakeLineageStore instead -- the connector
    import happens lazily inside this branch so consentml.store stays
    connector-free at import time. This factory is Python-API only; the CLI
    stays SQLite-only.
    """
    if isinstance(target, dict) or (isinstance(target, str) and target.startswith("snowflake://")):
        from consentml.snowflake_store import SnowflakeLineageStore, parse_snowflake_uri
        connection = target if isinstance(target, dict) else parse_snowflake_uri(target)
        return SnowflakeLineageStore(connection=connection)
    if db_path is not None and target is None:
        return SQLiteLineageStore(db_path=db_path)
    if target is None or isinstance(target, (str, __import__("pathlib").Path)):
        return SQLiteLineageStore(db_path=target if target is not None else db_path)
    raise ConsentMLError(f"unrecognized store target: {target!r}")
