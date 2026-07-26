"""SQLite-backed lineage store.

Four tables:
- training_runs: one row per decorated training execution.
- subjects: each distinct subject key, stored once.
- subject_index: one row per (run, subject) pair, by integer foreign key.
- audit_log: append-only, hash-chained event log.

Schema version lives in PRAGMA user_version. Version 0 databases predate
versioning; they can be read but not written -- see consentml.migrate.
"""

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from consentml.errors import ConsentMLError

GENESIS_HASH = "0" * 64
SCHEMA_VERSION = 1

_RUN_COLS = [
    "run_id", "model_name", "model_hash", "data_source",
    "subject_id_col", "subject_ids_hashed", "n_subjects",
    "started_at", "finished_at",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS training_runs (
    run_pk INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    model_name TEXT NOT NULL,
    model_hash TEXT NOT NULL,
    data_source TEXT NOT NULL,
    subject_id_col TEXT NOT NULL,
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


class LineageStore:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self.schema_version = self._detect_schema()

    def _detect_schema(self) -> int:
        """Return the schema version, creating a fresh v1 database if needed.

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
        data_source,
        subject_id_col,
        subject_ids_hashed,
        subject_id_values,
        started_at,
        finished_at,
    ) -> str:
        """Record one training run, its subject index rows, and an audit
        entry, in a single transaction. Returns the new run_id."""
        self._require_writable()
        run_id = str(uuid.uuid4())
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO training_runs (run_id, model_name, model_hash, "
                "data_source, subject_id_col, subject_ids_hashed, n_subjects, "
                "started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    model_name,
                    model_hash,
                    data_source,
                    subject_id_col,
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
                        "data_source": data_source,
                        "n_subjects": len(subject_id_values),
                    },
                    sort_keys=True,
                ),
            )
        return run_id

    def runs_for_subject_value(self, subject_id_value) -> list[dict]:
        """Training runs whose subject index contains the given stored value
        (a hash when subject_ids_hashed, else the raw ID)."""
        cols = ", ".join(f"r.{c}" for c in _RUN_COLS)
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
        row = self._conn.execute(
            f"SELECT {', '.join(_RUN_COLS)} FROM training_runs "
            "WHERE model_name = ? ORDER BY started_at DESC LIMIT 1",
            (model_name,),
        ).fetchone()
        return dict(zip(_RUN_COLS, row)) if row else None

    def run_by_id(self, run_id) -> dict | None:
        """The training run with this id, or None if it is absent."""
        row = self._conn.execute(
            f"SELECT {', '.join(_RUN_COLS)} FROM training_runs WHERE run_id = ?",
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
        entry_hash = hashlib.sha256(
            (prev_hash + timestamp + event_type + payload).encode("utf-8")
        ).hexdigest()
        cursor = self._conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, payload, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp, event_type, payload, prev_hash, entry_hash),
        )
        return cursor.lastrowid
