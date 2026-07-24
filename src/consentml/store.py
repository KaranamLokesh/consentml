"""SQLite-backed lineage store.

Three tables:
- training_runs: one row per decorated training execution.
- subject_index: one row per (run, subject) pair; indexed for revocation lookups.
- audit_log: append-only, hash-chained event log.
"""

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64

_RUN_COLS = [
    "run_id", "model_name", "model_hash", "data_source",
    "subject_id_col", "subject_ids_hashed", "n_subjects",
    "started_at", "finished_at",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS training_runs (
    run_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    model_hash TEXT NOT NULL,
    data_source TEXT NOT NULL,
    subject_id_col TEXT NOT NULL,
    subject_ids_hashed INTEGER NOT NULL,
    n_subjects INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subject_index (
    run_id TEXT NOT NULL REFERENCES training_runs(run_id),
    subject_id_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_subject_id_hash
    ON subject_index(subject_id_hash);

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
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

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
        run_id = str(uuid.uuid4())
        with self._conn:
            self._conn.execute(
                "INSERT INTO training_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            self._conn.executemany(
                "INSERT INTO subject_index VALUES (?, ?)",
                [(run_id, v) for v in subject_id_values],
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
        rows = self._conn.execute(
            """
            SELECT r.run_id, r.model_name, r.model_hash, r.data_source,
                   r.subject_id_col, r.subject_ids_hashed, r.n_subjects,
                   r.started_at, r.finished_at
            FROM training_runs r
            JOIN subject_index s ON s.run_id = r.run_id
            WHERE s.subject_id_hash = ?
            ORDER BY r.started_at
            """,
            (subject_id_value,),
        ).fetchall()
        return [dict(zip(_RUN_COLS, row)) for row in rows]

    def latest_run_for_model(self, model_name) -> dict | None:
        """The most recent training run (by started_at) for a model name."""
        row = self._conn.execute(
            f"SELECT {', '.join(_RUN_COLS)} FROM training_runs "
            "WHERE model_name = ? ORDER BY started_at DESC LIMIT 1",
            (model_name,),
        ).fetchone()
        return dict(zip(_RUN_COLS, row)) if row else None

    def record_revocation(self, *, subject_key, n_affected_runs, recommended_actions) -> int:
        """Append a revocation event to the audit log. Returns the entry id.

        The payload carries only the hashed subject key, never a raw ID."""
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
