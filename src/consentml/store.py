"""SQLite-backed lineage store.

Three tables:
- training_runs: one row per decorated training execution.
- subject_index: one row per (run, subject) pair; indexed for revocation lookups.
- audit_log: append-only, hash-chained event log.
"""

import os
import sqlite3
from pathlib import Path

GENESIS_HASH = "0" * 64

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
