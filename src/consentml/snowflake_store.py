"""Snowflake-backed lineage store.

A pluggable backend behind consentml.store.open_store; SQLite stays the
default. The schema is DENORMALIZED relative to SQLite -- subject_index holds
(run_id, subject_key) directly, with no integer interning and no subjects
table. run_id is a client-generated UUID, so no lastrowid is ever needed.

The audit chain is byte-for-byte identical to SQLite's: same
compute_entry_hash formula, same GENESIS_HASH, same row shape. An audit log
written here verifies under the same consentml.verify code as a SQLite one.

CONCURRENCY: single logical writer per lineage table. The audit append is a
read-modify-write (read last entry_hash, insert) with no cross-writer locking;
two concurrent writers could fork the chain. Coordinating multiple writers is
an explicit non-goal.
"""

import json
import uuid
from datetime import datetime, timezone

from consentml.errors import ConsentMLError
from consentml.store import (
    GENESIS_HASH,
    LineageStore,
    compute_entry_hash,
    provenance_hash,
    provenance_text,
)

_RUN_COLS = [
    "run_id", "model_name", "model_hash", "provenance",
    "subject_ids_hashed", "n_subjects", "started_at", "finished_at",
]

_DDL = [
    """CREATE TABLE IF NOT EXISTS training_runs (
        run_id VARCHAR PRIMARY KEY,
        model_name VARCHAR NOT NULL,
        model_hash VARCHAR NOT NULL,
        provenance VARCHAR NOT NULL,
        subject_ids_hashed NUMBER NOT NULL,
        n_subjects NUMBER NOT NULL,
        started_at VARCHAR NOT NULL,
        finished_at VARCHAR NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS subject_index (
        run_id VARCHAR NOT NULL,
        subject_key VARCHAR NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        id NUMBER IDENTITY PRIMARY KEY,
        timestamp VARCHAR NOT NULL,
        event_type VARCHAR NOT NULL,
        payload VARCHAR NOT NULL,
        prev_hash VARCHAR NOT NULL,
        entry_hash VARCHAR NOT NULL
    )""",
    "CREATE TABLE IF NOT EXISTS schema_meta (version NUMBER NOT NULL)",
]


def _import_connector():
    try:
        import snowflake.connector as connector
    except ImportError as exc:
        raise ConsentMLError(
            "SnowflakeLineageStore needs snowflake-connector-python. Install "
            "it with: pip install 'consentml[snowflake]'"
        ) from exc
    return connector


def _connect(connection: dict):
    """Connection seam. Tests monkeypatch this to return the SQLite shim.

    qmark paramstyle makes the store's SQL identical to what the shim runs on
    SQLite; autocommit off lets record_training_run be one transaction."""
    connector = _import_connector()
    params = dict(connection)
    params.setdefault("paramstyle", "qmark")
    params.setdefault("autocommit", False)
    return connector.connect(**params)


class SnowflakeLineageStore(LineageStore):
    def __init__(self, *, connection):
        self._conn = _connect(connection)
        self._create_schema()

    def _create_schema(self):
        cur = self._conn.cursor()
        with cur:
            for stmt in _DDL:
                cur.execute(stmt)
            cur.execute("SELECT COUNT(*) FROM schema_meta")
            if cur.fetchone()[0] == 0:
                cur.execute("INSERT INTO schema_meta (version) VALUES (?)", (1,))
        self._conn.commit()

    def close(self):
        self._conn.close()

    def record_training_run(self, *, model_name, model_hash, provenance,
                            subject_ids_hashed, subject_id_values,
                            started_at, finished_at) -> str:
        run_id = str(uuid.uuid4())
        text = provenance_text(provenance)
        cur = self._conn.cursor()
        try:
            with cur:
                cur.execute(
                    "INSERT INTO training_runs (run_id, model_name, model_hash, "
                    "provenance, subject_ids_hashed, n_subjects, started_at, "
                    "finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, model_name, model_hash, text,
                     int(subject_ids_hashed), len(subject_id_values),
                     started_at, finished_at),
                )
                cur.executemany(
                    "INSERT INTO subject_index (run_id, subject_key) VALUES (?, ?)",
                    [(run_id, v) for v in subject_id_values],
                )
                self._append_audit_entry(
                    cur,
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
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return run_id

    def _append_audit_entry(self, cur, *, event_type, payload):
        cur.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        prev_hash = row[0] if row else GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()
        entry_hash = compute_entry_hash(prev_hash, timestamp, event_type, payload)
        cur.execute(
            "INSERT INTO audit_log (timestamp, event_type, payload, prev_hash, "
            "entry_hash) VALUES (?, ?, ?, ?, ?)",
            (timestamp, event_type, payload, prev_hash, entry_hash),
        )

    def _run_row_to_dict(self, row):
        return dict(zip(_RUN_COLS, row))

    def runs_for_subject_value(self, subject_id_value) -> list[dict]:
        cols = ", ".join(f"r.{c}" for c in _RUN_COLS)
        cur = self._conn.cursor()
        with cur:
            cur.execute(
                f"SELECT {cols} FROM training_runs r "
                "JOIN subject_index s ON s.run_id = r.run_id "
                "WHERE s.subject_key = ? ORDER BY r.started_at",
                (subject_id_value,),
            )
            return [self._run_row_to_dict(row) for row in cur.fetchall()]

    def latest_run_for_model(self, model_name) -> dict | None:
        cols = ", ".join(_RUN_COLS)
        cur = self._conn.cursor()
        with cur:
            cur.execute(
                f"SELECT {cols} FROM training_runs WHERE model_name = ? "
                "ORDER BY started_at DESC LIMIT 1", (model_name,))
            row = cur.fetchone()
        return self._run_row_to_dict(row) if row else None

    def run_by_id(self, run_id) -> dict | None:
        cols = ", ".join(_RUN_COLS)
        cur = self._conn.cursor()
        with cur:
            cur.execute(f"SELECT {cols} FROM training_runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
        return self._run_row_to_dict(row) if row else None

    def subject_count_for_run(self, run_id) -> int:
        cur = self._conn.cursor()
        with cur:
            cur.execute("SELECT COUNT(*) FROM subject_index WHERE run_id = ?", (run_id,))
            return cur.fetchone()[0]

    def all_run_ids(self) -> set:
        cur = self._conn.cursor()
        with cur:
            cur.execute("SELECT run_id FROM training_runs")
            return {row[0] for row in cur.fetchall()}

    def record_revocation(self, *, subject_key, n_affected_runs,
                          recommended_actions) -> int:
        raise NotImplementedError

    def audit_entries(self) -> list[dict]:
        raise NotImplementedError
