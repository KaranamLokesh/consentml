# tests/test_verify.py
import hashlib
import json
import sqlite3

import pytest

from consentml.store import GENESIS_HASH, LineageStore
from consentml.verify import VerificationReport, verify_audit_log


@pytest.fixture
def db(tmp_path):
    return tmp_path / "lineage.db"


def _seed(db, n_runs=3):
    """Record n_runs training runs, each with two subjects."""
    store = LineageStore(db_path=db)
    try:
        return [
            store.record_training_run(
                model_name=f"model_{i}",
                model_hash=f"hash_{i}",
                data_source="postgres://prod/customers",
                subject_id_col="email",
                subject_ids_hashed=True,
                subject_id_values=[f"s{i}a", f"s{i}b"],
                started_at=f"2026-07-{i + 1:02d}T00:00:00+00:00",
                finished_at=f"2026-07-{i + 1:02d}T00:01:00+00:00",
            )
            for i in range(n_runs)
        ]
    finally:
        store.close()


def _sql(db, statement, params=()):
    """Tamper with the database directly -- this is the threat model."""
    conn = sqlite3.connect(db)
    try:
        with conn:
            conn.execute(statement, params)
    finally:
        conn.close()


def _codes(report):
    return [f.code for f in report.findings]


def test_clean_log_verifies(db):
    _seed(db)
    report = verify_audit_log(db_path=db)
    assert isinstance(report, VerificationReport)
    assert report.ok is True
    assert report.findings == []
    assert report.n_entries == 3


def test_empty_log_verifies(db):
    LineageStore(db_path=db).close()
    report = verify_audit_log(db_path=db)
    assert report.ok is True
    assert report.n_entries == 0


def test_edited_payload_is_detected_without_cascade(db):
    _seed(db, n_runs=5)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 3", ('{"run_id": "x"}',))
    report = verify_audit_log(db_path=db)
    hash_findings = [f for f in report.findings if f.code == "entry_hash_mismatch"]
    assert [f.entry_id for f in hash_findings] == [3]
    assert "broken_link" not in _codes(report)


def test_rehashed_entry_breaks_the_next_link(db):
    _seed(db, n_runs=5)
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT timestamp, event_type, prev_hash FROM audit_log WHERE id = 3"
        ).fetchone()
        timestamp, event_type, prev_hash = row
        payload = '{"forged": true}'
        forged = hashlib.sha256(
            (prev_hash + timestamp + event_type + payload).encode("utf-8")
        ).hexdigest()
        with conn:
            conn.execute(
                "UPDATE audit_log SET payload = ?, entry_hash = ? WHERE id = 3",
                (payload, forged),
            )
    finally:
        conn.close()

    report = verify_audit_log(db_path=db)
    link_findings = [f for f in report.findings if f.code == "broken_link"]
    assert [f.entry_id for f in link_findings] == [4]
    assert "entry_hash_mismatch" not in _codes(report)


def test_bad_genesis_is_detected(db):
    _seed(db, n_runs=2)
    _sql(db, "UPDATE audit_log SET prev_hash = ? WHERE id = 1", ("f" * 64,))
    report = verify_audit_log(db_path=db)
    assert "bad_genesis" in _codes(report)
    assert "broken_link" not in _codes(report)


def test_malformed_payload_does_not_raise(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ("not json{",))
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)
    assert report.ok is False


def test_payload_missing_keys_is_malformed(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ('{"run_id": "x"}',))
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)


def test_report_to_dict_round_trips_through_json(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ("not json{",))
    report = verify_audit_log(db_path=db)
    data = json.loads(json.dumps(report.to_dict()))
    assert data["ok"] is False
    assert data["n_entries"] == 1
    assert any(f["code"] == "malformed_payload" for f in data["findings"])
    assert data["generated_at"] == report.generated_at


def test_non_dict_payload_is_detected_without_raising(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ("42",))
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)


def test_blob_in_hashed_column_is_detected_without_raising(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET timestamp = ? WHERE id = 1", (b"blob",))
    report = verify_audit_log(db_path=db)
    assert "entry_hash_mismatch" in _codes(report)
