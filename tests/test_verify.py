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


def test_blob_payload_is_detected_without_raising(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", (b"\x80\x81\x82",))
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)
    assert report.ok is False


def test_deeply_nested_payload_is_detected_without_raising(db):
    _seed(db, n_runs=1)
    nested = "[" * 10000 + "1" + "]" * 10000
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", (nested,))
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)


def test_oversized_integer_literal_payload_is_detected_without_raising(db):
    """A bare integer literal thousands of digits long: CPython's int/str
    conversion guard (sys.get_int_max_str_digits) makes json.loads raise
    ValueError here for a reason distinct from bad JSON syntax, bad UTF-8,
    or recursion depth -- a fourth failure mode for the same broad except."""
    _seed(db, n_runs=1)
    huge_int = "1" + "0" * 5000
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", (huge_int,))
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)
    assert report.ok is False


def test_deleted_subject_row_is_detected(db):
    run_ids = _seed(db, n_runs=2)
    _sql(db, "DELETE FROM subject_index WHERE run_id = ? AND subject_id_hash = ?",
         (run_ids[0], "s0a"))
    report = verify_audit_log(db_path=db)
    assert report.ok is False
    findings = [f for f in report.findings if f.code == "subject_count_mismatch"]
    assert len(findings) == 1
    assert "2" in findings[0].detail and "1" in findings[0].detail


def test_deleted_subject_with_matching_n_subjects_edit_is_still_detected(db):
    """The full attack story: delete a subject_index row AND edit
    training_runs.n_subjects to match, so the tables look internally
    consistent with each other. Only the hash-chain-protected audit
    payload still disagrees, which is what subject_count_mismatch must
    catch -- it has to compare against the live subject_index COUNT(*),
    never against training_runs.n_subjects, or this attack goes silent."""
    run_ids = _seed(db, n_runs=1)
    _sql(db, "DELETE FROM subject_index WHERE run_id = ? AND subject_id_hash = ?",
         (run_ids[0], "s0a"))
    _sql(db, "UPDATE training_runs SET n_subjects = 1 WHERE run_id = ?", (run_ids[0],))
    report = verify_audit_log(db_path=db)
    assert "subject_count_mismatch" in _codes(report)


def test_added_subject_row_is_detected(db):
    run_ids = _seed(db, n_runs=1)
    _sql(db, "INSERT INTO subject_index VALUES (?, ?)", (run_ids[0], "smuggled"))
    report = verify_audit_log(db_path=db)
    assert "subject_count_mismatch" in _codes(report)


def test_deleted_run_is_detected(db):
    run_ids = _seed(db, n_runs=2)
    _sql(db, "DELETE FROM training_runs WHERE run_id = ?", (run_ids[0],))
    report = verify_audit_log(db_path=db)
    findings = [f for f in report.findings if f.code == "missing_run"]
    assert len(findings) == 1
    assert run_ids[0] in findings[0].detail


def test_modified_model_hash_is_detected(db):
    run_ids = _seed(db, n_runs=1)
    _sql(db, "UPDATE training_runs SET model_hash = ? WHERE run_id = ?",
         ("forged", run_ids[0]))
    report = verify_audit_log(db_path=db)
    assert "run_modified" in _codes(report)


def test_modified_n_subjects_is_detected(db):
    """training_runs.n_subjects is attacker-editable and is surfaced to
    operators via runs_for_subject_value() (which feeds revoke()), so a
    divergence from the logged value must trip run_modified even when
    subject_index itself is untouched."""
    run_ids = _seed(db, n_runs=1)
    _sql(db, "UPDATE training_runs SET n_subjects = ? WHERE run_id = ?",
         (99, run_ids[0]))
    report = verify_audit_log(db_path=db)
    assert "run_modified" in _codes(report)


def test_unlogged_run_is_detected(db):
    _seed(db, n_runs=1)
    _sql(
        db,
        "INSERT INTO training_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("smuggled-run", "shadow", "h", "src", "email", 1, 0,
         "2026-07-20T00:00:00+00:00", "2026-07-20T00:01:00+00:00"),
    )
    report = verify_audit_log(db_path=db)
    findings = [f for f in report.findings if f.code == "unlogged_run"]
    assert len(findings) == 1
    assert findings[0].entry_id is None
    assert "smuggled-run" in findings[0].detail


def test_zero_subject_run_is_not_a_mismatch(db):
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="empty",
            model_hash="h",
            data_source="src",
            subject_id_col="email",
            subject_ids_hashed=True,
            subject_id_values=[],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    report = verify_audit_log(db_path=db)
    assert report.ok is True


def test_revocation_entries_are_not_cross_checked(db):
    _seed(db, n_runs=1)
    store = LineageStore(db_path=db)
    try:
        store.record_revocation(
            subject_key="k", n_affected_runs=99, recommended_actions=[]
        )
    finally:
        store.close()
    report = verify_audit_log(db_path=db)
    assert report.ok is True


def test_malformed_training_payload_skips_cross_check(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ("not json{",))
    report = verify_audit_log(db_path=db)
    codes = _codes(report)
    assert "malformed_payload" in codes
    assert "missing_run" not in codes
    assert "unlogged_run" in codes  # the run is now effectively unlogged


# -- Adversarial: a training_run payload is only guaranteed to be a dict
# with the required keys present (see _parse_payloads); the values
# themselves can be any JSON type. run_id in particular flows into a set
# and into SQLite parameter binding, both of which reject certain types.


def test_list_run_id_in_payload_does_not_raise(db):
    _seed(db, n_runs=1)
    _sql(
        db,
        "UPDATE audit_log SET payload = ? WHERE id = 1",
        (json.dumps({"run_id": [1, 2], "model_name": "m",
                     "model_hash": "h", "n_subjects": 1}),),
    )
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)
    assert report.ok is False


def test_dict_run_id_in_payload_does_not_raise(db):
    _seed(db, n_runs=1)
    _sql(
        db,
        "UPDATE audit_log SET payload = ? WHERE id = 1",
        (json.dumps({"run_id": {"a": 1}, "model_name": "m",
                     "model_hash": "h", "n_subjects": 1}),),
    )
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)
    assert report.ok is False


def test_oversized_integer_run_id_does_not_raise(db):
    """A run_id past SQLite's 64-bit INTEGER range: valid JSON, hashable,
    but sqlite3 raises OverflowError when binding it as a parameter."""
    _seed(db, n_runs=1)
    _sql(
        db,
        "UPDATE audit_log SET payload = ? WHERE id = 1",
        (json.dumps({"run_id": 10**30, "model_name": "m",
                     "model_hash": "h", "n_subjects": 1}),),
    )
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)
    assert report.ok is False


def test_mixed_type_unlogged_run_ids_do_not_raise(db):
    """training_runs.run_id has TEXT affinity but SQLite still allows a
    BLOB to be stored there directly. sorted() on the unlogged-run-id set
    must not crash when it has to compare across types -- which requires
    at least two unlogged run_ids of genuinely different types, or the
    comparison is never actually exercised."""
    LineageStore(db_path=db).close()
    _sql(
        db,
        "INSERT INTO training_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("text-run-id", "shadow-a", "h", "src", "email", 1, 0,
         "2026-07-20T00:00:00+00:00", "2026-07-20T00:01:00+00:00"),
    )
    _sql(
        db,
        "INSERT INTO training_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (b"\x00\x01blob-run-id", "shadow-b", "h", "src", "email", 1, 0,
         "2026-07-20T00:00:00+00:00", "2026-07-20T00:01:00+00:00"),
    )
    report = verify_audit_log(db_path=db)
    findings = [f for f in report.findings if f.code == "unlogged_run"]
    assert len(findings) == 2


def test_head_hash_is_the_last_entry_hash(db):
    _seed(db, n_runs=2)
    store = LineageStore(db_path=db)
    try:
        expected = store.audit_entries()[-1]["entry_hash"]
    finally:
        store.close()
    assert verify_audit_log(db_path=db).head_hash == expected


def test_head_hash_of_empty_log_is_genesis(db):
    LineageStore(db_path=db).close()
    assert verify_audit_log(db_path=db).head_hash == GENESIS_HASH


def test_matching_expected_head_verifies(db):
    _seed(db, n_runs=2)
    head = verify_audit_log(db_path=db).head_hash
    report = verify_audit_log(db_path=db, expected_head=head)
    assert report.ok is True


def test_legitimate_growth_after_anchor_is_not_a_mismatch(db):
    _seed(db, n_runs=1)
    anchored = verify_audit_log(db_path=db).head_hash
    _seed(db, n_runs=1)  # more legitimate activity after the anchor
    report = verify_audit_log(db_path=db, expected_head=anchored)
    assert "head_mismatch" not in _codes(report)


def test_rewrite_before_the_anchor_point_is_still_caught(db):
    """The security argument for membership-checking the anchor: a rewrite
    of an entry *earlier* than the anchor, with the whole chain recomputed
    forward to stay internally consistent (as a real attacker would), must
    still make the anchored hash disappear from the chain -- because that
    hash was computed from the now-changed earlier entry."""
    _seed(db, n_runs=3)
    anchored = verify_audit_log(db_path=db).head_hash

    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT id, timestamp, event_type, payload FROM audit_log ORDER BY id"
        ).fetchall()
        prev = GENESIS_HASH
        for entry_id, timestamp, event_type, payload in rows:
            if entry_id == 1:
                payload = payload.replace("hash_0", "forged_hash")
            new_hash = hashlib.sha256(
                (prev + timestamp + event_type + payload).encode("utf-8")
            ).hexdigest()
            conn.execute(
                "UPDATE audit_log SET payload = ?, prev_hash = ?, entry_hash = ? "
                "WHERE id = ?",
                (payload, prev, new_hash, entry_id),
            )
            prev = new_hash
        conn.commit()
    finally:
        conn.close()

    rewritten = verify_audit_log(db_path=db)
    assert "entry_hash_mismatch" not in _codes(rewritten)
    assert "broken_link" not in _codes(rewritten)

    anchored_report = verify_audit_log(db_path=db, expected_head=anchored)
    assert anchored_report.ok is False
    assert "head_mismatch" in _codes(anchored_report)


def test_empty_log_anchored_against_genesis_verifies(db):
    # Fresh-install case: the operator anchors the genesis head before any
    # training runs are recorded, and that anchor must still validate later.
    LineageStore(db_path=db).close()
    report = verify_audit_log(db_path=db, expected_head=GENESIS_HASH)
    assert report.ok is True
    assert report.findings == []


def test_empty_log_anchored_against_non_genesis_is_mismatch(db):
    # Complementary case: an attacker deletes the entire log, including all
    # its entries, after an anchor was taken. The now-empty log's head is
    # GENESIS_HASH, which must not match a previously anchored non-genesis
    # value.
    LineageStore(db_path=db).close()
    report = verify_audit_log(db_path=db, expected_head="f" * 64)
    assert report.ok is False
    assert "head_mismatch" in _codes(report)


def test_wholesale_rewrite_is_caught_by_the_anchor(db):
    _seed(db, n_runs=2)
    anchored = verify_audit_log(db_path=db).head_hash

    # Rewrite history from genesis: drop the log and rebuild it cleanly.
    _sql(db, "DELETE FROM audit_log")
    store = LineageStore(db_path=db)
    try:
        store.record_revocation(
            subject_key="k", n_affected_runs=0, recommended_actions=[]
        )
    finally:
        store.close()

    unanchored = verify_audit_log(db_path=db)
    assert "entry_hash_mismatch" not in _codes(unanchored)

    anchored_report = verify_audit_log(db_path=db, expected_head=anchored)
    assert anchored_report.ok is False
    assert "head_mismatch" in _codes(anchored_report)


# -- Robustness: expected_head is caller-supplied (will come from a CLI
# --expected-head flag), not database-supplied, so it can be any string, an
# empty string, or a value of the wrong type entirely. Comparison must never
# raise regardless.


def test_expected_head_of_wrong_type_does_not_raise(db):
    _seed(db, n_runs=2)
    report = verify_audit_log(db_path=db, expected_head=12345)
    assert report.ok is False
    assert "head_mismatch" in _codes(report)


def test_unhashable_expected_head_does_not_raise(db):
    _seed(db, n_runs=1)
    for value in ([1, 2], {"a": 1}):
        report = verify_audit_log(db_path=db, expected_head=value)
        assert "head_mismatch" in _codes(report)


def test_expected_head_empty_string_on_nonempty_log_is_mismatch(db):
    _seed(db, n_runs=2)
    report = verify_audit_log(db_path=db, expected_head="")
    assert report.ok is False
    assert "head_mismatch" in _codes(report)


def test_expected_head_none_is_not_checked(db):
    _seed(db, n_runs=2)
    report = verify_audit_log(db_path=db, expected_head=None)
    assert report.ok is True
    assert "head_mismatch" not in _codes(report)


def test_head_mismatch_finding_has_no_entry_id(db):
    _seed(db, n_runs=2)
    report = verify_audit_log(db_path=db, expected_head="f" * 64)
    findings = [f for f in report.findings if f.code == "head_mismatch"]
    assert len(findings) == 1
    assert findings[0].entry_id is None
