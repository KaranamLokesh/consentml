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
                provenance={"kind": "dataframe", "label": "postgres://prod/customers"},
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


def _run_pk(db, run_id):
    """Resolve a run_id to its surrogate run_pk, for tampering with
    subject_index directly (it references run_pk, not run_id)."""
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT run_pk FROM training_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    finally:
        conn.close()
    return row[0]


def _subject_pk(db, subject_key):
    """Resolve an interned subject_key to its surrogate subject_pk."""
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT subject_pk FROM subjects WHERE subject_key = ?", (subject_key,)
        ).fetchone()
    finally:
        conn.close()
    return row[0]


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


def test_missing_database_is_reported_not_created(db):
    assert not db.exists()
    report = verify_audit_log(db_path=db)
    assert report.ok is False
    assert report.n_entries == 0
    assert _codes(report) == ["missing_database"]
    assert not db.exists()


def test_empty_file_is_reported_not_a_lineage_database_and_left_untouched(db):
    # An empty file *exists* and SQLite opens it happily as a valid, empty
    # database -- so it doesn't hit the missing_database check, and it's
    # genuinely readable, not an I/O failure. But LineageStore._detect_schema
    # treats a training_runs-less file as "provision a fresh v1 schema
    # here," which would silently turn this into an empty-but-valid lineage
    # database and then report ok=True.
    db.write_bytes(b"")
    report = verify_audit_log(db_path=db)
    assert report.ok is False
    assert _codes(report) == ["not_a_lineage_database"]
    assert db.read_bytes() == b""


def test_non_sqlite_file_raises_instead_of_reporting_not_a_lineage_database(db):
    # Distinct from the empty-file case: this file cannot be read as a
    # SQLite database at all -- an I/O failure, not "readable but not
    # ours". verify_audit_log() deliberately lets this propagate (the CLI
    # catches it and reports exit 2) rather than folding it into
    # not_a_lineage_database, which would make "permission denied" and
    # "directory at this path" indistinguishable from "wrong --db path".
    junk = b"this is not a sqlite database, just plain bytes" * 5
    db.write_bytes(junk)
    with pytest.raises(sqlite3.DatabaseError):
        verify_audit_log(db_path=db)
    assert db.read_bytes() == junk


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
    run_pk = _run_pk(db, run_ids[0])
    subject_pk = _subject_pk(db, "s0a")
    _sql(db, "DELETE FROM subject_index WHERE run_pk = ? AND subject_pk = ?",
         (run_pk, subject_pk))
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
    run_pk = _run_pk(db, run_ids[0])
    subject_pk = _subject_pk(db, "s0a")
    _sql(db, "DELETE FROM subject_index WHERE run_pk = ? AND subject_pk = ?",
         (run_pk, subject_pk))
    _sql(db, "UPDATE training_runs SET n_subjects = 1 WHERE run_id = ?", (run_ids[0],))
    report = verify_audit_log(db_path=db)
    assert "subject_count_mismatch" in _codes(report)


def test_added_subject_row_is_detected(db):
    run_ids = _seed(db, n_runs=1)
    run_pk = _run_pk(db, run_ids[0])
    _sql(db, "INSERT INTO subjects (subject_key) VALUES (?)", ("smuggled",))
    subject_pk = _subject_pk(db, "smuggled")
    _sql(db, "INSERT INTO subject_index (run_pk, subject_pk) VALUES (?, ?)",
         (run_pk, subject_pk))
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
        "INSERT INTO training_runs (run_id, model_name, model_hash, provenance, "
        "subject_ids_hashed, n_subjects, started_at, finished_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("smuggled-run", "shadow", "h", '{"kind": "dataframe", "label": "src"}', 1, 0,
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
            provenance={"kind": "dataframe", "label": "src"},
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
        "INSERT INTO training_runs (run_id, model_name, model_hash, provenance, "
        "subject_ids_hashed, n_subjects, started_at, finished_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("text-run-id", "shadow-a", "h", '{"kind": "dataframe", "label": "src"}', 1, 0,
         "2026-07-20T00:00:00+00:00", "2026-07-20T00:01:00+00:00"),
    )
    _sql(
        db,
        "INSERT INTO training_runs (run_id, model_name, model_hash, provenance, "
        "subject_ids_hashed, n_subjects, started_at, finished_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (b"\x00\x01blob-run-id", "shadow-b", "h", '{"kind": "dataframe", "label": "src"}',
         1, 0, "2026-07-20T00:00:00+00:00", "2026-07-20T00:01:00+00:00"),
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


def test_public_api_exports_verify():
    import consentml

    assert consentml.verify_audit_log is verify_audit_log
    assert consentml.VerificationReport is VerificationReport


def test_verify_works_on_a_legacy_database(legacy_db):
    report = verify_audit_log(db_path=legacy_db)
    assert report.ok is True
    assert report.n_entries == 2


def test_verify_detects_tampering_in_a_legacy_database(legacy_db):
    _sql(legacy_db, "DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    report = verify_audit_log(db_path=legacy_db)
    assert "subject_count_mismatch" in _codes(report)


def _one_run(db_path, provenance=None):
    store = LineageStore(db_path=db_path)
    store.record_training_run(
        model_name="m",
        model_hash="mh",
        provenance=provenance or {"kind": "dataframe", "label": "x", "n_rows": 1},
        subject_ids_hashed=True,
        subject_id_values=["a"],
        started_at="t0",
        finished_at="t1",
    )
    store.close()


def test_editing_provenance_is_detected(tmp_path):
    db = tmp_path / "l.db"
    _one_run(db)
    assert verify_audit_log(db_path=db).ok

    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE training_runs SET provenance = ?",
        (json.dumps({"kind": "dataframe", "label": "somewhere-else", "n_rows": 1},
                    sort_keys=True),),
    )
    conn.commit()
    conn.close()

    report = verify_audit_log(db_path=db)
    assert not report.ok
    assert [f.code for f in report.findings] == ["provenance_modified"]


def test_provenance_replaced_with_a_blob_is_detected_not_raised(tmp_path):
    db = tmp_path / "l.db"
    _one_run(db)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE training_runs SET provenance = ?", (b"\xff\xfe",))
    conn.commit()
    conn.close()

    report = verify_audit_log(db_path=db)
    assert [f.code for f in report.findings] == ["provenance_modified"]


def test_provenance_forged_to_null_does_not_verify_against_a_blob(tmp_path):
    """provenance_hash() returns None for a BLOB it can't treat as text.
    That None must never be allowed to compare equal to anything -- including
    a payload whose provenance_sha256 was itself forged to JSON null, which
    would otherwise let `None == None` slip through as a clean bill of
    health for exactly this tampering."""
    db = tmp_path / "l.db"
    _one_run(db)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE training_runs SET provenance = ?", (b"\xff\xfe",))
    # Forging provenance_sha256 to null also changes the payload text, so
    # entry_hash has to be recomputed here too -- otherwise the tamper would
    # be masked by (and reported as) entry_hash_mismatch instead of
    # exercising the None-vs-None comparison this test targets.
    entry_id, timestamp, event_type, payload, prev_hash = conn.execute(
        "SELECT id, timestamp, event_type, payload, prev_hash FROM audit_log"
    ).fetchone()
    forged_payload = json.loads(payload)
    forged_payload["provenance_sha256"] = None
    new_payload = json.dumps(forged_payload, sort_keys=True)
    new_hash = hashlib.sha256(
        (prev_hash + timestamp + event_type + new_payload).encode("utf-8")
    ).hexdigest()
    conn.execute(
        "UPDATE audit_log SET payload = ?, entry_hash = ? WHERE id = ?",
        (new_payload, new_hash, entry_id),
    )
    conn.commit()
    conn.close()

    report = verify_audit_log(db_path=db)
    assert not report.ok
    assert [f.code for f in report.findings] == ["provenance_modified"]


def test_provenance_undecodable_utf8_text_is_detected_not_raised(tmp_path):
    """CAST(... AS TEXT) forces genuine TEXT storage class holding bytes that
    aren't valid UTF-8 -- distinct from the BLOB case above, which sqlite3
    returns as bytes without attempting to decode at all. Reading a TEXT
    column that fails to decode raises sqlite3.OperationalError from inside
    store.run_by_id() itself, before provenance_hash() ever gets a chance to
    run. That must still surface as a finding here, not propagate up to the
    CLI's exit-2 (I/O failure) path -- the database was read fine; only its
    contents are hostile."""
    db = tmp_path / "l.db"
    _one_run(db)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE training_runs SET provenance = CAST(x'fffe' AS TEXT)")
    conn.commit()
    conn.close()

    report = verify_audit_log(db_path=db)
    assert not report.ok
    assert [f.code for f in report.findings] == ["malformed_payload"]


def test_clean_v2_database_reports_no_legacy_runs(tmp_path):
    db = tmp_path / "l.db"
    _one_run(db)
    report = verify_audit_log(db_path=db)
    assert report.ok
    assert report.n_legacy_runs == 0
    assert report.to_dict()["n_legacy_runs"] == 0


def _insert_legacy_training_run(db, run_id, model_hash="legacy-mh", n_subjects=0):
    """Insert a training_runs row directly, bypassing LineageStore, the way
    an already-migrated legacy run would look: current v2 columns
    (including a populated provenance, per migrate.py's design intent of
    backfilling it from the old data_source), but referenced by an audit
    entry whose payload predates provenance hashing entirely."""
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "INSERT INTO training_runs (run_id, model_name, model_hash, "
            "provenance, subject_ids_hashed, n_subjects, started_at, "
            "finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, "legacy-m", model_hash,
             '{"kind": "dataframe", "label": "postgres://prod/customers"}',
             1, n_subjects, "2020-01-01T00:00:00+00:00", "2020-01-01T00:01:00+00:00"),
        )
        conn.commit()
    finally:
        conn.close()


def test_legacy_payload_in_a_v2_database_is_counted_not_checked(tmp_path, append_entry):
    """A single audit log can legitimately hold a MIX of payload shapes once
    a future migration backfills old entries' training_runs rows alongside
    new ones: pre-v2 entries carry data_source, post-v2 entries carry
    provenance_sha256. This builds that mix directly (there's no public API
    path to produce it yet): one ordinary v2 run plus one legacy run with
    its own run_id and its own training_runs row -- not a second audit entry
    bolted onto the v2 run's row, which would model a duplicate-log database
    instead of a post-migration one. n_legacy_runs must count the one
    genuinely-legacy run out of the two logged runs, and the report must
    still be clean."""
    db = tmp_path / "l.db"
    _one_run(db)  # the ordinary v2 run
    _insert_legacy_training_run(db, "legacy-run")

    payload = json.dumps(
        {
            "run_id": "legacy-run",
            "model_name": "legacy-m",
            "model_hash": "legacy-mh",
            "data_source": "postgres://prod/customers",
            "n_subjects": 0,
        },
        sort_keys=True,
    )
    append_entry(db, "training_run", payload)

    report = verify_audit_log(db_path=db)
    assert report.ok
    assert report.n_legacy_runs == 1


def test_legacy_run_with_two_entries_is_counted_once(tmp_path, append_entry):
    """n_legacy_runs counts distinct runs, not entries: a legacy run logged
    twice (e.g. re-recorded, or simply two audit entries referencing the
    same run_id) must still contribute 1 to the count, not 2."""
    db = tmp_path / "l.db"
    LineageStore(db_path=db).close()  # provision the v2 schema
    _insert_legacy_training_run(db, "legacy-run")
    payload = json.dumps(
        {
            "run_id": "legacy-run",
            "model_name": "legacy-m",
            "model_hash": "legacy-mh",
            "data_source": "postgres://prod/customers",
            "n_subjects": 0,
        },
        sort_keys=True,
    )
    append_entry(db, "training_run", payload)
    append_entry(db, "training_run", payload)

    report = verify_audit_log(db_path=db)
    assert report.ok
    assert report.n_legacy_runs == 1


def test_payload_with_neither_provenance_key_is_malformed_not_legacy(tmp_path, append_entry):
    """A payload lacking provenance_sha256 is only legacy if it carries the
    one thing that ever made a payload lack it: data_source. Anything else
    missing both keys is a shape no schema version ever wrote and must be
    flagged as malformed, not silently folded into "merely old"."""
    db = tmp_path / "l.db"
    LineageStore(db_path=db).close()  # provision the v2 schema
    _insert_legacy_training_run(db, "legacy-run")
    payload = json.dumps(
        {
            "run_id": "legacy-run",
            "model_name": "legacy-m",
            "model_hash": "legacy-mh",
            "n_subjects": 0,
        },
        sort_keys=True,
    )
    append_entry(db, "training_run", payload)

    report = verify_audit_log(db_path=db)
    assert not report.ok
    assert [f.code for f in report.findings] == ["malformed_payload"]
    assert report.n_legacy_runs == 0
