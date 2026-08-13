"""build_dossier assembles the regulator dossier from three reads.

The ordering test below is the important one: build_dossier composes
revoke(), and revoke() constructs a LineageStore, which provisions a schema
onto any path that lacks one. Verifying first is what stops a typoed --db
from producing a clean-looking dossier for a database that never existed.
"""

import hashlib

import pytest

from consentml.export import build_dossier
from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


@pytest.fixture
def seeded_db(tmp_path):
    """Two models sharing one subject; churn_v3 also has a later run."""
    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "warehouse://customers"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com"), hash_subject_id("b@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
        store.record_training_run(
            model_name="upsell",
            model_hash="cafe",
            provenance={"kind": "dataframe", "label": "warehouse://customers"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-02T00:00:00+00:00",
            finished_at="2026-07-02T00:01:00+00:00",
        )
    finally:
        store.close()
    return db


def test_dossier_reports_both_affected_models(seeded_db):
    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert [m.model_name for m in dossier.affected_models] == ["churn_v3", "upsell"]
    assert dossier.recommended_actions == [
        {"model_name": "churn_v3", "action": "retrain"},
        {"model_name": "upsell", "action": "retrain"},
    ]


def test_dossier_carries_subject_id_and_key(seeded_db):
    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert dossier.subject_id == "a@x.com"
    assert dossier.subject_key == hash_subject_id("a@x.com")


def test_dossier_on_a_clean_database_verifies_ok(seeded_db):
    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert dossier.verification.ok is True
    assert dossier.head_hash == dossier.verification.head_hash
    assert dossier.database_found is True


def test_a_subject_with_no_models_still_gets_a_dossier(seeded_db):
    dossier = build_dossier(subject_id="nobody@x.com", db_path=seeded_db)
    assert dossier.affected_models == []
    assert dossier.verification.ok is True
    assert dossier.database_found is True


def test_dossier_includes_this_subjects_revocation_events(seeded_db):
    from consentml.revoke import revoke

    revoke(subject_id="a@x.com", db_path=seeded_db)
    revoke(subject_id="b@x.com", db_path=seeded_db)

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert len(dossier.revocation_events) == 1
    assert dossier.revocation_events[0]["subject_key"] == hash_subject_id("a@x.com")


def test_build_dossier_creates_nothing_at_a_missing_path(tmp_path):
    """The false-clean guard.

    If build_dossier ever calls revoke() before verifying, LineageStore
    provisions an empty database here, finds no models, verifies the empty
    log as clean, and the dossier asserts the opposite of the truth.
    """
    missing = tmp_path / "nope.db"

    dossier = build_dossier(subject_id="a@x.com", db_path=missing)

    assert not missing.exists()
    assert dossier.database_found is False
    assert dossier.verification.ok is False
    assert [f.code for f in dossier.verification.findings] == ["missing_database"]
    assert dossier.affected_models == []


def test_build_dossier_reports_a_foreign_sqlite_database(tmp_path):
    """A real SQLite database that simply isn't ours.

    This is the true not_a_lineage_database case: readable, but with no
    audit_log table. Distinct from unreadable bytes, which propagate as an
    I/O error for the CLI to report as exit 2 -- see the test below.
    """
    import sqlite3

    foreign = tmp_path / "foreign.db"
    conn = sqlite3.connect(foreign)
    conn.execute("CREATE TABLE unrelated (id INTEGER)")
    conn.commit()
    conn.close()

    dossier = build_dossier(subject_id="a@x.com", db_path=foreign)

    assert dossier.database_found is False
    assert [f.code for f in dossier.verification.findings] == ["not_a_lineage_database"]
    assert dossier.affected_models == []


def test_build_dossier_lets_unreadable_bytes_propagate(tmp_path):
    """Bytes that aren't a SQLite database at all.

    build_dossier must not catch this. verify.py deliberately lets it
    propagate so the CLI can distinguish "cannot read this file" (exit 2)
    from "wrong --db path" (exit 1); swallowing it here would make
    permission-denied indistinguishable from a typo.
    """
    import sqlite3

    junk = tmp_path / "junk.db"
    junk.write_bytes(b"not a sqlite file at all" * 5)

    with pytest.raises(sqlite3.DatabaseError):
        build_dossier(subject_id="a@x.com", db_path=junk)


def test_export_does_not_modify_the_database(seeded_db):
    """Read-only is proven by bytes, not by trusting dry_run=True."""
    before = hashlib.sha256(seeded_db.read_bytes()).hexdigest()
    build_dossier(subject_id="a@x.com", db_path=seeded_db)
    after = hashlib.sha256(seeded_db.read_bytes()).hexdigest()
    assert before == after


def test_tampered_database_surfaces_the_finding(seeded_db):
    import sqlite3

    conn = sqlite3.connect(seeded_db)
    conn.execute("UPDATE audit_log SET payload = replace(payload, 'churn_v3', 'x')")
    conn.commit()
    conn.close()

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert dossier.verification.ok is False
    assert "entry_hash_mismatch" in {f.code for f in dossier.verification.findings}
    # Still produced a dossier -- refusing would leave the operator nothing.
    assert dossier.affected_models != []


def test_legacy_v0_database_reports_unverified_runs(legacy_db):
    dossier = build_dossier(subject_id="h1", db_path=legacy_db)
    assert dossier.n_legacy_runs == 2
    assert dossier.database_found is True


def test_legacy_v1_database_reports_unverified_runs(v1_db):
    dossier = build_dossier(subject_id="h1", db_path=v1_db)
    assert dossier.n_legacy_runs == 2


def test_malformed_revocation_payload_is_skipped_not_raised(seeded_db, append_entry):
    append_entry(seeded_db, "revocation", "{not json at all")

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)

    assert dossier.revocation_events == []
    # The broken entry is not silently ignored -- verification reports it.
    assert "malformed_payload" in {f.code for f in dossier.verification.findings}


def test_revocation_payload_that_is_valid_json_but_not_an_object_is_skipped(
    seeded_db, append_entry
):
    """Distinct from the not-JSON-at-all case above: this payload parses,

    it just isn't a dict, so there is no subject_key to compare against.
    Mirrors the isinstance(payload, dict) guard in verify.py's own payload
    parsing.
    """
    append_entry(seeded_db, "revocation", "[1, 2, 3]")

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)

    assert dossier.revocation_events == []
    assert "malformed_payload" in {f.code for f in dossier.verification.findings}


def test_unreadable_event_fields_are_marked_not_crashed_on(seeded_db):
    """A tampered timestamp must not take the whole dossier down.

    The store's lenient text_factory returns bytes for TEXT that does not
    decode, and json.dumps() raises TypeError on bytes -- so `--format json`
    crashed on a database `--format html` rendered fine. str(b'\\xff') would
    stop the crash and print b'\\xff' into a compliance document as if it
    were the recorded time; the marker says what is true instead. The
    tampering itself is not being hidden: verification reports it as its own
    finding in the same dossier.
    """
    import json
    import sqlite3

    from consentml.render import render_html, render_json
    from consentml.revoke import revoke

    revoke(subject_id="a@x.com", db_path=seeded_db)
    # b@x.com's revocation is appended after a@x.com's, so tampering with
    # a@x.com's entry leaves the *head* entry's hash readable. That keeps
    # this test on _revocation_events_for: a bytes head_hash is a separate
    # crash, in verify.py, that this fix does not claim to address.
    revoke(subject_id="b@x.com", db_path=seeded_db)
    conn = sqlite3.connect(seeded_db)
    conn.execute(
        "UPDATE audit_log SET timestamp = CAST(x'ff' AS TEXT), "
        "entry_hash = CAST(x'ff' AS TEXT) "
        "WHERE id = (SELECT min(id) FROM audit_log WHERE event_type = 'revocation')"
    )
    conn.commit()
    conn.close()

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    event = dossier.revocation_events[0]
    assert event["timestamp"] == "unreadable - not readable text"
    assert event["entry_hash"] == "unreadable - not readable text"

    # The renderer that used to crash, and the one that used to disagree.
    assert json.loads(render_json(dossier))["revocation_events"] == [event]
    assert "unreadable - not readable text" in render_html(dossier)
    assert not dossier.verification.ok


def test_dossier_to_dict_is_json_serializable(seeded_db):
    import json

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    data = json.loads(json.dumps(dossier.to_dict()))
    assert data["subject_id"] == "a@x.com"
    assert data["verification"]["ok"] is True
    assert data["consentml_version"]
