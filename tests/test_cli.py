import json
import os
import sqlite3

import pytest

from consentml.cli import main
from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


@pytest.fixture
def seeded_db(tmp_path):
    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            data_source="postgres://prod/customers",
            subject_id_col="email",
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    return db


def test_cli_revoke_json_output(seeded_db, capsys):
    exit_code = main(
        ["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db), "--json"]
    )
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["affected_models"][0]["model_name"] == "churn_v3"
    assert data["recommended_actions"] == [
        {"model_name": "churn_v3", "action": "retrain"}
    ]


def test_cli_revoke_human_output(seeded_db, capsys):
    main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db)])
    out = capsys.readouterr().out
    assert "churn_v3" in out
    assert "retrain" in out
    assert "1 affected model" in out


def test_cli_dry_run_does_not_record(seeded_db, capsys):
    main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db), "--dry-run"])
    store = LineageStore(db_path=seeded_db)
    try:
        assert all(
            e["event_type"] != "revocation" for e in store.audit_entries()
        )
    finally:
        store.close()


def test_cli_no_affected_models(tmp_path, capsys):
    db = tmp_path / "empty.db"
    exit_code = main(["revoke", "--subject-id", "x@x.com", "--db", str(db)])
    assert exit_code == 0
    assert "0 affected models" in capsys.readouterr().out


def test_cli_verify_clean_exits_zero(seeded_db, capsys):
    exit_code = main(["verify", "--db", str(seeded_db)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Audit log OK" in out
    assert "1 entries" in out


def test_cli_verify_tampered_exits_one(seeded_db, capsys):
    conn = sqlite3.connect(seeded_db)
    try:
        with conn:
            conn.execute("UPDATE audit_log SET payload = ? WHERE id = 1",
                         ("not json{",))
    finally:
        conn.close()
    exit_code = main(["verify", "--db", str(seeded_db)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "malformed_payload" in out


def test_cli_verify_json_output(seeded_db, capsys):
    exit_code = main(["verify", "--db", str(seeded_db), "--json"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True
    assert data["findings"] == []
    assert len(data["head_hash"]) == 64


def test_cli_verify_expected_head_mismatch_exits_one(seeded_db, capsys):
    exit_code = main(
        ["verify", "--db", str(seeded_db), "--expected-head", "f" * 64]
    )
    assert exit_code == 1
    assert "head_mismatch" in capsys.readouterr().out


def test_cli_revoke_still_exits_zero(seeded_db, capsys):
    assert main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db)]) == 0


def test_cli_verify_missing_db_exits_nonzero(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.db"
    exit_code = main(["verify", "--db", str(missing)])
    assert exit_code != 0
    out = capsys.readouterr().out
    assert "no lineage database" in out
    assert not missing.exists()


def test_cli_verify_unopenable_db_exits_two(tmp_path, capsys):
    # A directory at the db path can't be opened by sqlite3 at all, so this
    # never gets far enough to see "no database" -- it's a harder failure,
    # distinct from not_a_lineage_database (a readable file that just isn't
    # ours). verify_audit_log() lets this propagate on purpose so the CLI
    # can tell "wrong --db path" apart from "couldn't read it at all".
    unopenable = tmp_path / "not-a-db.db"
    unopenable.mkdir()
    exit_code = main(["verify", "--db", str(unopenable)])
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "Error: could not open database" in err


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores file permission bits, so chmod 000 wouldn't block reads",
)
def test_cli_verify_permission_denied_db_exits_two(tmp_path, capsys):
    # A real, valid lineage database that the process simply cannot read.
    # Distinct from not_a_lineage_database in the same way as the directory
    # case above: this is an I/O failure (fix permissions), not "wrong
    # --db path" (fix the path) -- and unlike the directory case, this one
    # actually is a lineage database, so it must not be reported as if it
    # weren't.
    unreadable = tmp_path / "lineage.db"
    LineageStore(db_path=unreadable).close()
    os.chmod(unreadable, 0o000)
    try:
        exit_code = main(["verify", "--db", str(unreadable)])
    finally:
        os.chmod(unreadable, 0o644)  # restore so tmp_path cleanup can remove it
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "Error: could not open database" in err


def test_cli_migrate_succeeds(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    assert main(["migrate", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "Migrated" in out


def test_cli_migrate_is_idempotent(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    main(["migrate", "--db", str(db)])
    capsys.readouterr()
    assert main(["migrate", "--db", str(db)]) == 0
    assert "already" in capsys.readouterr().out.lower()


def test_cli_migrate_refuses_tampered_and_exits_one(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    conn = sqlite3.connect(db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    assert main(["migrate", "--db", str(db)]) == 1
    out = capsys.readouterr().out
    assert "subject_count_mismatch" in out


def test_cli_migrate_json(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    assert main(["migrate", "--db", str(db), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["migrated"] is True
    assert data["bytes_after"] > 0


def test_cli_migrate_allow_unverified_migrates_tampered(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    conn = sqlite3.connect(db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    exit_code = main(["migrate", "--db", str(db), "--allow-unverified"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Migrated" in out
