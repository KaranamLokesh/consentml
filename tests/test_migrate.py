import hashlib
import sqlite3

import pytest

from consentml.migrate import MigrationResult, migrate_database
from consentml.revoke import revoke
from consentml.store import LineageStore
from consentml.verify import verify_audit_log


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_migrates_a_legacy_database(legacy_db):
    result = migrate_database(db_path=legacy_db)
    assert isinstance(result, MigrationResult)
    assert result.migrated is True
    assert result.already_current is False
    s = LineageStore(db_path=legacy_db)
    try:
        assert s.schema_version == 1
    finally:
        s.close()


def test_verification_clean_before_and_after(legacy_db):
    assert verify_audit_log(db_path=legacy_db).ok is True
    migrate_database(db_path=legacy_db)
    assert verify_audit_log(db_path=legacy_db).ok is True


def test_revoke_reports_are_identical_across_migration(legacy_db):
    before = revoke(subject_id="h1", db_path=legacy_db, dry_run=True).to_dict()
    migrate_database(db_path=legacy_db)
    after = revoke(subject_id="h1", db_path=legacy_db, dry_run=True).to_dict()
    for report in (before, after):
        report.pop("generated_at")
    assert before == after


def test_leaves_a_backup(legacy_db):
    original = _digest(legacy_db)
    result = migrate_database(db_path=legacy_db)
    backup = legacy_db.parent / (legacy_db.name + ".pre-migration.bak")
    assert backup.exists()
    assert _digest(backup) == original
    assert result.backup_path == str(backup)


def test_is_idempotent(legacy_db):
    migrate_database(db_path=legacy_db)
    second = migrate_database(db_path=legacy_db)
    assert second.already_current is True
    assert second.migrated is False


def test_refuses_a_tampered_database(legacy_db):
    conn = sqlite3.connect(legacy_db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    original = _digest(legacy_db)

    result = migrate_database(db_path=legacy_db)

    assert result.migrated is False
    assert "subject_count_mismatch" in [f.code for f in result.findings]
    assert _digest(legacy_db) == original  # byte-identical, untouched
    assert not (legacy_db.parent / (legacy_db.name + ".pre-migration.bak")).exists()


def test_allow_unverified_overrides_the_refusal(legacy_db):
    conn = sqlite3.connect(legacy_db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    result = migrate_database(db_path=legacy_db, allow_unverified=True)
    assert result.migrated is True


def test_missing_database_is_reported(tmp_path):
    result = migrate_database(db_path=tmp_path / "nope.db")
    assert result.migrated is False
    assert result.error is not None
    assert not (tmp_path / "nope.db").exists()


def test_subject_keys_are_deduplicated_but_counts_preserved(tmp_path, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=(("a", ("h1", "h2")), ("b", ("h1", "h2"))))
    migrate_database(db_path=db)
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM subjects").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM subject_index").fetchone()[0] == 4
    finally:
        conn.close()


def test_audit_log_survives_byte_for_byte(legacy_db):
    def rows(path):
        conn = sqlite3.connect(path)
        try:
            return conn.execute(
                "SELECT id, timestamp, event_type, payload, prev_hash, entry_hash "
                "FROM audit_log ORDER BY id"
            ).fetchall()
        finally:
            conn.close()

    before = rows(legacy_db)
    migrate_database(db_path=legacy_db)
    assert rows(legacy_db) == before
