import hashlib
import os
import sqlite3

import pytest

import consentml.migrate as migrate_mod
from consentml.migrate import MigrationResult, migrate_database
from consentml.revoke import revoke
from consentml.store import LineageStore
from consentml.verify import (
    VerificationFinding,
    VerificationReport,
    verify_audit_log,
)


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


def test_public_api_exports_migrate():
    import consentml

    assert consentml.migrate_database is migrate_database
    assert consentml.MigrationResult is MigrationResult


def test_interning_shrinks_a_repeated_population(tmp_path, build_legacy):
    """The whole point of the exercise, pinned by a test.

    Five runs over the same 2000 subjects. Under the old schema every run
    re-stored every key; under v1 the keys are stored once.

    Measured with these exact parameters: 1662976 bytes -> 675840 bytes
    (ratio ~0.406). If a future change to this test moves that ratio much
    closer to the 0.6 gate, treat it as a signal worth investigating rather
    than nudging the threshold to match.
    """
    # 64-char SHA-256 digests, matching what hash_subject_id() actually
    # stores. Interning's saving scales with key length -- with short
    # placeholder keys this ratio lands near 0.75 and the test would fail
    # for a reason that cannot occur in real use.
    keys = tuple(
        hashlib.sha256(f"subject-{i}".encode()).hexdigest() for i in range(2000)
    )
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=tuple((f"m{i}", keys) for i in range(5)))
    before = db.stat().st_size

    migrate_database(db_path=db)
    after = db.stat().st_size

    assert after < before * 0.6, f"expected a clear shrink, got {before} -> {after}"

    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT COUNT(*) FROM subjects").fetchone()[0] == 2000
        assert conn.execute(
            "SELECT COUNT(*) FROM subject_index"
        ).fetchone()[0] == 10000
    finally:
        conn.close()


def test_migrate_wraps_unexpected_errors(tmp_path, build_legacy, monkeypatch):
    """migrate_database()'s never-raise contract covers hostile database
    contents, not just the sqlite3.Error/OSError cases -- see its docstring's
    "last-resort net". Force an unrelated exception out of verify_audit_log
    to confirm it lands as an error MigrationResult, not a traceback."""
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=(("a", ("h1", "h2")),))

    def boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(migrate_mod, "verify_audit_log", boom)

    result = migrate_database(db_path=db)

    assert result.migrated is False
    assert "unexpected error migrating" in result.error
    assert "kaboom" in result.error


def test_migrate_reports_a_copy_failure(tmp_path, build_legacy, monkeypatch):
    """A sqlite3.Error while building the staging copy (e.g. a write failure
    partway through) must be reported, not raised -- and the original must
    be left alone (never even touched by this failure)."""
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=(("a", ("h1", "h2")),))
    original = db.read_bytes()

    real_connect = sqlite3.connect

    class _Boom:
        def __init__(self, real_conn):
            self._real_conn = real_conn

        def executescript(self, *args, **kwargs):
            raise sqlite3.OperationalError("simulated failure creating staging db")

        def close(self):
            self._real_conn.close()

    def fake_connect(path, *args, **kwargs):
        conn = real_connect(path, *args, **kwargs)
        if str(path).endswith(".migrating"):
            return _Boom(conn)
        return conn

    monkeypatch.setattr(migrate_mod.sqlite3, "connect", fake_connect)

    result = migrate_database(db_path=db)

    assert result.migrated is False
    assert "migration failed while copying data" in result.error
    assert db.read_bytes() == original


def test_row_count_mismatch_is_caught_and_refused(tmp_path, build_legacy):
    """A subject_index row referencing a run_id absent from training_runs,
    with no audit_log entry mentioning it either, is invisible to
    verify_audit_log()'s audit-log-anchored checks -- it never shows up as a
    subject_count_mismatch for any real run. The join-based copy in
    _copy_into_v1 silently drops such a row (no match, no insert), which the
    raw row-count comparison exists specifically to catch."""
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=(("a", ("h1", "h2")),))

    conn = sqlite3.connect(db)
    with conn:
        conn.execute(
            "INSERT INTO subject_index VALUES (?, ?)", ("no-such-run", "orphan-hash")
        )
    conn.close()

    # Confirm the setup: this dangling row really is invisible to verify.
    assert verify_audit_log(db_path=db).ok is True

    result = migrate_database(db_path=db)

    assert result.migrated is False
    assert "row_count_mismatch" in [f.code for f in result.findings]
    assert "row counts do not match the original" in result.error

    conn = sqlite3.connect(db)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0  # untouched
    finally:
        conn.close()


def test_migrate_refuses_when_the_migrated_copy_fails_verification(
    tmp_path, build_legacy, monkeypatch
):
    """The second verification gate: even after the row-count check passes,
    the freshly-built staging copy is itself re-verified before it is
    swapped in. Simulated here via monkeypatch, since a real corruption that
    slips past both the original's verification and the row-count check but
    still fails the copy's own verification is not one this suite can
    otherwise construct -- the guarantee this exercises is in the handling
    code, not in finding such a database in the wild."""
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=(("a", ("h1", "h2")),))

    real_verify = migrate_mod.verify_audit_log
    calls = []

    def fake_verify(*, db_path, expected_head=None):
        calls.append(db_path)
        if len(calls) == 1:
            return real_verify(db_path=db_path, expected_head=expected_head)
        return VerificationReport(
            ok=False,
            n_entries=0,
            head_hash="0" * 64,
            findings=[
                VerificationFinding(
                    entry_id=None, code="simulated", detail="simulated failure"
                )
            ],
            generated_at="2026-01-01T00:00:00+00:00",
        )

    monkeypatch.setattr(migrate_mod, "verify_audit_log", fake_verify)

    result = migrate_database(db_path=db)

    assert result.migrated is False
    assert "migrated database failed verification" in result.error
    assert [f.code for f in result.findings] == ["simulated"]
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0  # untouched
    finally:
        conn.close()


def test_finalize_failure_restores_the_original(tmp_path, build_legacy, monkeypatch):
    """If the second of the two finalizing renames fails, the first must be
    undone so the canonical path is never left missing."""
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=(("a", ("h1", "h2")),))

    real_replace = os.replace
    calls = []

    def fake_replace(src, dst):
        calls.append((src, dst))
        if len(calls) == 2:
            raise OSError("simulated failure: staging -> db")
        return real_replace(src, dst)

    monkeypatch.setattr(migrate_mod.os, "replace", fake_replace)

    result = migrate_database(db_path=db)

    assert result.migrated is False
    assert "migration failed while finalizing" in result.error
    assert db.exists()
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0  # restored to v0
    finally:
        conn.close()


def test_finalize_failure_when_restore_also_fails(tmp_path, build_legacy, monkeypatch):
    """If the recovery rename (putting the original back after a failed
    finalize) *also* fails, the error must say so explicitly rather than
    claiming the original is safe when it might not be."""
    db = tmp_path / "legacy.db"
    build_legacy(db, runs=(("a", ("h1", "h2")),))

    real_replace = os.replace
    calls = []

    def fake_replace(src, dst):
        calls.append((src, dst))
        if len(calls) == 1:
            return real_replace(src, dst)  # db -> backup: really happens
        raise OSError("simulated failure")  # staging -> db, and the recovery attempt

    monkeypatch.setattr(migrate_mod.os, "replace", fake_replace)

    result = migrate_database(db_path=db)

    assert result.migrated is False
    assert "could not be restored" in result.error
