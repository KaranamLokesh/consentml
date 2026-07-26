"""Migrate a v0 lineage database onto the interned v1 schema.

The migration is gated by verification on both sides. It refuses to run on a
database that fails verification, because rewriting a tampered database
produces a fresh, internally consistent one -- laundering the tampering and
destroying the evidence.

The new database is built alongside the original and only swapped into place
once it verifies clean, so a failure leaves the original untouched and there
is no rollback logic to get wrong. The cost is temporary extra disk usage.
"""

import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from consentml.store import SCHEMA_VERSION, _SCHEMA, default_db_path
from consentml.verify import VerificationFinding, verify_audit_log

_RUN_COLS_V0 = (
    "run_id, model_name, model_hash, data_source, subject_id_col, "
    "subject_ids_hashed, n_subjects, started_at, finished_at"
)


@dataclass
class MigrationResult:
    migrated: bool
    already_current: bool
    findings: list = field(default_factory=list)
    bytes_before: int = 0
    bytes_after: int = 0
    backup_path: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "migrated": self.migrated,
            "already_current": self.already_current,
            "findings": [
                {"entry_id": f.entry_id, "code": f.code, "detail": f.detail}
                for f in self.findings
            ],
            "bytes_before": self.bytes_before,
            "bytes_after": self.bytes_after,
            "backup_path": self.backup_path,
            "error": self.error,
        }


def _copy_into_v1(src_path, dst_path):
    """Build a v1 database at dst_path from the v0 database at src_path."""
    dst = sqlite3.connect(dst_path)
    try:
        dst.executescript(_SCHEMA)
        dst.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        src = sqlite3.connect(src_path)
        try:
            with dst:
                for row in src.execute(f"SELECT {_RUN_COLS_V0} FROM training_runs"):
                    dst.execute(
                        f"INSERT INTO training_runs ({_RUN_COLS_V0}) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        row,
                    )
                # Intern the keys: each distinct value stored once...
                dst.executemany(
                    "INSERT OR IGNORE INTO subjects (subject_key) VALUES (?)",
                    src.execute("SELECT DISTINCT subject_id_hash FROM subject_index"),
                )
                # ...but one index row per original row, so per-run counts
                # are preserved exactly.
                #
                # Measured ~8us/row (1.60s for 200k subject_index rows) with
                # this per-row executemany, each doing a two-table lookup.
                # A set-based rewrite (ATTACH the source db, single
                # INSERT...SELECT...JOIN) measured ~10x faster on the same
                # 200k rows. Deliberately not taken: migration is a one-time
                # offline operation -- even at millions of rows this is
                # minutes, not hours -- and this is the one piece of code
                # whose entire job is not corrupting an audit trail, so the
                # simpler, more obviously-correct version is worth the
                # extra wall-clock time. Revisit if real databases grow
                # large enough that this stops being true.
                dst.executemany(
                    "INSERT INTO subject_index (run_pk, subject_pk) "
                    "SELECT r.run_pk, s.subject_pk FROM training_runs r, subjects s "
                    "WHERE r.run_id = ? AND s.subject_key = ?",
                    src.execute("SELECT run_id, subject_id_hash FROM subject_index"),
                )
                for row in src.execute(
                    "SELECT id, timestamp, event_type, payload, prev_hash, "
                    "entry_hash FROM audit_log ORDER BY id"
                ):
                    dst.execute(
                        "INSERT INTO audit_log (id, timestamp, event_type, "
                        "payload, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?)",
                        row,
                    )
        finally:
            src.close()
    finally:
        dst.close()


def _row_counts(path) -> dict:
    conn = sqlite3.connect(path)
    try:
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("training_runs", "subject_index", "audit_log")
        }
    finally:
        conn.close()


def migrate_database(*, db_path=None, allow_unverified=False) -> MigrationResult:
    """Migrate a lineage database onto schema v1.

    Verifies before and after. Refuses to migrate a database that fails
    verification unless allow_unverified is set.

    This function's never-raise contract covers hostile *database contents*
    -- like verify_audit_log(), a corrupt or tampered lineage database is
    always reported as a MigrationResult, never a traceback. It does NOT
    cover I/O failures while opening the database: a directory at the path
    or a permission-denied file was never read at all, which is a different
    operator problem (fix the path / fix permissions) from "this is a
    readable database with a problem in it" -- so sqlite3.Error and OSError
    raised while opening the original database are deliberately let through
    here, exactly as verify_audit_log() lets them through, so the CLI can
    report that class of failure distinctly (exit 2, vs. exit 1 for a
    reported finding). Widening this except to swallow them would make exit
    2 unreachable and silently mislabel "permission denied" as "database
    problem". _migrate_database does the real work; every step that touches
    the original database is already individually guarded, so this outer
    catch is a last-resort net for whatever that per-step analysis missed,
    not a substitute for it.
    """
    try:
        return _migrate_database(db_path=db_path, allow_unverified=allow_unverified)
    except (sqlite3.Error, OSError):
        # Open/read failures on the original database -- see docstring.
        # Must propagate uncaught so the CLI can distinguish exit 2 from
        # exit 1.
        raise
    except Exception as exc:  # noqa: BLE001 -- last-resort net, see docstring
        db = Path(db_path) if db_path is not None else default_db_path()
        return MigrationResult(
            migrated=False,
            already_current=False,
            error=f"unexpected error migrating {db}: {exc}",
        )


def _migrate_database(*, db_path=None, allow_unverified=False) -> MigrationResult:
    db = Path(db_path) if db_path is not None else default_db_path()
    if not db.exists():
        return MigrationResult(
            migrated=False,
            already_current=False,
            error=f"no lineage database at {db}",
        )

    # Deliberately not caught here: sqlite3.Error/OSError from opening a
    # directory or a permission-denied file means the database was never
    # read at all, which must propagate out to migrate_database()'s caller
    # (see its docstring) rather than being reported as a MigrationResult.
    conn = sqlite3.connect(db)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()
    if version >= SCHEMA_VERSION:
        return MigrationResult(
            migrated=False, already_current=True, bytes_before=db.stat().st_size
        )

    # No separate "is this even a lineage database" pre-check here: an
    # empty file, a directory, or some other non-lineage SQLite database
    # is exactly what verify_audit_log()'s own not_a_lineage_database
    # finding now reports -- via a strictly read-only probe that can't
    # mutate the file, so it's safe to call directly rather than
    # duplicating that check here.
    before = verify_audit_log(db_path=db)
    if not before.ok and not allow_unverified:
        return MigrationResult(
            migrated=False,
            already_current=False,
            findings=before.findings,
            bytes_before=db.stat().st_size,
            error="database failed verification; refusing to migrate",
        )

    bytes_before = db.stat().st_size
    staging = db.parent / (db.name + ".migrating")
    staging.unlink(missing_ok=True)
    try:
        try:
            _copy_into_v1(db, staging)
        except sqlite3.Error as exc:
            return MigrationResult(
                migrated=False,
                already_current=False,
                bytes_before=bytes_before,
                error=f"migration failed while copying data: {exc}",
            )

        # The subject_index copy is a join on run_id/subject_key: a row
        # whose run_id matches nothing in training_runs (e.g. tampering, or
        # a dangling reference verify_audit_log's audit-log-anchored checks
        # never see because no audit entry mentions it) simply produces no
        # match and vanishes silently. Compare raw row counts so a dropped
        # row is reported instead of shipping as a quiet success.
        before_counts = _row_counts(db)
        after_counts = _row_counts(staging)
        if before_counts != after_counts and not allow_unverified:
            mismatched = {
                table: (before_counts[table], after_counts[table])
                for table in before_counts
                if before_counts[table] != after_counts[table]
            }
            return MigrationResult(
                migrated=False,
                already_current=False,
                bytes_before=bytes_before,
                findings=[
                    VerificationFinding(
                        entry_id=None,
                        code="row_count_mismatch",
                        detail=(
                            f"row counts changed during migration: {mismatched} "
                            "(likely a subject_index row referencing a "
                            "nonexistent run); refusing to migrate"
                        ),
                    )
                ],
                error="migrated database row counts do not match the "
                "original; original untouched",
            )

        after = verify_audit_log(db_path=staging)
        if not after.ok and not allow_unverified:
            return MigrationResult(
                migrated=False,
                already_current=False,
                findings=after.findings,
                bytes_before=bytes_before,
                error="migrated database failed verification; original untouched",
            )
        backup = db.parent / (db.name + ".pre-migration.bak")
        try:
            # os.replace is a rename, not a byte copy: on the same filesystem
            # (guaranteed here -- backup lives in db.parent) it is O(1)
            # regardless of database size, unlike shutil.copy2. The two
            # renames leave a window of a few microseconds where the db path
            # doesn't exist between them; migration is a one-time offline
            # operation with no concurrent writer expected, so that window
            # is preferable to holding three copies of a multi-gigabyte
            # database on disk at once (original + copy2 backup + staging).
            os.replace(db, backup)
            os.replace(staging, db)
        except OSError as exc:
            # rename() is atomic -- if the first replace succeeded and the
            # second failed, db is left missing (moved to backup) while
            # staging is untouched. Put the original back before reporting,
            # so a mid-finalize failure can never leave the canonical path
            # empty.
            if not db.exists() and backup.exists():
                try:
                    os.replace(backup, db)
                except OSError:
                    return MigrationResult(
                        migrated=False,
                        already_current=False,
                        bytes_before=bytes_before,
                        error=(
                            f"migration failed while finalizing: {exc}; "
                            f"the original database could not be restored "
                            f"from {backup} -- restore it manually before "
                            "retrying"
                        ),
                    )
            return MigrationResult(
                migrated=False,
                already_current=False,
                bytes_before=bytes_before,
                error=f"migration failed while finalizing: {exc}",
            )
    finally:
        staging.unlink(missing_ok=True)

    return MigrationResult(
        migrated=True,
        already_current=False,
        bytes_before=bytes_before,
        bytes_after=db.stat().st_size,
        backup_path=str(backup),
    )
