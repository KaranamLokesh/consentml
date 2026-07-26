"""Command-line interface.

    consentml revoke --subject-id <id>
    consentml verify [--expected-head <hash>]

Exit codes: 0 clean, 1 the database was read and problems were found
(including no database at the given path), 2 the database could not be read.
"""

import argparse
import json
import sqlite3
import sys

from consentml.migrate import migrate_database
from consentml.revoke import revoke
from consentml.verify import verify_audit_log


def _print_summary(report):
    n = len(report.affected_models)
    plural = "" if n == 1 else "s"
    print(f"{n} affected model{plural} for subject {report.subject_key[:12]}…")
    for m in report.affected_models:
        print(
            f"  - {m.model_name}  run={m.run_id[:8]}  "
            f"trained={m.started_at}  recommendation={m.recommendation}"
        )
    if report.audit_log_entry_id is not None:
        print(f"Revocation recorded (audit entry #{report.audit_log_entry_id}).")
    else:
        print("Dry run: nothing recorded.")


def _print_verify_summary(report):
    if report.ok:
        print(f"Audit log OK: {report.n_entries} entries, chain intact.")
    else:
        n = len(report.findings)
        print(
            f"Audit log FAILED verification: {n} finding{'' if n == 1 else 's'} "
            f"across {report.n_entries} entries."
        )
        for f in report.findings:
            where = f"entry {f.entry_id}" if f.entry_id is not None else "tables"
            print(f"  - [{f.code}] {where}: {f.detail}")
    print(f"head: {report.head_hash}")


def _format_bytes(n: int) -> str:
    """Format a byte count with the smallest unit that keeps it readable.

    A fixed MB scale makes any database under a few hundred KB round to
    "0.0 MB" on both sides of a migration, which reads as if nothing
    happened. Adaptive units keep small databases legible.
    """
    if n < 1024:
        return f"{n} bytes"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _format_delta(n: int) -> str:
    sign = "+" if n >= 0 else "-"
    return f"{sign}{_format_bytes(abs(n))}"


def _print_migrate_summary(result):
    if result.already_current:
        print("Database is already on the current schema; nothing to do.")
        return
    if not result.migrated:
        print(f"Migration refused: {result.error}")
        for f in result.findings:
            where = f"entry {f.entry_id}" if f.entry_id is not None else "tables"
            print(f"  - [{f.code}] {where}: {f.detail}")
        return
    delta = result.bytes_after - result.bytes_before
    print(
        f"Migrated: {_format_bytes(result.bytes_before)} -> "
        f"{_format_bytes(result.bytes_after)} ({_format_delta(delta)})."
    )
    if delta > 0:
        # The expected outcome for small databases: the interned schema's
        # extra tables and indexes carry fixed overhead that only nets a
        # win once subjects repeat across many runs. Without this note, a
        # small database growing after migration reads like a bug.
        print(
            "The new schema's tables and indexes add fixed overhead; "
            "deduplication only pays off once subjects repeat across many "
            "runs."
        )
    print(f"Original kept at {result.backup_path}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="consentml",
        description="Training-data lineage and consent-revocation reporting.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_revoke = sub.add_parser(
        "revoke", help="Report models affected by a consent revocation"
    )
    p_revoke.add_argument("--subject-id", required=True)
    p_revoke.add_argument(
        "--db", default=None, help="Lineage DB path (default: ~/.consentml/lineage.db)"
    )
    p_revoke.add_argument(
        "--dry-run",
        action="store_true",
        help="Report only; do not record a revocation event",
    )
    p_revoke.add_argument(
        "--json", dest="as_json", action="store_true", help="Emit JSON"
    )

    p_verify = sub.add_parser(
        "verify", help="Verify the audit log's integrity"
    )
    p_verify.add_argument(
        "--db", default=None, help="Lineage DB path (default: ~/.consentml/lineage.db)"
    )
    p_verify.add_argument(
        "--expected-head",
        default=None,
        help="Previously anchored head_hash; detects a wholesale log rewrite",
    )
    p_verify.add_argument(
        "--json", dest="as_json", action="store_true", help="Emit JSON"
    )

    p_migrate = sub.add_parser(
        "migrate", help="Upgrade a lineage database to the current schema"
    )
    p_migrate.add_argument(
        "--db", default=None, help="Lineage DB path (default: ~/.consentml/lineage.db)"
    )
    p_migrate.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Migrate even if the database fails verification (not recommended)",
    )
    p_migrate.add_argument(
        "--json", dest="as_json", action="store_true", help="Emit JSON"
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "verify":
            report = verify_audit_log(
                db_path=args.db, expected_head=args.expected_head
            )
        elif args.command == "migrate":
            report = migrate_database(
                db_path=args.db, allow_unverified=args.allow_unverified
            )
        else:
            report = revoke(
                subject_id=args.subject_id, db_path=args.db, dry_run=args.dry_run
            )
    except (sqlite3.Error, OSError) as e:
        print(f"Error: could not open database at {args.db!r}: {e}", file=sys.stderr)
        return 2

    if args.command == "verify":
        if args.as_json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            _print_verify_summary(report)
        return 0 if report.ok else 1

    if args.command == "migrate":
        if args.as_json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            _print_migrate_summary(report)
        return 0 if (report.migrated or report.already_current) else 1

    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_summary(report)
    return 0
