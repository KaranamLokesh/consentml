"""Command-line interface: consentml revoke --subject-id <id>."""

import argparse
import json
import sqlite3
import sys

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

    args = parser.parse_args(argv)

    try:
        if args.command == "verify":
            report = verify_audit_log(
                db_path=args.db, expected_head=args.expected_head
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

    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_summary(report)
    return 0
