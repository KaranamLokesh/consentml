"""Command-line interface: consentml revoke --subject-id <id>."""

import argparse
import json

from consentml.revoke import revoke


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

    args = parser.parse_args(argv)
    report = revoke(
        subject_id=args.subject_id, db_path=args.db, dry_run=args.dry_run
    )
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_summary(report)
    return 0
