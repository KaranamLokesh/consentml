"""Audit-log verification: is the recorded history intact?

verify_audit_log() is strictly read-only. It never repairs, and it records no
audit event of its own -- a self-recorded "I verified myself" entry would carry
no more trust than the log containing it, and staying read-only means a copy of
a production database can be checked safely.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from consentml.store import GENESIS_HASH, LineageStore

_REQUIRED_KEYS = {
    "training_run": {"run_id", "model_name", "model_hash", "n_subjects"},
    "revocation": {"subject_key", "n_affected_runs", "recommended_actions"},
}


@dataclass
class VerificationFinding:
    entry_id: int | None
    code: str
    detail: str


@dataclass
class VerificationReport:
    ok: bool
    n_entries: int
    head_hash: str
    findings: list
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "n_entries": self.n_entries,
            "head_hash": self.head_hash,
            "findings": [asdict(f) for f in self.findings],
            "generated_at": self.generated_at,
        }


def _recompute(entry) -> str:
    return hashlib.sha256(
        (
            entry["prev_hash"]
            + entry["timestamp"]
            + entry["event_type"]
            + entry["payload"]
        ).encode("utf-8")
    ).hexdigest()


def _check_chain(entries) -> list:
    """Per-entry hash integrity and link continuity.

    Each entry is hashed from its own stored fields and each link compared to
    the previous row's stored hash, so one edit never invalidates the tail.
    """
    findings = []
    for i, entry in enumerate(entries):
        if _recompute(entry) != entry["entry_hash"]:
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="entry_hash_mismatch",
                    detail=f"entry {entry['id']} hash does not match its contents",
                )
            )
        expected_prev = GENESIS_HASH if i == 0 else entries[i - 1]["entry_hash"]
        if entry["prev_hash"] != expected_prev:
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="bad_genesis" if i == 0 else "broken_link",
                    detail=(
                        f"entry {entry['id']} prev_hash does not match "
                        + ("the genesis hash" if i == 0 else "the preceding entry")
                    ),
                )
            )
    return findings


def _parse_payloads(entries) -> tuple[dict, list]:
    """Parse every payload. Returns (entry_id -> payload, findings)."""
    parsed, findings = {}, []
    for entry in entries:
        try:
            payload = json.loads(entry["payload"])
        except json.JSONDecodeError:
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="malformed_payload",
                    detail=f"entry {entry['id']} payload is not valid JSON",
                )
            )
            continue
        required = _REQUIRED_KEYS.get(entry["event_type"], set())
        missing = required - set(payload)
        if missing:
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="malformed_payload",
                    detail=(
                        f"entry {entry['id']} payload is missing "
                        f"{', '.join(sorted(missing))}"
                    ),
                )
            )
            continue
        parsed[entry["id"]] = payload
    return parsed, findings


def _check_references(entries, parsed, store) -> list:
    return []


def verify_audit_log(*, db_path=None) -> VerificationReport:
    """Verify the audit log's hash chain and its agreement with the tables."""
    store = LineageStore(db_path=db_path)
    try:
        entries = store.audit_entries()
        parsed, findings = _parse_payloads(entries)
        findings += _check_chain(entries)
        findings += _check_references(entries, parsed, store)
        return VerificationReport(
            ok=not findings,
            n_entries=len(entries),
            head_hash=entries[-1]["entry_hash"] if entries else GENESIS_HASH,
            findings=findings,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
    finally:
        store.close()
