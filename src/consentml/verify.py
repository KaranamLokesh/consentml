"""Audit-log verification: is the recorded history intact?

verify_audit_log() is strictly read-only. It never repairs, and it records no
audit event of its own -- a self-recorded "I verified myself" entry would carry
no more trust than the log containing it, and staying read-only means a copy of
a production database can be checked safely.
"""

import hashlib
import json
import sqlite3
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
            str(entry["prev_hash"])
            + str(entry["timestamp"])
            + str(entry["event_type"])
            + str(entry["payload"])
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
        except Exception:
            # Any json.loads failure means the payload is malformed: bad JSON
            # text, a BLOB that isn't valid UTF-8, or nesting deep enough to
            # blow the parser's recursion limit. The try wraps exactly this
            # one call, so a broad except can't mask an unrelated bug.
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="malformed_payload",
                    detail=f"entry {entry['id']} payload is not valid JSON",
                )
            )
            continue
        if not isinstance(payload, dict):
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="malformed_payload",
                    detail=f"entry {entry['id']} payload is not a JSON object",
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
    """Compare training_run entries against the live tables.

    Revocation entries are deliberately not cross-checked: their
    n_affected_runs was point-in-time and legitimately differs once later
    runs are recorded.
    """
    findings = []
    logged_run_ids = set()
    for entry in entries:
        if entry["event_type"] != "training_run":
            continue
        payload = parsed.get(entry["id"])
        if payload is None:  # already reported as malformed
            continue
        run_id = payload["run_id"]

        # run_id came straight out of parsed JSON, so it can be any JSON
        # type -- e.g. a list or dict -- not just the string _append_audit_
        # entry always wrote. Those are unhashable (breaks the set below)
        # and unbindable as a SQLite parameter (breaks the lookups below),
        # so reject them here instead of letting either raise.
        try:
            hash(run_id)
        except TypeError:
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="malformed_payload",
                    detail=(
                        f"entry {entry['id']} run_id is not a valid reference"
                    ),
                )
            )
            continue
        logged_run_ids.add(run_id)

        try:
            run = store.run_by_id(run_id)
        except (sqlite3.InterfaceError, OverflowError):
            # InterfaceError: a type sqlite3 can't bind at all (shouldn't
            # reach here given the hash() check above, but defense in
            # depth). OverflowError: a JSON integer wider than SQLite's
            # 64-bit INTEGER, which hash()/bindability alone don't rule out.
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="malformed_payload",
                    detail=(
                        f"entry {entry['id']} run_id is not a valid reference"
                    ),
                )
            )
            continue
        if run is None:
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="missing_run",
                    detail=(
                        f"run {run_id} from entry {entry['id']} is absent "
                        "from training_runs"
                    ),
                )
            )
            continue

        actual = store.subject_count_for_run(run_id)
        if actual != payload["n_subjects"]:
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="subject_count_mismatch",
                    detail=(
                        f"run {run_id}: audit log records {payload['n_subjects']} "
                        f"subjects, subject_index holds {actual}"
                    ),
                )
            )
        for field in ("model_hash", "n_subjects"):
            if run[field] != payload[field]:
                findings.append(
                    VerificationFinding(
                        entry_id=entry["id"],
                        code="run_modified",
                        detail=(
                            f"run {run_id}: {field} in training_runs "
                            f"({run[field]!r}) differs from the logged "
                            f"value ({payload[field]!r})"
                        ),
                    )
                )

    # sorted() on raw run_id values would raise TypeError if training_runs
    # ever holds a mix of types (e.g. a BLOB run_id alongside normal TEXT
    # ones) -- sort by string representation so ordering stays deterministic
    # without assuming every run_id is comparable to every other.
    for run_id in sorted(store.all_run_ids() - logged_run_ids, key=str):
        findings.append(
            VerificationFinding(
                entry_id=None,
                code="unlogged_run",
                detail=(
                    f"run {run_id} exists in training_runs with no audit entry"
                ),
            )
        )
    return findings


def verify_audit_log(*, db_path=None) -> VerificationReport:
    """Verify the audit log's hash chain and its agreement with the tables."""
    store = LineageStore(db_path=db_path)
    try:
        entries = store.audit_entries()
        parsed, findings = _parse_payloads(entries)
        findings += _check_chain(entries)
        findings += _check_references(entries, parsed, store)
        findings.sort(key=lambda f: (f.entry_id is None, f.entry_id or 0))
        return VerificationReport(
            ok=not findings,
            n_entries=len(entries),
            head_hash=entries[-1]["entry_hash"] if entries else GENESIS_HASH,
            findings=findings,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
    finally:
        store.close()
