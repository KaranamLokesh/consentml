"""Per-subject regulator dossier assembly.

build_dossier() answers one data subject's erasure request: which models
learned from their data, what the operator recommended for each, when the
request was processed, and whether the log backing all of it is intact.

Strictly read-only -- it calls revoke() with dry_run=True and never touches a
write path, so a dossier can be produced from a snapshot of production
without modifying production. That also means the scope is deliberately one
subject: the audit log is a single global chain, and exporting all of it to
answer one subject's request would disclose every other subject's activity
to that subject's regulator.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from consentml.hashing import hash_subject_id
from consentml.revoke import revoke
from consentml.store import LineageStore
from consentml.verify import verify_audit_log

# Findings that mean there is nothing to read at the given path, as opposed
# to a real database with problems in it. build_dossier stops on these
# without constructing a LineageStore -- see the ordering note below.
_NO_DATABASE_CODES = {"missing_database", "not_a_lineage_database"}


@dataclass
class Dossier:
    subject_id: str
    subject_key: str
    generated_at: str
    affected_models: list
    recommended_actions: list
    revocation_events: list
    verification: object
    head_hash: str
    n_legacy_runs: int
    consentml_version: str
    database_found: bool = True

    def to_dict(self) -> dict:
        return {
            "subject_id": self.subject_id,
            "subject_key": self.subject_key,
            "generated_at": self.generated_at,
            "affected_models": [asdict(m) for m in self.affected_models],
            "recommended_actions": self.recommended_actions,
            "revocation_events": self.revocation_events,
            "verification": self.verification.to_dict(),
            "head_hash": self.head_hash,
            "n_legacy_runs": self.n_legacy_runs,
            "consentml_version": self.consentml_version,
            "database_found": self.database_found,
        }


def _revocation_events_for(store, subject_key) -> list:
    """This subject's revocation events, oldest first.

    Payloads are attacker-editable and the store's lenient text_factory can
    hand back bytes for undecodable TEXT, so anything that does not parse to
    a dict is skipped rather than raised on -- mirroring _parse_payloads() in
    verify.py. Skipping is safe here only because the verification read
    reports those same entries as malformed_payload, so a dossier can never
    quietly omit an event without the document also showing the log is
    broken.
    """
    events = []
    for entry in store.audit_entries():
        if entry["event_type"] != "revocation":
            continue
        try:
            payload = json.loads(entry["payload"])
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("subject_key") != subject_key:
            continue
        events.append(
            {
                "entry_id": entry["id"],
                "timestamp": entry["timestamp"],
                "subject_key": payload["subject_key"],
                "n_affected_runs": payload.get("n_affected_runs"),
                "recommended_actions": payload.get("recommended_actions"),
                "entry_hash": entry["entry_hash"],
            }
        )
    return events


def build_dossier(*, subject_id, db_path=None) -> Dossier:
    """Assemble the dossier for one subject. Never writes to the database.

    Verification runs FIRST, and a missing or foreign database returns here
    before revoke() is ever called. That ordering is load-bearing, not
    stylistic: revoke() constructs a LineageStore, and LineageStore.__init__
    creates parent directories and runs the schema script against any path
    that lacks one. Calling revoke() first against a typoed --db would
    silently create an empty database, find zero affected models, verify the
    empty log as clean, and emit an official-looking dossier stating that no
    models were trained on this person's data. That false clean is the worst
    available bug in this feature, and it is the same hazard verify.py was
    hardened against; composing revoke() into a new caller re-introduces it
    unless this order is preserved.
    """
    # Imported here, not at module scope: consentml/__init__.py imports this
    # module, so a top-level `from consentml import __version__` would be a
    # circular import.
    from consentml import __version__

    subject_key = hash_subject_id(subject_id)
    generated_at = datetime.now(timezone.utc).isoformat()
    verification = verify_audit_log(db_path=db_path)

    if any(f.code in _NO_DATABASE_CODES for f in verification.findings):
        return Dossier(
            subject_id=str(subject_id),
            subject_key=subject_key,
            generated_at=generated_at,
            affected_models=[],
            recommended_actions=[],
            revocation_events=[],
            verification=verification,
            head_hash=verification.head_hash,
            n_legacy_runs=verification.n_legacy_runs,
            consentml_version=__version__,
            database_found=False,
        )

    report = revoke(subject_id=subject_id, db_path=db_path, dry_run=True)

    store = LineageStore(db_path=db_path)
    try:
        events = _revocation_events_for(store, subject_key)
    finally:
        store.close()

    return Dossier(
        subject_id=str(subject_id),
        subject_key=subject_key,
        generated_at=generated_at,
        affected_models=report.affected_models,
        recommended_actions=report.recommended_actions,
        revocation_events=events,
        verification=verification,
        head_hash=verification.head_hash,
        n_legacy_runs=verification.n_legacy_runs,
        consentml_version=__version__,
        database_found=True,
    )
