"""Audit-log verification: is the recorded history intact?

verify_audit_log() is strictly read-only. It never repairs, records no audit
event of its own -- a self-recorded "I verified myself" entry would carry no
more trust than the log containing it -- and never creates or modifies the
database, including never provisioning one that doesn't exist yet, or one
that exists but isn't a ConsentML lineage database (empty, foreign schema,
or not a SQLite file at all). Staying read-only means a copy of a
production database can be checked safely.
"""

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from consentml.store import (
    GENESIS_HASH,
    LineageStore,
    default_db_path,
    provenance_hash,
)

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
    n_legacy_runs: int = 0

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "n_entries": self.n_entries,
            "head_hash": self.head_hash,
            "findings": [asdict(f) for f in self.findings],
            "generated_at": self.generated_at,
            "n_legacy_runs": self.n_legacy_runs,
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


def _check_references(entries, parsed, store) -> tuple[list, int]:
    """Compare training_run entries against the live tables.

    Revocation entries are deliberately not cross-checked: their
    n_affected_runs was point-in-time and legitimately differs once later
    runs are recorded.

    Returns (findings, n_legacy_runs). A legacy run is one whose audit payload
    predates provenance hashing -- its provenance is intended to be backfilled
    by a future migration and is NOT hash-protected, so it is counted and
    reported rather than silently passing as if it had been checked.
    """
    findings = []
    logged_run_ids = set()
    legacy_run_ids = set()
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

        if "provenance_sha256" in payload:
            actual_hash = provenance_hash(run["provenance"])
            # provenance_hash() returns None as a sentinel for "not
            # verifiable text" (a BLOB, an int, ...), never as a real
            # digest. It must never be allowed to compare equal to
            # anything, including a payload whose provenance_sha256 was
            # itself forged to JSON null -- `None == None` would otherwise
            # report a clean bill of health for exactly the tampering this
            # check exists to catch.
            if actual_hash is None or actual_hash != payload["provenance_sha256"]:
                findings.append(
                    VerificationFinding(
                        entry_id=entry["id"],
                        code="provenance_modified",
                        detail=(
                            f"run {run_id}: provenance in training_runs does "
                            "not match the hash recorded in the audit log"
                        ),
                    )
                )
        elif "data_source" in payload:
            # Pre-v2 entry: its payload was hashed before provenance existed
            # and must never be rewritten, or the hash chain over it would
            # no longer match (a migration is expected to backfill
            # training_runs.provenance from this free-text field without
            # touching the already-hashed audit entry) -- so there is
            # nothing to check it against. Counted by run_id, not by entry,
            # so a run with more than one legacy entry isn't reported as
            # more than one unverified run. Reported so the report can say
            # so rather than implying it verified something it did not.
            legacy_run_ids.add(run_id)
        else:
            # Neither key: not a shape any schema version ever wrote. Must
            # not fall into the legacy bucket, which would silently accept
            # any payload missing provenance_sha256 as "merely old" instead
            # of flagging it as the malformed payload it actually is.
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="malformed_payload",
                    detail=(
                        f"entry {entry['id']} payload has neither "
                        "provenance_sha256 nor data_source"
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
    return findings, len(legacy_run_ids)


def _is_lineage_database(db) -> bool:
    """True if db contains an audit_log table.

    Opened strictly read-only via a URI connection, so this probe can never
    create or modify the file no matter what it contains -- unlike a plain
    sqlite3.connect() or LineageStore, either of which will happily
    provision a fresh empty schema onto a file that doesn't have one yet.
    A 0-byte file lands here: SQLite opens it as a valid, empty database,
    so the query below runs cleanly and simply finds no audit_log table.

    Deliberately does NOT catch sqlite3.Error or OSError here. Those mean
    the file could not be read at all -- permission denied, a directory,
    bytes that aren't a SQLite database -- which is a different operator
    problem from "this is a readable database that just isn't ours" (fix
    permissions/the path, vs. fix --db). verify_audit_log() has always let
    that class of failure propagate so the CLI can report it distinctly
    (exit 2, vs. exit 1 for a reported finding); this function's never-raise
    contract covers hostile *database contents*, not I/O failures, and
    widening this except to swallow them would make exit 2 unreachable and
    silently mislabel "permission denied" as "wrong --db path".
    """
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_log'"
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def verify_audit_log(*, db_path=None, expected_head=None) -> VerificationReport:
    """Verify the audit log's hash chain and its agreement with the tables.

    A hash chain alone cannot detect a wholesale rewrite from genesis. Pass
    expected_head with a previously recorded head_hash -- anchored somewhere
    outside this database -- to check that the anchor is still present
    somewhere in the current chain. An entry's hash transitively depends on
    every entry before it, so finding the anchor proves everything up to
    that point is byte-for-byte intact; new entries appended after it are a
    legitimate extension, not a mismatch.

    This proves history up to the anchor point only. It says nothing about
    entries appended after it -- a sophisticated attacker can append
    validly-chained forged entries past the anchor, and no anchor taken
    before those entries can detect that.
    """
    db = Path(db_path) if db_path is not None else default_db_path()
    if not db.exists():
        # LineageStore.__init__ would create the parent directories and the
        # database file itself -- fine for @track/revoke, which legitimately
        # provision a database on first use, but wrong here: verification
        # never legitimately creates one, and a typoed --db path must not be
        # able to silently report a clean bill of health for a database that
        # was never checked.
        return VerificationReport(
            ok=False,
            n_entries=0,
            head_hash=GENESIS_HASH,
            findings=[
                VerificationFinding(
                    entry_id=None,
                    code="missing_database",
                    detail=f"no lineage database at {db}",
                )
            ],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
    if not _is_lineage_database(db):
        # The path exists but isn't a ConsentML lineage database: empty
        # file, a directory, a foreign SQLite database, or not a SQLite
        # file at all. A distinct code from missing_database on purpose --
        # the two conditions have different fixes (wrong path vs. wrong
        # file) and an operator debugging "missing database" against a
        # file that plainly exists would go looking in the wrong place.
        # Checked with a strictly read-only connection, before
        # LineageStore ever touches the path, because LineageStore would
        # provision a fresh empty current-version schema onto exactly this
        # kind of file and then report a clean bill of health for it.
        return VerificationReport(
            ok=False,
            n_entries=0,
            head_hash=GENESIS_HASH,
            findings=[
                VerificationFinding(
                    entry_id=None,
                    code="not_a_lineage_database",
                    detail=f"{db} does not look like a ConsentML lineage database",
                )
            ],
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
    store = LineageStore(db_path=db_path)
    try:
        entries = store.audit_entries()
        parsed, findings = _parse_payloads(entries)
        findings += _check_chain(entries)
        reference_findings, n_legacy = _check_references(entries, parsed, store)
        findings += reference_findings
        head_hash = entries[-1]["entry_hash"] if entries else GENESIS_HASH
        if expected_head is not None:
            # expected_head is caller-supplied and may be any type, including
            # unhashable ones (a list, a dict) -- a set (and `in` against it)
            # would raise on those. A linear == scan never raises for any
            # pair of types, so use that even though it costs O(n); this
            # function already makes several O(n) passes over entries, and
            # audit logs are small.
            known = [GENESIS_HASH] + [e["entry_hash"] for e in entries]
            if not any(expected_head == h for h in known):
                findings.append(
                    VerificationFinding(
                        entry_id=None,
                        code="head_mismatch",
                        detail=(
                            "the anchored head is not present anywhere in "
                            "the current chain; history has been rewritten "
                            "or truncated"
                        ),
                    )
                )
        findings.sort(key=lambda f: (f.entry_id is None, f.entry_id or 0))
        return VerificationReport(
            ok=not findings,
            n_entries=len(entries),
            head_hash=head_hash,
            findings=findings,
            generated_at=datetime.now(timezone.utc).isoformat(),
            n_legacy_runs=n_legacy,
        )
    finally:
        store.close()
