# ConsentML v0 Week-7 Audit Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `verify_audit_log()` and a `consentml verify` CLI subcommand that detect both tampering with the hash-chained audit log and silent divergence between the log and the live `training_runs` / `subject_index` tables.

**Architecture:** A new read-only `verify.py` module mirroring the shape of `revoke.py`: dataclasses (`VerificationFinding`, `VerificationReport`) plus a `verify_audit_log()` entry point that composes two private check functions. `LineageStore` gains three small read-only queries. Verification never writes — it records no audit event of its own and never repairs.

**Tech Stack:** Same as Weeks 5–6 — Python ≥3.10, stdlib `sqlite3`/`hashlib`/`json`/`argparse`/`dataclasses`, pytest. No new dependencies.

**File structure:**

```
src/consentml/
├── __init__.py     # modify: export verify_audit_log, VerificationReport, VerificationFinding
├── store.py        # modify: run_by_id, subject_count_for_run, all_run_ids
├── verify.py       # new: VerificationFinding, VerificationReport, verify_audit_log
└── cli.py          # modify: `verify` subcommand, dispatch, exit code
tests/
├── test_store.py   # modify: tests for the three new queries
├── test_verify.py  # new
└── test_cli.py     # modify: verify subcommand tests
```

**Conventions:** all commands run from the repo root with the venv: `.venv/bin/pytest ...`. Work happens on branch `v0-week7-verify`.

**Threat model note for the implementer:** tests tamper by opening the SQLite file directly with `sqlite3` and issuing `UPDATE`/`DELETE`. That *is* the attack being defended against, so do not be tempted to route these through `LineageStore`.

---

### Task 0: Branch

- [ ] **Step 1: Create the working branch**

```bash
git checkout -b v0-week7-verify
```

---

### Task 1: Store queries for cross-checking

**Files:**
- Modify: `src/consentml/store.py`
- Test: `tests/test_store.py` (append)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_store.py`)

```python
def test_run_by_id_returns_the_run(store):
    run_id = _record_sample_run(store)
    run = store.run_by_id(run_id)
    assert run["run_id"] == run_id
    assert run["model_name"] == "churn_v3"
    assert run["n_subjects"] == 2


def test_run_by_id_unknown_is_none(store):
    assert store.run_by_id("nope") is None


def test_subject_count_for_run(store):
    run_id = _record_sample_run(store, subject_hashes=("h1", "h2", "h3"))
    assert store.subject_count_for_run(run_id) == 3


def test_subject_count_for_unknown_run_is_zero(store):
    assert store.subject_count_for_run("nope") == 0


def test_all_run_ids(store):
    a = _record_sample_run(store, model_name="a")
    b = _record_sample_run(store, model_name="b")
    assert store.all_run_ids() == {a, b}


def test_all_run_ids_empty(store):
    assert store.all_run_ids() == set()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_store.py -v`
Expected: 6 new tests FAIL with `AttributeError: 'LineageStore' object has no attribute 'run_by_id'` (and similarly for the others); the 15 existing tests still pass.

- [ ] **Step 3: Implement in `src/consentml/store.py`**

Add these three methods to `LineageStore`, immediately after `latest_run_for_model`:

```python
    def run_by_id(self, run_id) -> dict | None:
        """The training run with this id, or None if it is absent."""
        row = self._conn.execute(
            f"SELECT {', '.join(_RUN_COLS)} FROM training_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        return dict(zip(_RUN_COLS, row)) if row else None

    def subject_count_for_run(self, run_id) -> int:
        """How many subject_index rows currently exist for this run."""
        return self._conn.execute(
            "SELECT COUNT(*) FROM subject_index WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    def all_run_ids(self) -> set:
        """Every run id present in training_runs."""
        rows = self._conn.execute("SELECT run_id FROM training_runs").fetchall()
        return {row[0] for row in rows}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_store.py -v`
Expected: 21 passed

- [ ] **Step 5: Commit**

```bash
git add src/consentml/store.py tests/test_store.py
git commit -m "feat: store queries for audit cross-checking"
```

---

### Task 2: Chain verification (hash integrity and linkage)

**Files:**
- Create: `src/consentml/verify.py`
- Test: `tests/test_verify.py`

**Design note on the no-cascade guarantee.** Each entry's hash is recomputed from its **own stored fields**, and each link is checked against the previous row's **stored** `entry_hash` — never against a running recomputed hash. Consequences, which the tests below pin down:

- A naive tamperer edits a payload and leaves `entry_hash` alone → exactly **one** `entry_hash_mismatch` at that entry. The next entry's `prev_hash` still matches the (unchanged) stored hash, so no link breaks.
- A sophisticated tamperer edits the payload *and* recomputes `entry_hash` → that entry passes its hash check, but the next entry's `prev_hash` no longer matches → exactly **one** `broken_link`, at *k+1*.

Either way one edit yields one finding, never a corrupted tail.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_verify.py
import hashlib
import json
import sqlite3

import pytest

from consentml.store import GENESIS_HASH, LineageStore
from consentml.verify import VerificationReport, verify_audit_log


@pytest.fixture
def db(tmp_path):
    return tmp_path / "lineage.db"


def _seed(db, n_runs=3):
    """Record n_runs training runs, each with two subjects."""
    store = LineageStore(db_path=db)
    try:
        return [
            store.record_training_run(
                model_name=f"model_{i}",
                model_hash=f"hash_{i}",
                data_source="postgres://prod/customers",
                subject_id_col="email",
                subject_ids_hashed=True,
                subject_id_values=[f"s{i}a", f"s{i}b"],
                started_at=f"2026-07-{i + 1:02d}T00:00:00+00:00",
                finished_at=f"2026-07-{i + 1:02d}T00:01:00+00:00",
            )
            for i in range(n_runs)
        ]
    finally:
        store.close()


def _sql(db, statement, params=()):
    """Tamper with the database directly -- this is the threat model."""
    conn = sqlite3.connect(db)
    try:
        with conn:
            conn.execute(statement, params)
    finally:
        conn.close()


def _codes(report):
    return [f.code for f in report.findings]


def test_clean_log_verifies(db):
    _seed(db)
    report = verify_audit_log(db_path=db)
    assert isinstance(report, VerificationReport)
    assert report.ok is True
    assert report.findings == []
    assert report.n_entries == 3


def test_empty_log_verifies(db):
    LineageStore(db_path=db).close()
    report = verify_audit_log(db_path=db)
    assert report.ok is True
    assert report.n_entries == 0


def test_edited_payload_is_detected_without_cascade(db):
    _seed(db, n_runs=5)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 3", ('{"run_id": "x"}',))
    report = verify_audit_log(db_path=db)
    hash_findings = [f for f in report.findings if f.code == "entry_hash_mismatch"]
    assert [f.entry_id for f in hash_findings] == [3]
    assert "broken_link" not in _codes(report)


def test_rehashed_entry_breaks_the_next_link(db):
    _seed(db, n_runs=5)
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT timestamp, event_type, prev_hash FROM audit_log WHERE id = 3"
        ).fetchone()
        timestamp, event_type, prev_hash = row
        payload = '{"forged": true}'
        forged = hashlib.sha256(
            (prev_hash + timestamp + event_type + payload).encode("utf-8")
        ).hexdigest()
        with conn:
            conn.execute(
                "UPDATE audit_log SET payload = ?, entry_hash = ? WHERE id = 3",
                (payload, forged),
            )
    finally:
        conn.close()

    report = verify_audit_log(db_path=db)
    link_findings = [f for f in report.findings if f.code == "broken_link"]
    assert [f.entry_id for f in link_findings] == [4]
    assert "entry_hash_mismatch" not in _codes(report)


def test_bad_genesis_is_detected(db):
    _seed(db, n_runs=2)
    _sql(db, "UPDATE audit_log SET prev_hash = ? WHERE id = 1", ("f" * 64,))
    report = verify_audit_log(db_path=db)
    assert "bad_genesis" in _codes(report)
    assert "broken_link" not in _codes(report)


def test_malformed_payload_does_not_raise(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ("not json{",))
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)
    assert report.ok is False


def test_payload_missing_keys_is_malformed(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ('{"run_id": "x"}',))
    report = verify_audit_log(db_path=db)
    assert "malformed_payload" in _codes(report)


def test_report_to_dict_round_trips_through_json(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ("not json{",))
    report = verify_audit_log(db_path=db)
    data = json.loads(json.dumps(report.to_dict()))
    assert data["ok"] is False
    assert data["n_entries"] == 1
    assert data["findings"][0]["code"] == "malformed_payload"
    assert data["generated_at"] == report.generated_at
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_verify.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'consentml.verify'`

- [ ] **Step 3: Write `src/consentml/verify.py`**

Note: `_check_references` is a stub returning `[]` in this task; Task 3 fills it in. The `malformed_payload` check lives in `_check_payloads` and applies to **every** entry type, while Task 3's cross-checks apply only to `training_run` entries.

```python
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
        findings = _check_chain(entries) + findings
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_verify.py -v`
Expected: 8 passed

- [ ] **Step 5: Commit**

```bash
git add src/consentml/verify.py tests/test_verify.py
git commit -m "feat: audit-log chain verification with no-cascade findings"
```

---

### Task 3: Referential cross-checks against the live tables

**Files:**
- Modify: `src/consentml/verify.py`
- Test: `tests/test_verify.py` (append)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_verify.py`)

```python
def test_deleted_subject_row_is_detected(db):
    run_ids = _seed(db, n_runs=2)
    _sql(db, "DELETE FROM subject_index WHERE run_id = ? AND subject_id_hash = ?",
         (run_ids[0], "s0a"))
    report = verify_audit_log(db_path=db)
    assert report.ok is False
    findings = [f for f in report.findings if f.code == "subject_count_mismatch"]
    assert len(findings) == 1
    assert "2" in findings[0].detail and "1" in findings[0].detail


def test_added_subject_row_is_detected(db):
    run_ids = _seed(db, n_runs=1)
    _sql(db, "INSERT INTO subject_index VALUES (?, ?)", (run_ids[0], "smuggled"))
    report = verify_audit_log(db_path=db)
    assert "subject_count_mismatch" in _codes(report)


def test_deleted_run_is_detected(db):
    run_ids = _seed(db, n_runs=2)
    _sql(db, "DELETE FROM training_runs WHERE run_id = ?", (run_ids[0],))
    report = verify_audit_log(db_path=db)
    findings = [f for f in report.findings if f.code == "missing_run"]
    assert len(findings) == 1
    assert run_ids[0] in findings[0].detail


def test_modified_model_hash_is_detected(db):
    run_ids = _seed(db, n_runs=1)
    _sql(db, "UPDATE training_runs SET model_hash = ? WHERE run_id = ?",
         ("forged", run_ids[0]))
    report = verify_audit_log(db_path=db)
    assert "run_modified" in _codes(report)


def test_unlogged_run_is_detected(db):
    _seed(db, n_runs=1)
    _sql(
        db,
        "INSERT INTO training_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("smuggled-run", "shadow", "h", "src", "email", 1, 0,
         "2026-07-20T00:00:00+00:00", "2026-07-20T00:01:00+00:00"),
    )
    report = verify_audit_log(db_path=db)
    findings = [f for f in report.findings if f.code == "unlogged_run"]
    assert len(findings) == 1
    assert findings[0].entry_id is None
    assert "smuggled-run" in findings[0].detail


def test_zero_subject_run_is_not_a_mismatch(db):
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="empty",
            model_hash="h",
            data_source="src",
            subject_id_col="email",
            subject_ids_hashed=True,
            subject_id_values=[],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    report = verify_audit_log(db_path=db)
    assert report.ok is True


def test_revocation_entries_are_not_cross_checked(db):
    _seed(db, n_runs=1)
    store = LineageStore(db_path=db)
    try:
        store.record_revocation(
            subject_key="k", n_affected_runs=99, recommended_actions=[]
        )
    finally:
        store.close()
    report = verify_audit_log(db_path=db)
    assert report.ok is True


def test_malformed_training_payload_skips_cross_check(db):
    _seed(db, n_runs=1)
    _sql(db, "UPDATE audit_log SET payload = ? WHERE id = 1", ("not json{",))
    report = verify_audit_log(db_path=db)
    codes = _codes(report)
    assert "malformed_payload" in codes
    assert "missing_run" not in codes
    assert "unlogged_run" in codes  # the run is now effectively unlogged
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_verify.py -v`
Expected: the 8 new tests FAIL (`assert report.ok is False` fails because `_check_references` is still a stub returning `[]`); the 8 tests from Task 2 still pass.

- [ ] **Step 3: Replace the `_check_references` stub in `src/consentml/verify.py`**

Replace the entire stub:

```python
def _check_references(entries, parsed, store) -> list:
    return []
```

with:

```python
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
        logged_run_ids.add(run_id)

        run = store.run_by_id(run_id)
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
        if run["model_hash"] != payload["model_hash"]:
            findings.append(
                VerificationFinding(
                    entry_id=entry["id"],
                    code="run_modified",
                    detail=(
                        f"run {run_id}: model_hash in training_runs differs "
                        "from the logged value"
                    ),
                )
            )

    for run_id in sorted(store.all_run_ids() - logged_run_ids):
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_verify.py -v`
Expected: 16 passed

- [ ] **Step 5: Commit**

```bash
git add src/consentml/verify.py tests/test_verify.py
git commit -m "feat: cross-check audit log against training_runs and subject_index"
```

---

### Task 4: External head anchoring

**Files:**
- Modify: `src/consentml/verify.py`
- Test: `tests/test_verify.py` (append)

**Why this task exists.** A hash chain detects *partial* tampering. It cannot detect an attacker who rewrites the whole log from genesis and recomputes every hash — that forgery verifies clean. The standard mitigation is anchoring the head hash somewhere the attacker does not control (CI logs, a separate system, a printed compliance record) and comparing on the next run. `head_hash` is already on the report from Task 2; this task adds the comparison.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_verify.py`)

```python
def test_head_hash_is_the_last_entry_hash(db):
    _seed(db, n_runs=2)
    store = LineageStore(db_path=db)
    try:
        expected = store.audit_entries()[-1]["entry_hash"]
    finally:
        store.close()
    assert verify_audit_log(db_path=db).head_hash == expected


def test_head_hash_of_empty_log_is_genesis(db):
    LineageStore(db_path=db).close()
    assert verify_audit_log(db_path=db).head_hash == GENESIS_HASH


def test_matching_expected_head_verifies(db):
    _seed(db, n_runs=2)
    head = verify_audit_log(db_path=db).head_hash
    report = verify_audit_log(db_path=db, expected_head=head)
    assert report.ok is True


def test_wholesale_rewrite_is_caught_by_the_anchor(db):
    _seed(db, n_runs=2)
    anchored = verify_audit_log(db_path=db).head_hash

    # Rewrite history from genesis: drop the log and rebuild it cleanly.
    _sql(db, "DELETE FROM audit_log")
    store = LineageStore(db_path=db)
    try:
        store.record_revocation(
            subject_key="k", n_affected_runs=0, recommended_actions=[]
        )
    finally:
        store.close()

    unanchored = verify_audit_log(db_path=db)
    assert "entry_hash_mismatch" not in _codes(unanchored)

    anchored_report = verify_audit_log(db_path=db, expected_head=anchored)
    assert anchored_report.ok is False
    assert "head_mismatch" in _codes(anchored_report)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_verify.py -v`
Expected: the 4 head tests FAIL — the first two with `AttributeError: 'VerificationReport' object has no attribute 'head_hash'` **only if Task 2 was skipped**; otherwise the last two fail with `TypeError: verify_audit_log() got an unexpected keyword argument 'expected_head'`.

- [ ] **Step 3: Add the `expected_head` parameter in `src/consentml/verify.py`**

Replace the `verify_audit_log` function body:

```python
def verify_audit_log(*, db_path=None, expected_head=None) -> VerificationReport:
    """Verify the audit log's hash chain and its agreement with the tables.

    A hash chain alone cannot detect a wholesale rewrite from genesis. Pass
    expected_head with a previously recorded head_hash -- anchored somewhere
    outside this database -- to detect that too.
    """
    store = LineageStore(db_path=db_path)
    try:
        entries = store.audit_entries()
        parsed, findings = _parse_payloads(entries)
        findings = _check_chain(entries) + findings
        findings += _check_references(entries, parsed, store)
        head = entries[-1]["entry_hash"] if entries else GENESIS_HASH
        if expected_head is not None and head != expected_head:
            findings.append(
                VerificationFinding(
                    entry_id=None,
                    code="head_mismatch",
                    detail=(
                        "log head does not match the expected anchor; entries "
                        "may have been removed, reordered, or rewritten"
                    ),
                )
            )
        return VerificationReport(
            ok=not findings,
            n_entries=len(entries),
            head_hash=head,
            findings=findings,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
    finally:
        store.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_verify.py -v`
Expected: 20 passed

- [ ] **Step 5: Commit**

```bash
git add src/consentml/verify.py tests/test_verify.py
git commit -m "feat: external head anchoring to detect wholesale log rewrites"
```

---

### Task 5: CLI — `consentml verify`

**Files:**
- Modify: `src/consentml/cli.py`
- Test: `tests/test_cli.py` (append)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cli.py`)

Note: `test_cli.py` already imports `json` and `main` at the top of the file, so
only `sqlite3` is new.

```python
import sqlite3


def test_cli_verify_clean_exits_zero(seeded_db, capsys):
    exit_code = main(["verify", "--db", str(seeded_db)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Audit log OK" in out
    assert "1 entries" in out


def test_cli_verify_tampered_exits_one(seeded_db, capsys):
    conn = sqlite3.connect(seeded_db)
    try:
        with conn:
            conn.execute("UPDATE audit_log SET payload = ? WHERE id = 1",
                         ("not json{",))
    finally:
        conn.close()
    exit_code = main(["verify", "--db", str(seeded_db)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "malformed_payload" in out


def test_cli_verify_json_output(seeded_db, capsys):
    exit_code = main(["verify", "--db", str(seeded_db), "--json"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True
    assert data["findings"] == []
    assert len(data["head_hash"]) == 64


def test_cli_verify_expected_head_mismatch_exits_one(seeded_db, capsys):
    exit_code = main(
        ["verify", "--db", str(seeded_db), "--expected-head", "f" * 64]
    )
    assert exit_code == 1
    assert "head_mismatch" in capsys.readouterr().out


def test_cli_revoke_still_exits_zero(seeded_db, capsys):
    assert main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db)]) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: the 5 new tests FAIL with `SystemExit: 2` — argparse rejects the unknown `verify` subcommand; the 4 existing tests still pass.

- [ ] **Step 3: Update `src/consentml/cli.py`**

Change the import line at the top of the file from:

```python
from consentml.revoke import revoke
```

to:

```python
from consentml.revoke import revoke
from consentml.verify import verify_audit_log
```

Add this function immediately after `_print_summary`:

```python
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
```

Register the subcommand by inserting this immediately before the `args = parser.parse_args(argv)` line:

```python
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
```

Replace everything from `args = parser.parse_args(argv)` to the end of `main` with:

```python
    args = parser.parse_args(argv)

    if args.command == "verify":
        report = verify_audit_log(
            db_path=args.db, expected_head=args.expected_head
        )
        if args.as_json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            _print_verify_summary(report)
        return 0 if report.ok else 1

    report = revoke(
        subject_id=args.subject_id, db_path=args.db, dry_run=args.dry_run
    )
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_summary(report)
    return 0
```

- [ ] **Step 4: Run tests and the CLI by hand**

```bash
.venv/bin/pytest tests/test_cli.py -v
.venv/bin/consentml verify --help
```

Expected: 9 passed; help text prints usage for `verify` including `--expected-head`.

- [ ] **Step 5: Commit**

```bash
git add src/consentml/cli.py tests/test_cli.py
git commit -m "feat: consentml verify CLI with exit-1 on tamper"
```

---

### Task 6: Public API exports, README, and coverage gate

**Files:**
- Modify: `src/consentml/__init__.py`
- Modify: `README.md`
- Test: `tests/test_verify.py` (append)

- [ ] **Step 1: Write the failing test** (append to `tests/test_verify.py`)

```python
def test_public_api_exports_verify():
    import consentml

    assert consentml.verify_audit_log is verify_audit_log
    assert consentml.VerificationReport is VerificationReport
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_verify.py::test_public_api_exports_verify -v`
Expected: FAIL with `AttributeError: module 'consentml' has no attribute 'verify_audit_log'`

- [ ] **Step 3: Update `src/consentml/__init__.py`**

```python
"""ConsentML: training-data lineage and consent-revocation reporting."""

from consentml.revoke import AffectedModel, AffectedModelsReport, revoke
from consentml.track import ConsentMLError, track
from consentml.verify import (
    VerificationFinding,
    VerificationReport,
    verify_audit_log,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "track",
    "revoke",
    "verify_audit_log",
    "AffectedModel",
    "AffectedModelsReport",
    "VerificationFinding",
    "VerificationReport",
    "ConsentMLError",
    "__version__",
]
```

- [ ] **Step 4: Update `README.md`**

Replace the whole file with:

```markdown
# ConsentML

Data-lineage tracking and consent-revocation reporting for production ML
pipelines. Add one decorator to your training function; when a user revokes
consent, ConsentML tells you which deployed models were trained on their data
and produces a tamper-evident audit trail.

## Verifying the audit trail

```bash
consentml verify --db lineage.db
```

Verification checks that every audit entry hashes to its recorded value, that
the chain links correctly, and that the log still agrees with the live tables —
catching a `subject_index` row deleted to hide that someone was in a training
set. It exits non-zero on any finding, so it can gate CI.

A hash chain cannot by itself detect an attacker who rewrites the entire log
from genesis. Record the reported `head_hash` somewhere outside the database
and pass it back with `--expected-head` to detect that too.

Status: pre-release (v0 in development). MIT license.
```

- [ ] **Step 5: Run the full suite with coverage**

Run: `.venv/bin/pytest --cov=consentml --cov-report=term-missing`
Expected: 70 passed, total coverage 100%. If a line is uncovered, add a test for it before committing rather than lowering the bar.

- [ ] **Step 6: Commit**

```bash
git add src/consentml/__init__.py README.md tests/test_verify.py
git commit -m "feat: export verification API; document consentml verify"
```

---

### Task 7: Merge

- [ ] **Step 1: Verify the branch is green from a clean state**

```bash
.venv/bin/pytest --cov=consentml --cov-report=term-missing
```

Expected: 70 passed, 100% coverage.

- [ ] **Step 2: Merge to main**

```bash
git checkout main
git merge --no-ff v0-week7-verify -m "Merge v0-week7-verify: audit-log verification and consentml verify CLI"
```
