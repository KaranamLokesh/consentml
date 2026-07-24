# ConsentML v0 Week-6 Revocation API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `revoke()` API that, given a subject identifier, reports every model trained on that subject's data with a remediation recommendation, records the revocation in the hash-chained audit log, and is callable from a `consentml revoke` CLI.

**Architecture:** `revoke()` hashes the incoming subject ID, queries the existing `subject_index` (matching both hashed and raw stored values so it works regardless of the `hash_subject_ids` setting at training time), groups affected runs by model, applies a recommendation heuristic, and appends a `revocation` audit event. The report is a dataclass with a `to_dict()` for JSON output. The CLI is a thin argparse wrapper over `revoke()`.

**Recommendation heuristic (v0, locked):** per affected model name — `retrain` if the subject appears in that model's *latest* training run (the deployed model presumably contains their data); `review` if the subject appears only in older runs (the current model may already exclude them — the operator verifies which artifact is deployed). `retire` is a valid operator decision but is never auto-recommended in v0.

**Privacy rule:** the audit log payload for a revocation contains only the hashed `subject_key`, never the raw subject ID.

**Tech Stack:** Same as Week 5 — Python ≥3.10, stdlib sqlite3/argparse/dataclasses, pytest. No new dependencies.

**File structure:**

```
src/consentml/
├── __init__.py          # modify: export revoke, AffectedModelsReport
├── store.py             # modify: _RUN_COLS, latest_run_for_model, record_revocation,
│                        #         _append_audit_entry returns row id
├── revoke.py            # new: AffectedModel, AffectedModelsReport, revoke()
└── cli.py               # new: main(argv) → `consentml revoke ...`
tests/
├── test_store.py        # modify: tests for new store methods
├── test_revoke.py       # new
├── test_integration.py  # new: @track → revoke() end-to-end with sklearn
└── test_cli.py          # new
pyproject.toml           # modify: [project.scripts] consentml = "consentml.cli:main"
```

**Conventions:** all commands run from the repo root with the venv: `.venv/bin/pytest ...`. Work happens on branch `v0-week6-revoke`.

---

### Task 1: Store support — latest run per model, revocation events, audit entry IDs

**Files:**
- Modify: `src/consentml/store.py`
- Test: `tests/test_store.py` (append)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_store.py`; note `_record_sample_run` gains a `started_at` parameter in this task — update the helper as shown)

Replace the existing `_record_sample_run` helper with:

```python
def _record_sample_run(
    store,
    model_name="churn_v3",
    subject_hashes=("h1", "h2"),
    started_at="2026-07-21T00:00:00+00:00",
):
    return store.record_training_run(
        model_name=model_name,
        model_hash="deadbeef",
        data_source="postgres://prod/customers",
        subject_id_col="email",
        subject_ids_hashed=True,
        subject_id_values=list(subject_hashes),
        started_at=started_at,
        finished_at="2026-07-21T00:01:00+00:00",
    )
```

Append the new tests:

```python
def test_latest_run_for_model_picks_latest_started_at(store):
    _record_sample_run(store, started_at="2026-07-01T00:00:00+00:00")
    newest = _record_sample_run(store, started_at="2026-07-15T00:00:00+00:00")
    latest = store.latest_run_for_model("churn_v3")
    assert latest["run_id"] == newest


def test_latest_run_for_unknown_model_is_none(store):
    assert store.latest_run_for_model("nope") is None


def test_record_revocation_appends_audit_entry_and_returns_id(store):
    entry_id = store.record_revocation(
        subject_key="abc123",
        n_affected_runs=2,
        recommended_actions=[{"model_name": "churn_v3", "action": "retrain"}],
    )
    entries = store.audit_entries()
    assert len(entries) == 1
    assert entries[0]["id"] == entry_id
    assert entries[0]["event_type"] == "revocation"
    payload = json.loads(entries[0]["payload"])
    assert payload["subject_key"] == "abc123"
    assert payload["n_affected_runs"] == 2
    assert payload["recommended_actions"] == [
        {"model_name": "churn_v3", "action": "retrain"}
    ]


def test_revocation_extends_hash_chain(store):
    _record_sample_run(store)
    store.record_revocation(subject_key="k", n_affected_runs=0, recommended_actions=[])
    first, second = store.audit_entries()
    assert second["prev_hash"] == first["entry_hash"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_store.py -v`
Expected: 4 new tests FAIL with `AttributeError` (no `latest_run_for_model` / `record_revocation`); prior tests still pass.

- [ ] **Step 3: Implement in `src/consentml/store.py`**

Add a module-level column list after `GENESIS_HASH` and use it in both query methods:

```python
_RUN_COLS = [
    "run_id", "model_name", "model_hash", "data_source",
    "subject_id_col", "subject_ids_hashed", "n_subjects",
    "started_at", "finished_at",
]
```

In `runs_for_subject_value`, delete the local `cols = [...]` list and use `_RUN_COLS` in the `dict(zip(...))`.

Add the two public methods to `LineageStore`:

```python
    def latest_run_for_model(self, model_name) -> dict | None:
        """The most recent training run (by started_at) for a model name."""
        row = self._conn.execute(
            f"SELECT {', '.join(_RUN_COLS)} FROM training_runs "
            "WHERE model_name = ? ORDER BY started_at DESC LIMIT 1",
            (model_name,),
        ).fetchone()
        return dict(zip(_RUN_COLS, row)) if row else None

    def record_revocation(self, *, subject_key, n_affected_runs, recommended_actions) -> int:
        """Append a revocation event to the audit log. Returns the entry id.

        The payload carries only the hashed subject key, never a raw ID."""
        with self._conn:
            return self._append_audit_entry(
                event_type="revocation",
                payload=json.dumps(
                    {
                        "subject_key": subject_key,
                        "n_affected_runs": n_affected_runs,
                        "recommended_actions": recommended_actions,
                    },
                    sort_keys=True,
                ),
            )
```

Change the end of `_append_audit_entry` to return the new row's id:

```python
        cursor = self._conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, payload, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp, event_type, payload, prev_hash, entry_hash),
        )
        return cursor.lastrowid
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_store.py -v`
Expected: 15 passed

- [ ] **Step 5: Commit**

```bash
git add src/consentml/store.py tests/test_store.py
git commit -m "feat: store support for revocation events and latest-run lookup"
```

---

### Task 2: revoke() and AffectedModelsReport

**Files:**
- Create: `src/consentml/revoke.py`
- Test: `tests/test_revoke.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_revoke.py
import json

import pytest

from consentml.hashing import hash_subject_id
from consentml.revoke import AffectedModelsReport, revoke
from consentml.store import LineageStore


@pytest.fixture
def db(tmp_path):
    return tmp_path / "lineage.db"


def _seed_run(db, model_name, subjects, started_at, hashed=True):
    store = LineageStore(db_path=db)
    try:
        values = [hash_subject_id(s) if hashed else s for s in subjects]
        return store.record_training_run(
            model_name=model_name,
            model_hash="beef",
            data_source="postgres://prod/customers",
            subject_id_col="email",
            subject_ids_hashed=hashed,
            subject_id_values=values,
            started_at=started_at,
            finished_at=started_at,
        )
    finally:
        store.close()


def test_revoke_reports_affected_model_with_retrain(db):
    run_id = _seed_run(db, "churn_v3", ["a@x.com"], "2026-07-01T00:00:00+00:00")
    report = revoke(subject_id="a@x.com", db_path=db)
    assert isinstance(report, AffectedModelsReport)
    assert [m.run_id for m in report.affected_models] == [run_id]
    assert report.affected_models[0].recommendation == "retrain"
    assert report.recommended_actions == [
        {"model_name": "churn_v3", "action": "retrain"}
    ]


def test_revoke_recommends_review_when_subject_only_in_older_run(db):
    _seed_run(db, "churn_v3", ["a@x.com"], "2026-07-01T00:00:00+00:00")
    _seed_run(db, "churn_v3", ["b@x.com"], "2026-07-15T00:00:00+00:00")
    report = revoke(subject_id="a@x.com", db_path=db)
    assert len(report.affected_models) == 1
    assert report.affected_models[0].recommendation == "review"


def test_revoke_unknown_subject_still_records_event(db):
    report = revoke(subject_id="ghost@x.com", db_path=db)
    assert report.affected_models == []
    assert report.recommended_actions == []
    store = LineageStore(db_path=db)
    try:
        entries = store.audit_entries()
        assert len(entries) == 1
        assert entries[0]["id"] == report.audit_log_entry_id
        payload = json.loads(entries[0]["payload"])
        assert payload["n_affected_runs"] == 0
    finally:
        store.close()


def test_revoke_matches_unhashed_stores(db):
    _seed_run(db, "m", ["a@x.com"], "2026-07-01T00:00:00+00:00", hashed=False)
    report = revoke(subject_id="a@x.com", db_path=db)
    assert len(report.affected_models) == 1


def test_revoke_audit_payload_has_hash_not_raw_id(db):
    _seed_run(db, "m", ["a@x.com"], "2026-07-01T00:00:00+00:00")
    report = revoke(subject_id="a@x.com", db_path=db)
    assert report.subject_key == hash_subject_id("a@x.com")
    store = LineageStore(db_path=db)
    try:
        payload = store.audit_entries()[-1]["payload"]
    finally:
        store.close()
    assert "a@x.com" not in payload
    assert hash_subject_id("a@x.com") in payload


def test_revoke_dry_run_writes_nothing(db):
    _seed_run(db, "m", ["a@x.com"], "2026-07-01T00:00:00+00:00")
    report = revoke(subject_id="a@x.com", db_path=db, dry_run=True)
    assert report.audit_log_entry_id is None
    store = LineageStore(db_path=db)
    try:
        assert all(e["event_type"] != "revocation" for e in store.audit_entries())
    finally:
        store.close()


def test_report_to_dict_round_trips_through_json(db):
    _seed_run(db, "m", ["a@x.com"], "2026-07-01T00:00:00+00:00")
    report = revoke(subject_id="a@x.com", db_path=db)
    data = json.loads(json.dumps(report.to_dict()))
    assert data["affected_models"][0]["model_name"] == "m"
    assert data["audit_log_entry_id"] == report.audit_log_entry_id
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_revoke.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'consentml.revoke'`

- [ ] **Step 3: Write `src/consentml/revoke.py`**

```python
"""The revoke() API: consent-revocation reporting.

revoke() never modifies training data or models. It reports which models a
subject's data reached and records that the revocation request was processed.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


@dataclass
class AffectedModel:
    run_id: str
    model_name: str
    model_hash: str
    data_source: str
    started_at: str
    finished_at: str
    recommendation: str


@dataclass
class AffectedModelsReport:
    subject_key: str
    generated_at: str
    affected_models: list
    recommended_actions: list
    audit_log_entry_id: int | None

    def to_dict(self) -> dict:
        return {
            "subject_key": self.subject_key,
            "generated_at": self.generated_at,
            "affected_models": [asdict(m) for m in self.affected_models],
            "recommended_actions": self.recommended_actions,
            "audit_log_entry_id": self.audit_log_entry_id,
        }


def revoke(*, subject_id, db_path=None, dry_run=False) -> AffectedModelsReport:
    """Report every model trained on this subject's data.

    Matches both hashed and raw stored subject values, so it works whether
    training used hash_subject_ids=True or False. Unless dry_run, appends a
    revocation event to the audit log (payload holds the hashed key only).
    """
    subject_key = hash_subject_id(subject_id)
    store = LineageStore(db_path=db_path)
    try:
        runs = {
            r["run_id"]: r
            for r in (
                store.runs_for_subject_value(subject_key)
                + store.runs_for_subject_value(str(subject_id))
            )
        }

        actions = {}
        for run in runs.values():
            name = run["model_name"]
            if name not in actions:
                latest = store.latest_run_for_model(name)
                actions[name] = (
                    "retrain" if latest and latest["run_id"] in runs else "review"
                )

        affected = sorted(
            (
                AffectedModel(
                    run_id=r["run_id"],
                    model_name=r["model_name"],
                    model_hash=r["model_hash"],
                    data_source=r["data_source"],
                    started_at=r["started_at"],
                    finished_at=r["finished_at"],
                    recommendation=actions[r["model_name"]],
                )
                for r in runs.values()
            ),
            key=lambda m: (m.model_name, m.started_at),
        )
        recommended_actions = [
            {"model_name": name, "action": action}
            for name, action in sorted(actions.items())
        ]

        entry_id = None
        if not dry_run:
            entry_id = store.record_revocation(
                subject_key=subject_key,
                n_affected_runs=len(affected),
                recommended_actions=recommended_actions,
            )

        return AffectedModelsReport(
            subject_key=subject_key,
            generated_at=datetime.now(timezone.utc).isoformat(),
            affected_models=affected,
            recommended_actions=recommended_actions,
            audit_log_entry_id=entry_id,
        )
    finally:
        store.close()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_revoke.py -v`
Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/consentml/revoke.py tests/test_revoke.py
git commit -m "feat: revoke() API with AffectedModelsReport and retrain/review heuristic"
```

---

### Task 3: End-to-end integration test (@track → revoke with sklearn)

**Files:**
- Test: `tests/test_integration.py`

- [ ] **Step 1: Write the test** (this task adds no implementation code; it proves the Week-5 and Week-6 pieces compose)

```python
# tests/test_integration.py
import hashlib

import pandas as pd
from sklearn.linear_model import LogisticRegression

from consentml import revoke, track
from consentml.store import GENESIS_HASH, LineageStore


def test_track_then_revoke_end_to_end(tmp_path):
    db = tmp_path / "lineage.db"
    df = pd.DataFrame(
        {
            "email": ["a@x.com", "b@x.com", "c@x.com"],
            "f1": [0.1, 0.9, 0.5],
            "label": [0, 1, 1],
        }
    )

    def fit(df):
        model = LogisticRegression()
        model.fit(df[["f1"]], df["label"])
        return model

    track(
        data_source="postgres://prod/customers",
        subject_id_col="email",
        model_name="churn",
        db_path=db,
    )(fit)(df)
    track(
        data_source="postgres://prod/customers",
        subject_id_col="email",
        model_name="upsell",
        db_path=db,
    )(fit)(df)

    report = revoke(subject_id="a@x.com", db_path=db)

    assert [m.model_name for m in report.affected_models] == ["churn", "upsell"]
    assert {a["action"] for a in report.recommended_actions} == {"retrain"}

    # Audit log: 2 training events + 1 revocation, chain intact end-to-end.
    store = LineageStore(db_path=db)
    try:
        entries = store.audit_entries()
    finally:
        store.close()
    assert [e["event_type"] for e in entries] == [
        "training_run",
        "training_run",
        "revocation",
    ]
    prev = GENESIS_HASH
    for e in entries:
        assert e["prev_hash"] == prev
        recomputed = hashlib.sha256(
            (e["prev_hash"] + e["timestamp"] + e["event_type"] + e["payload"]).encode()
        ).hexdigest()
        assert e["entry_hash"] == recomputed
        prev = e["entry_hash"]
```

- [ ] **Step 2: Run the test — it should pass immediately**

Run: `.venv/bin/pytest tests/test_integration.py -v`
Expected: 1 passed. If it fails, the composition of track/revoke is broken — stop and fix before proceeding.

- [ ] **Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: end-to-end @track → revoke() integration with sklearn"
```

---

### Task 4: CLI — `consentml revoke`

**Files:**
- Create: `src/consentml/cli.py`
- Modify: `pyproject.toml` (add `[project.scripts]`)
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli.py
import json

import pytest

from consentml.cli import main
from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


@pytest.fixture
def seeded_db(tmp_path):
    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            data_source="postgres://prod/customers",
            subject_id_col="email",
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    return db


def test_cli_revoke_json_output(seeded_db, capsys):
    exit_code = main(
        ["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db), "--json"]
    )
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["affected_models"][0]["model_name"] == "churn_v3"
    assert data["recommended_actions"] == [
        {"model_name": "churn_v3", "action": "retrain"}
    ]


def test_cli_revoke_human_output(seeded_db, capsys):
    main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db)])
    out = capsys.readouterr().out
    assert "churn_v3" in out
    assert "retrain" in out
    assert "1 affected model" in out


def test_cli_dry_run_does_not_record(seeded_db, capsys):
    main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db), "--dry-run"])
    store = LineageStore(db_path=seeded_db)
    try:
        assert all(
            e["event_type"] != "revocation" for e in store.audit_entries()
        )
    finally:
        store.close()


def test_cli_no_affected_models(tmp_path, capsys):
    db = tmp_path / "empty.db"
    exit_code = main(["revoke", "--subject-id", "x@x.com", "--db", str(db)])
    assert exit_code == 0
    assert "0 affected models" in capsys.readouterr().out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'consentml.cli'`

- [ ] **Step 3: Write `src/consentml/cli.py`**

```python
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
```

- [ ] **Step 4: Add the console script to `pyproject.toml`** (after the `[project.optional-dependencies]` table)

```toml
[project.scripts]
consentml = "consentml.cli:main"
```

- [ ] **Step 5: Reinstall so the entry point registers, then run tests**

```bash
.venv/bin/pip install -q -e ".[dev]"
.venv/bin/pytest tests/test_cli.py -v
.venv/bin/consentml revoke --help
```

Expected: 4 passed; help text prints usage for `revoke`.

- [ ] **Step 6: Commit**

```bash
git add src/consentml/cli.py tests/test_cli.py pyproject.toml
git commit -m "feat: consentml revoke CLI"
```

---

### Task 5: Public API exports and coverage gate

**Files:**
- Modify: `src/consentml/__init__.py`
- Test: `tests/test_revoke.py` (append)

- [ ] **Step 1: Write the failing test** (append to `tests/test_revoke.py`)

```python
def test_public_api_exports_revoke():
    import consentml

    assert consentml.revoke is revoke
    assert consentml.AffectedModelsReport is AffectedModelsReport
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_revoke.py::test_public_api_exports_revoke -v`
Expected: FAIL with `AttributeError: module 'consentml' has no attribute 'revoke'`

- [ ] **Step 3: Update `src/consentml/__init__.py`**

```python
"""ConsentML: training-data lineage and consent-revocation reporting."""

from consentml.revoke import AffectedModel, AffectedModelsReport, revoke
from consentml.track import ConsentMLError, track

__version__ = "0.1.0.dev0"

__all__ = [
    "track",
    "revoke",
    "AffectedModel",
    "AffectedModelsReport",
    "ConsentMLError",
    "__version__",
]
```

- [ ] **Step 4: Run the full suite with coverage**

Run: `.venv/bin/pytest --cov=consentml --cov-report=term-missing`
Expected: all tests pass, total coverage ≥ 90%. If a line is uncovered, add a test for it before committing rather than lowering the bar.

- [ ] **Step 5: Commit**

```bash
git add src/consentml/__init__.py tests/test_revoke.py
git commit -m "feat: export revoke API; coverage gate"
```
