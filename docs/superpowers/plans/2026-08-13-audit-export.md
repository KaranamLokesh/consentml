# Audit Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `consentml export`, which produces a per-subject regulator dossier in HTML, JSON, or PDF from an existing lineage database, without writing to it.

**Architecture:** `export.py` assembles a `Dossier` dataclass by composing `verify_audit_log()`, `revoke(dry_run=True)`, and a subject-key filter over the audit log. `render.py` holds three pure functions that turn a `Dossier` into text or bytes. `cli.py` gains an `export` subcommand. The assembly/rendering seam means dossier contents are tested against data structures, never against rendered strings.

**Tech Stack:** Python 3.10+, stdlib only for core (`dataclasses`, `json`, `html`, `pathlib`), reportlab behind an optional `[pdf]` extra, pytest.

**Spec:** `docs/superpowers/specs/2026-07-27-audit-export-design.md`

## Global Constraints

- Python floor is **3.10** (`requires-python = ">=3.10"`). No `match`, no PEP 695 generics, no `itertools.batched`.
- Default-install runtime dependencies stay at **`pandas>=2.0`**. reportlab goes only in the `pdf` extra.
- **Export never writes to the database.** No `LineageStore` write method may be called on any code path reached from `build_dossier()`.
- Coverage gate is **100%** (`pytest --cov=consentml --cov-fail-under=100`). Every branch added needs a test.
- Exit codes follow `cli.py`'s existing contract: **0** clean, **1** problems found (including no database at the path), **2** the database could not be read or output could not be produced.
- `verify_audit_log()` must be called **before** `revoke()` in `build_dossier()`. Reversing this creates a database at a typoed path and emits a false-clean dossier.
- All database-derived text reaching HTML passes through `html.escape()`.
- Existing style: module docstrings explain *why*, comments explain non-obvious decisions. Match it.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/consentml/export.py` | **Create.** `Dossier` dataclass, `build_dossier()`. Assembly only, no rendering. |
| `src/consentml/render.py` | **Create.** `render_json()`, `render_html()`, `render_pdf()`. Presentation only, no database access. |
| `src/consentml/__init__.py` | **Modify.** Export `Dossier`, `build_dossier`, and the three renderers. |
| `src/consentml/cli.py` | **Modify.** Add the `export` subcommand, its argument parsing, and its exit-code branch. |
| `pyproject.toml` | **Modify.** Add the `pdf` extra; add reportlab to `dev`. |
| `tests/test_export.py` | **Create.** Assembly, ordering guard, read-only proof, legacy databases. |
| `tests/test_render.py` | **Create.** Three renderers, escaping, missing-extra path. |
| `tests/test_cli.py` | **Modify.** `export` subcommand: formats, destinations, exit codes. |
| `examples/consentml_demo.ipynb` | **Modify.** An export section at the end of the narrative. |
| `README.md` | **Modify.** Document the command and the extra. |

---

## Task 1: The Dossier model and assembly

**Files:**
- Create: `src/consentml/export.py`
- Create: `tests/test_export.py`
- Modify: `src/consentml/__init__.py`

**Interfaces:**
- Consumes: `revoke(subject_id=..., db_path=..., dry_run=True) -> AffectedModelsReport` from `consentml.revoke`; `verify_audit_log(db_path=...) -> VerificationReport` from `consentml.verify`; `hash_subject_id(subject_id) -> str` from `consentml.hashing`; `LineageStore(db_path=...).audit_entries() -> list[dict]` from `consentml.store`.
- Produces: `Dossier` dataclass with fields `subject_id`, `subject_key`, `generated_at`, `affected_models`, `recommended_actions`, `revocation_events`, `verification`, `head_hash`, `n_legacy_runs`, `consentml_version`, plus `to_dict() -> dict` and a `database_found: bool` flag. `build_dossier(*, subject_id, db_path=None) -> Dossier`. Tasks 2, 3 and 4 all consume these exact names.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_export.py`:

```python
"""build_dossier assembles the regulator dossier from three reads.

The ordering test below is the important one: build_dossier composes
revoke(), and revoke() constructs a LineageStore, which provisions a schema
onto any path that lacks one. Verifying first is what stops a typoed --db
from producing a clean-looking dossier for a database that never existed.
"""

import hashlib

import pytest

from consentml.export import build_dossier
from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


@pytest.fixture
def seeded_db(tmp_path):
    """Two models sharing one subject; churn_v3 also has a later run."""
    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "warehouse://customers"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com"), hash_subject_id("b@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
        store.record_training_run(
            model_name="upsell",
            model_hash="cafe",
            provenance={"kind": "dataframe", "label": "warehouse://customers"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-02T00:00:00+00:00",
            finished_at="2026-07-02T00:01:00+00:00",
        )
    finally:
        store.close()
    return db


def test_dossier_reports_both_affected_models(seeded_db):
    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert [m.model_name for m in dossier.affected_models] == ["churn_v3", "upsell"]
    assert dossier.recommended_actions == [
        {"model_name": "churn_v3", "action": "retrain"},
        {"model_name": "upsell", "action": "retrain"},
    ]


def test_dossier_carries_subject_id_and_key(seeded_db):
    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert dossier.subject_id == "a@x.com"
    assert dossier.subject_key == hash_subject_id("a@x.com")


def test_dossier_on_a_clean_database_verifies_ok(seeded_db):
    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert dossier.verification.ok is True
    assert dossier.head_hash == dossier.verification.head_hash
    assert dossier.database_found is True


def test_a_subject_with_no_models_still_gets_a_dossier(seeded_db):
    dossier = build_dossier(subject_id="nobody@x.com", db_path=seeded_db)
    assert dossier.affected_models == []
    assert dossier.verification.ok is True
    assert dossier.database_found is True


def test_dossier_includes_this_subjects_revocation_events(seeded_db):
    from consentml.revoke import revoke

    revoke(subject_id="a@x.com", db_path=seeded_db)
    revoke(subject_id="b@x.com", db_path=seeded_db)

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert len(dossier.revocation_events) == 1
    assert dossier.revocation_events[0]["subject_key"] == hash_subject_id("a@x.com")


def test_build_dossier_creates_nothing_at_a_missing_path(tmp_path):
    """The false-clean guard.

    If build_dossier ever calls revoke() before verifying, LineageStore
    provisions an empty database here, finds no models, verifies the empty
    log as clean, and the dossier asserts the opposite of the truth.
    """
    missing = tmp_path / "nope.db"

    dossier = build_dossier(subject_id="a@x.com", db_path=missing)

    assert not missing.exists()
    assert dossier.database_found is False
    assert dossier.verification.ok is False
    assert [f.code for f in dossier.verification.findings] == ["missing_database"]
    assert dossier.affected_models == []


def test_build_dossier_reports_a_foreign_database_without_reading_it(tmp_path):
    foreign = tmp_path / "foreign.db"
    foreign.write_bytes(b"not a sqlite file at all")

    dossier = build_dossier(subject_id="a@x.com", db_path=foreign)

    assert dossier.database_found is False
    assert [f.code for f in dossier.verification.findings] == ["not_a_lineage_database"]


def test_export_does_not_modify_the_database(seeded_db):
    """Read-only is proven by bytes, not by trusting dry_run=True."""
    before = hashlib.sha256(seeded_db.read_bytes()).hexdigest()
    build_dossier(subject_id="a@x.com", db_path=seeded_db)
    after = hashlib.sha256(seeded_db.read_bytes()).hexdigest()
    assert before == after


def test_tampered_database_surfaces_the_finding(seeded_db):
    import sqlite3

    conn = sqlite3.connect(seeded_db)
    conn.execute("UPDATE audit_log SET payload = replace(payload, 'churn_v3', 'x')")
    conn.commit()
    conn.close()

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    assert dossier.verification.ok is False
    assert "entry_hash_mismatch" in {f.code for f in dossier.verification.findings}
    # Still produced a dossier -- refusing would leave the operator nothing.
    assert dossier.affected_models != []


def test_legacy_v0_database_reports_unverified_runs(legacy_db):
    dossier = build_dossier(subject_id="h1", db_path=legacy_db)
    assert dossier.n_legacy_runs == 2
    assert dossier.database_found is True


def test_legacy_v1_database_reports_unverified_runs(v1_db):
    dossier = build_dossier(subject_id="h1", db_path=v1_db)
    assert dossier.n_legacy_runs == 2


def test_malformed_revocation_payload_is_skipped_not_raised(seeded_db, append_entry):
    append_entry(seeded_db, "revocation", "{not json at all")

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)

    assert dossier.revocation_events == []
    # The broken entry is not silently ignored -- verification reports it.
    assert "malformed_payload" in {f.code for f in dossier.verification.findings}


def test_dossier_to_dict_is_json_serializable(seeded_db):
    import json

    dossier = build_dossier(subject_id="a@x.com", db_path=seeded_db)
    data = json.loads(json.dumps(dossier.to_dict()))
    assert data["subject_id"] == "a@x.com"
    assert data["verification"]["ok"] is True
    assert data["consentml_version"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_export.py -v`
Expected: every test FAILS with `ModuleNotFoundError: No module named 'consentml.export'`

- [ ] **Step 3: Implement `export.py`**

Create `src/consentml/export.py`:

```python
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
```

- [ ] **Step 4: Export the new names**

Modify `src/consentml/__init__.py` — add the import and the `__all__` entries:

```python
from consentml.export import Dossier, build_dossier
```

Add `"Dossier"` and `"build_dossier"` to `__all__`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_export.py -v`
Expected: all PASS

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/python -m pytest --ignore=tests/test_sources_postgres.py`
Expected: 177 existing + the new tests, all passing

- [ ] **Step 7: Commit**

```bash
git add src/consentml/export.py src/consentml/__init__.py tests/test_export.py
git commit -m "feat: build_dossier assembles the per-subject regulator dossier"
```

---

## Task 2: JSON and HTML renderers

**Files:**
- Create: `src/consentml/render.py`
- Create: `tests/test_render.py`
- Modify: `src/consentml/__init__.py`

**Interfaces:**
- Consumes: `Dossier` and `build_dossier()` from Task 1, with the exact field names listed there.
- Produces: `render_json(dossier) -> str` and `render_html(dossier) -> str`. Task 3 adds `render_pdf` to this same module; Task 4's CLI dispatches on all three.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_render.py`:

```python
"""Renderers turn a Dossier into a document. No database access here."""

import json

import pytest

from consentml.export import build_dossier
from consentml.hashing import hash_subject_id
from consentml.render import render_html, render_json
from consentml.store import LineageStore


@pytest.fixture
def dossier(tmp_path):
    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "warehouse://customers"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    return build_dossier(subject_id="a@x.com", db_path=db)


def test_render_json_round_trips_to_the_dossier_dict(dossier):
    assert json.loads(render_json(dossier)) == dossier.to_dict()


def test_render_html_names_the_subject_and_the_models(dossier):
    html = render_html(dossier)
    assert "a@x.com" in html
    assert "churn_v3" in html
    assert dossier.head_hash in html
    assert dossier.subject_key in html


def test_render_html_states_the_verification_verdict(dossier):
    assert "VERIFIED" in render_html(dossier)


def test_render_html_leads_with_failure_when_verification_failed(tmp_path):
    import sqlite3

    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "w://c"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    conn = sqlite3.connect(db)
    conn.execute("UPDATE audit_log SET payload = replace(payload, 'churn', 'x')")
    conn.commit()
    conn.close()

    html = render_html(build_dossier(subject_id="a@x.com", db_path=db))
    assert "FAILED" in html
    assert "entry_hash_mismatch" in html


def test_render_html_escapes_hostile_model_names(tmp_path):
    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="<script>alert(1)</script>",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "w://c"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()

    html = render_html(build_dossier(subject_id="a@x.com", db_path=db))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_html_escapes_the_subject_id(tmp_path):
    db = tmp_path / "lineage.db"
    LineageStore(db_path=db).close()
    dossier = build_dossier(subject_id="<img src=x onerror=1>", db_path=db)
    html = render_html(dossier)
    assert "<img src=x onerror=1>" not in html
    assert "&lt;img" in html


def test_render_html_lists_recorded_revocation_events(tmp_path):
    """The events table branch. The fixture above has no revocation recorded,
    so without this the 'no events' branch is the only one exercised."""
    from consentml.revoke import revoke

    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "w://c"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    revoke(subject_id="a@x.com", db_path=db)

    html = render_html(build_dossier(subject_id="a@x.com", db_path=db))
    assert "Recorded at" in html
    assert "No revocation event" not in html


def test_render_html_says_when_no_revocation_was_recorded(dossier):
    assert "No revocation event has been recorded" in render_html(dossier)


def test_render_html_says_so_when_no_models_were_affected(tmp_path):
    db = tmp_path / "lineage.db"
    LineageStore(db_path=db).close()
    html = render_html(build_dossier(subject_id="nobody@x.com", db_path=db))
    assert "No models were trained" in html


def test_render_html_warns_about_unverified_legacy_runs(legacy_db):
    html = render_html(build_dossier(subject_id="h1", db_path=legacy_db))
    assert "predate provenance hashing" in html


def test_render_html_shows_unreadable_provenance_visibly(tmp_path):
    import sqlite3

    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "w://c"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    conn = sqlite3.connect(db)
    conn.execute("UPDATE training_runs SET provenance = X'ff'")
    conn.commit()
    conn.close()

    html = render_html(build_dossier(subject_id="a@x.com", db_path=db))
    assert "unreadable" in html


def test_render_html_reports_a_missing_database(tmp_path):
    html = render_html(build_dossier(subject_id="a@x.com", db_path=tmp_path / "no.db"))
    assert "No lineage database" in html


def test_render_html_dumps_provenance_that_has_no_label(tmp_path):
    """PostgresSource provenance has no 'label' key.

    It records the query, its digest and the referenced tables instead, so
    the renderer falls back to dumping the whole record. Built here by
    recording the provenance shape directly rather than by standing up a
    Postgres, so this covers the fallback without a live database.
    """
    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={
                "kind": "postgres",
                "host": "prod",
                "dbname": "customers",
                "query": "SELECT email FROM customers",
                "query_sha256": "abc123",
                "referenced_tables": ["public.customers"],
                "referenced_tables_source": "explain",
                "n_rows": 1,
            },
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()

    html = render_html(build_dossier(subject_id="a@x.com", db_path=db))
    assert "public.customers" in html
    assert "SELECT email FROM customers" in html
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_render.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'consentml.render'`

- [ ] **Step 3: Implement the JSON and HTML renderers**

Create `src/consentml/render.py`:

```python
"""Dossier renderers.

Three functions, each taking a Dossier and returning a document. They read
nothing from the database -- everything they need was assembled by
build_dossier() -- which is what lets the dossier's contents be tested
against data structures rather than against rendered strings.

Every database-derived value passes through html.escape() in the HTML
renderer. Model names and provenance labels are arbitrary text an operator's
own pipeline supplied, this document is emailed to third parties, and an
artifact whose entire value is being trustworthy cannot also be a script
injection vector.
"""

import html
import json

_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 2rem auto; max-width: 50rem; line-height: 1.5; color: #111; }
h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
h2 { font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #ddd;
     padding-bottom: 0.25rem; }
table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee;
         vertical-align: top; font-size: 0.9rem; }
th { background: #fafafa; }
.verdict-ok { background: #e8f5e9; border-left: 4px solid #2e7d32;
              padding: 0.75rem 1rem; }
.verdict-fail { background: #ffebee; border-left: 4px solid #c62828;
                padding: 0.75rem 1rem; }
.caveat { background: #fff8e1; border-left: 4px solid #f9a825;
          padding: 0.75rem 1rem; margin-top: 1rem; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 0.8rem; word-break: break-all; }
footer { margin-top: 3rem; color: #666; font-size: 0.8rem; }
"""


def render_json(dossier) -> str:
    """The dossier as indented JSON."""
    return json.dumps(dossier.to_dict(), indent=2, sort_keys=True)


def _e(value) -> str:
    """Escape any value for HTML text content."""
    return html.escape(str(value))


def _provenance_cell(provenance) -> str:
    """Human-readable provenance.

    Always a dict: revoke()._parse_provenance() normalizes every stored form
    into one, including {"kind": "unreadable"} for provenance that is not
    readable text (tampered, or a BLOB). That case must render as a visible
    statement rather than an empty cell, which would read as "nothing to see
    here" for exactly the condition an auditor needs to notice.

    DataFrameSource provenance carries a "label"; PostgresSource provenance
    does not -- it carries the query, its digest, and the referenced tables --
    so the fallback dumps the whole record. Both shapes reach here in
    practice, which is why neither branch is dead.
    """
    if provenance.get("kind") == "unreadable":
        return "<em>unreadable — provenance is not readable text</em>"
    label = provenance.get("label")
    if label is not None:
        return _e(label)
    return _e(json.dumps(provenance, sort_keys=True))


def _verdict_block(dossier) -> str:
    if not dossier.database_found:
        detail = "; ".join(_e(f.detail) for f in dossier.verification.findings)
        return (
            '<div class="verdict-fail"><strong>No lineage database was '
            f"read.</strong><br>{detail}</div>"
        )
    if dossier.verification.ok:
        return (
            '<div class="verdict-ok"><strong>Audit log VERIFIED.</strong><br>'
            f"{dossier.verification.n_entries} entries; hash chain intact and "
            "consistent with the lineage tables.</div>"
        )
    rows = "".join(
        f"<li><code>{_e(f.code)}</code> — {_e(f.detail)}</li>"
        for f in dossier.verification.findings
    )
    return (
        '<div class="verdict-fail"><strong>Audit log FAILED '
        "verification.</strong><br>This log has been modified since it was "
        f"written. The findings below are unresolved.<ul>{rows}</ul></div>"
    )


def _models_section(dossier) -> str:
    if not dossier.affected_models:
        return (
            "<p>No models were trained on this data subject's data. No "
            "remediation is required.</p>"
        )
    rows = "".join(
        "<tr>"
        f"<td>{_e(m.model_name)}</td>"
        f"<td>{_provenance_cell(m.provenance)}</td>"
        f"<td>{_e(m.started_at)}</td>"
        f'<td class="mono">{_e(m.model_hash)}</td>'
        f"<td>{_e(m.recommendation)}</td>"
        "</tr>"
        for m in dossier.affected_models
    )
    return (
        "<table><thead><tr><th>Model</th><th>Training data</th>"
        "<th>Trained at</th><th>Model hash</th><th>Recommendation</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _events_section(dossier) -> str:
    if not dossier.revocation_events:
        return (
            "<p>No revocation event has been recorded for this subject. The "
            "request has not yet been processed through "
            "<code>consentml revoke</code>.</p>"
        )
    rows = "".join(
        "<tr>"
        f"<td>{_e(e['timestamp'])}</td>"
        f"<td>{_e(e['n_affected_runs'])}</td>"
        f'<td class="mono">{_e(e["entry_hash"])}</td>'
        "</tr>"
        for e in dossier.revocation_events
    )
    return (
        "<table><thead><tr><th>Recorded at</th><th>Affected runs</th>"
        f"<th>Audit entry hash</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _caveats(dossier) -> str:
    if not dossier.n_legacy_runs:
        return ""
    return (
        f'<div class="caveat"><strong>{dossier.n_legacy_runs} training '
        "run(s) predate provenance hashing.</strong> Their recorded training "
        "data source is not covered by the audit log's hash chain and was "
        "not verified. Run <code>consentml migrate</code> to bring the "
        "database onto the current schema.</div>"
    )


def render_html(dossier) -> str:
    """A self-contained HTML dossier. No external assets, prints to PDF."""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Consent revocation dossier — {_e(dossier.subject_id)}</title>
<style>{_CSS}</style></head><body>
<h1>Consent revocation dossier</h1>
<p>Response to the erasure request from
<strong>{_e(dossier.subject_id)}</strong></p>
<p class="mono">Subject key (SHA-256): {_e(dossier.subject_key)}</p>

<h2>1. Audit log integrity</h2>
{_verdict_block(dossier)}
<p class="mono">Head hash: {_e(dossier.head_hash)}</p>
<p>Record this head hash outside the database. It lets any third party
re-verify this log later, independently of the organization that produced
this document.</p>
{_caveats(dossier)}

<h2>2. Models trained on this subject's data</h2>
{_models_section(dossier)}

<h2>3. Recorded processing of this request</h2>
{_events_section(dossier)}

<footer>Generated {_e(dossier.generated_at)} by ConsentML
{_e(dossier.consentml_version)}. ConsentML is a lineage and reporting tool:
it identifies which models a data subject's data reached and records what the
operator decided. It does not modify models or delete data.</footer>
</body></html>
"""
```

- [ ] **Step 4: Export the renderers**

Modify `src/consentml/__init__.py`:

```python
from consentml.render import render_html, render_json
```

Add `"render_html"` and `"render_json"` to `__all__`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_render.py -v`
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add src/consentml/render.py src/consentml/__init__.py tests/test_render.py
git commit -m "feat: JSON and HTML dossier renderers"
```

---

## Task 3: The PDF renderer and its optional extra

**Files:**
- Modify: `src/consentml/render.py`
- Modify: `tests/test_render.py`
- Modify: `pyproject.toml`
- Modify: `src/consentml/__init__.py`

**Interfaces:**
- Consumes: `Dossier` from Task 1; the `_provenance_cell`-equivalent formatting is re-derived for PDF because reportlab takes plain strings, not HTML.
- Produces: `render_pdf(dossier) -> bytes`.

- [ ] **Step 1: Add the optional extra**

Modify `pyproject.toml` — add a `pdf` extra and add reportlab to `dev`:

```toml
[project.optional-dependencies]
postgres = ["psycopg[binary]>=3.1"]
pdf = ["reportlab>=4.0"]
dev = [
    "pytest>=8",
    "pytest-cov",
    "scikit-learn",
    # Used by tests/test_notebook.py to execute the demo notebook.
    "nbclient",
    "nbformat",
    "ipykernel",
    "psycopg[binary]>=3.1",
    # Exercises the --format pdf path; the extra itself is optional at runtime.
    "reportlab>=4.0",
]
```

Then install it:

```bash
.venv/bin/pip install -e ".[dev]"
```

- [ ] **Step 2: Write the failing tests**

Add to `tests/test_render.py`:

```python
def test_render_pdf_produces_a_pdf(dossier):
    from consentml.render import render_pdf

    data = render_pdf(dossier)
    assert data.startswith(b"%PDF")


def test_render_pdf_without_the_extra_names_the_install_command(dossier, monkeypatch):
    """The optional dependency is checked at call time, with a fix in the
    message -- an ImportError traceback mentioning 'reportlab' does not tell
    an operator what to type."""
    import builtins

    from consentml.errors import ConsentMLError
    from consentml.render import render_pdf

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("No module named 'reportlab'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ConsentMLError) as excinfo:
        render_pdf(dossier)
    assert "pip install consentml[pdf]" in str(excinfo.value)


def test_render_pdf_lists_recorded_revocation_events(tmp_path):
    from consentml.render import render_pdf
    from consentml.revoke import revoke

    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "w://c"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    revoke(subject_id="a@x.com", db_path=db)

    data = render_pdf(build_dossier(subject_id="a@x.com", db_path=db))
    assert data.startswith(b"%PDF")


def test_render_pdf_handles_a_dossier_with_no_models(tmp_path):
    from consentml.render import render_pdf

    db = tmp_path / "lineage.db"
    LineageStore(db_path=db).close()
    data = render_pdf(build_dossier(subject_id="nobody@x.com", db_path=db))
    assert data.startswith(b"%PDF")


def test_render_pdf_handles_a_failed_verification(tmp_path):
    from consentml.render import render_pdf

    data = render_pdf(build_dossier(subject_id="a@x.com", db_path=tmp_path / "no.db"))
    assert data.startswith(b"%PDF")


def test_render_pdf_handles_legacy_caveats(legacy_db):
    """A v0 database renders, and exercises the n_legacy_runs caveat branch.

    Legacy provenance is free text that _parse_provenance normalizes to
    {"kind": "legacy", "label": ...}, so this covers the label branch of
    _plain_provenance, not the unreadable one -- that has its own test below.
    """
    from consentml.render import render_pdf

    data = render_pdf(build_dossier(subject_id="h1", db_path=legacy_db))
    assert data.startswith(b"%PDF")


def test_render_pdf_handles_unreadable_provenance(tmp_path):
    import sqlite3

    from consentml.render import render_pdf

    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "w://c"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    conn = sqlite3.connect(db)
    conn.execute("UPDATE training_runs SET provenance = X'ff'")
    conn.commit()
    conn.close()

    data = render_pdf(build_dossier(subject_id="a@x.com", db_path=db))
    assert data.startswith(b"%PDF")


def test_render_pdf_dumps_provenance_that_has_no_label(tmp_path):
    """The PostgresSource provenance shape, which carries no 'label'."""
    from consentml.render import render_pdf

    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={
                "kind": "postgres",
                "host": "prod",
                "query": "SELECT email FROM customers",
                "referenced_tables": ["public.customers"],
                "n_rows": 1,
            },
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()

    data = render_pdf(build_dossier(subject_id="a@x.com", db_path=db))
    assert data.startswith(b"%PDF")
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_render.py -k pdf -v`
Expected: FAIL with `ImportError: cannot import name 'render_pdf'`

- [ ] **Step 4: Implement `render_pdf`**

Add to `src/consentml/render.py` — the import at the top:

```python
from consentml.errors import ConsentMLError
```

and this function at the end:

```python
def _plain_provenance(provenance) -> str:
    """Provenance as plain text, for the PDF renderer.

    Separate from _provenance_cell because reportlab paragraphs take a
    minimal markup dialect, not HTML -- reusing the HTML version would emit
    literal <em> tags into the document.
    """
    if provenance.get("kind") == "unreadable":
        return "unreadable - provenance is not readable text"
    label = provenance.get("label")
    if label is not None:
        return str(label)
    return json.dumps(provenance, sort_keys=True)


def render_pdf(dossier) -> bytes:
    """The dossier as a PDF. Requires the optional [pdf] extra.

    reportlab is imported here rather than at module scope so that importing
    consentml -- or rendering HTML -- never requires the extra. The
    ImportError is translated into a ConsentMLError naming the exact install
    command, because a raw traceback mentioning 'reportlab' does not tell an
    operator what to do about it.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ConsentMLError(
            "PDF output needs the optional 'pdf' extra: "
            "pip install consentml[pdf]"
        ) from exc

    import io

    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        title=f"Consent revocation dossier - {dossier.subject_id}",
        leftMargin=0.9 * inch,
        rightMargin=0.9 * inch,
    )

    story = [
        Paragraph("Consent revocation dossier", styles["Title"]),
        Paragraph(
            f"Response to the erasure request from "
            f"<b>{_e(dossier.subject_id)}</b>",
            body,
        ),
        Paragraph(f"Subject key (SHA-256): {_e(dossier.subject_key)}", body),
        Spacer(1, 0.25 * inch),
        Paragraph("1. Audit log integrity", styles["Heading2"]),
    ]

    if not dossier.database_found:
        story.append(
            Paragraph(
                "<b>No lineage database was read.</b> "
                + "; ".join(_e(f.detail) for f in dossier.verification.findings),
                body,
            )
        )
    elif dossier.verification.ok:
        story.append(
            Paragraph(
                f"<b>Audit log VERIFIED.</b> {dossier.verification.n_entries} "
                "entries; hash chain intact and consistent with the lineage "
                "tables.",
                body,
            )
        )
    else:
        story.append(
            Paragraph(
                "<b>Audit log FAILED verification.</b> This log has been "
                "modified since it was written.",
                body,
            )
        )
        for f in dossier.verification.findings:
            story.append(Paragraph(f"- {_e(f.code)}: {_e(f.detail)}", body))

    story.append(Paragraph(f"Head hash: {_e(dossier.head_hash)}", body))
    if dossier.n_legacy_runs:
        story.append(
            Paragraph(
                f"<b>Caveat:</b> {dossier.n_legacy_runs} training run(s) "
                "predate provenance hashing. Their training data source is "
                "not covered by the hash chain and was not verified.",
                body,
            )
        )

    story += [
        Spacer(1, 0.2 * inch),
        Paragraph("2. Models trained on this subject's data", styles["Heading2"]),
    ]
    if not dossier.affected_models:
        story.append(
            Paragraph(
                "No models were trained on this data subject's data. No "
                "remediation is required.",
                body,
            )
        )
    else:
        rows = [["Model", "Training data", "Trained at", "Recommendation"]]
        rows += [
            [
                Paragraph(_e(m.model_name), body),
                Paragraph(_e(_plain_provenance(m.provenance)), body),
                Paragraph(_e(m.started_at), body),
                Paragraph(_e(m.recommendation), body),
            ]
            for m in dossier.affected_models
        ]
        table = Table(rows, colWidths=[1.5 * inch, 2.2 * inch, 1.6 * inch, 1.4 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(table)

    story += [
        Spacer(1, 0.2 * inch),
        Paragraph("3. Recorded processing of this request", styles["Heading2"]),
    ]
    if not dossier.revocation_events:
        story.append(
            Paragraph(
                "No revocation event has been recorded for this subject.", body
            )
        )
    else:
        for e in dossier.revocation_events:
            story.append(
                Paragraph(
                    f"{_e(e['timestamp'])} - {_e(e['n_affected_runs'])} "
                    f"affected run(s) - entry hash {_e(e['entry_hash'])}",
                    body,
                )
            )

    story += [
        Spacer(1, 0.3 * inch),
        Paragraph(
            f"Generated {_e(dossier.generated_at)} by ConsentML "
            f"{_e(dossier.consentml_version)}. ConsentML is a lineage and "
            "reporting tool: it identifies which models a data subject's data "
            "reached and records what the operator decided. It does not modify "
            "models or delete data.",
            styles["Italic"],
        ),
    ]

    doc.build(story)
    return buffer.getvalue()
```

`_e()` is reused deliberately: reportlab's `Paragraph` parses a small XML-ish markup dialect, so unescaped `<` in a model name raises a parse error and would crash the render.

- [ ] **Step 5: Export it**

Modify `src/consentml/__init__.py` — extend the render import to `render_html, render_json, render_pdf` and add `"render_pdf"` to `__all__`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_render.py -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add src/consentml/render.py src/consentml/__init__.py tests/test_render.py pyproject.toml
git commit -m "feat: PDF dossier renderer behind an optional [pdf] extra"
```

---

## Task 4: The `export` CLI subcommand

**Files:**
- Modify: `src/consentml/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `build_dossier(*, subject_id, db_path) -> Dossier` from Task 1; `render_json`, `render_html` from Task 2; `render_pdf` from Task 3; `ConsentMLError` from `consentml.errors`.
- Produces: `consentml export` with `--subject-id`, `--db`, `--format`, `--out`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py`:

```python
def test_cli_export_writes_html_by_default(seeded_db, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["export", "--subject-id", "a@x.com", "--db", str(seeded_db)])
    assert exit_code == 0

    key = hash_subject_id("a@x.com")
    written = tmp_path / f"consentml-dossier-{key[:12]}.html"
    assert written.exists()
    assert "churn_v3" in written.read_text()
    assert str(written) in capsys.readouterr().out


def test_cli_export_default_filename_uses_the_hash_not_the_raw_id(
    seeded_db, tmp_path, monkeypatch
):
    """The raw identifier belongs in the document, not in a directory listing."""
    monkeypatch.chdir(tmp_path)
    main(["export", "--subject-id", "a@x.com", "--db", str(seeded_db)])
    assert not any("a@x.com" in p.name for p in tmp_path.iterdir())


def test_cli_export_honors_out(seeded_db, tmp_path):
    out = tmp_path / "dossier.html"
    assert main(
        ["export", "--subject-id", "a@x.com", "--db", str(seeded_db), "--out", str(out)]
    ) == 0
    assert out.exists()


def test_cli_export_json_to_stdout(seeded_db, capsys):
    exit_code = main(
        [
            "export", "--subject-id", "a@x.com", "--db", str(seeded_db),
            "--format", "json", "--out", "-",
        ]
    )
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["subject_id"] == "a@x.com"
    assert data["affected_models"][0]["model_name"] == "churn_v3"


def test_cli_export_pdf_writes_a_pdf(seeded_db, tmp_path):
    out = tmp_path / "dossier.pdf"
    exit_code = main(
        [
            "export", "--subject-id", "a@x.com", "--db", str(seeded_db),
            "--format", "pdf", "--out", str(out),
        ]
    )
    assert exit_code == 0
    assert out.read_bytes().startswith(b"%PDF")


def test_cli_export_pdf_refuses_stdout(seeded_db, capsys):
    exit_code = main(
        [
            "export", "--subject-id", "a@x.com", "--db", str(seeded_db),
            "--format", "pdf", "--out", "-",
        ]
    )
    assert exit_code == 2
    assert "binary" in capsys.readouterr().err.lower()


def test_cli_export_exits_1_on_a_tampered_log(seeded_db, tmp_path):
    conn = sqlite3.connect(seeded_db)
    conn.execute("UPDATE audit_log SET payload = replace(payload, 'churn', 'x')")
    conn.commit()
    conn.close()

    out = tmp_path / "d.html"
    exit_code = main(
        ["export", "--subject-id", "a@x.com", "--db", str(seeded_db), "--out", str(out)]
    )
    assert exit_code == 1
    # The dossier is still written -- refusing would leave nothing to file.
    assert "FAILED" in out.read_text()


def test_cli_export_exits_1_and_creates_nothing_at_a_missing_db(tmp_path, capsys):
    missing = tmp_path / "nope.db"
    out = tmp_path / "d.html"
    exit_code = main(
        ["export", "--subject-id", "a@x.com", "--db", str(missing), "--out", str(out)]
    )
    assert exit_code == 1
    assert not missing.exists()
    assert not out.exists()
    assert "no lineage database" in capsys.readouterr().err.lower()


def test_cli_export_reports_a_missing_pdf_extra(seeded_db, tmp_path, capsys, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("No module named 'reportlab'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    exit_code = main(
        [
            "export", "--subject-id", "a@x.com", "--db", str(seeded_db),
            "--format", "pdf", "--out", str(tmp_path / "d.pdf"),
        ]
    )
    assert exit_code == 2
    assert "pip install consentml[pdf]" in capsys.readouterr().err
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_cli.py -k export -v`
Expected: FAIL — argparse rejects the unknown `export` command with SystemExit

- [ ] **Step 3: Implement the subcommand**

Modify `src/consentml/cli.py`. Update the module docstring's usage block to add:

```
    consentml export --subject-id <id> [--format html|json|pdf] [--out PATH]
```

Add the imports:

```python
from consentml.errors import ConsentMLError
from consentml.export import build_dossier
from consentml.render import render_html, render_json, render_pdf
```

Add the parser, after `p_migrate`:

```python
    p_export = sub.add_parser(
        "export", help="Export a per-subject dossier for a revocation request"
    )
    p_export.add_argument("--subject-id", required=True)
    p_export.add_argument(
        "--db", default=None, help="Lineage DB path (default: ~/.consentml/lineage.db)"
    )
    p_export.add_argument(
        "--format",
        dest="fmt",
        default="html",
        choices=["html", "json", "pdf"],
        help="Output format (default: html)",
    )
    p_export.add_argument(
        "--out",
        default=None,
        help=(
            "Output path; '-' writes to stdout (html/json only). Default: "
            "consentml-dossier-<subject-key-prefix>.<ext> in the working directory"
        ),
    )
```

Add this handler function above `main()`:

```python
def _run_export(args) -> int:
    """Build and write the dossier. Returns the process exit code.

    The dossier is written even when verification fails: export is read-only,
    so refusing protects nothing and would leave an operator facing a
    statutory deadline with nothing to file. A document whose first section
    reads "FAILED verification" is more useful than no document -- the
    nonzero exit is what stops that passing silently in a pipeline.
    """
    if args.fmt == "pdf" and args.out == "-":
        print(
            "Error: PDF output is binary; pass --out with a file path.",
            file=sys.stderr,
        )
        return 2

    dossier = build_dossier(subject_id=args.subject_id, db_path=args.db)

    if not dossier.database_found:
        for f in dossier.verification.findings:
            print(f"Error: {f.detail}", file=sys.stderr)
        return 1

    try:
        if args.fmt == "json":
            payload = render_json(dossier)
        elif args.fmt == "pdf":
            payload = render_pdf(dossier)
        else:
            payload = render_html(dossier)
    except ConsentMLError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if args.out == "-":
        print(payload)
    else:
        out = (
            Path(args.out)
            if args.out
            else Path(f"consentml-dossier-{dossier.subject_key[:12]}.{args.fmt}")
        )
        if isinstance(payload, bytes):
            out.write_bytes(payload)
        else:
            out.write_text(payload)
        print(f"Wrote {out}")

    return 0 if dossier.verification.ok else 1
```

Add `from pathlib import Path` to the imports.

Wire it into `main()` — add this immediately after `args = parser.parse_args(argv)`, before the existing `try`:

```python
    if args.command == "export":
        try:
            return _run_export(args)
        except (sqlite3.Error, OSError) as e:
            print(
                f"Error: could not open database at {args.db!r}: {e}",
                file=sys.stderr,
            )
            return 2
```

Handled separately rather than folded into the existing `try` because export's exit code comes from the dossier's verification verdict, not from a report's `ok` flag, and its output is written to a file rather than printed.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_cli.py -v`
Expected: all PASS

- [ ] **Step 5: Verify coverage is still 100%**

Run: `.venv/bin/python -m pytest --cov=consentml --cov-report=term-missing --ignore=tests/test_sources_postgres.py`
Expected: no uncovered lines in `export.py`, `render.py`, or the new `cli.py` code. Add tests for any gap.

- [ ] **Step 6: Commit**

```bash
git add src/consentml/cli.py tests/test_cli.py
git commit -m "feat: consentml export CLI subcommand"
```

---

## Task 5: Demo notebook and README

**Files:**
- Modify: `examples/consentml_demo.ipynb`
- Modify: `README.md`

**Interfaces:**
- Consumes: `build_dossier` and `render_html` from Tasks 1–2; the `consentml export` CLI from Task 4.
- Produces: nothing other code depends on.

- [ ] **Step 1: Add the export section to the notebook**

Insert two cells after the current section 6 (the tamper demonstration) and before section 7 (the CLI section). Note the notebook has tampered with `lineage.db` by that point, so the dossier will legitimately show a failed verification — which is the more interesting demonstration, and the cell says so.

Markdown cell:

```markdown
## 7. The document you actually hand a regulator

`revoke()` answers the question; a dossier is the artifact you file. It names
the subject, lists every model their data reached, records when the request
was processed, and states whether the log backing all of it is intact.

Because we tampered with the database above, this dossier reports a **failed**
verification — which is exactly what it should do. A tool that produced a
clean-looking compliance document over a modified log would be worse than
useless.
```

Code cell:

```python
from pathlib import Path

from consentml import build_dossier, render_html

dossier = build_dossier(subject_id=revoked_email, db_path=DB)

print("subject:      ", dossier.subject_id)
print("models:       ", [m.model_name for m in dossier.affected_models])
print("verified:     ", dossier.verification.ok)
print("revocations:  ", len(dossier.revocation_events))

Path("dossier.html").write_text(render_html(dossier))
print("\nWrote dossier.html")
```

- [ ] **Step 2: Add a CLI export example**

In the notebook's existing CLI section, after the `consentml verify` cell, add:

```python
!consentml export --subject-id user007@example.com --db lineage.db --format json --out - | head -20
```

- [ ] **Step 3: Run the notebook tests**

Run: `.venv/bin/python -m pytest tests/test_notebook.py -v`
Expected: both PASS — the notebook executes cleanly and still demonstrates detection

- [ ] **Step 4: Add the README section**

Add after the existing `verify` documentation:

```markdown
### Export a dossier

When a data subject exercises their right to erasure, `export` produces the
document you file: which models learned from their data, what you recommended
for each, when the request was processed, and whether the audit log backing it
is intact.

```bash
consentml export --subject-id user@example.com --db lineage.db
```

Writes `consentml-dossier-<key>.html` — self-contained, opens in any browser,
prints to PDF. `--format json` emits the same content machine-readably;
`--format pdf` writes a PDF directly and needs the optional extra:

```bash
pip install consentml[pdf]
```

Export never writes to the database, so it is safe to run against a copy of a
production lineage store. Exit codes match `verify`: 0 clean, 1 problems found
(the dossier is still written, and says so), 2 the database could not be read.

The dossier covers one subject. The audit log is a single global chain, so
exporting all of it to answer one subject's request would disclose every other
subject's activity.
```

- [ ] **Step 5: Run the full suite**

Run: `.venv/bin/python -m pytest --cov=consentml --cov-fail-under=100 --ignore=tests/test_sources_postgres.py`
Expected: all pass, coverage 100%

- [ ] **Step 6: Commit**

```bash
git add examples/consentml_demo.ipynb README.md
git commit -m "docs: document consentml export in the README and demo notebook"
```

---

## Task 6: Full verification against Postgres and CI

**Files:**
- None modified. This task is verification only.

**Interfaces:**
- Consumes: everything from Tasks 1–5.
- Produces: a branch ready for PR.

- [ ] **Step 1: Start the test Postgres**

```bash
docker compose -f docker-compose.test.yml up -d
```

- [ ] **Step 2: Run the complete suite with coverage**

```bash
export CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test
.venv/bin/python -m pytest --cov=consentml --cov-fail-under=100
```

Expected: every test passes, coverage 100%. The Postgres tests error rather than skip when the DSN is unset, so this step is what proves nothing regressed in the connector.

- [ ] **Step 3: Smoke-test the real CLI end to end**

```bash
cd /tmp && rm -f smoke.db smoke-*.html
.venv/bin/python -c "
from consentml import track
from consentml.sources import DataFrameSource
import pandas as pd
df = pd.DataFrame({'email': ['a@x.com', 'b@x.com'], 'y': [0, 1]})
@track(model_name='m', source=DataFrameSource(df, subject_id_col='email', label='w://c'), db_path='smoke.db')
def t(d):
    return object()
t()
"
.venv/bin/consentml export --subject-id a@x.com --db smoke.db; echo "exit=$?"
```

Expected: exit 0, writes an HTML file naming `a@x.com` and listing model `m`.

- [ ] **Step 4: Confirm export left the database untouched**

```bash
shasum -a 256 /tmp/smoke.db
.venv/bin/consentml export --subject-id a@x.com --db /tmp/smoke.db --format json --out - > /dev/null
shasum -a 256 /tmp/smoke.db
```

Expected: identical digests.

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin v0-week10-audit-export
gh pr create --title "Audit export: the per-subject regulator dossier" --body "$(cat <<'EOF'
Implements `consentml export`, per the design at
`docs/superpowers/specs/2026-07-27-audit-export-design.md`.

- Per-subject dossier: the audit log is one global chain, so a whole-log
  export would disclose every other subject's activity to one subject's
  regulator.
- Strictly read-only, proven by a byte comparison of the database file before
  and after, not by trusting `dry_run=True`.
- Verification runs before `revoke()` in `build_dossier()`. Reversing that
  order lets `LineageStore` provision a database at a typoed path and emit a
  clean-looking dossier for a database that never existed; there is a test
  pinning the ordering.
- HTML core with no new required dependencies; PDF behind an optional
  `[pdf]` extra, mirroring how `psycopg` is gated.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 6: Confirm CI is green**

```bash
gh run watch
```

Expected: green on both 3.10 and 3.13.

---

## Done when

- `pytest --cov=consentml --cov-fail-under=100` passes with a live Postgres.
- CI is green on 3.10 and 3.13.
- `consentml export --subject-id <id>` writes an HTML dossier and exits 0 on a clean database, exits 1 on a tampered one, and exits 1 against a path holding no lineage database — creating nothing there.
- `pip install consentml[pdf]` enables `--format pdf`; without it the command fails naming the install command.
- The demo notebook produces a dossier and README documents the command.
- The database is byte-identical before and after any export.
