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
