import json

import pytest

from consentml.errors import ConsentMLError
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


def test_public_api_exports_revoke():
    import consentml

    assert consentml.revoke is revoke
    assert consentml.AffectedModelsReport is AffectedModelsReport


def test_revoke_dry_run_works_on_legacy_database(legacy_db):
    report = revoke(subject_id="h1", db_path=legacy_db, dry_run=True)
    assert [m.model_name for m in report.affected_models] == ["churn_v3", "upsell"]
    assert report.audit_log_entry_id is None


def test_revoke_recording_is_refused_on_legacy_database(legacy_db):
    with pytest.raises(ConsentMLError, match="consentml migrate"):
        revoke(subject_id="h1", db_path=legacy_db)
