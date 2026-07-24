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
