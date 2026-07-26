import hashlib

import pandas as pd
from sklearn.linear_model import LogisticRegression

from consentml.revoke import revoke
from consentml.sources import DataFrameSource
from consentml.store import GENESIS_HASH, LineageStore
from consentml.track import track


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
        source=DataFrameSource(df, subject_id_col="email",
                                label="postgres://prod/customers"),
        model_name="churn",
        db_path=db,
    )(fit)()
    track(
        source=DataFrameSource(df, subject_id_col="email",
                                label="postgres://prod/customers"),
        model_name="upsell",
        db_path=db,
    )(fit)()

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
