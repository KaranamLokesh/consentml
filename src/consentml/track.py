"""The @track decorator: lineage capture around a training function."""

import functools
import hashlib
import pickle
from datetime import datetime, timezone

import pandas as pd

from consentml.errors import ConsentMLError
from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


def _find_dataframe(args, kwargs):
    for value in list(args) + list(kwargs.values()):
        if isinstance(value, pd.DataFrame):
            return value
    return None


def track(*, data_source, subject_id_col, model_name, hash_subject_ids=True, db_path=None):
    """Record training-data lineage for the decorated training function.

    The decorated function must accept a pandas DataFrame (positionally or by
    keyword) containing `subject_id_col`, and return the trained model. The
    model is hashed (SHA-256 of its pickle) and a lineage record is written
    after training completes.
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            df = _find_dataframe(args, kwargs)
            if df is None:
                raise ConsentMLError(
                    "No pandas DataFrame found in arguments to "
                    f"'{fn.__name__}'; @track needs the training DataFrame."
                )
            if subject_id_col not in df.columns:
                raise ConsentMLError(
                    f"Subject ID column '{subject_id_col}' not found in "
                    f"training DataFrame (columns: {list(df.columns)})."
                )
            subjects = df[subject_id_col].astype(str).unique()
            subject_values = [
                hash_subject_id(s) if hash_subject_ids else s for s in subjects
            ]

            started_at = datetime.now(timezone.utc).isoformat()
            model = fn(*args, **kwargs)
            finished_at = datetime.now(timezone.utc).isoformat()

            model_hash = hashlib.sha256(pickle.dumps(model)).hexdigest()
            store = LineageStore(db_path=db_path)
            try:
                store.record_training_run(
                    model_name=model_name,
                    model_hash=model_hash,
                    provenance={
                        "kind": "dataframe",
                        "label": data_source,
                        "subject_id_col": subject_id_col,
                        "n_rows": len(df),
                    },
                    subject_ids_hashed=hash_subject_ids,
                    subject_id_values=subject_values,
                    started_at=started_at,
                    finished_at=finished_at,
                )
            finally:
                store.close()
            return model

        return wrapper

    return decorator
