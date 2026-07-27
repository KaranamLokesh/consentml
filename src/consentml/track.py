"""The @track decorator: lineage capture around a training function."""

import functools
import hashlib
import pickle
from datetime import datetime, timezone

from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


def track(*, model_name, source, hash_subject_ids=True, db_path=None):
    """Record training-data lineage for the decorated training function.

    The source is loaded first and its payload passed to the decorated
    function as the first positional argument -- the caller does not supply
    training data. Loading first means a bad source fails immediately rather
    than after training has already run.

    The model is hashed (SHA-256 of its pickle) and the lineage record is
    written only after training completes, so a training run that raises
    leaves nothing behind.
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            result = source.load()
            subject_values = [
                hash_subject_id(s) if hash_subject_ids else s
                for s in result.subject_ids
            ]

            started_at = datetime.now(timezone.utc).isoformat()
            model = fn(result.payload, *args, **kwargs)
            finished_at = datetime.now(timezone.utc).isoformat()

            model_hash = hashlib.sha256(pickle.dumps(model)).hexdigest()
            store = LineageStore(db_path=db_path)
            try:
                store.record_training_run(
                    model_name=model_name,
                    model_hash=model_hash,
                    provenance=result.provenance,
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
