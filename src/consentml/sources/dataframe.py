"""In-memory pandas DataFrame source.

The validation @track used to do inline lives here now: this is the one place
that knows the payload is a DataFrame, so it is the one place entitled to
check its shape.
"""

import pandas as pd

from consentml.errors import ConsentMLError
from consentml.sources.base import SourceResult


class DataFrameSource:
    """Track a DataFrame the caller already has in memory.

    `label` is caller-asserted and unverifiable -- ConsentML has no way to
    check where an in-memory frame came from. It is recorded under
    kind="dataframe" precisely so a reader can tell it apart from a
    connector-verified record.
    """

    def __init__(self, df, *, subject_id_col, label=None):
        self._df = df
        self._subject_id_col = subject_id_col
        self._label = label

    def load(self) -> SourceResult:
        if not isinstance(self._df, pd.DataFrame):
            got = type(self._df)
            raise ConsentMLError(
                f"DataFrameSource needs a pandas DataFrame, got "
                f"{got.__module__}.{got.__qualname__}."
            )
        if self._subject_id_col not in self._df.columns:
            raise ConsentMLError(
                f"Subject ID column '{self._subject_id_col}' not found in "
                f"training DataFrame (columns: {list(self._df.columns)})."
            )
        if len(self._df) == 0:
            raise ConsentMLError(
                "Training DataFrame has no rows; refusing to record a "
                "training run over zero subjects."
            )
        # See SourceResult.subject_ids in sources/base.py for the full
        # contract (distinct, non-null, stringified) and why a null here
        # matters -- this is one of two call sites (sources/postgres.py is
        # the other) that enforce it.
        n_null = int(self._df[self._subject_id_col].isna().sum())
        if n_null:
            raise ConsentMLError(
                f"Subject ID column '{self._subject_id_col}' has {n_null} null "
                f"value(s); a null subject ID cannot be revoked, so refusing to "
                f"record it as training coverage."
            )
        subject_ids = self._df[self._subject_id_col].astype(str).unique().tolist()
        return SourceResult(
            payload=self._df,
            subject_ids=subject_ids,
            provenance={
                "kind": "dataframe",
                "label": self._label,
                "subject_id_col": self._subject_id_col,
                # Rows, not subjects -- a subject with repeat rows makes
                # this larger than len(subject_ids). n_subjects is recorded
                # separately in the schema for exactly that reason; don't
                # read this field as a coverage count.
                "n_rows": int(len(self._df)),
            },
        )
