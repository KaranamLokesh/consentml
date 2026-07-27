"""The Source interface: where training data and its provenance come from.

A Source is asked for everything in one call. That is the whole point: the
payload the model trains on and the subject IDs recorded as lineage come out
of a single observation of the underlying system, so they cannot disagree.
Splitting this into separate calls would reintroduce exactly the skew this
design exists to eliminate -- two queries against a live table at two points
in time, with nothing to signal that they diverged.
"""

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class SourceResult:
    payload: object
    """Handed to the training function untouched. ConsentML never inspects
    it, so a pandas DataFrame, a Spark DataFrame, or anything else works."""

    subject_ids: list
    """The contract every Source.load() must uphold for this field:

    - **Distinct**: one entry per subject, even if the underlying rows repeat
      the same subject (e.g. a join or a UNION ALL). Sources dedupe with
      .unique() for exactly this reason -- an undeduped list would inflate
      n_subjects with rows that are not additional coverage.
    - **Non-null**: a null subject ID cannot be revoked -- there is no value a
      later revocation request could ever match. Worse, stringifying a null
      (see below) turns it into a *distinct* phantom subject ("nan", "None",
      or "<NA>" depending on pandas version and dtype), silently inflating
      n_subjects with coverage that was never real. Sources must reject nulls
      before they reach this list, not stringify them into it.
    - **Stringified**: every element is already `str`, regardless of the
      underlying column's type. A source that skips this (e.g. a Postgres
      `uuid` column, or any non-text pandas dtype) hands the store a value
      its SQL layer cannot bind, which fails *after* the training function
      has already run -- exactly the split-observation failure this
      interface exists to prevent (see the module docstring).

    Note: frozen=True stops attribute *reassignment* (result.subject_ids = ..)
    but the list object itself is still mutable in place. Sources return a
    fresh list each call, so this hasn't bitten anyone -- flagged here so a
    future caller who wants to hold onto a SourceResult doesn't assume more
    protection than the dataclass actually gives."""

    provenance: dict = field(default_factory=dict)
    """JSON-serializable record of where the data came from. Discriminated by
    a "kind" key; every other field is that kind's business."""


@runtime_checkable
class Source(Protocol):
    def load(self) -> SourceResult: ...
