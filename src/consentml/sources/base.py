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
    """Distinct subject identifiers, before hashing.

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
