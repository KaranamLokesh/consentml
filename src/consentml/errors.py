"""Exception types shared across the package.

ConsentMLError lives here rather than in track.py so that store.py can raise
it without importing track.py, which would be circular.
"""


class ConsentMLError(Exception):
    """Raised for ConsentML usage errors (bad arguments, missing data)."""
