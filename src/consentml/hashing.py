"""Subject-identifier hashing.

Subject IDs are stored as SHA-256 digests by default so the lineage store
does not hold raw personal identifiers. Hashing is deterministic (no salt)
because revocation lookups must be able to re-derive the stored value from
the identifier presented at revocation time.
"""

import hashlib


def hash_subject_id(subject_id) -> str:
    """Return the SHA-256 hex digest of a subject identifier."""
    return hashlib.sha256(str(subject_id).encode("utf-8")).hexdigest()
