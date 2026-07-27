"""ConsentML: training-data lineage and consent-revocation reporting."""

from consentml.errors import ConsentMLError
from consentml.migrate import MigrationResult, migrate_database
from consentml.revoke import AffectedModel, AffectedModelsReport, revoke
from consentml.sources import DataFrameSource, Source, SourceResult
from consentml.track import track
from consentml.verify import (
    VerificationFinding,
    VerificationReport,
    verify_audit_log,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "track",
    "revoke",
    "verify_audit_log",
    "migrate_database",
    "AffectedModel",
    "AffectedModelsReport",
    "VerificationFinding",
    "VerificationReport",
    "MigrationResult",
    "ConsentMLError",
    "Source",
    "SourceResult",
    "DataFrameSource",
    "__version__",
]
