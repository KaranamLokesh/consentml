"""ConsentML: training-data lineage and consent-revocation reporting."""

from consentml.errors import ConsentMLError
from consentml.export import Dossier, build_dossier
from consentml.migrate import MigrationResult, migrate_database
from consentml.render import render_html, render_json
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
    "Dossier",
    "build_dossier",
    "render_html",
    "render_json",
    "__version__",
]
