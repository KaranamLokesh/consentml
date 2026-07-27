"""Data sources for @track.

PostgresSource is deliberately not re-exported here: importing it pulls in
psycopg, an optional extra (`pip install 'consentml[postgres]'`), and this
package's own import must stay pandas-only. Import it directly from
consentml.sources.postgres.
"""

from consentml.sources.base import Source, SourceResult
from consentml.sources.dataframe import DataFrameSource

__all__ = ["Source", "SourceResult", "DataFrameSource"]
