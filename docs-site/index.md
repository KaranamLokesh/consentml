# ConsentML

ConsentML tracks which data reached which model during training and keeps a
tamper-evident record of it. When a subject asks to be forgotten, it tells you
which deployed models were trained on their data instead of leaving you to
guess.

## Status

Beta: v0.x is on PyPI and the API may still change before 1.0.
Requires Python 3.10 or later. MIT license.

## Install

```bash
pip install consentml
```

Optional extras add a Postgres data source (`consentml[postgres]`) and PDF
dossier export (`consentml[pdf]`).

## In six lines

```python
from consentml import track
from consentml.sources import DataFrameSource

@track(model_name="churn", source=DataFrameSource(df, subject_id_col="email",
                                                  label="warehouse.customers"))
def train(df):
    return RandomForestClassifier().fit(df[FEATURES], df["churned"])
```

## Where to go next

- [Quickstart](getting-started/quickstart.md)
- [Reference](reference/cli.md)
- [Why ConsentML](why/index.md)

ConsentML reports which models a subject's data reached. It does not delete
data and does not modify models.
