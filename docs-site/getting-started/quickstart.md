# Quickstart

This walks through the whole lifecycle once: track a training run, ask which
models a subject's data reached, hand over a dossier, and check that the
audit trail backing it hasn't been tampered with. Every command below is one
you can run yourself, in order, in an empty directory.

!!! tip "Prefer a notebook?"
    [`consentml_demo.ipynb`](https://github.com/KaranamLokesh/consentml/blob/main/examples/consentml_demo.ipynb)
    is this same end-to-end workflow as a runnable notebook — train with
    lineage, revoke, verify, and export a dossier — on a synthetic in-memory
    dataset. It renders on GitHub without running anything.

## Install

```bash
pip install consentml
```

Requires Python 3.10 or later.

Data sources and export formats beyond the basics are behind optional
extras — `consentml[postgres]` and `consentml[pdf]` — introduced as they come
up below.

## Track a training run

`@track` wraps a training function and hands it data from a `Source` you
declare. For data already in memory, `DataFrameSource` reads subject IDs out
of a column you name. Save this as `train.py`:

```python
import pandas as pd
from sklearn.linear_model import LogisticRegression

from consentml import track
from consentml.sources import DataFrameSource

df = pd.DataFrame({
    "patient_id": ["p1", "p2", "p3", "p4", "p5", "p6"],
    "age": [52, 61, 45, 70, 39, 58],
    "ldl": [130, 145, 110, 160, 95, 150],
    "outcome": [0, 1, 0, 1, 0, 1],
})

@track(
    model_name="readmission-risk",
    source=DataFrameSource(df, subject_id_col="patient_id", label="clinic.patients"),
    db_path="lineage.db",
)
def train(df):
    return LogisticRegression().fit(df[["age", "ldl"]], df["outcome"])

model = train()
print(f"Trained {type(model).__name__} on {len(df)} rows.")
```

```bash
python train.py
```

```
Trained LogisticRegression on 6 rows.
```

That call trained the model and, in the same step, recorded a training run
in `lineage.db`: which subjects (as SHA-256 digests, not raw IDs), what
query or frame produced the data, and a hash of the trained model itself.

## Ask who was affected

`revoke` looks up a subject and reports which recorded runs their data
covers, with a per-model recommendation. `--dry-run` reports without writing
anything back to the log:

```bash
consentml revoke --subject-id p2 --db lineage.db --dry-run
```

```
1 affected model for subject 3946ca64ff78…
  - readmission-risk  run=e8240888  trained=2026-08-14T04:00:04.211248+00:00  recommendation=retrain
Dry run: nothing recorded.
```

`readmission-risk` is flagged `retrain` because patient `p2`'s data is in
this run and no later run supersedes it.

Double-check `--db` before you rely on a `0 affected models` result: if the
path is wrong, `revoke` doesn't error — it creates an empty database at that
path and reports `0 affected models` against it, `--dry-run` included. See
[the CLI reference](../reference/cli.md#revoke) for what that means in
practice.

## Produce a dossier

`export` turns that same lookup into the document you'd hand to whoever is
asking — audit-log integrity, affected models, and any revocation already on
record, all in one file:

```bash
consentml export --subject-id p2 --db lineage.db
```

```
Wrote /path/to/your/directory/consentml-dossier-3946ca64ff78.html
```

The printed path is absolute and will point into your own working directory;
`3946ca64ff78` is the same subject-key prefix `revoke` printed above, not the
raw subject ID — see [Your first dossier](first-dossier.md) for what the
document contains and why the filename is hashed.

## Verify the trail

`verify` checks the audit log independently of any one subject — that every
entry still hashes to its recorded value, that the chain links correctly,
and that the log agrees with the live tables:

```bash
consentml verify --db lineage.db
```

```
Audit log OK: 1 entries, chain intact.
head: 85d36e6f5c1ff020f9bd0221e1069294c983baa51b080d20f1a1ba101e747eff
```

Record that `head` hash somewhere outside the database if you want to be
able to detect a wholesale rewrite of the log later — see
[the anchoring guide](../guides/anchoring.md) for how `--expected-head` uses
it.

From here: [Tracking a run](tracking.md) covers the decorator and data
sources in more depth, and [Your first dossier](first-dossier.md) covers
what the exported document says and doesn't say.
