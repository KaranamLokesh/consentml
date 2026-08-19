# Your first dossier

## What a dossier is

A dossier answers one data subject's erasure request: which models were
trained on their data, what you recommended doing about each one, when the
request was processed, and whether the audit log behind all of that is
intact. It's the document you hand to whoever raised the request — one
subject, one document.

## Producing one

```bash
consentml export --subject-id user@example.com --db lineage.db
```

```
Wrote /path/to/your/directory/consentml-dossier-b4c9a289323b.html
```

By default this writes `consentml-dossier-<key>.html` in the current
directory, where `<key>` is the first 12 characters of the subject's
SHA-256 hash — `b4c9a289323b` above, not `user@example.com`. The filename
is derived the same way the database stores the subject, so it never puts
the raw ID into a filename that might end up in a shared directory or a
ticket attachment.

## The three formats

HTML is the default: a single self-contained file — the CSS is inline, there
are no external resources — that opens in any browser and prints to PDF from
there.

`--format json` emits the same content machine-readably, for a pipeline that
wants to route or store the result rather than read it directly:

```bash
consentml export --subject-id user@example.com --db lineage.db --format json --out -
```

```json
{
  "affected_models": [
    {
      "finished_at": "2026-08-14T04:00:34.710815+00:00",
      "model_hash": "4faa1a97978cd7eedf66cb089841a0b7e40ea0b7e1e2a58e0f4c020cd7f07ed7",
      "model_name": "churn",
      "provenance": {
        "kind": "dataframe",
        "label": "warehouse.customers",
        "n_rows": 3,
        "subject_id_col": "email"
      },
      "recommendation": "retrain",
      "run_id": "23bb8e8e-1894-482e-a4c0-fed236f9bc00",
      "started_at": "2026-08-14T04:00:34.643178+00:00"
    }
  ],
  "consentml_version": "0.2.0",
  "database_found": true,
  "generated_at": "2026-08-14T04:00:35.281337+00:00",
  "head_hash": "02f4d018a952dde6409661f2762115e20137df2185033a255ee85235bb3814b5",
  "n_legacy_runs": 0,
  "recommended_actions": [
    {
      "action": "retrain",
      "model_name": "churn"
    }
  ],
  "revocation_events": [],
  "subject_id": "user@example.com",
  "subject_key": "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514",
  "verification": {
    "findings": [],
    "generated_at": "2026-08-14T04:00:35.282063+00:00",
    "head_hash": "02f4d018a952dde6409661f2762115e20137df2185033a255ee85235bb3814b5",
    "n_entries": 1,
    "n_legacy_runs": 0,
    "ok": true
  }
}
```

`--format pdf` writes a PDF directly, and needs the optional extra:

```bash
pip install 'consentml[pdf]'
```

Without it, `export --format pdf` fails clearly rather than falling back to
another format:

```
Error: PDF output needs the optional 'pdf' extra: pip install consentml[pdf]
```

## Reading the document

Every dossier, in any format, has the same three sections, in this order:

1. **Audit log integrity** — whether every entry still hashes to its
   recorded value, the chain links correctly, and the log agrees with the
   live tables, plus the head hash of the log as read.
2. **Models trained on the subject's data** — one row per affected training
   run: model name, training data, when it trained, the model's hash, and
   the recommended action.
3. **Recorded processing of the request** — any `consentml revoke` call
   already on record for this subject, or a note that none has been.

## What it will not claim

Sections 2 and 3 report an absence — no models, no recorded revocation — but
only when a database was actually read. If no lineage database was found,
`render.py`'s renderers substitute a caveat instead of reporting a negative:

> No lineage database was read, so it could not be determined whether any
> models were trained on this data subject's data. This is not a finding
> that there were none.

and the equivalent for revocation events. That guard exists because an
erasure-response document that says "no models were trained on this
person's data" without ever having read anything would be exactly the false
clean the dossier is meant to rule out. In practice the CLI is stricter
still: `export` won't reach that renderer at all against a missing
database — it writes nothing and reports the problem instead:

```bash
consentml export --subject-id user@example.com --db does-not-exist.db
```

```
Error: no lineage database at does-not-exist.db
```

(exit code 1)

## One subject per document

A dossier only ever covers the subject you asked for. The audit log is a
single chain shared by every subject and every run, so exporting the whole
log to answer one person's request would hand their regulator everyone
else's activity along with it. `export` never reads more of the log than it
needs to answer for the one subject named on the command line.
