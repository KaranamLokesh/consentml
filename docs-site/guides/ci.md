# Using exit codes in CI

## The exit-code contract

`verify`, `migrate` and `export` share one exit-code contract: 0 means
clean, 1 means the database was read and something was found — a
verification finding, a missing database, a migration that was refused —
and 2 means the database could not be read at all, or the requested output
could not be produced. `revoke` is the exception: it always reports what it
found and exits 0, whether or not the subject affected any model, and only
exits 2 if the database can't be read.

The distinction between 1 and 2 matters for how a pipeline should react. A
missing database is exit 1 — the path was checked and there was nothing
there:

```bash
consentml verify --db does-not-exist.db
```

```
Audit log FAILED verification: 1 finding across 0 entries.
  - [missing_database] tables: no lineage database at does-not-exist.db
head: 0000000000000000000000000000000000000000000000000000000000000000
```

A path that can't be opened at all — a directory, a permission error — is
exit 2, because nothing was actually read:

```bash
consentml verify --db some-directory
```

```
Error: could not open database at 'some-directory': disk I/O error
```

## Gating a pipeline on verification

```yaml
- name: Verify the lineage audit log
  run: |
    pip install consentml
    consentml verify --db lineage.db --expected-head "${{ secrets.CONSENTML_ANCHOR }}"
```

A nonzero exit from this step fails the job, the same way any other `run:`
step would. See [the anchoring guide](anchoring.md) for what
`--expected-head` checks and where the hash it takes comes from.

## Why the anchor belongs in secrets, not the repo

An anchor is only useful if whoever can rewrite the lineage database can't
also rewrite the value being checked against it. Store the anchor next to
the database it protects — a file checked into the same repo, a column in
the same table — and the two move together: an attacker who rewrites the
database from genesis recomputes a new head and updates the stored anchor to
match in the same act, and `--expected-head` passes cleanly over history
that never happened. A CI secret is a separate, more restricted store than
the repository or the database it's checking, which is what makes rewriting
one without also being able to rewrite the other actually hard.

## Exporting dossiers in CI

```bash
consentml export --format json --out -
```

`--format json` produces the same dossier content as the default HTML
export, structured for a pipeline step to parse rather than a person to
read; `--out -` writes it to stdout instead of a file, for piping into
whatever handles revocation requests downstream.

Export follows the same exit-code contract as `verify`, and it keeps
writing the dossier even when verification fails — refusing would leave
whoever's handling a live request with nothing to file, and a document
whose own first section reports the failure is more useful than no document
at all. Against a database with a tampered entry, export still prints the
full dossier and exits 1:

```bash
consentml export --subject-id user@example.com --db lineage.db --format json --out -
```

The tail end of that JSON — the same `verification` block `consentml verify`
reports on its own — carries the failure:

```json
"verification": {
  "findings": [
    {
      "code": "entry_hash_mismatch",
      "detail": "entry 1 hash does not match its contents",
      "entry_id": 1
    },
    {
      "code": "run_modified",
      "detail": "run 852c5f43-cdfd-4b62-9d6c-02d9e7cbbbe0: model_name in training_runs ('m1') differs from the logged value ('m1-tampered')",
      "entry_id": 1
    }
  ],
  "head_hash": "67ab7e46f61b46945676d0a7bbaf8641fd11f6a868145c2e7717020c1a2fcfe5",
  "n_entries": 2,
  "n_legacy_runs": 0,
  "ok": false
}
```

(exit code 1 — the full dossier, 51 lines of JSON, was still written before
the process exited)

The exit code is what a pipeline should branch on; the document itself is
for the person or system handling the request, not for the pipeline to
inspect.
