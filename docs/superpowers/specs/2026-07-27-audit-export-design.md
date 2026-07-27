# Audit Export Design

Status: approved 2026-07-27

`consentml export` produces the document an organization hands to a regulator
when a data subject exercises their right to be forgotten: which models learned
from that person's data, what the operator recommended for each, when the
request was processed, and whether the log backing all of it is intact.

This closes the last substantive gap in the v0 design spec's claim that
ConsentML "generates a regulator-ready audit log." Today `revoke --json` and
`verify --json` emit machine-readable reports of their own results, but nothing
produces a document a compliance officer can file.

## Scope

One exported document covers **one subject's revocation request**.

The audit log is global: one hash chain holding every training run, every
revocation, and every hashed subject key in the database. Exporting the whole
log to answer a single subject access request would disclose every other data
subject's activity to that subject's regulator. The per-subject dossier
discloses only what the request is about.

A whole-log export is a plausible future feature for internal archives and
periodic attestation. It is not in this change.

## Non-goals

- No whole-log or date-range export.
- No signing. Signed audit logs are a v1 item in the design spec's deferred
  table and need a decision on the signing model first.
- No new audit event. Export writes nothing (see Read-only, below).
- No templating engine or theming. One HTML layout, generated in Python.

## Read-only

`export` never writes to the database. It follows the precedent set by
`verify_audit_log()`, whose docstring argues that a self-recorded "I verified
myself" entry carries no more trust than the log containing it.

The same reasoning applies here: the `revocation` event that `revoke()` already
records is what proves the request was processed. A dossier is a re-rendering
of history that is already logged, so an "I exported this" entry adds
negligible evidentiary weight while turning export into a write path — one that
would need `_require_writable`, would refuse on unmigrated databases, and could
not run against a read-only copy of a production database.

Staying read-only means an operator can produce a dossier from a snapshot of
production without touching production.

## Subject identification

The document names the subject in the clear — "Response to the erasure request
from user@example.com" — alongside the SHA-256 subject key that ties it to the
log.

The raw identifier is necessary for the document to do its job. A regulator
holding a complaint from a named individual cannot match a bare hash to it, and
requiring the operator to attach a separate note explaining who the hash is
re-introduces exactly the manual gap-filling the library exists to remove.

This does not weaken the storage claim. The database still holds subject IDs
only as SHA-256 hashes; the raw value comes from the caller's `--subject-id`
argument at export time and is never written back. The default output filename
uses the hash prefix, not the raw ID, so the identifier does not leak into
directory listings, shell history, or CI logs.

## Architecture

Two new modules, flat, matching the existing package layout.

### `src/consentml/export.py`

`Dossier` dataclass and `build_dossier(*, subject_id, db_path=None) -> Dossier`.
Assembly only, no rendering. It composes three reads:

| Read | Source | Provides |
|---|---|---|
| `revoke(subject_id=..., dry_run=True)` | `revoke.py` | Affected models and per-model recommendations. `dry_run=True` is what keeps export read-only. |
| `verify_audit_log(db_path=...)` | `verify.py` | Integrity verdict, head hash, legacy-run count. |
| Revocation events for this subject | `store.audit_entries()`, filtered on `payload["subject_key"]` | Proof the request was processed, with timestamps. |

The third read is the only one not already available through a public API. It is
what turns the dossier from an assertion about current state into evidence that
the request was handled, and when.

### `src/consentml/render.py`

Three functions, each taking a `Dossier`:

- `render_json(dossier) -> str`
- `render_html(dossier) -> str`
- `render_pdf(dossier) -> bytes`

Only `render_pdf` imports reportlab, and it does so at call time so that
`import consentml` never requires the extra.

The seam between assembly and rendering means the dossier's contents are tested
against data structures rather than against rendered output — no HTML string
matching to assert that a model appears in the report. Adding a format later
touches one file.

### Why not the alternatives

**Render HTML once and convert it to PDF** keeps the two formats visually
identical, but every converter costs more than it saves. WeasyPrint needs cairo
and pango, which would be the library's first non-Python dependency and would
break `pip install consentml[pdf]` on a clean machine. Headless-browser
conversion is worse. reportlab draws directly and needs nothing, but then it is
not consuming the HTML, which collapses the approach back into separate
renderers.

**Extend `AffectedModelsReport` with render methods** saves a file but couples
the reporting API to presentation, and the dossier needs the verification result
and log entries that `revoke()` has no business fetching. `revoke --json`'s
output shape is also already public.

## Dossier contents

| Field | Source | Why a regulator's document needs it |
|---|---|---|
| `subject_id` | caller's raw input | Names the person the document concerns |
| `subject_key` | `hash_subject_id()` | Ties the document to the log, which is hash-only |
| `generated_at` | UTC now, ISO 8601 | When this response was produced |
| `affected_models` | `revoke()` | The substantive answer: which models learned from this person |
| `recommended_actions` | `revoke()` | Per model: `retrain` or `review` |
| `revocation_events` | audit log, filtered by subject key | Proof the request was processed, with timestamps |
| `verification` | `verify_audit_log()` | Whether the log backing all of the above is intact |
| `head_hash` | `verify_audit_log()` | Lets a third party re-verify independently, later |
| `n_legacy_runs` | `verify_audit_log()` | How many runs' provenance could not be verified |
| `consentml_version` | `consentml.__version__` | Which code produced this |

### What the log cannot prove on its own

Filtering the audit log by subject key yields **revocation events only**.
`training_run` payloads carry `run_id`, `model_name`, `model_hash`,
`provenance_sha256`, and `n_subjects` — never subject keys — by design, so that
the log itself never becomes a roster of who was in which training set.

Membership therefore comes from `subject_index` via `revoke()`, not from the
log. The dossier presents these as the distinct things they are rather than
implying the hash chain alone proves membership.

## CLI

```
consentml export --subject-id <id> [--db PATH] [--format html|json|pdf] [--out PATH]
```

`--format` defaults to `html`: it is the human-readable artifact and the only
format that works with no extra installed.

`--out` defaults to `consentml-dossier-<first-12-of-subject-key>.<ext>` in the
working directory, and the command prints the path it wrote. `--out -` streams
to stdout for html and json; for pdf it is an error rather than binary down a
terminal.

### Exit codes

Follows the convention documented at the top of `cli.py`, so `export` can gate
CI the way `verify` does:

- **0** — dossier written, log verified clean.
- **1** — problems were found. Either the dossier was written and verification
  failed (the document says so in its first section), or there is no lineage
  database at the given path and no dossier was written.
- **2** — the database could not be read, or output could not be produced:
  `sqlite3.Error`/`OSError` on open, or `--format pdf` without the extra
  installed.

Exit 1 deliberately covers both "wrote a dossier over a broken log" and "found
no database to read". That mirrors `verify`, whose documented contract already
places "no database at the given path" at exit 1 rather than 2 — a missing file
is a finding the command reports, not a failure to read a file that is there.
Diverging here would mean `export` and `verify` report the identical condition
with different codes against the same `--db` argument.

### Why a failed verification still produces a document

When the database is present but its log fails verification, export renders the
dossier anyway. This diverges from `migrate`, which refuses outright when
verification fails.
`migrate` writes, so refusing protects the data. Export is read-only, so
refusing protects nothing and leaves an operator facing a statutory deadline
with nothing to file.

A document whose first section reads "verification FAILED — this log has been
modified since it was written" is more useful and more honest than no document.
The nonzero exit is what keeps that from passing silently in a pipeline.

A subject with no affected models likewise still gets a dossier and exits 0.
"No models were trained on this person's data" is a legitimate regulator answer.

## Packaging

reportlab goes in a new optional extra, mirroring how psycopg is already gated:

```toml
[project.optional-dependencies]
pdf = ["reportlab>=4.0"]
```

It is added to the `dev` extra so CI exercises the PDF path. Runtime
dependencies for a default install stay at `pandas>=2.0`.

reportlab is BSD-licensed, pure Python, and needs no system libraries, so
`pip install consentml[pdf]` works on a clean machine without a compiler.

## Error handling

### Ordering: verify before revoke

`build_dossier()` calls `verify_audit_log()` **first** and returns immediately
on a `missing_database` or `not_a_lineage_database` finding, before `revoke()`
is ever constructed.

This ordering is load-bearing, not incidental. `revoke()` constructs a
`LineageStore`, and `LineageStore.__init__` creates parent directories and runs
the schema script against any path that lacks one. Calling `revoke()` first
against a typoed `--db` would silently create an empty database, find zero
affected models, verify the empty log as clean, and emit an official-looking
dossier stating that no models were trained on the subject's data — exit 0.

That is a false clean, and it is the worst available bug in this feature: a
confident document asserting the opposite of the truth. It is also the exact
failure mode `verify_audit_log()` was hardened against; composing `revoke()`
into a new caller re-introduces the hazard unless the ordering is explicit.

The ordering carries a comment saying so and a test that asserts no file is
created at a nonexistent path.

### Other cases

- **Legacy databases.** v0 and v1 databases are readable but not writable.
  Export never writes, so it works against them. `verify_audit_log()` reports
  `n_legacy_runs` for runs whose provenance predates hashing, and the dossier
  surfaces that as an explicit caveat. Presenting unverified provenance as
  verified is precisely the overpromise §4 of the design spec says the
  library's credibility depends on avoiding.
- **Missing reportlab.** `--format pdf` without the extra raises
  `ConsentMLError` naming the fix (`pip install consentml[pdf]`); the CLI
  reports it and exits 2.
- **Malformed audit payloads.** The subject-key filter parses every payload to
  read `subject_key`, and payloads are attacker-editable: invalid JSON, a JSON
  array, or bytes returned by the store's lenient `text_factory`. Entries whose
  payload does not parse to a dict are skipped rather than raising, matching
  `_parse_payloads()` in `verify.py`. Skipping is safe because the same entries
  are independently reported as `malformed_payload` findings by the
  verification read, so a dossier can never quietly omit a revocation event
  without the document also showing the log is broken.
- **Unreadable provenance.** `revoke()` already returns `{"kind": "unreadable"}`
  for tampered or non-text provenance. Renderers display that state visibly
  rather than an empty cell that reads as "nothing to see here."
- **HTML escaping.** Model names, provenance labels, and the raw subject ID all
  pass through `html.escape()`. Provenance can hold arbitrary text from a
  Postgres source label, and this document is emailed to third parties;
  unescaped it is a script-injection vector in an artifact whose entire value is
  being trustworthy.

## Testing

TDD, against the existing `--cov-fail-under=100` gate. New files
`tests/test_export.py` and `tests/test_render.py`, plus CLI cases in
`tests/test_cli.py`.

Two tests carry the design's central claims:

**Read-only is asserted, not assumed.** Hash the database file's bytes before
and after an export and assert they are identical. `dry_run=True` is the
mechanism; a byte comparison is the proof, and it catches a future change that
introduces a write anywhere in the composition.

**The false-clean guard has its own test.** Export against a nonexistent path,
then assert the path still does not exist, no dossier was written, and the exit
code is 1. If someone later reorders `build_dossier()` to call `revoke()` before
verifying, that test fails.

The rest:

- A subject in two models produces both, with correct per-model
  recommendations.
- A subject in no models still renders, and exits 0.
- A tampered database surfaces the finding in the rendered document, and
  exits 1.
- A v0 database and a v1 database (conftest has `build_legacy` and `build_v1`
  builders for both) each surface `n_legacy_runs`.
- `render_json` output round-trips through `json.loads` to the dossier's dict.
- `render_html` output contains the subject ID, every model name, and the head
  hash.
- A model name containing `<script>` comes out escaped.
- `render_pdf` output starts with `%PDF`.
- The missing-reportlab path raises with the install command in the message.

## Also in this change

- An export section in `examples/consentml_demo.ipynb`. The notebook is the
  launch demo, and the dossier is the artifact the whole narrative builds
  toward. `tests/test_notebook.py` executes the new cells, so it cannot silently
  rot.
- A README section covering the command and the optional extra.

## Done when

- `pytest --cov=consentml --cov-fail-under=100` passes with a live Postgres.
- CI is green on 3.10 and 3.13.
- `consentml export --subject-id <id>` writes an HTML dossier and exits 0 on a
  clean database, exits 1 on a tampered one, and exits 1 against a path that
  holds no lineage database — creating nothing there.
- `pip install consentml[pdf]` enables `--format pdf`; without it the command
  fails with the install instruction.
- The demo notebook produces a dossier, and README documents the command.
