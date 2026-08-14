# CLI reference

Four subcommands: `revoke`, `verify`, `migrate`, `export`. All read `--db`
the same way — a path you pass, or `~/.consentml/lineage.db` if you don't —
and all accept `--json` (where noted) to emit the same report as structured
JSON instead of the printed summary.

## revoke

Reports which recorded training runs a subject's data reached, with a
per-model recommendation, and — unless `--dry-run` is given — appends a
revocation event to the audit log.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--subject-id` | required | The raw subject identifier to look up. |
| `--db` | `~/.consentml/lineage.db` | Lineage database path. |
| `--dry-run` | off | Report only; do not record a revocation event. |
| `--json` | off | Emit JSON instead of the printed summary. |

```bash
consentml revoke --subject-id p2 --db lineage.db --dry-run
```

```
1 affected model for subject 3946ca64ff78…
  - readmission-risk  run=e8240888  trained=2026-08-14T04:00:04.211248+00:00  recommendation=retrain
Dry run: nothing recorded.
```

`revoke` provisions a database at `--db` if nothing exists there yet, the
same way `@track` does on first use — `--dry-run` doesn't change this, it
only skips the audit-log write. A mistyped path is not reported as an
error: it silently creates an empty database, then reports `0 affected
models` against it, with a normal exit code. Confirm the path points at the
database you actually mean to query before trusting a `0 affected models`
result — `verify` against the same path would report `missing_database`
instead.

## verify

Checks the audit log independently of any one subject: that every entry
still hashes to its recorded value, that the chain links correctly, and
that the log agrees with the live tables.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--db` | `~/.consentml/lineage.db` | Lineage database path. |
| `--expected-head` | none | A previously anchored `head_hash`; detects a wholesale rewrite of the log. |
| `--json` | off | Emit JSON instead of the printed summary. |

```bash
consentml verify --db lineage.db --expected-head "$CONSENTML_ANCHOR"
```

```
Audit log OK: 1 entries, chain intact.
head: 85d36e6f5c1ff020f9bd0221e1069294c983baa51b080d20f1a1ba101e747eff
```

## migrate

Upgrades a v0 or v1 lineage database onto the current schema. Gated by
verification on both sides — it refuses to run against a database that
fails verification, and only swaps the migrated copy into place once that
copy verifies clean in turn.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--db` | `~/.consentml/lineage.db` | Lineage database path. |
| `--allow-unverified` | off | Migrate even if the database fails verification (not recommended). |
| `--json` | off | Emit JSON instead of the printed summary. |

```bash
consentml migrate --db lineage.db
```

```
Migrated: 28.0 KB -> 40.0 KB (+12.0 KB).
The new schema's tables and indexes add fixed overhead; deduplication only pays off once subjects repeat across many runs.
Original kept at lineage.db.pre-migration.bak
```

## export

Builds a per-subject dossier — audit-log integrity, affected models, and
any revocation already on record — and writes it to a file, or to stdout
with `--out -`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--subject-id` | required | The raw subject identifier to look up. |
| `--db` | `~/.consentml/lineage.db` | Lineage database path. |
| `--format` | `html` | Output format: `html`, `json`, or `pdf`. `pdf` needs the `consentml[pdf]` extra. |
| `--out` | `consentml-dossier-<subject-key-prefix>.<ext>` in the working directory | Output path; `-` writes to stdout (`html`/`json` only, not `pdf`). |

```bash
consentml export --subject-id p2 --db lineage.db
```

```
Wrote /path/to/your/directory/consentml-dossier-3946ca64ff78.html
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Clean: no problems found. |
| 1 | Problems were found. For `verify` and `migrate`, that's a verification finding, a missing database, a migration refused, or a file that opens fine as SQLite but isn't a ConsentML lineage database — a 0-byte file or a foreign SQLite database report `not_a_lineage_database` the same way. For `export`, a dossier is still written and reports the problem in its own verification section — unless there was no lineage database at the given path, in which case nothing is written at all. `revoke` never exits 1: it always reports what it found, whether or not the subject affected any model. |
| 2 | The database could not be read at all — a bad path, a permission error, bytes that genuinely aren't a SQLite database — or `--format pdf` was used without the `consentml[pdf]` extra installed. |

The missing-database case is exit 1, not 2, but it isn't "the database was
read and problems were found" either: `verify` checks whether the path
exists before it ever opens anything, and reports `missing_database` without
reading a byte. `export` shares that same check, which is why it's the one
case where exit 1 produces no dossier — there's nothing built yet to write.

A file that exists and opens as SQLite, but isn't one of ours — an empty
file, or a database from something else entirely — is also exit 1, reported
as `not_a_lineage_database`. It's a distinct code from `missing_database` on
purpose: the fixes differ (wrong path vs. wrong file), and someone debugging
"missing database" against a file that plainly exists would look in the
wrong place. Exit 2 is reserved for paths that can't be opened as SQLite at
all.
