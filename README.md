# ConsentML

Data-lineage tracking and consent-revocation reporting for production ML
pipelines. Add one decorator to your training function; when a user revokes
consent, ConsentML tells you which deployed models were trained on their data
and produces a tamper-evident audit trail.

## Verifying the audit trail

```bash
consentml verify --db lineage.db
```

Verification checks three things: that every audit entry hashes to its recorded
value, that the chain links correctly, and that the log still agrees with the
live tables. That last check is the one that matters most — it catches a
`subject_index` row deleted to hide that someone was in a training set, which
the hash chain alone cannot see.

Exit codes, so it can gate CI:

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Read the database and found problems (including: no database there) |
| 2 | Could not read the database at all |

Verification never writes. It records no audit event of its own, and it will not
create a database that isn't there — a mistyped `--db` reports a missing
database rather than silently reporting a clean, empty one.

## Anchoring

A hash chain cannot detect an attacker who rewrites the whole log from genesis
and recomputes every hash. Record the `head_hash` that `verify` reports,
somewhere outside the database, and pass it back:

```bash
consentml verify --db lineage.db --expected-head <previously recorded hash>
```

The anchor is looked up across the whole chain rather than compared to the
current head, so a log that has legitimately grown since you anchored still
verifies; only a rewrite or truncation of history reports `head_mismatch`.

This proves history up to the anchor point. It says nothing about entries
appended after it — re-anchor regularly to narrow that window.

Status: pre-release (v0 in development). MIT license.
