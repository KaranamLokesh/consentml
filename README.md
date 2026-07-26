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

`verify` and `migrate` share this contract: `migrate` exits 1 when it refuses to
migrate (including onto a missing database) and 0 once migrated or already
current. `revoke` does not use it — it always reports what it found and exits
0, whether or not the subject affected any models or the database exists yet;
it only exits 2 if the database cannot be read at all.

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

## Upgrading an existing database

Databases created before the interned-storage schema need a one-time upgrade:

```bash
consentml migrate --db lineage.db
```

Migration verifies the audit log before it starts and **refuses to run** if
verification fails — rewriting a tampered database would launder the tampering.
The new database is built alongside the original and only swapped in once it
verifies clean, so a failure leaves the original untouched. The original is kept
as `<name>.pre-migration.bak`; delete it once you are satisfied. Migration
temporarily needs room for two copies of the database.

Until a database is migrated it can be read but not written to, so `@track` and
a recording `revoke()` will raise. `consentml verify` and
`revoke(dry_run=True)` keep working.

Status: pre-release (v0 in development). MIT license.
