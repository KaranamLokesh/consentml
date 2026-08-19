# Changelog

All notable changes to ConsentML are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-08-17

### Added
- **Snowflake support**, in two independent pieces (both opt-in, Python-API
  only; the CLI stays SQLite-only):
  - `SnowflakeSource` — read a training set out of Snowflake with arbitrary
    SELECT SQL, with credential-free provenance and best-effort referenced
    tables via `EXPLAIN USING JSON`. Mirrors `PostgresSource`.
  - `SnowflakeLineageStore` — persist the hash-chained audit log in Snowflake.
    The audit-log row shape and `entry_hash` formula are byte-for-byte
    identical to the SQLite backend, so the same code verifies either.
- `open_store(target)` factory and a pluggable `LineageStore` interface; the
  former SQLite store is now `SQLiteLineageStore` (default, unchanged).
- `@track(..., store=...)` and `verify_audit_log(store=...)` accept a store
  target, so a run's lineage can be written to and verified in Snowflake (pass
  a connection dict). `store=` and `db_path=` are mutually exclusive.
- `install: consentml[snowflake]` optional extra (adds
  `snowflake-connector-python`; never imported at package import time).
- Docs: a Snowflake guide, plus API reference for the sources and store
  backends.

### Notes
- The Snowflake lineage store assumes a single logical writer per lineage
  table; coordinating concurrent writers is an explicit non-goal.
- Snowflake exposes no connection-level read-only flag, so `SnowflakeSource`
  cannot enforce read-only — supply a role with read-only grants.

## [0.1.1] - 2026-08-16

### Added
- Audit dossier export (`build_dossier`, HTML/JSON/PDF renderers) and the
  documentation site.

## [0.1.0]

- Initial release: `@track`, hash-chained lineage store, subject-ID hashing,
  `revoke()` + affected-models report, `verify_audit_log`, schema interning +
  migration, the Postgres connector, and the `consentml` CLI.

[0.2.0]: https://github.com/KaranamLokesh/consentml/releases/tag/v0.2.0
[0.1.1]: https://github.com/KaranamLokesh/consentml/releases/tag/v0.1.1
[0.1.0]: https://github.com/KaranamLokesh/consentml/releases/tag/v0.1.0
