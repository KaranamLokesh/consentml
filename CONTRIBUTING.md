# Contributing to ConsentML

## Setting up

```bash
git clone https://github.com/KaranamLokesh/consentml.git
cd consentml
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running the tests

```bash
pytest
```

The Postgres connector tests (`tests/test_sources_postgres.py`) need a live
database. Without one they **error, not skip** — deliberately, so a missing
database shows up as a failure instead of quietly dropping tests from a
green run:

```bash
docker compose -f docker-compose.test.yml up -d
export CONSENTML_TEST_PG_DSN=postgresql://postgres:consentml@localhost:5432/consentml_test
pytest --cov=consentml --cov-fail-under=100
```

## The coverage gate

CI enforces 100% coverage, and that is not negotiable. ConsentML is a
compliance tool: its failure mode is not a crash, it's a false clean — a
`verify` or `migrate` run that reports everything is fine when it isn't. An
uncovered branch is a branch nobody has watched execute, and in this kind of
tool that's exactly the branch most likely to hide a bug that only shows up
against a real, tampered database.

## Building the docs

```bash
pip install -e ".[docs]"
mkdocs serve
```

`mkdocs build --strict` must pass before docs changes are merged.

## Commit style

Commits use conventional-commit prefixes, matching the existing history:
`feat:`, `fix:`, `docs:`, `test:`, `chore:`.
