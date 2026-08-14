# Documentation Site Design

Status: approved 2026-08-14

A MkDocs Material site covering what the README cannot hold without bloating:
the rationale, the threat model, the standards mapping, per-connector guides,
and a generated API reference.

This is the last substantial Month 2 deliverable. It is what a stranger lands
on after finding the project, so it is a credibility surface as much as a
reference.

## Division of labour with the README

The README keeps its current job and its current length: install, the four
commands, worked examples. It gains links into the site. It must keep working
standalone, because GitHub and PyPI render it and neither renders the site.

The site carries what a README cannot hold: the rationale, the threat model,
standards mapping, per-connector guides, and the generated API reference. The
two `getting-started` pages expand README sections that are currently
compressed; the README links to them rather than repeating them.

Content is never duplicated verbatim between the two. Where a page covers the
same ground as a README section, the site page is the longer treatment and the
README stays the summary.

## Non-goals

- No versioned docs (`mike`). Pre-1.0 with a single release; a version switcher
  on a one-version project is noise.
- No blog, changelog page, or search plugin beyond Material's built-in search.
- No custom theme or brand design. Material's defaults, unmodified.
- No rendering of the demo notebook into the site (`mkdocs-jupyter`). The
  notebook links out to GitHub, which renders it well already.
- No API docs for private functions. mkdocstrings covers the public API only.

## The EB1 constraint

**The Why material is rewritten from the v0 design specification, never pasted
from it.**

That spec lives in Google Docs and is framed for an immigration petition — §3
opens by stating the section is mandatory for the EB1 originality argument and
must be defensible against an immigration adjudicator. The substance is
publishable and is the strongest prose available for these pages. The framing
is not, and this is the first time that material moves from a private document
into files that ship in a repo that goes public at launch.

Prose review is not sufficient protection, because the risk is a later edit by
someone not thinking about it. The build therefore carries a mechanical gate
(see CI, below): a **case-insensitive** grep across the docs sources for `EB1`,
`petition`, `USCIS`, `adjudicator`, `immigration`, and `criterion`, failing the
build on any hit.

Case-insensitivity matters — `eb1` in a lowercase heading anchor or a URL slug
would slip past a case-sensitive match. The term list deliberately excludes
`evidence`, which has legitimate uses in audit-trail prose and would false-
positive constantly; the six chosen terms have no plausible use in library
documentation.

The gate covers `docs-site/`, `mkdocs.yml`, `README.md`, and `CONTRIBUTING.md`.
It deliberately does NOT cover `docs/superpowers/`, which holds internal specs
and plans that legitimately discuss project context and are not published.

## Site structure

Four top-level sections, each answering a different reader's question. Both
audiences self-serve: the engineer evaluating `pip install` lives in Getting
started and Reference; the compliance-minded reader lives in Why and the threat
model.

```
Home
Getting started/  quickstart, tracking a run, your first dossier
Guides/           postgres, migrating, anchoring, ci
Reference/        cli, api, schema
Why ConsentML     why, threat-model
```

### Page inventory

| Page | Content | Source |
|---|---|---|
| `index.md` | One-paragraph statement, a short `@track` example, install, links into the three paths | New, adapted from the README opening |
| `getting-started/quickstart.md` | Install → track a run → revoke → export a dossier, end to end | Adapted from README and the demo notebook |
| `getting-started/tracking.md` | `@track`, the `Source` protocol, `DataFrameSource`, what provenance records | README "Tracking a training run", expanded |
| `getting-started/first-dossier.md` | `export`, the three formats, how to read the document | README "Export a dossier", expanded |
| `guides/postgres.md` | `PostgresSource`, read-only enforcement, EXPLAIN-derived referenced tables, credential handling | New; source is `sources/postgres.py` |
| `guides/migrating.md` | v0/v1 → v2, what migration touches, the backup it keeps | README "Upgrading an existing database" |
| `guides/anchoring.md` | Why a head hash needs an external anchor; `--expected-head` | README "Anchoring", expanded |
| `guides/ci.md` | Exit codes as a CI gate, with a worked GitHub Actions example | New |
| `reference/cli.md` | All four commands, every flag, the exit-code contract | New; source is `cli.py` |
| `reference/api.md` | Public API, generated | mkdocstrings |
| `reference/schema.md` | The four tables, the hash chain, what is hashed into the audit payload | New; source is `store.py` |
| `why/index.md` | The two questions organisations cannot answer; reporting-not-deletion and why; a compact comparison table; a short NIST/GDPR/CCPA mapping table | Rewritten from design spec §2, §3, §4, §9 |
| `why/threat-model.md` | What it protects against, what it explicitly does not, trust assumptions | Rewritten from design spec §8 |

Thirteen pages. Every page has one job.

`threat-model.md` stays standalone and stays complete. It is the page that says
this is not a security tool against an adversarial operator and not a substitute
for differential privacy. A reader needs that before relying on the output, and
trimming it is the one cut here that would cost credibility rather than remove
noise.

The Why material is deliberately two pages rather than five. Prior art shrinks
from an argument to a table: a long defence of originality is the wrong
register for library documentation, whatever its merits elsewhere.

## Build and tooling

MkDocs with the Material theme. Sources live in a new `docs-site/` tree;
`mkdocs.yml` sits at the repo root.

`docs-site/` rather than `docs/` because `docs/superpowers/` already holds
internal specs and plans. Those are private working documents. Pointing MkDocs
at `docs/` would publish them.

Dependencies go in a new `docs` optional extra — `mkdocs`, `mkdocs-material`,
`mkdocstrings[python]` — mirroring how `pdf` and `postgres` are already gated.
Runtime dependencies stay `pandas>=2.0`.

All builds run `--strict`, so broken internal links and unresolvable
mkdocstrings references fail the build instead of shipping as 404s.

## CI and deployment

A separate `.github/workflows/docs.yml`. Separate from `ci.yml` because the
triggers and cadence differ.

**Leak gate**, first step, before anything else: the grep described above.
Failing first means a leak never reaches a built artifact.

**Build job**, on every pull request and every push to `main`: install
`.[docs]`, run `mkdocs build --strict`.

**Deploy job**, on push to `main` only, guarded by
`if: github.event.repository.private == false`.

While the repository is private the deploy is a no-op. When it flips public at
launch, the next push deploys with no workflow edit required — the alternative
is editing CI during launch week, which is the worst possible time.

### Manual step, owner action required

GitHub Pages must be pointed at the `gh-pages` branch in the repository's
settings. This is an account-settings change and is the repository owner's to
make. Without it the deploy job succeeds and the site 404s.

## Repo hygiene

Folded into this change because each piece is small and all of it is
prerequisite to the repo being read by strangers:

- `CONTRIBUTING.md` — dev setup, running the suite including the Docker
  Postgres, the 100% coverage gate and why it is not negotiable, commit style.
  This was a Week 8 roadmap deliverable and does not exist.
- `.github/ISSUE_TEMPLATE/bug_report.md` and `feature_request.md`.
- `.github/pull_request_template.md`.

## Verification

- `mkdocs build --strict` exits clean.
- The leak grep returns no matches across `docs-site/`, `mkdocs.yml`,
  `README.md`, and `CONTRIBUTING.md`.
- Every nav entry resolves to a file that exists, and no page under
  `docs-site/` is missing from the nav.
- mkdocstrings renders every public symbol without warnings.
- The existing test suite still passes at 100% coverage. Nothing in this change
  touches `src/`, so a failure here means something unintended happened.
- The site is served locally and inspected in a browser: navigation, rendered
  API pages, code blocks, and behaviour at mobile width. A docs site is not
  verified by a build command exiting 0.

## Done when

- `mkdocs build --strict` passes locally and in CI.
- The leak gate passes, and fails when a forbidden term is deliberately
  introduced as a test.
- All thirteen pages exist, are reachable from the nav, and contain real
  content — no placeholders.
- `CONTRIBUTING.md`, both issue templates, and the PR template exist.
- The README links into the site without duplicating it.
- The site has been viewed in a browser and looks right.
- The deploy workflow is committed and correctly gated; the Pages setting is
  documented as an owner action.
