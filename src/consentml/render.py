"""Dossier renderers.

Three functions, each taking a Dossier and returning a document. They read
nothing from the database -- everything they need was assembled by
build_dossier() -- which is what lets the dossier's contents be tested
against data structures rather than against rendered strings.

Every database-derived value passes through html.escape() in the HTML
renderer. Model names and provenance labels are arbitrary text an operator's
own pipeline supplied, this document is emailed to third parties, and an
artifact whose entire value is being trustworthy cannot also be a script
injection vector.
"""

import html
import json

_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 2rem auto; max-width: 50rem; line-height: 1.5; color: #111; }
h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
h2 { font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #ddd;
     padding-bottom: 0.25rem; }
table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee;
         vertical-align: top; font-size: 0.9rem; }
th { background: #fafafa; }
.verdict-ok { background: #e8f5e9; border-left: 4px solid #2e7d32;
              padding: 0.75rem 1rem; }
.verdict-fail { background: #ffebee; border-left: 4px solid #c62828;
                padding: 0.75rem 1rem; }
.caveat { background: #fff8e1; border-left: 4px solid #f9a825;
          padding: 0.75rem 1rem; margin-top: 1rem; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        font-size: 0.8rem; word-break: break-all; }
footer { margin-top: 3rem; color: #666; font-size: 0.8rem; }
"""


def render_json(dossier) -> str:
    """The dossier as indented JSON."""
    return json.dumps(dossier.to_dict(), indent=2, sort_keys=True)


def _e(value) -> str:
    """Escape any value for HTML text content."""
    return html.escape(str(value))


def _provenance_cell(provenance) -> str:
    """Human-readable provenance.

    Always a dict: revoke()._parse_provenance() normalizes every stored form
    into one, including {"kind": "unreadable"} for provenance that is not
    readable text (tampered, or a BLOB). That case must render as a visible
    statement rather than an empty cell, which would read as "nothing to see
    here" for exactly the condition an auditor needs to notice.

    DataFrameSource provenance carries a "label"; PostgresSource provenance
    does not -- it carries the query, its digest, and the referenced tables --
    so the fallback dumps the whole record. Both shapes reach here in
    practice, which is why neither branch is dead.
    """
    if provenance.get("kind") == "unreadable":
        return "<em>unreadable — provenance is not readable text</em>"
    label = provenance.get("label")
    if label is not None:
        return _e(label)
    return _e(json.dumps(provenance, sort_keys=True))


def _verdict_block(dossier) -> str:
    if not dossier.database_found:
        detail = "; ".join(_e(f.detail) for f in dossier.verification.findings)
        return (
            '<div class="verdict-fail"><strong>No lineage database was '
            f"read.</strong><br>{detail}</div>"
        )
    if dossier.verification.ok:
        return (
            '<div class="verdict-ok"><strong>Audit log VERIFIED.</strong><br>'
            f"{dossier.verification.n_entries} entries; hash chain intact and "
            "consistent with the lineage tables.</div>"
        )
    rows = "".join(
        f"<li><code>{_e(f.code)}</code> — {_e(f.detail)}</li>"
        for f in dossier.verification.findings
    )
    return (
        '<div class="verdict-fail"><strong>Audit log FAILED '
        "verification.</strong><br>This log has been modified since it was "
        f"written. The findings below are unresolved.<ul>{rows}</ul></div>"
    )


def _models_section(dossier) -> str:
    if not dossier.affected_models:
        return (
            "<p>No models were trained on this data subject's data. No "
            "remediation is required.</p>"
        )
    rows = "".join(
        "<tr>"
        f"<td>{_e(m.model_name)}</td>"
        f"<td>{_provenance_cell(m.provenance)}</td>"
        f"<td>{_e(m.started_at)}</td>"
        f'<td class="mono">{_e(m.model_hash)}</td>'
        f"<td>{_e(m.recommendation)}</td>"
        "</tr>"
        for m in dossier.affected_models
    )
    return (
        "<table><thead><tr><th>Model</th><th>Training data</th>"
        "<th>Trained at</th><th>Model hash</th><th>Recommendation</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _events_section(dossier) -> str:
    if not dossier.revocation_events:
        return (
            "<p>No revocation event has been recorded for this subject. The "
            "request has not yet been processed through "
            "<code>consentml revoke</code>.</p>"
        )
    rows = "".join(
        "<tr>"
        f"<td>{_e(e['timestamp'])}</td>"
        f"<td>{_e(e['n_affected_runs'])}</td>"
        f'<td class="mono">{_e(e["entry_hash"])}</td>'
        "</tr>"
        for e in dossier.revocation_events
    )
    return (
        "<table><thead><tr><th>Recorded at</th><th>Affected runs</th>"
        f"<th>Audit entry hash</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _caveats(dossier) -> str:
    if not dossier.n_legacy_runs:
        return ""
    return (
        f'<div class="caveat"><strong>{dossier.n_legacy_runs} training '
        "run(s) predate provenance hashing.</strong> Their recorded training "
        "data source is not covered by the audit log's hash chain and was "
        "not verified. Run <code>consentml migrate</code> to bring the "
        "database onto the current schema.</div>"
    )


def render_html(dossier) -> str:
    """A self-contained HTML dossier. No external assets, prints to PDF."""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Consent revocation dossier — {_e(dossier.subject_id)}</title>
<style>{_CSS}</style></head><body>
<h1>Consent revocation dossier</h1>
<p>Response to the erasure request from
<strong>{_e(dossier.subject_id)}</strong></p>
<p class="mono">Subject key (SHA-256): {_e(dossier.subject_key)}</p>

<h2>1. Audit log integrity</h2>
{_verdict_block(dossier)}
<p class="mono">Head hash: {_e(dossier.head_hash)}</p>
<p>Record this head hash outside the database. It lets any third party
re-verify this log later, independently of the organization that produced
this document.</p>
{_caveats(dossier)}

<h2>2. Models trained on this subject's data</h2>
{_models_section(dossier)}

<h2>3. Recorded processing of this request</h2>
{_events_section(dossier)}

<footer>Generated {_e(dossier.generated_at)} by ConsentML
{_e(dossier.consentml_version)}. ConsentML is a lineage and reporting tool:
it identifies which models a data subject's data reached and records what the
operator decided. It does not modify models or delete data.</footer>
</body></html>
"""
