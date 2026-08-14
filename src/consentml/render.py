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

from consentml.errors import ConsentMLError

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


# Sections 2 and 3 report the absence of something -- no models, no recorded
# revocation. Absence is only a finding if a database was actually read. When
# none was, these say so instead: an erasure-response document that asserts
# "no models were trained on this person's data" without having read anything
# is the false clean the whole feature is built to avoid, and the dossier is
# the artifact that leaves the building. Shared constants rather than one
# string per renderer, so HTML and PDF cannot drift apart on the point.
_NO_DB_MODELS = (
    "No lineage database was read, so it could not be determined whether any "
    "models were trained on this data subject's data. This is not a finding "
    "that there were none."
)
_NO_DB_EVENTS = (
    "No lineage database was read, so it could not be determined whether this "
    "request has been processed. This is not a finding that no revocation was "
    "recorded."
)

# Stated next to the head hash in both renderers. verify.py's docstring and
# the README's anchoring section both carry this caveat; the dossier is the
# copy a third party reads, so omitting it here is where it matters most.
_HEAD_CAVEAT = (
    "Record this head hash outside the database. A hash chain alone cannot "
    "detect an attacker who rewrites the whole log from genesis and "
    "recomputes every hash, so "
    '"intact" means intact relative to this database as it stands. Comparing '
    "this head hash against one anchored earlier, elsewhere, is what detects "
    "a rewrite -- see consentml verify --expected-head."
)


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
    if not dossier.database_found:
        return f'<div class="caveat">{_NO_DB_MODELS}</div>'
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
    if not dossier.database_found:
        return f'<div class="caveat">{_NO_DB_EVENTS}</div>'
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
<p>{_HEAD_CAVEAT} It also lets any third party re-verify this log later,
independently of the organization that produced this document.</p>
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


def _plain_provenance(provenance) -> str:
    """Provenance as plain text, for the PDF renderer.

    Separate from _provenance_cell because reportlab paragraphs take a
    minimal markup dialect, not HTML -- reusing the HTML version would emit
    literal <em> tags into the document.
    """
    if provenance.get("kind") == "unreadable":
        return "unreadable - provenance is not readable text"
    label = provenance.get("label")
    if label is not None:
        return str(label)
    return json.dumps(provenance, sort_keys=True)


def _pdf_model_rows(dossier) -> list:
    """The models table as plain cell text: header row, then one row per model.

    Split out of render_pdf so a test can assert what the table actually says
    without parsing a PDF. It was tests asserting only that the bytes start
    with %PDF that let the PDF drop the Model hash column the HTML has --
    two renderings of one dossier stating different per-model facts, with the
    hash that ties a recommendation to a specific deployed artifact missing
    from the copy that gets filed.
    """
    rows = [["Model", "Training data", "Trained at", "Model hash", "Recommendation"]]
    rows += [
        [
            str(m.model_name),
            _plain_provenance(m.provenance),
            str(m.started_at),
            str(m.model_hash),
            str(m.recommendation),
        ]
        for m in dossier.affected_models
    ]
    return rows


def _pdf_story(dossier) -> list:
    """Everything the PDF says, as reportlab flowables.

    Separate from render_pdf so a test can read the document's own words:
    reportlab compresses its text streams, so an assertion against the
    output bytes can only confirm that *a* PDF was produced. Tests that could
    say no more than that are how this renderer came to omit a column the
    HTML includes and to assert things about a database it never read.
    """
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    # wordWrap="CJK" breaks between any two characters. A model hash is one
    # 64-character token with nothing to wrap on, so the default word wrap
    # would run it out of its column and off the page.
    hash_cell = ParagraphStyle(
        "ModelHash", parent=body, fontName="Courier", fontSize=7, wordWrap="CJK"
    )
    story = [
        Paragraph("Consent revocation dossier", styles["Title"]),
        Paragraph(
            f"Response to the erasure request from "
            f"<b>{_e(dossier.subject_id)}</b>",
            body,
        ),
        Paragraph(f"Subject key (SHA-256): {_e(dossier.subject_key)}", body),
        Spacer(1, 0.25 * inch),
        Paragraph("1. Audit log integrity", styles["Heading2"]),
    ]

    if not dossier.database_found:
        story.append(
            Paragraph(
                "<b>No lineage database was read.</b> "
                + "; ".join(_e(f.detail) for f in dossier.verification.findings),
                body,
            )
        )
    elif dossier.verification.ok:
        story.append(
            Paragraph(
                f"<b>Audit log VERIFIED.</b> {dossier.verification.n_entries} "
                "entries; hash chain intact and consistent with the lineage "
                "tables.",
                body,
            )
        )
    else:
        story.append(
            Paragraph(
                "<b>Audit log FAILED verification.</b> This log has been "
                "modified since it was written.",
                body,
            )
        )
        for f in dossier.verification.findings:
            story.append(Paragraph(f"- {_e(f.code)}: {_e(f.detail)}", body))

    story.append(Paragraph(f"Head hash: {_e(dossier.head_hash)}", body))
    story.append(Paragraph(_HEAD_CAVEAT, body))
    if dossier.n_legacy_runs:
        story.append(
            Paragraph(
                f"<b>Caveat:</b> {dossier.n_legacy_runs} training run(s) "
                "predate provenance hashing. Their training data source is "
                "not covered by the hash chain and was not verified.",
                body,
            )
        )

    story += [
        Spacer(1, 0.2 * inch),
        Paragraph("2. Models trained on this subject's data", styles["Heading2"]),
    ]
    if not dossier.database_found:
        story.append(Paragraph(_NO_DB_MODELS, body))
    elif not dossier.affected_models:
        story.append(
            Paragraph(
                "No models were trained on this data subject's data. No "
                "remediation is required.",
                body,
            )
        )
    else:
        header, *model_rows = _pdf_model_rows(dossier)
        rows = [[Paragraph(_e(cell), body) for cell in header]]
        rows += [
            [
                Paragraph(_e(name), body),
                Paragraph(_e(provenance), body),
                Paragraph(_e(started_at), body),
                Paragraph(_e(model_hash), hash_cell),
                Paragraph(_e(recommendation), body),
            ]
            for name, provenance, started_at, model_hash, recommendation in model_rows
        ]
        # Sums to 6.7in, the printable width between the margins set above.
        table = Table(
            rows,
            colWidths=[1.2 * inch, 1.7 * inch, 1.25 * inch, 1.15 * inch, 1.4 * inch],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(table)

    story += [
        Spacer(1, 0.2 * inch),
        Paragraph("3. Recorded processing of this request", styles["Heading2"]),
    ]
    if not dossier.database_found:
        story.append(Paragraph(_NO_DB_EVENTS, body))
    elif not dossier.revocation_events:
        story.append(
            Paragraph(
                "No revocation event has been recorded for this subject.", body
            )
        )
    else:
        for e in dossier.revocation_events:
            story.append(
                Paragraph(
                    f"{_e(e['timestamp'])} - {_e(e['n_affected_runs'])} "
                    f"affected run(s) - entry hash {_e(e['entry_hash'])}",
                    body,
                )
            )

    story += [
        Spacer(1, 0.3 * inch),
        Paragraph(
            f"Generated {_e(dossier.generated_at)} by ConsentML "
            f"{_e(dossier.consentml_version)}. ConsentML is a lineage and "
            "reporting tool: it identifies which models a data subject's data "
            "reached and records what the operator decided. It does not modify "
            "models or delete data.",
            styles["Italic"],
        ),
    ]

    return story


def render_pdf(dossier) -> bytes:
    """The dossier as a PDF. Requires the optional [pdf] extra.

    reportlab is imported here rather than at module scope so that importing
    consentml -- or rendering HTML -- never requires the extra. The
    ImportError is translated into a ConsentMLError naming the exact install
    command, because a raw traceback mentioning 'reportlab' does not tell an
    operator what to do about it. This function is the only entry point, so
    catching it here also covers the imports inside _pdf_story().
    """
    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate
    except ImportError as exc:
        raise ConsentMLError(
            "PDF output needs the optional 'pdf' extra: "
            "pip install consentml[pdf]"
        ) from exc

    import io

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        title=f"Consent revocation dossier - {dossier.subject_id}",
        leftMargin=0.9 * inch,
        rightMargin=0.9 * inch,
    )
    doc.build(_pdf_story(dossier))
    return buffer.getvalue()
