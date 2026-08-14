"""The published-docs term gate.

The Why pages are rewritten from a design document written for a different
audience. Prose review catches that once; a grep catches it every time,
including on edits nobody is watching.
"""

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-docs-terms.sh"


def _run(*paths):
    return subprocess.run(
        [str(SCRIPT), *[str(p) for p in paths]],
        capture_output=True,
        text=True,
    )


def test_clean_tree_passes(tmp_path):
    (tmp_path / "page.md").write_text("# ConsentML\n\nA lineage tool.\n")
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "term",
    ["EB1", "petition", "USCIS", "adjudicator", "immigration", "criterion"],
)
def test_each_forbidden_term_fails(tmp_path, term):
    (tmp_path / "page.md").write_text(f"# Why\n\nThis supports the {term}.\n")
    result = _run(tmp_path)
    assert result.returncode == 1
    assert term.lower() in (result.stdout + result.stderr).lower()


def test_matching_is_case_insensitive(tmp_path):
    """A lowercase heading anchor or URL slug must not slip past."""
    (tmp_path / "page.md").write_text("# Why\n\nsee /eb1-notes for detail.\n")
    assert _run(tmp_path).returncode == 1


def test_nothing_to_scan_is_a_failure(tmp_path):
    """A gate that silently passes because the paths moved is not a gate."""
    assert _run(tmp_path / "does-not-exist").returncode == 1
