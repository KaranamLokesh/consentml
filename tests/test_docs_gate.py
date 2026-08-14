"""The published-docs term gate.

The Why pages are rewritten from a design document written for a different
audience. Prose review catches that once; a grep catches it every time,
including on edits nobody is watching.
"""

import os
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


def test_unreadable_subdirectory_with_term_fails(tmp_path):
    """grep exits >1 (not 0) when a subdirectory can't be opened, even if it
    already found a match elsewhere. That must not be read as clean."""
    if os.geteuid() == 0:
        pytest.skip("root bypasses permission bits")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "page.md").write_text("nothing\n")
    (tmp_path / "visible.md").write_text("This mentions EB1 in the open.\n")
    sub.chmod(0o000)
    try:
        assert _run(tmp_path).returncode == 1
    finally:
        sub.chmod(0o755)  # restore so pytest can clean up tmp_path


def test_empty_directory_is_a_failure(tmp_path):
    """An existing-but-empty directory must not read as clean: that's the
    exact case of docs-site being emptied by a bad rename or build step."""
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _run(empty).returncode == 1


def test_directory_with_no_forbidden_terms_passes(tmp_path):
    """Regression guard: the emptiness/error fixes must not make the gate
    fail closed on an ordinary, populated, clean directory."""
    (tmp_path / "a.md").write_text("# ConsentML\n\nA lineage tool.\n")
    (tmp_path / "b.md").write_text("# More docs\n\nStill fine.\n")
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
