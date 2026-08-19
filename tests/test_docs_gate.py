"""The published-docs term gate.

The gate greps published files for a project-specific forbidden-term list and
fails if any appears. The real term list is supplied out-of-band and never
committed (this repo is public), so these tests inject their own PLACEHOLDER
terms via the environment: they exercise the mechanism without putting any
sensitive word in the repo.
"""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-docs-terms.sh"

# Fake terms, meaningless on their own, used only to drive the gate.
TEST_TERMS = "forbiddenword|blockedterm"


def _env(terms=TEST_TERMS):
    env = dict(os.environ)
    if terms is None:
        env.pop("CONSENTML_DOCS_TERMS", None)
    else:
        env["CONSENTML_DOCS_TERMS"] = terms
    # Pin the file fallback at a path that cannot exist, so a maintainer's real
    # .docs-forbidden-terms never influences a test run.
    env["CONSENTML_DOCS_TERMS_FILE"] = "/nonexistent/__no_docs_terms_file__"
    return env


def _run(*paths, terms=TEST_TERMS):
    return subprocess.run(
        [str(SCRIPT), *[str(p) for p in paths]],
        capture_output=True,
        text=True,
        env=_env(terms),
    )


def test_clean_tree_passes(tmp_path):
    (tmp_path / "page.md").write_text("# ConsentML\n\nA lineage tool.\n")
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("term", ["forbiddenword", "blockedterm"])
def test_each_forbidden_term_fails(tmp_path, term):
    (tmp_path / "page.md").write_text(f"# Why\n\nThis mentions {term}.\n")
    result = _run(tmp_path)
    assert result.returncode == 1
    assert term.lower() in (result.stdout + result.stderr).lower()


def test_matching_is_case_insensitive(tmp_path):
    """A lowercase heading anchor or URL slug must not slip past."""
    (tmp_path / "page.md").write_text("# Why\n\nSee /FORBIDDENWORD-notes for detail.\n")
    assert _run(tmp_path).returncode == 1


def test_no_terms_configured_skips(tmp_path):
    """With no term list configured the gate skips (exit 0): there is nothing
    project-specific to enforce, and a contributor without the list has
    nothing to leak. The publish workflows require the secret separately."""
    (tmp_path / "page.md").write_text("This mentions forbiddenword in the open.\n")
    result = _run(tmp_path, terms=None)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "skipping" in (result.stdout + result.stderr).lower()


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
    (tmp_path / "visible.md").write_text("This mentions forbiddenword in the open.\n")
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


def test_substring_matches_do_not_trigger(tmp_path):
    """Regression test: a term appearing as a mid-word substring (no leading
    word boundary) is an ordinary word, not a forbidden term. A gate that
    forces someone to reword correct prose to appease it trains people to
    route around it."""
    (tmp_path / "page.md").write_text(
        "The overforbiddenword pattern is fine.\n"
        "A theblockedterm reference is also fine.\n"
    )
    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("word", ["forbiddenwords", "forbiddenwordy"])
def test_inflected_forms_still_trigger(tmp_path, word):
    """The leading-boundary-only rule must not narrow the gate into
    uselessness: a bare term with a trailing suffix still matches."""
    (tmp_path / "page.md").write_text(f"# Why\n\nThis mentions {word} directly.\n")
    result = _run(tmp_path)
    assert result.returncode == 1


def test_filename_containing_term_is_caught(tmp_path):
    """A file's name becomes its published URL slug, so a term in the
    filename must fail the gate even when the file's content is clean."""
    (tmp_path / "forbiddenword-notes.md").write_text("# ConsentML\n\nClean content.\n")
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "forbiddenword" in (result.stdout + result.stderr).lower()


def test_default_mode_scans_git_tracked_files(tmp_path):
    """With no arguments, the scan set comes from `git ls-files` -- every
    tracked file -- not a hardcoded path list, so a tracked file anywhere
    in the repo is covered even if it's outside the historical four paths."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    (tmp_path / "random-notes.md").write_text("This describes a forbiddenword.\n")
    subprocess.run(["git", "add", "random-notes.md"], cwd=tmp_path, check=True)

    result = subprocess.run(
        [str(SCRIPT)], cwd=tmp_path, capture_output=True, text=True, env=_env()
    )
    assert result.returncode == 1
    assert "forbiddenword" in (result.stdout + result.stderr).lower()


def test_default_mode_ignores_untracked_files(tmp_path):
    """An untracked file is not part of what ships, so `git ls-files` --
    and therefore the default scan -- must not pick it up."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    (tmp_path / "tracked.md").write_text("# ConsentML\n\nClean content.\n")
    subprocess.run(["git", "add", "tracked.md"], cwd=tmp_path, check=True)
    (tmp_path / "untracked-forbiddenword-notes.md").write_text("Also a forbiddenword.\n")

    result = subprocess.run(
        [str(SCRIPT)], cwd=tmp_path, capture_output=True, text=True, env=_env()
    )
    assert result.returncode == 0, result.stdout + result.stderr
