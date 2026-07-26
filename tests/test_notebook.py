"""Execute the demo notebook end to end.

The notebook reaches below the public API -- it tampers with the database
using raw SQL to demonstrate what verification catches -- so a schema change
can break it while every other test stays green. That happened once: the
week-8 interning change left the notebook raising OperationalError, and it
was merged and pushed before anyone ran it.

Running it here means `pytest` catches that, not a reader.
"""

from pathlib import Path

import nbformat
from nbclient import NotebookClient

NOTEBOOK = Path(__file__).resolve().parents[1] / "examples" / "consentml_demo.ipynb"


def test_demo_notebook_runs_clean(tmp_path):
    """Every cell executes without error.

    The kernel runs in tmp_path so the notebook's `lineage.db` is written
    there rather than into the repo. The setup cell is Colab-guarded and
    installs nothing outside Colab, so this does not touch the environment.
    """
    nb = nbformat.read(NOTEBOOK, as_version=4)
    NotebookClient(
        nb,
        timeout=300,
        kernel_name="python3",
        resources={"metadata": {"path": str(tmp_path)}},
    ).execute()


def test_demo_notebook_still_demonstrates_detection(tmp_path):
    """The notebook's point survives, not just its syntax.

    A notebook can run cleanly while having quietly stopped demonstrating
    anything -- if the tamper cell no longer matches real rows, verification
    reports nothing and the narrative silently becomes false. Assert the
    findings the demo claims to show actually appear in its output.
    """
    nb = nbformat.read(NOTEBOOK, as_version=4)
    NotebookClient(
        nb,
        timeout=300,
        kernel_name="python3",
        resources={"metadata": {"path": str(tmp_path)}},
    ).execute()

    output = "\n".join(
        "".join(o.get("text", "") for o in cell.get("outputs", []))
        for cell in nb.cells
        if cell.cell_type == "code"
    )

    # The deleted-subject attack the hash chain alone cannot see.
    assert "subject_count_mismatch" in output
    # The edited-payload attack the chain does catch.
    assert "entry_hash_mismatch" in output
    # And a clean run reported clean before any tampering.
    assert "ok:       True" in output
