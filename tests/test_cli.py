import json
import os
import sqlite3

import pytest

from consentml.cli import main
from consentml.hashing import hash_subject_id
from consentml.store import LineageStore


@pytest.fixture
def seeded_db(tmp_path):
    db = tmp_path / "lineage.db"
    store = LineageStore(db_path=db)
    try:
        store.record_training_run(
            model_name="churn_v3",
            model_hash="beef",
            provenance={"kind": "dataframe", "label": "postgres://prod/customers"},
            subject_ids_hashed=True,
            subject_id_values=[hash_subject_id("a@x.com")],
            started_at="2026-07-01T00:00:00+00:00",
            finished_at="2026-07-01T00:01:00+00:00",
        )
    finally:
        store.close()
    return db


def test_cli_revoke_json_output(seeded_db, capsys):
    exit_code = main(
        ["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db), "--json"]
    )
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["affected_models"][0]["model_name"] == "churn_v3"
    assert data["recommended_actions"] == [
        {"model_name": "churn_v3", "action": "retrain"}
    ]


def test_cli_revoke_human_output(seeded_db, capsys):
    main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db)])
    out = capsys.readouterr().out
    assert "churn_v3" in out
    assert "retrain" in out
    assert "1 affected model" in out


def test_cli_dry_run_does_not_record(seeded_db, capsys):
    main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db), "--dry-run"])
    store = LineageStore(db_path=seeded_db)
    try:
        assert all(
            e["event_type"] != "revocation" for e in store.audit_entries()
        )
    finally:
        store.close()


def test_cli_no_affected_models(tmp_path, capsys):
    db = tmp_path / "empty.db"
    exit_code = main(["revoke", "--subject-id", "x@x.com", "--db", str(db)])
    assert exit_code == 0
    assert "0 affected models" in capsys.readouterr().out


def test_cli_verify_clean_exits_zero(seeded_db, capsys):
    exit_code = main(["verify", "--db", str(seeded_db)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Audit log OK" in out
    assert "1 entries" in out


def test_cli_verify_tampered_exits_one(seeded_db, capsys):
    conn = sqlite3.connect(seeded_db)
    try:
        with conn:
            conn.execute("UPDATE audit_log SET payload = ? WHERE id = 1",
                         ("not json{",))
    finally:
        conn.close()
    exit_code = main(["verify", "--db", str(seeded_db)])
    assert exit_code == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "malformed_payload" in out


def test_cli_verify_json_output(seeded_db, capsys):
    exit_code = main(["verify", "--db", str(seeded_db), "--json"])
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True
    assert data["findings"] == []
    assert len(data["head_hash"]) == 64


def test_cli_verify_expected_head_mismatch_exits_one(seeded_db, capsys):
    exit_code = main(
        ["verify", "--db", str(seeded_db), "--expected-head", "f" * 64]
    )
    assert exit_code == 1
    assert "head_mismatch" in capsys.readouterr().out


def test_cli_revoke_still_exits_zero(seeded_db, capsys):
    assert main(["revoke", "--subject-id", "a@x.com", "--db", str(seeded_db)]) == 0


def test_cli_verify_notes_legacy_runs(legacy_db, capsys):
    # legacy_db (see conftest.py) is a schema-v0 database whose audit
    # payloads predate provenance hashing entirely, so verifying it must
    # surface the note rather than silently reporting a clean bill of
    # health for provenance it never checked.
    exit_code = main(["verify", "--db", str(legacy_db)])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "predate provenance hashing" in out


def test_cli_verify_missing_db_exits_nonzero(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.db"
    exit_code = main(["verify", "--db", str(missing)])
    assert exit_code != 0
    out = capsys.readouterr().out
    assert "no lineage database" in out
    assert not missing.exists()


def test_cli_verify_unopenable_db_exits_two(tmp_path, capsys):
    # A directory at the db path can't be opened by sqlite3 at all, so this
    # never gets far enough to see "no database" -- it's a harder failure,
    # distinct from not_a_lineage_database (a readable file that just isn't
    # ours). verify_audit_log() lets this propagate on purpose so the CLI
    # can tell "wrong --db path" apart from "couldn't read it at all".
    unopenable = tmp_path / "not-a-db.db"
    unopenable.mkdir()
    exit_code = main(["verify", "--db", str(unopenable)])
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "Error: could not open database" in err


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores file permission bits, so chmod 000 wouldn't block reads",
)
def test_cli_verify_permission_denied_db_exits_two(tmp_path, capsys):
    # A real, valid lineage database that the process simply cannot read.
    # Distinct from not_a_lineage_database in the same way as the directory
    # case above: this is an I/O failure (fix permissions), not "wrong
    # --db path" (fix the path) -- and unlike the directory case, this one
    # actually is a lineage database, so it must not be reported as if it
    # weren't.
    unreadable = tmp_path / "lineage.db"
    LineageStore(db_path=unreadable).close()
    os.chmod(unreadable, 0o000)
    try:
        exit_code = main(["verify", "--db", str(unreadable)])
    finally:
        os.chmod(unreadable, 0o644)  # restore so tmp_path cleanup can remove it
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "Error: could not open database" in err


def test_cli_migrate_succeeds(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    assert main(["migrate", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "Migrated" in out


def test_cli_migrate_is_idempotent(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    main(["migrate", "--db", str(db)])
    capsys.readouterr()
    assert main(["migrate", "--db", str(db)]) == 0
    assert "already" in capsys.readouterr().out.lower()


def test_cli_migrate_refuses_tampered_and_exits_one(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    conn = sqlite3.connect(db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    assert main(["migrate", "--db", str(db)]) == 1
    out = capsys.readouterr().out
    assert "subject_count_mismatch" in out


def test_cli_migrate_json(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    assert main(["migrate", "--db", str(db), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["migrated"] is True
    assert data["bytes_after"] > 0


def test_cli_migrate_allow_unverified_migrates_tampered(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    conn = sqlite3.connect(db)
    with conn:
        conn.execute("DELETE FROM subject_index WHERE subject_id_hash = ?", ("h1",))
    conn.close()
    exit_code = main(["migrate", "--db", str(db), "--allow-unverified"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Migrated" in out


def test_cli_migrate_unopenable_db_exits_two(tmp_path, capsys):
    # A directory at the db path can't be opened by sqlite3 at all -- never
    # read, so this must report exit 2 (couldn't read it), the same as
    # verify's equivalent case, not exit 1 (read it, found a problem).
    unopenable = tmp_path / "not-a-db.db"
    unopenable.mkdir()
    exit_code = main(["migrate", "--db", str(unopenable)])
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "Error: could not open database" in err


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores file permission bits, so chmod 000 wouldn't block reads",
)
def test_cli_migrate_permission_denied_db_exits_two(tmp_path, capsys, build_legacy):
    # A real, valid legacy database that the process simply cannot read.
    unreadable = tmp_path / "legacy.db"
    build_legacy(unreadable)
    os.chmod(unreadable, 0o000)
    try:
        exit_code = main(["migrate", "--db", str(unreadable)])
    finally:
        os.chmod(unreadable, 0o644)  # restore so tmp_path cleanup can remove it
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "Error: could not open database" in err


def test_cli_migrate_small_db_reports_growth_accurately(tmp_path, capsys, build_legacy):
    db = tmp_path / "legacy.db"
    build_legacy(db)
    assert main(["migrate", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert "0.0 MB -> 0.0 MB" not in out
    assert "KB" in out
    assert "fixed overhead" in out


def test_format_bytes_sub_kilobyte_scale():
    """Below 1 KB, _format_bytes uses a plain byte count.

    Real database sizes never land here (SQLite's minimum page size already
    exceeds 1024 bytes), so this branch is exercised directly against the
    pure formatting function rather than through a contrived migration.
    """
    from consentml.cli import _format_bytes

    assert _format_bytes(500) == "500 bytes"


def test_format_bytes_megabyte_scale():
    from consentml.cli import _format_bytes

    assert _format_bytes(2 * 1024 * 1024) == "2.0 MB"


def test_cli_export_writes_html_by_default(seeded_db, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exit_code = main(["export", "--subject-id", "a@x.com", "--db", str(seeded_db)])
    assert exit_code == 0

    key = hash_subject_id("a@x.com")
    written = tmp_path / f"consentml-dossier-{key[:12]}.html"
    assert written.exists()
    assert "churn_v3" in written.read_text()
    assert str(written) in capsys.readouterr().out


def test_cli_export_default_filename_uses_the_hash_not_the_raw_id(
    seeded_db, tmp_path, monkeypatch
):
    """The raw identifier belongs in the document, not in a directory listing."""
    monkeypatch.chdir(tmp_path)
    main(["export", "--subject-id", "a@x.com", "--db", str(seeded_db)])
    assert not any("a@x.com" in p.name for p in tmp_path.iterdir())


def test_cli_export_honors_out(seeded_db, tmp_path):
    out = tmp_path / "dossier.html"
    assert main(
        ["export", "--subject-id", "a@x.com", "--db", str(seeded_db), "--out", str(out)]
    ) == 0
    assert out.exists()


def test_cli_export_writes_utf8_under_a_non_utf8_locale(seeded_db, tmp_path):
    """The file's bytes must match the charset the document declares.

    render_html() emits U+2014 and declares <meta charset="utf-8">, so
    writing at the platform default encoding produces a file contradicting
    its own declaration -- and on an ASCII locale raises UnicodeEncodeError
    instead of writing anything at all.

    Run in a subprocess under LC_ALL=C because the default encoding is fixed
    at interpreter start and cannot be changed from inside the test; on a
    developer's UTF-8 machine an in-process test passes either way, which is
    exactly the kind of test that lets this ship.
    """
    import os
    import subprocess
    import sys

    out = tmp_path / "dossier.html"
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from consentml.cli import main; sys.exit(main(sys.argv[1:]))",
            "export",
            "--subject-id",
            "a@x.com",
            "--db",
            str(seeded_db),
            "--out",
            str(out),
        ],
        env={**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0",
             "PYTHONCOERCECLOCALE": "0"},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    text = out.read_bytes().decode("utf-8")  # strict: fails on mojibake
    assert "—" in text
    assert 'charset="utf-8"' in text


def test_cli_export_json_to_stdout(seeded_db, capsys):
    exit_code = main(
        [
            "export", "--subject-id", "a@x.com", "--db", str(seeded_db),
            "--format", "json", "--out", "-",
        ]
    )
    assert exit_code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["subject_id"] == "a@x.com"
    assert data["affected_models"][0]["model_name"] == "churn_v3"


def test_cli_export_pdf_writes_a_pdf(seeded_db, tmp_path):
    out = tmp_path / "dossier.pdf"
    exit_code = main(
        [
            "export", "--subject-id", "a@x.com", "--db", str(seeded_db),
            "--format", "pdf", "--out", str(out),
        ]
    )
    assert exit_code == 0
    assert out.read_bytes().startswith(b"%PDF")


def test_cli_export_pdf_refuses_stdout(seeded_db, capsys):
    exit_code = main(
        [
            "export", "--subject-id", "a@x.com", "--db", str(seeded_db),
            "--format", "pdf", "--out", "-",
        ]
    )
    assert exit_code == 2
    assert "binary" in capsys.readouterr().err.lower()


def test_cli_export_exits_1_on_a_tampered_log(seeded_db, tmp_path):
    conn = sqlite3.connect(seeded_db)
    conn.execute("UPDATE audit_log SET payload = replace(payload, 'churn', 'x')")
    conn.commit()
    conn.close()

    out = tmp_path / "d.html"
    exit_code = main(
        ["export", "--subject-id", "a@x.com", "--db", str(seeded_db), "--out", str(out)]
    )
    assert exit_code == 1
    # The dossier is still written -- refusing would leave nothing to file.
    assert "FAILED" in out.read_text()


def test_cli_export_exits_1_and_creates_nothing_at_a_missing_db(tmp_path, capsys):
    missing = tmp_path / "nope.db"
    out = tmp_path / "d.html"
    exit_code = main(
        ["export", "--subject-id", "a@x.com", "--db", str(missing), "--out", str(out)]
    )
    assert exit_code == 1
    assert not missing.exists()
    assert not out.exists()
    assert "no lineage database" in capsys.readouterr().err.lower()


def test_cli_export_reports_a_missing_pdf_extra(seeded_db, tmp_path, capsys, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("reportlab"):
            raise ImportError("No module named 'reportlab'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    exit_code = main(
        [
            "export", "--subject-id", "a@x.com", "--db", str(seeded_db),
            "--format", "pdf", "--out", str(tmp_path / "d.pdf"),
        ]
    )
    assert exit_code == 2
    assert "pip install consentml[pdf]" in capsys.readouterr().err


def test_cli_export_unopenable_db_exits_two(tmp_path, capsys):
    # A directory at the db path can't be opened by sqlite3 at all -- the
    # same "couldn't read it" case verify and migrate distinguish from
    # "no database at this path" (exit 1). See their equivalent tests above.
    unopenable = tmp_path / "not-a-db.db"
    unopenable.mkdir()
    exit_code = main(
        ["export", "--subject-id", "a@x.com", "--db", str(unopenable)]
    )
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "Error: could not open database" in err
