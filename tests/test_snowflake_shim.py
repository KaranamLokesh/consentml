"""The persistent shim: two independent connects must share one sqlite file,
so data written under the first open is visible to the second. This models
@track (open, write, close) followed by verify_audit_log (open, read, close)."""


def test_persistent_shim_shares_state_across_connects(tmp_path):
    from tests.fakes.snowflake import persistent_shim_connect

    connect = persistent_shim_connect(tmp_path / "sf.sqlite")

    c1 = connect({"account": "a"})
    cur = c1.cursor()
    with cur:
        cur.execute("CREATE TABLE t (v VARCHAR)")
        cur.execute("INSERT INTO t (v) VALUES (?)", ("hello",))
    c1.commit()
    c1.close()

    c2 = connect({"account": "a"})
    cur = c2.cursor()
    with cur:
        cur.execute("SELECT v FROM t")
        assert cur.fetchone()[0] == "hello"
    c2.close()
