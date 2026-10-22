"""Engine-aware analysis-session ledger tests (v0.28 ghidra_manage):
ida_sessions carries an `engine` column, migrated in place on old DBs,
so about(sha=…) lists IDA and Ghidra sessions side by side."""
from __future__ import annotations

import sqlite3

from suspex.findings import FindingsLedger


def _old_schema_db(path) -> None:
    """Recreate the pre-v0.28 ida_sessions shape (no engine column) plus
    a live row, as a v0.18-era findings.db would carry."""
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE ida_sessions (
            ida_session_name TEXT PRIMARY KEY,
            artifact_sha TEXT DEFAULT '',
            opened_by_agent TEXT DEFAULT '',
            opened_at REAL,
            last_touched REAL,
            status TEXT DEFAULT 'live',
            on_disk_path TEXT DEFAULT ''
        );
        INSERT INTO ida_sessions
            (ida_session_name, artifact_sha, opened_by_agent,
             opened_at, last_touched, status, on_disk_path)
        VALUES ('tcpip', '', 'agent-1', 1.0, 1.0, 'live', 'x.sys');
    """)
    conn.commit()
    conn.close()


def test_engine_column_default_and_ghidra(tmp_path) -> None:
    led = FindingsLedger(tmp_path / "f.db")
    led.open_ida_session("tcpip", artifact_sha="a" * 64,
                       opened_by_agent="agent-1")
    led.open_ida_session("ghidra:tcpip", artifact_sha="a" * 64,
                         opened_by_agent="agent-2", engine="ghidra")
    rows = {r.ida_session_name: r for r in
            led.ida_sessions_for(artifact_sha="a" * 64)}
    assert rows["tcpip"].engine == "ida"
    assert rows["ghidra:tcpip"].engine == "ghidra"
    led.close()


def test_same_name_sessions_coexist_across_engines(tmp_path) -> None:
    """An IDA 'tcpip' and a Ghidra 'tcpip' must not clobber each other's
    row — the ghidra row key carries the engine prefix."""
    led = FindingsLedger(tmp_path / "f.db")
    led.open_ida_session("tcpip", artifact_sha="a" * 64,
                         opened_by_agent="agent-1")
    led.open_ida_session("ghidra:tcpip", artifact_sha="a" * 64,
                         opened_by_agent="agent-2", engine="ghidra")
    led.close_ida_session("tcpip")
    rows = {r.ida_session_name: r for r in
            led.ida_sessions_for(artifact_sha="a" * 64)}
    assert rows["tcpip"].status == "closed"
    assert rows["ghidra:tcpip"].status == "live"
    led.close()


def test_migration_adds_engine_to_old_db(tmp_path) -> None:
    """A v0.18-era findings.db gains the engine column on open; existing
    rows default to 'ida'."""
    db = tmp_path / "old.db"
    _old_schema_db(db)
    led = FindingsLedger(db)
    cols = {r["name"] for r in
            led._conn.execute("PRAGMA table_info(ida_sessions)")}
    assert "engine" in cols
    row = led._conn.execute(
        "SELECT engine FROM ida_sessions WHERE ida_session_name='tcpip'"
    ).fetchone()
    assert row["engine"] == "ida"
    # And new ghidra rows write cleanly into the migrated table.
    led.open_ida_session("ghidra:tcpip", artifact_sha="b" * 64,
                         opened_by_agent="agent-2", engine="ghidra")
    rows = led.ida_sessions_for(artifact_sha="b" * 64)
    assert rows[0].engine == "ghidra"
    led.close()
