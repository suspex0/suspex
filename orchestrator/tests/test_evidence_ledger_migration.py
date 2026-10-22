"""Ledger evidence-column migration tests (Part 3, Task 3.2).

A findings.db built with the OLD evidence schema upgrades on first open:
backup created, columns added, existing rows still readable, second open
is a no-op.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from suspex.findings import FindingsLedger
from suspex.findings.ledger import EVIDENCE_SCHEMA_VERSION

NEW_COLUMNS = ("digest", "operation", "tool", "action", "coverage_json",
               "size_bytes", "detail", "parent_id")


def _build_old_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE evidence (id TEXT PRIMARY KEY, finding_id TEXT,"
        " kind TEXT, content TEXT, created REAL)")
    conn.execute(
        "INSERT INTO evidence (id, finding_id, kind, content, created)"
        " VALUES ('oldrow1', 'finding-1', 'hexdump', '4141', 1700000000.0)")
    conn.commit()
    conn.close()


def _columns(db: Path) -> set[str]:
    conn = sqlite3.connect(str(db))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(evidence)")}
    ver = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()
    cols.add(f"user_version={ver}")
    return cols


def test_migration_adds_columns_with_backup(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    _build_old_db(db)

    led = FindingsLedger(db)
    try:
        backups = list(tmp_path.glob("findings.db.bak-*"))
        assert len(backups) == 1, f"expected one backup, got {backups}"
        # The backup holds the OLD row and the OLD shape.
        bconn = sqlite3.connect(str(backups[0]))
        old = bconn.execute(
            "SELECT id, kind FROM evidence").fetchall()
        bcols = {r[1] for r in bconn.execute("PRAGMA table_info(evidence)")}
        bconn.close()
        assert old == [("oldrow1", "hexdump")]
        assert "digest" not in bcols

        cols = _columns(db)
        for c in NEW_COLUMNS:
            assert c in cols
        assert f"user_version={EVIDENCE_SCHEMA_VERSION}" in cols

        # Existing rows still readable, extended fields defaulted.
        rows = led.evidence_for("finding-1")
        assert len(rows) == 1
        assert rows[0].kind == "hexdump"
        assert rows[0].digest == ""
        assert rows[0].detail == "complete"

        # New-style retention works on the migrated table.
        ev = led.add_evidence_record("ev_" + "a" * 32, "mem_rw", "read",
                                     "", "", 128, "complete", "",
                                     "preview-bytes")
        assert ev == "ev_" + "a" * 32
        rec = led.evidence_record(ev)
        assert rec is not None
        assert rec["tool"] == "mem_rw"
        assert rec["kind"] == "tool_result"
        # Double-retention (same digest) collapses to one row.
        led.add_evidence_record(ev, "mem_rw", "read", "", "", 128,
                                "complete", "", "preview-bytes")
        assert led.evidence_records()[0]["evidence_id"] == ev
        assert len(led.evidence_records()) == 1
        # Finding-attached evidence is NOT in the tool_result listing.
        led.add_evidence("finding-1", "note", "attached")
        assert len(led.evidence_records()) == 1
        assert len(led.evidence_for("finding-1")) == 2
    finally:
        led.close()


def test_migration_idempotent_on_reopen(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    _build_old_db(db)
    led = FindingsLedger(db)
    led.close()
    backups_after_first = list(tmp_path.glob("findings.db.bak-*"))
    assert len(backups_after_first) == 1

    led2 = FindingsLedger(db)
    try:
        assert len(list(tmp_path.glob("findings.db.bak-*"))) == 1
        rows = led2.evidence_for("finding-1")
        assert rows[0].id == "oldrow1"
    finally:
        led2.close()


def test_fresh_db_born_current_no_backup(tmp_path: Path) -> None:
    db = tmp_path / "findings.db"
    led = FindingsLedger(db)
    try:
        assert list(tmp_path.glob("findings.db.bak-*")) == []
        cols = _columns(db)
        for c in NEW_COLUMNS:
            assert c in cols
        assert led.add_evidence_record("ev_" + "b" * 32, "ida_manage",
                                       "decompile", "", "", 10,
                                       "summary", "", "p") == "ev_" + "b" * 32
    finally:
        led.close()


def test_delete_evidence_records(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "findings.db")
    try:
        e1 = "ev_" + "c" * 32
        led.add_evidence_record(e1, "mem_rw", "read", "", "", 1,
                                "complete", "", "p")
        fid = led.record(led.start_session("t"), "low", "t", "d")
        led.add_evidence(fid, "note", "attached stays")
        assert led.delete_evidence_record(e1) is True
        assert led.delete_evidence_record(e1) is False
        assert led.evidence_record(e1) is None
        led.add_evidence_record("ev_" + "d" * 32, "dump_manage", "parse",
                                "", "", 2, "complete", "", "p")
        assert led.delete_all_evidence_records() == 1
        assert led.evidence_records() == []
        # Finding-attached evidence untouched by the tool_result wipe.
        assert len(led.evidence_for(fid)) == 1
    finally:
        led.close()
