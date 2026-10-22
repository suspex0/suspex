"""v0.18 shared-knowledge-base tests: migration, about, search, dedupe,
breadcrumbs, backfill. Uses only the ledger's public surface — the MCP
tool wrapper is thin passthrough exercised by the migration test."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from suspex.findings import FindingsLedger, _FINDINGS_V2_COLUMNS


# ------------------------------------------------------------ schema migration ----

def _make_legacy_db(path: Path) -> None:
    """Build a pre-v0.18 findings.db (three tables, no v2 columns)."""
    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE sessions (id TEXT PRIMARY KEY, target TEXT,
                                started REAL, notes TEXT);
        CREATE TABLE findings (id TEXT PRIMARY KEY, session_id TEXT,
                                severity TEXT, title TEXT, description TEXT,
                                status TEXT DEFAULT 'open', refs TEXT DEFAULT '',
                                created REAL, updated REAL);
        CREATE TABLE evidence (id TEXT PRIMARY KEY, finding_id TEXT,
                                kind TEXT, content TEXT, created REAL);
    """)
    conn.execute("INSERT INTO sessions VALUES ('sess1', 'lab-vm-07', 1000, '')")
    conn.execute(
        "INSERT INTO findings (id, session_id, severity, title, description,"
        " status, refs, created, updated) VALUES"
        " ('f00000000001', 'sess1', 'high', 'old title', 'old body',"
        "  'open', 'refs:legacy', 1000, 1000)")
    conn.execute(
        "INSERT INTO evidence VALUES ('e00000000001', 'f00000000001',"
        " 'note', 'legacy evidence', 1000)")
    conn.commit()
    conn.close()


def test_migration_adds_v2_columns_without_data_loss(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    _make_legacy_db(db)
    # Open through v0.18 ledger → migration runs
    led = FindingsLedger(db)
    cols = {r["name"] for r in led._conn.execute("PRAGMA table_info(findings)")}
    for name, _typ, _default in _FINDINGS_V2_COLUMNS:
        assert name in cols, f"missing v2 column {name}"
    tables = {r[0] for r in led._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for t in ("artifacts", "artifact_aliases", "notes", "tool_events",
              "ida_sessions"):
        assert t in tables, f"missing v2 table {t}"
    # legacy rows survived
    rows = led.list_findings("sess1")
    assert len(rows) == 1 and rows[0].title == "old title"
    assert len(led.evidence_for("f00000000001")) == 1
    led.close()


def test_migration_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    _make_legacy_db(db)
    for _ in range(3):
        led = FindingsLedger(db)
        cols = {r["name"] for r in led._conn.execute("PRAGMA table_info(findings)")}
        assert "artifact_sha" in cols
        led.close()


# --------------------------------------------------------------------- about ----

def test_about_requires_at_least_one_scope(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "x.db")
    with pytest.raises(ValueError):
        led.about()
    led.close()


def test_about_by_sha_returns_findings_notes_events(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "x.db")
    sha = "a" * 64
    led.upsert_artifact(sha, name="foo.sys", kind="sys", size=100,
                        origin="test", alias="foo.sys")
    sid = led.start_session("192.168.1.1:50074")
    led.record(sid, "high", "buggy dispatch", "details",
               agent_id="agentA", artifact_sha=sha, module="foo.sys")
    led.annotate("interesting VMT layout", agent_id="agentB",
                 artifact_sha=sha, module="foo.sys", kind="hypothesis")
    led.event("ida_manage", "decompile", agent_id="agentB", artifact_sha=sha,
              module="foo.sys", summary="decompile(0x140010200)")
    result = led.about(sha=sha)
    assert len(result["artifacts"]) == 1
    assert result["artifacts"][0]["sha256"] == sha
    assert result["artifacts"][0]["findings_count"] == 1
    assert result["artifacts"][0]["notes_count"] == 1
    assert len(result["findings"]) == 1
    assert result["findings"][0]["agent_id"] == "agentA"
    assert len(result["notes"]) == 1
    assert result["notes"][0]["kind"] == "hypothesis"
    assert len(result["events"]) == 1
    led.close()


def test_about_by_alias_returns_multiple_versions(tmp_path: Path) -> None:
    """Two shas under the same alias → about(alias=…) returns both."""
    led = FindingsLedger(tmp_path / "x.db")
    for sha in ("a" * 64, "b" * 64):
        led.upsert_artifact(sha, name="nvlddmkm.sys", kind="sys",
                            size=1000, origin="test", alias="nvlddmkm.sys")
        sid = led.start_session("lab")
        led.record(sid, "info", f"nv @ {sha[:6]}", "body",
                   artifact_sha=sha, module="nvlddmkm.sys")
    result = led.about(alias="nvlddmkm.sys")
    assert len(result["artifacts"]) == 2
    assert len(result["findings"]) == 2
    led.close()


# --------------------------------------------------------------------- dedupe ----

def test_record_ex_dedupes_on_open_signature(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "x.db")
    sha = "c" * 64
    sid = led.start_session("t")
    fid1, dup1 = led.record_ex(sid, "high", "same title", "body v1",
                                artifact_sha=sha, address="0x1000",
                                dedupe=True)
    assert dup1 is None
    fid2, dup2 = led.record_ex(sid, "high", "same title", "body v2",
                                artifact_sha=sha, address="0x1000",
                                dedupe=True)
    assert dup2 == fid1
    assert fid2 == fid1
    # dedupe=false forces a new row
    fid3, dup3 = led.record_ex(sid, "high", "same title", "body v3",
                                artifact_sha=sha, address="0x1000",
                                dedupe=False)
    assert dup3 is None
    assert fid3 != fid1
    assert len(led.list_findings(sid)) == 2
    led.close()


# ---------------------------------------------------------------- fts search ----

def test_search_returns_snippets_by_relevance(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "x.db")
    if not led.fts_available():
        pytest.skip("fts5 unavailable")
    sid = led.start_session("t")
    led.record(sid, "high", "pool tag hijack in Ndis dispatcher",
               "detailed exploration of pool tag XYZ mismatch",
               agent_id="a1")
    led.annotate("random unrelated note about USB descriptors",
                 agent_id="a2", kind="context")
    hits = led.search("pool tag")
    kinds = {h["kind"] for h in hits}
    assert "finding" in kinds
    # snippet() reads the body column; either the finding OR the note
    # (which doesn't match) shows up, so we just assert on the source
    # title enrichment coming from the referenced row.
    finding_hit = next(h for h in hits if h["kind"] == "finding")
    assert "pool tag" in (finding_hit.get("source_title") or "").lower() \
        or "pool tag" in (finding_hit.get("snippet") or "").lower()
    led.close()


# ---------------------------------------------------------------- artifacts ----

def test_artifacts_list_and_aliases(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "x.db")
    sha1 = "a" * 64
    sha2 = "b" * 64
    led.upsert_artifact(sha1, name="foo.sys", kind="sys", size=100,
                        origin="test", alias="foo.sys")
    led.upsert_artifact(sha1, alias="foo_v1")  # second alias
    led.upsert_artifact(sha2, name="bar.dll", kind="dll", size=200,
                        origin="test", alias="bar.dll")
    all_arts = led.artifacts_list()
    assert len(all_arts) == 2
    foo = next(a for a in all_arts if a.sha256 == sha1)
    assert set(foo.aliases) >= {"foo.sys", "foo_v1"}
    # search by alias returns the right sha
    hits = led.artifacts_list(alias="foo_v1")
    assert len(hits) == 1 and hits[0].sha256 == sha1
    led.close()


# ---------------------------------------------------------- ida_sessions ----

def test_ida_session_lifecycle(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "x.db")
    sha = "d" * 64
    led.upsert_artifact(sha, name="usbhub.sys", kind="sys", size=100,
                        origin="test", alias="usbhub.sys")
    led.open_ida_session("usbhub.sys", artifact_sha=sha,
                          opened_by_agent="alice",
                          on_disk_path="/art/xx/usbhub.sys.i64")
    rows = led.ida_sessions_for(artifact_sha=sha)
    assert len(rows) == 1
    assert rows[0].status == "live"
    assert rows[0].on_disk_path.endswith("usbhub.sys.i64")
    led.close_ida_session("usbhub.sys")
    rows = led.ida_sessions_for(artifact_sha=sha)
    assert rows[0].status == "closed"
    led.close()


# ------------------------------------------------------- backfill fallback ----

def test_onboot_backfill_populates_artifacts(tmp_path: Path) -> None:
    """Simulate an artifacts_dir with a sha-named subdir; opening a
    fresh ledger with artifacts_dir= should populate the table."""
    adir = tmp_path / "artifacts"
    sha = "e" * 64
    (adir / sha).mkdir(parents=True)
    (adir / sha / "some.sys").write_bytes(b"MZ payload")
    led = FindingsLedger(tmp_path / "db.sqlite", artifacts_dir=adir)
    all_arts = led.artifacts_list()
    assert len(all_arts) == 1
    assert all_arts[0].sha256 == sha
    assert all_arts[0].name == "some.sys"
    # Second call is a no-op (guarded on non-empty table)
    led.close()
    led2 = FindingsLedger(tmp_path / "db.sqlite", artifacts_dir=adir)
    assert len(led2.artifacts_list()) == 1
    led2.close()
