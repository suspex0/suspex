"""v0.17 E-2: rotating JSONL audit writer + Session wire.

  * E-2a: :class:`suspex.audit.AuditWriter` writes, rolls (size + day),
    reaps old files, and swallows I/O errors.
  * E-2a: :func:`suspex.audit.query` filters by owner/method/time and
    reads across roll files.
  * E-2b: :meth:`suspex.session.Session.record_tool_call` mirrors to
    the persistent sink.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from suspex import audit as audit_mod
from suspex.audit import (
    AuditWriter,
    query,
)
from suspex.config import SuspexConfig
from suspex.session import Session


# ---------------------------------------------------------------------------
# E-2a — writer behavior
# ---------------------------------------------------------------------------


def test_e_2a_write_creates_file_and_appends(tmp_path, monkeypatch):
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    w = AuditWriter("s1", base=tmp_path)
    w.write({"ts": 1.0, "tool": "target_manage", "action": "connect", "ok": True})
    w.write({"ts": 2.0, "tool": "mem_rw", "action": "read", "ok": True})
    w.close()
    files = sorted((tmp_path / "s1").glob("*.jsonl"))
    assert len(files) == 1
    rows = [json.loads(l) for l in files[0].read_text().splitlines() if l]
    assert [r["action"] for r in rows] == ["connect", "read"]


def test_e_2a_roll_on_size_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_AUDIT_ROLL_BYTES", "128")
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    w = AuditWriter("s2", base=tmp_path)
    payload = "x" * 200  # each row is ~200 bytes over the 128-byte roll cap
    for i in range(4):
        w.write({"ts": float(i), "tool": "mem_rw", "action": "read",
                 "payload": payload, "ok": True})
        # Force distinct roll timestamps: sleep 1ms so the filename's
        # nano-suffix advances.
        time.sleep(0.002)
    w.close()
    files = sorted((tmp_path / "s2").glob("*.jsonl"))
    assert len(files) >= 3


def test_e_2a_roll_on_day_change(tmp_path, monkeypatch):
    """A change in the UTC calendar day triggers a roll on the next write."""
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    w = AuditWriter("s3", base=tmp_path)
    w.write({"ts": 1.0, "tool": "mem_rw", "action": "read", "ok": True})
    # Simulate yesterday by rewriting the writer's day marker.
    w._day = "1970-01-01"
    w.write({"ts": 2.0, "tool": "mem_rw", "action": "write", "ok": True})
    w.close()
    files = sorted((tmp_path / "s3").glob("*.jsonl"))
    assert len(files) == 2


def test_e_2a_query_filters_by_method(tmp_path, monkeypatch):
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    w = AuditWriter("s4", base=tmp_path)
    w.write({"ts": 1.0, "tool": "mem_rw", "action": "read", "ok": True})
    w.write({"ts": 2.0, "tool": "mem_rw", "action": "write", "ok": True})
    w.write({"ts": 3.0, "tool": "bp_manage", "action": "add", "ok": True})
    w.close()
    reads = query("s4", method="read", base=tmp_path)
    assert [r["action"] for r in reads] == ["read"]
    bp = query("s4", tool="bp_manage", base=tmp_path)
    assert [r["action"] for r in bp] == ["add"]


def test_e_2a_query_reads_across_roll_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_AUDIT_ROLL_BYTES", "128")
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    w = AuditWriter("s5", base=tmp_path)
    payload = "x" * 200
    for i in range(5):
        w.write({"ts": float(i), "tool": "mem_rw", "action": "read",
                 "payload": payload, "ok": True})
        time.sleep(0.002)
    w.close()
    rows = query("s5", method="read", base=tmp_path)
    assert len(rows) == 5
    # Oldest-first order.
    assert [r["ts"] for r in rows] == [0.0, 1.0, 2.0, 3.0, 4.0]


def test_e_2a_query_filters_by_owner_and_time(tmp_path, monkeypatch):
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    w = AuditWriter("s6", base=tmp_path)
    w.write({"ts": 100.0, "tool": "mem_rw", "action": "read",
             "owner": "peer-A", "ok": True})
    w.write({"ts": 200.0, "tool": "mem_rw", "action": "read",
             "owner": "peer-B", "ok": True})
    w.close()
    only_a = query("s6", owner="peer-A", base=tmp_path)
    assert len(only_a) == 1 and only_a[0]["owner"] == "peer-A"
    # Time bounds: since=150s cuts the peer-A row.
    since_iso = datetime.fromtimestamp(150, tz=timezone.utc).isoformat()
    later = query("s6", since_iso=since_iso, base=tmp_path)
    assert [r["owner"] for r in later] == ["peer-B"]


def test_e_2a_retention_deletes_old_files(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_AUDIT_RETAIN_DAYS", "1")
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    # Pre-seed an ancient file that a retention pass should reap.
    dir_ = tmp_path / "s7"
    dir_.mkdir(parents=True, exist_ok=True)
    old = dir_ / "1970-01-01-000000-000.jsonl"
    old.write_text('{"ts": 0, "tool": "t", "action": "a", "ok": true}\n',
                    encoding="utf-8")
    ancient_mtime = (datetime.now(timezone.utc)
                      - timedelta(days=30)).timestamp()
    os.utime(old, (ancient_mtime, ancient_mtime))
    # Constructing a new writer at the same base triggers _reap_old().
    AuditWriter("s7", base=tmp_path)
    assert not old.exists()


def test_e_2a_disk_full_swallows_error(tmp_path, monkeypatch):
    """A writer whose stream is closed must count-not-raise on write."""
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    w = AuditWriter("s8", base=tmp_path)
    w.write({"ts": 1.0, "tool": "t", "action": "a", "ok": True})
    # Nuke the file handle to simulate mid-run I/O collapse.
    w._fp.close()
    w._fp = None
    # Point base at a nonexistent read-only-ish path to force _open_new
    # to fail. Windows / POSIX both refuse a mkdir under a file — we can
    # exploit that.
    victim = tmp_path / "not_a_dir.txt"
    victim.write_text("not a dir")
    w.base = victim / "sub"
    before = w.dropped
    w.write({"ts": 2.0, "tool": "t", "action": "a", "ok": True})
    # Either open failed or write failed — either way, dropped++.
    assert w.dropped > before


def test_e_2a_audit_disabled_env_short_circuits(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_AUDIT_DISABLE", "1")
    w = AuditWriter("s9", base=tmp_path)
    w.write({"ts": 1.0, "tool": "t", "action": "a", "ok": True})
    # No tree materialized under the disabled writer.
    assert not (tmp_path / "s9").exists() or not list(
        (tmp_path / "s9").glob("*.jsonl"))


# ---------------------------------------------------------------------------
# E-2b — Session.record_tool_call mirrors to the sink
# ---------------------------------------------------------------------------


def test_e_2b_record_tool_call_mirrors_to_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_AUDIT_BASE_DIR", str(tmp_path / "audit"))
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    cfg = SuspexConfig()
    s = Session(cfg)
    s.record_tool_call("target_manage", "connect",
                        args={"host": "127.0.0.1", "_current_owner": "peer-E"},
                        ok=True, error="")
    s.record_tool_call("mem_rw", "read",
                        args={"address": "0x1000", "_current_owner": "peer-E"},
                        ok=False, error="probe_va says nope")
    rows = query(s.audit_session_id(), base=tmp_path / "audit")
    assert len(rows) == 2
    assert rows[0]["tool"] == "target_manage"
    assert rows[0]["ok"] is True
    assert rows[0]["owner"] == "peer-E"
    assert rows[1]["tool"] == "mem_rw"
    assert rows[1]["ok"] is False
    assert rows[1]["error"] == "probe_va says nope"


def test_e_2b_disk_error_never_masks_call(tmp_path, monkeypatch):
    """Even a broken audit sink must not raise from record_tool_call —
    the in-memory ring is the source of truth for the active session."""
    monkeypatch.setenv("SUSPX_AUDIT_BASE_DIR", str(tmp_path / "audit"))
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)
    cfg = SuspexConfig()
    s = Session(cfg)
    # Simulate a disk failure by nuking the audit writer's fp handle.
    s._audit.close()
    s._audit.base = tmp_path / "not_a_dir.txt" / "sub"  # invalid path
    (tmp_path / "not_a_dir.txt").write_text("blocker")
    # No exception — the ring still records.
    s.record_tool_call("t", "a", args={}, ok=True)
    assert len(s.tool_log) == 1


# ---------------------------------------------------------------------------
# E-2c — target_manage(action="recent_ops", persistent=true) surface
# ---------------------------------------------------------------------------


import asyncio  # noqa: E402 — grouped with the E-2c helpers

from suspex.caller import CLIENT_ID  # noqa: E402
from suspex.clients import ClientRegistry  # noqa: E402
from suspex.config import TargetConfig  # noqa: E402
from suspex.findings import FindingsLedger  # noqa: E402
from suspex.ida_bridge import IdaBridge, IdaConfigLite  # noqa: E402
from suspex.leases import LeaseManager  # noqa: E402
from suspex.mcp.tools import Context, build_server  # noqa: E402
from suspex.ownership import OwnershipRegistry  # noqa: E402


async def _mk_ctx_e2c(tmp_path):
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=9000)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr,
                  ownership=ownership_reg)
    server = build_server(ctx)
    return ctx, server


def _flat(env):
    body = getattr(env, "structured_content", None)
    if body is None:
        text = env.content[0].text if env.content else ""
        body = json.loads(text) if text else {}
    return body


def test_e_2c_persistent_true_reads_audit_sink(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_AUDIT_BASE_DIR", str(tmp_path / "audit"))
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)

    async def go():
        ctx, server = await _mk_ctx_e2c(tmp_path)
        # Seed the sink with a handful of rows.
        ctx.session.record_tool_call("mem_rw", "read",
                                       args={"_current_owner": "peer-A"},
                                       ok=True)
        ctx.session.record_tool_call("bp_manage", "add",
                                       args={"_current_owner": "peer-A"},
                                       ok=True)
        ctx.session.record_tool_call("mem_rw", "read",
                                       args={"_current_owner": "peer-B"},
                                       ok=False, error="boom")
        token = CLIENT_ID.set("peer-A")
        try:
            result = await server.call_tool("target_manage", {
                "action": "recent_ops", "persistent": True,
            })
        finally:
            CLIENT_ID.reset(token)
        env = _flat(result)
        data = env.get("data") or {}
        assert data.get("persistent") is True
        assert data.get("count") == 3
        methods = [r.get("action") for r in data.get("ops", [])]
        assert methods == ["read", "add", "read"]

    asyncio.run(go())


def test_e_2c_persistent_filter_by_method_and_owner(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_AUDIT_BASE_DIR", str(tmp_path / "audit"))
    monkeypatch.delenv("SUSPX_AUDIT_DISABLE", raising=False)

    async def go():
        ctx, server = await _mk_ctx_e2c(tmp_path)
        ctx.session.record_tool_call("mem_rw", "read",
                                       args={"_current_owner": "peer-A"},
                                       ok=True)
        ctx.session.record_tool_call("bp_manage", "add",
                                       args={"_current_owner": "peer-B"},
                                       ok=True)
        ctx.session.record_tool_call("mem_rw", "read",
                                       args={"_current_owner": "peer-B"},
                                       ok=True)
        token = CLIENT_ID.set("peer-A")
        try:
            # Filter to peer-B / method=read → 1 row.
            result = await server.call_tool("target_manage", {
                "action": "recent_ops", "persistent": True,
                "op_method": "read", "op_owner": "peer-B",
            })
        finally:
            CLIENT_ID.reset(token)
        env = _flat(result)
        data = env.get("data") or {}
        assert data.get("count") == 1
        row = data["ops"][0]
        assert row["tool"] == "mem_rw"
        assert row["owner"] == "peer-B"


    asyncio.run(go())
