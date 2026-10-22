"""v0.22 · mem_rw(action='handles') chunked pull + stream-close kinds.

The field failure: a single `HandleList` unary call returning pid=4's
whole table (~100k rows) died mid-transfer under engine load. The
orchestrator now pages the RPC (limit/offset are post-fill on the agent,
so each page still costs an enumeration — but each wire response is
bounded, which is what killed the stream).

Contract notes pinned by these tests:
- a default call fetches just the resolved window (128 rows) plus a
  1-row probe past the end — `item_total` is honestly None (unknown)
  and `truncated`+`next_cursor` carry the paging contract.
- an explicit limit= early-outs without fetching the whole table.
- filter=/summary= fetch the full table (post-fetch filtering needs it).
- a mid-pull stream close surfaces as kind='handles_stream_closed' with
  the cheap-shape retry hint.
"""
from __future__ import annotations

import asyncio
import json as _json
from typing import Any

import pytest

from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


class _FakeAgentClient:
    """Serves a synthetic handle table in post-fill pages, like the real
    agent: every call re-enumerates, then slices limit/offset."""

    TABLE_SIZE = 4500  # > 2 pages at _PAGE=2000

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.calls: list[tuple[int, int]] = []  # (limit, offset) history

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.2"}

    async def handle_list(self, pid: int, want_names: bool = False,
                          *, limit: int = 0, offset: int = 0):
        self.calls.append((limit, offset))
        rows = [{"handle": i * 4, "type_name": "Process",
                 "object": 0xFFFF0000 + i, "granted_access": 0x1FFFFF,
                 "name": f"h{i}" if want_names else ""}
                for i in range(self.TABLE_SIZE)]
        if offset:
            rows = rows[offset:]
        if limit:
            rows = rows[:limit]
        return rows

    def recent_ops(self, limit: int = 32):
        return []


class _ClosingAgentClient(_FakeAgentClient):
    """handle_list dies the way _call's None-guard phrases it."""

    async def handle_list(self, pid: int, want_names: bool = False,
                          *, limit: int = 0, offset: int = 0):
        raise RuntimeError(
            "agent RPC suspex.Memory/HandleList returned no message; "
            "likely a stream close mid-call")


async def _server(tmp_path, monkeypatch, client_cls=_FakeAgentClient):
    monkeypatch.setattr("suspex.session.AgentClient", client_cls)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", client_cls)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=1)
    cfg.artifacts.dir = str(tmp_path / "artifacts")
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    session = Session(cfg)
    ledger = FindingsLedger(tmp_path / "artifacts" / "findings.db")
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg,
                  leases=LeaseManager(publish_event=lambda ev:
                                      asyncio.create_task(
                                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    token = CLIENT_ID.set("peer-B")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = _json.loads(text) if text else {}
    if not isinstance(body, dict):
        return body
    merged: dict = {}
    if isinstance(body.get("data"), dict):
        merged.update(body["data"])
    if isinstance(body.get("error"), dict):
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    merged.setdefault("summary", body.get("summary", {}))
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


def _summary(body: dict) -> dict:
    return body.get("summary") or {}


# --------------------------------------------------------------------------- #
# Chunked pull
# --------------------------------------------------------------------------- #


async def test_handles_default_fetches_window_not_table(
        tmp_path, monkeypatch) -> None:
    """A default call resolves to the max_results=64 window — one data
    page plus the 1-row 'is there more' probe. item_total is honestly
    null because the full table was never pulled."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "handles", "pid": 4, "space": "kernel"})
    assert body["ok"] is not False, body
    assert len(body.get("items", [])) == 64
    assert body.get("pages_fetched") == 2          # data page + probe
    summ = _summary(body)
    assert summ.get("truncated") is True
    assert summ.get("next_cursor") == "offset:64"
    assert summ.get("item_total") is None           # honestly unknown
    assert body.get("table_total_unknown") is True


async def test_handles_limit_early_out(tmp_path, monkeypatch) -> None:
    """limit=50 fetches one 50-row page + probe; no full-table pull."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "handles", "pid": 4, "space": "kernel", "limit": 50})
    assert body["ok"] is not False
    assert len(body.get("items", [])) == 50
    assert body.get("pages_fetched") == 2
    assert _summary(body).get("truncated") is True
    assert _summary(body).get("next_cursor") == "offset:50"


async def test_handles_offset_window(tmp_path, monkeypatch) -> None:
    """offset=2100+limit=100 needs 2200 rows -> pages 2000+200 + probe."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    # verbosity="full" keeps structured rows — at the default "normal" the
    # v0.31 row-collapse renders handles as text lines (see
    # test_envelope_compact_more); this test asserts on the handle field.
    body = await _call(server, "mem_rw", {
        "action": "handles", "pid": 4, "space": "kernel",
        "offset": 2100, "limit": 100, "verbosity": "full"})
    assert body["ok"] is not False
    assert body.get("pages_fetched") == 3
    assert len(body.get("items", [])) == 100
    assert body["items"][0]["handle"] in (2100 * 4, hex(2100 * 4))
    assert _summary(body).get("next_cursor") == "offset:2200"


async def test_handles_last_page_no_probe_when_table_ends(
        tmp_path, monkeypatch) -> None:
    """If the window ends exactly at the table end the probe returns
    empty and item_total is the true count (not null)."""
    _FakeAgentClient.TABLE_SIZE = 200
    try:
        ctx, server = await _server(tmp_path, monkeypatch)
        await _call(server, "target_manage", {"action": "connect"})
        body = await _call(server, "mem_rw", {
            "action": "handles", "pid": 4, "space": "kernel",
            "limit": 50, "offset": 150})
        assert body["ok"] is not False
        assert len(body.get("items", [])) == 50
        # 150+50=200 rows fetched (exactly the table) -> probe says empty
        assert _summary(body).get("truncated") is False
        assert _summary(body).get("item_total") == 200
    finally:
        _FakeAgentClient.TABLE_SIZE = 4500


async def test_handles_summary_fetches_full_table(
        tmp_path, monkeypatch) -> None:
    """summary=true aggregates the whole table — pages until short page,
    and item_total is the true count."""
    ctx, server = await _server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "handles", "pid": 4, "space": "kernel", "summary": True})
    assert body["ok"] is not False
    assert body.get("pages_fetched") == 3           # 2000 + 2000 + 500
    assert _summary(body).get("item_total") == 4500
    assert _summary(body).get("truncated") is True  # summary reports count


# --------------------------------------------------------------------------- #
# Stream-close error kind
# --------------------------------------------------------------------------- #


async def test_handles_stream_close_gets_named_kind(
        tmp_path, monkeypatch) -> None:
    """The _call None-guard RuntimeError must classify to
    kind='handles_stream_closed' with the cheap-shape retry hint."""
    ctx, server = await _server(tmp_path, monkeypatch, _ClosingAgentClient)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "handles", "pid": 4, "space": "kernel"})
    assert body["ok"] is False
    assert body["kind"] == "handles_stream_closed"
    hint = body.get("hint", "")
    assert "summary=true" in hint or "want_names=false" in hint
