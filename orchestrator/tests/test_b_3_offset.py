"""v0.17 B-3 — `mem_rw read` `offset` is no longer a silent no-op.

Before v0.17 the tool signature accepted ``offset`` but the ``read`` branch
never referenced it, so a caller migrating from a ``base+offset`` call
convention would receive the wrong bytes with no diagnostic. B-3 turns the
kwarg into a hard error on read so the misuse surfaces at the tool layer,
with an actionable hint pointing at the intended ``address+offset``
migration path. The unaltered ``read`` (no ``offset``) still works.
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
    """Minimal duck-typed AgentClient — the read branch we're exercising
    only needs mem_read + status + connect/close."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "DRIVER_SERVICE"}

    async def mem_read(self, pid: int, addr: int, size: int, space: str,
                       **kw: Any) -> bytes:
        # Deterministic payload — 16 bytes of 0xAA. The B-3 tests only care
        # about the "no offset -> succeeds" contract; content is inspected as
        # a shape check, not for exact bytes.
        return b"\xAA" * int(size)


async def _build_ctx_and_server(tmp_path, monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _FakeAgentClient)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _FakeAgentClient)

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
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr, ownership=ownership_reg)
    server = build_server(ctx)
    return ctx, server


async def _call(server, tool: str, args: dict) -> dict:
    """Unwrap ``ToolResult.structured_content`` per v0.17 A-1, with a
    fallback to the legacy content[0].text JSON string for
    SUSPX_MCP_LEGACY_DUAL_CONTENT=1 mode."""
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
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


async def test_b_3_read_with_offset_errors(tmp_path, monkeypatch) -> None:
    """Passing ``offset`` on read now returns kind='unknown_kwarg'."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "read",
        "space": "kernel",
        "address": "0xFFFFF80000000000",
        "size": 16,
        "offset": 0x40,
    })
    assert body["ok"] is False
    assert body["kind"] == "unknown_kwarg"
    # The hint must show the exact migration formula so the LLM can fix it
    # in one step.
    assert "0x40" in body.get("hint", "")
    assert "address" in body.get("error", "").lower()


async def test_b_3_read_without_offset_still_works(tmp_path, monkeypatch) -> None:
    """Baseline: a plain read (no offset) succeeds and returns the buffer."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "read",
        "space": "kernel",
        "address": "0xFFFFF80000000000",
        "size": 16,
    })
    assert body["ok"] is not False
    # payload shape carries hex+size, not an offset echo.
    assert body.get("size") == 16
    assert body.get("hex", "").lower() == "aa" * 16


async def test_b_3_read_with_offset_zero_still_reads(tmp_path, monkeypatch) -> None:
    """offset=0 is the default — it must NOT trip the guard. Explicit zero
    means "no shift requested" and preserves the pre-B-3 accept path."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "read",
        "space": "kernel",
        "address": "0xFFFFF80000000000",
        "size": 8,
        "offset": 0,
    })
    assert body["ok"] is not False
    assert body.get("size") == 8
