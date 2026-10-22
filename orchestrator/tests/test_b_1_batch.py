"""v0.17 B-1b — `mem_rw read` batch mode via ``reads=[{va, size, decode?}]``.

Each row runs independently; a single bad va surfaces as ``{address, error}``
while the rest of the batch completes.
"""
from __future__ import annotations

import asyncio
import json as _json
import struct
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


class _BatchFake:
    """AgentClient stub — serves canned payloads per VA, or raises on a
    poisoned VA registered via ``.poison[va]``."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0
        self.payloads: dict[int, bytes] = {}
        self.poison: dict[int, str] = {}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_read(self, pid: int, addr: int, size: int, space: str,
                       **kw: Any) -> bytes:
        if addr in self.poison:
            raise RuntimeError(self.poison[addr])
        return self.payloads.get(addr, b"\x00" * size)[:size]


async def _build_ctx_and_server(tmp_path, monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _BatchFake)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _BatchFake)

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


async def test_b_1b_batch_three_way_success(tmp_path, monkeypatch) -> None:
    """Three-entry batch with mixed decode specs; every row succeeds."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.payloads[0x1000] = struct.pack("<Q", 0xAAAAAAAA)
    fake.payloads[0x2000] = struct.pack("<II", 0x11, 0x22)
    fake.payloads[0x3000] = b"hello\x00world\x00\x00\x00\x00\x00"
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "reads": [
            {"va": "0x1000", "size": 8, "decode": "u64"},
            {"va": "0x2000", "size": 8, "decode": ["u32", "u32"]},
            {"va": "0x3000", "size": 16, "decode": "cstr"},
        ],
    })
    assert body["ok"] is not False
    assert body["batch"] is True
    assert body["count"] == 3
    rows = body["results"]
    assert rows[0]["values"] == [0xAAAAAAAA]
    assert rows[1]["values"] == [0x11, 0x22]
    assert rows[2]["values"] == ["hello"]


async def test_b_1b_batch_one_entry_errors(tmp_path, monkeypatch) -> None:
    """A poisoned VA appears as {address, error, size:0}; the rest of the
    batch completes."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.payloads[0x1000] = struct.pack("<Q", 0xABCD)
    fake.poison[0x2000] = "invalid VA"
    fake.payloads[0x3000] = struct.pack("<Q", 0x9999)
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "reads": [
            {"va": "0x1000", "size": 8, "decode": "u64"},
            {"va": "0x2000", "size": 8, "decode": "u64"},
            {"va": "0x3000", "size": 8, "decode": "u64"},
        ],
    })
    assert body["ok"] is not False
    rows = body["results"]
    assert rows[0]["values"] == [0xABCD]
    assert "error" in rows[1]
    assert "invalid VA" in rows[1]["error"]
    assert rows[1]["address"] == "0x2000"
    assert rows[2]["values"] == [0x9999]


async def test_b_1b_batch_missing_size_marks_bad_row(
        tmp_path, monkeypatch) -> None:
    """A row without size gets flagged with `error='size required (> 0)'`
    without derailing the batch."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.payloads[0x1000] = struct.pack("<Q", 0xABCD)
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "reads": [
            {"va": "0x1000", "size": 8, "decode": "u64"},
            {"va": "0x2000"},  # no size
        ],
    })
    assert body["ok"] is not False
    rows = body["results"]
    assert rows[0]["values"] == [0xABCD]
    assert "size" in rows[1]["error"].lower()
