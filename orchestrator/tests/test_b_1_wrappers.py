"""v0.17 B-1d — thin convenience wrappers built on decode_buffer.

Covers:
- read_qwords(va, count) -> {values, values_hex, layout, hex}
- read_unicode_string(va) -> UNICODE_STRING chase + utf-16-le decode
- read_ansi_string(va)   -> ANSI_STRING chase + mbcs decode
- read_unicode_string with empty Length / NULL Buffer short-circuit
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


class _WrapFake:
    """Fake AgentClient serving a range-aware memory map."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0
        self.memory: dict[int, bytes] = {}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_read(self, pid: int, addr: int, size: int, space: str,
                       **kw: Any) -> bytes:
        for base, buf in self.memory.items():
            if base <= addr < base + len(buf):
                offset = addr - base
                return buf[offset:offset + size]
        raise RuntimeError(f"unmapped VA 0x{addr:X}")


async def _build_ctx_and_server(tmp_path, monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _WrapFake)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _WrapFake)

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


# --------------------------------------------------------------------------- #
# read_qwords
# --------------------------------------------------------------------------- #


async def test_b_1d_read_qwords(tmp_path, monkeypatch) -> None:
    """read_qwords returns a values list AND a values_hex list — the LLM
    reads both without a second call."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.memory[0x1000] = struct.pack("<4Q", 0xA1, 0xB2, 0xC3, 0xD4)
    body = await _call(server, "mem_rw", {
        "action": "read_qwords", "space": "kernel",
        "address": "0x1000", "count": 4,
    })
    assert body["ok"] is not False
    assert body["values"] == [0xA1, 0xB2, 0xC3, 0xD4]
    assert body["values_hex"] == [
        "0x00000000000000A1",
        "0x00000000000000B2",
        "0x00000000000000C3",
        "0x00000000000000D4",
    ]


# --------------------------------------------------------------------------- #
# read_unicode_string
# --------------------------------------------------------------------------- #


async def test_b_1d_read_unicode_string_success(
        tmp_path, monkeypatch) -> None:
    """UNICODE_STRING header at 0x1000 -> Buffer at 0x2000 with wide chars."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    text = "\\Device\\Tcp"
    text_bytes = text.encode("utf-16-le")
    # UNICODE_STRING: Length=u16 (bytes), MaxLength=u16, Alignment=u32,
    # Buffer=ptr (u64). 16 bytes total on x64.
    header = struct.pack("<HHIQ", len(text_bytes), len(text_bytes) + 2, 0,
                         0x2000)
    fake.memory[0x1000] = header
    fake.memory[0x2000] = text_bytes + b"\x00\x00"
    body = await _call(server, "mem_rw", {
        "action": "read_unicode_string", "space": "kernel",
        "address": "0x1000",
    })
    assert body["ok"] is not False
    assert body["length"] == len(text_bytes)
    assert body["buffer_va"] == "0x2000"
    assert body["text"] == text


async def test_b_1d_read_unicode_string_empty_buffer(
        tmp_path, monkeypatch) -> None:
    """UNICODE_STRING with Length=0 short-circuits (empty text, no buffer
    read)."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    header = struct.pack("<HHIQ", 0, 0, 0, 0)
    fake.memory[0x1000] = header
    body = await _call(server, "mem_rw", {
        "action": "read_unicode_string", "space": "kernel",
        "address": "0x1000",
    })
    assert body["ok"] is not False
    assert body["length"] == 0
    assert body["buffer_va"] == "0x0"
    assert body["text"] == ""


async def test_b_1d_read_ansi_string(tmp_path, monkeypatch) -> None:
    """ANSI_STRING variant decodes under mbcs and strips trailing NULs."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    text = "SystemRoot"
    text_bytes = text.encode("ascii")
    header = struct.pack("<HHIQ", len(text_bytes), len(text_bytes) + 1, 0,
                         0x3000)
    fake.memory[0x1000] = header
    fake.memory[0x3000] = text_bytes + b"\x00"
    body = await _call(server, "mem_rw", {
        "action": "read_ansi_string", "space": "kernel",
        "address": "0x1000",
    })
    assert body["ok"] is not False
    assert body["text"] == text
