"""v0.17 B-2 — `mem_rw read` `from_va=<VA>` + `space='physical'` shortcut.

One driver round-trip replaces (va_translate) + (mem_rw read
space='physical') so a caller doesn't need two calls to inspect a
physical page from a VA.
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


class _TranslateFake:
    """Fake AgentClient with mem_va_translate + mem_read.

    ``.va_map[VA] = {"pa": int, "present": bool, "cr3": int}`` — configured
    per test. A missing VA raises to simulate a driver-side translate fault.
    """

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0
        self.va_map: dict[int, dict[str, Any]] = {}
        self.physical_memory: dict[int, bytes] = {}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_va_translate(self, va: int, space: str = "kernel",
                               pid: int = 0) -> dict[str, Any]:
        if va not in self.va_map:
            raise RuntimeError(f"STATUS_INVALID_ADDRESS at VA 0x{va:X}")
        entry = self.va_map[va]
        return {"pa": entry.get("pa", 0),
                "present": entry.get("present", True),
                "cr3": entry.get("cr3", 0),
                "page_size_shift": entry.get("page_size_shift", 12)}

    async def mem_read(self, pid: int, addr: int, size: int, space: str,
                       **kw: Any) -> bytes:
        # Only physical reads land here in B-2; simulate a byte-addressed
        # backing store.
        for base, buf in self.physical_memory.items():
            if base <= addr < base + len(buf):
                offset = addr - base
                return buf[offset:offset + size]
        raise RuntimeError(f"unmapped PA 0x{addr:X}")


async def _build_ctx_and_server(tmp_path, monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _TranslateFake)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _TranslateFake)

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


async def test_b_2_va_physical_success(tmp_path, monkeypatch) -> None:
    """VA translated to PA, physical read returns the seeded bytes."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.va_map[0xFFFFF80000000000] = {
        "pa": 0x1000, "present": True, "cr3": 0x1AA000,
        "page_size_shift": 12,
    }
    fake.physical_memory[0x1000] = struct.pack("<Q", 0xDEADBEEF)
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "physical",
        "from_va": "0xFFFFF80000000000",
        "size": 8,
    })
    assert body["ok"] is not False
    assert body["physical_address"] == "0x1000"
    assert body["va"] == "0xfffff80000000000"
    assert body["size"] == 8
    assert body["cr3"] == "0x1aa000"


async def test_b_2_va_physical_pte_absent(tmp_path, monkeypatch) -> None:
    """A VA the driver can't translate surfaces as kind='pte_absent'."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    # No va_map entry -> mem_va_translate raises.
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "physical",
        "from_va": "0xFFFFF80000001000",
        "size": 8,
    })
    assert body["ok"] is False
    assert body["kind"] == "pte_absent"


async def test_b_2_va_physical_present_false_is_pte_absent(
        tmp_path, monkeypatch) -> None:
    """Translator returned present=false -> kind='pte_absent' + translate
    dict for the layer breakdown."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.va_map[0xFFFFF80000002000] = {
        "pa": 0, "present": False, "cr3": 0x1AA000,
    }
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "physical",
        "from_va": "0xFFFFF80000002000",
        "size": 8,
    })
    assert body["ok"] is False
    assert body["kind"] == "pte_absent"
    assert body.get("translate", {}).get("present") is False


async def test_b_2_from_va_and_address_collision(
        tmp_path, monkeypatch) -> None:
    """`address` + `from_va` set together -> kind='kwarg_collision'."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "physical",
        "from_va": "0xFFFFF80000000000",
        "address": "0x2000", "size": 8,
    })
    assert body["ok"] is False
    assert body["kind"] == "kwarg_collision"


async def test_b_2_resolve_physical_without_physical_space_errors(
        tmp_path, monkeypatch) -> None:
    """`resolve_physical=true` with space='kernel' -> invalid_parameter."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "address": "0xFFFFF80000000000",
        "resolve_physical": True, "size": 8,
    })
    assert body["ok"] is False
    assert body["kind"] == "invalid_parameter"


async def test_b_2_va_physical_with_decode(tmp_path, monkeypatch) -> None:
    """The shortcut composes with decode= — the returned dict carries
    values + layout the same as a plain physical read."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.va_map[0xFFFFF80000000000] = {
        "pa": 0x1000, "present": True, "cr3": 0x1AA000,
    }
    fake.physical_memory[0x1000] = struct.pack("<2Q", 0xAA, 0xBB)
    body = await _call(server, "mem_rw", {
        "action": "read", "space": "physical",
        "from_va": "0xFFFFF80000000000",
        "size": 16, "decode": "u64[2]",
    })
    assert body["ok"] is not False
    assert body["values"] == [0xAA, 0xBB]
