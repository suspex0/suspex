"""v0.25 WP2 — `mem_rw resolve_range` (alias `dps`) pointer annotation.

Cases exercised against a fake client:

- canned mem_read bytes + kernel module list -> classified rows:
  in-module kernel qword -> {class:"kernel", module, rva},
  out-of-module kernel canonical -> {class:"kernel_unresolved"},
  user-range qword -> {class:"user"},
  small int -> {class:"nonptr"}, 0 -> {class:"zero"}
- filter semantics: default drops nonptrs/zeros, filter='all' dumps
  every scanned qword, include_ascii doubles as include_zeros
- hole truncation: short mem_read -> truncated:true + scanned < requested
- dps alias dispatches identically
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


_NT_BASE = 0xFFFFF80000000000
_EVIL_BASE = 0xFFFFF90000000000
_USER_DLL_BASE = 0x00007FF600000000

_KMODS = [
    {"name": "ntoskrnl.exe", "base": _NT_BASE, "size": 0x1000000,
     "path": "\\SystemRoot\\system32\\ntoskrnl.exe"},
    {"name": "evil.sys", "base": _EVIL_BASE, "size": 0x10000,
     "path": "\\SystemRoot\\system32\\drivers\\evil.sys"},
]
_UMODS = [
    {"name": "app.exe", "base": _USER_DLL_BASE, "size": 0x40000,
     "path": "C:\\app\\app.exe"},
]


def _q(*vals: int) -> bytes:
    return b"".join(struct.pack("<Q", v) for v in vals)


class _DpsFake:
    """Fake AgentClient — `seed_read` maps base VA -> bytes; mem_read
    honors want_meta/partial like the real ABI."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.seed_read: dict[int, bytes] = {}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_modules(self, pid: int, kernel: bool = False,
                          **kw: Any) -> list[dict]:
        return list(_KMODS if kernel else _UMODS)

    async def mem_read(self, pid: int, addr: int, size: int,
                       space: str = "user", **kw: Any):
        data = self.seed_read.get(addr, b"")[:size]
        if kw.get("want_meta"):
            return data, {"read_bytes": len(data),
                          "first_bad_offset": len(data)}
        return data


async def _build_ctx_and_server(tmp_path, monkeypatch, fake_cls):
    monkeypatch.setattr("suspex.session.AgentClient", fake_cls)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", fake_cls)

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
                  clients=clients_reg, leases=leases_mgr,
                  ownership=ownership_reg)
    server = build_server(ctx)
    return ctx, server


async def _call(server, tool: str, args: dict) -> dict:
    """Return {data-fields..., ok, kind} merged from the envelope."""
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


async def _connect_and_seed(ctx, server, va: int, data: bytes) -> None:
    await _call(server, "target_manage", {"action": "connect"})
    ctx.session.require_client().seed_read[va] = data


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


async def test_v025_wp2_dps_classifies_qwords(tmp_path, monkeypatch) -> None:
    """Default (filter='ptr') view: kernel/user classes kept, nonptr +
    zero dropped; in-module kernel qword resolves to module+rva."""
    va = 0xFFFFF80010000000
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DpsFake)
    buf = _q(_NT_BASE + 0x1234,        # in ntoskrnl -> kernel
             0xFFFF810000000000,       # kernel canon, no module -> unres
             _USER_DLL_BASE + 0x40,    # user-range -> user (+module w/pid)
             0x5,                      # nonptr
             0x0)                      # zero
    await _connect_and_seed(ctx, server, va, buf)
    body = await _call(server, "mem_rw", {
        "action": "resolve_range", "space": "kernel",
        "address": hex(va), "size": len(buf), "pid": 4,
    })
    assert body["ok"] is True
    items = body["items"]
    classes = [r["class"] for r in items]
    assert classes == ["kernel", "kernel_unresolved", "user"]
    k = items[0]
    assert k["module"] == "ntoskrnl.exe"
    assert k["rva"] == "0x1234"
    assert k["name"] == "ntoskrnl.exe+0x1234"
    u = items[2]
    assert u["module"] == "app.exe"           # resolved via pid's user list
    assert body["pointers"] == 3
    assert body["resolved"] == 2
    assert body["scanned"] == len(buf)
    assert body["qwords"] == 5


async def test_v025_wp2_dps_all_dumps_every_qword(tmp_path, monkeypatch) -> None:
    """filter='all' keeps nonptr and zero rows too."""
    va = 0xFFFFF80010000000
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DpsFake)
    buf = _q(_NT_BASE + 0x10, 0x5, 0x0)
    await _connect_and_seed(ctx, server, va, buf)
    body = await _call(server, "mem_rw", {
        "action": "resolve_range", "space": "kernel",
        "address": hex(va), "size": len(buf), "filter": "all",
    })
    assert body["ok"] is True
    assert [r["class"] for r in body["items"]] == [
        "kernel", "nonptr", "zero"]


async def test_v025_wp2_dps_include_zeros(tmp_path, monkeypatch) -> None:
    """include_ascii doubles as include_zeros: zero slots join the
    pointer-class default view (nonptrs still dropped)."""
    va = 0xFFFFF80010000000
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DpsFake)
    buf = _q(_NT_BASE + 0x10, 0x0, 0x5)
    await _connect_and_seed(ctx, server, va, buf)
    body = await _call(server, "mem_rw", {
        "action": "resolve_range", "space": "kernel",
        "address": hex(va), "size": len(buf), "include_ascii": True,
    })
    assert body["ok"] is True
    assert [r["class"] for r in body["items"]] == ["kernel", "zero"]


async def test_v025_wp2_dps_hole_truncates(tmp_path, monkeypatch) -> None:
    """A short partial read truncates the sweep honestly."""
    va = 0xFFFFF80010000000
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DpsFake)
    buf = _q(_NT_BASE + 0x10, 0x7)   # 16B of a 0x200 request
    await _connect_and_seed(ctx, server, va, buf)
    body = await _call(server, "mem_rw", {
        "action": "resolve_range", "space": "kernel",
        "address": hex(va), "size": 0x200,
    })
    assert body["ok"] is True
    assert body["scanned"] == 16
    assert body["requested"] == 0x200
    assert body["truncated"] is True
    assert body["qwords"] == 2


async def test_v025_wp2_dps_alias(tmp_path, monkeypatch) -> None:
    """action='dps' dispatches to the same implementation."""
    va = 0xFFFFF80010000000
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DpsFake)
    await _connect_and_seed(ctx, server, va, _q(_NT_BASE + 0x10))
    body = await _call(server, "mem_rw", {
        "action": "dps", "space": "kernel",
        "address": hex(va), "size": 8,
    })
    assert body["ok"] is True
    assert body["items"][0]["class"] == "kernel"
    assert body["items"][0]["module"] == "ntoskrnl.exe"


async def test_v025_wp2_dps_size_required(tmp_path, monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DpsFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "resolve_range", "space": "kernel",
        "address": "0xFFFFF80010000000",
    })
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"
