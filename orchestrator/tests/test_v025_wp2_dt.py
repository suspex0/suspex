"""v0.25 WP2 — `mem_rw dt`: named-type read sugar over read decode={'type'}.

Cases exercised:

- dbghelp path (symbols.type_layout monkeypatched) + fake mem_read ->
  decoded member dict, same payload shape as read decode=
- bad type name via the layout-cache source -> kind='type_not_found'
- missing value=/address= -> bad_arg
"""
from __future__ import annotations

import asyncio
import json as _json
import struct
from typing import Any

import pytest

from suspex import pdb_layout_cache as _plc
from suspex.caller import CLIENT_ID
from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session


_MEMBERS = [
    {"name": "Foo", "offset": 0x0, "size": 0x8,
     "type": "unsigned __int64"},
    {"name": "Bar", "offset": 0x8, "size": 0x4,
     "type": "unsigned long"},
]

_VA = 0xFFFFF80030000000


class _DtFake:
    """Fake AgentClient — mem_read replays `seed_read` bytes."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.seed_read: bytes = b""

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_modules(self, pid: int, kernel: bool = False,
                          **kw: Any) -> list[dict]:
        return []

    async def mem_read(self, pid: int, addr: int, size: int,
                       space: str = "user", **kw: Any):
        data = self.seed_read[:size]
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
    (tmp_path / "artifacts" / "dumps").mkdir(parents=True, exist_ok=True)
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
# Tests
# --------------------------------------------------------------------------- #


async def test_v025_wp2_dt_decodes_named_type(tmp_path, monkeypatch) -> None:
    """value='<TYPE>' + module + address decodes like read decode={...}."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DtFake)
    # Fake local image so _resolve_image finds the module; type_layout
    # is monkeypatched so no real dbghelp/PDB is needed.
    (tmp_path / "artifacts" / "dumps" / "ntoskrnl.exe").write_bytes(b"MZ")

    def _fake_type_layout(binary_path, type_name, cache_dir="",
                          allow_download=True, servers=None,
                          max_depth=3):
        assert type_name == "_TEST_STRUCT"
        return {"ok": True, "name": "_TEST_STRUCT", "size": 0xC,
                "members": _MEMBERS}

    monkeypatch.setattr("suspex.symbols.type_layout", _fake_type_layout)
    await _call(server, "target_manage", {"action": "connect"})
    ctx.session.require_client().seed_read = struct.pack(
        "<QI", 0x1122334455667788, 0xDEADBEEF)
    body = await _call(server, "mem_rw", {
        "action": "dt", "value": "_TEST_STRUCT",
        "module": "ntoskrnl.exe", "space": "kernel",
        "address": hex(_VA),
    })
    assert body["ok"] is True, body
    assert body["type"] == "_TEST_STRUCT"
    assert body["layout_source"] == "dbghelp"
    vals = body["values"]
    assert vals["Foo"] == 0x1122334455667788
    assert vals["Bar"] == 0xDEADBEEF
    # Same payload shape as read decode= — hex + layout + values.
    assert body["hex"] == struct.pack("<QI", 0x1122334455667788,
                                      0xDEADBEEF).hex()
    assert any(r["path"] == "Foo" for r in body["layout"])


async def test_v025_wp2_dt_bad_type_name(tmp_path, monkeypatch) -> None:
    """A type absent from the layout source -> kind='type_not_found'
    (driven through decode={'source':'cache'} + a seeded cache)."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DtFake)
    cache_dir = tmp_path / "layouts"
    cache_dir.mkdir(parents=True, exist_ok=True)
    p = _plc.cache_path("ntoskrnl.exe", "BIDTEST", cache_dir=cache_dir)
    p.write_text(_json.dumps({
        "module": "ntoskrnl.exe", "build_id": "BIDTEST",
        "types": {"_PRESENT": {"size": 8, "members": [
            {"name": "X", "offset": 0, "size": 8,
             "type": "unsigned __int64"}]}},
    }), encoding="utf-8")
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "dt", "value": "_MISSING",
        "module": "ntoskrnl.exe", "space": "kernel",
        "address": hex(_VA),
        "decode": {"source": "cache", "cache_dir": str(cache_dir)},
    })
    assert body["ok"] is False
    assert body["kind"] == "type_not_found"


async def test_v025_wp2_dt_requires_value(tmp_path, monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DtFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "dt", "module": "ntoskrnl.exe", "space": "kernel",
        "address": hex(_VA),
    })
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"
    assert "value" in body.get("error", "")


async def test_v025_wp2_dt_user_space_needs_pid(tmp_path, monkeypatch) -> None:
    """Same pid guard as read: space='user' + pid=0 is rejected."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _DtFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "dt", "value": "_EPROCESS", "space": "user",
        "address": "0x1000",
    })
    assert body["ok"] is False
    assert "pid" in body.get("error", "")
