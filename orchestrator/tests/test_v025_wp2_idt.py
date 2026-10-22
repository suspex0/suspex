"""v0.25 WP2 — `mem_rw idt`: per-CPU IDT dump + suspicious-handler flag.

Cases exercised against a fake client:

- fake `idt_list` payload -> rows symbolized to module!sym+off;
  handler in an off-allowlist module and a handler outside every module
  both get `suspicious:true`
- a client WITHOUT `idt_list` -> `kind:"agent_old"` (feature gate —
  verb lands before the ABI v12 agent does)
- `all_cpus=true` -> all_cpus passthrough, rows grouped by cpu,
  handler drift across CPUs surfaced
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


_NT_BASE = 0xFFFFF80000000000
_EVIL_BASE = 0xFFFFF90000000000

_KMODS = [
    {"name": "ntoskrnl.exe", "base": _NT_BASE, "size": 0x1000000,
     "path": "\\SystemRoot\\system32\\ntoskrnl.exe"},
    {"name": "evil.sys", "base": _EVIL_BASE, "size": 0x10000,
     "path": "\\SystemRoot\\system32\\drivers\\evil.sys"},
]

_IDT_ENTRIES = [
    {"cpu": 0, "vector": 0x2E, "handler_va": _NT_BASE + 0x1234,
     "selector": 0x10, "ist": 0, "dpl": 3},
    {"cpu": 0, "vector": 0x80, "handler_va": _EVIL_BASE + 0x100,
     "selector": 0x10, "ist": 0, "dpl": 3},
    {"cpu": 0, "vector": 0x81, "handler_va": 0xFFFF810000000000,
     "selector": 0x10, "ist": 0, "dpl": 0},
]


class _BaseFake:
    """Fake AgentClient without `idt_list` (the pre-WP4 shape)."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.last_all_cpus: bool | None = None

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_modules(self, pid: int, kernel: bool = False,
                          **kw: Any) -> list[dict]:
        return list(_KMODS if kernel else [])


class _IdtFake(_BaseFake):
    """Fake AgentClient carrying an `idt_list` implementation."""

    async def idt_list(self, all_cpus: bool = False) -> dict[str, Any]:
        self.last_all_cpus = all_cpus
        return {"ok": True,
                "idt_base": 0xFFFFF80020000000, "idt_limit": 0xFFF,
                "entries": [dict(e) for e in _IDT_ENTRIES]}


class _NoIdtFake(_BaseFake):
    """Pre-WP4 agent shape: no `idt_list` method at all."""


class _AllCpusFake(_IdtFake):
    async def idt_list(self, all_cpus: bool = False) -> dict[str, Any]:
        self.last_all_cpus = all_cpus
        entries = [dict(e) for e in _IDT_ENTRIES]
        # CPU1's copy of vector 0x80 lands at a different handler —
        # the drift signature.
        for e in _IDT_ENTRIES:
            e2 = dict(e)
            e2["cpu"] = 1
            if e2["vector"] == 0x80:
                e2["handler_va"] = _NT_BASE + 0x9999
            entries.append(e2)
        return {"ok": True,
                "idt_base": 0xFFFFF80020000000, "idt_limit": 0xFFF,
                "entries": entries}


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


async def test_v025_wp2_idt_resolves_and_flags(tmp_path, monkeypatch) -> None:
    """Handlers resolve to module+off; off-allowlist and unresolved
    handlers get suspicious:true."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _IdtFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {"action": "idt"})
    assert body["ok"] is True
    items = {r["vector"]: r for r in body["items"]}
    # ntoskrnl handler — resolved, not flagged.
    r = items[0x2E]
    assert r["module"] == "ntoskrnl.exe"
    assert r["rva"] == "0x1234"
    assert not r.get("suspicious")
    assert r["name"] == "ntoskrnl.exe+0x1234"
    # evil.sys handler — in a module but off the allowlist -> suspicious.
    r = items[0x80]
    assert r["module"] == "evil.sys"
    assert r["suspicious"] is True
    # Outside every module -> suspicious.
    r = items[0x81]
    assert "module" not in r
    assert r["suspicious"] is True
    assert body["suspicious"] == 2
    assert body["idt_base"] == "0xfffff80020000000"
    assert body["all_cpus"] is False


async def test_v025_wp2_idt_agent_old(tmp_path, monkeypatch) -> None:
    """Missing `idt_list` on the client -> kind='agent_old' (lands
    before the ABI v12 agent exists)."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _NoIdtFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {"action": "idt"})
    assert body["ok"] is False
    assert body["kind"] == "agent_old"
    assert "v12" in body.get("hint", "") or "v12" in body.get("error", "")


async def test_v025_wp2_idt_all_cpus_drift(tmp_path, monkeypatch) -> None:
    """all_cpus=true passes all_cpus through, groups rows by cpu,
    and surfaces per-vector handler drift."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _AllCpusFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "idt", "all_cpus": True})
    assert body["ok"] is True
    assert body["all_cpus"] is True
    client = ctx.session.require_client()
    assert client.last_all_cpus is True
    # Rows sorted by (cpu, vector): cpu0 rows first.
    cpus = [r["cpu"] for r in body["items"]]
    assert cpus == sorted(cpus)
    assert {r["cpu"] for r in body["items"]} == {0, 1}
    # Vector 0x80 differs across CPUs -> drift listed.
    assert 0x80 in body.get("handler_drift", [])
    assert body["handler_drift_total"] == 1


async def test_v025_wp2_idt_filter_on_name(tmp_path, monkeypatch) -> None:
    """filter= narrows rows against the resolved name/module text."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch,
                                              _IdtFake)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "idt", "filter": "ntoskrnl"})
    assert body["ok"] is True
    assert [r["vector"] for r in body["items"]] == [0x2E]
