"""v0.26 — exec_manage(action='call') remote function calls.

Cases exercised:

- gate off (allow_function_call=false) -> kind=not_allowed, no gRPC issued
- argc>16 -> bad_arg
- user call happy path -> status=completed + return_value, request fields
  forwarded (pid, target_va, args, space=CALL_USER)
- module!export resolution feeds the resolved VA
- module+offset resolution feeds base+offset
- UNIMPLEMENTED from the agent -> kind=agent_old
- timed_out response -> status=timeout with stub_va/thread_tid passthrough
- kernel call forwards space=CALL_KERNEL; kernel call via the user view
  (name='user') -> bad_arg
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


class _CallFake:
    """Fake AgentClient — records call_function requests, serves module
    lists for target resolution."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.calls: list[dict[str, Any]] = []
        self.export_addr = 0x12340000
        self.module_base = 0x140000000
        self.module_size = 0x8000000
        self.respond: dict[str, Any] | None = None
        self.error: str = ""

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "DRIVER_SERVICE", "boot_epoch_ms": 1}

    async def mem_exports(self, pid: int, module: str,
                          kernel: bool = False) -> list[dict[str, Any]]:
        return [{"name": "GetCurrentProcessId", "ordinal": 1,
                 "rva": 0x0, "address": self.export_addr, "forwarder": ""}]

    async def mem_modules(self, pid: int, kernel: bool = True) -> list[dict[str, Any]]:
        return [{"name": "ntoskrnl.exe",
                 "path": r"C:\Windows\System32\ntoskrnl.exe",
                 "base": self.module_base, "size": self.module_size,
                 "kernel": kernel}]

    async def call_function(self, *, pid: int = 0, target_va: int,
                            args: list[int] | None = None, space: str = "user",
                            timeout_ms: int = 0, flags: int = 0) -> dict[str, Any]:
        self.calls.append({"pid": pid, "target_va": target_va,
                           "args": list(args or []), "space": space,
                           "timeout_ms": timeout_ms, "flags": flags})
        if self.error:
            raise RuntimeError(self.error)
        if self.respond is not None:
            return dict(self.respond)
        return {"ok": True, "error": "",
                "return_value": 0x1234, "last_error": 0, "exit_code": 0,
                "timed_out": False, "exception": False, "exception_code": 0,
                "thread_tid": 0, "stub_va": 0}


async def _build_ctx_and_server(tmp_path, monkeypatch, fake_cls=_CallFake,
                                gate: bool = True):
    monkeypatch.setattr("suspex.session.AgentClient", fake_cls)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", fake_cls)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.security.allow_function_call = gate
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


async def test_call_gate_off_refuses_without_grpc(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch, gate=False)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    body = await _call(server, "exec_manage", {
        "action": "call", "address": "0x1000", "pid": 42})
    assert body["ok"] is False
    assert body["kind"] == "not_allowed"
    assert fake.calls == []


async def test_call_argc_over_16(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "exec_manage", {
        "action": "call", "address": "0x1000", "pid": 42,
        "call_args": [str(i) for i in range(17)]})
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"
    assert "16" in body["error"]


async def test_call_user_happy_path(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    body = await _call(server, "exec_manage", {
        "action": "call", "space": "user", "pid": 4321,
        "address": "0x7FFB0000", "call_args": ["1", "0x22"], "timeout_ms": 5000})
    assert body["ok"] is True, body
    assert body["status"] == "completed"
    assert body["return_value"] == 0x1234
    assert body["return_value_hex"] == "0x1234"

    req = fake.calls[-1]
    assert req["pid"] == 4321
    assert req["target_va"] == 0x7FFB0000
    assert req["args"] == [1, 0x22]
    assert req["space"] == "user"
    assert req["timeout_ms"] == 5000
    assert req["flags"] == 0


async def test_call_resolves_module_export(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.export_addr = 0x1ED0000

    body = await _call(server, "exec_manage", {
        "action": "call", "pid": 7,
        "address": "kernel32!GetCurrentProcessId"})
    assert body["ok"] is True, body
    assert fake.calls[-1]["target_va"] == 0x1ED0000


async def test_call_resolves_module_offset(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    body = await _call(server, "exec_manage", {
        "action": "call", "pid": 7,
        "address": "ntoskrnl.exe+0x1000"})
    assert body["ok"] is True, body
    assert fake.calls[-1]["target_va"] == fake.module_base + 0x1000


async def test_call_agent_old_on_unimplemented(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.error = "Method not implemented! UNIMPLEMENTED [exec.CallFunction]"

    body = await _call(server, "exec_manage", {
        "action": "call", "pid": 7, "address": "0x1000"})
    assert body["ok"] is False
    assert body["kind"] == "agent_old"


async def test_call_timeout_passthrough(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.respond = {"ok": True, "error": "call: timed out",
                    "return_value": 0, "last_error": 0, "exit_code": 0,
                    "timed_out": True, "exception": False,
                    "exception_code": 0, "thread_tid": 77,
                    "stub_va": 0x3000}

    body = await _call(server, "exec_manage", {
        "action": "call", "pid": 7, "address": "0x1000"})
    assert body["ok"] is True, body
    assert body["status"] == "timeout"
    assert body["thread_tid"] == 77
    assert body["stub_va"] == 0x3000
    assert "free" in body["hint"]


async def test_call_kernel_wire_space(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    body = await _call(server, "exec_manage", {
        "action": "call", "space": "kernel",
        "address": "0xFFFFF80001234000", "force": True})
    assert body["ok"] is True, body
    req = fake.calls[-1]
    assert req["space"] == "kernel"
    assert req["target_va"] == 0xFFFFF80001234000
    assert req["flags"] == 2  # force


async def test_call_kernel_on_user_view_refused(tmp_path, monkeypatch):
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})

    body = await _call(server, "exec_manage", {
        "action": "call", "space": "kernel", "name": "user",
        "address": "0xFFFFF80001234000"})
    assert body["ok"] is False
    assert body["kind"] == "bad_arg"
    assert "driver" in body["error"]