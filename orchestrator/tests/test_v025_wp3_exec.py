"""v0.25 WP3 — exec_manage background=true + timeout_s deadline.

Cases exercised:

- run_powershell background=true routes through run_detached with the
  same quoted-cmdline assembly as run_script and returns handle_id +
  the detached_status/detached_tail hint
- run_cmd / run_exe background=true take the same path
- timeout_s wraps run_shell/run_detached in an orchestrator-side
  deadline — a slow call lands kind=deadline_exceeded with the
  "spawn may have succeeded" hint on the detached verb
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


class _ExecFake:
    """Fake AgentClient — records detached spawns, can stall run_shell."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self.last_op_ts: float = 0.0
        self.detached_calls: list[tuple] = []
        self.next_handle = "h-0001"
        self.shell_sleep_s = 0.0

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "DRIVER_SERVICE", "boot_epoch_ms": 1}

    async def run_detached(self, cmdline: str, workdir: str = "",
                           stdout_path: str = "", stderr_path: str = "",
                           **kw: Any) -> dict[str, Any]:
        self.detached_calls.append(
            (cmdline, workdir, stdout_path, stderr_path))
        hid = self.next_handle
        self.next_handle = "h-%04d" % (int(hid.split("-")[1]) + 1)
        return {"ok": True, "handle_id": hid, "pid": 4321,
                "stdout_path": stdout_path or r"C:\Temp\o.log",
                "stderr_path": stderr_path or r"C:\Temp\e.log",
                "started_ts": 1}

    async def run_shell(self, command: str, shell: str = "cmd",
                        workdir: str = "",
                        timeout_ms: int = 30000) -> dict[str, Any]:
        if self.shell_sleep_s:
            await asyncio.sleep(self.shell_sleep_s)
        return {"exit_code": 0, "output": "done"}

    async def run_exe(self, exe: str, args: list[str] | None = None,
                      workdir: str = "",
                      timeout_ms: int = 30000) -> dict[str, Any]:
        return {"exit_code": 0, "stdout": "ok", "stderr": "",
                "timed_out": False}


async def _build_ctx_and_server(tmp_path, monkeypatch, fake_cls=_ExecFake):
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


async def test_v025_wp3_run_powershell_background_detaches(
        tmp_path, monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    body = await _call(server, "exec_manage", {
        "action": "run_powershell", "command": "Get-Date",
        "background": True})
    assert body["ok"] is True, body
    assert body["handle_id"] == "h-0001"
    assert body["background"] is True
    assert "detached_status" in body["hint"]

    # Quoted-cmdline assembly: powershell.exe -NoProfile -Command <cmd>
    cmdline = fake.detached_calls[-1][0]
    assert cmdline.startswith('"powershell.exe"')
    assert "-Command" in cmdline
    assert "Get-Date" in cmdline


async def test_v025_wp3_run_cmd_and_exe_background(tmp_path,
                                                   monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    body = await _call(server, "exec_manage", {
        "action": "run_cmd", "command": "dir C:\\", "background": True})
    assert body["ok"] is True, body
    cmdline = fake.detached_calls[-1][0]
    assert cmdline.startswith('"cmd.exe"')
    assert "/c" in cmdline

    body = await _call(server, "exec_manage", {
        "action": "run_exe", "exe": "long_task.exe",
        "args_list": ["--flag", "two words"], "background": True})
    assert body["ok"] is True, body
    assert body["handle_id"] == "h-0002"
    cmdline = fake.detached_calls[-1][0]
    assert cmdline.startswith('"long_task.exe"')
    assert '"two words"' in cmdline  # spaces re-quoted


async def test_v025_wp3_timeout_s_deadline(tmp_path, monkeypatch) -> None:
    """timeout_s bounds the call; run_detached gets the spawn-may-have-
    succeeded hint."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.shell_sleep_s = 5.0

    body = await _call(server, "exec_manage", {
        "action": "run_powershell", "command": "Start-Sleep 60",
        "timeout_s": 0.2})
    assert body["ok"] is False
    assert body["kind"] == "deadline_exceeded"
    assert "run_detached" in body["hint"]


async def test_v025_wp3_run_detached_deadline_hint(tmp_path,
                                                  monkeypatch) -> None:
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()

    async def _stall(*a, **kw):
        await asyncio.sleep(5.0)
        return {"ok": True, "handle_id": "h-late"}

    fake.run_detached = _stall  # spawn reply never arrives in time
    body = await _call(server, "exec_manage", {
        "action": "run_detached", "command": "wedged.exe",
        "timeout_s": 0.2})
    assert body["ok"] is False
    assert body["kind"] == "deadline_exceeded"
    assert "spawn may have succeeded" in body["hint"]
