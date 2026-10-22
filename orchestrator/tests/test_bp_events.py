"""v0.23 · bp_manage(action='events') — kernel HW-BP hit observability.

Phase 4 reuses the driver notify ring + Events.Poll: the driver's int1
hook appends BP_HIT records (rip/dr6/bp_id/slot/access/irql), the agent
drains them, and the orchestrator surfaces them as `hits` with
best-effort kernel-module attribution.

Contracts pinned here:
- security.allow_event_stream=false → not_allowed (never touches agent).
- c.events=None (agent < v12) → agent_version kind.
- agent refusal without dangerous_ok → not_allowed with the consent hint.
- hits carry rip/dr6/bp_id/slot/access/irql + module attribution when
  the faulting RIP lands inside a kernel module range.
- dropped/last_seq/subscribed/hook_installed pass through honestly.
- event_manage subscribe kinds_mask bit 6 without dangerous_ok →
  not_allowed before any agent contact.
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


_BP_HIT = 6  # EventsKind EVENTS_KIND_BP_HIT


class _FakeAgentClient:
    """v12-capable agent: serves BP_HIT drains from a canned ring."""

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.events = object()  # v12 marker — non-None
        self.poll_calls: list[dict] = []
        self.poll_resp: dict[str, Any] = {
            "ok": True, "error": "", "last_seq": 42, "dropped": 0,
            "subscribed": True, "bp_hook": True,
            "events": [{
                "seq": 41, "ts_ms": 123456, "kind": _BP_HIT,
                "pid": 1234, "parent_pid": 0, "tid": 5678,
                "image": "", "cmdline": "", "dropped": False,
                "address": 0xFFFFF80012345678, "dr6": 0x2,
                "bp_id": 7, "slot": 1, "access": 3, "irql": 0,
                "in_bp_table": True}]}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.3"}

    async def events_poll(self, since_seq: int = 0, max_events: int = 256,
                          kinds_mask: int = 0,
                          dangerous_ok: bool = False) -> dict[str, Any]:
        self.poll_calls.append({"since_seq": since_seq,
                                "max_events": max_events,
                                "kinds_mask": kinds_mask,
                                "dangerous_ok": dangerous_ok})
        if not dangerous_ok:
            return {"ok": False, "error": "bp_hook_refused: dangerous_ok=false",
                    "last_seq": 0, "dropped": 0, "subscribed": False,
                    "bp_hook": False, "events": []}
        return dict(self.poll_resp)

    async def mem_modules(self, pid: int, kernel: bool = False):
        return [{"base": 0xFFFFF80000000000, "size": 0x20000000,
                 "name": "ntoskrnl.exe"},
                {"base": 0xFFFFF80600000000, "size": 0x100000,
                 "name": "suspex_driver.sys"}]

    def recent_ops(self, limit: int = 32):
        return []


class _OldAgentClient(_FakeAgentClient):
    """Pre-v12 agent: no Events service."""

    def __init__(self, *a, **kw) -> None:
        super().__init__(*a, **kw)
        self.events = None


async def _server(tmp_path, monkeypatch, client_cls=_FakeAgentClient,
                  allow_event_stream: bool = True):
    monkeypatch.setattr("suspex.session.AgentClient", client_cls)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", client_cls)

    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.security.allow_event_stream = allow_event_stream
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
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged


async def _connect(server) -> None:
    body = await _call(server, "target_manage", {"action": "connect"})
    assert body.get("ok") is not False, body


# --------------------------------------------------------------------------- #
# Gates
# --------------------------------------------------------------------------- #


async def test_events_blocked_when_stream_gate_off(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                allow_event_stream=False)
    await _connect(server)
    body = await _call(server, "bp_manage",
                       {"action": "events", "dangerous_ok": True})
    assert body["ok"] is False
    assert body["kind"] == "not_allowed"
    assert "allow_event_stream" in body["error"]


async def test_events_old_agent_gets_agent_version(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch,
                                client_cls=_OldAgentClient)
    await _connect(server)
    body = await _call(server, "bp_manage",
                       {"action": "events", "dangerous_ok": True})
    assert body["ok"] is False
    assert body["kind"] == "agent_version"
    assert "v12" in body["error"]


async def test_events_no_target_surfaces_unknown(tmp_path, monkeypatch):
    """Disconnected: require_client raises before the events branch —
    kind='unknown', matching every other bp_manage action's convention."""
    ctx, server = await _server(tmp_path, monkeypatch)
    body = await _call(server, "bp_manage",
                       {"action": "events", "dangerous_ok": True})
    assert body["ok"] is False
    assert body["kind"] == "unknown"


async def test_events_agent_refusal_maps_not_allowed(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "bp_manage",
                       {"action": "events"})  # dangerous_ok defaults false
    assert body["ok"] is False
    assert body["kind"] == "not_allowed"
    assert "dangerous_ok" in body.get("hint", "")


async def test_event_manage_bp_mask_needs_dangerous_ok(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "event_manage",
                       {"action": "subscribe",
                        "kinds_mask": 1 << _BP_HIT})
    assert body["ok"] is False
    assert body["kind"] == "not_allowed"
    assert "dangerous_ok" in body.get("hint", "")


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


async def test_events_returns_hit_fields_and_module(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    body = await _call(server, "bp_manage",
                       {"action": "events", "dangerous_ok": True})
    assert body["ok"] is not False, body
    assert body["count"] == 1
    hit = body["hits"][0]
    assert hit["rip"] == 0xFFFFF80012345678
    assert hit["rip_hex"] == hex(0xFFFFF80012345678)
    assert hit["dr6"] == 0x2
    assert hit["bp_id"] == 7 and hit["slot"] == 1
    assert hit["access"] == 3 and hit["irql"] == 0
    assert hit["pid"] == 1234 and hit["tid"] == 5678
    # RIP lands inside ntoskrnl range → attributed
    assert hit.get("module") == "ntoskrnl.exe"
    assert hit.get("module_offset") == hex(0x12345678)
    assert body["hook_installed"] is True
    assert body["subscribed"] is True
    assert body["last_seq"] == 42


async def test_events_poll_args_pass_mask_and_consent(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    await _call(server, "bp_manage",
                {"action": "events", "dangerous_ok": True,
                 "since_seq": 40, "limit": 32})
    c = ctx.session.clients[ctx.session.primary]
    call = c.poll_calls[-1]
    assert call["since_seq"] == 40
    assert call["max_events"] == 32
    assert call["kinds_mask"] == 1 << _BP_HIT
    assert call["dangerous_ok"] is True


async def test_events_empty_ring_is_honest(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    await _connect(server)
    c = ctx.session.clients[ctx.session.primary]
    c.poll_resp = {"ok": True, "error": "", "last_seq": 42, "dropped": 3,
                   "subscribed": True, "bp_hook": True, "events": []}
    body = await _call(server, "bp_manage",
                       {"action": "events", "dangerous_ok": True})
    assert body["ok"] is not False
    assert body["hits"] == [] and body["count"] == 0
    assert body["dropped"] == 3  # loss reported, never hidden
    assert "no hits" in body.get("hint", "")


# --------------------------------------------------------------------------- #
# Schema / discovery
# --------------------------------------------------------------------------- #


async def test_bp_actions_enum_includes_events(tmp_path, monkeypatch):
    ctx, server = await _server(tmp_path, monkeypatch)
    tools = {t.name: t for t in await server.list_tools()}
    enum = tools["bp_manage"].parameters["properties"]["action"]["enum"]
    assert "events" in enum
