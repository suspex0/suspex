"""Shared fakes / fixtures / helpers for the split test_multi_* modules.

Extracted verbatim from the original ``test_multi_agent.py`` as part of the
mechanical Phase 5b split. No logic changes — every public name previously
defined at module scope in test_multi_agent.py is defined here and
re-exported by that facade for any external caller.
"""

from __future__ import annotations

import asyncio
import json as _json
from typing import Any

import pytest

from suspex.clients import ClientRegistry
from suspex.config import SuspexConfig, TargetConfig
from suspex.findings import FindingsLedger
from suspex.ida_bridge import IdaBridge, IdaConfigLite
from suspex.leases import LeaseManager
from suspex.mcp.tools import Context, build_server
from suspex.ownership import OwnershipRegistry
from suspex.session import Session
from suspex.caller import CLIENT_ID


# -----------------------------------------------------------------------------
# caller.py fakes
# -----------------------------------------------------------------------------


class _FakeHeaders:
    def __init__(self, data: dict[str, str]) -> None:
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, name: str, default: Any = None) -> Any:
        return self._data.get(name.lower(), default)


class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(self, headers: dict[str, str] | None = None, host: str | None = None) -> None:
        self.headers = _FakeHeaders(headers or {})
        self.client = _FakeClient(host) if host is not None else None


# -----------------------------------------------------------------------------
# session.py fakes + fixture
# -----------------------------------------------------------------------------


class _FakeAgentClient:
    """Duck-typed for Session.connect / Session.disconnect exercise."""
    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self._closed = False

    async def connect(self) -> None:
        pass

    async def close(self) -> None:
        self._closed = True

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}"}


@pytest.fixture()
def fake_agent_class(monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _FakeAgentClient)
    # v0.17 F-1b: pre-flight TCP probe now runs on every new connect.
    # Tests wire fake agents to closed loopback ports; short-circuit the
    # real socket connect so the fake agent path still exercises.
    async def _noop_probe(host: str, port: int, timeout_s: float = 3.0) -> None:
        return None
    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    return _FakeAgentClient


# -----------------------------------------------------------------------------
# MCP tool surface — richer fake + server wiring
# -----------------------------------------------------------------------------


class _RichFakeAgentClient(_FakeAgentClient):
    """Extends the connect/close fake with the RPCs bp_manage needs."""
    _NEXT_BP_ID = 1000

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        super().__init__(host, port, token, timeout_ms, max_inflight)
        self._bps: dict[int, dict[str, Any]] = {}

    async def bp_add(self, kind: str, addr: int, slot: int, size: int, access: str,
                     kernel_target: bool, pid: int, tid: int,
                     global_: bool = False, dangerous_ok: bool = False) -> dict:
        _RichFakeAgentClient._NEXT_BP_ID += 1
        bp_id = _RichFakeAgentClient._NEXT_BP_ID
        self._bps[bp_id] = {"bp_id": bp_id, "kind": kind, "address": addr,
                            "kernel_target": kernel_target}
        return {"bp_id": bp_id}

    async def bp_list(self) -> list[dict]:
        return list(self._bps.values())

    async def bp_remove(self, bp_id: int) -> dict:
        self._bps.pop(bp_id, None)
        return {"ok": True}

    async def bp_set_enabled(self, bp_id: int, enabled: bool) -> dict:
        return {"ok": True, "bp_id": bp_id, "enabled": enabled}


async def _build_ctx_and_server(tmp_path, monkeypatch) -> tuple[Context, Any]:
    """Wire a Context + FastMCP server with FakeAgentClients pre-seeded."""
    monkeypatch.setattr("suspex.session.AgentClient", _RichFakeAgentClient)
    # v0.17 F-1b: skip the real pre-flight TCP probe under fakes.
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
    leases_mgr = LeaseManager(publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr, ownership=ownership_reg)
    server = build_server(ctx)
    return ctx, server


async def _call_as(client_id: str, server, tool: str, args: dict) -> dict:
    """Invoke `tool` on `server` while CLIENT_ID is pinned to `client_id`.

    The updated caller middleware defers to a pre-set ContextVar, so the
    dispatch inside call_tool sees the id we bind here rather than a
    synthesised anon-* one.

    v0.14 tool responses are wrapped as ``{ok, kind, tool, action, data:
    {...}, summary}``; when a ``data`` sub-object is present, we return it
    (merging in the outer ``ok`` so error branches keep their top-level
    ``ok=False`` shape). This lets tests read the payload naturally.
    """
    token = CLIENT_ID.set(client_id)
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    # v0.17 A-1: envelope now rides in ``structured_content`` (no text
    # copy in ``content`` unless SUSPX_MCP_LEGACY_DUAL_CONTENT=1). Fall
    # back to the text path for the legacy dual-emit shape.
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
        # The envelope lifts an ok=False body's error metadata into a nested
        # dict; flatten `error.kind`, `error.hint`, and any extra keys so
        # test assertions can read them at the top level.
        for k, v in body["error"].items():
            merged.setdefault(k, v)
    merged.setdefault("ok", body.get("ok"))
    # Envelope's outer kind is the generic "error" or the domain kind on
    # success; prefer the inner error.kind when it exists.
    err = body.get("error")
    if isinstance(err, dict) and "kind" in err:
        merged["kind"] = err["kind"]
    else:
        merged.setdefault("kind", body.get("kind"))
    return merged
