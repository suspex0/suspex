"""v0.17 E-3: view contention observability + reconnect surface.

  * E-3b: `target_manage(action="reconnect")` tears down + rebuilds the
    view's client without going through disconnect. Preserves co-owner
    refcounts. Refuses on unknown view.
  * E-3c: degraded-view warn banner — `target_manage(action="status")`
    emits a warning for every connected view idle longer than
    SUSPX_DEGRADED_WARN_MS (default 5000 ms).
"""

from __future__ import annotations

import asyncio
import json
import time
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


# --------------------------------------------------------------------------- #
# Fake AgentClient stand-in — enough surface for status + close + connect.
# --------------------------------------------------------------------------- #


class _FakeAgentClient:
    _instances: list["_FakeAgentClient"] = []

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.token = token
        self._closed = False
        # v0.17 E-3c: `all_views` reads `last_op_ts` off the client to
        # compute idle time — expose a mutable attr so tests can pretend
        # a view has been silent for N seconds.
        self.last_op_ts = time.time()
        self.last_seen_ts = time.time()
        self.connected_ts = time.time()
        _FakeAgentClient._instances.append(self)

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        self._closed = True

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": self.endpoint,
                "driver_state": "DRIVER_SERVICE"}

    async def host_info(self, *, include_hardware: bool = False,
                         include_security_products: bool = False
                         ) -> dict[str, Any]:
        # target_manage(status) fires host_info to promote fields — return
        # ok:False so the status handler falls through to the host_info_hint
        # branch (we're not testing that logic here).
        return {"ok": False, "error": "host_info: fake stub"}

    def recent_ops(self, limit: int = 32) -> list[dict[str, Any]]:
        return []


async def _mk_ctx_e3(tmp_path, monkeypatch):
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _FakeAgentClient)
    monkeypatch.setattr("suspex.session.AgentClient", _FakeAgentClient)

    async def _noop_probe(host, port, timeout_s: float = 3.0) -> None:
        return None

    monkeypatch.setattr("suspex.session._probe_tcp", _noop_probe)
    monkeypatch.setenv("SUSPX_AUDIT_DISABLE", "1")
    cfg = SuspexConfig()
    cfg.security.authorized_targets = ["127.0.0.0/8"]
    cfg.target = TargetConfig(host="127.0.0.1", port=9000)
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


async def _call(server, tool: str, args: dict, *, peer: str = "peer-E") -> dict:
    token = CLIENT_ID.set(peer)
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    return body if isinstance(body, dict) else {}


# ---------------------------------------------------------------------------
# E-3b — reconnect action
# ---------------------------------------------------------------------------


def test_e_3b_reconnect_replaces_client_without_disconnect_flow(tmp_path, monkeypatch):
    async def go():
        _FakeAgentClient._instances.clear()
        ctx, server = await _mk_ctx_e3(tmp_path, monkeypatch)
        # Establish the view first.
        connect_env = await _call(server, "target_manage",
                                     {"action": "connect", "name": "kernel"})
        assert connect_env.get("ok") is True
        vk = next(iter(ctx.session.clients))  # '<machine>.kernel' key
        old_client = ctx.session.clients[vk]
        # Reconnect.
        rc_env = await _call(server, "target_manage",
                              {"action": "reconnect", "name": "kernel"})
        assert rc_env.get("ok") is True
        data = rc_env.get("data") or {}
        assert data.get("reconnected") is True
        assert data.get("view") == vk
        # A fresh client instance now backs the view — the old one is closed.
        new_client = ctx.session.clients[vk]
        assert new_client is not old_client
        assert old_client._closed is True
        # Warn banner explains what happened.
        warnings = rc_env.get("warnings") or []
        assert any("torn down and re-established" in w for w in warnings), warnings

    asyncio.run(go())


def test_e_3b_reconnect_on_unknown_view_errors(tmp_path, monkeypatch):
    async def go():
        _FakeAgentClient._instances.clear()
        ctx, server = await _mk_ctx_e3(tmp_path, monkeypatch)
        # Never connected — reconnect must refuse.
        env = await _call(server, "target_manage",
                          {"action": "reconnect", "name": "kernel"})
        assert env.get("ok") is False
        err = env.get("error") or {}
        # kind can be embedded either under error.kind or at top level.
        assert (err.get("kind") == "no_target"
                or env.get("kind") == "no_target"), env

    asyncio.run(go())


def test_e_3b_reconnect_preserves_coowner_refs(tmp_path, monkeypatch):
    async def go():
        _FakeAgentClient._instances.clear()
        ctx, server = await _mk_ctx_e3(tmp_path, monkeypatch)
        # peer-E connects first (primary owner).
        await _call(server, "target_manage",
                     {"action": "connect", "name": "kernel"},
                     peer="peer-E")
        # peer-F attaches as co-owner (same-endpoint connect increments refs).
        await _call(server, "target_manage",
                     {"action": "connect", "name": "kernel"},
                     peer="peer-F")
        vk = next(iter(ctx.session.clients))
        pre_refs = dict(ctx.session.refs.get(vk, {}))
        assert "peer-E" in pre_refs and "peer-F" in pre_refs
        # peer-E reconnects.
        rc = await _call(server, "target_manage",
                          {"action": "reconnect", "name": "kernel"},
                          peer="peer-E")
        assert rc.get("ok") is True
        post_refs = dict(ctx.session.refs.get(vk, {}))
        # peer-F's ref survived the reconnect — its next call will land
        # on the new client without being told "not connected".
        assert "peer-F" in post_refs
        data = rc.get("data") or {}
        # The reconnect envelope names surviving co-owners.
        coowner = data.get("coowner_refs") or {}
        assert "peer-F" in coowner

    asyncio.run(go())


# ---------------------------------------------------------------------------
# E-3c — degraded-view warn banner on status
# ---------------------------------------------------------------------------


def test_e_3c_degraded_view_emits_warning(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_DEGRADED_WARN_MS", "1000")  # 1 s threshold

    async def go():
        _FakeAgentClient._instances.clear()
        ctx, server = await _mk_ctx_e3(tmp_path, monkeypatch)
        await _call(server, "target_manage",
                     {"action": "connect", "name": "kernel"})
        # Backdate last_op_ts so all_views reports 10s idle.
        client = ctx.session.clients[next(iter(ctx.session.clients))]
        client.last_op_ts = time.time() - 10.0
        env = await _call(server, "target_manage",
                           {"action": "status", "name": "kernel"})
        assert env.get("ok") is True
        warnings = env.get("warnings") or []
        assert any("silent for" in w for w in warnings), warnings
        assert any("reconnect" in w for w in warnings), warnings

    asyncio.run(go())


def test_e_3c_healthy_view_no_warn(tmp_path, monkeypatch):
    monkeypatch.setenv("SUSPX_DEGRADED_WARN_MS", "5000")  # 5 s threshold

    async def go():
        _FakeAgentClient._instances.clear()
        ctx, server = await _mk_ctx_e3(tmp_path, monkeypatch)
        await _call(server, "target_manage",
                     {"action": "connect", "name": "kernel"})
        # last_op_ts stays fresh — no warn.
        env = await _call(server, "target_manage",
                           {"action": "status", "name": "kernel"})
        assert env.get("ok") is True
        warnings = env.get("warnings") or []
        assert not any("silent for" in w for w in warnings), warnings

    asyncio.run(go())
