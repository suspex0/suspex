"""v0.22 · action-verb discoverability — schema-level enums.

The original discoverability gap: every tool's inputSchema exposed
``action`` as a bare ``{"type": "string"}``; the ``*Args`` Field
descriptions never reached the wire, so clients that don't render
descriptions saw nothing.

This file pins the fix: every action-dispatch tool now emits
``properties.action.enum`` in its live FastMCP schema, and every enum
contains the ``actions`` discovery verb. ``ida_manage`` is the lone
exception — it forwards unknown actions verbatim to the idalib shim, so
an enum would break passthrough; it gets no enum on purpose.
"""
from __future__ import annotations

import asyncio
import json as _json
import tempfile
from pathlib import Path
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


class _FakeAgentClient:
    """Offline stand-in — never connects; only satisfies the Session."""

    def __init__(self, host: str, port: int, token: str,
                 timeout_ms: int, max_inflight: int = 16) -> None:
        self.host = host
        self.port = port

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.2"}


async def _server(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("suspex.session.AgentClient", _FakeAgentClient)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _FakeAgentClient)

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
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida),
                       tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg,
                  leases=LeaseManager(publish_event=lambda ev:
                                      asyncio.create_task(
                                          clients_reg.publish(ev))),
                  ownership=OwnershipRegistry())
    return build_server(ctx)


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
# Schema-level enum coverage
# --------------------------------------------------------------------------- #

_PASSTHROUGH_TOOLS = {"ida_manage", "ghidra_manage"}  # forward unknown verbs to the shim


async def test_every_dispatch_tool_exposes_action_enum(
        tmp_path, monkeypatch) -> None:
    """Every action= tool except the ida passthrough must publish a
    non-empty ``action.enum`` in its live inputSchema."""
    server = await _server(tmp_path, monkeypatch)
    tools = {t.name: t for t in await server.list_tools()}
    assert len(tools) >= 16
    missing: list[str] = []
    for name, t in tools.items():
        props = (t.parameters or {}).get("properties", {})
        enum = (props.get("action") or {}).get("enum")
        if name in _PASSTHROUGH_TOOLS:
            assert enum is None, f"{name} must stay passthrough (no enum)"
            continue
        if not enum:
            missing.append(name)
        else:
            assert "actions" in enum, f"{name} enum lacks the actions verb"
    assert not missing, f"tools missing action.enum: {missing}"


async def test_action_enum_matches_dispatch_list(tmp_path, monkeypatch) -> None:
    """The schema enum and the tool's runtime action list are the same
    source — spot-check mem_rw's enum contains its headline verbs."""
    server = await _server(tmp_path, monkeypatch)
    tools = {t.name: t for t in await server.list_tools()}
    enum = (tools["mem_rw"].parameters["properties"]["action"]["enum"])
    for verb in ("read", "write", "handles", "pattern_scan", "scan_start",
                 "phys_ranges", "resolve", "disasm", "actions"):
        assert verb in enum


# --------------------------------------------------------------------------- #
# action='actions' — per-tool help, pure-compute (no target needed)
# --------------------------------------------------------------------------- #


async def test_actions_verb_answers_unconnected(tmp_path, monkeypatch) -> None:
    """`action='actions'` must return per-verb help with NO target
    connected — discovery can't depend on require_client()."""
    server = await _server(tmp_path, monkeypatch)
    tools = [t.name for t in await server.list_tools()]
    for name in tools:
        body = await _call(server, name, {"action": "actions"})
        assert body["ok"] is True, f"{name} actions failed: {body}"
        acts = body.get("actions", {})
        assert len(acts) >= 2, f"{name} returned too few verbs"
        for verb, spec in acts.items():
            assert set(spec) >= {"one_liner", "key_args", "example"}, (
                f"{name}.{verb} spec shape wrong: {spec}")
            assert spec["one_liner"], f"{name}.{verb} empty one_liner"


async def test_actions_verb_lists_itself(tmp_path, monkeypatch) -> None:
    server = await _server(tmp_path, monkeypatch)
    body = await _call(server, "mem_rw", {"action": "actions"})
    assert "actions" in body["actions"]


async def test_unknown_action_hint_points_to_actions(
        tmp_path, monkeypatch) -> None:
    """A typo'd action must carry kind='unknown' plus a hint steering the
    caller to action='actions' / tool_index — before require_client."""
    server = await _server(tmp_path, monkeypatch)
    body = await _call(server, "mem_rw", {"action": "actionz"})
    assert body["ok"] is False
    assert body["kind"] == "unknown"
    hint = body.get("hint", "")
    assert "action='actions'" in hint
    assert "tool_index" in hint
    # valid verbs are still enumerated in the error text
    assert "read" in body.get("error", "")


# --------------------------------------------------------------------------- #
# target_manage(action='tool_index') — global surface map
# --------------------------------------------------------------------------- #


async def test_tool_index_lists_every_tool(tmp_path, monkeypatch) -> None:
    server = await _server(tmp_path, monkeypatch)
    body = await _call(server, "target_manage", {"action": "tool_index"})
    assert body["ok"] is True
    rows = body.get("tools", [])
    names = {r["tool"] for r in rows}
    expected = await server.list_tools()
    assert names == {t.name for t in expected}
    for row in rows:
        assert row.get("one_liner") is not None
        if row["tool"] in _PASSTHROUGH_TOOLS:
            assert row["actions"] == "<passthrough>"
        else:
            assert isinstance(row["actions"], list)
            assert "actions" in row["actions"]


async def test_tool_index_answers_unconnected(tmp_path, monkeypatch) -> None:
    """tool_index must work with zero views connected."""
    server = await _server(tmp_path, monkeypatch)
    body = await _call(server, "target_manage", {"action": "tool_index"})
    assert body["ok"] is True
    assert body.get("count", 0) >= 16
