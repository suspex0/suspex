"""Provenance-marker tests (rea-adoption Part 1).

Covers:
- the anti-drift rule: every registered (tool, action) pair from the
  per-module *_ACTIONS enums is explicitly classified in
  `_provenance.classification_table()` (failures list the missing pairs);
- trusted actions produce envelopes with NO `provenance` key;
- target-derived results (and their error envelopes) carry
  provenance == {"untrusted_content": true, "source": "target"};
- unclassified pairs fall back to UNTRUSTED_TARGET with a `warnings`
  entry;
- the SUSPX_MCP_LEGACY_DUAL_CONTENT path carries the same fields.
"""
from __future__ import annotations

import json

import pytest

from suspex.mcp import _provenance
from suspex.mcp._provenance import (
    TRUSTED,
    UNTRUSTED_SESSION,
    UNTRUSTED_TARGET,
    classification_table,
    provenance_for,
    stamp,
)

# tool -> (module, ACTIONS constant). Open-surface tools (ida/ghidra)
# have no enum; their short verbs are pinned in the table and any
# passthrough verb falls back to the tool default — covered below.
_ENUM_TOOLS: dict[str, tuple[str, str]] = {
    "target_manage": ("suspex.mcp.tools.target", "TARGET_ACTIONS"),
    "mem_rw": ("suspex.mcp.tools.mem", "MEM_ACTIONS"),
    "debug_manage": ("suspex.mcp.tools.debug", "DEBUG_ACTIONS"),
    "bp_manage": ("suspex.mcp.tools.bp", "BP_ACTIONS"),
    "exec_manage": ("suspex.mcp.tools.exec_", "EXEC_ACTIONS"),
    "file_manage": ("suspex.mcp.tools.files", "FILE_ACTIONS"),
    "script_manage": ("suspex.mcp.tools.scripts", "SCRIPT_ACTIONS"),
    "knowledge_manage": ("suspex.mcp.tools.knowledge", "KNOWLEDGE_ACTIONS"),
    "reg_manage": ("suspex.mcp.tools.reg", "REG_ACTIONS"),
    "watchdog_manage": ("suspex.mcp.tools.watchdog", "WDG_ACTIONS"),
    "value_manage": ("suspex.mcp.tools.value", "VALUE_MANAGE_ACTIONS"),
    "emulate_manage": ("suspex.mcp.tools.emulate", "EMU_ACTIONS"),
    "bin_manage": ("suspex.mcp.tools.bin", "_BIN_ACTIONS"),
    "device_manage": ("suspex.mcp.tools.device", "DEVICE_ACTIONS"),
    "event_manage": ("suspex.mcp.tools.events", "EVENT_ACTIONS"),
    "symbols_manage": ("suspex.mcp.tools.symbols", "SYMBOL_ACTIONS"),
    "dump_manage": ("suspex.mcp.tools.dump", "DUMP_ACTIONS"),
    "screen_manage": ("suspex.mcp.tools.screen", "SCREEN_ACTIONS"),
}
# Short verbs of the deliberately-enum-less tools (still pinned).
_OPEN_TOOLS: dict[str, list[str]] = {
    "ida_manage": ["actions", "list", "schemas", "tools", "health",
                   "open", "open_async", "open_status", "close",
                   "dump_layout"],
    "ghidra_manage": ["actions", "list", "schemas", "tools", "health",
                      "open", "open_async", "open_status", "close",
                      "dump_layout"],
}


# ---------------------------------------------------------------------------
# Anti-drift — every registered (tool, action) is explicitly classified
# ---------------------------------------------------------------------------

def test_every_registered_pair_is_classified() -> None:
    import importlib

    table = classification_table()
    missing: list[str] = []
    for tool, (modname, const) in _ENUM_TOOLS.items():
        actions = getattr(importlib.import_module(modname), const)
        for action in actions:
            if (tool, action) not in table:
                missing.append(f"{tool}.{action}")
    for tool, actions in _OPEN_TOOLS.items():
        for action in actions:
            if (tool, action) not in table:
                missing.append(f"{tool}.{action}")
    assert not missing, (
        "unclassified (tool, action) pairs — add them to "
        f"_provenance._TABLE: {sorted(missing)}")


def test_every_classified_pair_is_a_registered_action() -> None:
    """Reverse drift: the table only names actions that exist."""
    import importlib

    known: set[tuple[str, str]] = set()
    for tool, (modname, const) in _ENUM_TOOLS.items():
        actions = getattr(importlib.import_module(modname), const)
        known |= {(tool, a) for a in actions}
    for tool, actions in _OPEN_TOOLS.items():
        known |= {(tool, a) for a in actions}
    phantom = sorted(set(classification_table()) - known)
    assert not phantom, f"classified but not registered: {phantom}"


def test_open_surface_passthrough_defaults_to_target() -> None:
    # Decompiler-ish passthrough verbs never trip the KeyError fallback.
    assert provenance_for("ida_manage", "decompile") == UNTRUSTED_TARGET
    assert provenance_for("ghidra_manage", "pcode") == UNTRUSTED_TARGET


# ---------------------------------------------------------------------------
# Trusted actions carry NO provenance block
# ---------------------------------------------------------------------------

def test_trusted_actions_render_no_block() -> None:
    for tool, action in [("value_manage", "cast"), ("value_manage", "actions"),
                         ("target_manage", "tool_index"),
                         ("target_manage", "actions"),
                         ("watchdog_manage", "arm"),
                         ("script_manage", "list"),
                         ("knowledge_manage", "record")]:
        assert provenance_for(tool, action) is TRUSTED, (tool, action)
        env: dict = {"ok": True}
        assert "provenance" not in stamp(env, tool, action)


def test_session_actions_render_session_block() -> None:
    assert provenance_for("knowledge_manage", "about") == UNTRUSTED_SESSION
    assert provenance_for("file_manage", "grep_artifact") == UNTRUSTED_SESSION


# ---------------------------------------------------------------------------
# Unclassified pair → UNTRUSTED_TARGET fallback + warnings entry
# ---------------------------------------------------------------------------

def test_unclassified_pair_falls_back_with_warning() -> None:
    with pytest.raises(KeyError):
        provenance_for("mem_rw", "not_a_real_action")
    env: dict = {"ok": True}
    stamped = stamp(env, "mem_rw", "not_a_real_action")
    assert stamped["provenance"] == UNTRUSTED_TARGET
    assert any("unclassified action mem_rw.not_a_real_action" in w
               for w in stamped.get("warnings", []))


# ---------------------------------------------------------------------------
# Wire-level: server-built envelopes (fake target, no driver needed)
# ---------------------------------------------------------------------------

class _ProvFake:
    """Minimal fake AgentClient serving one kernel memory range."""

    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0
        self.memory: dict[int, bytes] = {}

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict:
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True}

    async def mem_read(self, pid: int, addr: int, size: int, space: str,
                       **kw) -> bytes:
        for base, buf in self.memory.items():
            if base <= addr < base + len(buf):
                off = addr - base
                return buf[off:off + size]
        raise RuntimeError(f"unmapped VA 0x{addr:X}")


async def _build_server(tmp_path, monkeypatch):
    import asyncio

    from suspex.caller import CLIENT_ID
    from suspex.clients import ClientRegistry
    from suspex.config import SuspexConfig, TargetConfig
    from suspex.findings import FindingsLedger
    from suspex.ida_bridge import IdaBridge, IdaConfigLite
    from suspex.leases import LeaseManager
    from suspex.mcp.tools import Context, build_server
    from suspex.ownership import OwnershipRegistry
    from suspex.session import Session

    monkeypatch.setattr("suspex.session.AgentClient", _ProvFake)
    monkeypatch.setattr("suspex.mcp.tools.AgentClient", _ProvFake)

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
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr,
                  ownership=OwnershipRegistry())
    return ctx, build_server(ctx)


async def _call(server, tool: str, args: dict) -> dict:
    from suspex.caller import CLIENT_ID

    token = CLIENT_ID.set("peer-P1")
    try:
        result = await server.call_tool(tool, args)
    finally:
        CLIENT_ID.reset(token)
    body = getattr(result, "structured_content", None)
    if body is None:
        text = result.content[0].text if result.content else ""
        body = json.loads(text) if text else {}
    return body if isinstance(body, dict) else {}


async def test_mem_rw_result_carries_target_marker(
        tmp_path, monkeypatch) -> None:
    ctx, server = await _build_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    fake = ctx.session.require_client()
    fake.memory[0x1000] = b"\x90\x90\x90\x90"
    env = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "address": "0x1000", "size": 4,
    })
    assert env["ok"] is True
    assert env["provenance"] == {
        "untrusted_content": True, "source": "target",
    }


async def test_value_manage_result_has_no_provenance_key(
        tmp_path, monkeypatch) -> None:
    _ctx, server = await _build_server(tmp_path, monkeypatch)
    env = await _call(server, "value_manage", {
        "action": "cast", "value": 0xFFFFFFFE,
        "from_type": "u32", "to_type": "i32",
    })
    assert env["ok"] is True
    assert "provenance" not in env


async def test_target_manage_tool_index_has_no_provenance_key(
        tmp_path, monkeypatch) -> None:
    _ctx, server = await _build_server(tmp_path, monkeypatch)
    env = await _call(server, "target_manage", {"action": "tool_index"})
    assert env["ok"] is True
    assert "provenance" not in env


async def test_error_envelope_from_marked_action_keeps_marker(
        tmp_path, monkeypatch) -> None:
    ctx, server = await _build_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    # Unmapped VA -> mem_rw read fails, but the (tool, action) marker stays.
    env = await _call(server, "mem_rw", {
        "action": "read", "space": "kernel",
        "address": "0xDEAD0000", "size": 4,
    })
    assert env["ok"] is False
    assert env["provenance"] == {
        "untrusted_content": True, "source": "target",
    }


async def test_error_envelope_from_unclassified_action_warns(
        tmp_path, monkeypatch) -> None:
    _ctx, server = await _build_server(tmp_path, monkeypatch)
    env = await _call(server, "mem_rw", {"action": "bogus_verb"})
    assert env["ok"] is False
    assert env["provenance"] == {
        "untrusted_content": True, "source": "target",
    }
    assert any("unclassified action mem_rw.bogus_verb" in w
               for w in env.get("warnings", []))


# ---------------------------------------------------------------------------
# SUSPX_MCP_LEGACY_DUAL_CONTENT carries the same fields
# ---------------------------------------------------------------------------

def test_legacy_dual_content_carries_blocks(monkeypatch) -> None:
    from suspex.mcp._envelope import to_tool_result

    env = {
        "ok": True, "kind": "read", "tool": "mem_rw", "action": "read",
        "data": {"hex": "90"},
        "provenance": dict(UNTRUSTED_TARGET),
        "coverage": {"scope": "mem-read", "status": "complete",
                     "limits": []},
        "summary": {"size_bytes": 10},
    }
    monkeypatch.setenv("SUSPX_MCP_LEGACY_DUAL_CONTENT", "1")
    result = to_tool_result(env, legacy_dual=None)
    body = getattr(result, "structured_content", None)
    if body is None:  # fastmcp unavailable -> JSON string fallback
        text = result.content[0].text
        body = json.loads(text)
    assert body["provenance"] == {
        "untrusted_content": True, "source": "target",
    }
    assert body["coverage"]["scope"] == "mem-read"
    text = result.content[0].text
    assert "untrusted_content" in text
