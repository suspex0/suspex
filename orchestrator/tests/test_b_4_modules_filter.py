"""v0.17 B-4 — `mem_rw modules` filter finish-up.

Four sub-items, one file:

- B-4a · stale exact-match docstring fixed (documented in tool schema)
- B-4b · `_apply_modules_filter` wired via new `name_regex` / `name_glob` /
        `path_contains` kwargs (defined since v0.14, never invoked before)
- B-4c · zero-match returns `kind:"filter_no_match"` with a 5-item name sample
- B-4d · `name=` collides between view selector + row filter — refused with
        `kind:"kwarg_collision"`
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


_SEED_MODS = [
    {"name": "ntoskrnl.exe", "base": 0xFFFFF80000000000,
     "size": 0xA00000, "path": r"C:\Windows\System32\ntoskrnl.exe"},
    {"name": "tcpip.sys", "base": 0xFFFFF80000A00000,
     "size": 0x200000, "path": r"C:\Windows\System32\drivers\tcpip.sys"},
    {"name": "ndis.sys", "base": 0xFFFFF80000C00000,
     "size": 0x180000, "path": r"C:\Windows\System32\drivers\ndis.sys"},
    {"name": "afd.sys", "base": 0xFFFFF80000D80000,
     "size": 0x50000, "path": r"C:\Windows\System32\drivers\afd.sys"},
    {"name": "hal.dll", "base": 0xFFFFF80000DD0000,
     "size": 0x30000, "path": r"C:\Windows\System32\hal.dll"},
    {"name": "cng.sys", "base": 0xFFFFF80000E00000,
     "size": 0x70000, "path": r"C:\Windows\System32\drivers\cng.sys"},
]


class _FakeAgentClient:
    def __init__(self, host: str, port: int, token: str, timeout_ms: int,
                 max_inflight: int = 16) -> None:
        self.host = host
        self.port = port
        self.last_op_ts: float = 0.0

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def status(self) -> dict[str, Any]:
        # driver_state=loaded so the `_require_driver` guard passes for the
        # kernel modules branch.
        return {"ok": True, "endpoint": f"{self.host}:{self.port}",
                "driver_state": "loaded", "driver_present": True,
                "driver_version": "1.2"}

    async def mem_modules(self, pid: int, kernel: bool) -> list[dict]:
        # Return copies to keep the seed pristine across test cases.
        return [dict(m) for m in _SEED_MODS]


async def _build_ctx_and_server(tmp_path, monkeypatch):
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
    bridge = IdaBridge(IdaConfigLite.from_config(cfg.ida), tmp_path / "artifacts")
    clients_reg = ClientRegistry()
    ownership_reg = OwnershipRegistry()
    leases_mgr = LeaseManager(
        publish_event=lambda ev: asyncio.create_task(clients_reg.publish(ev)))
    ctx = Context(cfg=cfg, session=session, ledger=ledger, bridge=bridge,
                  clients=clients_reg, leases=leases_mgr, ownership=ownership_reg)
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
# B-4b · typed name_regex / name_glob / path_contains filters
# --------------------------------------------------------------------------- #


async def test_b_4_modules_filter_substring_matches_case_insensitive(
        tmp_path, monkeypatch) -> None:
    """The pre-existing string `filter=` still does case-insensitive
    substring — verified via a mixed-case needle."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "modules", "space": "kernel", "filter": "TcPiP"})
    assert body["ok"] is not False
    names = [m["name"] for m in body.get("items", [])]
    assert names == ["tcpip.sys"]


async def test_b_4_modules_name_regex_typed(tmp_path, monkeypatch) -> None:
    """name_regex applies case-insensitive; anchored regex isolates one row."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "modules", "space": "kernel",
        "name_regex": r"^tcpip\.sys$"})
    assert body["ok"] is not False
    names = [m["name"] for m in body.get("items", [])]
    assert names == ["tcpip.sys"]


async def test_b_4_modules_name_glob_star_matches(
        tmp_path, monkeypatch) -> None:
    """name_glob = 'tcp*' picks up tcpip.sys via case-insensitive fnmatch."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "modules", "space": "kernel", "name_glob": "tcp*"})
    assert body["ok"] is not False
    names = [m["name"] for m in body.get("items", [])]
    assert names == ["tcpip.sys"]


async def test_b_4_modules_path_contains_filters(
        tmp_path, monkeypatch) -> None:
    """path_contains applies case-insensitive substring on the module path
    — 'drivers' picks all four .sys entries under System32\\drivers."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "modules", "space": "kernel", "path_contains": "DRIVERS"})
    assert body["ok"] is not False
    names = {m["name"] for m in body.get("items", [])}
    assert names == {"tcpip.sys", "ndis.sys", "afd.sys", "cng.sys"}


# --------------------------------------------------------------------------- #
# B-4c · zero-match diagnostic
# --------------------------------------------------------------------------- #


async def test_b_4_modules_zero_match_returns_sample(
        tmp_path, monkeypatch) -> None:
    """No matching regex -> kind='filter_no_match' with a 5-item name sample
    and `filter_matched:false` so callers can programmatic-branch."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "modules", "space": "kernel",
        "name_regex": r"^definitely_not_a_real_module_name$"})
    assert body["ok"] is True  # zero match is not an error, just diagnostic
    assert body["kind"] == "filter_no_match"
    assert body.get("filter_matched") is False
    # 6 modules seeded, 5 in the sample.
    assert body.get("total_available") == len(_SEED_MODS)
    sample = body.get("sample_available_names", [])
    assert len(sample) == 5
    assert "ntoskrnl.exe" in sample


# --------------------------------------------------------------------------- #
# B-4b failure mode · bad regex -> invalid_parameter
# --------------------------------------------------------------------------- #


async def test_b_4_modules_bad_regex_returns_invalid_parameter(
        tmp_path, monkeypatch) -> None:
    """A malformed regex must not crash; caller sees kind='invalid_parameter'
    with the compile error text quoted."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "modules", "space": "kernel",
        "name_regex": r"[unterminated"})
    assert body["ok"] is False
    assert body["kind"] == "invalid_parameter"
    assert "name_regex" in body.get("error", "")


# --------------------------------------------------------------------------- #
# B-4d · name= collision refused
# --------------------------------------------------------------------------- #


async def test_b_4_modules_name_as_row_filter_returns_kwarg_collision(
        tmp_path, monkeypatch) -> None:
    """The tool-level `name=` selects the target view ('kernel'|'user'),
    never a row filter. Any other value is refused with
    kind='kwarg_collision' — with a hint pointing to filter=/name_regex=."""
    ctx, server = await _build_ctx_and_server(tmp_path, monkeypatch)
    await _call(server, "target_manage", {"action": "connect"})
    body = await _call(server, "mem_rw", {
        "action": "modules", "space": "kernel", "name": "tcpip"})
    assert body["ok"] is False
    assert body["kind"] == "kwarg_collision"
    hint = body.get("hint", "")
    assert "filter" in hint or "name_regex" in hint
